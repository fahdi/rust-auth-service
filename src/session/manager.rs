use anyhow::Result;
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;
use super::{
    Session, SessionService, CreateSessionRequest, SessionValidationResult, 
    SessionStatistics, TerminationReason, SecurityWarning, SecurityAction,
    SecurityWarningType, WarningSevertiy, SessionConfig, DeviceInfo,
    SessionLocation, SecurityLevel, generate_session_id, parse_user_agent,
    calculate_distance_km, default_session_flags
};

/// Session manager implementation
pub struct SessionManager<T: SessionService> {
    service: T,
    config: SessionConfig,
}

impl<T: SessionService> SessionManager<T> {
    /// Create new session manager
    pub fn new(service: T, config: SessionConfig) -> Self {
        Self { service, config }
    }

    /// Create session with security checks
    pub async fn create_session(&self, request: CreateSessionRequest) -> Result<Session> {
        // Check concurrent session limits
        let existing_sessions = self.service.get_user_sessions(&request.user_id).await?;
        let active_sessions: Vec<_> = existing_sessions
            .iter()
            .filter(|s| s.terminated_at.is_none() && s.expires_at > Utc::now())
            .collect();

        if active_sessions.len() >= self.config.max_concurrent_sessions_per_user as usize {
            // Terminate oldest session to make room
            if let Some(oldest_session) = active_sessions
                .iter()
                .min_by_key(|s| s.last_accessed_at)
            {
                self.service.terminate_session(&oldest_session.id, TerminationReason::ConcurrentLoginLimit).await?;
            }
        }

        // Parse device information
        let device_info = parse_user_agent(&request.user_agent);
        
        // Check if this is a new device
        let is_new_device = !existing_sessions
            .iter()
            .any(|s| s.device_info.fingerprint == device_info.fingerprint);

        // Determine session security level
        let security_level = self.determine_security_level(&request, is_new_device)?;

        // Calculate session expiration
        let session_duration = request.session_duration
            .unwrap_or(self.config.default_session_duration);
        let expires_at = Utc::now() + session_duration;

        // Create session
        let session = Session {
            id: generate_session_id(),
            user_id: request.user_id.clone(),
            device_id: device_info.device_id.clone(),
            refresh_token: self.generate_refresh_token(),
            access_token: self.generate_access_token(&request.user_id)?,
            ip_address: request.ip_address.clone(),
            user_agent: request.user_agent.clone(),
            device_info,
            location: self.resolve_location(&request.ip_address).await.ok(),
            security_level,
            flags: self.determine_session_flags(&request, is_new_device),
            metadata: HashMap::new(),
            created_at: Utc::now(),
            last_accessed_at: Utc::now(),
            expires_at,
            terminated_at: None,
            termination_reason: None,
        };

        self.service.create_session(session).await
    }

    /// Validate session with comprehensive security checks
    pub async fn validate_session(
        &self, 
        session_id: &str, 
        ip_address: &str, 
        user_agent: &str
    ) -> Result<SessionValidationResult> {
        let session = match self.service.get_session(session_id).await? {
            Some(session) => session,
            None => {
                return Ok(SessionValidationResult {
                    is_valid: false,
                    session: None,
                    security_warnings: vec![],
                    actions_required: vec![SecurityAction::ForceLogout],
                });
            }
        };

        let mut warnings = Vec::new();
        let mut actions_required = Vec::new();

        // Check if session is terminated
        if session.terminated_at.is_some() {
            return Ok(SessionValidationResult {
                is_valid: false,
                session: Some(session),
                security_warnings: warnings,
                actions_required: vec![SecurityAction::ForceLogout],
            });
        }

        // Check expiration
        if session.expires_at <= Utc::now() {
            return Ok(SessionValidationResult {
                is_valid: false,
                session: Some(session),
                security_warnings: warnings,
                actions_required: vec![SecurityAction::ForceLogout],
            });
        }

        // Check IP address changes
        if session.ip_address != ip_address {
            warnings.push(SecurityWarning {
                warning_type: SecurityWarningType::SuspiciousActivity,
                message: format!("IP address changed from {} to {}", session.ip_address, ip_address),
                severity: WarningSevertiy::Medium,
                triggered_at: Utc::now(),
            });

            // Check if location change is suspicious
            if let Some(session_location) = &session.location {
                if let Ok(current_location) = self.resolve_location(ip_address).await {
                    if let (Some(lat1), Some(lon1), Some(lat2), Some(lon2)) = (
                        session_location.latitude,
                        session_location.longitude,
                        current_location.latitude,
                        current_location.longitude,
                    ) {
                        let distance = calculate_distance_km(lat1, lon1, lat2, lon2);
                        if distance > self.config.suspicious_location_threshold_km {
                            warnings.push(SecurityWarning {
                                warning_type: SecurityWarningType::UnusualLocation,
                                message: format!("Location changed by {:.0} km", distance),
                                severity: WarningSevertiy::High,
                                triggered_at: Utc::now(),
                            });
                            
                            if session.security_level < SecurityLevel::High {
                                actions_required.push(SecurityAction::RequireMFA);
                            }
                        }
                    }
                }
            }
        }

        // Check user agent changes
        if session.user_agent != user_agent {
            warnings.push(SecurityWarning {
                warning_type: SecurityWarningType::SuspiciousActivity,
                message: "User agent changed during session".to_string(),
                severity: WarningSevertiy::Medium,
                triggered_at: Utc::now(),
            });
        }

        // Check for concurrent sessions
        let user_sessions = self.service.get_user_sessions(&session.user_id).await?;
        let active_count = user_sessions
            .iter()
            .filter(|s| s.terminated_at.is_none() && s.expires_at > Utc::now())
            .count();

        if active_count > 1 {
            warnings.push(SecurityWarning {
                warning_type: SecurityWarningType::ConcurrentSessions,
                message: format!("User has {} active sessions", active_count),
                severity: WarningSevertiy::Low,
                triggered_at: Utc::now(),
            });
        }

        // Check for forced logout flag
        if session.flags.force_logout {
            actions_required.push(SecurityAction::ForceLogout);
        }

        // Check if MFA is required
        if session.flags.requires_mfa {
            actions_required.push(SecurityAction::RequireMFA);
        }

        // Update last accessed time
        let mut updated_session = session.clone();
        updated_session.last_accessed_at = Utc::now();
        updated_session.ip_address = ip_address.to_string();
        updated_session.user_agent = user_agent.to_string();
        
        self.service.update_session(session_id, updated_session.clone()).await?;

        let is_valid = actions_required.is_empty() || 
                      !actions_required.contains(&SecurityAction::ForceLogout);

        Ok(SessionValidationResult {
            is_valid,
            session: Some(updated_session),
            security_warnings: warnings,
            actions_required,
        })
    }

    /// Refresh session tokens
    pub async fn refresh_session(&self, session_id: &str) -> Result<Session> {
        let mut session = self.service.get_session(session_id).await?
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;

        // Check if session is still valid
        if session.terminated_at.is_some() || session.expires_at <= Utc::now() {
            return Err(anyhow::anyhow!("Session is no longer valid"));
        }

        // Generate new tokens
        session.refresh_token = self.generate_refresh_token();
        session.access_token = self.generate_access_token(&session.user_id)?;
        session.last_accessed_at = Utc::now();

        // Extend expiration if needed
        let remaining_time = session.expires_at - Utc::now();
        if remaining_time < Duration::hours(1) {
            session.expires_at = Utc::now() + self.config.default_session_duration;
        }

        self.service.update_session(session_id, session).await
    }

    /// Terminate user sessions with specific criteria
    pub async fn terminate_user_sessions_conditional(
        &self,
        user_id: &str,
        condition: SessionTerminationCondition,
        reason: TerminationReason,
    ) -> Result<u64> {
        let sessions = self.service.get_user_sessions(user_id).await?;
        let mut terminated_count = 0;

        for session in sessions {
            if session.terminated_at.is_some() {
                continue;
            }

            let should_terminate = match &condition {
                SessionTerminationCondition::All => true,
                SessionTerminationCondition::ExceptCurrent(current_id) => session.id != *current_id,
                SessionTerminationCondition::OlderThan(cutoff) => session.created_at < *cutoff,
                SessionTerminationCondition::SecurityLevelBelow(level) => session.security_level < *level,
                SessionTerminationCondition::SuspiciousOnly => session.flags.is_suspicious,
                SessionTerminationCondition::DeviceType(device_type) => session.device_info.device_type == *device_type,
            };

            if should_terminate {
                if self.service.terminate_session(&session.id, reason.clone()).await.is_ok() {
                    terminated_count += 1;
                }
            }
        }

        Ok(terminated_count)
    }

    /// Get detailed session analytics
    pub async fn get_session_analytics(&self, user_id: &str) -> Result<SessionAnalytics> {
        let sessions = self.service.get_user_sessions(user_id).await?;
        
        let total_sessions = sessions.len();
        let active_sessions = sessions
            .iter()
            .filter(|s| s.terminated_at.is_none() && s.expires_at > Utc::now())
            .count();

        let average_duration = if !sessions.is_empty() {
            let total_duration: Duration = sessions
                .iter()
                .map(|s| {
                    let end_time = s.terminated_at.unwrap_or(Utc::now());
                    end_time - s.created_at
                })
                .sum();
            total_duration / sessions.len() as i32
        } else {
            Duration::zero()
        };

        let mut device_types = HashMap::new();
        let mut locations = HashMap::new();
        let mut security_levels = HashMap::new();

        for session in &sessions {
            *device_types.entry(session.device_info.device_type.clone()).or_insert(0) += 1;
            *security_levels.entry(session.security_level.clone()).or_insert(0) += 1;
            
            if let Some(location) = &session.location {
                if let Some(country) = &location.country {
                    *locations.entry(country.clone()).or_insert(0) += 1;
                }
            }
        }

        Ok(SessionAnalytics {
            total_sessions,
            active_sessions,
            average_session_duration: average_duration,
            device_types,
            locations,
            security_levels,
            most_recent_session: sessions.iter().max_by_key(|s| s.created_at).cloned(),
        })
    }

    /// Determine security level for new session
    fn determine_security_level(&self, request: &CreateSessionRequest, is_new_device: bool) -> Result<SecurityLevel> {
        let mut level = request.security_level.clone();

        // Upgrade security level based on risk factors
        if is_new_device && self.config.require_mfa_for_new_devices {
            level = level.max(SecurityLevel::Medium);
        }

        if request.mfa_verified {
            level = level.max(SecurityLevel::Medium);
        }

        if request.trusted_device {
            level = level.max(SecurityLevel::High);
        }

        Ok(level)
    }

    /// Determine session flags
    fn determine_session_flags(&self, request: &CreateSessionRequest, is_new_device: bool) -> super::SessionFlags {
        let mut flags = default_session_flags();

        flags.requires_mfa = is_new_device && self.config.require_mfa_for_new_devices;
        flags.is_suspicious = false; // Will be set by security analysis

        flags
    }

    /// Generate refresh token
    fn generate_refresh_token(&self) -> String {
        use uuid::Uuid;
        format!("refresh_{}", Uuid::new_v4())
    }

    /// Generate access token (placeholder - integrate with JWT system)
    fn generate_access_token(&self, user_id: &str) -> Result<String> {
        use uuid::Uuid;
        // TODO: Integrate with existing JWT token generation
        Ok(format!("access_{}_{}", user_id, Uuid::new_v4()))
    }

    /// Resolve IP address to location (placeholder)
    async fn resolve_location(&self, ip_address: &str) -> Result<SessionLocation> {
        // TODO: Integrate with GeoIP service
        Ok(SessionLocation {
            country: Some("Unknown".to_string()),
            region: None,
            city: None,
            latitude: None,
            longitude: None,
            timezone: None,
            isp: None,
            is_vpn: None,
            is_proxy: None,
        })
    }
}

/// Session termination conditions
#[derive(Debug, Clone)]
pub enum SessionTerminationCondition {
    All,
    ExceptCurrent(String),
    OlderThan(DateTime<Utc>),
    SecurityLevelBelow(SecurityLevel),
    SuspiciousOnly,
    DeviceType(super::DeviceType),
}

/// Session analytics data
#[derive(Debug, Clone)]
pub struct SessionAnalytics {
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub average_session_duration: Duration,
    pub device_types: HashMap<super::DeviceType, u32>,
    pub locations: HashMap<String, u32>,
    pub security_levels: HashMap<SecurityLevel, u32>,
    pub most_recent_session: Option<Session>,
}

/// Session cleanup service for expired sessions
pub struct SessionCleanupService<T: SessionService> {
    service: T,
}

impl<T: SessionService> SessionCleanupService<T> {
    pub fn new(service: T) -> Self {
        Self { service }
    }

    /// Run cleanup process
    pub async fn run_cleanup(&self) -> Result<SessionCleanupReport> {
        let start_time = Utc::now();
        
        // Clean up expired sessions
        let expired_count = self.service.cleanup_expired_sessions().await?;
        
        // Get current statistics
        let stats = self.service.get_session_statistics().await?;
        
        let end_time = Utc::now();
        
        Ok(SessionCleanupReport {
            cleanup_start: start_time,
            cleanup_end: end_time,
            expired_sessions_removed: expired_count,
            total_active_sessions: stats.total_active_sessions,
            cleanup_duration: end_time - start_time,
        })
    }
}

/// Session cleanup report
#[derive(Debug, Clone)]
pub struct SessionCleanupReport {
    pub cleanup_start: DateTime<Utc>,
    pub cleanup_end: DateTime<Utc>,
    pub expired_sessions_removed: u64,
    pub total_active_sessions: u64,
    pub cleanup_duration: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{DeviceType, SessionFlags};

    #[tokio::test]
    async fn test_session_termination_conditions() {
        let condition = SessionTerminationCondition::SecurityLevelBelow(SecurityLevel::High);
        
        // Test would require mock service implementation
        // This is a placeholder for actual test implementation
        assert!(matches!(condition, SessionTerminationCondition::SecurityLevelBelow(_)));
    }

    #[test]
    fn test_security_level_determination() {
        let request = CreateSessionRequest {
            user_id: "user123".to_string(),
            ip_address: "192.168.1.1".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            device_fingerprint: "fp123".to_string(),
            security_level: SecurityLevel::Low,
            mfa_verified: true,
            trusted_device: false,
            session_duration: None,
        };

        let config = SessionConfig::default();
        let mock_service = MockSessionService;
        let manager = SessionManager::new(mock_service, config);
        
        let level = manager.determine_security_level(&request, false).unwrap();
        assert!(level >= SecurityLevel::Medium); // MFA verified should upgrade
    }

    // Mock service for testing
    struct MockSessionService;

    #[async_trait::async_trait]
    impl SessionService for MockSessionService {
        async fn create_session(&self, _request: CreateSessionRequest) -> Result<Session> { unimplemented!() }
        async fn get_session(&self, _session_id: &str) -> Result<Option<Session>> { unimplemented!() }
        async fn update_session(&self, _session_id: &str, _session: Session) -> Result<Session> { unimplemented!() }
        async fn terminate_session(&self, _session_id: &str, _reason: TerminationReason) -> Result<bool> { unimplemented!() }
        async fn validate_session(&self, _session_id: &str, _ip_address: &str, _user_agent: &str) -> Result<SessionValidationResult> { unimplemented!() }
        async fn refresh_session(&self, _session_id: &str) -> Result<Session> { unimplemented!() }
        async fn get_user_sessions(&self, _user_id: &str) -> Result<Vec<Session>> { unimplemented!() }
        async fn terminate_user_sessions(&self, _user_id: &str, _reason: TerminationReason) -> Result<u64> { unimplemented!() }
        async fn get_device_sessions(&self, _device_id: &str) -> Result<Vec<Session>> { unimplemented!() }
        async fn trust_device(&self, _device_id: &str, _user_id: &str) -> Result<bool> { unimplemented!() }
        async fn untrust_device(&self, _device_id: &str, _user_id: &str) -> Result<bool> { unimplemented!() }
        async fn get_session_statistics(&self) -> Result<SessionStatistics> { unimplemented!() }
        async fn cleanup_expired_sessions(&self) -> Result<u64> { unimplemented!() }
        async fn emergency_logout_all(&self, _reason: TerminationReason) -> Result<u64> { unimplemented!() }
    }
}