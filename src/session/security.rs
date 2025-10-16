use super::{SecurityWarning, SecurityWarningType, Session, SessionService, WarningSevertiy};
use anyhow::Result;
use chrono::{DateTime, Duration, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Security policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub max_failed_attempts: u32,
    pub lockout_duration: Duration,
    pub password_expiry_days: u32,
    pub require_mfa_after_days: u32,
    pub max_concurrent_sessions: u32,
    pub suspicious_activity_threshold: f64,
    pub enable_rate_limiting: bool,
    pub enable_geolocation_blocking: bool,
    pub allowed_countries: Option<HashSet<String>>,
    pub blocked_ips: HashSet<String>,
    pub require_device_verification: bool,
    pub session_timeout_warning_minutes: u32,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            max_failed_attempts: 5,
            lockout_duration: Duration::minutes(15),
            password_expiry_days: 90,
            require_mfa_after_days: 30,
            max_concurrent_sessions: 10,
            suspicious_activity_threshold: 0.7,
            enable_rate_limiting: true,
            enable_geolocation_blocking: false,
            allowed_countries: None,
            blocked_ips: HashSet::new(),
            require_device_verification: true,
            session_timeout_warning_minutes: 5,
        }
    }
}

/// Security event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityEventType {
    LoginSuccess,
    LoginFailure,
    PasswordChange,
    MfaEnabled,
    MfaDisabled,
    SuspiciousLogin,
    AccountLockout,
    SessionTermination,
    DeviceRegistration,
    PermissionElevation,
    DataExport,
    PasswordReset,
    EmailChange,
    PhoneChange,
    UnusualActivity,
}

/// Security event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub user_id: String,
    pub event_type: SecurityEventType,
    pub description: String,
    pub severity: WarningSevertiy,
    pub ip_address: String,
    pub user_agent: String,
    pub device_id: Option<String>,
    pub session_id: Option<String>,
    pub location: Option<super::SessionLocation>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub timestamp: DateTime<Utc>,
    pub resolved: bool,
    pub resolution_notes: Option<String>,
}

/// Threat detection system
pub struct ThreatDetector {
    policy: SecurityPolicy,
    anomaly_threshold: f64,
}

impl ThreatDetector {
    /// Create new threat detector
    pub fn new(policy: SecurityPolicy) -> Self {
        Self {
            policy,
            anomaly_threshold: 0.8,
        }
    }

    /// Analyze session for security threats
    pub async fn analyze_session(&self, session: &Session) -> Result<ThreatAnalysisResult> {
        let mut threats = Vec::new();
        let mut risk_score = 0.0;

        // Check for unusual location
        if let Some(location) = &session.location {
            if let Some(risk) = self
                .analyze_location_risk(location, &session.user_id)
                .await?
            {
                threats.push(risk.clone());
                risk_score += risk.risk_score;
            }
        }

        // Check for unusual timing
        if let Some(risk) = self.analyze_timing_risk(session).await? {
            threats.push(risk.clone());
            risk_score += risk.risk_score;
        }

        // Check for device anomalies
        if let Some(risk) = self
            .analyze_device_risk(&session.device_info, &session.user_id)
            .await?
        {
            threats.push(risk.clone());
            risk_score += risk.risk_score;
        }

        // Check for concurrent session anomalies
        if let Some(risk) = self.analyze_concurrent_sessions(&session.user_id).await? {
            threats.push(risk.clone());
            risk_score += risk.risk_score;
        }

        let threat_level = self.calculate_threat_level(risk_score);
        let recommended_actions = self.get_recommended_actions(&threat_level, &threats);

        Ok(ThreatAnalysisResult {
            risk_score,
            threat_level,
            threats,
            recommended_actions,
            analysis_timestamp: Utc::now(),
        })
    }

    /// Analyze location-based risk
    async fn analyze_location_risk(
        &self,
        location: &super::SessionLocation,
        _user_id: &str,
    ) -> Result<Option<ThreatIndicator>> {
        // Check if country is allowed
        if let Some(allowed_countries) = &self.policy.allowed_countries {
            if let Some(country) = &location.country {
                if !allowed_countries.contains(country) {
                    return Ok(Some(ThreatIndicator {
                        indicator_type: ThreatType::UnauthorizedLocation,
                        description: format!("Login from unauthorized country: {}", country),
                        risk_score: 0.8,
                        evidence: vec![format!("Country: {}", country)],
                    }));
                }
            }
        }

        // Check for VPN/Proxy usage
        if location.is_vpn == Some(true) || location.is_proxy == Some(true) {
            return Ok(Some(ThreatIndicator {
                indicator_type: ThreatType::VpnOrProxy,
                description: "Login through VPN or proxy detected".to_string(),
                risk_score: 0.5,
                evidence: vec!["VPN/Proxy detected".to_string()],
            }));
        }

        // TODO: Check historical login locations for this user
        // This would require location history data

        Ok(None)
    }

    /// Analyze timing-based risk
    async fn analyze_timing_risk(&self, _session: &Session) -> Result<Option<ThreatIndicator>> {
        let now = Utc::now();
        let hour = now.time().hour();

        // Check for unusual login times (very early or very late)
        if hour < 6 || hour > 22 {
            return Ok(Some(ThreatIndicator {
                indicator_type: ThreatType::UnusualTiming,
                description: format!("Login at unusual hour: {}:00", hour),
                risk_score: 0.3,
                evidence: vec![format!("Login time: {}:00", hour)],
            }));
        }

        // TODO: Check user's typical login patterns
        // This would require historical login data

        Ok(None)
    }

    /// Analyze device-based risk
    async fn analyze_device_risk(
        &self,
        device_info: &super::DeviceInfo,
        _user_id: &str,
    ) -> Result<Option<ThreatIndicator>> {
        // Check for new device
        if !device_info.is_trusted {
            return Ok(Some(ThreatIndicator {
                indicator_type: ThreatType::NewDevice,
                description: "Login from new/untrusted device".to_string(),
                risk_score: 0.6,
                evidence: vec![
                    format!("Device type: {:?}", device_info.device_type),
                    format!("Device fingerprint: {}", device_info.fingerprint),
                ],
            }));
        }

        // Check for suspicious device characteristics
        if device_info.os.is_none() && device_info.browser.is_none() {
            return Ok(Some(ThreatIndicator {
                indicator_type: ThreatType::AnomalousDevice,
                description: "Device with missing OS/browser information".to_string(),
                risk_score: 0.4,
                evidence: vec!["Missing device information".to_string()],
            }));
        }

        Ok(None)
    }

    /// Analyze concurrent session patterns
    async fn analyze_concurrent_sessions(&self, _user_id: &str) -> Result<Option<ThreatIndicator>> {
        // TODO: Get actual concurrent sessions from service
        // For now, return None as placeholder
        Ok(None)
    }

    /// Calculate overall threat level
    fn calculate_threat_level(&self, risk_score: f64) -> ThreatLevel {
        if risk_score >= 0.8 {
            ThreatLevel::Critical
        } else if risk_score >= 0.6 {
            ThreatLevel::High
        } else if risk_score >= 0.4 {
            ThreatLevel::Medium
        } else if risk_score >= 0.2 {
            ThreatLevel::Low
        } else {
            ThreatLevel::Minimal
        }
    }

    /// Get recommended security actions
    fn get_recommended_actions(
        &self,
        threat_level: &ThreatLevel,
        threats: &[ThreatIndicator],
    ) -> Vec<SecurityRecommendation> {
        let mut actions = Vec::new();

        match threat_level {
            ThreatLevel::Critical => {
                actions.push(SecurityRecommendation::TerminateSession);
                actions.push(SecurityRecommendation::RequirePasswordChange);
                actions.push(SecurityRecommendation::EnableMfa);
                actions.push(SecurityRecommendation::ContactUser);
            }
            ThreatLevel::High => {
                actions.push(SecurityRecommendation::RequireMfa);
                actions.push(SecurityRecommendation::LimitSessionCapabilities);
                actions.push(SecurityRecommendation::MonitorClosely);
            }
            ThreatLevel::Medium => {
                actions.push(SecurityRecommendation::RequireDeviceVerification);
                actions.push(SecurityRecommendation::SendSecurityAlert);
            }
            ThreatLevel::Low => {
                actions.push(SecurityRecommendation::LogSecurityEvent);
            }
            ThreatLevel::Minimal => {
                // No action required
            }
        }

        // Add specific actions based on threat types
        for threat in threats {
            match threat.indicator_type {
                ThreatType::NewDevice => {
                    actions.push(SecurityRecommendation::RequireDeviceVerification);
                }
                ThreatType::UnauthorizedLocation => {
                    actions.push(SecurityRecommendation::RequireMfa);
                    actions.push(SecurityRecommendation::ContactUser);
                }
                ThreatType::VpnOrProxy => {
                    actions.push(SecurityRecommendation::RequireAdditionalVerification);
                }
                _ => {}
            }
        }

        actions
            .into_iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect()
    }
}

/// Threat analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAnalysisResult {
    pub risk_score: f64,
    pub threat_level: ThreatLevel,
    pub threats: Vec<ThreatIndicator>,
    pub recommended_actions: Vec<SecurityRecommendation>,
    pub analysis_timestamp: DateTime<Utc>,
}

/// Threat indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: ThreatType,
    pub description: String,
    pub risk_score: f64,
    pub evidence: Vec<String>,
}

/// Types of security threats
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThreatType {
    NewDevice,
    UnauthorizedLocation,
    VpnOrProxy,
    UnusualTiming,
    AnomalousDevice,
    ConcurrentSessions,
    RapidLocationChange,
    SuspiciousUserAgent,
    BruteForceAttempt,
    CredentialStuffing,
}

/// Threat severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    Minimal = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

/// Security recommendations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SecurityRecommendation {
    LogSecurityEvent,
    SendSecurityAlert,
    RequireMfa,
    RequireDeviceVerification,
    RequireAdditionalVerification,
    RequirePasswordChange,
    LimitSessionCapabilities,
    TerminateSession,
    EnableMfa,
    ContactUser,
    MonitorClosely,
    BlockIpAddress,
    EscalateToSecurity,
}

/// Rate limiting manager
pub struct RateLimiter {
    attempts: HashMap<String, AttemptCounter>,
    cleanup_interval: Duration,
}

impl RateLimiter {
    /// Create new rate limiter
    pub fn new() -> Self {
        Self {
            attempts: HashMap::new(),
            cleanup_interval: Duration::hours(1),
        }
    }

    /// Check if request should be rate limited
    pub fn check_rate_limit(&mut self, identifier: &str, limit: u32, window: Duration) -> bool {
        let now = Utc::now();

        // Clean up old entries
        self.cleanup_expired(now);

        let counter = self
            .attempts
            .entry(identifier.to_string())
            .or_insert_with(|| AttemptCounter::new(now));

        counter.add_attempt(now, window);
        counter.count <= limit
    }

    /// Record failed attempt
    pub fn record_failure(&mut self, identifier: &str) {
        let now = Utc::now();
        let counter = self
            .attempts
            .entry(identifier.to_string())
            .or_insert_with(|| AttemptCounter::new(now));

        counter.add_attempt(now, Duration::minutes(15));
    }

    /// Clean up expired counters
    fn cleanup_expired(&mut self, now: DateTime<Utc>) {
        self.attempts
            .retain(|_, counter| now - counter.window_start < self.cleanup_interval);
    }
}

/// Attempt counter for rate limiting
#[derive(Debug, Clone)]
struct AttemptCounter {
    count: u32,
    window_start: DateTime<Utc>,
    last_attempt: DateTime<Utc>,
}

impl AttemptCounter {
    fn new(now: DateTime<Utc>) -> Self {
        Self {
            count: 0,
            window_start: now,
            last_attempt: now,
        }
    }

    fn add_attempt(&mut self, now: DateTime<Utc>, window: Duration) {
        // Reset window if expired
        if now - self.window_start > window {
            self.count = 0;
            self.window_start = now;
        }

        self.count += 1;
        self.last_attempt = now;
    }
}

/// Security monitoring service
pub struct SecurityMonitor<T: SessionService> {
    session_service: T,
    threat_detector: ThreatDetector,
    rate_limiter: RateLimiter,
}

impl<T: SessionService> SecurityMonitor<T> {
    /// Create new security monitor
    pub fn new(session_service: T, policy: SecurityPolicy) -> Self {
        Self {
            session_service,
            threat_detector: ThreatDetector::new(policy),
            rate_limiter: RateLimiter::new(),
        }
    }

    /// Monitor session for security threats
    pub async fn monitor_session(&mut self, session: &Session) -> Result<SecurityMonitoringResult> {
        // Analyze threats
        let threat_analysis = self.threat_detector.analyze_session(session).await?;

        // Check rate limiting
        let rate_limit_exceeded = !self.rate_limiter.check_rate_limit(
            &session.user_id,
            10, // Max 10 requests per minute
            Duration::minutes(1),
        );

        // Generate security warnings
        let mut warnings = Vec::new();
        for threat in &threat_analysis.threats {
            warnings.push(SecurityWarning {
                warning_type: match threat.indicator_type {
                    ThreatType::NewDevice => SecurityWarningType::NewDevice,
                    ThreatType::UnauthorizedLocation => SecurityWarningType::UnusualLocation,
                    _ => SecurityWarningType::SuspiciousActivity,
                },
                message: threat.description.clone(),
                severity: match threat_analysis.threat_level {
                    ThreatLevel::Critical => WarningSevertiy::Critical,
                    ThreatLevel::High => WarningSevertiy::High,
                    ThreatLevel::Medium => WarningSevertiy::Medium,
                    ThreatLevel::Low => WarningSevertiy::Low,
                    ThreatLevel::Minimal => WarningSevertiy::Info,
                },
                triggered_at: Utc::now(),
            });
        }

        Ok(SecurityMonitoringResult {
            threat_analysis,
            rate_limit_exceeded,
            security_warnings: warnings,
            monitoring_timestamp: Utc::now(),
        })
    }

    /// Record security event
    pub async fn record_security_event(&self, event: SecurityEvent) -> Result<()> {
        // TODO: Store security event in database/log system
        println!("Security Event: {:?}", event);
        Ok(())
    }
}

/// Security monitoring result
#[derive(Debug, Clone)]
pub struct SecurityMonitoringResult {
    pub threat_analysis: ThreatAnalysisResult,
    pub rate_limit_exceeded: bool,
    pub security_warnings: Vec<SecurityWarning>,
    pub monitoring_timestamp: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_level_ordering() {
        assert!(ThreatLevel::Minimal < ThreatLevel::Low);
        assert!(ThreatLevel::Low < ThreatLevel::Medium);
        assert!(ThreatLevel::Medium < ThreatLevel::High);
        assert!(ThreatLevel::High < ThreatLevel::Critical);
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new();

        // Should allow first few attempts
        assert!(limiter.check_rate_limit("user1", 5, Duration::minutes(1)));
        assert!(limiter.check_rate_limit("user1", 5, Duration::minutes(1)));

        // Add more attempts
        for _ in 0..4 {
            limiter.record_failure("user1");
        }

        // Should now be rate limited
        assert!(!limiter.check_rate_limit("user1", 5, Duration::minutes(1)));
    }

    #[test]
    fn test_threat_detector_risk_calculation() {
        let policy = SecurityPolicy::default();
        let detector = ThreatDetector::new(policy);

        assert_eq!(detector.calculate_threat_level(0.1), ThreatLevel::Minimal);
        assert_eq!(detector.calculate_threat_level(0.3), ThreatLevel::Low);
        assert_eq!(detector.calculate_threat_level(0.5), ThreatLevel::Medium);
        assert_eq!(detector.calculate_threat_level(0.7), ThreatLevel::High);
        assert_eq!(detector.calculate_threat_level(0.9), ThreatLevel::Critical);
    }

    #[tokio::test]
    async fn test_location_risk_analysis() {
        let policy = SecurityPolicy {
            allowed_countries: Some(
                vec!["US".to_string(), "CA".to_string()]
                    .into_iter()
                    .collect(),
            ),
            ..SecurityPolicy::default()
        };

        let detector = ThreatDetector::new(policy);

        let unauthorized_location = super::super::SessionLocation {
            country: Some("CN".to_string()),
            region: None,
            city: None,
            latitude: None,
            longitude: None,
            timezone: None,
            isp: None,
            is_vpn: Some(false),
            is_proxy: Some(false),
        };

        let risk = detector
            .analyze_location_risk(&unauthorized_location, "user123")
            .await
            .unwrap();
        assert!(risk.is_some());
        assert_eq!(
            risk.unwrap().indicator_type,
            ThreatType::UnauthorizedLocation
        );
    }
}
