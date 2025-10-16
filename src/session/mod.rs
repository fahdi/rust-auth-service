use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

pub mod analytics;
pub mod device;
pub mod manager;
pub mod security;

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub device_id: String,
    pub refresh_token: String,
    pub access_token: String,
    pub ip_address: String,
    pub user_agent: String,
    pub device_info: DeviceInfo,
    pub location: Option<SessionLocation>,
    pub security_level: SecurityLevel,
    pub flags: SessionFlags,
    pub metadata: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub last_accessed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub terminated_at: Option<DateTime<Utc>>,
    pub termination_reason: Option<TerminationReason>,
}

/// Device information associated with a session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub device_name: Option<String>,
    pub device_type: DeviceType,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub browser: Option<String>,
    pub browser_version: Option<String>,
    pub is_mobile: bool,
    pub is_trusted: bool,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub fingerprint: String,
}

/// Device type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DeviceType {
    Desktop,
    Mobile,
    Tablet,
    SmartTV,
    GameConsole,
    IoT,
    Unknown,
}

/// Session location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionLocation {
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
    pub isp: Option<String>,
    pub is_vpn: Option<bool>,
    pub is_proxy: Option<bool>,
}

/// Session security level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SecurityLevel {
    Low = 1,     // Basic authentication
    Medium = 2,  // Two-factor authentication
    High = 3,    // Multi-factor + trusted device
    Maximum = 4, // Hardware security key + biometric
}

/// Session security flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionFlags {
    pub is_suspicious: bool,
    pub is_concurrent: bool,
    pub requires_mfa: bool,
    pub is_elevated: bool,
    pub is_impersonated: bool,
    pub force_logout: bool,
    pub readonly_mode: bool,
}

/// Session termination reason
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub enum TerminationReason {
    UserLogout,
    AdminLogout,
    Expired,
    Replaced,
    SecurityViolation,
    ConcurrentLoginLimit,
    PasswordChanged,
    AccountSuspended,
    PolicyViolation,
    SystemMaintenance,
}

/// Session creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    pub user_id: String,
    pub ip_address: String,
    pub user_agent: String,
    pub device_fingerprint: String,
    pub security_level: SecurityLevel,
    pub mfa_verified: bool,
    pub trusted_device: bool,
    pub session_duration: Option<Duration>,
}

/// Session validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionValidationResult {
    pub is_valid: bool,
    pub session: Option<Session>,
    pub security_warnings: Vec<SecurityWarning>,
    pub actions_required: Vec<SecurityAction>,
}

/// Security warning for session validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityWarning {
    pub warning_type: SecurityWarningType,
    pub message: String,
    pub severity: WarningSevertiy,
    pub triggered_at: DateTime<Utc>,
}

/// Security warning types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityWarningType {
    UnusualLocation,
    NewDevice,
    SuspiciousActivity,
    ConcurrentSessions,
    WeakSecurity,
    ExpiredCredentials,
    PolicyViolation,
}

/// Warning severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum WarningSevertiy {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Required security actions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityAction {
    RequireMFA,
    RequirePasswordChange,
    RequireDeviceVerification,
    RequireSecurityQuestions,
    LimitSessionCapabilities,
    ForceLogout,
    ContactSupport,
}

/// Session statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatistics {
    pub total_active_sessions: u64,
    pub total_sessions_today: u64,
    pub total_sessions_this_week: u64,
    pub total_sessions_this_month: u64,
    pub average_session_duration: Duration,
    pub concurrent_sessions_by_user: HashMap<String, u64>,
    pub sessions_by_device_type: HashMap<DeviceType, u64>,
    pub sessions_by_security_level: HashMap<SecurityLevel, u64>,
    pub suspicious_sessions: u64,
    pub terminated_sessions: HashMap<TerminationReason, u64>,
}

/// Session service trait for session management operations
#[async_trait::async_trait]
pub trait SessionService: Send + Sync {
    /// Create a new session
    async fn create_session(&self, request: CreateSessionRequest) -> Result<Session>;

    /// Get session by ID
    async fn get_session(&self, session_id: &str) -> Result<Option<Session>>;

    /// Update session information
    async fn update_session(&self, session_id: &str, session: Session) -> Result<Session>;

    /// Terminate session
    async fn terminate_session(&self, session_id: &str, reason: TerminationReason) -> Result<bool>;

    /// Validate session and check security
    async fn validate_session(
        &self,
        session_id: &str,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<SessionValidationResult>;

    /// Refresh session tokens
    async fn refresh_session(&self, session_id: &str) -> Result<Session>;

    /// Get all active sessions for a user
    async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<Session>>;

    /// Terminate all sessions for a user
    async fn terminate_user_sessions(
        &self,
        user_id: &str,
        reason: TerminationReason,
    ) -> Result<u64>;

    /// Get sessions by device
    async fn get_device_sessions(&self, device_id: &str) -> Result<Vec<Session>>;

    /// Mark device as trusted
    async fn trust_device(&self, device_id: &str, user_id: &str) -> Result<bool>;

    /// Mark device as untrusted
    async fn untrust_device(&self, device_id: &str, user_id: &str) -> Result<bool>;

    /// Get session statistics
    async fn get_session_statistics(&self) -> Result<SessionStatistics>;

    /// Clean up expired sessions
    async fn cleanup_expired_sessions(&self) -> Result<u64>;

    /// Force logout all sessions for security
    async fn emergency_logout_all(&self, reason: TerminationReason) -> Result<u64>;
}

/// Session configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub default_session_duration: Duration,
    pub max_session_duration: Duration,
    pub max_concurrent_sessions_per_user: u32,
    pub max_concurrent_sessions_per_device: u32,
    pub session_cleanup_interval: Duration,
    pub require_mfa_for_new_devices: bool,
    pub auto_trust_same_location: bool,
    pub suspicious_location_threshold_km: f64,
    pub enable_device_fingerprinting: bool,
    pub enable_location_tracking: bool,
    pub enable_security_analytics: bool,
    pub force_logout_on_password_change: bool,
    pub force_logout_on_role_change: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            default_session_duration: Duration::hours(8),
            max_session_duration: Duration::days(30),
            max_concurrent_sessions_per_user: 10,
            max_concurrent_sessions_per_device: 5,
            session_cleanup_interval: Duration::hours(1),
            require_mfa_for_new_devices: true,
            auto_trust_same_location: false,
            suspicious_location_threshold_km: 100.0,
            enable_device_fingerprinting: true,
            enable_location_tracking: true,
            enable_security_analytics: true,
            force_logout_on_password_change: true,
            force_logout_on_role_change: true,
        }
    }
}

/// Create a new session ID
pub fn generate_session_id() -> String {
    format!("sess_{}", Uuid::new_v4())
}

/// Create device fingerprint from user agent and other factors
pub fn generate_device_fingerprint(user_agent: &str, additional_data: &[&str]) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(user_agent.as_bytes());

    for data in additional_data {
        hasher.update(data.as_bytes());
    }

    format!("{:x}", hasher.finalize())
}

/// Parse user agent to extract device information
pub fn parse_user_agent(user_agent: &str) -> DeviceInfo {
    let device_id = generate_device_fingerprint(user_agent, &[]);
    let now = Utc::now();

    // Basic user agent parsing (in production, use a proper user agent parser)
    let is_mobile = user_agent.to_lowercase().contains("mobile")
        || user_agent.to_lowercase().contains("android")
        || user_agent.to_lowercase().contains("iphone");

    let device_type = if is_mobile {
        if user_agent.to_lowercase().contains("tablet")
            || user_agent.to_lowercase().contains("ipad")
        {
            DeviceType::Tablet
        } else {
            DeviceType::Mobile
        }
    } else if user_agent.to_lowercase().contains("tv") {
        DeviceType::SmartTV
    } else {
        DeviceType::Desktop
    };

    // Extract OS information
    let os = if user_agent.contains("Windows") {
        Some("Windows".to_string())
    } else if user_agent.contains("Mac OS") {
        Some("macOS".to_string())
    } else if user_agent.contains("Linux") {
        Some("Linux".to_string())
    } else if user_agent.contains("Android") {
        Some("Android".to_string())
    } else if user_agent.contains("iOS") || user_agent.contains("iPhone") {
        Some("iOS".to_string())
    } else {
        None
    };

    // Extract browser information
    let browser = if user_agent.contains("Chrome") {
        Some("Chrome".to_string())
    } else if user_agent.contains("Firefox") {
        Some("Firefox".to_string())
    } else if user_agent.contains("Safari") && !user_agent.contains("Chrome") {
        Some("Safari".to_string())
    } else if user_agent.contains("Edge") {
        Some("Edge".to_string())
    } else {
        None
    };

    DeviceInfo {
        device_id: device_id.clone(),
        device_name: None,
        device_type,
        os,
        os_version: None,
        browser,
        browser_version: None,
        is_mobile,
        is_trusted: false,
        first_seen_at: now,
        last_seen_at: now,
        fingerprint: device_id,
    }
}

/// Calculate distance between two geographic points (Haversine formula)
pub fn calculate_distance_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let r = 6371.0; // Earth's radius in kilometers

    let d_lat = (lat2 - lat1).to_radians();
    let d_lon = (lon2 - lon1).to_radians();

    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();

    let a =
        (d_lat / 2.0).sin().powi(2) + lat1_rad.cos() * lat2_rad.cos() * (d_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

    r * c
}

/// Default session flags for new sessions
pub fn default_session_flags() -> SessionFlags {
    SessionFlags {
        is_suspicious: false,
        is_concurrent: false,
        requires_mfa: false,
        is_elevated: false,
        is_impersonated: false,
        force_logout: false,
        readonly_mode: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_session_id() {
        let id = generate_session_id();
        assert!(id.starts_with("sess_"));
        assert_eq!(id.len(), 41); // "sess_" + UUID length
    }

    #[test]
    fn test_generate_device_fingerprint() {
        let fingerprint1 = generate_device_fingerprint("Mozilla/5.0", &["additional"]);
        let fingerprint2 = generate_device_fingerprint("Mozilla/5.0", &["different"]);

        assert_ne!(fingerprint1, fingerprint2);
        assert_eq!(fingerprint1.len(), 64); // SHA256 hex length
    }

    #[test]
    fn test_parse_user_agent() {
        let mobile_ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)";
        let device = parse_user_agent(mobile_ua);

        assert!(device.is_mobile);
        assert_eq!(device.device_type, DeviceType::Mobile);
        assert_eq!(device.os, Some("iOS".to_string()));
    }

    #[test]
    fn test_calculate_distance() {
        // Distance between New York and Los Angeles (approximately 3944 km)
        let distance = calculate_distance_km(40.7128, -74.0060, 34.0522, -118.2437);
        assert!((distance - 3944.0).abs() < 100.0); // Allow 100km tolerance
    }

    #[test]
    fn test_security_level_ordering() {
        assert!(SecurityLevel::Low < SecurityLevel::Medium);
        assert!(SecurityLevel::Medium < SecurityLevel::High);
        assert!(SecurityLevel::High < SecurityLevel::Maximum);
    }
}
