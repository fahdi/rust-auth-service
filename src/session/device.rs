use super::{DeviceInfo, DeviceType, SessionService};
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Device management service
pub struct DeviceManager<T: SessionService> {
    session_service: T,
    config: DeviceConfig,
}

impl<T: SessionService> DeviceManager<T> {
    /// Create new device manager
    pub fn new(session_service: T, config: DeviceConfig) -> Self {
        Self {
            session_service,
            config,
        }
    }

    /// Register a new device
    pub async fn register_device(
        &self,
        request: DeviceRegistrationRequest,
    ) -> Result<RegisteredDevice> {
        let device_id = super::generate_device_fingerprint(
            &request.user_agent,
            &[
                &request.ip_address,
                &request.additional_fingerprint_data.unwrap_or_default(),
            ],
        );

        let device_info = super::parse_user_agent(&request.user_agent);

        let registered_device = RegisteredDevice {
            device_id: device_id.clone(),
            user_id: request.user_id.clone(),
            device_name: request
                .device_name
                .or_else(|| self.generate_device_name(&device_info)),
            device_info,
            trust_level: if request.auto_trust {
                DeviceTrustLevel::Trusted
            } else {
                DeviceTrustLevel::Pending
            },
            registration_method: request.registration_method,
            registered_at: Utc::now(),
            last_used_at: Utc::now(),
            location_at_registration: request.location,
            verification_status: DeviceVerificationStatus::Pending,
            verification_token: Some(self.generate_verification_token()),
            verification_expires_at: Some(Utc::now() + Duration::hours(24)),
            metadata: request.metadata.unwrap_or_default(),
        };

        // TODO: Store device in database
        Ok(registered_device)
    }

    /// Verify a device using verification token
    pub async fn verify_device(&self, _device_id: &str, _verification_token: &str) -> Result<bool> {
        // TODO: Implement device verification logic
        // This would:
        // 1. Look up device by ID
        // 2. Check verification token
        // 3. Update verification status
        // 4. Set trust level appropriately

        Ok(true) // Placeholder
    }

    /// Trust a device for a user
    pub async fn trust_device(&self, device_id: &str, user_id: &str) -> Result<bool> {
        self.session_service.trust_device(device_id, user_id).await
    }

    /// Untrust a device
    pub async fn untrust_device(&self, device_id: &str, user_id: &str) -> Result<bool> {
        self.session_service
            .untrust_device(device_id, user_id)
            .await
    }

    /// Get all devices for a user
    pub async fn get_user_devices(&self, _user_id: &str) -> Result<Vec<RegisteredDevice>> {
        // TODO: Implement device lookup by user
        // This would query the database for all devices registered to the user
        Ok(vec![]) // Placeholder
    }

    /// Analyze device for security risks
    pub async fn analyze_device_security(
        &self,
        device_info: &DeviceInfo,
        _user_id: &str,
    ) -> Result<DeviceSecurityAnalysis> {
        let mut risk_factors = Vec::new();
        let mut risk_score = 0.0;

        // Check device age
        let device_age = Utc::now() - device_info.first_seen_at;
        if device_age < Duration::days(1) {
            risk_factors.push(DeviceRiskFactor {
                factor_type: DeviceRiskType::NewDevice,
                description: "Device is very new".to_string(),
                risk_score: 0.6,
            });
            risk_score += 0.6;
        }

        // Check if device has unusual characteristics
        if device_info.os.is_none() || device_info.browser.is_none() {
            risk_factors.push(DeviceRiskFactor {
                factor_type: DeviceRiskType::MissingInformation,
                description: "Device missing OS or browser information".to_string(),
                risk_score: 0.4,
            });
            risk_score += 0.4;
        }

        // Check device type patterns
        match device_info.device_type {
            DeviceType::Unknown => {
                risk_factors.push(DeviceRiskFactor {
                    factor_type: DeviceRiskType::UnknownDeviceType,
                    description: "Unknown device type".to_string(),
                    risk_score: 0.3,
                });
                risk_score += 0.3;
            }
            DeviceType::IoT => {
                risk_factors.push(DeviceRiskFactor {
                    factor_type: DeviceRiskType::IoTDevice,
                    description: "IoT device may have security vulnerabilities".to_string(),
                    risk_score: 0.5,
                });
                risk_score += 0.5;
            }
            _ => {}
        }

        // Check if device is trusted
        if !device_info.is_trusted {
            risk_factors.push(DeviceRiskFactor {
                factor_type: DeviceRiskType::UntrustedDevice,
                description: "Device is not trusted".to_string(),
                risk_score: 0.4,
            });
            risk_score += 0.4;
        }

        let security_level = self.calculate_device_security_level(risk_score);
        let recommendations =
            self.get_device_security_recommendations(&security_level, &risk_factors);

        Ok(DeviceSecurityAnalysis {
            device_id: device_info.device_id.clone(),
            risk_score,
            security_level,
            risk_factors,
            recommendations,
            analysis_timestamp: Utc::now(),
        })
    }

    /// Generate device statistics
    pub async fn get_device_statistics(&self, user_id: &str) -> Result<DeviceStatistics> {
        let devices = self.get_user_devices(user_id).await?;

        let total_devices = devices.len();
        let trusted_devices = devices
            .iter()
            .filter(|d| d.trust_level == DeviceTrustLevel::Trusted)
            .count();
        let verified_devices = devices
            .iter()
            .filter(|d| d.verification_status == DeviceVerificationStatus::Verified)
            .count();

        let mut device_types = HashMap::new();
        for device in &devices {
            *device_types
                .entry(device.device_info.device_type.clone())
                .or_insert(0) += 1;
        }

        let most_recent_device = devices.iter().max_by_key(|d| d.last_used_at).cloned();

        Ok(DeviceStatistics {
            total_devices,
            trusted_devices,
            verified_devices,
            device_types,
            most_recent_device,
            oldest_device: devices.iter().min_by_key(|d| d.registered_at).cloned(),
        })
    }

    /// Remove old/unused devices
    pub async fn cleanup_old_devices(&self, user_id: &str) -> Result<u32> {
        let devices = self.get_user_devices(user_id).await?;
        let cutoff = Utc::now() - self.config.device_retention_period;

        let mut removed_count = 0;
        for device in devices {
            if device.last_used_at < cutoff && device.trust_level != DeviceTrustLevel::Trusted {
                // TODO: Remove device from database
                removed_count += 1;
            }
        }

        Ok(removed_count)
    }

    /// Generate device name from device info
    fn generate_device_name(&self, device_info: &DeviceInfo) -> Option<String> {
        match &device_info.device_type {
            DeviceType::Desktop => {
                if let Some(os) = &device_info.os {
                    Some(format!("{} Desktop", os))
                } else {
                    Some("Desktop Computer".to_string())
                }
            }
            DeviceType::Mobile => {
                if let Some(os) = &device_info.os {
                    Some(format!("{} Phone", os))
                } else {
                    Some("Mobile Phone".to_string())
                }
            }
            DeviceType::Tablet => {
                if let Some(os) = &device_info.os {
                    Some(format!("{} Tablet", os))
                } else {
                    Some("Tablet".to_string())
                }
            }
            DeviceType::SmartTV => Some("Smart TV".to_string()),
            DeviceType::GameConsole => Some("Game Console".to_string()),
            DeviceType::IoT => Some("IoT Device".to_string()),
            DeviceType::Unknown => Some("Unknown Device".to_string()),
        }
    }

    /// Generate verification token
    fn generate_verification_token(&self) -> String {
        use uuid::Uuid;
        format!("verify_{value}"), Uuid::new_v4())
    }

    /// Calculate device security level
    fn calculate_device_security_level(&self, risk_score: f64) -> DeviceSecurityLevel {
        if risk_score >= 0.8 {
            DeviceSecurityLevel::High
        } else if risk_score >= 0.5 {
            DeviceSecurityLevel::Medium
        } else {
            DeviceSecurityLevel::Low
        }
    }

    /// Get device security recommendations
    fn get_device_security_recommendations(
        &self,
        security_level: &DeviceSecurityLevel,
        risk_factors: &[DeviceRiskFactor],
    ) -> Vec<DeviceSecurityRecommendation> {
        let mut recommendations = Vec::new();

        match security_level {
            DeviceSecurityLevel::High => {
                recommendations.push(DeviceSecurityRecommendation::RequireVerification);
                recommendations.push(DeviceSecurityRecommendation::RequireMfa);
                recommendations.push(DeviceSecurityRecommendation::LimitAccess);
            }
            DeviceSecurityLevel::Medium => {
                recommendations.push(DeviceSecurityRecommendation::RequireVerification);
                recommendations.push(DeviceSecurityRecommendation::MonitorActivity);
            }
            DeviceSecurityLevel::Low => {
                recommendations.push(DeviceSecurityRecommendation::AllowNormalAccess);
            }
        }

        // Add specific recommendations based on risk factors
        for risk_factor in risk_factors {
            match risk_factor.factor_type {
                DeviceRiskType::NewDevice => {
                    recommendations.push(DeviceSecurityRecommendation::RequireVerification);
                }
                DeviceRiskType::UntrustedDevice => {
                    recommendations.push(DeviceSecurityRecommendation::RequireMfa);
                }
                DeviceRiskType::IoTDevice => {
                    recommendations.push(DeviceSecurityRecommendation::LimitAccess);
                    recommendations.push(DeviceSecurityRecommendation::MonitorActivity);
                }
                _ => {}
            }
        }

        recommendations
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }
}

/// Device registration request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistrationRequest {
    pub user_id: String,
    pub ip_address: String,
    pub user_agent: String,
    pub device_name: Option<String>,
    pub registration_method: DeviceRegistrationMethod,
    pub auto_trust: bool,
    pub location: Option<super::SessionLocation>,
    pub additional_fingerprint_data: Option<String>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Device registration methods
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceRegistrationMethod {
    FirstLogin,
    ManualRegistration,
    TrustedDevice,
    AdminApproval,
    EmailVerification,
    SmsVerification,
}

/// Registered device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredDevice {
    pub device_id: String,
    pub user_id: String,
    pub device_name: Option<String>,
    pub device_info: DeviceInfo,
    pub trust_level: DeviceTrustLevel,
    pub registration_method: DeviceRegistrationMethod,
    pub registered_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub location_at_registration: Option<super::SessionLocation>,
    pub verification_status: DeviceVerificationStatus,
    pub verification_token: Option<String>,
    pub verification_expires_at: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Device trust levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceTrustLevel {
    Untrusted,
    Pending,
    Trusted,
    HighlyTrusted,
}

/// Device verification status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceVerificationStatus {
    Pending,
    Verified,
    Failed,
    Expired,
}

/// Device security analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSecurityAnalysis {
    pub device_id: String,
    pub risk_score: f64,
    pub security_level: DeviceSecurityLevel,
    pub risk_factors: Vec<DeviceRiskFactor>,
    pub recommendations: Vec<DeviceSecurityRecommendation>,
    pub analysis_timestamp: DateTime<Utc>,
}

/// Device security levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceSecurityLevel {
    Low,
    Medium,
    High,
}

/// Device risk factors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRiskFactor {
    pub factor_type: DeviceRiskType,
    pub description: String,
    pub risk_score: f64,
}

/// Types of device security risks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceRiskType {
    NewDevice,
    UntrustedDevice,
    MissingInformation,
    UnknownDeviceType,
    IoTDevice,
    OutdatedSoftware,
    RootedOrJailbroken,
    EmulatorDetected,
}

/// Device security recommendations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DeviceSecurityRecommendation {
    AllowNormalAccess,
    RequireVerification,
    RequireMfa,
    LimitAccess,
    MonitorActivity,
    BlockDevice,
    RequireUpdate,
    ContactUser,
}

/// Device configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub max_devices_per_user: u32,
    pub device_retention_period: Duration,
    pub require_verification_for_new_devices: bool,
    pub auto_trust_same_network: bool,
    pub enable_device_fingerprinting: bool,
    pub verification_token_expiry: Duration,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            max_devices_per_user: 20,
            device_retention_period: Duration::days(365),
            require_verification_for_new_devices: true,
            auto_trust_same_network: false,
            enable_device_fingerprinting: true,
            verification_token_expiry: Duration::hours(24),
        }
    }
}

/// Device statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStatistics {
    pub total_devices: usize,
    pub trusted_devices: usize,
    pub verified_devices: usize,
    pub device_types: HashMap<DeviceType, u32>,
    pub most_recent_device: Option<RegisteredDevice>,
    pub oldest_device: Option<RegisteredDevice>,
}

/// Device fingerprinting service
pub struct DeviceFingerprintingService {
    config: DeviceConfig,
}

impl DeviceFingerprintingService {
    /// Create new fingerprinting service
    pub fn new(config: DeviceConfig) -> Self {
        Self { config }
    }

    /// Generate enhanced device fingerprint
    pub fn generate_enhanced_fingerprint(&self, request: &EnhancedFingerprintRequest) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        // Basic browser fingerprinting
        hasher.update(request.user_agent.as_bytes());
        hasher.update(request.screen_resolution.as_bytes());
        hasher.update(request.timezone.as_bytes());
        hasher.update(request.language.as_bytes());

        // Optional canvas fingerprinting
        if let Some(canvas) = &request.canvas_fingerprint {
            hasher.update(canvas.as_bytes());
        }

        // Optional WebGL fingerprinting
        if let Some(webgl) = &request.webgl_fingerprint {
            hasher.update(webgl.as_bytes());
        }

        // Browser features
        for feature in &request.browser_features {
            hasher.update(feature.as_bytes());
        }

        format!("{:x}", hasher.finalize())
    }

    /// Analyze fingerprint for suspicious characteristics
    pub fn analyze_fingerprint(&self, fingerprint: &str, user_agent: &str) -> FingerprintAnalysis {
        let mut suspicious_indicators = Vec::new();
        let mut risk_score = 0.0;

        // Check for common bot/automation indicators
        if user_agent.contains("HeadlessChrome") || user_agent.contains("PhantomJS") {
            suspicious_indicators.push("Headless browser detected".to_string());
            risk_score += 0.8;
        }

        // Check for missing typical browser features
        if fingerprint.len() < 32 {
            suspicious_indicators.push("Unusually short fingerprint".to_string());
            risk_score += 0.4;
        }

        let is_suspicious = risk_score > 0.5;

        FingerprintAnalysis {
            fingerprint: fingerprint.to_string(),
            is_suspicious,
            risk_score,
            suspicious_indicators,
            analysis_timestamp: Utc::now(),
        }
    }
}

/// Enhanced fingerprint request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedFingerprintRequest {
    pub user_agent: String,
    pub screen_resolution: String,
    pub timezone: String,
    pub language: String,
    pub canvas_fingerprint: Option<String>,
    pub webgl_fingerprint: Option<String>,
    pub browser_features: Vec<String>,
}

/// Fingerprint analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintAnalysis {
    pub fingerprint: String,
    pub is_suspicious: bool,
    pub risk_score: f64,
    pub suspicious_indicators: Vec<String>,
    pub analysis_timestamp: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_trust_levels() {
        assert_ne!(DeviceTrustLevel::Untrusted, DeviceTrustLevel::Trusted);
        assert_eq!(DeviceTrustLevel::Trusted, DeviceTrustLevel::Trusted);
    }

    #[test]
    fn test_device_name_generation() {
        let config = DeviceConfig::default();
        let mock_service = MockSessionService;
        let manager = DeviceManager::new(mock_service, config);

        let device_info = DeviceInfo {
            device_id: "test123".to_string(),
            device_name: None,
            device_type: DeviceType::Desktop,
            os: Some("Windows".to_string()),
            os_version: None,
            browser: Some("Chrome".to_string()),
            browser_version: None,
            is_mobile: false,
            is_trusted: false,
            first_seen_at: Utc::now(),
            last_seen_at: Utc::now(),
            fingerprint: "fp123".to_string(),
        };

        let name = manager.generate_device_name(&device_info);
        assert_eq!(name, Some("Windows Desktop".to_string()));
    }

    #[test]
    fn test_fingerprint_generation() {
        let config = DeviceConfig::default();
        let service = DeviceFingerprintingService::new(config);

        let request = EnhancedFingerprintRequest {
            user_agent: "Mozilla/5.0".to_string(),
            screen_resolution: "1920x1080".to_string(),
            timezone: "UTC".to_string(),
            language: "en-US".to_string(),
            canvas_fingerprint: None,
            webgl_fingerprint: None,
            browser_features: vec!["WebGL".to_string(), "Touch".to_string()],
        };

        let fingerprint = service.generate_enhanced_fingerprint(&request);
        assert_eq!(fingerprint.len(), 64); // SHA256 hex length
    }

    // Mock service for testing
    struct MockSessionService;

    #[async_trait::async_trait]
    impl SessionService for MockSessionService {
        async fn create_session(
            &self,
            _request: super::super::CreateSessionRequest,
        ) -> Result<super::super::Session> {
            unimplemented!()
        }
        async fn get_session(&self, _session_id: &str) -> Result<Option<super::super::Session>> {
            unimplemented!()
        }
        async fn update_session(
            &self,
            _session_id: &str,
            _session: super::super::Session,
        ) -> Result<super::super::Session> {
            unimplemented!()
        }
        async fn terminate_session(
            &self,
            _session_id: &str,
            _reason: super::super::TerminationReason,
        ) -> Result<bool> {
            unimplemented!()
        }
        async fn validate_session(
            &self,
            _session_id: &str,
            _ip_address: &str,
            _user_agent: &str,
        ) -> Result<super::super::SessionValidationResult> {
            unimplemented!()
        }
        async fn refresh_session(&self, _session_id: &str) -> Result<super::super::Session> {
            unimplemented!()
        }
        async fn get_user_sessions(&self, _user_id: &str) -> Result<Vec<super::super::Session>> {
            unimplemented!()
        }
        async fn terminate_user_sessions(
            &self,
            _user_id: &str,
            _reason: super::super::TerminationReason,
        ) -> Result<u64> {
            unimplemented!()
        }
        async fn get_device_sessions(
            &self,
            _device_id: &str,
        ) -> Result<Vec<super::super::Session>> {
            unimplemented!()
        }
        async fn trust_device(&self, _device_id: &str, _user_id: &str) -> Result<bool> {
            Ok(true)
        }
        async fn untrust_device(&self, _device_id: &str, _user_id: &str) -> Result<bool> {
            Ok(true)
        }
        async fn get_session_statistics(&self) -> Result<super::super::SessionStatistics> {
            unimplemented!()
        }
        async fn cleanup_expired_sessions(&self) -> Result<u64> {
            unimplemented!()
        }
        async fn emergency_logout_all(
            &self,
            _reason: super::super::TerminationReason,
        ) -> Result<u64> {
            unimplemented!()
        }
    }
}
