// MFA module is disabled - adding allow to suppress warnings
#![allow(dead_code)]

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod backup_codes;
pub mod sms;
pub mod totp;
pub mod webauthn;

/// Multi-Factor Authentication types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MfaType {
    Totp,        // Time-based One-Time Password (Google Authenticator, etc.)
    Sms,         // SMS verification
    Email,       // Email verification
    BackupCodes, // Backup recovery codes
    WebAuthn,    // FIDO2/WebAuthn (hardware keys, biometrics)
    Push,        // Push notifications
}

/// MFA challenge status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MfaStatus {
    Pending,  // Challenge issued, awaiting response
    Verified, // Successfully verified
    Failed,   // Verification failed
    Expired,  // Challenge expired
    Disabled, // MFA method disabled
}

/// MFA challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaChallenge {
    pub challenge_id: String,
    pub user_id: String,
    pub mfa_type: MfaType,
    pub status: MfaStatus,
    pub challenge_data: serde_json::Value, // Type-specific challenge data
    pub attempts: u32,
    pub max_attempts: u32,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// MFA method configuration for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaMethod {
    pub method_id: String,
    pub user_id: String,
    pub mfa_type: MfaType,
    pub is_enabled: bool,
    pub is_primary: bool,
    pub name: String,              // User-friendly name (e.g., "iPhone", "YubiKey")
    pub config: serde_json::Value, // Type-specific configuration
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub backup_codes_remaining: Option<u32>, // For backup codes
}

/// MFA verification request
#[derive(Debug, Clone, Deserialize)]
pub struct MfaVerificationRequest {
    pub challenge_id: String,
    pub code: String,
    pub method_id: Option<String>,
}

/// MFA setup request
#[derive(Debug, Clone, Deserialize)]
pub struct MfaSetupRequest {
    pub mfa_type: MfaType,
    pub name: String,
    pub config: Option<serde_json::Value>,
}

/// MFA setup response
#[derive(Debug, Clone, Serialize)]
pub struct MfaSetupResponse {
    pub method_id: String,
    pub mfa_type: MfaType,
    pub setup_data: serde_json::Value, // QR code, setup instructions, etc.
    pub backup_codes: Option<Vec<String>>,
}

/// MFA verification response
#[derive(Debug, Clone, Serialize)]
pub struct MfaVerificationResponse {
    pub success: bool,
    pub challenge_id: String,
    pub remaining_attempts: Option<u32>,
    pub lockout_duration: Option<u64>, // seconds
    pub backup_codes_remaining: Option<u32>,
}

/// MFA service trait for database operations
#[async_trait::async_trait]
pub trait MfaService: Send + Sync {
    // Challenge management
    async fn create_challenge(&self, challenge: MfaChallenge) -> Result<MfaChallenge>;
    async fn get_challenge(&self, challenge_id: &str) -> Result<Option<MfaChallenge>>;
    async fn update_challenge(&self, challenge: MfaChallenge) -> Result<MfaChallenge>;
    async fn delete_challenge(&self, challenge_id: &str) -> Result<bool>;
    async fn cleanup_expired_challenges(&self) -> Result<u64>;

    // Method management
    async fn create_method(&self, method: MfaMethod) -> Result<MfaMethod>;
    async fn get_method(&self, method_id: &str) -> Result<Option<MfaMethod>>;
    async fn get_user_methods(&self, user_id: &str) -> Result<Vec<MfaMethod>>;
    async fn update_method(&self, method: MfaMethod) -> Result<MfaMethod>;
    async fn delete_method(&self, method_id: &str) -> Result<bool>;
    async fn disable_method(&self, method_id: &str) -> Result<bool>;

    // User MFA status
    async fn get_user_mfa_status(&self, user_id: &str) -> Result<UserMfaStatus>;
    async fn enable_user_mfa(&self, user_id: &str) -> Result<bool>;
    async fn disable_user_mfa(&self, user_id: &str) -> Result<bool>;
    async fn reset_user_mfa(&self, user_id: &str) -> Result<bool>;

    // Backup codes
    async fn create_backup_codes(&self, user_id: &str, codes: Vec<String>) -> Result<bool>;
    async fn use_backup_code(&self, user_id: &str, code: &str) -> Result<bool>;
    async fn get_backup_codes_count(&self, user_id: &str) -> Result<u32>;
    async fn regenerate_backup_codes(&self, user_id: &str, codes: Vec<String>) -> Result<bool>;
}

/// User MFA status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMfaStatus {
    pub user_id: String,
    pub mfa_enabled: bool,
    pub primary_method: Option<MfaType>,
    pub available_methods: Vec<MfaType>,
    pub backup_codes_remaining: u32,
    pub last_mfa_at: Option<DateTime<Utc>>,
    pub mfa_required: bool, // Based on security policy
}

/// MFA configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaConfig {
    pub enabled: bool,
    pub require_for_all_users: bool,
    pub require_for_admin_users: bool,
    pub allow_sms: bool,
    pub allow_email: bool,
    pub allow_totp: bool,
    pub allow_webauthn: bool,
    pub allow_backup_codes: bool,
    pub challenge_timeout: u64, // seconds
    pub max_attempts: u32,
    pub lockout_duration: u64, // seconds after max attempts
    pub backup_codes_count: u32,
    pub backup_code_length: u32,
    pub totp_window: u32, // time steps (usually 1-2)
    pub totp_digits: u32, // usually 6
    pub sms_provider: Option<String>,
    pub webauthn_rp_id: String,
    pub webauthn_rp_name: String,
}

impl Default for MfaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            require_for_all_users: false,
            require_for_admin_users: true,
            allow_sms: true,
            allow_email: true,
            allow_totp: true,
            allow_webauthn: true,
            allow_backup_codes: true,
            challenge_timeout: 300, // 5 minutes
            max_attempts: 3,
            lockout_duration: 900, // 15 minutes
            backup_codes_count: 10,
            backup_code_length: 8,
            totp_window: 1,
            totp_digits: 6,
            sms_provider: None,
            webauthn_rp_id: "auth.example.com".to_string(),
            webauthn_rp_name: "Auth Service".to_string(),
        }
    }
}

/// MFA manager
pub struct MfaManager<T: MfaService> {
    service: T,
    config: MfaConfig,
    totp_provider: totp::TotpProvider,
    sms_provider: Option<sms::SmsProvider>,
    webauthn_provider: webauthn::WebAuthnProvider,
}

impl<T: MfaService> MfaManager<T> {
    pub fn new(
        service: T,
        config: MfaConfig,
        sms_provider: Option<sms::SmsProvider>,
    ) -> Result<Self> {
        let totp_provider =
            totp::TotpProvider::new(config.totp_digits as usize, config.totp_window as i64)?;
        let webauthn_provider =
            webauthn::WebAuthnProvider::new(&config.webauthn_rp_id, &config.webauthn_rp_name)?;

        Ok(Self {
            service,
            config,
            totp_provider,
            sms_provider,
            webauthn_provider,
        })
    }

    /// Check if MFA is required for a user
    pub async fn is_mfa_required(&self, user_id: &str, user_role: &str) -> Result<bool> {
        if !self.config.enabled {
            return Ok(false);
        }

        if self.config.require_for_all_users {
            return Ok(true);
        }

        if self.config.require_for_admin_users
            && (user_role == "admin" || user_role == "super_admin")
        {
            return Ok(true);
        }

        // Check if user has voluntarily enabled MFA
        let status = self.service.get_user_mfa_status(user_id).await?;
        Ok(status.mfa_enabled)
    }

    /// Setup a new MFA method for a user
    pub async fn setup_method(
        &self,
        user_id: &str,
        request: MfaSetupRequest,
    ) -> Result<MfaSetupResponse> {
        match request.mfa_type {
            MfaType::Totp => self.setup_totp(user_id, &request.name).await,
            MfaType::Sms => self.setup_sms(user_id, &request.name, request.config).await,
            MfaType::Email => self.setup_email(user_id, &request.name).await,
            MfaType::WebAuthn => self.setup_webauthn(user_id, &request.name).await,
            MfaType::BackupCodes => self.setup_backup_codes(user_id).await,
            MfaType::Push => Err(anyhow::anyhow!("Push notifications not yet implemented")),
        }
    }

    /// Issue an MFA challenge
    pub async fn create_challenge(
        &self,
        user_id: &str,
        method_id: Option<&str>,
    ) -> Result<MfaChallenge> {
        let methods = self.service.get_user_methods(user_id).await?;
        let enabled_methods: Vec<_> = methods.iter().filter(|m| m.is_enabled).collect();

        if enabled_methods.is_empty() {
            return Err(anyhow::anyhow!("No MFA methods enabled for user"));
        }

        let method = if let Some(id) = method_id {
            enabled_methods
                .iter()
                .find(|m| m.method_id == id)
                .ok_or_else(|| anyhow::anyhow!("MFA method not found or disabled"))?
        } else {
            // Use primary method or first available
            enabled_methods
                .iter()
                .find(|m| m.is_primary)
                .unwrap_or(&enabled_methods[0])
        };

        match method.mfa_type {
            MfaType::Totp => self.create_totp_challenge(user_id, method).await,
            MfaType::Sms => self.create_sms_challenge(user_id, method).await,
            MfaType::Email => self.create_email_challenge(user_id, method).await,
            MfaType::WebAuthn => self.create_webauthn_challenge(user_id, method).await,
            MfaType::BackupCodes => self.create_backup_codes_challenge(user_id).await,
            MfaType::Push => Err(anyhow::anyhow!("Push notifications not yet implemented")),
        }
    }

    /// Verify an MFA challenge
    pub async fn verify_challenge(
        &self,
        request: MfaVerificationRequest,
    ) -> Result<MfaVerificationResponse> {
        let mut challenge = self
            .service
            .get_challenge(&request.challenge_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Challenge not found"))?;

        // Check if challenge is expired
        if challenge.expires_at < Utc::now() {
            challenge.status = MfaStatus::Expired;
            self.service.update_challenge(challenge.clone()).await?;
            return Ok(MfaVerificationResponse {
                success: false,
                challenge_id: challenge.challenge_id,
                remaining_attempts: Some(0),
                lockout_duration: None,
                backup_codes_remaining: None,
            });
        }

        // Check if already verified or failed
        if challenge.status != MfaStatus::Pending {
            return Ok(MfaVerificationResponse {
                success: false,
                challenge_id: challenge.challenge_id,
                remaining_attempts: Some(0),
                lockout_duration: None,
                backup_codes_remaining: None,
            });
        }

        // Increment attempts
        challenge.attempts += 1;

        let verification_result = match challenge.mfa_type {
            MfaType::Totp => self.verify_totp(&challenge, &request.code).await,
            MfaType::Sms => self.verify_sms(&challenge, &request.code).await,
            MfaType::Email => self.verify_email(&challenge, &request.code).await,
            MfaType::WebAuthn => self.verify_webauthn(&challenge, &request.code).await,
            MfaType::BackupCodes => self.verify_backup_code(&challenge, &request.code).await,
            MfaType::Push => Err(anyhow::anyhow!("Push notifications not yet implemented")),
        };

        let success = verification_result.unwrap_or(false);

        if success {
            challenge.status = MfaStatus::Verified;
            challenge.verified_at = Some(Utc::now());
        } else if challenge.attempts >= challenge.max_attempts {
            challenge.status = MfaStatus::Failed;
        }

        let remaining_attempts = if challenge.max_attempts > challenge.attempts {
            Some(challenge.max_attempts - challenge.attempts)
        } else {
            Some(0)
        };

        let backup_codes_remaining = if challenge.mfa_type == MfaType::BackupCodes {
            Some(
                self.service
                    .get_backup_codes_count(&challenge.user_id)
                    .await
                    .unwrap_or(0),
            )
        } else {
            None
        };

        self.service.update_challenge(challenge.clone()).await?;

        Ok(MfaVerificationResponse {
            success,
            challenge_id: challenge.challenge_id,
            remaining_attempts,
            lockout_duration: if !success && remaining_attempts == Some(0) {
                Some(self.config.lockout_duration)
            } else {
                None
            },
            backup_codes_remaining,
        })
    }

    /// Get user's MFA status
    pub async fn get_user_status(&self, user_id: &str) -> Result<UserMfaStatus> {
        self.service.get_user_mfa_status(user_id).await
    }

    /// Disable MFA for a user (admin function)
    pub async fn disable_user_mfa(&self, user_id: &str) -> Result<bool> {
        self.service.disable_user_mfa(user_id).await
    }

    /// Reset user MFA (remove all methods, useful for account recovery)
    pub async fn reset_user_mfa(&self, user_id: &str) -> Result<bool> {
        self.service.reset_user_mfa(user_id).await
    }

    // Private helper methods for each MFA type
    async fn setup_totp(&self, user_id: &str, name: &str) -> Result<MfaSetupResponse> {
        let secret = self.totp_provider.generate_secret();
        let totp_setup = self
            .totp_provider
            .setup_totp(&secret, user_id, "Auth Service")?;

        let method_id = uuid::Uuid::new_v4().to_string();
        let config = serde_json::json!({
            "secret": secret,
        });

        let method = MfaMethod {
            method_id: method_id.clone(),
            user_id: user_id.to_string(),
            mfa_type: MfaType::Totp,
            is_enabled: false, // Will be enabled after verification
            is_primary: false,
            name: name.to_string(),
            config,
            created_at: Utc::now(),
            last_used_at: None,
            backup_codes_remaining: None,
        };

        self.service.create_method(method).await?;

        Ok(MfaSetupResponse {
            method_id,
            mfa_type: MfaType::Totp,
            setup_data: serde_json::json!({
                "secret": totp_setup.secret,
                "qr_code": totp_setup.qr_code,
                "manual_entry_key": totp_setup.secret,
            }),
            backup_codes: Some(totp_setup.backup_codes),
        })
    }

    async fn setup_sms(
        &self,
        user_id: &str,
        name: &str,
        config: Option<serde_json::Value>,
    ) -> Result<MfaSetupResponse> {
        let phone_number = config
            .as_ref()
            .and_then(|c| c.get("phone_number"))
            .and_then(|p| p.as_str())
            .ok_or_else(|| anyhow::anyhow!("Phone number required for SMS MFA"))?;

        let method_id = uuid::Uuid::new_v4().to_string();
        let method_config = serde_json::json!({
            "phone_number": phone_number,
        });

        let method = MfaMethod {
            method_id: method_id.clone(),
            user_id: user_id.to_string(),
            mfa_type: MfaType::Sms,
            is_enabled: true,
            is_primary: false,
            name: name.to_string(),
            config: method_config,
            created_at: Utc::now(),
            last_used_at: None,
            backup_codes_remaining: None,
        };

        self.service.create_method(method).await?;

        Ok(MfaSetupResponse {
            method_id,
            mfa_type: MfaType::Sms,
            setup_data: serde_json::json!({
                "phone_number": phone_number,
                "message": "SMS MFA has been configured",
            }),
            backup_codes: None,
        })
    }

    async fn setup_email(&self, user_id: &str, name: &str) -> Result<MfaSetupResponse> {
        let method_id = uuid::Uuid::new_v4().to_string();

        let method = MfaMethod {
            method_id: method_id.clone(),
            user_id: user_id.to_string(),
            mfa_type: MfaType::Email,
            is_enabled: true,
            is_primary: false,
            name: name.to_string(),
            config: serde_json::json!({}),
            created_at: Utc::now(),
            last_used_at: None,
            backup_codes_remaining: None,
        };

        self.service.create_method(method).await?;

        Ok(MfaSetupResponse {
            method_id,
            mfa_type: MfaType::Email,
            setup_data: serde_json::json!({
                "message": "Email MFA has been configured",
            }),
            backup_codes: None,
        })
    }

    async fn setup_webauthn(&self, user_id: &str, name: &str) -> Result<MfaSetupResponse> {
        let registration_request = crate::mfa::webauthn::WebAuthnRegistrationRequest {
            user_id: user_id.to_string(),
            username: user_id.to_string(),
            display_name: name.to_string(),
        };
        let registration_challenge = self
            .webauthn_provider
            .start_registration(&registration_request)?;

        let method_id = uuid::Uuid::new_v4().to_string();

        Ok(MfaSetupResponse {
            method_id,
            mfa_type: MfaType::WebAuthn,
            setup_data: serde_json::to_value(registration_challenge)?,
            backup_codes: None,
        })
    }

    async fn setup_backup_codes(&self, user_id: &str) -> Result<MfaSetupResponse> {
        let codes = backup_codes::generate_backup_codes(
            self.config.backup_codes_count as usize,
            self.config.backup_code_length as usize,
        );

        self.service
            .create_backup_codes(user_id, codes.clone())
            .await?;

        Ok(MfaSetupResponse {
            method_id: format!("{}_backup_codes", user_id),
            mfa_type: MfaType::BackupCodes,
            setup_data: serde_json::json!({
                "message": "Backup codes generated",
                "codes_count": codes.len(),
            }),
            backup_codes: Some(codes),
        })
    }

    // Challenge creation methods
    async fn create_totp_challenge(
        &self,
        user_id: &str,
        method: &MfaMethod,
    ) -> Result<MfaChallenge> {
        let challenge_id = uuid::Uuid::new_v4().to_string();

        let challenge = MfaChallenge {
            challenge_id: challenge_id.clone(),
            user_id: user_id.to_string(),
            mfa_type: MfaType::Totp,
            status: MfaStatus::Pending,
            challenge_data: serde_json::json!({
                "method_id": method.method_id,
                "message": "Enter the 6-digit code from your authenticator app",
            }),
            attempts: 0,
            max_attempts: self.config.max_attempts,
            expires_at: Utc::now()
                + chrono::Duration::seconds(self.config.challenge_timeout as i64),
            created_at: Utc::now(),
            verified_at: None,
            metadata: HashMap::new(),
        };

        self.service.create_challenge(challenge.clone()).await?;
        Ok(challenge)
    }

    async fn create_sms_challenge(
        &self,
        user_id: &str,
        method: &MfaMethod,
    ) -> Result<MfaChallenge> {
        let challenge_id = uuid::Uuid::new_v4().to_string();
        let code = backup_codes::generate_backup_codes(1, 6)[0].clone();

        let phone_number = method
            .config
            .get("phone_number")
            .and_then(|p| p.as_str())
            .ok_or_else(|| anyhow::anyhow!("Phone number not configured"))?;

        // Send SMS
        if let Some(ref sms_provider) = self.sms_provider {
            sms_provider.send_code(phone_number, &code).await?;
        }

        let challenge = MfaChallenge {
            challenge_id: challenge_id.clone(),
            user_id: user_id.to_string(),
            mfa_type: MfaType::Sms,
            status: MfaStatus::Pending,
            challenge_data: serde_json::json!({
                "method_id": method.method_id,
                "phone_number_masked": format!("***-***-{value}"), &phone_number[phone_number.len()-4..]),
                "code": code, // This would be hashed in production
            }),
            attempts: 0,
            max_attempts: self.config.max_attempts,
            expires_at: Utc::now()
                + chrono::Duration::seconds(self.config.challenge_timeout as i64),
            created_at: Utc::now(),
            verified_at: None,
            metadata: HashMap::new(),
        };

        self.service.create_challenge(challenge.clone()).await?;
        Ok(challenge)
    }

    async fn create_email_challenge(
        &self,
        user_id: &str,
        method: &MfaMethod,
    ) -> Result<MfaChallenge> {
        let challenge_id = uuid::Uuid::new_v4().to_string();
        let code = backup_codes::generate_backup_codes(1, 6)[0].clone();

        // TODO: Send email via email service

        let challenge = MfaChallenge {
            challenge_id: challenge_id.clone(),
            user_id: user_id.to_string(),
            mfa_type: MfaType::Email,
            status: MfaStatus::Pending,
            challenge_data: serde_json::json!({
                "method_id": method.method_id,
                "code": code, // This would be hashed in production
            }),
            attempts: 0,
            max_attempts: self.config.max_attempts,
            expires_at: Utc::now()
                + chrono::Duration::seconds(self.config.challenge_timeout as i64),
            created_at: Utc::now(),
            verified_at: None,
            metadata: HashMap::new(),
        };

        self.service.create_challenge(challenge.clone()).await?;
        Ok(challenge)
    }

    async fn create_webauthn_challenge(
        &self,
        user_id: &str,
        _method: &MfaMethod,
    ) -> Result<MfaChallenge> {
        let challenge_id = uuid::Uuid::new_v4().to_string();
        let auth_request = crate::mfa::webauthn::WebAuthnAuthenticationRequest {
            user_id: user_id.to_string(),
        };
        let auth_challenge = self.webauthn_provider.start_authentication(&auth_request)?;

        let challenge = MfaChallenge {
            challenge_id: challenge_id.clone(),
            user_id: user_id.to_string(),
            mfa_type: MfaType::WebAuthn,
            status: MfaStatus::Pending,
            challenge_data: serde_json::to_value(auth_challenge)?,
            attempts: 0,
            max_attempts: self.config.max_attempts,
            expires_at: Utc::now()
                + chrono::Duration::seconds(self.config.challenge_timeout as i64),
            created_at: Utc::now(),
            verified_at: None,
            metadata: HashMap::new(),
        };

        self.service.create_challenge(challenge.clone()).await?;
        Ok(challenge)
    }

    async fn create_backup_codes_challenge(&self, user_id: &str) -> Result<MfaChallenge> {
        let challenge_id = uuid::Uuid::new_v4().to_string();

        let challenge = MfaChallenge {
            challenge_id: challenge_id.clone(),
            user_id: user_id.to_string(),
            mfa_type: MfaType::BackupCodes,
            status: MfaStatus::Pending,
            challenge_data: serde_json::json!({
                "message": "Enter one of your backup codes",
            }),
            attempts: 0,
            max_attempts: self.config.max_attempts,
            expires_at: Utc::now()
                + chrono::Duration::seconds(self.config.challenge_timeout as i64),
            created_at: Utc::now(),
            verified_at: None,
            metadata: HashMap::new(),
        };

        self.service.create_challenge(challenge.clone()).await?;
        Ok(challenge)
    }

    // Verification methods
    async fn verify_totp(&self, challenge: &MfaChallenge, code: &str) -> Result<bool> {
        let method_id = challenge
            .challenge_data
            .get("method_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Method ID not found in challenge"))?;

        let method = self
            .service
            .get_method(method_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("MFA method not found"))?;

        let secret = method
            .config
            .get("secret")
            .and_then(|s| s.as_str())
            .ok_or_else(|| anyhow::anyhow!("TOTP secret not found"))?;

        Ok(self.totp_provider.verify_code(secret, code)?)
    }

    async fn verify_sms(&self, challenge: &MfaChallenge, code: &str) -> Result<bool> {
        let expected_code = challenge
            .challenge_data
            .get("code")
            .and_then(|c| c.as_str())
            .ok_or_else(|| anyhow::anyhow!("SMS code not found in challenge"))?;

        Ok(code == expected_code)
    }

    async fn verify_email(&self, challenge: &MfaChallenge, code: &str) -> Result<bool> {
        let expected_code = challenge
            .challenge_data
            .get("code")
            .and_then(|c| c.as_str())
            .ok_or_else(|| anyhow::anyhow!("Email code not found in challenge"))?;

        Ok(code == expected_code)
    }

    async fn verify_webauthn(&self, challenge: &MfaChallenge, response: &str) -> Result<bool> {
        // Parse WebAuthn response and verify
        let response_data: serde_json::Value = serde_json::from_str(response)?;
        Ok(self
            .webauthn_provider
            .finish_authentication(&challenge.user_id, &response_data)?)
    }

    async fn verify_backup_code(&self, challenge: &MfaChallenge, code: &str) -> Result<bool> {
        Ok(self
            .service
            .use_backup_code(&challenge.user_id, code)
            .await?)
    }
}
