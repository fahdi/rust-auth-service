use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

/// WebAuthn provider for FIDO2/WebAuthn authentication
#[derive(Debug, Clone)]
pub struct WebAuthnProvider {
    rp_id: String,
    rp_name: String,
    // In-memory storage for demo - replace with database in production
    challenges: std::sync::Arc<std::sync::Mutex<HashMap<String, String>>>,
}

/// WebAuthn registration request
#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnRegistrationRequest {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
}

/// WebAuthn registration response
#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnRegistrationResponse {
    pub challenge: String,
    pub options: Value,
}

/// WebAuthn authentication request
#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationRequest {
    pub user_id: String,
}

/// WebAuthn authentication response
#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationResponse {
    pub challenge: String,
    pub options: Value,
}

/// WebAuthn credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredential {
    pub id: String,
    pub user_id: String,
    pub public_key: String,
    pub counter: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
    pub nickname: Option<String>,
}

impl WebAuthnProvider {
    /// Create new WebAuthn provider
    pub fn new(rp_id: &str, rp_name: &str) -> Result<Self> {
        Ok(Self {
            rp_id: rp_id.to_string(),
            rp_name: rp_name.to_string(),
            challenges: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
        })
    }

    /// Start WebAuthn registration ceremony
    pub fn start_registration(&self, request: &WebAuthnRegistrationRequest) -> Result<WebAuthnRegistrationResponse> {
        let challenge = self.generate_challenge();
        
        // Store challenge for verification
        {
            let mut challenges = self.challenges.lock().unwrap();
            challenges.insert(request.user_id.clone(), challenge.clone());
        }

        // Create WebAuthn registration options
        let options = serde_json::json!({
            "challenge": challenge,
            "rp": {
                "name": self.rp_name,
                "id": self.rp_id
            },
            "user": {
                "id": request.user_id,
                "name": request.username,
                "displayName": request.display_name
            },
            "pubKeyCredParams": [
                {
                    "type": "public-key",
                    "alg": -7  // ES256
                },
                {
                    "type": "public-key", 
                    "alg": -257 // RS256
                }
            ],
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "userVerification": "preferred",
                "requireResidentKey": false
            },
            "attestation": "none",
            "timeout": 60000
        });

        Ok(WebAuthnRegistrationResponse { challenge, options })
    }

    /// Finish WebAuthn registration ceremony
    pub fn finish_registration(&self, user_id: &str, response: &Value) -> Result<WebAuthnCredential> {
        // Verify challenge
        let stored_challenge = {
            let mut challenges = self.challenges.lock().unwrap();
            challenges.remove(user_id)
        };

        let _challenge = stored_challenge
            .ok_or_else(|| anyhow::anyhow!("No challenge found for user"))?;

        // TODO: Implement actual WebAuthn verification
        // For now, create a mock credential
        let credential = WebAuthnCredential {
            id: format!("cred_{}", uuid::Uuid::new_v4()),
            user_id: user_id.to_string(),
            public_key: "mock_public_key".to_string(),
            counter: 0,
            created_at: chrono::Utc::now(),
            last_used: None,
            nickname: response.get("nickname")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        };

        tracing::info!("WebAuthn registration completed for user: {}", user_id);
        Ok(credential)
    }

    /// Start WebAuthn authentication ceremony
    pub fn start_authentication(&self, request: &WebAuthnAuthenticationRequest) -> Result<WebAuthnAuthenticationResponse> {
        let challenge = self.generate_challenge();
        
        // Store challenge for verification
        {
            let mut challenges = self.challenges.lock().unwrap();
            challenges.insert(request.user_id.clone(), challenge.clone());
        }

        // Create WebAuthn authentication options
        let options = serde_json::json!({
            "challenge": challenge,
            "timeout": 60000,
            "rpId": self.rp_id,
            "allowCredentials": [],
            "userVerification": "preferred"
        });

        Ok(WebAuthnAuthenticationResponse { challenge, options })
    }

    /// Finish WebAuthn authentication ceremony
    pub fn finish_authentication(&self, user_id: &str, response: &Value) -> Result<bool> {
        // Verify challenge
        let stored_challenge = {
            let mut challenges = self.challenges.lock().unwrap();
            challenges.remove(user_id)
        };

        let _challenge = stored_challenge
            .ok_or_else(|| anyhow::anyhow!("No challenge found for user"))?;

        // TODO: Implement actual WebAuthn verification
        // For now, return success if response contains required fields
        let has_required_fields = response.get("id").is_some() 
            && response.get("type").is_some()
            && response.get("rawId").is_some()
            && response.get("response").is_some();

        if has_required_fields {
            tracing::info!("WebAuthn authentication completed for user: {}", user_id);
            Ok(true)
        } else {
            tracing::warn!("WebAuthn authentication failed for user: {}", user_id);
            Ok(false)
        }
    }

    /// Generate cryptographically secure challenge
    fn generate_challenge(&self) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let challenge_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        URL_SAFE_NO_PAD.encode(challenge_bytes)
    }

    /// Validate WebAuthn credential
    pub fn validate_credential(&self, credential: &WebAuthnCredential) -> Result<()> {
        if credential.id.is_empty() {
            return Err(anyhow::anyhow!("Credential ID cannot be empty"));
        }
        
        if credential.user_id.is_empty() {
            return Err(anyhow::anyhow!("User ID cannot be empty"));
        }
        
        if credential.public_key.is_empty() {
            return Err(anyhow::anyhow!("Public key cannot be empty"));
        }
        
        Ok(())
    }

    /// Get relying party ID
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// Get relying party name
    pub fn rp_name(&self) -> &str {
        &self.rp_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_provider() -> WebAuthnProvider {
        WebAuthnProvider::new("example.com", "Test Service").unwrap()
    }

    #[test]
    fn test_webauthn_registration_flow() {
        let provider = create_test_provider();
        let request = WebAuthnRegistrationRequest {
            user_id: "test_user".to_string(),
            username: "testuser".to_string(),
            display_name: "Test User".to_string(),
        };

        let registration_response = provider.start_registration(&request).unwrap();
        assert!(!registration_response.challenge.is_empty());
        assert!(registration_response.options.get("challenge").is_some());

        // Mock credential response
        let credential_response = serde_json::json!({
            "id": "credential_id",
            "type": "public-key",
            "rawId": "raw_credential_id",
            "response": {
                "attestationObject": "mock_attestation",
                "clientDataJSON": "mock_client_data"
            }
        });

        let credential = provider.finish_registration(&request.user_id, &credential_response).unwrap();
        assert_eq!(credential.user_id, request.user_id);
        assert!(!credential.id.is_empty());
    }

    #[test]
    fn test_webauthn_authentication_flow() {
        let provider = create_test_provider();
        let request = WebAuthnAuthenticationRequest {
            user_id: "test_user".to_string(),
        };

        let auth_response = provider.start_authentication(&request).unwrap();
        assert!(!auth_response.challenge.is_empty());
        assert!(auth_response.options.get("challenge").is_some());

        // Mock authentication response
        let auth_credential = serde_json::json!({
            "id": "credential_id",
            "type": "public-key",
            "rawId": "raw_credential_id",
            "response": {
                "authenticatorData": "mock_auth_data",
                "clientDataJSON": "mock_client_data",
                "signature": "mock_signature"
            }
        });

        let result = provider.finish_authentication(&request.user_id, &auth_credential).unwrap();
        assert!(result);
    }

    #[test]
    fn test_credential_validation() {
        let provider = create_test_provider();
        
        let valid_credential = WebAuthnCredential {
            id: "cred_123".to_string(),
            user_id: "user_123".to_string(),
            public_key: "public_key_data".to_string(),
            counter: 0,
            created_at: chrono::Utc::now(),
            last_used: None,
            nickname: Some("My Security Key".to_string()),
        };

        assert!(provider.validate_credential(&valid_credential).is_ok());

        let invalid_credential = WebAuthnCredential {
            id: "".to_string(),
            user_id: "user_123".to_string(),
            public_key: "public_key_data".to_string(),
            counter: 0,
            created_at: chrono::Utc::now(),
            last_used: None,
            nickname: None,
        };

        assert!(provider.validate_credential(&invalid_credential).is_err());
    }
}