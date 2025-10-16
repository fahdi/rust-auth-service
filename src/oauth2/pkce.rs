use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Digest, Sha256};

/// PKCE (Proof Key for Code Exchange) implementation for OAuth2
/// RFC 7636: https://tools.ietf.org/html/rfc7636

/// PKCE code challenge methods
#[derive(Debug, Clone, PartialEq)]
pub enum CodeChallengeMethod {
    Plain,
    S256,
}

impl CodeChallengeMethod {
    pub fn from_str(method: &str) -> Result<Self> {
        match method {
            "plain" => Ok(CodeChallengeMethod::Plain),
            "S256" => Ok(CodeChallengeMethod::S256),
            _ => Err(anyhow!("Unsupported code challenge method: {}", method)),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CodeChallengeMethod::Plain => "plain",
            CodeChallengeMethod::S256 => "S256",
        }
    }
}

/// PKCE code verifier and challenge
#[derive(Debug, Clone)]
pub struct PKCEChallenge {
    pub code_verifier: String,
    pub code_challenge: String,
    pub code_challenge_method: CodeChallengeMethod,
}

impl PKCEChallenge {
    /// Generate a new PKCE challenge using S256 method
    pub fn generate() -> Self {
        Self::generate_with_method(CodeChallengeMethod::S256)
    }

    /// Generate a new PKCE challenge with specified method
    pub fn generate_with_method(method: CodeChallengeMethod) -> Self {
        let code_verifier = Self::generate_code_verifier();
        let code_challenge = Self::generate_code_challenge(&code_verifier, &method);

        PKCEChallenge {
            code_verifier,
            code_challenge,
            code_challenge_method: method,
        }
    }

    /// Generate a cryptographically random code verifier
    /// RFC 7636 Section 4.1: 43-128 characters, unreserved characters only
    pub fn generate_code_verifier() -> String {
        // Generate 96 random bytes and encode as URL-safe base64 (128 characters)
        let random_bytes: Vec<u8> = (0..96).map(|_| rand::random::<u8>()).collect();
        URL_SAFE_NO_PAD.encode(random_bytes)
    }

    /// Generate code challenge from verifier
    pub fn generate_code_challenge(code_verifier: &str, method: &CodeChallengeMethod) -> String {
        match method {
            CodeChallengeMethod::Plain => code_verifier.to_string(),
            CodeChallengeMethod::S256 => {
                let digest = Sha256::digest(code_verifier.as_bytes());
                URL_SAFE_NO_PAD.encode(digest)
            }
        }
    }

    /// Verify that a code verifier matches this challenge
    pub fn verify(&self, code_verifier: &str) -> bool {
        let computed_challenge =
            Self::generate_code_challenge(code_verifier, &self.code_challenge_method);
        computed_challenge == self.code_challenge
    }

    /// Validate code verifier format (RFC 7636 Section 4.1)
    pub fn validate_code_verifier(code_verifier: &str) -> Result<()> {
        if code_verifier.len() < 43 || code_verifier.len() > 128 {
            return Err(anyhow!(
                "Code verifier length must be between 43 and 128 characters"
            ));
        }

        // Check that code verifier only contains unreserved characters
        // unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
        for ch in code_verifier.chars() {
            if !ch.is_ascii_alphanumeric() && !matches!(ch, '-' | '.' | '_' | '~') {
                return Err(anyhow!("Code verifier contains invalid characters"));
            }
        }

        Ok(())
    }

    /// Validate code challenge format
    pub fn validate_code_challenge(
        code_challenge: &str,
        method: &CodeChallengeMethod,
    ) -> Result<()> {
        match method {
            CodeChallengeMethod::Plain => Self::validate_code_verifier(code_challenge),
            CodeChallengeMethod::S256 => {
                // S256 challenges should be 43 characters (256 bits base64url encoded)
                if code_challenge.len() != 43 {
                    return Err(anyhow!("S256 code challenge must be 43 characters"));
                }

                // Check that it's valid base64url
                if URL_SAFE_NO_PAD.decode(code_challenge).is_err() {
                    return Err(anyhow!("Invalid base64url encoding in code challenge"));
                }

                Ok(())
            }
        }
    }
}

/// PKCE verification result
#[derive(Debug, PartialEq)]
pub enum PKCEVerificationResult {
    Valid,
    Invalid,
    MethodMismatch,
    MissingVerifier,
    MissingChallenge,
}

/// Standalone PKCE verification function
pub fn verify_pkce(
    code_verifier: Option<&str>,
    code_challenge: Option<&str>,
    code_challenge_method: Option<&str>,
) -> PKCEVerificationResult {
    match (code_verifier, code_challenge, code_challenge_method) {
        (Some(verifier), Some(challenge), method) => {
            let method = method.unwrap_or("plain");

            let challenge_method = match CodeChallengeMethod::from_str(method) {
                Ok(method) => method,
                Err(_) => return PKCEVerificationResult::MethodMismatch,
            };

            let computed_challenge =
                PKCEChallenge::generate_code_challenge(verifier, &challenge_method);

            if computed_challenge == challenge {
                PKCEVerificationResult::Valid
            } else {
                PKCEVerificationResult::Invalid
            }
        }
        (None, Some(_), _) => PKCEVerificationResult::MissingVerifier,
        (Some(_), None, _) => PKCEVerificationResult::MissingChallenge,
        (None, None, _) => PKCEVerificationResult::Valid, // No PKCE used
    }
}

/// Client-side PKCE helper for testing and client libraries
pub struct PKCEClient {
    challenge: PKCEChallenge,
}

impl PKCEClient {
    /// Create new PKCE client with generated challenge
    pub fn new() -> Self {
        PKCEClient {
            challenge: PKCEChallenge::generate(),
        }
    }

    /// Create PKCE client with specific method
    pub fn with_method(method: CodeChallengeMethod) -> Self {
        PKCEClient {
            challenge: PKCEChallenge::generate_with_method(method),
        }
    }

    /// Get the code challenge for authorization request
    pub fn code_challenge(&self) -> &str {
        &self.challenge.code_challenge
    }

    /// Get the code challenge method
    pub fn code_challenge_method(&self) -> &str {
        self.challenge.code_challenge_method.as_str()
    }

    /// Get the code verifier for token request
    pub fn code_verifier(&self) -> &str {
        &self.challenge.code_verifier
    }

    /// Get authorization URL parameters
    pub fn authorization_params(&self) -> Vec<(&str, &str)> {
        vec![
            ("code_challenge", &self.challenge.code_challenge),
            (
                "code_challenge_method",
                self.challenge.code_challenge_method.as_str(),
            ),
        ]
    }

    /// Get token request parameters
    pub fn token_params(&self) -> Vec<(&str, &str)> {
        vec![("code_verifier", &self.challenge.code_verifier)]
    }
}

impl Default for PKCEClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_code_verifier() {
        let verifier = PKCEChallenge::generate_code_verifier();

        // Should be between 43 and 128 characters
        assert!(verifier.len() >= 43 && verifier.len() <= 128);

        // Should contain only unreserved characters
        assert!(PKCEChallenge::validate_code_verifier(&verifier).is_ok());
    }

    #[test]
    fn test_code_challenge_s256() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        let challenge =
            PKCEChallenge::generate_code_challenge(verifier, &CodeChallengeMethod::S256);
        assert_eq!(challenge, expected_challenge);
    }

    #[test]
    fn test_code_challenge_plain() {
        let verifier = "test_code_verifier_12345";
        let challenge =
            PKCEChallenge::generate_code_challenge(verifier, &CodeChallengeMethod::Plain);
        assert_eq!(challenge, verifier);
    }

    #[test]
    fn test_pkce_verification() {
        let pkce = PKCEChallenge::generate();

        // Should verify with correct verifier
        assert!(pkce.verify(&pkce.code_verifier));

        // Should not verify with incorrect verifier
        assert!(!pkce.verify("wrong_verifier"));
    }

    #[test]
    fn test_verify_pkce_function() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        // Valid S256 verification
        assert_eq!(
            verify_pkce(Some(verifier), Some(challenge), Some("S256")),
            PKCEVerificationResult::Valid
        );

        // Invalid verifier
        assert_eq!(
            verify_pkce(Some("wrong"), Some(challenge), Some("S256")),
            PKCEVerificationResult::Invalid
        );

        // Missing verifier
        assert_eq!(
            verify_pkce(None, Some(challenge), Some("S256")),
            PKCEVerificationResult::MissingVerifier
        );

        // No PKCE
        assert_eq!(verify_pkce(None, None, None), PKCEVerificationResult::Valid);
    }

    #[test]
    fn test_pkce_client() {
        let client = PKCEClient::new();

        // Should generate valid challenge
        assert!(client.code_challenge().len() > 0);
        assert_eq!(client.code_challenge_method(), "S256");

        // Verifier should match challenge
        let computed = PKCEChallenge::generate_code_challenge(
            client.code_verifier(),
            &CodeChallengeMethod::S256,
        );
        assert_eq!(computed, client.code_challenge());
    }

    #[test]
    fn test_validate_code_verifier() {
        // Valid verifiers
        assert!(PKCEChallenge::validate_code_verifier(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        )
        .is_ok());
        assert!(PKCEChallenge::validate_code_verifier(&"a".repeat(43)).is_ok());
        assert!(PKCEChallenge::validate_code_verifier(&"a".repeat(128)).is_ok());

        // Invalid verifiers
        assert!(PKCEChallenge::validate_code_verifier(&"a".repeat(42)).is_err()); // Too short
        assert!(PKCEChallenge::validate_code_verifier(&"a".repeat(129)).is_err()); // Too long
        assert!(PKCEChallenge::validate_code_verifier("invalid@character").is_err());
        // Invalid char
    }

    #[test]
    fn test_validate_code_challenge() {
        // Valid S256 challenge
        assert!(PKCEChallenge::validate_code_challenge(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            &CodeChallengeMethod::S256
        )
        .is_ok());

        // Invalid S256 challenge (wrong length)
        assert!(
            PKCEChallenge::validate_code_challenge("too_short", &CodeChallengeMethod::S256)
                .is_err()
        );

        // Valid plain challenge
        assert!(PKCEChallenge::validate_code_challenge(
            "valid_plain_challenge_123",
            &CodeChallengeMethod::Plain
        )
        .is_ok());
    }

    #[test]
    fn test_code_challenge_method_conversion() {
        assert_eq!(
            CodeChallengeMethod::from_str("plain").unwrap(),
            CodeChallengeMethod::Plain
        );
        assert_eq!(
            CodeChallengeMethod::from_str("S256").unwrap(),
            CodeChallengeMethod::S256
        );
        assert!(CodeChallengeMethod::from_str("invalid").is_err());

        assert_eq!(CodeChallengeMethod::Plain.as_str(), "plain");
        assert_eq!(CodeChallengeMethod::S256.as_str(), "S256");
    }
}
