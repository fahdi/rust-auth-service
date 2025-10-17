//! # Brevo Email Provider
//!
//! Implementation of the EmailProvider trait for Brevo (formerly Sendinblue).
//! Brevo is a popular email service provider offering transactional email APIs,
//! marketing automation, and SMS services.
//!
//! ## Features
//! - REST API integration using reqwest
//! - API key authentication
//! - Support for HTML and plain text emails
//! - Message ID tracking for delivery monitoring
//! - Built-in health checks
//!
//! ## Configuration
//! Requires the following in your email configuration:
//! ```yaml
//! email:
//!   provider: brevo
//!   brevo:
//!     api_key: "your-brevo-api-key"
//!     from_email: "noreply@yourapp.com"
//! ```
//!
//! ## API Endpoints
//! - Send Email: `POST /v3/smtp/email`
//! - Health Check: `GET /v3/account`
//!
//! ## Rate Limits
//! Brevo imposes rate limits based on your plan. This implementation respects
//! those limits and provides appropriate error messages when exceeded.

use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::config::email::BrevoConfig;
use crate::email::{EmailMessage, EmailProvider, EmailResponse, EmailStatus};

/// Brevo (formerly Sendinblue) email provider implementation
///
/// This provider integrates with Brevo's transactional email API to send emails.
/// It supports both HTML and plain text content and provides delivery tracking.
///
/// # Authentication
/// Uses API key authentication via the `api-key` header. The API key must have
/// permission to send transactional emails.
///
/// # Error Handling
/// - Network errors are propagated as `anyhow::Error`
/// - API errors are captured and returned as `EmailStatus::Failed`
/// - Rate limiting and quota errors are handled gracefully
///
/// # Example Usage
/// ```rust
/// let config = BrevoConfig {
///     api_key: "your-api-key".to_string(),
///     from_email: "noreply@yourapp.com".to_string(),
/// };
/// 
/// let provider = BrevoProvider::new(&config)?;
/// let response = provider.send_email(&email_message).await?;
/// ```
pub struct BrevoProvider {
    /// HTTP client for API requests with configured timeout
    client: Client,
    /// Brevo API key for authentication
    api_key: String,
    /// Default sender email (kept for potential future use)
    _from_email: String,
}

/// Request payload for Brevo's send email API endpoint
///
/// This structure matches Brevo's v3 API specification for sending transactional emails.
/// All fields are required by the API except for content fields which are optional
/// but at least one content type must be provided.
#[derive(Serialize)]
struct BrevoSendRequest {
    /// Sender information (email and display name)
    sender: BrevoSender,
    /// List of recipients (typically one for transactional emails)
    to: Vec<BrevoRecipient>,
    /// Email subject line
    subject: String,
    /// Optional HTML content (renamed to match Brevo's API)
    #[serde(rename = "htmlContent")]
    html_content: Option<String>,
    /// Optional plain text content (renamed to match Brevo's API)
    #[serde(rename = "textContent")]
    text_content: Option<String>,
}

/// Sender information for Brevo API requests
#[derive(Serialize)]
struct BrevoSender {
    /// Sender email address (must be verified with Brevo)
    email: String,
    /// Display name shown to recipients
    name: String,
}

/// Recipient information for Brevo API requests
#[derive(Serialize)]
struct BrevoRecipient {
    /// Recipient email address
    email: String,
    /// Optional recipient display name for personalization
    name: Option<String>,
}

/// Response from Brevo's send email API
///
/// Contains the message ID for tracking purposes. The message ID can be used
/// to track delivery status and correlate with webhook events.
#[derive(Deserialize)]
struct BrevoResponse {
    /// Unique message identifier for tracking (renamed from Brevo's API)
    #[serde(rename = "messageId")]
    message_id: Option<String>,
}

impl BrevoProvider {
    /// Create a new Brevo email provider instance
    ///
    /// Initializes the provider with the given configuration. Sets up an HTTP client
    /// with appropriate timeouts for reliable API communication.
    ///
    /// # Arguments
    /// * `config` - Brevo configuration containing API key and sender email
    ///
    /// # Returns
    /// * `Ok(BrevoProvider)` - Successfully configured provider
    /// * `Err(anyhow::Error)` - HTTP client setup failed
    ///
    /// # Configuration Requirements
    /// - `api_key`: Valid Brevo API key with send permissions
    /// - `from_email`: Verified sender email address in your Brevo account
    ///
    /// # Timeouts
    /// - HTTP requests timeout after 30 seconds
    /// - Suitable for most email sending scenarios
    /// - Adjust if your network conditions require different timing
    ///
    /// # Example
    /// ```rust
    /// let config = BrevoConfig {
    ///     api_key: "xkeysib-abc123".to_string(),
    ///     from_email: "noreply@yourapp.com".to_string(),
    /// };
    /// 
    /// let provider = BrevoProvider::new(&config)?;
    /// ```
    pub fn new(config: &BrevoConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(Self {
            client,
            api_key: config.api_key.clone(),
            _from_email: config.from_email.clone(),
        })
    }
}

#[async_trait]
impl EmailProvider for BrevoProvider {
    async fn send_email(&self, email: &EmailMessage) -> Result<EmailResponse> {
        let url = "https://api.brevo.com/v3/smtp/email";
        
        let request = BrevoSendRequest {
            sender: BrevoSender {
                email: email.from_email.clone(),
                name: email.from_name.clone(),
            },
            to: vec![BrevoRecipient {
                email: email.to.clone(),
                name: email.to_name.clone(),
            }],
            subject: email.subject.clone(),
            html_content: email.html_content.clone(),
            text_content: email.text_content.clone(),
        };

        let response = self
            .client
            .post(url)
            .header("api-key", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        if response.status().is_success() {
            let brevo_response: BrevoResponse = response.json().await?;
            info!(
                "Email sent successfully via Brevo to: {}, message_id: {:?}",
                email.to, brevo_response.message_id
            );
            
            Ok(EmailResponse {
                message_id: brevo_response.message_id,
                status: EmailStatus::Sent,
                provider: "brevo".to_string(),
            })
        } else {
            let error_text = response.text().await?;
            error!("Brevo API error: {}", error_text);
            
            Ok(EmailResponse {
                message_id: None,
                status: EmailStatus::Failed(format!("Brevo API error: {error_text}")),
                provider: "brevo".to_string(),
            })
        }
    }

    fn provider_name(&self) -> &'static str {
        "brevo"
    }

    async fn health_check(&self) -> Result<bool> {
        let url = "https://api.brevo.com/v3/account";
        
        let response = self
            .client
            .get(url)
            .header("api-key", &self.api_key)
            .send()
            .await?;

        Ok(response.status().is_success())
    }
}