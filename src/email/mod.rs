//! # Email Service Module
//!
//! This module provides a comprehensive email service with support for multiple providers
//! and templated email content. The service is designed with a provider abstraction
//! pattern to allow runtime switching between different email services.
//!
//! ## Supported Providers
//! - **Brevo (formerly Sendinblue)**: Full API integration with authentication
//! - **SendGrid**: v3 API with personalization support
//! - **SMTP**: Generic SMTP support using the lettre library
//!
//! ## Features
//! - Async email sending with error handling
//! - HTML and text email content support
//! - Built-in email templates with placeholder substitution
//! - Provider health checks for monitoring
//! - Configurable email settings per provider
//!
//! ## Usage
//! ```rust
//! use email::{EmailService, EmailMessage};
//!
//! // Initialize email service from configuration
//! let email_service = EmailService::new(&config.email).await?;
//!
//! // Send verification email
//! email_service.send_verification_email(&user, &token).await?;
//! ```

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod providers;
pub mod templates;

use crate::config::email::EmailConfig;
use crate::models::user::User;

/// Email sending trait for different email service providers
///
/// This trait defines the interface that all email providers must implement.
/// It provides a consistent API for sending emails regardless of the underlying
/// email service (Brevo, SendGrid, SMTP, etc.).
///
/// # Provider Requirements
/// - Must be thread-safe (`Send + Sync`)
/// - Must support async operations
/// - Should implement health checks for monitoring
/// - Should handle errors gracefully and return appropriate responses
#[async_trait]
pub trait EmailProvider: Send + Sync {
    /// Send an email message using this provider
    ///
    /// # Arguments
    /// * `email` - The email message to send, containing recipient, content, etc.
    ///
    /// # Returns
    /// * `Ok(EmailResponse)` - Success response with message ID and status
    /// * `Err(anyhow::Error)` - Network, authentication, or configuration errors
    ///
    /// # Example
    /// ```rust
    /// let response = provider.send_email(&email_message).await?;
    /// if matches!(response.status, EmailStatus::Sent) {
    ///     println!("Email sent successfully: {:?}", response.message_id);
    /// }
    /// ```
    async fn send_email(&self, email: &EmailMessage) -> Result<EmailResponse>;

    /// Get the human-readable name of this email provider
    ///
    /// # Returns
    /// Static string identifying the provider (e.g., "brevo", "sendgrid", "smtp")
    ///
    /// Used for logging, monitoring, and configuration validation.
    fn provider_name(&self) -> &'static str;

    /// Perform a health check to verify the provider is operational
    ///
    /// # Returns
    /// * `Ok(true)` - Provider is healthy and ready to send emails
    /// * `Ok(false)` - Provider has issues but didn't fail completely
    /// * `Err(anyhow::Error)` - Provider is completely unavailable
    ///
    /// # Implementation Notes
    /// - Should test authentication credentials
    /// - Should verify network connectivity to provider
    /// - Should not send actual emails during health checks
    /// - Should complete quickly (< 5 seconds) for monitoring
    async fn health_check(&self) -> Result<bool>;
}

/// Email message structure containing all information needed to send an email
///
/// This structure represents a complete email message with recipient information,
/// content, and sender details. It supports both HTML and plain text content.
///
/// # Required Fields
/// - `to`: Recipient email address (must be valid email format)
/// - `subject`: Email subject line
/// - `from_email`: Sender email address (must be valid and authorized)
/// - `from_name`: Sender display name
///
/// # Content Requirements
/// At least one of `html_content` or `text_content` must be provided.
/// Providing both allows email clients to choose the appropriate format.
///
/// # Example
/// ```rust
/// let email = EmailMessage {
///     to: "user@example.com".to_string(),
///     to_name: Some("John Doe".to_string()),
///     subject: "Welcome to our service".to_string(),
///     html_content: Some("<h1>Welcome!</h1><p>Thanks for joining.</p>".to_string()),
///     text_content: Some("Welcome!\n\nThanks for joining.".to_string()),
///     from_email: "noreply@yourapp.com".to_string(),
///     from_name: "Your App".to_string(),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailMessage {
    /// Recipient email address (required, must be valid email)
    pub to: String,
    /// Optional recipient display name for personalization
    pub to_name: Option<String>,
    /// Email subject line (required, should be descriptive)
    pub subject: String,
    /// Optional HTML content for rich formatting
    /// Should include complete HTML structure if provided
    pub html_content: Option<String>,
    /// Optional plain text content for compatibility
    /// Should be readable without HTML formatting
    pub text_content: Option<String>,
    /// Sender email address (required, must be authorized by provider)
    pub from_email: String,
    /// Sender display name (required, shown to recipient)
    pub from_name: String,
}

/// Response from email sending operation
///
/// Contains the result of an email sending attempt, including status,
/// provider information, and optional message tracking ID.
///
/// # Status Interpretation
/// - `EmailStatus::Sent`: Email was successfully accepted by provider
/// - `EmailStatus::Queued`: Email was queued for delivery by provider
/// - `EmailStatus::Failed(reason)`: Email sending failed with error details
///
/// # Message ID
/// When available, the message ID can be used for:
/// - Tracking delivery status with the email provider
/// - Correlating with webhook notifications
/// - Customer support investigations
///
/// # Example
/// ```rust
/// match response.status {
///     EmailStatus::Sent => {
///         info!("Email sent via {}: {:?}", response.provider, response.message_id);
///     }
///     EmailStatus::Failed(reason) => {
///         error!("Email failed via {}: {}", response.provider, reason);
///     }
///     EmailStatus::Queued => {
///         info!("Email queued via {}", response.provider);
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailResponse {
    /// Optional message ID from the email provider for tracking
    /// Not all providers return message IDs immediately
    pub message_id: Option<String>,
    /// Current status of the email sending operation
    pub status: EmailStatus,
    /// Name of the provider that handled this email
    pub provider: String,
}

/// Email delivery status indicating the current state of an email
///
/// This enum represents the various states an email can be in after
/// attempting to send it through a provider.
///
/// # Variants
/// - `Sent`: Email was successfully accepted and will be delivered
/// - `Queued`: Email was accepted but is waiting in the provider's queue
/// - `Failed(reason)`: Email sending failed with detailed error information
///
/// # Provider Behavior
/// Different providers may return different statuses:
/// - **Brevo**: Returns `Sent` on successful API acceptance
/// - **SendGrid**: Returns `Sent` for 202 Accepted responses
/// - **SMTP**: Returns `Sent` for successful SMTP transaction
///
/// # Error Handling
/// The `Failed` variant includes a descriptive error message that can be:
/// - Logged for debugging purposes
/// - Used to determine retry strategies
/// - Displayed to administrators (not end users)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmailStatus {
    /// Email was successfully sent and accepted by the provider
    Sent,
    /// Email was accepted but is queued for later delivery
    Queued,
    /// Email sending failed with error details
    Failed(String),
}

/// Main email service that manages email providers and templates
///
/// This service provides a high-level interface for sending emails through
/// various providers while handling template rendering and configuration.
/// It acts as the primary entry point for all email operations in the application.
///
/// # Architecture
/// The service uses dependency injection to work with different providers:
/// - **Provider**: Handles the actual email sending (Brevo, SendGrid, SMTP)
/// - **Templates**: Manages email template rendering with placeholder substitution
///
/// # Thread Safety
/// The service is designed to be shared across async tasks and can be safely
/// wrapped in `Arc<EmailService>` for use in web handlers.
///
/// # Configuration
/// The service is configured through `EmailConfig` which determines:
/// - Which email provider to use
/// - Provider-specific settings (API keys, SMTP settings)
/// - Template configuration and paths
///
/// # Example Usage
/// ```rust
/// // Initialize once at application startup
/// let email_service = EmailService::new(&config.email).await?;
/// let email_service = Arc::new(email_service);
///
/// // Use in handlers
/// email_service.send_verification_email(&user, &token).await?;
/// ```
pub struct EmailService {
    /// The email provider implementation (Brevo, SendGrid, SMTP)
    provider: Box<dyn EmailProvider>,
    /// Template engine for rendering email content
    templates: templates::TemplateEngine,
}

impl EmailService {
    /// Create a new email service instance from configuration
    ///
    /// This method initializes the email service with the configured provider
    /// and template engine. It performs provider-specific setup and validation.
    ///
    /// # Arguments
    /// * `config` - Email configuration containing provider settings and template paths
    ///
    /// # Returns
    /// * `Ok(EmailService)` - Successfully initialized email service
    /// * `Err(anyhow::Error)` - Configuration errors, provider setup failures, or template issues
    ///
    /// # Errors
    /// This method can fail for several reasons:
    /// - Invalid provider configuration (missing API keys, bad SMTP settings)
    /// - Network issues during provider validation
    /// - Template file loading errors
    /// - Provider-specific authentication failures
    ///
    /// # Example
    /// ```rust
    /// let config = EmailConfig {
    ///     provider: EmailProvider::Brevo,
    ///     brevo: Some(BrevoConfig {
    ///         api_key: "your-api-key".to_string(),
    ///         from_email: "noreply@yourapp.com".to_string(),
    ///     }),
    ///     templates: EmailTemplates {
    ///         verification: "templates/verification.html".to_string(),
    ///         password_reset: "templates/reset.html".to_string(),
    ///     },
    /// };
    ///
    /// let email_service = EmailService::new(&config).await?;
    /// ```
    pub async fn new(config: &EmailConfig) -> Result<Self> {
        let provider = providers::create_provider(config).await?;
        let templates = templates::TemplateEngine::new(&config.templates)?;

        Ok(Self {
            provider,
            templates,
        })
    }

    /// Send an email verification message to a newly registered user
    ///
    /// This method sends a professional email containing a verification link to confirm
    /// the user's email address. The email includes both HTML and plain text versions
    /// for maximum compatibility.
    ///
    /// # Arguments
    /// * `user` - The user who needs email verification (must have valid email)
    /// * `token` - Unique verification token for this user (should be cryptographically secure)
    ///
    /// # Returns
    /// * `Ok(EmailResponse)` - Email sent successfully with provider response
    /// * `Err(anyhow::Error)` - Template rendering, provider, or network errors
    ///
    /// # Security Considerations
    /// - The verification token should be cryptographically secure and time-limited
    /// - The verification URL should use HTTPS in production
    /// - Consider rate limiting to prevent abuse
    ///
    /// # Template Variables
    /// The verification email template receives:
    /// - `{{name}}` - User's full name
    /// - `{{email}}` - User's email address
    /// - `{{verification_url}}` - Complete verification URL with token
    ///
    /// # Example
    /// ```rust
    /// let verification_token = generate_secure_token();
    /// user.set_email_verification_token(verification_token.clone(), 24); // 24 hours
    ///
    /// let response = email_service
    ///     .send_verification_email(&user, &verification_token)
    ///     .await?;
    ///
    /// match response.status {
    ///     EmailStatus::Sent => info!("Verification email sent to {}", user.email),
    ///     EmailStatus::Failed(reason) => error!("Failed to send verification: {}", reason),
    ///     _ => info!("Verification email queued"),
    /// }
    /// ```
    pub async fn send_verification_email(&self, user: &User, token: &str) -> Result<EmailResponse> {
        let verification_url = format!("https://yourapp.com/verify?token={token}");

        let html_content = self.templates.render_verification_email(
            &user.email,
            &user.full_name(),
            &verification_url,
        )?;

        let email = EmailMessage {
            to: user.email.clone(),
            to_name: Some(user.full_name()),
            subject: "Verify your email address".to_string(),
            html_content: Some(html_content),
            text_content: Some(format!(
                "Please verify your email by visiting: {verification_url}"
            )),
            from_email: self.templates.from_email.clone(),
            from_name: self.templates.from_name.clone(),
        };

        self.provider.send_email(&email).await
    }

    /// Send a password reset email to a user who requested password recovery
    ///
    /// This method sends a secure password reset email containing a time-limited link
    /// that allows the user to set a new password. The email emphasizes security
    /// and includes warnings about unauthorized access attempts.
    ///
    /// # Arguments
    /// * `user` - The user requesting password reset (must be verified user)
    /// * `token` - Unique, time-limited reset token (should expire within 2 hours)
    ///
    /// # Returns
    /// * `Ok(EmailResponse)` - Email sent successfully with provider response
    /// * `Err(anyhow::Error)` - Template rendering, provider, or network errors
    ///
    /// # Security Considerations
    /// - Reset tokens MUST be cryptographically secure and single-use
    /// - Tokens should expire quickly (recommended: 2 hours maximum)
    /// - Consider logging reset attempts for security monitoring
    /// - The reset URL should use HTTPS in production
    /// - Rate limit reset requests to prevent abuse
    ///
    /// # Template Variables
    /// The password reset email template receives:
    /// - `{{name}}` - User's full name
    /// - `{{email}}` - User's email address  
    /// - `{{reset_url}}` - Complete password reset URL with token
    ///
    /// # Example
    /// ```rust
    /// let reset_token = generate_secure_token();
    /// user.set_password_reset_token(reset_token.clone(), 2); // 2 hours
    ///
    /// let response = email_service
    ///     .send_password_reset_email(&user, &reset_token)
    ///     .await?;
    ///
    /// match response.status {
    ///     EmailStatus::Sent => {
    ///         info!("Password reset email sent to {}", user.email);
    ///         // Save user with reset token to database
    ///     }
    ///     EmailStatus::Failed(reason) => {
    ///         error!("Failed to send password reset: {}", reason);
    ///         // Don't save reset token if email failed
    ///     }
    ///     _ => info!("Password reset email queued"),
    /// }
    /// ```
    pub async fn send_password_reset_email(
        &self,
        user: &User,
        token: &str,
    ) -> Result<EmailResponse> {
        let reset_url = format!("https://yourapp.com/reset-password?token={token}");

        let html_content = self.templates.render_password_reset_email(
            &user.email,
            &user.full_name(),
            &reset_url,
        )?;

        let email = EmailMessage {
            to: user.email.clone(),
            to_name: Some(user.full_name()),
            subject: "Reset your password".to_string(),
            html_content: Some(html_content),
            text_content: Some(format!("Reset your password by visiting: {reset_url}")),
            from_email: self.templates.from_email.clone(),
            from_name: self.templates.from_name.clone(),
        };

        self.provider.send_email(&email).await
    }

    /// Send a custom email message through the configured provider
    ///
    /// This is a low-level method for sending custom emails that don't use
    /// the built-in templates. Use this for custom email content or when
    /// integrating with external systems.
    ///
    /// # Arguments
    /// * `email` - Complete email message with all required fields
    ///
    /// # Returns
    /// * `Ok(EmailResponse)` - Email sent successfully
    /// * `Err(anyhow::Error)` - Provider or network errors
    ///
    /// # Note
    /// This method bypasses template rendering and validation. Ensure
    /// the EmailMessage is properly constructed with valid content.
    ///
    /// # Example
    /// ```rust
    /// let custom_email = EmailMessage {
    ///     to: "admin@example.com".to_string(),
    ///     to_name: Some("Admin".to_string()),
    ///     subject: "System Alert".to_string(),
    ///     html_content: Some("<p>System status update</p>".to_string()),
    ///     text_content: Some("System status update".to_string()),
    ///     from_email: "system@yourapp.com".to_string(),
    ///     from_name: "System".to_string(),
    /// };
    ///
    /// let response = email_service.send_email(&custom_email).await?;
    /// ```
    pub async fn send_email(&self, email: &EmailMessage) -> Result<EmailResponse> {
        self.provider.send_email(email).await
    }

    /// Get the name of the currently configured email provider
    ///
    /// Returns a static string identifying which provider is handling emails.
    /// Useful for logging, monitoring, and debugging purposes.
    ///
    /// # Returns
    /// Static string: "brevo", "sendgrid", or "smtp"
    ///
    /// # Example
    /// ```rust
    /// info!("Email service using provider: {}", email_service.provider_name());
    /// ```
    pub fn provider_name(&self) -> &'static str {
        self.provider.provider_name()
    }

    /// Perform a health check on the email service
    ///
    /// Tests the underlying email provider to ensure it's operational.
    /// This method should be called periodically for monitoring and
    /// included in application health check endpoints.
    ///
    /// # Returns
    /// * `Ok(true)` - Email service is healthy and ready
    /// * `Ok(false)` - Email service has issues but is partially functional
    /// * `Err(anyhow::Error)` - Email service is completely unavailable
    ///
    /// # Implementation
    /// - Tests provider authentication and connectivity
    /// - Does not send actual emails
    /// - Should complete quickly (< 5 seconds)
    /// - Safe to call frequently for monitoring
    ///
    /// # Example
    /// ```rust
    /// match email_service.health_check().await {
    ///     Ok(true) => info!("Email service healthy"),
    ///     Ok(false) => warn!("Email service degraded"),
    ///     Err(e) => error!("Email service unavailable: {}", e),
    /// }
    /// ```
    pub async fn health_check(&self) -> Result<bool> {
        self.provider.health_check().await
    }
}
