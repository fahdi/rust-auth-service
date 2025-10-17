use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod providers;
pub mod templates;

use crate::config::email::EmailConfig;
use crate::models::user::User;

/// Email sending trait for different providers
#[async_trait]
pub trait EmailProvider: Send + Sync {
    /// Send an email
    async fn send_email(&self, email: &EmailMessage) -> Result<EmailResponse>;
    
    /// Get provider name
    fn provider_name(&self) -> &'static str;
    
    /// Check if provider is configured correctly
    async fn health_check(&self) -> Result<bool>;
}

/// Email message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailMessage {
    pub to: String,
    pub to_name: Option<String>,
    pub subject: String,
    pub html_content: Option<String>,
    pub text_content: Option<String>,
    pub from_email: String,
    pub from_name: String,
}

/// Email sending response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailResponse {
    pub message_id: Option<String>,
    pub status: EmailStatus,
    pub provider: String,
}

/// Email delivery status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmailStatus {
    Sent,
    Queued,
    Failed(String),
}

/// Email service that manages different providers
pub struct EmailService {
    provider: Box<dyn EmailProvider>,
    templates: templates::TemplateEngine,
}

impl EmailService {
    /// Create new email service with specified provider
    pub async fn new(config: &EmailConfig) -> Result<Self> {
        let provider = providers::create_provider(config).await?;
        let templates = templates::TemplateEngine::new(&config.templates)?;
        
        Ok(Self {
            provider,
            templates,
        })
    }

    /// Send email verification message
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

    /// Send password reset email
    pub async fn send_password_reset_email(&self, user: &User, token: &str) -> Result<EmailResponse> {
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
            text_content: Some(format!(
                "Reset your password by visiting: {reset_url}"
            )),
            from_email: self.templates.from_email.clone(),
            from_name: self.templates.from_name.clone(),
        };

        self.provider.send_email(&email).await
    }

    /// Send generic email
    pub async fn send_email(&self, email: &EmailMessage) -> Result<EmailResponse> {
        self.provider.send_email(email).await
    }

    /// Get provider name
    pub fn provider_name(&self) -> &'static str {
        self.provider.provider_name()
    }

    /// Check email service health
    pub async fn health_check(&self) -> Result<bool> {
        self.provider.health_check().await
    }
}