use anyhow::Result;
use async_trait::async_trait;
use lettre::{
    message::{header::ContentType, Mailbox, Message},
    transport::smtp::{authentication::Credentials},
    SmtpTransport, Transport,
};
use tracing::{error, info};

use crate::config::email::SmtpConfig;
use crate::email::{EmailMessage, EmailProvider, EmailResponse, EmailStatus};

/// SMTP email provider using lettre
pub struct SmtpProvider {
    transport: SmtpTransport,
    _from_email: String,
}

impl SmtpProvider {
    /// Create new SMTP provider
    pub async fn new(config: &SmtpConfig) -> Result<Self> {
        let credentials = Credentials::new(
            config.username.clone(),
            config.password.clone(),
        );

        let transport = if config.use_tls {
            SmtpTransport::relay(&config.host)?
                .port(config.port)
                .credentials(credentials)
                .build()
        } else {
            SmtpTransport::builder_dangerous(&config.host)
                .port(config.port)
                .credentials(credentials)
                .build()
        };

        Ok(Self {
            transport,
            _from_email: config.from_email.clone(),
        })
    }
}

#[async_trait]
impl EmailProvider for SmtpProvider {
    async fn send_email(&self, email: &EmailMessage) -> Result<EmailResponse> {
        // Parse sender mailbox
        let from_mailbox: Mailbox = format!("{} <{}>", email.from_name, email.from_email)
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid from email: {e}"))?;

        // Parse recipient mailbox
        let to_mailbox: Mailbox = if let Some(to_name) = &email.to_name {
            format!("{} <{}>", to_name, email.to)
        } else {
            email.to.clone()
        }
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid to email: {e}"))?;

        // Build email message
        let message_builder = Message::builder()
            .from(from_mailbox)
            .to(to_mailbox)
            .subject(&email.subject);

        // Add content based on what's available
        let message = if let Some(html_content) = &email.html_content {
            if let Some(text_content) = &email.text_content {
                // Both HTML and text content
                message_builder
                    .multipart(
                        lettre::message::MultiPart::alternative()
                            .singlepart(
                                lettre::message::SinglePart::builder()
                                    .header(ContentType::TEXT_PLAIN)
                                    .body(text_content.clone()),
                            )
                            .singlepart(
                                lettre::message::SinglePart::builder()
                                    .header(ContentType::TEXT_HTML)
                                    .body(html_content.clone()),
                            ),
                    )?
            } else {
                // HTML only
                message_builder
                    .header(ContentType::TEXT_HTML)
                    .body(html_content.clone())?
            }
        } else if let Some(text_content) = &email.text_content {
            // Text only
            message_builder
                .header(ContentType::TEXT_PLAIN)
                .body(text_content.clone())?
        } else {
            return Err(anyhow::anyhow!("Email must have either text or HTML content"));
        };

        // Send email
        match self.transport.send(&message) {
            Ok(response) => {
                info!(
                    "Email sent successfully via SMTP to: {}, response: {:?}",
                    email.to, response
                );
                
                Ok(EmailResponse {
                    message_id: Some(response.first_line().unwrap_or("").to_string()),
                    status: EmailStatus::Sent,
                    provider: "smtp".to_string(),
                })
            }
            Err(e) => {
                error!("SMTP send error: {}", e);
                
                Ok(EmailResponse {
                    message_id: None,
                    status: EmailStatus::Failed(format!("SMTP error: {e}")),
                    provider: "smtp".to_string(),
                })
            }
        }
    }

    fn provider_name(&self) -> &'static str {
        "smtp"
    }

    async fn health_check(&self) -> Result<bool> {
        // For SMTP, we can test the connection
        match self.transport.test_connection() {
            Ok(is_connected) => Ok(is_connected),
            Err(e) => {
                error!("SMTP health check failed: {}", e);
                Ok(false)
            }
        }
    }
}