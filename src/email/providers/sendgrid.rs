use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde::Serialize;
use tracing::{error, info};

use crate::config::email::SendGridConfig;
use crate::email::{EmailMessage, EmailProvider, EmailResponse, EmailStatus};

/// SendGrid email provider
pub struct SendGridProvider {
    client: Client,
    api_key: String,
    _from_email: String,
}

#[derive(Serialize)]
struct SendGridRequest {
    personalizations: Vec<SendGridPersonalization>,
    from: SendGridEmail,
    subject: String,
    content: Vec<SendGridContent>,
}

#[derive(Serialize)]
struct SendGridPersonalization {
    to: Vec<SendGridEmail>,
}

#[derive(Serialize)]
struct SendGridEmail {
    email: String,
    name: Option<String>,
}

#[derive(Serialize)]
struct SendGridContent {
    #[serde(rename = "type")]
    content_type: String,
    value: String,
}

// SendGrid returns 202 Accepted with empty body, so no response struct needed

impl SendGridProvider {
    /// Create new SendGrid provider
    pub fn new(config: &SendGridConfig) -> Result<Self> {
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
impl EmailProvider for SendGridProvider {
    async fn send_email(&self, email: &EmailMessage) -> Result<EmailResponse> {
        let url = "https://api.sendgrid.com/v3/mail/send";
        
        let mut content = Vec::new();
        
        if let Some(text) = &email.text_content {
            content.push(SendGridContent {
                content_type: "text/plain".to_string(),
                value: text.clone(),
            });
        }
        
        if let Some(html) = &email.html_content {
            content.push(SendGridContent {
                content_type: "text/html".to_string(),
                value: html.clone(),
            });
        }

        let request = SendGridRequest {
            personalizations: vec![SendGridPersonalization {
                to: vec![SendGridEmail {
                    email: email.to.clone(),
                    name: email.to_name.clone(),
                }],
            }],
            from: SendGridEmail {
                email: email.from_email.clone(),
                name: Some(email.from_name.clone()),
            },
            subject: email.subject.clone(),
            content,
        };

        let response = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        if response.status().is_success() {
            // SendGrid returns 202 Accepted with empty body on success
            info!("Email sent successfully via SendGrid to: {}", email.to);
            
            Ok(EmailResponse {
                message_id: None, // SendGrid doesn't return message ID in response
                status: EmailStatus::Sent,
                provider: "sendgrid".to_string(),
            })
        } else {
            let error_text = response.text().await?;
            error!("SendGrid API error: {}", error_text);
            
            Ok(EmailResponse {
                message_id: None,
                status: EmailStatus::Failed(format!("SendGrid API error: {error_text}")),
                provider: "sendgrid".to_string(),
            })
        }
    }

    fn provider_name(&self) -> &'static str {
        "sendgrid"
    }

    async fn health_check(&self) -> Result<bool> {
        // SendGrid doesn't have a simple health check endpoint
        // We'll try to get API key info instead
        let url = "https://api.sendgrid.com/v3/user/account";
        
        let response = self
            .client
            .get(url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await?;

        Ok(response.status().is_success())
    }
}