use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::config::email::BrevoConfig;
use crate::email::{EmailMessage, EmailProvider, EmailResponse, EmailStatus};

/// Brevo (formerly Sendinblue) email provider
pub struct BrevoProvider {
    client: Client,
    api_key: String,
    _from_email: String,
}

#[derive(Serialize)]
struct BrevoSendRequest {
    sender: BrevoSender,
    to: Vec<BrevoRecipient>,
    subject: String,
    #[serde(rename = "htmlContent")]
    html_content: Option<String>,
    #[serde(rename = "textContent")]
    text_content: Option<String>,
}

#[derive(Serialize)]
struct BrevoSender {
    email: String,
    name: String,
}

#[derive(Serialize)]
struct BrevoRecipient {
    email: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct BrevoResponse {
    #[serde(rename = "messageId")]
    message_id: Option<String>,
}

impl BrevoProvider {
    /// Create new Brevo provider
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