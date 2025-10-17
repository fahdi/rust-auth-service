use anyhow::Result;

pub mod brevo;
pub mod sendgrid;
pub mod smtp;

use crate::config::email::EmailConfig;
use crate::email::EmailProvider;

/// Create email provider based on configuration
pub async fn create_provider(config: &EmailConfig) -> Result<Box<dyn EmailProvider>> {
    match config.provider.as_str() {
        "brevo" => {
            let brevo_config = config.brevo.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Brevo configuration missing"))?;
            Ok(Box::new(brevo::BrevoProvider::new(brevo_config)?))
        }
        "sendgrid" => {
            let sendgrid_config = config.sendgrid.as_ref()
                .ok_or_else(|| anyhow::anyhow!("SendGrid configuration missing"))?;
            Ok(Box::new(sendgrid::SendGridProvider::new(sendgrid_config)?))
        }
        "smtp" => {
            let smtp_config = config.smtp.as_ref()
                .ok_or_else(|| anyhow::anyhow!("SMTP configuration missing"))?;
            Ok(Box::new(smtp::SmtpProvider::new(smtp_config).await?))
        }
        _ => Err(anyhow::anyhow!("Unsupported email provider: {}", config.provider)),
    }
}