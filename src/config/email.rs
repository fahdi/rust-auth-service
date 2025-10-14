use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub provider: String, // brevo, sendgrid, smtp
    pub from_email: String,
    pub from_name: String,
    pub brevo: Option<BrevoConfig>,
    pub sendgrid: Option<SendGridConfig>,
    pub smtp: Option<SmtpConfig>,
    pub templates: EmailTemplates,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrevoConfig {
    pub api_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendGridConfig {
    pub api_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub use_tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailTemplates {
    pub verification: String,
    pub password_reset: String,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            provider: "brevo".to_string(),
            from_email: "noreply@yourapp.com".to_string(),
            from_name: "Your App".to_string(),
            brevo: Some(BrevoConfig {
                api_key: "your-brevo-api-key".to_string(),
            }),
            sendgrid: None,
            smtp: None,
            templates: EmailTemplates::default(),
        }
    }
}

impl Default for EmailTemplates {
    fn default() -> Self {
        Self {
            verification: "templates/verification.html".to_string(),
            password_reset: "templates/password_reset.html".to_string(),
        }
    }
}
