use anyhow::Result;
use std::fs;

use crate::config::email::EmailTemplates;

/// Template engine for email content
pub struct TemplateEngine {
    verification_template: Option<String>,
    password_reset_template: Option<String>,
    pub from_email: String,
    pub from_name: String,
}

impl TemplateEngine {
    /// Create new template engine
    pub fn new(config: &EmailTemplates) -> Result<Self> {
        // Try to load templates from files, fall back to built-in templates
        let verification_template = Self::load_template(&config.verification);
        let password_reset_template = Self::load_template(&config.password_reset);

        Ok(Self {
            verification_template,
            password_reset_template,
            from_email: "noreply@yourapp.com".to_string(),
            from_name: "Your App".to_string(),
        })
    }

    /// Load template from file, return None if file doesn't exist
    fn load_template(path: &str) -> Option<String> {
        fs::read_to_string(path).ok()
    }

    /// Render email verification template
    pub fn render_verification_email(
        &self,
        email: &str,
        name: &str,
        verification_url: &str,
    ) -> Result<String> {
        if let Some(template) = &self.verification_template {
            // Replace placeholders in custom template
            let html = template
                .replace("{{name}}", name)
                .replace("{{email}}", email)
                .replace("{{verification_url}}", verification_url);
            Ok(html)
        } else {
            // Use built-in template
            Ok(Self::default_verification_template(name, verification_url))
        }
    }

    /// Render password reset template
    pub fn render_password_reset_email(
        &self,
        email: &str,
        name: &str,
        reset_url: &str,
    ) -> Result<String> {
        if let Some(template) = &self.password_reset_template {
            // Replace placeholders in custom template
            let html = template
                .replace("{{name}}", name)
                .replace("{{email}}", email)
                .replace("{{reset_url}}", reset_url);
            Ok(html)
        } else {
            // Use built-in template
            Ok(Self::default_password_reset_template(name, reset_url))
        }
    }

    /// Default email verification template
    fn default_verification_template(name: &str, verification_url: &str) -> String {
        format!(
            r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Verify Your Email</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #4f46e5; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 30px; background: #f9f9f9; }}
        .button {{ 
            display: inline-block; 
            background: #4f46e5; 
            color: white; 
            padding: 12px 30px; 
            text-decoration: none; 
            border-radius: 5px; 
            margin: 20px 0;
        }}
        .footer {{ padding: 20px; text-align: center; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Verify Your Email Address</h1>
        </div>
        <div class="content">
            <p>Hello {name},</p>
            <p>Thank you for signing up! Please click the button below to verify your email address and activate your account.</p>
            <p style="text-align: center;">
                <a href="{verification_url}" class="button">Verify Email Address</a>
            </p>
            <p>If you can't click the button, copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #666;">{verification_url}</p>
            <p>This verification link will expire in 24 hours for security reasons.</p>
            <p>If you didn't create this account, you can safely ignore this email.</p>
        </div>
        <div class="footer">
            <p>This email was sent from an automated system. Please do not reply.</p>
        </div>
    </div>
</body>
</html>
"#
        )
    }

    /// Default password reset template
    fn default_password_reset_template(name: &str, reset_url: &str) -> String {
        format!(
            r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Reset Your Password</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #dc2626; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 30px; background: #f9f9f9; }}
        .button {{ 
            display: inline-block; 
            background: #dc2626; 
            color: white; 
            padding: 12px 30px; 
            text-decoration: none; 
            border-radius: 5px; 
            margin: 20px 0;
        }}
        .footer {{ padding: 20px; text-align: center; color: #666; font-size: 12px; }}
        .warning {{ background: #fef3cd; border: 1px solid #f6e05e; padding: 15px; border-radius: 5px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Reset Your Password</h1>
        </div>
        <div class="content">
            <p>Hello {name},</p>
            <p>We received a request to reset the password for your account. Click the button below to set a new password.</p>
            <p style="text-align: center;">
                <a href="{reset_url}" class="button">Reset Password</a>
            </p>
            <p>If you can't click the button, copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #666;">{reset_url}</p>
            <div class="warning">
                <strong>Security Notice:</strong> This password reset link will expire in 2 hours. If you didn't request this password reset, please ignore this email or contact support if you have concerns.
            </div>
            <p>For your security, never share this link with anyone.</p>
        </div>
        <div class="footer">
            <p>This email was sent from an automated system. Please do not reply.</p>
        </div>
    </div>
</body>
</html>
"#
        )
    }
}