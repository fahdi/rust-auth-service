use std::collections::HashMap;
use std::time::{Duration, Instant};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use super::{HealthCheck, HealthReport, HealthStatus};

/// Alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// Alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    pub enabled: bool,
    pub channels: Vec<AlertChannel>,
    pub cooldown_seconds: u64,
    pub escalation_enabled: bool,
    pub escalation_delay_seconds: u64,
}

/// Alert channel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertChannel {
    pub name: String,
    pub channel_type: AlertChannelType,
    pub enabled: bool,
    pub severity_filter: Vec<AlertSeverity>,
    pub config: HashMap<String, String>,
}

/// Types of alert channels
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AlertChannelType {
    Email {
        to: Vec<String>,
        from: String,
        subject_prefix: String,
    },
    Slack {
        webhook_url: String,
        channel: String,
        username: String,
    },
    PagerDuty {
        service_key: String,
        component: String,
    },
    Webhook {
        url: String,
        method: String,
        headers: HashMap<String, String>,
    },
    Log {
        level: String,
    },
}

/// Alert message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub title: String,
    pub message: String,
    pub severity: AlertSeverity,
    pub service: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source_check: String,
    pub details: Option<HashMap<String, serde_json::Value>>,
    pub resolved: bool,
    pub resolution_time: Option<chrono::DateTime<chrono::Utc>>,
}

/// Alert manager for handling health check alerts
pub struct AlertManager {
    config: AlertConfig,
    active_alerts: RwLock<HashMap<String, Alert>>,
    last_notification: RwLock<HashMap<String, Instant>>,
    alert_history: RwLock<Vec<Alert>>,
}

impl AlertManager {
    /// Create new alert manager
    pub fn new(config: AlertConfig) -> Self {
        Self {
            config,
            active_alerts: RwLock::new(HashMap::new()),
            last_notification: RwLock::new(HashMap::new()),
            alert_history: RwLock::new(Vec::new()),
        }
    }

    /// Process health report and generate alerts
    pub async fn process_health_report(&self, report: &HealthReport) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        for check in &report.checks {
            match check.status {
                HealthStatus::Critical => {
                    self.handle_critical_check(check).await?;
                }
                HealthStatus::Warning => {
                    self.handle_warning_check(check).await?;
                }
                HealthStatus::Healthy => {
                    self.handle_healthy_check(check).await?;
                }
                HealthStatus::Unknown => {
                    self.handle_unknown_check(check).await?;
                }
            }
        }

        Ok(())
    }

    /// Handle critical health check
    async fn handle_critical_check(&self, check: &HealthCheck) -> Result<()> {
        let alert_id = format!("critical_{}", check.name);
        
        // Check if alert already exists and is recent
        if self.should_suppress_alert(&alert_id).await {
            return Ok(());
        }

        let alert = Alert {
            id: alert_id.clone(),
            title: format!("CRITICAL: {} Health Check Failed", check.name),
            message: format!(
                "Health check '{}' is in critical state: {}\nLatency: {}ms\nTimestamp: {}",
                check.name, check.message, check.latency_ms, check.timestamp
            ),
            severity: AlertSeverity::Critical,
            service: "auth-service".to_string(),
            timestamp: chrono::Utc::now(),
            source_check: check.name.clone(),
            details: check.details.clone(),
            resolved: false,
            resolution_time: None,
        };

        self.send_alert(&alert).await?;
        self.store_alert(alert).await;
        self.update_last_notification(alert_id).await;

        Ok(())
    }

    /// Handle warning health check
    async fn handle_warning_check(&self, check: &HealthCheck) -> Result<()> {
        let alert_id = format!("warning_{}", check.name);
        
        if self.should_suppress_alert(&alert_id).await {
            return Ok(());
        }

        let alert = Alert {
            id: alert_id.clone(),
            title: format!("WARNING: {} Health Check Degraded", check.name),
            message: format!(
                "Health check '{}' is in warning state: {}\nLatency: {}ms\nTimestamp: {}",
                check.name, check.message, check.latency_ms, check.timestamp
            ),
            severity: AlertSeverity::Warning,
            service: "auth-service".to_string(),
            timestamp: chrono::Utc::now(),
            source_check: check.name.clone(),
            details: check.details.clone(),
            resolved: false,
            resolution_time: None,
        };

        self.send_alert(&alert).await?;
        self.store_alert(alert).await;
        self.update_last_notification(alert_id).await;

        Ok(())
    }

    /// Handle healthy check (resolve alerts if needed)
    async fn handle_healthy_check(&self, check: &HealthCheck) -> Result<()> {
        let critical_alert_id = format!("critical_{}", check.name);
        let warning_alert_id = format!("warning_{}", check.name);

        // Resolve any active alerts for this check
        self.resolve_alert(&critical_alert_id, check).await?;
        self.resolve_alert(&warning_alert_id, check).await?;

        Ok(())
    }

    /// Handle unknown health check
    async fn handle_unknown_check(&self, check: &HealthCheck) -> Result<()> {
        let alert_id = format!("unknown_{}", check.name);
        
        if self.should_suppress_alert(&alert_id).await {
            return Ok(());
        }

        let alert = Alert {
            id: alert_id.clone(),
            title: format!("INFO: {} Health Check Unknown", check.name),
            message: format!(
                "Health check '{}' returned unknown status: {}\nLatency: {}ms\nTimestamp: {}",
                check.name, check.message, check.latency_ms, check.timestamp
            ),
            severity: AlertSeverity::Info,
            service: "auth-service".to_string(),
            timestamp: chrono::Utc::now(),
            source_check: check.name.clone(),
            details: check.details.clone(),
            resolved: false,
            resolution_time: None,
        };

        self.send_alert(&alert).await?;
        self.store_alert(alert).await;
        self.update_last_notification(alert_id).await;

        Ok(())
    }

    /// Resolve an active alert
    async fn resolve_alert(&self, alert_id: &str, check: &HealthCheck) -> Result<()> {
        let mut active_alerts = self.active_alerts.write().await;
        
        if let Some(mut alert) = active_alerts.remove(alert_id) {
            alert.resolved = true;
            alert.resolution_time = Some(chrono::Utc::now());

            // Send resolution notification
            let resolution_alert = Alert {
                id: format!("{}_resolved", alert_id),
                title: format!("RESOLVED: {} Health Check Recovered", check.name),
                message: format!(
                    "Health check '{}' has recovered and is now healthy: {}\nAlert was active since: {}",
                    check.name, check.message, alert.timestamp
                ),
                severity: AlertSeverity::Info,
                service: "auth-service".to_string(),
                timestamp: chrono::Utc::now(),
                source_check: check.name.clone(),
                details: check.details.clone(),
                resolved: true,
                resolution_time: Some(chrono::Utc::now()),
            };

            self.send_alert(&resolution_alert).await?;

            // Update history
            let mut history = self.alert_history.write().await;
            history.push(alert);
            history.push(resolution_alert);

            // Keep only last 1000 alerts in history
            if history.len() > 1000 {
                history.drain(0..history.len() - 1000);
            }
        }

        Ok(())
    }

    /// Check if alert should be suppressed due to cooldown
    async fn should_suppress_alert(&self, alert_id: &str) -> bool {
        let last_notification = self.last_notification.read().await;
        
        if let Some(last_time) = last_notification.get(alert_id) {
            let cooldown = Duration::from_secs(self.config.cooldown_seconds);
            return last_time.elapsed() < cooldown;
        }

        false
    }

    /// Send alert through configured channels
    async fn send_alert(&self, alert: &Alert) -> Result<()> {
        for channel in &self.config.channels {
            if !channel.enabled {
                continue;
            }

            // Check severity filter
            if !channel.severity_filter.contains(&alert.severity) {
                continue;
            }

            match self.send_to_channel(alert, channel).await {
                Ok(_) => {
                    tracing::info!(
                        "Alert sent successfully to channel '{}' for alert '{}'",
                        channel.name, alert.id
                    );
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to send alert '{}' to channel '{}': {}",
                        alert.id, channel.name, e
                    );
                }
            }
        }

        Ok(())
    }

    /// Send alert to specific channel
    async fn send_to_channel(&self, alert: &Alert, channel: &AlertChannel) -> Result<()> {
        match &channel.channel_type {
            AlertChannelType::Email { to, from, subject_prefix } => {
                self.send_email_alert(alert, to, from, subject_prefix).await
            }
            AlertChannelType::Slack { webhook_url, channel: slack_channel, username } => {
                self.send_slack_alert(alert, webhook_url, slack_channel, username).await
            }
            AlertChannelType::PagerDuty { service_key, component } => {
                self.send_pagerduty_alert(alert, service_key, component).await
            }
            AlertChannelType::Webhook { url, method, headers } => {
                self.send_webhook_alert(alert, url, method, headers).await
            }
            AlertChannelType::Log { level } => {
                self.send_log_alert(alert, level).await
            }
        }
    }

    /// Send email alert
    async fn send_email_alert(
        &self,
        alert: &Alert,
        to: &[String],
        from: &str,
        subject_prefix: &str,
    ) -> Result<()> {
        let subject = format!("{} {}", subject_prefix, alert.title);
        let body = self.format_alert_email(alert);

        // Here you would integrate with your email service
        // For now, we'll just log it
        tracing::info!(
            "EMAIL ALERT: To: {:?}, From: {}, Subject: {}, Body: {}",
            to, from, subject, body
        );

        Ok(())
    }

    /// Send Slack alert
    async fn send_slack_alert(
        &self,
        alert: &Alert,
        webhook_url: &str,
        channel: &str,
        username: &str,
    ) -> Result<()> {
        let color = match alert.severity {
            AlertSeverity::Critical => "danger",
            AlertSeverity::Warning => "warning",
            AlertSeverity::Info => "good",
        };

        let payload = serde_json::json!({
            "channel": channel,
            "username": username,
            "attachments": [{
                "color": color,
                "title": alert.title,
                "text": alert.message,
                "fields": [
                    {
                        "title": "Service",
                        "value": alert.service,
                        "short": true
                    },
                    {
                        "title": "Severity",
                        "value": format!("{:?}", alert.severity),
                        "short": true
                    },
                    {
                        "title": "Timestamp",
                        "value": alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                        "short": true
                    }
                ]
            }]
        });

        // Send HTTP request to Slack webhook
        let client = reqwest::Client::new();
        let response = client
            .post(webhook_url)
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Slack webhook request failed with status: {}",
                response.status()
            ));
        }

        Ok(())
    }

    /// Send PagerDuty alert
    async fn send_pagerduty_alert(
        &self,
        alert: &Alert,
        service_key: &str,
        component: &str,
    ) -> Result<()> {
        let event_type = if alert.resolved { "resolve" } else { "trigger" };
        
        let payload = serde_json::json!({
            "service_key": service_key,
            "event_type": event_type,
            "incident_key": alert.id,
            "description": alert.title,
            "details": {
                "message": alert.message,
                "service": alert.service,
                "component": component,
                "severity": format!("{:?}", alert.severity),
                "timestamp": alert.timestamp.to_rfc3339()
            }
        });

        let client = reqwest::Client::new();
        let response = client
            .post("https://events.pagerduty.com/generic/2010-04-15/create_event.json")
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "PagerDuty API request failed with status: {}",
                response.status()
            ));
        }

        Ok(())
    }

    /// Send webhook alert
    async fn send_webhook_alert(
        &self,
        alert: &Alert,
        url: &str,
        method: &str,
        headers: &HashMap<String, String>,
    ) -> Result<()> {
        let client = reqwest::Client::new();
        let mut request = match method.to_uppercase().as_str() {
            "POST" => client.post(url),
            "PUT" => client.put(url),
            "PATCH" => client.patch(url),
            _ => return Err(anyhow::anyhow!("Unsupported HTTP method: {}", method)),
        };

        // Add headers
        for (key, value) in headers {
            request = request.header(key, value);
        }

        // Send alert as JSON payload
        let response = request.json(alert).send().await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Webhook request failed with status: {}",
                response.status()
            ));
        }

        Ok(())
    }

    /// Send log alert
    async fn send_log_alert(&self, alert: &Alert, level: &str) -> Result<()> {
        let log_message = format!(
            "ALERT [{}] {}: {} (Source: {}, Service: {})",
            format!("{:?}", alert.severity).to_uppercase(),
            alert.title,
            alert.message,
            alert.source_check,
            alert.service
        );

        match level.to_lowercase().as_str() {
            "error" => tracing::error!("{}", log_message),
            "warn" => tracing::warn!("{}", log_message),
            "info" => tracing::info!("{}", log_message),
            "debug" => tracing::debug!("{}", log_message),
            _ => tracing::info!("{}", log_message),
        }

        Ok(())
    }

    /// Format alert for email
    fn format_alert_email(&self, alert: &Alert) -> String {
        format!(
            r#"
Alert Details:
==============

Alert ID: {}
Title: {}
Severity: {:?}
Service: {}
Source Check: {}
Timestamp: {}

Message:
--------
{}

{}

--
Automated Alert from Auth Service Health Monitor
"#,
            alert.id,
            alert.title,
            alert.severity,
            alert.service,
            alert.source_check,
            alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            alert.message,
            if alert.resolved {
                format!("Resolved at: {}", 
                    alert.resolution_time
                        .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "Unknown".to_string())
                )
            } else {
                "Status: ACTIVE".to_string()
            }
        )
    }

    /// Store alert in active alerts
    async fn store_alert(&self, alert: Alert) {
        let mut active_alerts = self.active_alerts.write().await;
        active_alerts.insert(alert.id.clone(), alert);
    }

    /// Update last notification time
    async fn update_last_notification(&self, alert_id: String) {
        let mut last_notification = self.last_notification.write().await;
        last_notification.insert(alert_id, Instant::now());
    }

    /// Get active alerts
    pub async fn get_active_alerts(&self) -> HashMap<String, Alert> {
        self.active_alerts.read().await.clone()
    }

    /// Get alert history
    pub async fn get_alert_history(&self, limit: Option<usize>) -> Vec<Alert> {
        let history = self.alert_history.read().await;
        let len = history.len();
        
        match limit {
            Some(limit) if limit < len => {
                history[len - limit..].to_vec()
            }
            _ => history.clone(),
        }
    }

    /// Clear resolved alerts from history older than specified days
    pub async fn cleanup_old_alerts(&self, days: u32) -> usize {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
        let mut history = self.alert_history.write().await;
        
        let original_len = history.len();
        history.retain(|alert| alert.timestamp > cutoff);
        
        original_len - history.len()
    }
}