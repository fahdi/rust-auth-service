use super::{
    Permission, PermissionCheckResult, PermissionConditions, UserContext, UserGroup,
    UserManagementService,
};
use crate::models::user::UserRole;
use anyhow::Result;
use chrono::{Datelike, Timelike, Utc};
use regex::Regex;
use std::collections::{HashMap, HashSet};

/// Permission evaluator for checking access control
pub struct PermissionEvaluator<T: UserManagementService> {
    service: T,
    wildcard_cache: HashMap<String, Vec<String>>,
}

impl<T: UserManagementService> PermissionEvaluator<T> {
    /// Create new permission evaluator
    pub fn new(service: T) -> Self {
        Self {
            service,
            wildcard_cache: HashMap::new(),
        }
    }

    /// Check if user has specific permission
    pub async fn check_permission(
        &mut self,
        user_id: &str,
        required_permission: &str,
        context: Option<UserContext>,
    ) -> Result<PermissionCheckResult> {
        // Get user's effective permissions
        let user_permissions = self.service.get_user_permissions(user_id).await?;

        // Check direct permission match
        if user_permissions.contains(required_permission) {
            return self
                .evaluate_permission_conditions(required_permission, context)
                .await;
        }

        // Check wildcard permissions
        for user_perm in &user_permissions {
            if self.matches_wildcard_permission(user_perm, required_permission)? {
                return self
                    .evaluate_permission_conditions(user_perm, context)
                    .await;
            }
        }

        Ok(PermissionCheckResult {
            granted: false,
            reason: format!(
                "User {} does not have permission: {}",
                user_id, required_permission
            ),
            conditions_met: false,
            required_permissions: vec![required_permission.to_string()],
            missing_permissions: vec![required_permission.to_string()],
        })
    }

    /// Check if user has any of the required permissions
    pub async fn check_any_permission(
        &mut self,
        user_id: &str,
        required_permissions: &[String],
        context: Option<UserContext>,
    ) -> Result<PermissionCheckResult> {
        let mut missing_permissions = Vec::new();

        for permission in required_permissions {
            let result = self
                .check_permission(user_id, permission, context.clone())
                .await?;
            if result.granted {
                return Ok(result);
            }
            missing_permissions.push(permission.clone());
        }

        Ok(PermissionCheckResult {
            granted: false,
            reason: format!(
                "User {} does not have any of the required permissions",
                user_id
            ),
            conditions_met: false,
            required_permissions: required_permissions.to_vec(),
            missing_permissions,
        })
    }

    /// Check if user has all required permissions
    pub async fn check_all_permissions(
        &mut self,
        user_id: &str,
        required_permissions: &[String],
        context: Option<UserContext>,
    ) -> Result<PermissionCheckResult> {
        let mut missing_permissions = Vec::new();

        for permission in required_permissions {
            let result = self
                .check_permission(user_id, permission, context.clone())
                .await?;
            if !result.granted {
                missing_permissions.push(permission.clone());
            }
        }

        if missing_permissions.is_empty() {
            Ok(PermissionCheckResult {
                granted: true,
                reason: "All required permissions granted".to_string(),
                conditions_met: true,
                required_permissions: required_permissions.to_vec(),
                missing_permissions: vec![],
            })
        } else {
            Ok(PermissionCheckResult {
                granted: false,
                reason: format!(
                    "User {} is missing {} permissions",
                    user_id,
                    missing_permissions.len()
                ),
                conditions_met: false,
                required_permissions: required_permissions.to_vec(),
                missing_permissions,
            })
        }
    }

    /// Evaluate permission conditions (time-based, IP-based, etc.)
    async fn evaluate_permission_conditions(
        &self,
        permission_id: &str,
        context: Option<UserContext>,
    ) -> Result<PermissionCheckResult> {
        let permission = self
            .service
            .get_permission(permission_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Permission not found: {}", permission_id))?;

        if let Some(conditions) = &permission.conditions {
            if let Some(ctx) = context {
                return self.evaluate_conditions(conditions, &ctx).await;
            } else if self.requires_context(conditions) {
                return Ok(PermissionCheckResult {
                    granted: false,
                    reason: "Permission requires context but none provided".to_string(),
                    conditions_met: false,
                    required_permissions: vec![permission_id.to_string()],
                    missing_permissions: vec![],
                });
            }
        }

        Ok(PermissionCheckResult {
            granted: true,
            reason: "Permission granted".to_string(),
            conditions_met: true,
            required_permissions: vec![permission_id.to_string()],
            missing_permissions: vec![],
        })
    }

    /// Evaluate specific permission conditions
    async fn evaluate_conditions(
        &self,
        conditions: &PermissionConditions,
        context: &UserContext,
    ) -> Result<PermissionCheckResult> {
        let mut reasons = Vec::new();

        // Time-based conditions
        if let Some(time_condition) = &conditions.time_based {
            if !self.check_time_condition(time_condition) {
                reasons.push("Time-based condition not met".to_string());
            }
        }

        // IP-based conditions
        if let Some(ip_condition) = &conditions.ip_based {
            if !self.check_ip_condition(ip_condition, context) {
                reasons.push("IP-based condition not met".to_string());
            }
        }

        // Attribute-based conditions
        if let Some(attr_condition) = &conditions.attribute_based {
            if !self.check_attribute_condition(attr_condition, context) {
                reasons.push("Attribute-based condition not met".to_string());
            }
        }

        let conditions_met = reasons.is_empty();
        let reason = if conditions_met {
            "All conditions met".to_string()
        } else {
            reasons.join("; ")
        };

        Ok(PermissionCheckResult {
            granted: conditions_met,
            reason,
            conditions_met,
            required_permissions: vec![],
            missing_permissions: vec![],
        })
    }

    /// Check time-based conditions
    fn check_time_condition(&self, condition: &super::TimeBasedCondition) -> bool {
        let now = Utc::now();

        // Check allowed hours
        if let Some(allowed_hours) = &condition.allowed_hours {
            let current_hour = now.time().hour() as u8;
            if !allowed_hours.contains(&current_hour) {
                return false;
            }
        }

        // Check allowed days
        if let Some(allowed_days) = &condition.allowed_days {
            let current_day = now.weekday().num_days_from_sunday() as u8;
            if !allowed_days.contains(&current_day) {
                return false;
            }
        }

        true
    }

    /// Check IP-based conditions
    fn check_ip_condition(
        &self,
        condition: &super::IpBasedCondition,
        context: &UserContext,
    ) -> bool {
        if let Some(ip) = &context.ip_address {
            // Check blocked IPs first
            if condition.blocked_ips.contains(ip) {
                return false;
            }

            // Check allowed IPs
            if !condition.allowed_ips.is_empty() && !condition.allowed_ips.contains(ip) {
                return false;
            }

            // TODO: Implement country-based IP checking
            // This would require a GeoIP database
        }

        true
    }

    /// Check attribute-based conditions
    fn check_attribute_condition(
        &self,
        _condition: &super::AttributeBasedCondition,
        _context: &UserContext,
    ) -> bool {
        // TODO: Implement attribute-based checking
        // This would check user attributes against required/forbidden attributes
        true
    }

    /// Check if conditions require context
    fn requires_context(&self, conditions: &PermissionConditions) -> bool {
        conditions.ip_based.is_some() || conditions.attribute_based.is_some()
    }

    /// Check if permission matches wildcard pattern
    fn matches_wildcard_permission(&mut self, wildcard: &str, specific: &str) -> Result<bool> {
        if wildcard == "*" {
            return Ok(true);
        }

        if wildcard.ends_with(":*") {
            let resource = wildcard.trim_end_matches(":*");
            return Ok(specific.starts_with(&format!("{}:", resource)));
        }

        // Support regex patterns in permissions
        if wildcard.contains('*') || wildcard.contains('?') || wildcard.contains('[') {
            let pattern = self.wildcard_to_regex(wildcard)?;
            let regex = Regex::new(&pattern)?;
            return Ok(regex.is_match(specific));
        }

        Ok(false)
    }

    /// Convert wildcard pattern to regex
    fn wildcard_to_regex(&self, wildcard: &str) -> Result<String> {
        let mut regex = String::new();
        regex.push('^');

        for ch in wildcard.chars() {
            match ch {
                '*' => regex.push_str(".*"),
                '?' => regex.push('.'),
                '[' | ']' => regex.push(ch),
                _ => {
                    if "{}()^$.|\\+".contains(ch) {
                        regex.push('\\');
                    }
                    regex.push(ch);
                }
            }
        }

        regex.push('$');
        Ok(regex)
    }
}

/// Permission validator for permission definitions
pub struct PermissionValidator {
    valid_resources: HashSet<String>,
    valid_actions: HashSet<String>,
}

impl PermissionValidator {
    /// Create new permission validator
    pub fn new() -> Self {
        let mut validator = Self {
            valid_resources: HashSet::new(),
            valid_actions: HashSet::new(),
        };

        // Add default valid resources and actions
        validator.add_default_resources();
        validator.add_default_actions();

        validator
    }

    /// Add default valid resources
    fn add_default_resources(&mut self) {
        let resources = vec![
            "users",
            "roles",
            "permissions",
            "groups",
            "profile",
            "auth",
            "system",
            "public",
            "content",
            "reports",
            "analytics",
            "audit",
        ];

        for resource in resources {
            self.valid_resources.insert(resource.to_string());
        }
    }

    /// Add default valid actions
    fn add_default_actions(&mut self) {
        let actions = vec![
            "create",
            "read",
            "update",
            "delete",
            "list",
            "search",
            "execute",
            "manage",
            "admin",
            "moderate",
            "approve",
            "login",
            "logout",
            "change_password",
            "suspend",
            "activate",
        ];

        for action in actions {
            self.valid_actions.insert(action.to_string());
        }
    }

    /// Validate permission definition
    pub fn validate_permission(&self, permission: &Permission) -> Result<()> {
        // Validate ID format
        if permission.id.is_empty() {
            return Err(anyhow::anyhow!("Permission ID cannot be empty"));
        }

        if !permission.id.contains(':') && permission.id != "*" {
            return Err(anyhow::anyhow!(
                "Permission ID must be in format 'resource:action' or '*'"
            ));
        }

        // Validate resource and action
        if permission.id != "*" {
            let parts: Vec<&str> = permission.id.split(':').collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!(
                    "Invalid permission format: {}",
                    permission.id
                ));
            }

            let resource = parts[0];
            let action = parts[1];

            if resource != "*" && !self.valid_resources.contains(resource) {
                return Err(anyhow::anyhow!("Invalid resource: {}", resource));
            }

            if action != "*" && !self.valid_actions.contains(action) {
                return Err(anyhow::anyhow!("Invalid action: {}", action));
            }
        }

        // Validate name and description
        if permission.name.is_empty() {
            return Err(anyhow::anyhow!("Permission name cannot be empty"));
        }

        if permission.description.is_empty() {
            return Err(anyhow::anyhow!("Permission description cannot be empty"));
        }

        // Validate conditions if present
        if let Some(conditions) = &permission.conditions {
            self.validate_conditions(conditions)?;
        }

        Ok(())
    }

    /// Validate permission conditions
    fn validate_conditions(&self, conditions: &PermissionConditions) -> Result<()> {
        // Validate time-based conditions
        if let Some(time_condition) = &conditions.time_based {
            if let Some(hours) = &time_condition.allowed_hours {
                for hour in hours {
                    if *hour > 23 {
                        return Err(anyhow::anyhow!("Invalid hour: {}", hour));
                    }
                }
            }

            if let Some(days) = &time_condition.allowed_days {
                for day in days {
                    if *day > 6 {
                        return Err(anyhow::anyhow!("Invalid day: {}", day));
                    }
                }
            }
        }

        // Validate IP-based conditions
        if let Some(ip_condition) = &conditions.ip_based {
            for ip in &ip_condition.allowed_ips {
                if !self.is_valid_ip_or_cidr(ip) {
                    return Err(anyhow::anyhow!("Invalid IP address: {}", ip));
                }
            }

            for ip in &ip_condition.blocked_ips {
                if !self.is_valid_ip_or_cidr(ip) {
                    return Err(anyhow::anyhow!("Invalid IP address: {}", ip));
                }
            }
        }

        Ok(())
    }

    /// Validate IP address or CIDR notation
    fn is_valid_ip_or_cidr(&self, ip: &str) -> bool {
        // Basic IP validation - in production, use a proper IP parsing library
        if ip.contains('/') {
            // CIDR notation
            let parts: Vec<&str> = ip.split('/').collect();
            if parts.len() != 2 {
                return false;
            }

            if let Ok(prefix) = parts[1].parse::<u8>() {
                return prefix <= 32 && self.is_valid_ip(parts[0]);
            }
            return false;
        }

        self.is_valid_ip(ip)
    }

    /// Basic IP address validation
    fn is_valid_ip(&self, ip: &str) -> bool {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 {
            return false;
        }

        for part in parts {
            if let Ok(num) = part.parse::<u8>() {
                if num > 255 {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }

    /// Add custom resource type
    pub fn add_resource(&mut self, resource: &str) {
        self.valid_resources.insert(resource.to_string());
    }

    /// Add custom action type
    pub fn add_action(&mut self, action: &str) {
        self.valid_actions.insert(action.to_string());
    }
}

/// Permission manager for CRUD operations
pub struct PermissionManager<T: UserManagementService> {
    service: T,
    validator: PermissionValidator,
}

impl<T: UserManagementService> PermissionManager<T> {
    /// Create new permission manager
    pub fn new(service: T) -> Self {
        Self {
            service,
            validator: PermissionValidator::new(),
        }
    }

    /// Create permission with validation
    pub async fn create_permission(&self, permission: Permission) -> Result<Permission> {
        self.validator.validate_permission(&permission)?;

        // Check if permission already exists
        if self.service.get_permission(&permission.id).await?.is_some() {
            return Err(anyhow::anyhow!(
                "Permission already exists: {}",
                permission.id
            ));
        }

        self.service.create_permission(permission).await
    }

    /// Update permission with validation
    pub async fn update_permission(
        &self,
        permission_id: &str,
        permission: Permission,
    ) -> Result<Permission> {
        self.validator.validate_permission(&permission)?;

        // Check if permission exists
        if self.service.get_permission(permission_id).await?.is_none() {
            return Err(anyhow::anyhow!("Permission not found: {}", permission_id));
        }

        self.service
            .update_permission(permission_id, permission)
            .await
    }

    /// Delete permission with dependency checking
    pub async fn delete_permission(&self, permission_id: &str) -> Result<bool> {
        // Check if permission is used by any roles
        let roles = self.service.list_roles().await?;
        for role in &roles {
            if role.permissions.contains(permission_id) {
                return Err(anyhow::anyhow!(
                    "Cannot delete permission {} - it is used by role {}",
                    permission_id,
                    role.id
                ));
            }
        }

        self.service.delete_permission(permission_id).await
    }

    /// Get permissions by resource
    pub async fn get_permissions_by_resource(&self, resource: &str) -> Result<Vec<Permission>> {
        let all_permissions = self.service.list_permissions().await?;
        let filtered = all_permissions
            .into_iter()
            .filter(|p| p.resource == resource)
            .collect();

        Ok(filtered)
    }

    /// Get permissions by action
    pub async fn get_permissions_by_action(&self, action: &str) -> Result<Vec<Permission>> {
        let all_permissions = self.service.list_permissions().await?;
        let filtered = all_permissions
            .into_iter()
            .filter(|p| p.action == action)
            .collect();

        Ok(filtered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_permission_validator() {
        let validator = PermissionValidator::new();

        let valid_permission = Permission {
            id: "users:read".to_string(),
            name: "Read Users".to_string(),
            description: "Read user information".to_string(),
            resource: "users".to_string(),
            action: "read".to_string(),
            conditions: None,
            created_at: Utc::now(),
        };

        assert!(validator.validate_permission(&valid_permission).is_ok());

        let invalid_permission = Permission {
            id: "invalid_format".to_string(),
            name: "Invalid".to_string(),
            description: "Invalid permission".to_string(),
            resource: "invalid".to_string(),
            action: "invalid".to_string(),
            conditions: None,
            created_at: Utc::now(),
        };

        assert!(validator.validate_permission(&invalid_permission).is_err());
    }

    #[test]
    fn test_wildcard_to_regex() {
        let evaluator = PermissionEvaluator::new(MockUserManagementService);

        let regex = evaluator.wildcard_to_regex("users:*").unwrap();
        assert_eq!(regex, "^users:.*$");

        let regex = evaluator.wildcard_to_regex("*:read").unwrap();
        assert_eq!(regex, "^.*:read$");
    }

    #[test]
    fn test_ip_validation() {
        let validator = PermissionValidator::new();

        assert!(validator.is_valid_ip("192.168.1.1"));
        assert!(validator.is_valid_ip("127.0.0.1"));
        assert!(!validator.is_valid_ip("256.1.1.1"));
        assert!(!validator.is_valid_ip("192.168.1"));

        assert!(validator.is_valid_ip_or_cidr("192.168.1.0/24"));
        assert!(validator.is_valid_ip_or_cidr("10.0.0.1"));
        assert!(!validator.is_valid_ip_or_cidr("192.168.1.0/33"));
    }

    // Mock service for testing
    struct MockUserManagementService;

    #[async_trait::async_trait]
    impl UserManagementService for MockUserManagementService {
        async fn create_role(&self, _role: UserRole) -> Result<UserRole> {
            unimplemented!()
        }
        async fn get_role(&self, _role_id: &str) -> Result<Option<UserRole>> {
            unimplemented!()
        }
        async fn update_role(&self, _role_id: &str, _role: UserRole) -> Result<UserRole> {
            unimplemented!()
        }
        async fn delete_role(&self, _role_id: &str) -> Result<bool> {
            unimplemented!()
        }
        async fn list_roles(&self) -> Result<Vec<UserRole>> {
            unimplemented!()
        }
        async fn assign_role_to_user(&self, _user_id: &str, _role_id: &str) -> Result<()> {
            unimplemented!()
        }
        async fn remove_role_from_user(&self, _user_id: &str, _role_id: &str) -> Result<()> {
            unimplemented!()
        }
        async fn get_user_roles(&self, _user_id: &str) -> Result<Vec<UserRole>> {
            unimplemented!()
        }
        async fn create_permission(&self, _permission: Permission) -> Result<Permission> {
            unimplemented!()
        }
        async fn get_permission(&self, _permission_id: &str) -> Result<Option<Permission>> {
            unimplemented!()
        }
        async fn update_permission(
            &self,
            _permission_id: &str,
            _permission: Permission,
        ) -> Result<Permission> {
            unimplemented!()
        }
        async fn delete_permission(&self, _permission_id: &str) -> Result<bool> {
            unimplemented!()
        }
        async fn list_permissions(&self) -> Result<Vec<Permission>> {
            unimplemented!()
        }
        async fn check_user_permission(
            &self,
            _user_id: &str,
            _permission: &str,
            _context: Option<UserContext>,
        ) -> Result<PermissionCheckResult> {
            unimplemented!()
        }
        async fn get_user_permissions(&self, _user_id: &str) -> Result<HashSet<String>> {
            unimplemented!()
        }
        async fn create_group(&self, _group: UserGroup) -> Result<UserGroup> {
            unimplemented!()
        }
        async fn get_group(&self, _group_id: &str) -> Result<Option<UserGroup>> {
            unimplemented!()
        }
        async fn update_group(&self, _group_id: &str, _group: UserGroup) -> Result<UserGroup> {
            unimplemented!()
        }
        async fn delete_group(&self, _group_id: &str) -> Result<bool> {
            unimplemented!()
        }
        async fn list_groups(&self) -> Result<Vec<UserGroup>> {
            unimplemented!()
        }
        async fn add_user_to_group(&self, _user_id: &str, _group_id: &str) -> Result<()> {
            unimplemented!()
        }
        async fn remove_user_from_group(&self, _user_id: &str, _group_id: &str) -> Result<()> {
            unimplemented!()
        }
        async fn get_user_groups(&self, _user_id: &str) -> Result<Vec<super::UserGroup>> {
            unimplemented!()
        }
        async fn create_profile(&self, _profile: super::UserProfile) -> Result<super::UserProfile> {
            unimplemented!()
        }
        async fn get_profile(&self, _user_id: &str) -> Result<Option<super::UserProfile>> {
            unimplemented!()
        }
        async fn update_profile(
            &self,
            _user_id: &str,
            _profile: super::UserProfile,
        ) -> Result<super::UserProfile> {
            unimplemented!()
        }
        async fn delete_profile(&self, _user_id: &str) -> Result<bool> {
            unimplemented!()
        }
        async fn search_profiles(
            &self,
            _query: &str,
            _filters: Option<HashMap<String, String>>,
        ) -> Result<Vec<super::UserProfile>> {
            unimplemented!()
        }
        async fn update_privacy_settings(
            &self,
            _user_id: &str,
            _settings: super::PrivacySettings,
        ) -> Result<()> {
            unimplemented!()
        }
        async fn update_notification_preferences(
            &self,
            _user_id: &str,
            _preferences: super::NotificationPreferences,
        ) -> Result<()> {
            unimplemented!()
        }
    }
}
