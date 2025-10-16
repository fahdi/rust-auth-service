use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub mod groups;
pub mod permissions;
pub mod profiles;
pub mod roles;

/// User role definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserRole {
    pub id: String,
    pub name: String,
    pub description: String,
    pub permissions: HashSet<String>,
    pub inherits_from: Vec<String>,
    pub is_system_role: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Permission definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Permission {
    pub id: String,
    pub name: String,
    pub description: String,
    pub resource: String,
    pub action: String,
    pub conditions: Option<PermissionConditions>,
    pub created_at: DateTime<Utc>,
}

/// Permission conditions for fine-grained access control
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PermissionConditions {
    pub time_based: Option<TimeBasedCondition>,
    pub ip_based: Option<IpBasedCondition>,
    pub attribute_based: Option<AttributeBasedCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeBasedCondition {
    pub allowed_hours: Option<Vec<u8>>, // 0-23
    pub allowed_days: Option<Vec<u8>>,  // 0-6 (Sunday-Saturday)
    pub timezone: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpBasedCondition {
    pub allowed_ips: Vec<String>,
    pub blocked_ips: Vec<String>,
    pub allowed_countries: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttributeBasedCondition {
    pub required_attributes: HashMap<String, String>,
    pub forbidden_attributes: HashMap<String, String>,
}

/// User group for organizing users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserGroup {
    pub id: String,
    pub name: String,
    pub description: String,
    pub roles: HashSet<String>,
    pub parent_groups: Vec<String>,
    pub child_groups: Vec<String>,
    pub members: HashSet<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Extended user profile with management features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub user_id: String,
    pub email: String,
    pub username: Option<String>,
    pub display_name: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
    pub location: Option<String>,
    pub timezone: Option<String>,
    pub language: Option<String>,
    pub phone: Option<String>,
    pub date_of_birth: Option<DateTime<Utc>>,
    pub gender: Option<String>,
    pub website: Option<String>,
    pub social_links: HashMap<String, String>,
    pub custom_attributes: HashMap<String, serde_json::Value>,
    pub privacy_settings: PrivacySettings,
    pub notification_preferences: NotificationPreferences,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// User privacy settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacySettings {
    pub profile_visibility: ProfileVisibility,
    pub email_visibility: bool,
    pub phone_visibility: bool,
    pub location_visibility: bool,
    pub activity_tracking: bool,
    pub data_processing_consent: bool,
    pub marketing_consent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProfileVisibility {
    Public,
    Private,
    FriendsOnly,
    Custom(Vec<String>), // List of user IDs who can see profile
}

/// User notification preferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationPreferences {
    pub email_notifications: EmailNotificationSettings,
    pub push_notifications: PushNotificationSettings,
    pub sms_notifications: SmsNotificationSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailNotificationSettings {
    pub enabled: bool,
    pub security_alerts: bool,
    pub login_notifications: bool,
    pub marketing_emails: bool,
    pub system_updates: bool,
    pub password_changes: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushNotificationSettings {
    pub enabled: bool,
    pub security_alerts: bool,
    pub login_notifications: bool,
    pub app_updates: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsNotificationSettings {
    pub enabled: bool,
    pub security_alerts: bool,
    pub mfa_codes: bool,
    pub login_notifications: bool,
}

/// User management context for authorization checks
#[derive(Debug, Clone)]
pub struct UserContext {
    pub user_id: String,
    pub roles: HashSet<String>,
    pub permissions: HashSet<String>,
    pub groups: HashSet<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub session_id: Option<String>,
}

/// Permission check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionCheckResult {
    pub granted: bool,
    pub reason: String,
    pub conditions_met: bool,
    pub required_permissions: Vec<String>,
    pub missing_permissions: Vec<String>,
}

/// User management service trait
#[async_trait::async_trait]
pub trait UserManagementService: Send + Sync {
    // Role management
    async fn create_role(&self, role: UserRole) -> Result<UserRole>;
    async fn get_role(&self, role_id: &str) -> Result<Option<UserRole>>;
    async fn update_role(&self, role_id: &str, role: UserRole) -> Result<UserRole>;
    async fn delete_role(&self, role_id: &str) -> Result<bool>;
    async fn list_roles(&self) -> Result<Vec<UserRole>>;
    async fn assign_role_to_user(&self, user_id: &str, role_id: &str) -> Result<()>;
    async fn remove_role_from_user(&self, user_id: &str, role_id: &str) -> Result<()>;
    async fn get_user_roles(&self, user_id: &str) -> Result<Vec<UserRole>>;

    // Permission management
    async fn create_permission(&self, permission: Permission) -> Result<Permission>;
    async fn get_permission(&self, permission_id: &str) -> Result<Option<Permission>>;
    async fn update_permission(
        &self,
        permission_id: &str,
        permission: Permission,
    ) -> Result<Permission>;
    async fn delete_permission(&self, permission_id: &str) -> Result<bool>;
    async fn list_permissions(&self) -> Result<Vec<Permission>>;
    async fn check_user_permission(
        &self,
        user_id: &str,
        permission: &str,
        context: Option<UserContext>,
    ) -> Result<PermissionCheckResult>;
    async fn get_user_permissions(&self, user_id: &str) -> Result<HashSet<String>>;

    // Group management
    async fn create_group(&self, group: UserGroup) -> Result<UserGroup>;
    async fn get_group(&self, group_id: &str) -> Result<Option<UserGroup>>;
    async fn update_group(&self, group_id: &str, group: UserGroup) -> Result<UserGroup>;
    async fn delete_group(&self, group_id: &str) -> Result<bool>;
    async fn list_groups(&self) -> Result<Vec<UserGroup>>;
    async fn add_user_to_group(&self, user_id: &str, group_id: &str) -> Result<()>;
    async fn remove_user_from_group(&self, user_id: &str, group_id: &str) -> Result<()>;
    async fn get_user_groups(&self, user_id: &str) -> Result<Vec<UserGroup>>;

    // Profile management
    async fn create_profile(&self, profile: UserProfile) -> Result<UserProfile>;
    async fn get_profile(&self, user_id: &str) -> Result<Option<UserProfile>>;
    async fn update_profile(&self, user_id: &str, profile: UserProfile) -> Result<UserProfile>;
    async fn delete_profile(&self, user_id: &str) -> Result<bool>;
    async fn search_profiles(
        &self,
        query: &str,
        filters: Option<HashMap<String, String>>,
    ) -> Result<Vec<UserProfile>>;
    async fn update_privacy_settings(&self, user_id: &str, settings: PrivacySettings)
        -> Result<()>;
    async fn update_notification_preferences(
        &self,
        user_id: &str,
        preferences: NotificationPreferences,
    ) -> Result<()>;
}

/// Default system roles
pub fn get_default_system_roles() -> Vec<UserRole> {
    let now = Utc::now();

    vec![
        UserRole {
            id: "admin".to_string(),
            name: "Administrator".to_string(),
            description: "Full system access with all permissions".to_string(),
            permissions: vec![
                "users:*".to_string(),
                "roles:*".to_string(),
                "permissions:*".to_string(),
                "groups:*".to_string(),
                "system:*".to_string(),
            ]
            .into_iter()
            .collect(),
            inherits_from: vec![],
            is_system_role: true,
            created_at: now,
            updated_at: now,
        },
        UserRole {
            id: "moderator".to_string(),
            name: "Moderator".to_string(),
            description: "User management and content moderation permissions".to_string(),
            permissions: vec![
                "users:read".to_string(),
                "users:update".to_string(),
                "users:suspend".to_string(),
                "content:moderate".to_string(),
                "reports:manage".to_string(),
            ]
            .into_iter()
            .collect(),
            inherits_from: vec!["user".to_string()],
            is_system_role: true,
            created_at: now,
            updated_at: now,
        },
        UserRole {
            id: "user".to_string(),
            name: "User".to_string(),
            description: "Standard user permissions for basic operations".to_string(),
            permissions: vec![
                "profile:read".to_string(),
                "profile:update".to_string(),
                "auth:login".to_string(),
                "auth:logout".to_string(),
                "auth:change_password".to_string(),
            ]
            .into_iter()
            .collect(),
            inherits_from: vec![],
            is_system_role: true,
            created_at: now,
            updated_at: now,
        },
        UserRole {
            id: "guest".to_string(),
            name: "Guest".to_string(),
            description: "Limited read-only access for unauthenticated users".to_string(),
            permissions: vec!["public:read".to_string()].into_iter().collect(),
            inherits_from: vec![],
            is_system_role: true,
            created_at: now,
            updated_at: now,
        },
    ]
}

/// Default system permissions
pub fn get_default_system_permissions() -> Vec<Permission> {
    let now = Utc::now();

    vec![
        // User management permissions
        Permission {
            id: "users:create".to_string(),
            name: "Create Users".to_string(),
            description: "Create new user accounts".to_string(),
            resource: "users".to_string(),
            action: "create".to_string(),
            conditions: None,
            created_at: now,
        },
        Permission {
            id: "users:read".to_string(),
            name: "Read Users".to_string(),
            description: "View user information".to_string(),
            resource: "users".to_string(),
            action: "read".to_string(),
            conditions: None,
            created_at: now,
        },
        Permission {
            id: "users:update".to_string(),
            name: "Update Users".to_string(),
            description: "Modify user information".to_string(),
            resource: "users".to_string(),
            action: "update".to_string(),
            conditions: None,
            created_at: now,
        },
        Permission {
            id: "users:delete".to_string(),
            name: "Delete Users".to_string(),
            description: "Delete user accounts".to_string(),
            resource: "users".to_string(),
            action: "delete".to_string(),
            conditions: None,
            created_at: now,
        },
        Permission {
            id: "users:suspend".to_string(),
            name: "Suspend Users".to_string(),
            description: "Suspend or ban user accounts".to_string(),
            resource: "users".to_string(),
            action: "suspend".to_string(),
            conditions: None,
            created_at: now,
        },
        // Role management permissions
        Permission {
            id: "roles:create".to_string(),
            name: "Create Roles".to_string(),
            description: "Create new user roles".to_string(),
            resource: "roles".to_string(),
            action: "create".to_string(),
            conditions: None,
            created_at: now,
        },
        Permission {
            id: "roles:read".to_string(),
            name: "Read Roles".to_string(),
            description: "View role information".to_string(),
            resource: "roles".to_string(),
            action: "read".to_string(),
            conditions: None,
            created_at: now,
        },
        Permission {
            id: "roles:update".to_string(),
            name: "Update Roles".to_string(),
            description: "Modify role definitions".to_string(),
            resource: "roles".to_string(),
            action: "update".to_string(),
            conditions: None,
            created_at: now,
        },
        Permission {
            id: "roles:delete".to_string(),
            name: "Delete Roles".to_string(),
            description: "Delete user roles".to_string(),
            resource: "roles".to_string(),
            action: "delete".to_string(),
            conditions: None,
            created_at: now,
        },
        // Profile management permissions
        Permission {
            id: "profile:read".to_string(),
            name: "Read Profile".to_string(),
            description: "View own profile information".to_string(),
            resource: "profile".to_string(),
            action: "read".to_string(),
            conditions: None,
            created_at: now,
        },
        Permission {
            id: "profile:update".to_string(),
            name: "Update Profile".to_string(),
            description: "Modify own profile information".to_string(),
            resource: "profile".to_string(),
            action: "update".to_string(),
            conditions: None,
            created_at: now,
        },
        // Authentication permissions
        Permission {
            id: "auth:login".to_string(),
            name: "Login".to_string(),
            description: "Authenticate and obtain access tokens".to_string(),
            resource: "auth".to_string(),
            action: "login".to_string(),
            conditions: None,
            created_at: now,
        },
        Permission {
            id: "auth:logout".to_string(),
            name: "Logout".to_string(),
            description: "Invalidate authentication tokens".to_string(),
            resource: "auth".to_string(),
            action: "logout".to_string(),
            conditions: None,
            created_at: now,
        },
        Permission {
            id: "auth:change_password".to_string(),
            name: "Change Password".to_string(),
            description: "Change own password".to_string(),
            resource: "auth".to_string(),
            action: "change_password".to_string(),
            conditions: None,
            created_at: now,
        },
        // System permissions
        Permission {
            id: "system:health".to_string(),
            name: "System Health".to_string(),
            description: "View system health and status".to_string(),
            resource: "system".to_string(),
            action: "health".to_string(),
            conditions: None,
            created_at: now,
        },
        Permission {
            id: "system:metrics".to_string(),
            name: "System Metrics".to_string(),
            description: "View system metrics and analytics".to_string(),
            resource: "system".to_string(),
            action: "metrics".to_string(),
            conditions: None,
            created_at: now,
        },
        // Public permissions
        Permission {
            id: "public:read".to_string(),
            name: "Public Read".to_string(),
            description: "Read publicly available content".to_string(),
            resource: "public".to_string(),
            action: "read".to_string(),
            conditions: None,
            created_at: now,
        },
    ]
}

/// Generate default user profile
pub fn create_default_profile(user_id: &str, email: &str, display_name: &str) -> UserProfile {
    UserProfile {
        user_id: user_id.to_string(),
        email: email.to_string(),
        username: None,
        display_name: display_name.to_string(),
        first_name: None,
        last_name: None,
        avatar_url: None,
        bio: None,
        location: None,
        timezone: None,
        language: Some("en".to_string()),
        phone: None,
        date_of_birth: None,
        gender: None,
        website: None,
        social_links: HashMap::new(),
        custom_attributes: HashMap::new(),
        privacy_settings: PrivacySettings {
            profile_visibility: ProfileVisibility::Public,
            email_visibility: false,
            phone_visibility: false,
            location_visibility: false,
            activity_tracking: true,
            data_processing_consent: false,
            marketing_consent: false,
        },
        notification_preferences: NotificationPreferences {
            email_notifications: EmailNotificationSettings {
                enabled: true,
                security_alerts: true,
                login_notifications: true,
                marketing_emails: false,
                system_updates: true,
                password_changes: true,
            },
            push_notifications: PushNotificationSettings {
                enabled: false,
                security_alerts: true,
                login_notifications: false,
                app_updates: false,
            },
            sms_notifications: SmsNotificationSettings {
                enabled: false,
                security_alerts: false,
                mfa_codes: true,
                login_notifications: false,
            },
        },
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_system_roles() {
        let roles = get_default_system_roles();
        assert_eq!(roles.len(), 4);

        let admin_role = roles.iter().find(|r| r.id == "admin").unwrap();
        assert!(admin_role.is_system_role);
        assert!(admin_role.permissions.contains("users:*"));

        let user_role = roles.iter().find(|r| r.id == "user").unwrap();
        assert!(user_role.permissions.contains("profile:read"));
    }

    #[test]
    fn test_default_system_permissions() {
        let permissions = get_default_system_permissions();
        assert!(!permissions.is_empty());

        let login_perm = permissions.iter().find(|p| p.id == "auth:login").unwrap();
        assert_eq!(login_perm.resource, "auth");
        assert_eq!(login_perm.action, "login");
    }

    #[test]
    fn test_create_default_profile() {
        let profile = create_default_profile("user123", "test@example.com", "Test User");

        assert_eq!(profile.user_id, "user123");
        assert_eq!(profile.email, "test@example.com");
        assert_eq!(profile.display_name, "Test User");
        assert!(
            profile
                .notification_preferences
                .email_notifications
                .security_alerts
        );
        assert!(!profile.privacy_settings.email_visibility);
    }
}
