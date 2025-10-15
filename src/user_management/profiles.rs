use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use regex::Regex;
use super::{UserProfile, PrivacySettings, NotificationPreferences, ProfileVisibility, UserManagementService};

/// Profile validation rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileValidationRules {
    pub username_min_length: usize,
    pub username_max_length: usize,
    pub username_pattern: String,
    pub display_name_max_length: usize,
    pub bio_max_length: usize,
    pub allowed_social_platforms: Vec<String>,
    pub required_fields: Vec<String>,
    pub custom_field_rules: HashMap<String, FieldValidationRule>,
}

/// Validation rule for custom fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldValidationRule {
    pub field_type: FieldType,
    pub required: bool,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub pattern: Option<String>,
    pub allowed_values: Option<Vec<String>>,
}

/// Field type for validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldType {
    String,
    Integer,
    Float,
    Boolean,
    Date,
    Email,
    Url,
    Phone,
    Json,
}

impl Default for ProfileValidationRules {
    fn default() -> Self {
        Self {
            username_min_length: 3,
            username_max_length: 30,
            username_pattern: r"^[a-zA-Z0-9_-]+$".to_string(),
            display_name_max_length: 100,
            bio_max_length: 500,
            allowed_social_platforms: vec![
                "twitter".to_string(),
                "linkedin".to_string(),
                "github".to_string(),
                "facebook".to_string(),
                "instagram".to_string(),
                "website".to_string(),
            ],
            required_fields: vec!["email".to_string(), "display_name".to_string()],
            custom_field_rules: HashMap::new(),
        }
    }
}

/// Profile validator
pub struct ProfileValidator {
    rules: ProfileValidationRules,
    username_regex: Regex,
}

impl ProfileValidator {
    /// Create new profile validator with default rules
    pub fn new() -> Result<Self> {
        let rules = ProfileValidationRules::default();
        let username_regex = Regex::new(&rules.username_pattern)?;
        
        Ok(Self {
            rules,
            username_regex,
        })
    }

    /// Create profile validator with custom rules
    pub fn with_rules(rules: ProfileValidationRules) -> Result<Self> {
        let username_regex = Regex::new(&rules.username_pattern)?;
        
        Ok(Self {
            rules,
            username_regex,
        })
    }

    /// Validate complete user profile
    pub fn validate_profile(&self, profile: &UserProfile) -> Result<()> {
        // Validate required fields
        for field in &self.rules.required_fields {
            match field.as_str() {
                "email" => {
                    if profile.email.is_empty() {
                        return Err(anyhow::anyhow!("Email is required"));
                    }
                    self.validate_email(&profile.email)?;
                }
                "display_name" => {
                    if profile.display_name.is_empty() {
                        return Err(anyhow::anyhow!("Display name is required"));
                    }
                }
                "username" => {
                    if profile.username.is_none() {
                        return Err(anyhow::anyhow!("Username is required"));
                    }
                }
                _ => {} // Custom field validation handled separately
            }
        }

        // Validate username if present
        if let Some(username) = &profile.username {
            self.validate_username(username)?;
        }

        // Validate display name
        self.validate_display_name(&profile.display_name)?;

        // Validate optional fields
        if let Some(bio) = &profile.bio {
            self.validate_bio(bio)?;
        }

        if let Some(phone) = &profile.phone {
            self.validate_phone(phone)?;
        }

        if let Some(website) = &profile.website {
            self.validate_url(website)?;
        }

        // Validate social links
        self.validate_social_links(&profile.social_links)?;

        // Validate custom attributes
        self.validate_custom_attributes(&profile.custom_attributes)?;

        Ok(())
    }

    /// Validate username
    pub fn validate_username(&self, username: &str) -> Result<()> {
        if username.len() < self.rules.username_min_length {
            return Err(anyhow::anyhow!(
                "Username must be at least {} characters", 
                self.rules.username_min_length
            ));
        }

        if username.len() > self.rules.username_max_length {
            return Err(anyhow::anyhow!(
                "Username must be at most {} characters", 
                self.rules.username_max_length
            ));
        }

        if !self.username_regex.is_match(username) {
            return Err(anyhow::anyhow!(
                "Username contains invalid characters. Only letters, numbers, hyphens, and underscores are allowed"
            ));
        }

        // Check for reserved usernames
        let reserved = ["admin", "root", "api", "www", "mail", "support", "help", "info"];
        if reserved.contains(&username.to_lowercase().as_str()) {
            return Err(anyhow::anyhow!("Username '{}' is reserved", username));
        }

        Ok(())
    }

    /// Validate display name
    pub fn validate_display_name(&self, display_name: &str) -> Result<()> {
        if display_name.is_empty() {
            return Err(anyhow::anyhow!("Display name cannot be empty"));
        }

        if display_name.len() > self.rules.display_name_max_length {
            return Err(anyhow::anyhow!(
                "Display name must be at most {} characters", 
                self.rules.display_name_max_length
            ));
        }

        // Check for inappropriate content (basic check)
        if display_name.to_lowercase().contains("admin") && !display_name.eq_ignore_ascii_case("admin") {
            return Err(anyhow::anyhow!("Display name cannot contain 'admin'"));
        }

        Ok(())
    }

    /// Validate bio
    pub fn validate_bio(&self, bio: &str) -> Result<()> {
        if bio.len() > self.rules.bio_max_length {
            return Err(anyhow::anyhow!(
                "Bio must be at most {} characters", 
                self.rules.bio_max_length
            ));
        }

        Ok(())
    }

    /// Validate email format
    pub fn validate_email(&self, email: &str) -> Result<()> {
        let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")?;
        
        if !email_regex.is_match(email) {
            return Err(anyhow::anyhow!("Invalid email format"));
        }

        Ok(())
    }

    /// Validate phone number
    pub fn validate_phone(&self, phone: &str) -> Result<()> {
        // Basic international phone format validation
        let phone_regex = Regex::new(r"^\+?[1-9]\d{1,14}$")?;
        
        if !phone_regex.is_match(phone) {
            return Err(anyhow::anyhow!("Invalid phone number format"));
        }

        Ok(())
    }

    /// Validate URL
    pub fn validate_url(&self, url: &str) -> Result<()> {
        let url_regex = Regex::new(r"^https?://[^\s/$.?#].[^\s]*$")?;
        
        if !url_regex.is_match(url) {
            return Err(anyhow::anyhow!("Invalid URL format"));
        }

        Ok(())
    }

    /// Validate social links
    pub fn validate_social_links(&self, social_links: &HashMap<String, String>) -> Result<()> {
        for (platform, url) in social_links {
            // Check if platform is allowed
            if !self.rules.allowed_social_platforms.contains(platform) {
                return Err(anyhow::anyhow!("Social platform '{}' is not allowed", platform));
            }

            // Validate URL format
            self.validate_url(url)?;

            // Platform-specific validation
            match platform.as_str() {
                "twitter" => {
                    if !url.contains("twitter.com") && !url.contains("x.com") {
                        return Err(anyhow::anyhow!("Invalid Twitter URL"));
                    }
                }
                "github" => {
                    if !url.contains("github.com") {
                        return Err(anyhow::anyhow!("Invalid GitHub URL"));
                    }
                }
                "linkedin" => {
                    if !url.contains("linkedin.com") {
                        return Err(anyhow::anyhow!("Invalid LinkedIn URL"));
                    }
                }
                _ => {} // Generic URL validation already done
            }
        }

        Ok(())
    }

    /// Validate custom attributes
    pub fn validate_custom_attributes(&self, attributes: &HashMap<String, serde_json::Value>) -> Result<()> {
        for (field_name, value) in attributes {
            if let Some(rule) = self.rules.custom_field_rules.get(field_name) {
                self.validate_custom_field(field_name, value, rule)?;
            }
        }

        Ok(())
    }

    /// Validate custom field value
    fn validate_custom_field(
        &self, 
        field_name: &str, 
        value: &serde_json::Value, 
        rule: &FieldValidationRule
    ) -> Result<()> {
        // Check if required field is present
        if rule.required && value.is_null() {
            return Err(anyhow::anyhow!("Field '{}' is required", field_name));
        }

        if value.is_null() {
            return Ok(()); // Skip validation for null optional fields
        }

        // Type-specific validation
        match rule.field_type {
            FieldType::String => {
                if let Some(s) = value.as_str() {
                    if let Some(min_len) = rule.min_length {
                        if s.len() < min_len {
                            return Err(anyhow::anyhow!("Field '{}' must be at least {} characters", field_name, min_len));
                        }
                    }
                    if let Some(max_len) = rule.max_length {
                        if s.len() > max_len {
                            return Err(anyhow::anyhow!("Field '{}' must be at most {} characters", field_name, max_len));
                        }
                    }
                    if let Some(pattern) = &rule.pattern {
                        let regex = Regex::new(pattern)?;
                        if !regex.is_match(s) {
                            return Err(anyhow::anyhow!("Field '{}' does not match required pattern", field_name));
                        }
                    }
                    if let Some(allowed) = &rule.allowed_values {
                        if !allowed.contains(&s.to_string()) {
                            return Err(anyhow::anyhow!("Field '{}' value not in allowed list", field_name));
                        }
                    }
                } else {
                    return Err(anyhow::anyhow!("Field '{}' must be a string", field_name));
                }
            }
            FieldType::Integer => {
                if !value.is_i64() {
                    return Err(anyhow::anyhow!("Field '{}' must be an integer", field_name));
                }
            }
            FieldType::Float => {
                if !value.is_f64() && !value.is_i64() {
                    return Err(anyhow::anyhow!("Field '{}' must be a number", field_name));
                }
            }
            FieldType::Boolean => {
                if !value.is_boolean() {
                    return Err(anyhow::anyhow!("Field '{}' must be a boolean", field_name));
                }
            }
            FieldType::Email => {
                if let Some(s) = value.as_str() {
                    self.validate_email(s)?;
                } else {
                    return Err(anyhow::anyhow!("Field '{}' must be a valid email", field_name));
                }
            }
            FieldType::Url => {
                if let Some(s) = value.as_str() {
                    self.validate_url(s)?;
                } else {
                    return Err(anyhow::anyhow!("Field '{}' must be a valid URL", field_name));
                }
            }
            FieldType::Phone => {
                if let Some(s) = value.as_str() {
                    self.validate_phone(s)?;
                } else {
                    return Err(anyhow::anyhow!("Field '{}' must be a valid phone number", field_name));
                }
            }
            FieldType::Date => {
                if let Some(s) = value.as_str() {
                    DateTime::parse_from_rfc3339(s)
                        .map_err(|_| anyhow::anyhow!("Field '{}' must be a valid ISO 8601 date", field_name))?;
                } else {
                    return Err(anyhow::anyhow!("Field '{}' must be a valid date string", field_name));
                }
            }
            FieldType::Json => {
                // Any valid JSON is acceptable
            }
        }

        Ok(())
    }
}

/// Profile manager for CRUD operations and business logic
pub struct ProfileManager<T: UserManagementService> {
    service: T,
    validator: ProfileValidator,
}

impl<T: UserManagementService> ProfileManager<T> {
    /// Create new profile manager
    pub fn new(service: T) -> Result<Self> {
        Ok(Self {
            service,
            validator: ProfileValidator::new()?,
        })
    }

    /// Create profile with validation
    pub async fn create_profile(&self, mut profile: UserProfile) -> Result<UserProfile> {
        // Validate profile data
        self.validator.validate_profile(&profile)?;

        // Check if profile already exists
        if self.service.get_profile(&profile.user_id).await?.is_some() {
            return Err(anyhow::anyhow!("Profile already exists for user: {}", profile.user_id));
        }

        // Check username uniqueness if provided
        if let Some(username) = &profile.username {
            if self.is_username_taken(username).await? {
                return Err(anyhow::anyhow!("Username '{}' is already taken", username));
            }
        }

        // Set timestamps
        let now = Utc::now();
        profile.created_at = now;
        profile.updated_at = now;

        self.service.create_profile(profile).await
    }

    /// Update profile with validation
    pub async fn update_profile(&self, user_id: &str, mut profile: UserProfile) -> Result<UserProfile> {
        // Check if profile exists
        let existing_profile = self.service.get_profile(user_id).await?
            .ok_or_else(|| anyhow::anyhow!("Profile not found for user: {}", user_id))?;

        // Validate updated profile data
        self.validator.validate_profile(&profile)?;

        // Check username uniqueness if changed
        if let Some(username) = &profile.username {
            if Some(username) != existing_profile.username.as_ref() {
                if self.is_username_taken(username).await? {
                    return Err(anyhow::anyhow!("Username '{}' is already taken", username));
                }
            }
        }

        // Preserve creation timestamp
        profile.created_at = existing_profile.created_at;
        profile.updated_at = Utc::now();

        self.service.update_profile(user_id, profile).await
    }

    /// Update privacy settings
    pub async fn update_privacy_settings(&self, user_id: &str, settings: PrivacySettings) -> Result<()> {
        // Check if profile exists
        if self.service.get_profile(user_id).await?.is_none() {
            return Err(anyhow::anyhow!("Profile not found for user: {}", user_id));
        }

        self.service.update_privacy_settings(user_id, settings).await
    }

    /// Update notification preferences
    pub async fn update_notification_preferences(&self, user_id: &str, preferences: NotificationPreferences) -> Result<()> {
        // Check if profile exists
        if self.service.get_profile(user_id).await?.is_none() {
            return Err(anyhow::anyhow!("Profile not found for user: {}", user_id));
        }

        self.service.update_notification_preferences(user_id, preferences).await
    }

    /// Search profiles with privacy filtering
    pub async fn search_profiles(
        &self, 
        query: &str, 
        filters: Option<HashMap<String, String>>,
        requesting_user_id: Option<&str>
    ) -> Result<Vec<UserProfile>> {
        let mut profiles = self.service.search_profiles(query, filters).await?;

        // Apply privacy filtering
        profiles = profiles
            .into_iter()
            .filter(|profile| self.can_view_profile(profile, requesting_user_id))
            .map(|mut profile| {
                self.apply_privacy_mask(&mut profile, requesting_user_id);
                profile
            })
            .collect();

        Ok(profiles)
    }

    /// Check if username is already taken
    async fn is_username_taken(&self, username: &str) -> Result<bool> {
        let filters = HashMap::from([("username".to_string(), username.to_string())]);
        let profiles = self.service.search_profiles("", Some(filters)).await?;
        Ok(!profiles.is_empty())
    }

    /// Check if requesting user can view profile
    fn can_view_profile(&self, profile: &UserProfile, requesting_user_id: Option<&str>) -> bool {
        match &profile.privacy_settings.profile_visibility {
            ProfileVisibility::Public => true,
            ProfileVisibility::Private => {
                // Only the profile owner can view private profiles
                requesting_user_id == Some(&profile.user_id)
            }
            ProfileVisibility::FriendsOnly => {
                // TODO: Implement friends system
                requesting_user_id == Some(&profile.user_id)
            }
            ProfileVisibility::Custom(allowed_users) => {
                if let Some(user_id) = requesting_user_id {
                    allowed_users.contains(&user_id.to_string()) || user_id == profile.user_id
                } else {
                    false
                }
            }
        }
    }

    /// Apply privacy masking to profile fields
    fn apply_privacy_mask(&self, profile: &mut UserProfile, requesting_user_id: Option<&str>) {
        let is_owner = requesting_user_id == Some(&profile.user_id);
        
        if !is_owner {
            // Hide email if privacy setting is enabled
            if !profile.privacy_settings.email_visibility {
                profile.email = "***@***.***".to_string();
            }

            // Hide phone if privacy setting is enabled
            if !profile.privacy_settings.phone_visibility {
                profile.phone = None;
            }

            // Hide location if privacy setting is enabled
            if !profile.privacy_settings.location_visibility {
                profile.location = None;
            }

            // Remove sensitive custom attributes
            profile.custom_attributes.retain(|key, _| {
                !key.to_lowercase().contains("sensitive") && 
                !key.to_lowercase().contains("private")
            });
        }
    }

    /// Get profile statistics
    pub async fn get_profile_statistics(&self) -> Result<ProfileStatistics> {
        // This would require additional database queries
        // For now, return basic stats
        Ok(ProfileStatistics {
            total_profiles: 0,
            active_profiles: 0,
            profiles_with_avatar: 0,
            profiles_with_bio: 0,
            most_common_languages: HashMap::new(),
            privacy_settings_distribution: HashMap::new(),
        })
    }
}

/// Profile statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileStatistics {
    pub total_profiles: u64,
    pub active_profiles: u64,
    pub profiles_with_avatar: u64,
    pub profiles_with_bio: u64,
    pub most_common_languages: HashMap<String, u64>,
    pub privacy_settings_distribution: HashMap<String, u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_profile_validator() -> Result<()> {
        let validator = ProfileValidator::new()?;

        // Test username validation
        assert!(validator.validate_username("valid_user123").is_ok());
        assert!(validator.validate_username("ab").is_err()); // Too short
        assert!(validator.validate_username("admin").is_err()); // Reserved
        assert!(validator.validate_username("user@invalid").is_err()); // Invalid chars

        // Test email validation
        assert!(validator.validate_email("test@example.com").is_ok());
        assert!(validator.validate_email("invalid-email").is_err());

        // Test URL validation
        assert!(validator.validate_url("https://example.com").is_ok());
        assert!(validator.validate_url("not-a-url").is_err());

        Ok(())
    }

    #[test]
    fn test_custom_field_validation() -> Result<()> {
        let mut rules = ProfileValidationRules::default();
        rules.custom_field_rules.insert(
            "age".to_string(),
            FieldValidationRule {
                field_type: FieldType::Integer,
                required: true,
                min_length: None,
                max_length: None,
                pattern: None,
                allowed_values: None,
            }
        );

        let validator = ProfileValidator::with_rules(rules)?;

        let mut attributes = HashMap::new();
        attributes.insert("age".to_string(), serde_json::Value::Number(25.into()));

        assert!(validator.validate_custom_attributes(&attributes).is_ok());

        // Test invalid type
        attributes.insert("age".to_string(), serde_json::Value::String("not-a-number".to_string()));
        assert!(validator.validate_custom_attributes(&attributes).is_err());

        Ok(())
    }

    #[test]
    fn test_profile_privacy() {
        let profile = UserProfile {
            user_id: "user123".to_string(),
            email: "test@example.com".to_string(),
            username: Some("testuser".to_string()),
            display_name: "Test User".to_string(),
            first_name: None,
            last_name: None,
            avatar_url: None,
            bio: None,
            location: Some("New York".to_string()),
            timezone: None,
            language: None,
            phone: Some("+1234567890".to_string()),
            date_of_birth: None,
            gender: None,
            website: None,
            social_links: HashMap::new(),
            custom_attributes: HashMap::new(),
            privacy_settings: PrivacySettings {
                profile_visibility: ProfileVisibility::Public,
                email_visibility: false,
                phone_visibility: false,
                location_visibility: true,
                activity_tracking: true,
                data_processing_consent: true,
                marketing_consent: false,
            },
            notification_preferences: NotificationPreferences {
                email_notifications: super::super::EmailNotificationSettings {
                    enabled: true,
                    security_alerts: true,
                    login_notifications: false,
                    marketing_emails: false,
                    system_updates: true,
                    password_changes: true,
                },
                push_notifications: super::super::PushNotificationSettings {
                    enabled: false,
                    security_alerts: true,
                    login_notifications: false,
                    app_updates: false,
                },
                sms_notifications: super::super::SmsNotificationSettings {
                    enabled: false,
                    security_alerts: false,
                    mfa_codes: true,
                    login_notifications: false,
                },
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let mock_service = MockUserManagementService;
        let manager = ProfileManager::new(mock_service).unwrap();

        // Test privacy filtering
        assert!(manager.can_view_profile(&profile, Some("user123"))); // Owner can view
        assert!(manager.can_view_profile(&profile, Some("other_user"))); // Public profile
        
        let private_profile = UserProfile {
            privacy_settings: PrivacySettings {
                profile_visibility: ProfileVisibility::Private,
                ..profile.privacy_settings.clone()
            },
            ..profile
        };

        assert!(manager.can_view_profile(&private_profile, Some("user123"))); // Owner can view
        assert!(!manager.can_view_profile(&private_profile, Some("other_user"))); // Private profile
    }

    // Mock service for testing
    struct MockUserManagementService;

    #[async_trait::async_trait]
    impl UserManagementService for MockUserManagementService {
        async fn create_role(&self, _role: super::super::UserRole) -> Result<super::super::UserRole> { unimplemented!() }
        async fn get_role(&self, _role_id: &str) -> Result<Option<super::super::UserRole>> { unimplemented!() }
        async fn update_role(&self, _role_id: &str, _role: super::super::UserRole) -> Result<super::super::UserRole> { unimplemented!() }
        async fn delete_role(&self, _role_id: &str) -> Result<bool> { unimplemented!() }
        async fn list_roles(&self) -> Result<Vec<super::super::UserRole>> { unimplemented!() }
        async fn assign_role_to_user(&self, _user_id: &str, _role_id: &str) -> Result<()> { unimplemented!() }
        async fn remove_role_from_user(&self, _user_id: &str, _role_id: &str) -> Result<()> { unimplemented!() }
        async fn get_user_roles(&self, _user_id: &str) -> Result<Vec<super::super::UserRole>> { unimplemented!() }
        async fn create_permission(&self, _permission: super::super::Permission) -> Result<super::super::Permission> { unimplemented!() }
        async fn get_permission(&self, _permission_id: &str) -> Result<Option<super::super::Permission>> { unimplemented!() }
        async fn update_permission(&self, _permission_id: &str, _permission: super::super::Permission) -> Result<super::super::Permission> { unimplemented!() }
        async fn delete_permission(&self, _permission_id: &str) -> Result<bool> { unimplemented!() }
        async fn list_permissions(&self) -> Result<Vec<super::super::Permission>> { unimplemented!() }
        async fn check_user_permission(&self, _user_id: &str, _permission: &str, _context: Option<super::super::UserContext>) -> Result<super::super::PermissionCheckResult> { unimplemented!() }
        async fn get_user_permissions(&self, _user_id: &str) -> Result<HashSet<String>> { unimplemented!() }
        async fn create_group(&self, _group: super::super::UserGroup) -> Result<super::super::UserGroup> { unimplemented!() }
        async fn get_group(&self, _group_id: &str) -> Result<Option<super::super::UserGroup>> { unimplemented!() }
        async fn update_group(&self, _group_id: &str, _group: super::super::UserGroup) -> Result<super::super::UserGroup> { unimplemented!() }
        async fn delete_group(&self, _group_id: &str) -> Result<bool> { unimplemented!() }
        async fn list_groups(&self) -> Result<Vec<super::super::UserGroup>> { unimplemented!() }
        async fn add_user_to_group(&self, _user_id: &str, _group_id: &str) -> Result<()> { unimplemented!() }
        async fn remove_user_from_group(&self, _user_id: &str, _group_id: &str) -> Result<()> { unimplemented!() }
        async fn get_user_groups(&self, _user_id: &str) -> Result<Vec<super::super::UserGroup>> { unimplemented!() }
        async fn create_profile(&self, _profile: UserProfile) -> Result<UserProfile> { unimplemented!() }
        async fn get_profile(&self, _user_id: &str) -> Result<Option<UserProfile>> { unimplemented!() }
        async fn update_profile(&self, _user_id: &str, _profile: UserProfile) -> Result<UserProfile> { unimplemented!() }
        async fn delete_profile(&self, _user_id: &str) -> Result<bool> { unimplemented!() }
        async fn search_profiles(&self, _query: &str, _filters: Option<HashMap<String, String>>) -> Result<Vec<UserProfile>> { unimplemented!() }
        async fn update_privacy_settings(&self, _user_id: &str, _settings: PrivacySettings) -> Result<()> { unimplemented!() }
        async fn update_notification_preferences(&self, _user_id: &str, _preferences: NotificationPreferences) -> Result<()> { unimplemented!() }
    }
}