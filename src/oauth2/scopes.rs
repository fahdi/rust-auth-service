use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// OAuth2 scope management system
/// Handles scope validation, hierarchy, and permissions
/// Standard OAuth2 and OpenID Connect scopes
pub mod standard {
    pub const OPENID: &str = "openid";
    pub const PROFILE: &str = "profile";
    pub const EMAIL: &str = "email";
    pub const ADDRESS: &str = "address";
    pub const PHONE: &str = "phone";
    pub const OFFLINE_ACCESS: &str = "offline_access";
}

/// Application-specific scopes
pub mod app {
    pub const READ: &str = "read";
    pub const WRITE: &str = "write";
    pub const DELETE: &str = "delete";
    pub const ADMIN: &str = "admin";
    pub const USER_MANAGEMENT: &str = "user:management";
    pub const USER_READ: &str = "user:read";
    pub const USER_WRITE: &str = "user:write";
    pub const API_ACCESS: &str = "api:access";
    pub const API_ADMIN: &str = "api:admin";
}

/// Scope definition with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeDefinition {
    pub name: String,
    pub description: String,
    pub sensitive: bool,        // Requires explicit user consent
    pub admin_only: bool,       // Only admin users can grant
    pub implies: Vec<String>,   // Other scopes this scope includes
    pub conflicts: Vec<String>, // Scopes that conflict with this one
    pub resources: Vec<String>, // Resources this scope provides access to
    pub actions: Vec<String>,   // Actions allowed with this scope
}

/// Scope manager for validation and hierarchy
#[derive(Debug, Clone)]
pub struct ScopeManager {
    scopes: HashMap<String, ScopeDefinition>,
    hierarchy: HashMap<String, HashSet<String>>, // scope -> implied scopes
}

impl ScopeManager {
    /// Create new scope manager with default scopes
    pub fn new() -> Self {
        let mut manager = Self {
            scopes: HashMap::new(),
            hierarchy: HashMap::new(),
        };

        // Register standard scopes
        manager.register_standard_scopes();
        manager.register_application_scopes();
        manager.build_hierarchy();

        manager
    }

    /// Register a new scope
    pub fn register_scope(&mut self, scope: ScopeDefinition) {
        self.scopes.insert(scope.name.clone(), scope);
        self.build_hierarchy();
    }

    /// Get scope definition
    pub fn get_scope(&self, name: &str) -> Option<&ScopeDefinition> {
        self.scopes.get(name)
    }

    /// Check if scope exists
    pub fn scope_exists(&self, name: &str) -> bool {
        self.scopes.contains_key(name)
    }

    /// Validate requested scopes
    pub fn validate_scopes(&self, requested: &[String]) -> ScopeValidationResult {
        let mut result = ScopeValidationResult {
            valid: Vec::new(),
            invalid: Vec::new(),
            conflicts: Vec::new(),
            warnings: Vec::new(),
        };

        // Check if all scopes exist
        for scope in requested {
            if self.scope_exists(scope) {
                result.valid.push(scope.clone());
            } else {
                result.invalid.push(scope.clone());
            }
        }

        // Check for conflicts
        for scope in &result.valid {
            if let Some(scope_def) = self.get_scope(scope) {
                for conflict in &scope_def.conflicts {
                    if result.valid.contains(conflict) {
                        result.conflicts.push(ScopeConflict {
                            scope1: scope.clone(),
                            scope2: conflict.clone(),
                            reason: format!("Scope '{}' conflicts with '{}'", scope, conflict),
                        });
                    }
                }
            }
        }

        result
    }

    /// Expand scopes to include implied scopes
    pub fn expand_scopes(&self, scopes: &[String]) -> Vec<String> {
        let mut expanded = HashSet::new();

        for scope in scopes {
            if self.scope_exists(scope) {
                expanded.insert(scope.clone());

                // Add implied scopes
                if let Some(implied) = self.hierarchy.get(scope) {
                    expanded.extend(implied.iter().cloned());
                }
            }
        }

        expanded.into_iter().collect()
    }

    /// Filter scopes based on client permissions
    pub fn filter_allowed_scopes(&self, requested: &[String], allowed: &[String]) -> Vec<String> {
        requested
            .iter()
            .filter(|scope| allowed.contains(scope))
            .cloned()
            .collect()
    }

    /// Get sensitive scopes that require explicit consent
    pub fn get_sensitive_scopes(&self, scopes: &[String]) -> Vec<String> {
        scopes
            .iter()
            .filter(|scope| {
                self.get_scope(scope)
                    .map(|def| def.sensitive)
                    .unwrap_or(false)
            })
            .cloned()
            .collect()
    }

    /// Get admin-only scopes
    pub fn get_admin_only_scopes(&self, scopes: &[String]) -> Vec<String> {
        scopes
            .iter()
            .filter(|scope| {
                self.get_scope(scope)
                    .map(|def| def.admin_only)
                    .unwrap_or(false)
            })
            .cloned()
            .collect()
    }

    /// Check if user can grant specific scopes
    pub fn can_user_grant_scopes(&self, scopes: &[String], user_is_admin: bool) -> Vec<String> {
        if user_is_admin {
            return scopes.to_vec();
        }

        scopes
            .iter()
            .filter(|scope| {
                self.get_scope(scope)
                    .map(|def| !def.admin_only)
                    .unwrap_or(false)
            })
            .cloned()
            .collect()
    }

    /// Get scope permissions (resources and actions)
    pub fn get_scope_permissions(&self, scopes: &[String]) -> ScopePermissions {
        let mut resources = HashSet::new();
        let mut actions = HashSet::new();

        for scope in scopes {
            if let Some(scope_def) = self.get_scope(scope) {
                resources.extend(scope_def.resources.iter().cloned());
                actions.extend(scope_def.actions.iter().cloned());
            }
        }

        ScopePermissions {
            resources: resources.into_iter().collect(),
            actions: actions.into_iter().collect(),
        }
    }

    /// Compare two scope sets
    pub fn compare_scopes(&self, current: &[String], requested: &[String]) -> ScopeComparison {
        let current_set: HashSet<_> = current.iter().collect();
        let requested_set: HashSet<_> = requested.iter().collect();

        let added: Vec<String> = requested_set
            .difference(&current_set)
            .map(|s| s.to_string())
            .collect();

        let removed: Vec<String> = current_set
            .difference(&requested_set)
            .map(|s| s.to_string())
            .collect();

        let unchanged: Vec<String> = current_set
            .intersection(&requested_set)
            .map(|s| s.to_string())
            .collect();

        ScopeComparison {
            added,
            removed,
            unchanged,
        }
    }

    /// Format scopes for display
    pub fn format_scopes_for_display(&self, scopes: &[String]) -> Vec<ScopeDisplay> {
        scopes
            .iter()
            .filter_map(|scope| {
                self.get_scope(scope).map(|def| ScopeDisplay {
                    name: scope.clone(),
                    description: def.description.clone(),
                    sensitive: def.sensitive,
                    admin_only: def.admin_only,
                })
            })
            .collect()
    }

    // Private helper methods

    fn register_standard_scopes(&mut self) {
        // OpenID Connect scopes
        self.register_scope(ScopeDefinition {
            name: standard::OPENID.to_string(),
            description: "Access to OpenID Connect identity information".to_string(),
            sensitive: false,
            admin_only: false,
            implies: vec![],
            conflicts: vec![],
            resources: vec!["identity".to_string()],
            actions: vec!["read".to_string()],
        });

        self.register_scope(ScopeDefinition {
            name: standard::PROFILE.to_string(),
            description: "Access to user profile information (name, picture, etc.)".to_string(),
            sensitive: false,
            admin_only: false,
            implies: vec![],
            conflicts: vec![],
            resources: vec!["profile".to_string()],
            actions: vec!["read".to_string()],
        });

        self.register_scope(ScopeDefinition {
            name: standard::EMAIL.to_string(),
            description: "Access to user email address".to_string(),
            sensitive: true,
            admin_only: false,
            implies: vec![],
            conflicts: vec![],
            resources: vec!["email".to_string()],
            actions: vec!["read".to_string()],
        });

        self.register_scope(ScopeDefinition {
            name: standard::ADDRESS.to_string(),
            description: "Access to user postal address".to_string(),
            sensitive: true,
            admin_only: false,
            implies: vec![],
            conflicts: vec![],
            resources: vec!["address".to_string()],
            actions: vec!["read".to_string()],
        });

        self.register_scope(ScopeDefinition {
            name: standard::PHONE.to_string(),
            description: "Access to user phone number".to_string(),
            sensitive: true,
            admin_only: false,
            implies: vec![],
            conflicts: vec![],
            resources: vec!["phone".to_string()],
            actions: vec!["read".to_string()],
        });

        self.register_scope(ScopeDefinition {
            name: standard::OFFLINE_ACCESS.to_string(),
            description: "Request refresh tokens for offline access".to_string(),
            sensitive: false,
            admin_only: false,
            implies: vec![],
            conflicts: vec![],
            resources: vec!["tokens".to_string()],
            actions: vec!["refresh".to_string()],
        });
    }

    fn register_application_scopes(&mut self) {
        // Basic access scopes
        self.register_scope(ScopeDefinition {
            name: app::READ.to_string(),
            description: "Read access to your data".to_string(),
            sensitive: false,
            admin_only: false,
            implies: vec![],
            conflicts: vec![],
            resources: vec!["data".to_string()],
            actions: vec!["read".to_string()],
        });

        self.register_scope(ScopeDefinition {
            name: app::WRITE.to_string(),
            description: "Write access to modify your data".to_string(),
            sensitive: false,
            admin_only: false,
            implies: vec![app::READ.to_string()],
            conflicts: vec![],
            resources: vec!["data".to_string()],
            actions: vec!["read".to_string(), "write".to_string()],
        });

        self.register_scope(ScopeDefinition {
            name: app::DELETE.to_string(),
            description: "Permission to delete your data".to_string(),
            sensitive: true,
            admin_only: false,
            implies: vec![app::READ.to_string(), app::WRITE.to_string()],
            conflicts: vec![],
            resources: vec!["data".to_string()],
            actions: vec![
                "read".to_string(),
                "write".to_string(),
                "delete".to_string(),
            ],
        });

        self.register_scope(ScopeDefinition {
            name: app::ADMIN.to_string(),
            description: "Full administrative access".to_string(),
            sensitive: true,
            admin_only: true,
            implies: vec![
                app::READ.to_string(),
                app::WRITE.to_string(),
                app::DELETE.to_string(),
            ],
            conflicts: vec![],
            resources: vec!["*".to_string()],
            actions: vec!["*".to_string()],
        });

        // User management scopes
        self.register_scope(ScopeDefinition {
            name: app::USER_READ.to_string(),
            description: "Read user information".to_string(),
            sensitive: false,
            admin_only: false,
            implies: vec![],
            conflicts: vec![],
            resources: vec!["users".to_string()],
            actions: vec!["read".to_string()],
        });

        self.register_scope(ScopeDefinition {
            name: app::USER_WRITE.to_string(),
            description: "Modify user information".to_string(),
            sensitive: true,
            admin_only: false,
            implies: vec![app::USER_READ.to_string()],
            conflicts: vec![],
            resources: vec!["users".to_string()],
            actions: vec!["read".to_string(), "write".to_string()],
        });

        self.register_scope(ScopeDefinition {
            name: app::USER_MANAGEMENT.to_string(),
            description: "Full user management capabilities".to_string(),
            sensitive: true,
            admin_only: true,
            implies: vec![app::USER_READ.to_string(), app::USER_WRITE.to_string()],
            conflicts: vec![],
            resources: vec!["users".to_string()],
            actions: vec![
                "read".to_string(),
                "write".to_string(),
                "delete".to_string(),
                "manage".to_string(),
            ],
        });

        // API access scopes
        self.register_scope(ScopeDefinition {
            name: app::API_ACCESS.to_string(),
            description: "Basic API access".to_string(),
            sensitive: false,
            admin_only: false,
            implies: vec![app::READ.to_string()],
            conflicts: vec![],
            resources: vec!["api".to_string()],
            actions: vec!["access".to_string()],
        });

        self.register_scope(ScopeDefinition {
            name: app::API_ADMIN.to_string(),
            description: "Administrative API access".to_string(),
            sensitive: true,
            admin_only: true,
            implies: vec![app::API_ACCESS.to_string(), app::ADMIN.to_string()],
            conflicts: vec![],
            resources: vec!["api".to_string()],
            actions: vec!["*".to_string()],
        });
    }

    fn build_hierarchy(&mut self) {
        self.hierarchy.clear();

        for (scope_name, _scope_def) in &self.scopes {
            let mut implied = HashSet::new();
            self.collect_implied_scopes(scope_name, &mut implied);
            self.hierarchy.insert(scope_name.clone(), implied);
        }
    }

    fn collect_implied_scopes(&self, scope_name: &str, collected: &mut HashSet<String>) {
        if let Some(scope_def) = self.scopes.get(scope_name) {
            for implied in &scope_def.implies {
                if !collected.contains(implied) {
                    collected.insert(implied.clone());
                    self.collect_implied_scopes(implied, collected);
                }
            }
        }
    }
}

impl Default for ScopeManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Scope validation result
#[derive(Debug, Clone)]
pub struct ScopeValidationResult {
    pub valid: Vec<String>,
    pub invalid: Vec<String>,
    pub conflicts: Vec<ScopeConflict>,
    pub warnings: Vec<String>,
}

/// Scope conflict information
#[derive(Debug, Clone)]
pub struct ScopeConflict {
    pub scope1: String,
    pub scope2: String,
    pub reason: String,
}

/// Scope permissions
#[derive(Debug, Clone)]
pub struct ScopePermissions {
    pub resources: Vec<String>,
    pub actions: Vec<String>,
}

/// Scope comparison result
#[derive(Debug, Clone)]
pub struct ScopeComparison {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub unchanged: Vec<String>,
}

/// Scope display information
#[derive(Debug, Clone, Serialize)]
pub struct ScopeDisplay {
    pub name: String,
    pub description: String,
    pub sensitive: bool,
    pub admin_only: bool,
}

/// Utility functions for scope operations
pub mod utils {
    use super::*;

    /// Parse scope string into vector
    pub fn parse_scope_string(scope_str: &str) -> Vec<String> {
        scope_str
            .split_whitespace()
            .map(String::from)
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Join scopes into string
    pub fn join_scopes(scopes: &[String]) -> String {
        scopes.join(" ")
    }

    /// Check if scopes contain specific scope
    pub fn contains_scope(scopes: &[String], scope: &str) -> bool {
        scopes.iter().any(|s| s == scope)
    }

    /// Remove duplicates from scope list
    pub fn deduplicate_scopes(scopes: &[String]) -> Vec<String> {
        let mut unique = HashSet::new();
        scopes
            .iter()
            .filter(|scope| unique.insert(scope.as_str()))
            .cloned()
            .collect()
    }

    /// Sort scopes by name
    pub fn sort_scopes(scopes: &mut [String]) {
        scopes.sort();
    }

    /// Validate scope string format
    pub fn is_valid_scope_name(scope: &str) -> bool {
        // OAuth2 scope names should contain only ASCII characters
        // and specific symbols: !#$&'*+-.0-9A-Z^_`a-z|~
        scope.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '!' | '#'
                        | '$'
                        | '&'
                        | '\''
                        | '*'
                        | '+'
                        | '-'
                        | '.'
                        | '^'
                        | '_'
                        | '`'
                        | '|'
                        | '~'
                        | ':'
                )
        }) && !scope.is_empty()
            && scope.len() <= 128
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_manager_creation() {
        let manager = ScopeManager::new();

        // Should have standard scopes
        assert!(manager.scope_exists(standard::OPENID));
        assert!(manager.scope_exists(standard::EMAIL));
        assert!(manager.scope_exists(app::READ));
        assert!(manager.scope_exists(app::ADMIN));
    }

    #[test]
    fn test_scope_validation() {
        let manager = ScopeManager::new();

        let result = manager.validate_scopes(&[
            app::READ.to_string(),
            "invalid_scope".to_string(),
            standard::EMAIL.to_string(),
        ]);

        assert_eq!(result.valid.len(), 2);
        assert_eq!(result.invalid.len(), 1);
        assert_eq!(result.invalid[0], "invalid_scope");
    }

    #[test]
    fn test_scope_expansion() {
        let manager = ScopeManager::new();

        let expanded = manager.expand_scopes(&[app::WRITE.to_string()]);

        // Write should imply read
        assert!(expanded.contains(&app::WRITE.to_string()));
        assert!(expanded.contains(&app::READ.to_string()));
    }

    #[test]
    fn test_sensitive_scopes() {
        let manager = ScopeManager::new();

        let scopes = vec![
            standard::EMAIL.to_string(),
            app::READ.to_string(),
            app::DELETE.to_string(),
        ];

        let sensitive = manager.get_sensitive_scopes(&scopes);

        assert!(sensitive.contains(&standard::EMAIL.to_string()));
        assert!(sensitive.contains(&app::DELETE.to_string()));
        assert!(!sensitive.contains(&app::READ.to_string()));
    }

    #[test]
    fn test_admin_only_scopes() {
        let manager = ScopeManager::new();

        let scopes = vec![app::READ.to_string(), app::ADMIN.to_string()];

        let admin_only = manager.get_admin_only_scopes(&scopes);

        assert!(admin_only.contains(&app::ADMIN.to_string()));
        assert!(!admin_only.contains(&app::READ.to_string()));
    }

    #[test]
    fn test_user_grant_permissions() {
        let manager = ScopeManager::new();

        let scopes = vec![app::READ.to_string(), app::ADMIN.to_string()];

        // Non-admin user
        let non_admin_allowed = manager.can_user_grant_scopes(&scopes, false);
        assert!(non_admin_allowed.contains(&app::READ.to_string()));
        assert!(!non_admin_allowed.contains(&app::ADMIN.to_string()));

        // Admin user
        let admin_allowed = manager.can_user_grant_scopes(&scopes, true);
        assert_eq!(admin_allowed.len(), 2);
    }

    #[test]
    fn test_scope_utils() {
        let scope_str = "read write email";
        let scopes = utils::parse_scope_string(scope_str);
        assert_eq!(scopes, vec!["read", "write", "email"]);

        let joined = utils::join_scopes(&scopes);
        assert_eq!(joined, "read write email");

        assert!(utils::contains_scope(&scopes, "read"));
        assert!(!utils::contains_scope(&scopes, "admin"));

        assert!(utils::is_valid_scope_name("read"));
        assert!(utils::is_valid_scope_name("user:read"));
        assert!(!utils::is_valid_scope_name(""));
        assert!(!utils::is_valid_scope_name("invalid scope"));
    }
}
