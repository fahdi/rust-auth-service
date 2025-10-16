use super::{Permission, UserManagementService, UserRole};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Role hierarchy resolver for inheritance
pub struct RoleHierarchyResolver {
    roles: HashMap<String, UserRole>,
    permissions: HashMap<String, Permission>,
}

impl RoleHierarchyResolver {
    /// Create new role hierarchy resolver
    pub fn new() -> Self {
        Self {
            roles: HashMap::new(),
            permissions: HashMap::new(),
        }
    }

    /// Load roles and permissions into resolver
    pub fn load_roles(&mut self, roles: Vec<UserRole>) {
        for role in roles {
            self.roles.insert(role.id.clone(), role);
        }
    }

    pub fn load_permissions(&mut self, permissions: Vec<Permission>) {
        for permission in permissions {
            self.permissions.insert(permission.id.clone(), permission);
        }
    }

    /// Resolve all permissions for a role including inherited ones
    pub fn resolve_role_permissions(&self, role_id: &str) -> Result<HashSet<String>> {
        let mut resolved_permissions = HashSet::new();
        let mut visited_roles = HashSet::new();

        self.resolve_role_permissions_recursive(
            role_id,
            &mut resolved_permissions,
            &mut visited_roles,
        )?;

        Ok(resolved_permissions)
    }

    /// Recursively resolve permissions with cycle detection
    fn resolve_role_permissions_recursive(
        &self,
        role_id: &str,
        resolved_permissions: &mut HashSet<String>,
        visited_roles: &mut HashSet<String>,
    ) -> Result<()> {
        if visited_roles.contains(role_id) {
            return Err(anyhow::anyhow!(
                "Circular role inheritance detected: {}",
                role_id
            ));
        }

        let role = self
            .roles
            .get(role_id)
            .ok_or_else(|| anyhow::anyhow!("Role not found: {}", role_id))?;

        visited_roles.insert(role_id.to_string());

        // Add direct permissions
        for permission in &role.permissions {
            if permission.contains('*') {
                // Wildcard permission - expand to all matching permissions
                let expanded = self.expand_wildcard_permission(permission);
                resolved_permissions.extend(expanded);
            } else {
                resolved_permissions.insert(permission.clone());
            }
        }

        // Add inherited permissions
        for parent_role_id in &role.inherits_from {
            self.resolve_role_permissions_recursive(
                parent_role_id,
                resolved_permissions,
                visited_roles,
            )?;
        }

        visited_roles.remove(role_id);
        Ok(())
    }

    /// Expand wildcard permissions to concrete permissions
    fn expand_wildcard_permission(&self, wildcard: &str) -> HashSet<String> {
        let mut expanded = HashSet::new();

        if wildcard.ends_with(":*") {
            let resource = wildcard.trim_end_matches(":*");
            for permission in self.permissions.values() {
                if permission.resource == resource {
                    expanded.insert(permission.id.clone());
                }
            }
        } else if wildcard == "*" {
            // Full wildcard - all permissions
            for permission in self.permissions.values() {
                expanded.insert(permission.id.clone());
            }
        }

        expanded
    }

    /// Check if a role exists and is valid
    pub fn validate_role(&self, role_id: &str) -> Result<()> {
        self.roles
            .get(role_id)
            .ok_or_else(|| anyhow::anyhow!("Role not found: {}", role_id))?;
        Ok(())
    }

    /// Get role hierarchy depth for a role
    pub fn get_role_depth(&self, role_id: &str) -> Result<usize> {
        let mut visited = HashSet::new();
        self.get_role_depth_recursive(role_id, &mut visited)
    }

    fn get_role_depth_recursive(
        &self,
        role_id: &str,
        visited: &mut HashSet<String>,
    ) -> Result<usize> {
        if visited.contains(role_id) {
            return Err(anyhow::anyhow!("Circular role inheritance detected"));
        }

        let role = self
            .roles
            .get(role_id)
            .ok_or_else(|| anyhow::anyhow!("Role not found: {}", role_id))?;

        if role.inherits_from.is_empty() {
            return Ok(0);
        }

        visited.insert(role_id.to_string());
        let mut max_depth = 0;

        for parent_role_id in &role.inherits_from {
            let parent_depth = self.get_role_depth_recursive(parent_role_id, visited)?;
            max_depth = max_depth.max(parent_depth + 1);
        }

        visited.remove(role_id);
        Ok(max_depth)
    }

    /// Get all child roles of a parent role
    pub fn get_child_roles(&self, parent_role_id: &str) -> Vec<String> {
        let mut children = Vec::new();

        for role in self.roles.values() {
            if role.inherits_from.contains(&parent_role_id.to_string()) {
                children.push(role.id.clone());
            }
        }

        children
    }

    /// Get role inheritance chain
    pub fn get_role_inheritance_chain(&self, role_id: &str) -> Result<Vec<String>> {
        let mut chain = vec![role_id.to_string()];
        let mut visited = HashSet::new();

        self.build_inheritance_chain(role_id, &mut chain, &mut visited)?;

        Ok(chain)
    }

    fn build_inheritance_chain(
        &self,
        role_id: &str,
        chain: &mut Vec<String>,
        visited: &mut HashSet<String>,
    ) -> Result<()> {
        if visited.contains(role_id) {
            return Err(anyhow::anyhow!("Circular role inheritance detected"));
        }

        let role = self
            .roles
            .get(role_id)
            .ok_or_else(|| anyhow::anyhow!("Role not found: {}", role_id))?;

        visited.insert(role_id.to_string());

        for parent_role_id in &role.inherits_from {
            chain.push(parent_role_id.clone());
            self.build_inheritance_chain(parent_role_id, chain, visited)?;
        }

        visited.remove(role_id);
        Ok(())
    }
}

/// Role manager for CRUD operations and validation
pub struct RoleManager<T: UserManagementService> {
    service: T,
    hierarchy_resolver: RoleHierarchyResolver,
}

impl<T: UserManagementService> RoleManager<T> {
    /// Create new role manager
    pub fn new(service: T) -> Self {
        Self {
            service,
            hierarchy_resolver: RoleHierarchyResolver::new(),
        }
    }

    /// Initialize with system roles and permissions
    pub async fn initialize(&mut self) -> Result<()> {
        let system_roles = super::get_default_system_roles();
        let system_permissions = super::get_default_system_permissions();

        // Create permissions first
        for permission in &system_permissions {
            if self.service.get_permission(&permission.id).await?.is_none() {
                self.service.create_permission(permission.clone()).await?;
            }
        }

        // Create roles
        for role in &system_roles {
            if self.service.get_role(&role.id).await?.is_none() {
                self.service.create_role(role.clone()).await?;
            }
        }

        // Load into hierarchy resolver
        self.hierarchy_resolver.load_roles(system_roles);
        self.hierarchy_resolver.load_permissions(system_permissions);

        Ok(())
    }

    /// Create a new role with validation
    pub async fn create_role(&self, mut role: UserRole) -> Result<UserRole> {
        // Validate role data
        self.validate_role_data(&role).await?;

        // Check for inheritance cycles
        if !role.inherits_from.is_empty() {
            self.validate_role_inheritance(&role).await?;
        }

        // Ensure system roles cannot be recreated
        if role.is_system_role {
            return Err(anyhow::anyhow!("Cannot create system role: {}", role.id));
        }

        // Set timestamps
        let now = Utc::now();
        role.created_at = now;
        role.updated_at = now;

        self.service.create_role(role).await
    }

    /// Update role with inheritance validation
    pub async fn update_role(&self, role_id: &str, mut role: UserRole) -> Result<UserRole> {
        // Check if role exists
        let existing_role = self
            .service
            .get_role(role_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Role not found: {}", role_id))?;

        // Prevent modification of system roles
        if existing_role.is_system_role {
            return Err(anyhow::anyhow!("Cannot modify system role: {}", role_id));
        }

        // Validate updated role data
        self.validate_role_data(&role).await?;

        // Validate inheritance changes
        if !role.inherits_from.is_empty() {
            self.validate_role_inheritance(&role).await?;
        }

        // Update timestamp
        role.updated_at = Utc::now();

        self.service.update_role(role_id, role).await
    }

    /// Delete role with dependency checking
    pub async fn delete_role(&self, role_id: &str) -> Result<bool> {
        let role = self
            .service
            .get_role(role_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Role not found: {}", role_id))?;

        // Prevent deletion of system roles
        if role.is_system_role {
            return Err(anyhow::anyhow!("Cannot delete system role: {}", role_id));
        }

        // Check if role is inherited by other roles
        let all_roles = self.service.list_roles().await?;
        for other_role in &all_roles {
            if other_role.inherits_from.contains(&role_id.to_string()) {
                return Err(anyhow::anyhow!(
                    "Cannot delete role {} - it is inherited by role {}",
                    role_id,
                    other_role.id
                ));
            }
        }

        self.service.delete_role(role_id).await
    }

    /// Get effective permissions for a role (including inherited)
    pub async fn get_effective_permissions(&self, role_id: &str) -> Result<HashSet<String>> {
        // Refresh hierarchy resolver with current data
        let mut resolver = RoleHierarchyResolver::new();
        let roles = self.service.list_roles().await?;
        let permissions = self.service.list_permissions().await?;

        resolver.load_roles(roles);
        resolver.load_permissions(permissions);

        resolver.resolve_role_permissions(role_id)
    }

    /// Validate role data
    async fn validate_role_data(&self, role: &UserRole) -> Result<()> {
        if role.id.is_empty() {
            return Err(anyhow::anyhow!("Role ID cannot be empty"));
        }

        if role.name.is_empty() {
            return Err(anyhow::anyhow!("Role name cannot be empty"));
        }

        // Validate permission format
        for permission in &role.permissions {
            if !self.is_valid_permission_format(permission) {
                return Err(anyhow::anyhow!("Invalid permission format: {}", permission));
            }
        }

        Ok(())
    }

    /// Validate role inheritance to prevent cycles
    async fn validate_role_inheritance(&self, role: &UserRole) -> Result<()> {
        // Create temporary hierarchy resolver for validation
        let mut resolver = RoleHierarchyResolver::new();
        let mut roles = self.service.list_roles().await?;

        // Add the new/updated role to the list for validation
        roles.push(role.clone());
        resolver.load_roles(roles);

        // Check for cycles
        resolver.resolve_role_permissions(&role.id)?;

        Ok(())
    }

    /// Validate permission format
    fn is_valid_permission_format(&self, permission: &str) -> bool {
        if permission == "*" {
            return true;
        }

        if permission.contains(':') {
            let parts: Vec<&str> = permission.split(':').collect();
            if parts.len() == 2 {
                let resource = parts[0];
                let action = parts[1];
                return !resource.is_empty() && (!action.is_empty() || action == "*");
            }
        }

        false
    }
}

/// Role assignment tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub user_id: String,
    pub role_id: String,
    pub assigned_by: String,
    pub assigned_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

/// Role assignment manager
pub struct RoleAssignmentManager<T: UserManagementService> {
    service: T,
}

impl<T: UserManagementService> RoleAssignmentManager<T> {
    pub fn new(service: T) -> Self {
        Self { service }
    }

    /// Assign role to user with optional expiration
    pub async fn assign_role(
        &self,
        user_id: &str,
        role_id: &str,
        _assigned_by: &str,
        _expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        // Validate role exists
        self.service
            .get_role(role_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Role not found: {}", role_id))?;

        // Check if user already has this role
        let user_roles = self.service.get_user_roles(user_id).await?;
        if user_roles.iter().any(|r| r.id == role_id) {
            return Err(anyhow::anyhow!("User already has role: {}", role_id));
        }

        self.service.assign_role_to_user(user_id, role_id).await
    }

    /// Remove role from user
    pub async fn remove_role(&self, user_id: &str, role_id: &str) -> Result<()> {
        // Check if user has this role
        let user_roles = self.service.get_user_roles(user_id).await?;
        if !user_roles.iter().any(|r| r.id == role_id) {
            return Err(anyhow::anyhow!("User does not have role: {}", role_id));
        }

        self.service.remove_role_from_user(user_id, role_id).await
    }

    /// Get user's effective permissions from all roles
    pub async fn get_user_effective_permissions(&self, user_id: &str) -> Result<HashSet<String>> {
        let user_roles = self.service.get_user_roles(user_id).await?;
        let mut all_permissions = HashSet::new();

        // Create hierarchy resolver
        let mut resolver = RoleHierarchyResolver::new();
        let all_roles = self.service.list_roles().await?;
        let all_permissions_def = self.service.list_permissions().await?;

        resolver.load_roles(all_roles);
        resolver.load_permissions(all_permissions_def);

        // Resolve permissions for each user role
        for role in &user_roles {
            let role_permissions = resolver.resolve_role_permissions(&role.id)?;
            all_permissions.extend(role_permissions);
        }

        Ok(all_permissions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_role_hierarchy_resolver() {
        let mut resolver = RoleHierarchyResolver::new();

        let admin_role = UserRole {
            id: "admin".to_string(),
            name: "Admin".to_string(),
            description: "Admin role".to_string(),
            permissions: vec!["users:*".to_string()].into_iter().collect(),
            inherits_from: vec!["user".to_string()],
            is_system_role: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let user_role = UserRole {
            id: "user".to_string(),
            name: "User".to_string(),
            description: "User role".to_string(),
            permissions: vec!["profile:read".to_string()].into_iter().collect(),
            inherits_from: vec![],
            is_system_role: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        resolver.load_roles(vec![admin_role, user_role]);

        let permissions = resolver.resolve_role_permissions("admin").unwrap();
        assert!(permissions.contains("profile:read")); // Inherited
        assert!(permissions.contains("users:*")); // Direct
    }

    #[test]
    fn test_circular_inheritance_detection() {
        let mut resolver = RoleHierarchyResolver::new();

        let role_a = UserRole {
            id: "a".to_string(),
            name: "A".to_string(),
            description: "Role A".to_string(),
            permissions: HashSet::new(),
            inherits_from: vec!["b".to_string()],
            is_system_role: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let role_b = UserRole {
            id: "b".to_string(),
            name: "B".to_string(),
            description: "Role B".to_string(),
            permissions: HashSet::new(),
            inherits_from: vec!["a".to_string()], // Circular!
            is_system_role: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        resolver.load_roles(vec![role_a, role_b]);

        let result = resolver.resolve_role_permissions("a");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Circular"));
    }
}
