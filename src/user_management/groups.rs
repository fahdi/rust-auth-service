use super::{UserGroup, UserManagementService, UserRole};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Group hierarchy resolver for nested group management
pub struct GroupHierarchyResolver {
    groups: HashMap<String, UserGroup>,
}

impl GroupHierarchyResolver {
    /// Create new group hierarchy resolver
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
        }
    }

    /// Load groups into resolver
    pub fn load_groups(&mut self, groups: Vec<UserGroup>) {
        for group in groups {
            self.groups.insert(group.id.clone(), group);
        }
    }

    /// Get all ancestor groups for a given group
    pub fn get_ancestor_groups(&self, group_id: &str) -> Result<Vec<String>> {
        let mut ancestors = Vec::new();
        let mut visited = HashSet::new();

        self.collect_ancestors(group_id, &mut ancestors, &mut visited)?;

        Ok(ancestors)
    }

    /// Recursively collect ancestor groups with cycle detection
    fn collect_ancestors(
        &self,
        group_id: &str,
        ancestors: &mut Vec<String>,
        visited: &mut HashSet<String>,
    ) -> Result<()> {
        if visited.contains(group_id) {
            return Err(anyhow::anyhow!(
                "Circular group hierarchy detected: {}",
                group_id
            ));
        }

        let group = self
            .groups
            .get(group_id)
            .ok_or_else(|| anyhow::anyhow!("Group not found: {}", group_id))?;

        visited.insert(group_id.to_string());

        for parent_id in &group.parent_groups {
            ancestors.push(parent_id.clone());
            self.collect_ancestors(parent_id, ancestors, visited)?;
        }

        visited.remove(group_id);
        Ok(())
    }

    /// Get all descendant groups for a given group
    pub fn get_descendant_groups(&self, group_id: &str) -> Result<Vec<String>> {
        let mut descendants = Vec::new();
        let mut visited = HashSet::new();

        self.collect_descendants(group_id, &mut descendants, &mut visited)?;

        Ok(descendants)
    }

    /// Recursively collect descendant groups
    fn collect_descendants(
        &self,
        group_id: &str,
        descendants: &mut Vec<String>,
        visited: &mut HashSet<String>,
    ) -> Result<()> {
        if visited.contains(group_id) {
            return Err(anyhow::anyhow!(
                "Circular group hierarchy detected: {}",
                group_id
            ));
        }

        let group = self
            .groups
            .get(group_id)
            .ok_or_else(|| anyhow::anyhow!("Group not found: {}", group_id))?;

        visited.insert(group_id.to_string());

        for child_id in &group.child_groups {
            descendants.push(child_id.clone());
            self.collect_descendants(child_id, descendants, visited)?;
        }

        visited.remove(group_id);
        Ok(())
    }

    /// Get effective roles for a group (including inherited from parent groups)
    pub fn get_effective_roles(&self, group_id: &str) -> Result<HashSet<String>> {
        let mut effective_roles = HashSet::new();
        let mut visited = HashSet::new();

        self.collect_effective_roles(group_id, &mut effective_roles, &mut visited)?;

        Ok(effective_roles)
    }

    /// Recursively collect effective roles from group hierarchy
    fn collect_effective_roles(
        &self,
        group_id: &str,
        effective_roles: &mut HashSet<String>,
        visited: &mut HashSet<String>,
    ) -> Result<()> {
        if visited.contains(group_id) {
            return Err(anyhow::anyhow!(
                "Circular group hierarchy detected: {}",
                group_id
            ));
        }

        let group = self
            .groups
            .get(group_id)
            .ok_or_else(|| anyhow::anyhow!("Group not found: {}", group_id))?;

        visited.insert(group_id.to_string());

        // Add direct roles
        effective_roles.extend(group.roles.iter().cloned());

        // Add inherited roles from parent groups
        for parent_id in &group.parent_groups {
            self.collect_effective_roles(parent_id, effective_roles, visited)?;
        }

        visited.remove(group_id);
        Ok(())
    }

    /// Validate group hierarchy to prevent cycles
    pub fn validate_hierarchy(&self, group_id: &str, new_parent_id: &str) -> Result<()> {
        // Check if adding this parent would create a cycle
        let descendants = self.get_descendant_groups(group_id)?;

        if descendants.contains(&new_parent_id.to_string()) {
            return Err(anyhow::anyhow!(
                "Cannot add parent group '{}' - it would create a circular hierarchy",
                new_parent_id
            ));
        }

        Ok(())
    }

    /// Get group depth in hierarchy
    pub fn get_group_depth(&self, group_id: &str) -> Result<usize> {
        let mut visited = HashSet::new();
        self.calculate_depth(group_id, &mut visited)
    }

    fn calculate_depth(&self, group_id: &str, visited: &mut HashSet<String>) -> Result<usize> {
        if visited.contains(group_id) {
            return Err(anyhow::anyhow!("Circular group hierarchy detected"));
        }

        let group = self
            .groups
            .get(group_id)
            .ok_or_else(|| anyhow::anyhow!("Group not found: {}", group_id))?;

        if group.parent_groups.is_empty() {
            return Ok(0);
        }

        visited.insert(group_id.to_string());
        let mut max_depth = 0;

        for parent_id in &group.parent_groups {
            let parent_depth = self.calculate_depth(parent_id, visited)?;
            max_depth = max_depth.max(parent_depth + 1);
        }

        visited.remove(group_id);
        Ok(max_depth)
    }
}

/// Group manager for CRUD operations and hierarchy management
pub struct GroupManager<T: UserManagementService> {
    service: T,
    max_hierarchy_depth: usize,
    max_members_per_group: usize,
}

impl<T: UserManagementService> GroupManager<T> {
    /// Create new group manager
    pub fn new(service: T) -> Self {
        Self {
            service,
            max_hierarchy_depth: 10,      // Prevent overly deep hierarchies
            max_members_per_group: 10000, // Prevent performance issues
        }
    }

    /// Create group with validation
    pub async fn create_group(&self, mut group: UserGroup) -> Result<UserGroup> {
        // Validate group data
        self.validate_group_data(&group).await?;

        // Validate hierarchy if parent groups are specified
        if !group.parent_groups.is_empty() {
            self.validate_group_hierarchy(&group).await?;
        }

        // Set timestamps
        let now = Utc::now();
        group.created_at = now;
        group.updated_at = now;

        // Create the group
        let created_group = self.service.create_group(group.clone()).await?;

        // Update parent groups to include this group as a child
        for parent_id in &group.parent_groups {
            self.add_child_to_parent(parent_id, &created_group.id)
                .await?;
        }

        Ok(created_group)
    }

    /// Update group with hierarchy validation
    pub async fn update_group(&self, group_id: &str, mut group: UserGroup) -> Result<UserGroup> {
        // Get existing group
        let existing_group = self
            .service
            .get_group(group_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Group not found: {}", group_id))?;

        // Validate updated group data
        self.validate_group_data(&group).await?;

        // Handle parent group changes
        let old_parents: HashSet<_> = existing_group.parent_groups.iter().collect();
        let new_parents: HashSet<_> = group.parent_groups.iter().collect();

        // Validate new hierarchy
        if !group.parent_groups.is_empty() {
            self.validate_group_hierarchy(&group).await?;
        }

        // Update timestamps
        group.created_at = existing_group.created_at;
        group.updated_at = Utc::now();

        // Update the group
        let updated_group = self.service.update_group(group_id, group.clone()).await?;

        // Update parent-child relationships
        // Remove from old parents that are no longer parents
        for old_parent in old_parents.difference(&new_parents) {
            self.remove_child_from_parent(old_parent, group_id).await?;
        }

        // Add to new parents
        for new_parent in new_parents.difference(&old_parents) {
            self.add_child_to_parent(new_parent, group_id).await?;
        }

        Ok(updated_group)
    }

    /// Delete group with dependency checking
    pub async fn delete_group(&self, group_id: &str) -> Result<bool> {
        let group = self
            .service
            .get_group(group_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Group not found: {}", group_id))?;

        // Check if group has members
        if !group.members.is_empty() {
            return Err(anyhow::anyhow!(
                "Cannot delete group '{}' - it has {} members",
                group_id,
                group.members.len()
            ));
        }

        // Check if group has child groups
        if !group.child_groups.is_empty() {
            return Err(anyhow::anyhow!(
                "Cannot delete group '{}' - it has {} child groups",
                group_id,
                group.child_groups.len()
            ));
        }

        // Remove from parent groups
        for parent_id in &group.parent_groups {
            self.remove_child_from_parent(parent_id, group_id).await?;
        }

        self.service.delete_group(group_id).await
    }

    /// Add user to group with hierarchy consideration
    pub async fn add_user_to_group(&self, user_id: &str, group_id: &str) -> Result<()> {
        let group = self
            .service
            .get_group(group_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Group not found: {}", group_id))?;

        // Check member limit
        if group.members.len() >= self.max_members_per_group {
            return Err(anyhow::anyhow!(
                "Group '{}' has reached maximum member limit of {}",
                group_id,
                self.max_members_per_group
            ));
        }

        // Check if user is already a member
        if group.members.contains(user_id) {
            return Err(anyhow::anyhow!(
                "User '{}' is already a member of group '{}'",
                user_id,
                group_id
            ));
        }

        self.service.add_user_to_group(user_id, group_id).await
    }

    /// Remove user from group
    pub async fn remove_user_from_group(&self, user_id: &str, group_id: &str) -> Result<()> {
        let group = self
            .service
            .get_group(group_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Group not found: {}", group_id))?;

        // Check if user is a member
        if !group.members.contains(user_id) {
            return Err(anyhow::anyhow!(
                "User '{}' is not a member of group '{}'",
                user_id,
                group_id
            ));
        }

        self.service.remove_user_from_group(user_id, group_id).await
    }

    /// Get effective roles for user from all their groups
    pub async fn get_user_effective_roles_from_groups(
        &self,
        user_id: &str,
    ) -> Result<HashSet<String>> {
        let user_groups = self.service.get_user_groups(user_id).await?;
        let mut effective_roles = HashSet::new();

        // Create hierarchy resolver
        let mut resolver = GroupHierarchyResolver::new();
        let all_groups = self.service.list_groups().await?;
        resolver.load_groups(all_groups);

        // Get effective roles from each group
        for group in &user_groups {
            let group_roles = resolver.get_effective_roles(&group.id)?;
            effective_roles.extend(group_roles);
        }

        Ok(effective_roles)
    }

    /// Get all groups in hierarchy path for a group
    pub async fn get_group_hierarchy_path(&self, group_id: &str) -> Result<Vec<UserGroup>> {
        let mut resolver = GroupHierarchyResolver::new();
        let all_groups = self.service.list_groups().await?;
        resolver.load_groups(all_groups.clone());

        let ancestor_ids = resolver.get_ancestor_groups(group_id)?;

        let mut hierarchy_path = Vec::new();
        for ancestor_id in ancestor_ids {
            if let Some(group) = all_groups.iter().find(|g| g.id == ancestor_id) {
                hierarchy_path.push(group.clone());
            }
        }

        Ok(hierarchy_path)
    }

    /// Validate group data
    async fn validate_group_data(&self, group: &UserGroup) -> Result<()> {
        if group.id.is_empty() {
            return Err(anyhow::anyhow!("Group ID cannot be empty"));
        }

        if group.name.is_empty() {
            return Err(anyhow::anyhow!("Group name cannot be empty"));
        }

        // Validate that all roles exist
        for role_id in &group.roles {
            if self.service.get_role(role_id).await?.is_none() {
                return Err(anyhow::anyhow!("Role not found: {}", role_id));
            }
        }

        // Validate parent groups exist
        for parent_id in &group.parent_groups {
            if self.service.get_group(parent_id).await?.is_none() {
                return Err(anyhow::anyhow!("Parent group not found: {}", parent_id));
            }
        }

        Ok(())
    }

    /// Validate group hierarchy to prevent cycles and depth limits
    async fn validate_group_hierarchy(&self, group: &UserGroup) -> Result<()> {
        // Create hierarchy resolver for validation
        let mut resolver = GroupHierarchyResolver::new();
        let mut all_groups = self.service.list_groups().await?;

        // Add the new/updated group for validation
        all_groups.push(group.clone());
        resolver.load_groups(all_groups);

        // Check for cycles
        resolver.get_effective_roles(&group.id)?;

        // Check hierarchy depth
        let depth = resolver.get_group_depth(&group.id)?;
        if depth > self.max_hierarchy_depth {
            return Err(anyhow::anyhow!(
                "Group hierarchy depth {} exceeds maximum allowed depth of {}",
                depth,
                self.max_hierarchy_depth
            ));
        }

        Ok(())
    }

    /// Add child group reference to parent
    async fn add_child_to_parent(&self, parent_id: &str, child_id: &str) -> Result<()> {
        let mut parent_group = self
            .service
            .get_group(parent_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Parent group not found: {}", parent_id))?;

        if !parent_group.child_groups.contains(&child_id.to_string()) {
            parent_group.child_groups.push(child_id.to_string());
            parent_group.updated_at = Utc::now();
            self.service.update_group(parent_id, parent_group).await?;
        }

        Ok(())
    }

    /// Remove child group reference from parent
    async fn remove_child_from_parent(&self, parent_id: &str, child_id: &str) -> Result<()> {
        let mut parent_group = self
            .service
            .get_group(parent_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Parent group not found: {}", parent_id))?;

        parent_group.child_groups.retain(|id| id != child_id);
        parent_group.updated_at = Utc::now();
        self.service.update_group(parent_id, parent_group).await?;

        Ok(())
    }
}

/// Group membership manager for bulk operations
pub struct GroupMembershipManager<T: UserManagementService> {
    service: T,
}

impl<T: UserManagementService> GroupMembershipManager<T> {
    pub fn new(service: T) -> Self {
        Self { service }
    }

    /// Add multiple users to a group
    pub async fn add_users_to_group(
        &self,
        user_ids: &[String],
        group_id: &str,
    ) -> Result<Vec<String>> {
        let mut successful_additions = Vec::new();

        for user_id in user_ids {
            match self.service.add_user_to_group(user_id, group_id).await {
                Ok(_) => successful_additions.push(user_id.clone()),
                Err(_) => {
                    // Log error but continue with other users
                    continue;
                }
            }
        }

        Ok(successful_additions)
    }

    /// Remove multiple users from a group
    pub async fn remove_users_from_group(
        &self,
        user_ids: &[String],
        group_id: &str,
    ) -> Result<Vec<String>> {
        let mut successful_removals = Vec::new();

        for user_id in user_ids {
            match self.service.remove_user_from_group(user_id, group_id).await {
                Ok(_) => successful_removals.push(user_id.clone()),
                Err(_) => {
                    // Log error but continue with other users
                    continue;
                }
            }
        }

        Ok(successful_removals)
    }

    /// Transfer users from one group to another
    pub async fn transfer_users(
        &self,
        user_ids: &[String],
        from_group_id: &str,
        to_group_id: &str,
    ) -> Result<Vec<String>> {
        let mut successful_transfers = Vec::new();

        for user_id in user_ids {
            // Remove from source group
            if self
                .service
                .remove_user_from_group(user_id, from_group_id)
                .await
                .is_ok()
            {
                // Add to destination group
                if self
                    .service
                    .add_user_to_group(user_id, to_group_id)
                    .await
                    .is_ok()
                {
                    successful_transfers.push(user_id.clone());
                } else {
                    // Re-add to source group if destination addition failed
                    let _ = self.service.add_user_to_group(user_id, from_group_id).await;
                }
            }
        }

        Ok(successful_transfers)
    }

    /// Get group membership statistics
    pub async fn get_membership_statistics(&self, group_id: &str) -> Result<GroupMembershipStats> {
        let group = self
            .service
            .get_group(group_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Group not found: {}", group_id))?;

        // Create hierarchy resolver
        let mut resolver = GroupHierarchyResolver::new();
        let all_groups = self.service.list_groups().await?;
        resolver.load_groups(all_groups);

        // Get effective roles count
        let effective_roles = resolver.get_effective_roles(group_id)?;

        // Get descendant groups count
        let descendant_groups = resolver.get_descendant_groups(group_id)?;

        Ok(GroupMembershipStats {
            direct_members: group.members.len(),
            total_roles: effective_roles.len(),
            child_groups_count: group.child_groups.len(),
            descendant_groups_count: descendant_groups.len(),
        })
    }
}

/// Group membership statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMembershipStats {
    pub direct_members: usize,
    pub total_roles: usize,
    pub child_groups_count: usize,
    pub descendant_groups_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashSet;

    #[test]
    fn test_group_hierarchy_resolver() {
        let mut resolver = GroupHierarchyResolver::new();

        // Create test groups
        let root_group = UserGroup {
            id: "root".to_string(),
            name: "Root Group".to_string(),
            description: "Root level group".to_string(),
            roles: vec!["admin".to_string()].into_iter().collect(),
            parent_groups: vec![],
            child_groups: vec!["dept".to_string()],
            members: HashSet::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let dept_group = UserGroup {
            id: "dept".to_string(),
            name: "Department".to_string(),
            description: "Department group".to_string(),
            roles: vec!["user".to_string()].into_iter().collect(),
            parent_groups: vec!["root".to_string()],
            child_groups: vec!["team".to_string()],
            members: HashSet::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let team_group = UserGroup {
            id: "team".to_string(),
            name: "Team".to_string(),
            description: "Team group".to_string(),
            roles: vec!["member".to_string()].into_iter().collect(),
            parent_groups: vec!["dept".to_string()],
            child_groups: vec![],
            members: HashSet::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        resolver.load_groups(vec![root_group, dept_group, team_group]);

        // Test ancestor resolution
        let ancestors = resolver.get_ancestor_groups("team").unwrap();
        assert!(ancestors.contains(&"dept".to_string()));
        assert!(ancestors.contains(&"root".to_string()));

        // Test descendant resolution
        let descendants = resolver.get_descendant_groups("root").unwrap();
        assert!(descendants.contains(&"dept".to_string()));
        assert!(descendants.contains(&"team".to_string()));

        // Test effective roles
        let effective_roles = resolver.get_effective_roles("team").unwrap();
        assert!(effective_roles.contains("member"));
        assert!(effective_roles.contains("user"));
        assert!(effective_roles.contains("admin"));
    }

    #[test]
    fn test_circular_hierarchy_detection() {
        let mut resolver = GroupHierarchyResolver::new();

        let group_a = UserGroup {
            id: "a".to_string(),
            name: "Group A".to_string(),
            description: "Group A".to_string(),
            roles: HashSet::new(),
            parent_groups: vec!["b".to_string()],
            child_groups: vec![],
            members: HashSet::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let group_b = UserGroup {
            id: "b".to_string(),
            name: "Group B".to_string(),
            description: "Group B".to_string(),
            roles: HashSet::new(),
            parent_groups: vec!["a".to_string()], // Circular!
            child_groups: vec![],
            members: HashSet::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        resolver.load_groups(vec![group_a, group_b]);

        let result = resolver.get_effective_roles("a");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Circular"));
    }
}
