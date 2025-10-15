#![allow(dead_code)]

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;
use tracing::{info, warn};

pub mod mongodb;
#[cfg(feature = "mysql")]
pub mod mysql;
#[cfg(feature = "postgresql")]
pub mod postgresql;
pub mod runner;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Migration {
    pub version: u32,
    pub name: String,
    pub description: Option<String>,
    pub up_sql: Option<String>,
    pub down_sql: Option<String>,
    pub checksum: String,
    pub applied_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationRecord {
    pub version: u32,
    pub name: String,
    pub checksum: String,
    pub applied_at: chrono::DateTime<chrono::Utc>,
    pub execution_time_ms: i64,
}

#[async_trait]
#[allow(dead_code)]
pub trait MigrationProvider: Send + Sync {
    /// Initialize migration tracking table/collection
    async fn init_migration_table(&self) -> Result<()>;
    
    /// Get list of applied migrations
    async fn get_applied_migrations(&self) -> Result<Vec<MigrationRecord>>;
    
    /// Record a migration as applied
    async fn record_migration(&self, migration: &Migration, execution_time_ms: i64) -> Result<()>;
    
    /// Remove migration record (for rollback)
    async fn remove_migration_record(&self, version: u32) -> Result<()>;
    
    /// Execute migration SQL/commands
    async fn execute_migration(&self, migration: &Migration) -> Result<()>;
    
    /// Execute rollback SQL/commands
    async fn rollback_migration(&self, migration: &Migration) -> Result<()>;
    
    /// Check database connection
    async fn ping(&self) -> Result<()>;
}

#[allow(dead_code)]
pub struct MigrationLoader {
    migrations_dir: String,
    database_type: String,
}

#[allow(dead_code)]
impl MigrationLoader {
    pub fn new(migrations_dir: impl Into<String>, database_type: impl Into<String>) -> Self {
        Self {
            migrations_dir: migrations_dir.into(),
            database_type: database_type.into(),
        }
    }

    /// Load all migration files from the database-specific directory
    pub async fn load_migrations(&self) -> Result<Vec<Migration>> {
        let migrations_path = Path::new(&self.migrations_dir).join(&self.database_type);
        
        if !migrations_path.exists() {
            warn!("Migrations directory does not exist: {:?}", migrations_path);
            return Ok(vec![]);
        }

        let mut migrations = Vec::new();
        let mut dir = fs::read_dir(&migrations_path).await
            .context("Failed to read migrations directory")?;

        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            
            let extension = path.extension().and_then(|s| s.to_str());
            let is_migration_file = match extension {
                Some("sql") => true,
                Some("js") if self.database_type == "mongodb" => true,
                _ => false,
            };
            
            if is_migration_file {
                if let Some(migration) = self.parse_migration_file(&path).await? {
                    migrations.push(migration);
                }
            }
        }

        // Sort by version
        migrations.sort_by_key(|m| m.version);
        
        info!("Loaded {} migrations for {}", migrations.len(), self.database_type);
        Ok(migrations)
    }

    async fn parse_migration_file(&self, path: &Path) -> Result<Option<Migration>> {
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .context("Invalid filename")?;

        // Parse version from filename (e.g., "001_initial_schema.sql")
        let parts: Vec<&str> = filename.split('_').collect();
        if parts.is_empty() {
            warn!("Skipping file with invalid format: {}", filename);
            return Ok(None);
        }

        let version: u32 = parts[0].parse()
            .context("Failed to parse migration version")?;

        let name = filename.trim_end_matches(".sql").to_string();
        
        let content = fs::read_to_string(path).await
            .context("Failed to read migration file")?;

        // Calculate checksum
        let checksum = format!("{:x}", md5::compute(&content));

        // Split up/down sections if present
        let (up_sql, down_sql) = self.parse_migration_content(&content);

        Ok(Some(Migration {
            version,
            name,
            description: self.extract_description(&content),
            up_sql: Some(up_sql),
            down_sql,
            checksum,
            applied_at: None,
        }))
    }

    fn parse_migration_content(&self, content: &str) -> (String, Option<String>) {
        // Look for -- DOWN or similar markers
        if let Some(down_pos) = content.find("-- DOWN") {
            let up_sql = content[..down_pos].trim().to_string();
            let down_sql = content[down_pos + 7..].trim().to_string();
            (up_sql, if down_sql.is_empty() { None } else { Some(down_sql) })
        } else {
            (content.trim().to_string(), None)
        }
    }

    fn extract_description(&self, content: &str) -> Option<String> {
        for line in content.lines().take(10) {
            if let Some(stripped) = line.strip_prefix("-- Description:") {
                return Some(stripped.trim().to_string());
            }
        }
        None
    }
}

#[derive(Debug)]
pub struct MigrationPlan {
    pub pending_migrations: Vec<Migration>,
    pub applied_migrations: Vec<MigrationRecord>,
    pub conflicts: Vec<String>,
}

impl Default for MigrationPlan {
    fn default() -> Self {
        Self::new()
    }
}

impl MigrationPlan {
    pub fn new() -> Self {
        Self {
            pending_migrations: Vec::new(),
            applied_migrations: Vec::new(),
            conflicts: Vec::new(),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.conflicts.is_empty()
    }

    pub fn has_pending(&self) -> bool {
        !self.pending_migrations.is_empty()
    }
}

pub fn calculate_migration_plan(
    all_migrations: Vec<Migration>,
    applied_migrations: Vec<MigrationRecord>,
) -> MigrationPlan {
    let mut plan = MigrationPlan::new();
    plan.applied_migrations = applied_migrations.clone();

    // Create a map of applied migrations for quick lookup
    let applied_map: HashMap<u32, &MigrationRecord> = applied_migrations
        .iter()
        .map(|m| (m.version, m))
        .collect();

    for migration in all_migrations {
        if let Some(applied) = applied_map.get(&migration.version) {
            // Check if checksums match
            if applied.checksum != migration.checksum {
                plan.conflicts.push(format!(
                    "Migration {} checksum mismatch. Expected: {}, Found: {}",
                    migration.version, applied.checksum, migration.checksum
                ));
            }
        } else {
            // Migration not applied yet
            plan.pending_migrations.push(migration);
        }
    }

    // Sort pending migrations by version
    plan.pending_migrations.sort_by_key(|m| m.version);

    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_migration_plan_empty() {
        let plan = calculate_migration_plan(vec![], vec![]);
        assert!(plan.is_valid());
        assert!(!plan.has_pending());
    }

    #[test]
    fn test_calculate_migration_plan_with_pending() {
        let migrations = vec![
            Migration {
                version: 1,
                name: "initial".to_string(),
                description: None,
                up_sql: Some("CREATE TABLE users".to_string()),
                down_sql: None,
                checksum: "abc123".to_string(),
                applied_at: None,
            }
        ];

        let plan = calculate_migration_plan(migrations, vec![]);
        assert!(plan.is_valid());
        assert!(plan.has_pending());
        assert_eq!(plan.pending_migrations.len(), 1);
    }

    #[test]
    fn test_calculate_migration_plan_with_conflict() {
        let migrations = vec![
            Migration {
                version: 1,
                name: "initial".to_string(),
                description: None,
                up_sql: Some("CREATE TABLE users".to_string()),
                down_sql: None,
                checksum: "abc123".to_string(),
                applied_at: None,
            }
        ];

        let applied = vec![
            MigrationRecord {
                version: 1,
                name: "initial".to_string(),
                checksum: "different".to_string(),
                applied_at: chrono::Utc::now(),
                execution_time_ms: 100,
            }
        ];

        let plan = calculate_migration_plan(migrations, applied);
        assert!(!plan.is_valid());
        assert_eq!(plan.conflicts.len(), 1);
    }
}