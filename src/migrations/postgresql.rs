#![allow(dead_code)]

#[cfg(feature = "postgresql")]
use super::{Migration, MigrationProvider, MigrationRecord};
#[cfg(feature = "postgresql")]
use anyhow::{Context, Result};
#[cfg(feature = "postgresql")]
use async_trait::async_trait;
#[cfg(feature = "postgresql")]
use sqlx::{PgPool, Row};
#[cfg(feature = "postgresql")]
use tracing::info;

#[cfg(feature = "postgresql")]
pub struct PostgreSQLMigrationProvider {
    pool: PgPool,
}

#[cfg(feature = "postgresql")]
impl PostgreSQLMigrationProvider {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Smart SQL statement splitting that handles PostgreSQL functions and complex statements
    fn split_sql_statements(&self, sql: &str) -> Vec<String> {
        let mut statements = Vec::new();
        let mut current_statement = String::new();
        let mut in_function = false;
        let in_comment = false;
        let mut in_string = false;
        let mut string_char = '\0';
        
        let lines: Vec<&str> = sql.lines().collect();
        
        for line in lines {
            let trimmed = line.trim();
            
            // Skip comments
            if trimmed.starts_with("--") {
                continue;
            }
            
            // Check for function start/end
            if trimmed.to_lowercase().contains("create or replace function") 
                || trimmed.to_lowercase().contains("create function") {
                in_function = true;
            }
            
            for ch in line.chars() {
                if in_string {
                    current_statement.push(ch);
                    if ch == string_char {
                        in_string = false;
                    }
                    continue;
                }
                
                match ch {
                    '\'' | '"' => {
                        in_string = true;
                        string_char = ch;
                        current_statement.push(ch);
                    }
                    ';' => {
                        current_statement.push(ch);
                        if !in_function {
                            let stmt = current_statement.trim().to_string();
                            if !stmt.is_empty() && !stmt.starts_with("--") {
                                statements.push(stmt);
                            }
                            current_statement.clear();
                        }
                    }
                    _ => {
                        current_statement.push(ch);
                    }
                }
            }
            
            current_statement.push('\n');
            
            // Check for function end
            if in_function && trimmed == "$$ LANGUAGE plpgsql;" {
                in_function = false;
                let stmt = current_statement.trim().to_string();
                if !stmt.is_empty() {
                    statements.push(stmt);
                }
                current_statement.clear();
            }
        }
        
        // Add any remaining statement
        let remaining = current_statement.trim().to_string();
        if !remaining.is_empty() && !remaining.starts_with("--") {
            statements.push(remaining);
        }
        
        statements
    }
}

#[cfg(feature = "postgresql")]
#[async_trait]
impl MigrationProvider for PostgreSQLMigrationProvider {
    async fn init_migration_table(&self) -> Result<()> {
        let query = r#"
            CREATE TABLE IF NOT EXISTS _migrations (
                version INTEGER PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                checksum VARCHAR(32) NOT NULL,
                applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                execution_time_ms BIGINT NOT NULL
            );
            
            CREATE INDEX IF NOT EXISTS idx_migrations_applied_at ON _migrations(applied_at);
        "#;
        
        for statement in self.split_sql_statements(query) {
            sqlx::query(&statement)
                .execute(&self.pool)
                .await
                .context("Failed to create migration table")?;
        }
        
        info!("PostgreSQL migration table initialized");
        Ok(())
    }
    
    async fn get_applied_migrations(&self) -> Result<Vec<MigrationRecord>> {
        let rows = sqlx::query(
            "SELECT version, name, checksum, applied_at, execution_time_ms FROM _migrations ORDER BY version"
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch applied migrations")?;
        
        let mut migrations = Vec::new();
        for row in rows {
            migrations.push(MigrationRecord {
                version: row.get("version"),
                name: row.get("name"),
                checksum: row.get("checksum"),
                applied_at: row.get("applied_at"),
                execution_time_ms: row.get("execution_time_ms"),
            });
        }
        
        Ok(migrations)
    }
    
    async fn record_migration(&self, migration: &Migration, execution_time_ms: i64) -> Result<()> {
        sqlx::query(
            "INSERT INTO _migrations (version, name, checksum, execution_time_ms) VALUES ($1, $2, $3, $4)"
        )
        .bind(migration.version as i32)
        .bind(&migration.name)
        .bind(&migration.checksum)
        .bind(execution_time_ms)
        .execute(&self.pool)
        .await
        .context("Failed to record migration")?;
        
        info!("Recorded migration {} in PostgreSQL", migration.version);
        Ok(())
    }
    
    async fn remove_migration_record(&self, version: u32) -> Result<()> {
        sqlx::query("DELETE FROM _migrations WHERE version = $1")
            .bind(version as i32)
            .execute(&self.pool)
            .await
            .context("Failed to remove migration record")?;
        
        info!("Removed migration record {} from PostgreSQL", version);
        Ok(())
    }
    
    async fn execute_migration(&self, migration: &Migration) -> Result<()> {
        if let Some(ref sql) = migration.up_sql {
            for statement in self.split_sql_statements(sql) {
                if !statement.trim().is_empty() && !statement.trim().starts_with("--") {
                    sqlx::query(&statement)
                        .execute(&self.pool)
                        .await
                        .with_context(|| format!("Failed to execute migration {}: {}", migration.version, statement))?;
                }
            }
            info!("Executed PostgreSQL migration {}", migration.version);
        }
        Ok(())
    }
    
    async fn rollback_migration(&self, migration: &Migration) -> Result<()> {
        if let Some(ref sql) = migration.down_sql {
            for statement in self.split_sql_statements(sql) {
                if !statement.trim().is_empty() && !statement.trim().starts_with("--") {
                    sqlx::query(&statement)
                        .execute(&self.pool)
                        .await
                        .with_context(|| format!("Failed to rollback migration {}: {}", migration.version, statement))?;
                }
            }
            info!("Rolled back PostgreSQL migration {}", migration.version);
        } else {
            return Err(anyhow::anyhow!("No rollback SQL provided for migration {}", migration.version));
        }
        Ok(())
    }
    
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .context("PostgreSQL ping failed")?;
        Ok(())
    }
}

#[cfg(feature = "postgresql")]
pub async fn create_pool(config: &crate::config::database::DatabaseConfig) -> Result<PgPool> {
    use sqlx::postgres::PgPoolOptions;
    
    let pool = PgPoolOptions::new()
        .min_connections(config.pool.min_connections)
        .max_connections(config.pool.max_connections)
        .idle_timeout(std::time::Duration::from_secs(config.pool.idle_timeout))
        .connect(&config.url)
        .await
        .context("Failed to create PostgreSQL connection pool")?;
    
    info!("PostgreSQL connection pool created");
    Ok(pool)
}

// Provide empty implementations for when the feature is disabled
#[cfg(not(feature = "postgresql"))]
pub struct PostgreSQLMigrationProvider;

#[cfg(not(feature = "postgresql"))]
impl PostgreSQLMigrationProvider {
    pub fn new(_pool: ()) -> Self {
        Self
    }
}

#[cfg(not(feature = "postgresql"))]
pub async fn create_pool(_config: &crate::config::database::DatabaseConfig) -> Result<()> {
    Err(anyhow::anyhow!("PostgreSQL support not enabled"))
}