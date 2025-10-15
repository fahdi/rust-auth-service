#![allow(dead_code)]

use super::{Migration, MigrationProvider, MigrationRecord};
use anyhow::{Context, Result};
use async_trait::async_trait;
use sqlx::{MySqlPool, Row};
use tracing::info;

pub struct MySQLMigrationProvider {
    pool: MySqlPool,
}

impl MySQLMigrationProvider {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }

    /// Smart SQL statement splitting that handles MySQL-specific syntax
    fn split_sql_statements(&self, sql: &str) -> Vec<String> {
        let mut statements = Vec::new();
        let mut current_statement = String::new();
        let mut in_delimiter_block = false;
        let mut in_event_block = false;
        let mut delimiter = ";".to_string();
        
        let lines: Vec<&str> = sql.lines().collect();
        
        for line in lines {
            let trimmed = line.trim();
            
            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with("--") {
                continue;
            }
            
            // Handle DELIMITER statements
            if trimmed.to_uppercase().starts_with("DELIMITER") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    delimiter = parts[1].to_string();
                    in_delimiter_block = delimiter != ";";
                }
                continue;
            }
            
            // Detect event blocks
            if trimmed.to_uppercase().contains("CREATE EVENT") {
                in_event_block = true;
            }
            
            current_statement.push_str(line);
            current_statement.push('\n');
            
            // Check if we should end the current statement
            let should_end = if in_delimiter_block || in_event_block {
                // End when we see the custom delimiter
                trimmed.ends_with(&delimiter)
            } else {
                // Regular statement ends with semicolon
                trimmed.ends_with(';')
            };
            
            if should_end {
                let mut stmt = current_statement.trim().to_string();
                
                // Remove custom delimiter from the end of the statement
                if in_delimiter_block && stmt.ends_with(&delimiter) && delimiter != ";" {
                    let delimiter_len = delimiter.len();
                    if stmt.len() >= delimiter_len {
                        stmt = stmt[..stmt.len() - delimiter_len].trim().to_string();
                    }
                }
                
                if !stmt.is_empty() {
                    statements.push(stmt);
                }
                current_statement.clear();
                
                // Reset delimiter block if we finished with custom delimiter
                if in_delimiter_block && trimmed.ends_with(&delimiter) {
                    in_delimiter_block = false;
                    delimiter = ";".to_string();
                }
                
                if in_event_block && trimmed.ends_with(&delimiter) {
                    in_event_block = false;
                }
            }
        }
        
        // Handle any remaining statement
        let stmt = current_statement.trim().to_string();
        if !stmt.is_empty() {
            statements.push(stmt);
        }
        
        statements
    }
}

#[async_trait]
impl MigrationProvider for MySQLMigrationProvider {
    async fn init_migration_table(&self) -> Result<()> {
        info!("Initializing MySQL migration table...");

        let query = r#"
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                checksum CHAR(32) NOT NULL,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                execution_time_ms BIGINT NOT NULL,
                
                INDEX idx_schema_migrations_applied_at (applied_at)
            ) ENGINE=InnoDB CHARACTER SET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        "#;

        sqlx::query(query)
            .execute(&self.pool)
            .await
            .context("Failed to create migration table")?;

        info!("Migration table initialized successfully");
        Ok(())
    }

    async fn get_applied_migrations(&self) -> Result<Vec<MigrationRecord>> {
        let query = r#"
            SELECT version, name, checksum, applied_at, execution_time_ms
            FROM schema_migrations
            ORDER BY version ASC
        "#;

        let rows = sqlx::query(query)
            .fetch_all(&self.pool)
            .await
            .context("Failed to fetch applied migrations")?;

        let mut migrations = Vec::new();
        for row in rows {
            // MySQL TIMESTAMP is stored as UTC but returned as local time
            // We need to handle this conversion properly
            let applied_at: chrono::DateTime<chrono::Utc> = row.get("applied_at");

            migrations.push(MigrationRecord {
                version: row.get::<i32, _>("version") as u32,
                name: row.get("name"),
                checksum: row.get("checksum"),
                applied_at,
                execution_time_ms: row.get("execution_time_ms"),
            });
        }

        Ok(migrations)
    }

    async fn record_migration(&self, migration: &Migration, execution_time_ms: i64) -> Result<()> {
        let query = r#"
            INSERT INTO schema_migrations (version, name, checksum, execution_time_ms)
            VALUES (?, ?, ?, ?)
        "#;

        sqlx::query(query)
            .bind(migration.version as i32)
            .bind(&migration.name)
            .bind(&migration.checksum)
            .bind(execution_time_ms)
            .execute(&self.pool)
            .await
            .context("Failed to record migration")?;

        Ok(())
    }

    async fn remove_migration_record(&self, version: u32) -> Result<()> {
        let query = "DELETE FROM schema_migrations WHERE version = ?";

        let result = sqlx::query(query)
            .bind(version as i32)
            .execute(&self.pool)
            .await
            .context("Failed to remove migration record")?;

        if result.rows_affected() == 0 {
            return Err(anyhow::anyhow!("Migration record {} not found", version));
        }

        Ok(())
    }

    async fn execute_migration(&self, migration: &Migration) -> Result<()> {
        let sql = migration.up_sql.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Migration {} has no SQL", migration.version))?;

        // Begin transaction for migration
        let mut tx = self.pool.begin()
            .await
            .context("Failed to begin transaction")?;

        // Use smart SQL parsing to handle MySQL-specific syntax
        let statements = self.split_sql_statements(sql);

        for statement in statements {
            if statement.trim().is_empty() {
                continue;
            }

            sqlx::query(&statement)
                .execute(&mut *tx)
                .await
                .with_context(|| format!("Failed to execute statement: {}", statement))?;
        }

        tx.commit()
            .await
            .context("Failed to commit migration transaction")?;

        Ok(())
    }

    async fn rollback_migration(&self, migration: &Migration) -> Result<()> {
        let sql = migration.down_sql.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Migration {} has no rollback SQL", migration.version))?;

        // Begin transaction for rollback
        let mut tx = self.pool.begin()
            .await
            .context("Failed to begin transaction")?;

        // Use smart SQL parsing to handle MySQL-specific syntax
        let statements = self.split_sql_statements(sql);

        for statement in statements {
            if statement.trim().is_empty() {
                continue;
            }

            sqlx::query(&statement)
                .execute(&mut *tx)
                .await
                .with_context(|| format!("Failed to execute rollback statement: {}", statement))?;
        }

        tx.commit()
            .await
            .context("Failed to commit rollback transaction")?;

        Ok(())
    }

    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .context("Database ping failed")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::mysql::MySqlPoolOptions;

    #[tokio::test]
    #[ignore] // Requires MySQL instance
    async fn test_mysql_migration_provider() {
        let database_url = std::env::var("MYSQL_TEST_URL")
            .unwrap_or_else(|_| "mysql://root:password@localhost:3306/test".to_string());

        let pool = MySqlPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("Failed to connect to test database");

        let provider = MySQLMigrationProvider::new(pool);

        // Test initialization
        provider.init_migration_table().await.unwrap();

        // Test getting applied migrations (should be empty)
        let applied = provider.get_applied_migrations().await.unwrap();
        assert!(applied.is_empty());

        // Test ping
        provider.ping().await.unwrap();
    }
}