use super::{Migration, MigrationProvider, MigrationRecord};
use anyhow::{Context, Result};
use async_trait::async_trait;
use sqlx::{PgPool, Row};
use tracing::{info, error};

pub struct PostgreSQLMigrationProvider {
    pool: PgPool,
}

impl PostgreSQLMigrationProvider {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Smart SQL statement splitting that handles PostgreSQL functions and complex statements
    fn split_sql_statements(&self, sql: &str) -> Vec<String> {
        let mut statements = Vec::new();
        let mut current_statement = String::new();
        let mut in_function = false;
        let mut paren_count = 0;
        let mut in_comment = false;
        let mut in_string = false;
        let mut string_char = '\0';
        
        let lines: Vec<&str> = sql.lines().collect();
        
        for line in lines {
            let trimmed = line.trim();
            
            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with("--") {
                continue;
            }
            
            // Detect function blocks
            if trimmed.to_lowercase().contains("create or replace function") || 
               trimmed.to_lowercase().contains("create function") {
                in_function = true;
            }
            
            current_statement.push_str(line);
            current_statement.push('\n');
            
            // Count parentheses and detect end of function
            for ch in line.chars() {
                match ch {
                    '\'' | '"' if !in_comment => {
                        if !in_string {
                            in_string = true;
                            string_char = ch;
                        } else if ch == string_char {
                            in_string = false;
                        }
                    }
                    '(' if !in_string && !in_comment => paren_count += 1,
                    ')' if !in_string && !in_comment => paren_count -= 1,
                    _ => {}
                }
            }
            
            // Check if we should end the current statement
            let should_end = if in_function {
                // End function when we see $$ language plpgsql; or similar
                trimmed.to_lowercase().contains("$$ language") || 
                trimmed.to_lowercase().ends_with("language plpgsql;")
            } else {
                // Regular statement ends with semicolon
                trimmed.ends_with(';')
            };
            
            if should_end {
                let stmt = current_statement.trim().to_string();
                if !stmt.is_empty() {
                    statements.push(stmt);
                }
                current_statement.clear();
                in_function = false;
                paren_count = 0;
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
impl MigrationProvider for PostgreSQLMigrationProvider {
    async fn init_migration_table(&self) -> Result<()> {
        info!("Initializing PostgreSQL migration table...");

        // Create table
        let create_table_query = r#"
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                checksum VARCHAR(32) NOT NULL,
                applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                execution_time_ms BIGINT NOT NULL
            )
        "#;

        sqlx::query(create_table_query)
            .execute(&self.pool)
            .await
            .context("Failed to create migration table")?;

        // Create index
        let create_index_query = r#"
            CREATE INDEX IF NOT EXISTS idx_schema_migrations_applied_at 
            ON schema_migrations(applied_at)
        "#;

        sqlx::query(create_index_query)
            .execute(&self.pool)
            .await
            .context("Failed to create migration index")?;

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
            migrations.push(MigrationRecord {
                version: row.get::<i32, _>("version") as u32,
                name: row.get("name"),
                checksum: row.get("checksum"),
                applied_at: row.get("applied_at"),
                execution_time_ms: row.get("execution_time_ms"),
            });
        }

        Ok(migrations)
    }

    async fn record_migration(&self, migration: &Migration, execution_time_ms: i64) -> Result<()> {
        let query = r#"
            INSERT INTO schema_migrations (version, name, checksum, execution_time_ms)
            VALUES ($1, $2, $3, $4)
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
        let query = "DELETE FROM schema_migrations WHERE version = $1";

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

        // Split SQL into statements and execute each one
        // We need to be smarter about splitting - handle CREATE FUNCTION blocks properly
        let statements = self.split_sql_statements(sql);
        
        for statement in statements {
            if statement.trim().is_empty() {
                continue;
            }

            sqlx::query(&statement)
                .execute(&mut *tx)
                .await
                .with_context(|| format!("Failed to execute statement: {}", statement.chars().take(100).collect::<String>()))?;
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

        // Split and execute rollback statements
        let statements = self.split_sql_statements(sql);
        
        for statement in statements {
            if statement.trim().is_empty() {
                continue;
            }

            sqlx::query(&statement)
                .execute(&mut *tx)
                .await
                .with_context(|| format!("Failed to execute rollback statement: {}", statement.chars().take(100).collect::<String>()))?;
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
    use sqlx::postgres::PgPoolOptions;

    #[tokio::test]
    #[ignore] // Requires PostgreSQL instance
    async fn test_postgresql_migration_provider() {
        let database_url = std::env::var("POSTGRESQL_TEST_URL")
            .unwrap_or_else(|_| "postgresql://postgres:password@localhost:5432/test".to_string());

        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("Failed to connect to test database");

        let provider = PostgreSQLMigrationProvider::new(pool);

        // Test initialization
        provider.init_migration_table().await.unwrap();

        // Test getting applied migrations (should be empty)
        let applied = provider.get_applied_migrations().await.unwrap();
        assert!(applied.is_empty());

        // Test ping
        provider.ping().await.unwrap();
    }
}