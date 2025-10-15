#![allow(dead_code)]

#[cfg(feature = "mysql")]
use super::{Migration, MigrationProvider, MigrationRecord};
#[cfg(feature = "mysql")]
use anyhow::{Context, Result};
#[cfg(feature = "mysql")]
use async_trait::async_trait;
#[cfg(feature = "mysql")]
use sqlx::{MySqlPool, Row};
#[cfg(feature = "mysql")]
use tracing::info;

#[cfg(feature = "mysql")]
pub struct MySQLMigrationProvider {
    pool: MySqlPool,
}

#[cfg(feature = "mysql")]
impl MySQLMigrationProvider {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }

    /// Split SQL statements handling MySQL-specific syntax
    fn split_sql_statements(&self, sql: &str) -> Vec<String> {
        let mut statements = Vec::new();
        let mut current_statement = String::new();
        let mut in_string = false;
        let mut string_char = '\0';
        let mut in_delimiter_block = false;

        let lines: Vec<&str> = sql.lines().collect();

        for line in lines {
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("--") || trimmed.starts_with("#") {
                continue;
            }

            // Handle DELIMITER statements
            if trimmed.to_uppercase().starts_with("DELIMITER ") {
                in_delimiter_block = true;
                continue;
            }

            if in_delimiter_block && trimmed == "//" {
                in_delimiter_block = false;
                let stmt = current_statement.trim().to_string();
                if !stmt.is_empty() {
                    statements.push(stmt);
                }
                current_statement.clear();
                continue;
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
                    '\'' | '"' | '`' => {
                        in_string = true;
                        string_char = ch;
                        current_statement.push(ch);
                    }
                    ';' => {
                        current_statement.push(ch);
                        if !in_delimiter_block {
                            let stmt = current_statement.trim().to_string();
                            if !stmt.is_empty() && !stmt.starts_with("--") && !stmt.starts_with("#")
                            {
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
        }

        // Add any remaining statement
        let remaining = current_statement.trim().to_string();
        if !remaining.is_empty() && !remaining.starts_with("--") && !remaining.starts_with("#") {
            statements.push(remaining);
        }

        statements
    }
}

#[cfg(feature = "mysql")]
#[async_trait]
impl MigrationProvider for MySQLMigrationProvider {
    async fn init_migration_table(&self) -> Result<()> {
        let query = r#"
            CREATE TABLE IF NOT EXISTS _migrations (
                version INT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                checksum VARCHAR(32) NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                execution_time_ms BIGINT NOT NULL,
                
                INDEX idx_migrations_applied_at (applied_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        "#;

        for statement in self.split_sql_statements(query) {
            sqlx::query(&statement)
                .execute(&self.pool)
                .await
                .context("Failed to create migration table")?;
        }

        info!("MySQL migration table initialized");
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
            // MySQL TIMESTAMP is returned as NaiveDateTime, need to convert to UTC
            let applied_at: chrono::NaiveDateTime = row.get("applied_at");
            let applied_at_utc =
                chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(applied_at, chrono::Utc);

            migrations.push(MigrationRecord {
                version: row.get::<i32, _>("version") as u32,
                name: row.get("name"),
                checksum: row.get("checksum"),
                applied_at: applied_at_utc,
                execution_time_ms: row.get("execution_time_ms"),
            });
        }

        Ok(migrations)
    }

    async fn record_migration(&self, migration: &Migration, execution_time_ms: i64) -> Result<()> {
        sqlx::query(
            "INSERT INTO _migrations (version, name, checksum, execution_time_ms) VALUES (?, ?, ?, ?)"
        )
        .bind(migration.version as i32)
        .bind(&migration.name)
        .bind(&migration.checksum)
        .bind(execution_time_ms)
        .execute(&self.pool)
        .await
        .context("Failed to record migration")?;

        info!("Recorded migration {} in MySQL", migration.version);
        Ok(())
    }

    async fn remove_migration_record(&self, version: u32) -> Result<()> {
        sqlx::query("DELETE FROM _migrations WHERE version = ?")
            .bind(version as i32)
            .execute(&self.pool)
            .await
            .context("Failed to remove migration record")?;

        info!("Removed migration record {} from MySQL", version);
        Ok(())
    }

    async fn execute_migration(&self, migration: &Migration) -> Result<()> {
        if let Some(ref sql) = migration.up_sql {
            for statement in self.split_sql_statements(sql) {
                if !statement.trim().is_empty()
                    && !statement.trim().starts_with("--")
                    && !statement.trim().starts_with("#")
                {
                    sqlx::query(&statement)
                        .execute(&self.pool)
                        .await
                        .with_context(|| {
                            format!(
                                "Failed to execute migration {}: {}",
                                migration.version, statement
                            )
                        })?;
                }
            }
            info!("Executed MySQL migration {}", migration.version);
        }
        Ok(())
    }

    async fn rollback_migration(&self, migration: &Migration) -> Result<()> {
        if let Some(ref sql) = migration.down_sql {
            for statement in self.split_sql_statements(sql) {
                if !statement.trim().is_empty()
                    && !statement.trim().starts_with("--")
                    && !statement.trim().starts_with("#")
                {
                    sqlx::query(&statement)
                        .execute(&self.pool)
                        .await
                        .with_context(|| {
                            format!(
                                "Failed to rollback migration {}: {}",
                                migration.version, statement
                            )
                        })?;
                }
            }
            info!("Rolled back MySQL migration {}", migration.version);
        } else {
            return Err(anyhow::anyhow!(
                "No rollback SQL provided for migration {}",
                migration.version
            ));
        }
        Ok(())
    }

    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .context("MySQL ping failed")?;
        Ok(())
    }
}

#[cfg(feature = "mysql")]
pub async fn create_pool(config: &crate::config::database::DatabaseConfig) -> Result<MySqlPool> {
    use sqlx::mysql::MySqlPoolOptions;

    let pool = MySqlPoolOptions::new()
        .min_connections(config.pool.min_connections)
        .max_connections(config.pool.max_connections)
        .idle_timeout(std::time::Duration::from_secs(config.pool.idle_timeout))
        .connect(&config.url)
        .await
        .context("Failed to create MySQL connection pool")?;

    info!("MySQL connection pool created");
    Ok(pool)
}

// Provide empty implementations for when the feature is disabled
#[cfg(not(feature = "mysql"))]
pub struct MySQLMigrationProvider;

#[cfg(not(feature = "mysql"))]
impl MySQLMigrationProvider {
    pub fn new(_pool: ()) -> Self {
        Self
    }
}

#[cfg(not(feature = "mysql"))]
pub async fn create_pool(_config: &crate::config::database::DatabaseConfig) -> Result<()> {
    Err(anyhow::anyhow!("MySQL support not enabled"))
}
