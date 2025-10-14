use super::{Migration, MigrationProvider, MigrationRecord};
use anyhow::{Context, Result};
use async_trait::async_trait;
use sqlx::{MySqlPool, Row};
use tracing::{info, error};

pub struct MySQLMigrationProvider {
    pool: MySqlPool,
}

impl MySQLMigrationProvider {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
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
            let applied_at: chrono::NaiveDateTime = row.get("applied_at");
            let applied_at_utc = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
                applied_at, chrono::Utc
            );

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

        // MySQL doesn't support multi-statement transactions in the same way
        // We need to execute statements one by one
        let statements: Vec<&str> = sql.split(';')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && !s.starts_with("--"))
            .collect();

        for statement in statements {
            if statement.trim().is_empty() {
                continue;
            }

            sqlx::query(statement)
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

        // Split SQL by semicolons and execute each statement
        let statements: Vec<&str> = sql.split(';')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && !s.starts_with("--"))
            .collect();

        for statement in statements {
            if statement.trim().is_empty() {
                continue;
            }

            sqlx::query(statement)
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