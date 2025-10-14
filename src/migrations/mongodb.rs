use super::{Migration, MigrationProvider, MigrationRecord};
use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::TryStreamExt;
use mongodb::{bson::{doc, Document}, Collection, Database};
use serde::{Deserialize, Serialize};
use tracing::{info, error};

#[derive(Debug, Serialize, Deserialize)]
struct MongoMigrationRecord {
    version: u32,
    name: String,
    checksum: String,
    applied_at: chrono::DateTime<chrono::Utc>,
    execution_time_ms: i64,
}

pub struct MongoDBMigrationProvider {
    database: Database,
    migrations_collection: Collection<MongoMigrationRecord>,
}

impl MongoDBMigrationProvider {
    pub fn new(database: Database) -> Self {
        let migrations_collection = database.collection::<MongoMigrationRecord>("schema_migrations");
        Self {
            database,
            migrations_collection,
        }
    }

    /// Execute JavaScript migration code
    async fn execute_js_migration(&self, js_code: &str) -> Result<()> {
        // For MongoDB, we'll use the eval command to execute JavaScript
        // Note: eval is deprecated in newer MongoDB versions, but still useful for migrations
        let command = doc! {
            "eval": js_code,
            "nolock": true
        };

        self.database
            .run_command(command, None)
            .await
            .context("Failed to execute JavaScript migration")?;

        Ok(())
    }

    /// Parse migration content to extract JavaScript code
    fn extract_js_code(&self, content: &str) -> String {
        // Remove SQL-style comments and extract JavaScript
        content
            .lines()
            .filter(|line| !line.trim().starts_with("--") && !line.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[async_trait]
impl MigrationProvider for MongoDBMigrationProvider {
    async fn init_migration_table(&self) -> Result<()> {
        info!("Initializing MongoDB migration collection...");

        // Create index on version field for faster queries
        let index_model = mongodb::IndexModel::builder()
            .keys(doc! { "version": 1 })
            .options(
                mongodb::options::IndexOptions::builder()
                    .unique(true)
                    .build()
            )
            .build();

        self.migrations_collection
            .create_index(index_model, None)
            .await
            .context("Failed to create migration collection index")?;

        // Create index on applied_at for sorting
        let applied_at_index = mongodb::IndexModel::builder()
            .keys(doc! { "applied_at": 1 })
            .build();

        self.migrations_collection
            .create_index(applied_at_index, None)
            .await
            .context("Failed to create applied_at index")?;

        info!("Migration collection initialized successfully");
        Ok(())
    }

    async fn get_applied_migrations(&self) -> Result<Vec<MigrationRecord>> {
        let cursor = self.migrations_collection
            .find(None, None)
            .await
            .context("Failed to query applied migrations")?;

        let mongo_records: Vec<MongoMigrationRecord> = cursor
            .try_collect()
            .await
            .context("Failed to collect migration records")?;

        let mut migrations: Vec<MigrationRecord> = mongo_records
            .into_iter()
            .map(|record| MigrationRecord {
                version: record.version,
                name: record.name,
                checksum: record.checksum,
                applied_at: record.applied_at,
                execution_time_ms: record.execution_time_ms,
            })
            .collect();

        // Sort by version
        migrations.sort_by_key(|m| m.version);

        Ok(migrations)
    }

    async fn record_migration(&self, migration: &Migration, execution_time_ms: i64) -> Result<()> {
        let record = MongoMigrationRecord {
            version: migration.version,
            name: migration.name.clone(),
            checksum: migration.checksum.clone(),
            applied_at: chrono::Utc::now(),
            execution_time_ms,
        };

        self.migrations_collection
            .insert_one(record, None)
            .await
            .context("Failed to record migration")?;

        Ok(())
    }

    async fn remove_migration_record(&self, version: u32) -> Result<()> {
        let filter = doc! { "version": version };
        
        let result = self.migrations_collection
            .delete_one(filter, None)
            .await
            .context("Failed to remove migration record")?;

        if result.deleted_count == 0 {
            return Err(anyhow::anyhow!("Migration record {} not found", version));
        }

        Ok(())
    }

    async fn execute_migration(&self, migration: &Migration) -> Result<()> {
        let sql = migration.up_sql.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Migration {} has no SQL", migration.version))?;

        // For MongoDB, the "SQL" is actually JavaScript code
        let js_code = self.extract_js_code(sql);
        
        if js_code.trim().is_empty() {
            info!("Migration {} has no JavaScript code to execute", migration.version);
            return Ok(());
        }

        // MongoDB migrations often involve creating collections, indexes, or data transformations
        self.execute_js_migration(&js_code).await?;

        Ok(())
    }

    async fn rollback_migration(&self, migration: &Migration) -> Result<()> {
        let sql = migration.down_sql.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Migration {} has no rollback SQL", migration.version))?;

        // For MongoDB, the rollback "SQL" is also JavaScript code
        let js_code = self.extract_js_code(sql);
        
        if js_code.trim().is_empty() {
            return Err(anyhow::anyhow!("Migration {} has no rollback JavaScript code", migration.version));
        }

        self.execute_js_migration(&js_code).await?;

        Ok(())
    }

    async fn ping(&self) -> Result<()> {
        // Simple ping using a basic operation
        self.database
            .run_command(doc! { "ping": 1 }, None)
            .await
            .context("Database ping failed")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::Client;

    #[tokio::test]
    #[ignore] // Requires MongoDB instance
    async fn test_mongodb_migration_provider() {
        let database_url = std::env::var("MONGODB_TEST_URL")
            .unwrap_or_else(|_| "mongodb://localhost:27017".to_string());

        let client = Client::with_uri_str(&database_url)
            .await
            .expect("Failed to connect to test database");

        let database = client.database("test_migrations");
        let provider = MongoDBMigrationProvider::new(database);

        // Test initialization
        provider.init_migration_table().await.unwrap();

        // Test getting applied migrations (should be empty)
        let applied = provider.get_applied_migrations().await.unwrap();
        assert!(applied.is_empty());

        // Test ping
        provider.ping().await.unwrap();
    }
}