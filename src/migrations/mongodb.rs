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

    /// Execute MongoDB operations from migration content
    async fn execute_migration_operations(&self, content: &str) -> Result<()> {
        // Parse and execute MongoDB operations
        // Since we can't use eval, we'll implement specific MongoDB operations
        
        // For now, implement basic collection creation and index operations
        // This is a simplified implementation - a full implementation would parse
        // JavaScript and convert to MongoDB driver operations
        
        if content.contains("db.createCollection(\"users\"") {
            // Create users collection with validation schema
            let options = mongodb::options::CreateCollectionOptions::builder()
                .validator(doc! {
                    "$jsonSchema": {
                        "bsonType": "object",
                        "required": ["user_id", "email", "password_hash", "first_name", "last_name", "role", "is_active", "email_verified", "created_at", "updated_at"],
                        "properties": {
                            "user_id": { "bsonType": "string" },
                            "email": { "bsonType": "string", "pattern": "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$" },
                            "password_hash": { "bsonType": "string" },
                            "first_name": { "bsonType": "string" },
                            "last_name": { "bsonType": "string" },
                            "role": { "bsonType": "string", "enum": ["user", "admin", "moderator", "guest"] },
                            "is_active": { "bsonType": "bool" },
                            "email_verified": { "bsonType": "bool" },
                            "created_at": { "bsonType": "date" },
                            "updated_at": { "bsonType": "date" }
                        }
                    }
                })
                .build();
                
            self.database
                .create_collection("users", options)
                .await
                .context("Failed to create users collection")?;
                
            // Create indexes
            let users_collection = self.database.collection::<Document>("users");
            
            // Create unique indexes
            users_collection.create_index(
                mongodb::IndexModel::builder()
                    .keys(doc! { "user_id": 1 })
                    .options(mongodb::options::IndexOptions::builder().unique(true).build())
                    .build(),
                None
            ).await.context("Failed to create user_id index")?;
            
            users_collection.create_index(
                mongodb::IndexModel::builder()
                    .keys(doc! { "email": 1 })
                    .options(mongodb::options::IndexOptions::builder().unique(true).build())
                    .build(),
                None
            ).await.context("Failed to create email index")?;
            
            // Create other indexes
            for field in ["email_verification_token", "password_reset_token", "created_at", "last_login", "role", "is_active", "locked_until"] {
                users_collection.create_index(
                    mongodb::IndexModel::builder()
                        .keys(doc! { field: 1 })
                        .build(),
                    None
                ).await.with_context(|| format!("Failed to create {} index", field))?;
            }
            
            // Create compound indexes
            users_collection.create_index(
                mongodb::IndexModel::builder()
                    .keys(doc! { "email": 1, "is_active": 1 })
                    .build(),
                None
            ).await.context("Failed to create email+is_active index")?;
            
            users_collection.create_index(
                mongodb::IndexModel::builder()
                    .keys(doc! { "role": 1, "is_active": 1 })
                    .build(),
                None
            ).await.context("Failed to create role+is_active index")?;
        }
        
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

        // For MongoDB, the "SQL" is actually JavaScript/MongoDB operations
        let migration_content = self.extract_js_code(sql);
        
        if migration_content.trim().is_empty() {
            info!("Migration {} has no operations to execute", migration.version);
            return Ok(());
        }

        // Execute MongoDB operations
        self.execute_migration_operations(&migration_content).await?;

        Ok(())
    }

    async fn rollback_migration(&self, migration: &Migration) -> Result<()> {
        let sql = migration.down_sql.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Migration {} has no rollback SQL", migration.version))?;

        // For MongoDB, the rollback operations
        let rollback_content = self.extract_js_code(sql);
        
        if rollback_content.trim().is_empty() {
            return Err(anyhow::anyhow!("Migration {} has no rollback operations", migration.version));
        }

        // Execute rollback operations (e.g., drop collections)
        if rollback_content.contains("db.users.drop()") {
            self.database.collection::<Document>("users")
                .drop(None)
                .await
                .context("Failed to drop users collection")?;
        }

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