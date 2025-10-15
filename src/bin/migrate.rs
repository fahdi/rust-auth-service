use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Import from main crate
use rust_auth_service::{
    config::Config, 
    database, 
    migrations::{
        runner::MigrationRunner, 
        MigrationProvider,
        mongodb,
    }
};

#[cfg(feature = "postgresql")]
use rust_auth_service::migrations::postgresql;

#[cfg(feature = "mysql")]
use rust_auth_service::migrations::mysql;

#[derive(Parser)]
#[command(name = "migrate")]
#[command(about = "Database migration tool for Rust Auth Service")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to migrations directory
    #[arg(long, default_value = "migrations")]
    migrations_dir: String,

    /// Dry run - show what would be done without executing
    #[arg(long)]
    dry_run: bool,

    /// Force execution even if conflicts are detected
    #[arg(long)]
    force: bool,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run all pending migrations
    Up,
    /// Rollback the last N migrations
    Down {
        /// Number of migrations to rollback
        #[arg(default_value = "1")]
        steps: u32,
    },
    /// Show migration status
    Status,
    /// Validate all migrations
    Validate,
    /// Create a new migration file
    Create {
        /// Name of the migration
        name: String,
        /// Database type (postgresql, mysql, mongodb)
        #[arg(long)]
        database_type: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("migrate={},rust_auth_service=info", log_level).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Rust Auth Service Migration Tool v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = Config::from_env_and_file()
        .context("Failed to load configuration")?;

    // Create migration provider based on database type
    let migration_provider = create_migration_provider(&config).await?;

    // Create migration runner
    let runner = MigrationRunner::new(
        migration_provider,
        &cli.migrations_dir,
        &config.database.r#type,
    )
    .with_dry_run(cli.dry_run)
    .with_force(cli.force);

    // Execute command
    match cli.command {
        Commands::Up => {
            info!("Running migrations...");
            runner.migrate().await?;
        }
        Commands::Down { steps } => {
            info!("Rolling back {} migration(s)...", steps);
            runner.rollback(steps).await?;
        }
        Commands::Status => {
            runner.status().await?;
        }
        Commands::Validate => {
            runner.validate().await?;
        }
        Commands::Create { name, database_type } => {
            let db_type = database_type.unwrap_or_else(|| config.database.r#type.clone());
            create_migration_file(&cli.migrations_dir, &db_type, &name).await?;
        }
    }

    info!("Migration operation completed successfully!");
    Ok(())
}

async fn create_migration_provider(config: &Config) -> Result<Arc<dyn MigrationProvider>> {
    match config.database.r#type.as_str() {
        "postgresql" => {
            #[cfg(feature = "postgresql")]
            {
                let pool = database::create_pg_pool(&config.database).await?;
                Ok(Arc::new(postgresql::PostgreSQLMigrationProvider::new(pool)))
            }
            #[cfg(not(feature = "postgresql"))]
            {
                Err(anyhow::anyhow!("PostgreSQL support not enabled. Enable with --features postgresql"))
            }
        }
        "mysql" => {
            #[cfg(feature = "mysql")]
            {
                let pool = database::create_mysql_pool(&config.database).await?;
                Ok(Arc::new(mysql::MySQLMigrationProvider::new(pool)))
            }
            #[cfg(not(feature = "mysql"))]
            {
                Err(anyhow::anyhow!("MySQL support not enabled. Enable with --features mysql"))
            }
        }
        "mongodb" => {
            let database = database::create_mongo_database(&config.database).await?;
            Ok(Arc::new(mongodb::MongoDBMigrationProvider::new(database)))
        }
        _ => Err(anyhow::anyhow!(
            "Unsupported database type: {}. Available types: mongodb{}{}",
            config.database.r#type,
            if cfg!(feature = "postgresql") { ", postgresql" } else { "" },
            if cfg!(feature = "mysql") { ", mysql" } else { "" }
        )),
    }
}

async fn create_migration_file(
    migrations_dir: &str,
    database_type: &str,
    name: &str,
) -> Result<()> {
    use std::path::Path;
    use tokio::fs;

    let migrations_path = Path::new(migrations_dir).join(database_type);
    
    // Ensure directory exists
    fs::create_dir_all(&migrations_path).await
        .context("Failed to create migrations directory")?;

    // Find next version number
    let mut version = 1;
    if migrations_path.exists() {
        let mut dir = fs::read_dir(&migrations_path).await?;
        while let Some(entry) = dir.next_entry().await? {
            let filename = entry.file_name();
            let filename_str = filename.to_string_lossy();
            
            if let Some(v) = filename_str.split('_').next().and_then(|s| s.parse::<u32>().ok()) {
                if v >= version {
                    version = v + 1;
                }
            }
        }
    }

    // Create filename
    let filename = format!("{:03}_{}.sql", version, name.replace(' ', "_").to_lowercase());
    let filepath = migrations_path.join(&filename);

    // Generate template based on database type
    let template = match database_type {
        "postgresql" => generate_postgresql_template(name),
        "mysql" => generate_mysql_template(name),
        "mongodb" => generate_mongodb_template(name),
        _ => return Err(anyhow::anyhow!("Unsupported database type: {}", database_type)),
    };

    // Write file
    fs::write(&filepath, template).await
        .context("Failed to write migration file")?;

    info!("Created migration file: {}", filepath.display());
    Ok(())
}

fn generate_postgresql_template(name: &str) -> String {
    format!(
        r#"-- Description: {}
-- Created: {}

-- Create your PostgreSQL migration here
-- Example:
-- CREATE TABLE IF NOT EXISTS example_table (
--     id SERIAL PRIMARY KEY,
--     name VARCHAR(255) NOT NULL,
--     created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
-- );

-- CREATE INDEX IF NOT EXISTS idx_example_name ON example_table(name);

-- DOWN
-- Add rollback statements here (optional)
-- DROP INDEX IF EXISTS idx_example_name;
-- DROP TABLE IF EXISTS example_table;
"#,
        name,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    )
}

fn generate_mysql_template(name: &str) -> String {
    format!(
        r#"-- Description: {}
-- Created: {}

-- Create your MySQL migration here
-- Example:
-- CREATE TABLE IF NOT EXISTS example_table (
--     id INT AUTO_INCREMENT PRIMARY KEY,
--     name VARCHAR(255) NOT NULL,
--     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
--     
--     INDEX idx_example_name (name)
-- ) ENGINE=InnoDB CHARACTER SET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- DOWN
-- Add rollback statements here (optional)
-- DROP TABLE IF EXISTS example_table;
"#,
        name,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    )
}

fn generate_mongodb_template(name: &str) -> String {
    format!(
        r#"-- Description: {}
-- Created: {}

// Create your MongoDB migration here (JavaScript)
// Example:
// db.createCollection("example_collection", {{
//     validator: {{
//         $jsonSchema: {{
//             bsonType: "object",
//             required: ["name"],
//             properties: {{
//                 name: {{
//                     bsonType: "string",
//                     description: "must be a string and is required"
//                 }},
//                 created_at: {{
//                     bsonType: "date",
//                     description: "must be a date"
//                 }}
//             }}
//         }}
//     }}
// }});

// db.example_collection.createIndex({{ "name": 1 }});

// DOWN
// Add rollback JavaScript here (optional)
// db.example_collection.drop();
"#,
        name,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    )
}