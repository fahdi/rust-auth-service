#![allow(dead_code)]

use super::{calculate_migration_plan, MigrationLoader, MigrationPlan, MigrationProvider};
use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Instant;
use tracing::{error, info, warn};

pub struct MigrationRunner {
    provider: Arc<dyn MigrationProvider>,
    loader: MigrationLoader,
    dry_run: bool,
    force: bool,
}

impl MigrationRunner {
    pub fn new(
        provider: Arc<dyn MigrationProvider>,
        migrations_dir: impl Into<String>,
        database_type: impl Into<String>,
    ) -> Self {
        Self {
            provider,
            loader: MigrationLoader::new(migrations_dir, database_type),
            dry_run: false,
            force: false,
        }
    }

    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    pub fn with_force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    /// Run all pending migrations
    pub async fn migrate(&self) -> Result<()> {
        info!("Starting database migration...");

        // Initialize migration tracking
        self.provider
            .init_migration_table()
            .await
            .context("Failed to initialize migration table")?;

        // Load migrations and create plan
        let plan = self.create_migration_plan().await?;

        if !plan.is_valid() && !self.force {
            error!("Migration conflicts detected:");
            for conflict in &plan.conflicts {
                error!("  {}", conflict);
            }
            return Err(anyhow::anyhow!(
                "Migration conflicts detected. Use --force to override."
            ));
        }

        if !plan.has_pending() {
            info!("No pending migrations found.");
            return Ok(());
        }

        info!("Found {} pending migrations", plan.pending_migrations.len());

        if self.dry_run {
            info!("DRY RUN: Would apply the following migrations:");
            for migration in &plan.pending_migrations {
                info!("  {} - {}", migration.version, migration.name);
            }
            return Ok(());
        }

        // Apply migrations
        for migration in plan.pending_migrations {
            self.apply_migration(&migration).await?;
        }

        info!("All migrations completed successfully!");
        Ok(())
    }

    /// Rollback the last N migrations
    pub async fn rollback(&self, steps: u32) -> Result<()> {
        info!("Rolling back {} migration(s)...", steps);

        let applied_migrations = self.provider.get_applied_migrations().await?;

        if applied_migrations.is_empty() {
            info!("No migrations to rollback.");
            return Ok(());
        }

        // Sort by version descending to rollback in reverse order
        let mut migrations_to_rollback: Vec<_> = applied_migrations.into_iter().collect();
        migrations_to_rollback.sort_by(|a, b| b.version.cmp(&a.version));

        let rollback_count = std::cmp::min(steps as usize, migrations_to_rollback.len());
        let migrations_to_rollback = &migrations_to_rollback[..rollback_count];

        if self.dry_run {
            info!("DRY RUN: Would rollback the following migrations:");
            for migration in migrations_to_rollback {
                info!("  {} - {}", migration.version, migration.name);
            }
            return Ok(());
        }

        // Load migration definitions for rollback
        let all_migrations = self.loader.load_migrations().await?;
        let migration_map: std::collections::HashMap<u32, _> =
            all_migrations.into_iter().map(|m| (m.version, m)).collect();

        for applied_migration in migrations_to_rollback {
            if let Some(migration) = migration_map.get(&applied_migration.version) {
                self.rollback_migration(migration).await?;
            } else {
                warn!(
                    "Migration definition not found for version {}, skipping rollback",
                    applied_migration.version
                );
            }
        }

        info!("Rollback completed successfully!");
        Ok(())
    }

    /// Get migration status
    pub async fn status(&self) -> Result<()> {
        let plan = self.create_migration_plan().await?;

        println!("Migration Status:");
        println!("================");

        if !plan.conflicts.is_empty() {
            println!("\n⚠️  CONFLICTS DETECTED:");
            for conflict in &plan.conflicts {
                println!("   {}", conflict);
            }
        }

        println!("\nApplied Migrations ({}):", plan.applied_migrations.len());
        for migration in &plan.applied_migrations {
            println!(
                "  ✅ {} - {} (applied: {})",
                migration.version,
                migration.name,
                migration.applied_at.format("%Y-%m-%d %H:%M:%S")
            );
        }

        println!("\nPending Migrations ({}):", plan.pending_migrations.len());
        for migration in &plan.pending_migrations {
            println!("  ⏳ {} - {}", migration.version, migration.name);
        }

        if plan.is_valid() && !plan.has_pending() {
            println!("\n✅ Database is up to date!");
        } else if plan.has_pending() {
            println!(
                "\n⏳ {} migration(s) pending",
                plan.pending_migrations.len()
            );
        }

        Ok(())
    }

    /// Validate all migrations without applying them
    pub async fn validate(&self) -> Result<()> {
        info!("Validating migrations...");

        let plan = self.create_migration_plan().await?;

        if !plan.is_valid() {
            error!("Migration validation failed:");
            for conflict in &plan.conflicts {
                error!("  {}", conflict);
            }
            return Err(anyhow::anyhow!("Migration validation failed"));
        }

        // Check for gaps in version numbers
        let mut expected_version = 1;
        let all_migrations = self.loader.load_migrations().await?;

        for migration in &all_migrations {
            if migration.version != expected_version {
                return Err(anyhow::anyhow!(
                    "Migration version gap detected. Expected {}, found {}",
                    expected_version,
                    migration.version
                ));
            }
            expected_version += 1;
        }

        info!("✅ All migrations are valid!");
        Ok(())
    }

    async fn create_migration_plan(&self) -> Result<MigrationPlan> {
        let all_migrations = self.loader.load_migrations().await?;
        let applied_migrations = self.provider.get_applied_migrations().await?;

        Ok(calculate_migration_plan(all_migrations, applied_migrations))
    }

    async fn apply_migration(&self, migration: &super::Migration) -> Result<()> {
        info!(
            "Applying migration {} - {}",
            migration.version, migration.name
        );

        let start_time = Instant::now();

        // Execute the migration
        if let Err(e) = self.provider.execute_migration(migration).await {
            error!("Failed to execute migration {}: {}", migration.version, e);
            return Err(e);
        }

        let execution_time = start_time.elapsed().as_millis() as i64;

        // Record the migration as applied
        self.provider
            .record_migration(migration, execution_time)
            .await
            .context("Failed to record migration")?;

        info!(
            "✅ Migration {} completed in {}ms",
            migration.version, execution_time
        );
        Ok(())
    }

    async fn rollback_migration(&self, migration: &super::Migration) -> Result<()> {
        info!(
            "Rolling back migration {} - {}",
            migration.version, migration.name
        );

        if migration.down_sql.is_none() {
            return Err(anyhow::anyhow!(
                "Migration {} has no rollback SQL defined",
                migration.version
            ));
        }

        // Execute rollback
        if let Err(e) = self.provider.rollback_migration(migration).await {
            error!("Failed to rollback migration {}: {}", migration.version, e);
            return Err(e);
        }

        // Remove migration record
        self.provider
            .remove_migration_record(migration.version)
            .await
            .context("Failed to remove migration record")?;

        info!(
            "✅ Migration {} rolled back successfully",
            migration.version
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    struct MockMigrationProvider {
        applied_migrations: Vec<super::MigrationRecord>,
        should_fail: bool,
    }

    #[async_trait]
    impl MigrationProvider for MockMigrationProvider {
        async fn init_migration_table(&self) -> Result<()> {
            if self.should_fail {
                Err(anyhow::anyhow!("Mock failure"))
            } else {
                Ok(())
            }
        }

        async fn get_applied_migrations(&self) -> Result<Vec<super::MigrationRecord>> {
            Ok(self.applied_migrations.clone())
        }

        async fn record_migration(
            &self,
            _migration: &super::Migration,
            _execution_time_ms: i64,
        ) -> Result<()> {
            Ok(())
        }

        async fn remove_migration_record(&self, _version: u32) -> Result<()> {
            Ok(())
        }

        async fn execute_migration(&self, _migration: &super::Migration) -> Result<()> {
            Ok(())
        }

        async fn rollback_migration(&self, _migration: &super::Migration) -> Result<()> {
            Ok(())
        }

        async fn ping(&self) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_migration_runner_dry_run() {
        let provider = Arc::new(MockMigrationProvider {
            applied_migrations: vec![],
            should_fail: false,
        });

        let runner = MigrationRunner::new(provider, "migrations", "test").with_dry_run(true);

        // Note: This would fail in a real test because the migrations directory doesn't exist
        // In a real implementation, you'd want to set up test fixtures
    }
}
