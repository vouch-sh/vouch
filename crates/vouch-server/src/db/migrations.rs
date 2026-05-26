// SPDX-License-Identifier: Apache-2.0 OR MIT
//! DSQL-compatible migration runner.
//!
//! Aurora DSQL has restrictions that prevent standard sqlx migrations:
//! - No `pg_advisory_lock` support (used for migration locking)
//! - No mixing DDL and DML in the same transaction
//!
//! This module provides a custom migration runner that handles these limitations
//! by running each migration's DDL separately from the tracking DML.

use anyhow::{Context, Result};
use aws_lc_rs::digest::{self, SHA384};
use sqlx::PgPool;

/// Run PostgreSQL migrations with DSQL compatibility.
///
/// This runner:
/// 1. Creates the `_sqlx_migrations` table if needed (separate transaction)
/// 2. For each pending migration:
///    a. Executes the migration SQL (no transaction for DDL)
///    b. Records completion in `_sqlx_migrations` (separate transaction)
///
/// This approach works around DSQL's restriction on mixing DDL and DML.
/// Result of running migrations: (newly_applied, total).
pub(crate) type MigrationResult = (usize, usize);

pub(crate) async fn run_dsql_migrations(pool: &PgPool) -> Result<MigrationResult> {
    // Get the embedded migrations
    let migrator = sqlx::migrate!("./migrations/postgres");
    let total = migrator.iter().count();

    // Ensure _sqlx_migrations table exists
    create_migrations_table(pool).await?;

    // Get list of already-applied migrations
    let applied: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(pool)
            .await
            .context("failed to query applied migrations")?;

    let applied_set: std::collections::HashSet<i64> = applied.into_iter().collect();

    let mut newly_applied: usize = 0;

    // Run each pending migration
    for migration in migrator.iter() {
        let version = migration.version;

        if applied_set.contains(&version) {
            tracing::debug!(version, description = %migration.description, "migration already applied");
            continue;
        }

        tracing::info!(version, description = %migration.description, "applying migration");

        let start = std::time::Instant::now();

        // Execute the migration SQL directly (no transaction wrapper)
        // DSQL will auto-commit each statement.
        //
        // Crash recovery: if a previous attempt's DDL succeeded but the
        // subsequent `record_migration` write was lost (server crashed,
        // DSQL transient failure, …), the schema object already exists
        // and a re-run would normally fail with "relation already
        // exists" — leaving the server permanently unable to start.
        //
        // Treat a duplicate-object error here as evidence that the DDL
        // landed on the prior attempt, then re-record the migration so
        // future startups skip it cleanly. New deployments will hit the
        // happy path; only recovery paths exercise this branch.
        match sqlx::raw_sql(&migration.sql).execute(pool).await {
            Ok(_) => {}
            Err(e) if is_duplicate_object_error(&e) => {
                tracing::warn!(
                    version,
                    description = %migration.description,
                    "migration DDL already applied on a prior attempt — \
                     recovering by recording completion now",
                );
            }
            Err(e) => {
                return Err(anyhow::Error::from(e).context(format!(
                    "failed to execute migration {}: {}",
                    version, migration.description
                )));
            }
        }

        let elapsed = start.elapsed();

        // Record the migration as complete (separate transaction)
        record_migration(pool, migration, elapsed)
            .await
            .with_context(|| format!("failed to record migration {}", version))?;

        tracing::info!(
            version,
            description = %migration.description,
            elapsed_ms = elapsed.as_millis(),
            "migration complete"
        );

        newly_applied = newly_applied.saturating_add(1);
    }

    Ok((newly_applied, total))
}

/// Returns true if `err` is a PostgreSQL duplicate-object error.
/// See [`is_duplicate_object_sqlstate`] for the matched codes.
fn is_duplicate_object_error(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .and_then(|e| e.code())
        .is_some_and(|c| is_duplicate_object_sqlstate(c.as_ref()))
}

/// True if `code` is one of the PostgreSQL `SQLSTATE` values that
/// indicate "this object already exists" — the family signalling a
/// re-run of a DDL the database already executed.
///
/// - `42P07` — `duplicate_table`
/// - `42710` — `duplicate_object` (catches indexes, triggers, …)
/// - `42P06` — `duplicate_schema`
/// - `42701` — `duplicate_column`
/// - `42P16` — `invalid_table_definition` (raised by some PG flavours
///   when re-adding an identical constraint)
fn is_duplicate_object_sqlstate(code: &str) -> bool {
    matches!(code, "42P07" | "42710" | "42P06" | "42701" | "42P16")
}

/// Create the _sqlx_migrations table if it doesn't exist.
async fn create_migrations_table(pool: &PgPool) -> Result<()> {
    sqlx::raw_sql(
        r#"
        CREATE TABLE IF NOT EXISTS _sqlx_migrations (
            version BIGINT PRIMARY KEY,
            description TEXT NOT NULL,
            installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
            success BOOLEAN NOT NULL,
            checksum BYTEA NOT NULL,
            execution_time BIGINT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .context("failed to create _sqlx_migrations table")?;

    Ok(())
}

/// Record a completed migration in the tracking table.
async fn record_migration(
    pool: &PgPool,
    migration: &sqlx::migrate::Migration,
    elapsed: std::time::Duration,
) -> Result<()> {
    // Compute checksum (SHA-384 of the SQL, matching sqlx's approach)
    let checksum = digest::digest(&SHA384, migration.sql.as_bytes())
        .as_ref()
        .to_vec();

    let elapsed_nanos = i64::try_from(elapsed.as_nanos())
        .context("migration elapsed time exceeds i64 nanoseconds")?;
    sqlx::query(
        r#"
        INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(migration.version)
    .bind(&*migration.description)
    .bind(true)
    .bind(&checksum)
    .bind(elapsed_nanos)
    .execute(pool)
    .await
    .context("failed to insert migration record")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_duplicate_object_sqlstate;

    #[test]
    fn classifies_duplicate_table() {
        assert!(is_duplicate_object_sqlstate("42P07"));
    }

    #[test]
    fn classifies_duplicate_object() {
        // 42710 is raised for duplicate indexes (the case #397 cares
        // about most: a partial-recovery re-run of CREATE INDEX ASYNC).
        assert!(is_duplicate_object_sqlstate("42710"));
    }

    #[test]
    fn does_not_classify_unrelated_errors() {
        // 23505 = unique_violation (a DML conflict, not a DDL re-run)
        assert!(!is_duplicate_object_sqlstate("23505"));
        // 42703 = undefined_column — symptom of a wrong migration,
        // must propagate as failure, not be silently swallowed.
        assert!(!is_duplicate_object_sqlstate("42703"));
        // Connection failures must propagate.
        assert!(!is_duplicate_object_sqlstate("08006"));
        // Empty / nonsense codes must not match.
        assert!(!is_duplicate_object_sqlstate(""));
        assert!(!is_duplicate_object_sqlstate("nope"));
    }
}
