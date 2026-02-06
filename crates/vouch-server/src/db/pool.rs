// SPDX-License-Identifier: BUSL-1.1
//! Database pool type abstraction for multi-database support.
//!
//! This module provides a `Pool` enum that wraps both SQLite and PostgreSQL
//! connection pools, enabling runtime database selection based on the
//! `DATABASE_URL` environment variable scheme.
//!
//! # URL Schemes
//!
//! - `sqlite:` - SQLite database (including `sqlite::memory:` for in-memory)
//! - `postgres:` or `postgresql:` - PostgreSQL database
//!
//! # Aurora DSQL Support
//!
//! When the PostgreSQL URL points to a DSQL endpoint (hostname contains `.dsql.`
//! and ends with `.on.aws`), the pool automatically:
//! - Generates IAM authentication tokens using AWS credentials
//! - Refreshes tokens every 10 minutes (tokens expire after 15 minutes)
//! - Uses SSL with certificate verification (`sslmode=verify-full`)
//!
//! # Example
//!
//! ```rust,ignore
//! use crate::db::{Pool, DatabaseType};
//!
//! // Connect based on URL scheme
//! let pool = Pool::connect("sqlite::memory:").await?;
//! assert_eq!(pool.db_type(), DatabaseType::Sqlite);
//!
//! let pool = Pool::connect("postgres://localhost/vouch").await?;
//! assert_eq!(pool.db_type(), DatabaseType::Postgres);
//!
//! // DSQL endpoint - uses IAM authentication automatically
//! let pool = Pool::connect("postgres://admin@abc123.dsql.us-east-1.on.aws/postgres").await?;
//! assert_eq!(pool.db_type(), DatabaseType::Postgres);
//! ```

use std::time::Duration;

use anyhow::{Context, Result, bail};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use super::dsql::{DsqlEndpoint, generate_dsql_token, load_sdk_config};

/// Database type enum for runtime SQL dialect selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseType {
    /// SQLite database
    Sqlite,
    /// PostgreSQL database (including Aurora DSQL)
    Postgres,
}

impl DatabaseType {
    /// Detect database type from URL scheme.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL scheme is not supported.
    pub fn from_url(url: &str) -> Result<Self> {
        if url.starts_with("sqlite:") {
            Ok(Self::Sqlite)
        } else if url.starts_with("postgres:") || url.starts_with("postgresql:") {
            Ok(Self::Postgres)
        } else {
            bail!(
                "Unsupported database URL scheme. Expected 'sqlite:', 'postgres:', or 'postgresql:' prefix, got: {}",
                url.split(':').next().unwrap_or("empty")
            )
        }
    }
}

/// Database connection pool that wraps both SQLite and PostgreSQL pools.
///
/// This enum enables a single binary to support both database backends,
/// with runtime selection based on the database URL.
#[derive(Debug, Clone)]
pub enum Pool {
    /// SQLite connection pool
    Sqlite(sqlx::SqlitePool),
    /// PostgreSQL connection pool
    Postgres(sqlx::PgPool),
}

impl Pool {
    /// Create a new in-memory SQLite pool for testing.
    ///
    /// This creates a minimal pool without running migrations,
    /// suitable for tests that don't need database access.
    ///
    /// # Panics
    ///
    /// Panics if the in-memory pool creation fails (should never happen).
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn new_test() -> Self {
        // Create a synchronous in-memory pool
        // Note: This is intentionally synchronous for test setup convenience
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_lazy("sqlite::memory:")
            .expect("Failed to create test SQLite pool");
        Self::Sqlite(pool)
    }

    /// Connect to a database using the URL scheme to determine the backend.
    ///
    /// # Arguments
    ///
    /// * `url` - Database URL with scheme prefix (`sqlite:`, `postgres:`, or `postgresql:`)
    ///
    /// # Aurora DSQL
    ///
    /// When connecting to a DSQL endpoint (hostname contains `.dsql.` and ends
    /// with `.on.aws`), IAM authentication is used automatically. AWS credentials
    /// are loaded from the standard credential chain (environment variables,
    /// AWS profiles, EKS IRSA, ECS task roles, EC2 IMDS).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The URL scheme is not supported
    /// - The connection fails
    /// - For DSQL: AWS credentials cannot be loaded or token generation fails
    pub async fn connect(url: &str) -> Result<Self> {
        let db_type = DatabaseType::from_url(url)?;

        match db_type {
            DatabaseType::Sqlite => {
                let pool = sqlx::SqlitePool::connect(url).await?;
                Ok(Self::Sqlite(pool))
            }
            DatabaseType::Postgres => {
                if let Some(dsql) = DsqlEndpoint::from_url(url)? {
                    let parsed = url::Url::parse(url).context("failed to parse PostgreSQL URL")?;
                    Self::connect_dsql(&dsql, parsed.username()).await
                } else {
                    let pool = sqlx::PgPool::connect(url).await?;
                    Ok(Self::Postgres(pool))
                }
            }
        }
    }

    /// Connect to an Aurora DSQL cluster using IAM authentication.
    ///
    /// This method:
    /// 1. Loads AWS credentials from the standard credential chain
    /// 2. Generates a DSQL authentication token
    /// 3. Creates a connection pool with appropriate settings
    /// 4. Spawns a background task to refresh tokens before expiry
    ///
    /// # Arguments
    ///
    /// * `dsql` - Parsed DSQL endpoint (direct or VPC)
    /// * `user` - Database username (typically "admin" for admin access)
    async fn connect_dsql(dsql: &DsqlEndpoint, user: &str) -> Result<Self> {
        let region = dsql.region().to_string();

        // Use provided user or default to "admin"
        let user = if user.is_empty() {
            std::env::var("DSQL_USER").unwrap_or_else(|_| "admin".to_string())
        } else {
            user.to_string()
        };
        let is_admin = user == "admin";

        tracing::info!(
            connect_host = dsql.connect_hostname(),
            token_host = dsql.token_hostname(),
            region = region,
            user = user,
            cluster_id = dsql.cluster_id(),
            "connecting to Aurora DSQL with IAM authentication"
        );

        // Load AWS SDK config (handles all credential sources)
        let sdk_config = load_sdk_config(Some(&region)).await;

        // Generate initial authentication token (against the token hostname)
        let token =
            generate_dsql_token(&sdk_config, dsql.token_hostname(), &region, is_admin).await?;

        // Build connection options with appropriate SSL mode
        let mut connect_options = PgConnectOptions::new()
            .host(dsql.connect_hostname())
            .port(5432)
            .database("postgres")
            .username(&user)
            .password(&token)
            .ssl_mode(dsql.ssl_mode());

        // Set amzn-cluster-id option for VPC endpoints
        if let Some(opt) = dsql.pg_options() {
            connect_options = connect_options.options([opt]);
        }

        // Create pool with appropriate lifetime settings for DSQL:
        // - max_lifetime: 55 min (DSQL terminates connections after 60 min)
        // - idle_timeout: 10 min (close unused connections to allow token refresh)
        // - acquire_timeout: 30 sec (prevent indefinite waits)
        // - min_connections: 1 (keep one warm connection for lower latency)
        // - test_before_acquire: true (validate connections; DSQL may close idle ones)
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .min_connections(1)
            .max_lifetime(Duration::from_secs(55 * 60))
            .idle_timeout(Duration::from_secs(10 * 60))
            .acquire_timeout(Duration::from_secs(30))
            .test_before_acquire(true)
            .connect_with(connect_options)
            .await
            .context("failed to connect to DSQL cluster")?;

        // Spawn background task to refresh tokens before they expire
        spawn_token_refresh(pool.clone(), dsql.clone(), user, is_admin);

        Ok(Self::Postgres(pool))
    }

    /// Get the database type for this pool.
    #[must_use]
    pub fn db_type(&self) -> DatabaseType {
        match self {
            Self::Sqlite(_) => DatabaseType::Sqlite,
            Self::Postgres(_) => DatabaseType::Postgres,
        }
    }

    /// Begin a new transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction cannot be started.
    pub async fn begin(&self) -> Result<Transaction<'_>> {
        match self {
            Self::Sqlite(pool) => {
                let tx = pool.begin().await?;
                Ok(Transaction::Sqlite(tx))
            }
            Self::Postgres(pool) => {
                let tx = pool.begin().await?;
                Ok(Transaction::Postgres(tx))
            }
        }
    }

    /// Close the pool and release all connections.
    ///
    /// For DSQL pools, this also signals the background token refresh task to stop.
    /// After calling this method, the pool should not be used.
    ///
    /// This method is idempotent - calling it multiple times has no additional effect.
    pub async fn close(&self) {
        match self {
            Self::Sqlite(pool) => pool.close().await,
            Self::Postgres(pool) => pool.close().await,
        }
    }

    /// Check if the pool has been closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        match self {
            Self::Sqlite(pool) => pool.is_closed(),
            Self::Postgres(pool) => pool.is_closed(),
        }
    }
}

/// Database transaction that wraps both SQLite and PostgreSQL transactions.
pub enum Transaction<'a> {
    /// SQLite transaction
    Sqlite(sqlx::Transaction<'a, sqlx::Sqlite>),
    /// PostgreSQL transaction
    Postgres(sqlx::Transaction<'a, sqlx::Postgres>),
}

impl Transaction<'_> {
    /// Commit the transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the commit fails.
    pub async fn commit(self) -> Result<()> {
        match self {
            Self::Sqlite(tx) => {
                tx.commit().await?;
                Ok(())
            }
            Self::Postgres(tx) => {
                tx.commit().await?;
                Ok(())
            }
        }
    }

    /// Get the database type for this transaction.
    #[must_use]
    pub fn db_type(&self) -> DatabaseType {
        match self {
            Self::Sqlite(_) => DatabaseType::Sqlite,
            Self::Postgres(_) => DatabaseType::Postgres,
        }
    }
}

// ============================================================================
// Query Execution Helpers
// ============================================================================

/// Generic query result that works with both SQLite and PostgreSQL.
#[derive(Debug)]
pub struct QueryResult {
    rows_affected: u64,
}

impl QueryResult {
    /// Number of rows affected by the query.
    #[must_use]
    pub fn rows_affected(&self) -> u64 {
        self.rows_affected
    }
}

impl From<sqlx::sqlite::SqliteQueryResult> for QueryResult {
    fn from(result: sqlx::sqlite::SqliteQueryResult) -> Self {
        Self {
            rows_affected: result.rows_affected(),
        }
    }
}

impl From<sqlx::postgres::PgQueryResult> for QueryResult {
    fn from(result: sqlx::postgres::PgQueryResult) -> Self {
        Self {
            rows_affected: result.rows_affected(),
        }
    }
}

/// Execute a query that returns no rows against the pool.
///
/// This macro handles dispatching to the correct pool type.
#[macro_export]
macro_rules! db_execute {
    ($pool:expr, $query:expr) => {
        match $pool {
            $crate::db::Pool::Sqlite(p) => $query
                .execute(p)
                .await
                .map($crate::db::pool::QueryResult::from),
            $crate::db::Pool::Postgres(p) => $query
                .execute(p)
                .await
                .map($crate::db::pool::QueryResult::from),
        }
    };
}

/// Execute a query that returns rows against the pool.
#[macro_export]
macro_rules! db_fetch_all {
    ($pool:expr, $query:expr) => {
        match $pool {
            $crate::db::Pool::Sqlite(p) => $query.fetch_all(p).await,
            $crate::db::Pool::Postgres(p) => $query.fetch_all(p).await,
        }
    };
}

/// Execute a query that returns a single row against the pool.
#[macro_export]
macro_rules! db_fetch_one {
    ($pool:expr, $query:expr) => {
        match $pool {
            $crate::db::Pool::Sqlite(p) => $query.fetch_one(p).await,
            $crate::db::Pool::Postgres(p) => $query.fetch_one(p).await,
        }
    };
}

/// Execute a query that returns an optional row against the pool.
#[macro_export]
macro_rules! db_fetch_optional {
    ($pool:expr, $query:expr) => {
        match $pool {
            $crate::db::Pool::Sqlite(p) => $query.fetch_optional(p).await,
            $crate::db::Pool::Postgres(p) => $query.fetch_optional(p).await,
        }
    };
}

/// Execute a query against a transaction.
#[macro_export]
macro_rules! tx_execute {
    ($tx:expr, $query:expr) => {
        match $tx {
            $crate::db::Transaction::Sqlite(ref mut t) => $query
                .execute(&mut **t)
                .await
                .map($crate::db::pool::QueryResult::from),
            $crate::db::Transaction::Postgres(ref mut t) => $query
                .execute(&mut **t)
                .await
                .map($crate::db::pool::QueryResult::from),
        }
    };
}

/// Fetch all rows from a query against a transaction.
#[macro_export]
macro_rules! tx_fetch_all {
    ($tx:expr, $query:expr) => {
        match $tx {
            $crate::db::Transaction::Sqlite(ref mut t) => $query.fetch_all(&mut **t).await,
            $crate::db::Transaction::Postgres(ref mut t) => $query.fetch_all(&mut **t).await,
        }
    };
}

/// Fetch a single row from a query against a transaction.
#[macro_export]
macro_rules! tx_fetch_one {
    ($tx:expr, $query:expr) => {
        match $tx {
            $crate::db::Transaction::Sqlite(ref mut t) => $query.fetch_one(&mut **t).await,
            $crate::db::Transaction::Postgres(ref mut t) => $query.fetch_one(&mut **t).await,
        }
    };
}

/// Fetch an optional row from a query against a transaction.
#[macro_export]
macro_rules! tx_fetch_optional {
    ($tx:expr, $query:expr) => {
        match $tx {
            $crate::db::Transaction::Sqlite(ref mut t) => $query.fetch_optional(&mut **t).await,
            $crate::db::Transaction::Postgres(ref mut t) => $query.fetch_optional(&mut **t).await,
        }
    };
}

// ============================================================================
// DSQL Token Refresh
// ============================================================================

/// Spawn a background task that periodically refreshes DSQL authentication tokens.
///
/// DSQL tokens expire after 15 minutes by default. This task refreshes the token
/// every 10 minutes to ensure new connections always use a valid token.
///
/// The task exits gracefully when the pool is closed (via `Pool::close()`),
/// enabling clean shutdown integration.
///
/// When a token refresh fails, the task logs a warning but continues running.
/// Existing connections remain valid until they're closed or the connection
/// lifetime limit (60 minutes) is reached.
fn spawn_token_refresh(pool: sqlx::PgPool, dsql: DsqlEndpoint, user: String, is_admin: bool) {
    tokio::spawn(async move {
        // Refresh every 10 minutes (tokens expire after 15 min by default)
        let refresh_interval = Duration::from_secs(10 * 60);
        let region = dsql.region().to_string();

        loop {
            tokio::time::sleep(refresh_interval).await;

            // Check if pool has been closed (graceful shutdown)
            if pool.is_closed() {
                tracing::debug!("DSQL pool closed, stopping token refresh task");
                break;
            }

            // Reload AWS credentials (in case they've been rotated)
            let sdk_config = load_sdk_config(Some(&region)).await;

            match generate_dsql_token(&sdk_config, dsql.token_hostname(), &region, is_admin).await {
                Ok(new_token) => {
                    // Update the pool's connect options with the new token
                    let mut new_options = PgConnectOptions::new()
                        .host(dsql.connect_hostname())
                        .port(5432)
                        .database("postgres")
                        .username(&user)
                        .password(&new_token)
                        .ssl_mode(dsql.ssl_mode());

                    if let Some(opt) = dsql.pg_options() {
                        new_options = new_options.options([opt]);
                    }

                    pool.set_connect_options(new_options);
                    tracing::debug!("DSQL authentication token refreshed successfully");
                }
                Err(e) => {
                    // Log warning but continue - existing connections still work
                    tracing::warn!(
                        error = %e,
                        "failed to refresh DSQL authentication token"
                    );
                }
            }
        }
    });
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_database_type_from_url_sqlite() {
        assert_eq!(
            DatabaseType::from_url("sqlite::memory:").unwrap(),
            DatabaseType::Sqlite
        );
        assert_eq!(
            DatabaseType::from_url("sqlite:test.db").unwrap(),
            DatabaseType::Sqlite
        );
        assert_eq!(
            DatabaseType::from_url("sqlite:/path/to/db.sqlite").unwrap(),
            DatabaseType::Sqlite
        );
    }

    #[test]
    fn test_database_type_from_url_postgres() {
        assert_eq!(
            DatabaseType::from_url("postgres://localhost/vouch").unwrap(),
            DatabaseType::Postgres
        );
        assert_eq!(
            DatabaseType::from_url("postgresql://localhost/vouch").unwrap(),
            DatabaseType::Postgres
        );
        assert_eq!(
            DatabaseType::from_url("postgres://user:pass@host:5432/db").unwrap(),
            DatabaseType::Postgres
        );
    }

    #[test]
    fn test_database_type_from_url_invalid() {
        assert!(DatabaseType::from_url("mysql://localhost/db").is_err());
        assert!(DatabaseType::from_url("invalid").is_err());
        assert!(DatabaseType::from_url("").is_err());
    }

    #[tokio::test]
    async fn test_pool_connect_sqlite() {
        let pool = Pool::connect("sqlite::memory:").await.unwrap();
        assert_eq!(pool.db_type(), DatabaseType::Sqlite);
    }
}
