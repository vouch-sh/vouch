// SPDX-License-Identifier: Apache-2.0 OR MIT
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

/// Connection pool configuration.
///
/// Populated from CLI args / environment via clap in `config::Args`.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum pool connections.
    pub max_connections: u32,
    /// Minimum idle connections.
    pub min_connections: u32,
    /// Idle timeout in seconds.
    pub idle_timeout_secs: u64,
    /// Acquire timeout in seconds.
    pub acquire_timeout_secs: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 25,
            min_connections: 2,
            idle_timeout_secs: 300,
            acquire_timeout_secs: 5,
        }
    }
}

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
    #[expect(
        clippy::expect_used,
        reason = "test-only constructor; .expect surfaces broken in-memory sqlite setup"
    )]
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
    pub async fn connect(url: &str, pool_cfg: &PoolConfig) -> Result<Self> {
        let db_type = DatabaseType::from_url(url)?;

        match db_type {
            DatabaseType::Sqlite => {
                let opts = url
                    .parse::<sqlx::sqlite::SqliteConnectOptions>()?
                    .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                    .auto_vacuum(sqlx::sqlite::SqliteAutoVacuum::Incremental)
                    .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
                    .busy_timeout(Duration::from_secs(5))
                    .pragma("analysis_limit", "400");
                let pool = sqlx::SqlitePool::connect_with(opts).await?;
                Ok(Self::Sqlite(pool))
            }
            DatabaseType::Postgres => {
                if let Some(dsql) = DsqlEndpoint::from_url(url)? {
                    let parsed = url::Url::parse(url).context("failed to parse PostgreSQL URL")?;
                    Self::connect_dsql(&dsql, parsed.username(), pool_cfg).await
                } else {
                    let max_connections = pool_cfg.max_connections;
                    tracing::info!(
                        max_connections,
                        min_connections = pool_cfg.min_connections,
                        idle_timeout_secs = pool_cfg.idle_timeout_secs,
                        acquire_timeout_secs = pool_cfg.acquire_timeout_secs,
                        "creating PostgreSQL connection pool"
                    );
                    let pool = PgPoolOptions::new()
                        .max_connections(max_connections)
                        .min_connections(pool_cfg.min_connections)
                        .idle_timeout(Duration::from_secs(pool_cfg.idle_timeout_secs))
                        .acquire_timeout(Duration::from_secs(pool_cfg.acquire_timeout_secs))
                        .connect(url)
                        .await?;
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
    async fn connect_dsql(dsql: &DsqlEndpoint, user: &str, pool_cfg: &PoolConfig) -> Result<Self> {
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

        // DSQL-specific: max_lifetime 55 min (DSQL terminates at 60 min),
        // before_acquire pings only connections idle >30s.
        let max_connections = pool_cfg.max_connections;
        tracing::info!(
            max_connections,
            min_connections = pool_cfg.min_connections,
            idle_timeout_secs = pool_cfg.idle_timeout_secs,
            acquire_timeout_secs = pool_cfg.acquire_timeout_secs,
            "creating Aurora DSQL connection pool"
        );
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .min_connections(pool_cfg.min_connections)
            .max_lifetime(Duration::from_mins(55))
            .idle_timeout(Duration::from_secs(pool_cfg.idle_timeout_secs))
            .acquire_timeout(Duration::from_secs(pool_cfg.acquire_timeout_secs))
            .test_before_acquire(false)
            .before_acquire(|conn, meta| {
                Box::pin(async move {
                    if meta.idle_for.as_secs() > 30 {
                        sqlx::Connection::ping(conn).await?;
                    }
                    Ok(true)
                })
            })
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

    /// Check database connectivity by executing a simple query.
    ///
    /// Returns `Ok(())` if the database is reachable, or an error if it is not.
    /// Used by the `/health/ready` endpoint for Kubernetes readiness probes.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails (database unreachable, pool exhausted, etc.).
    pub async fn is_healthy(&self) -> Result<()> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i32>("SELECT 1")
                    .fetch_one(pool)
                    .await
                    .context("SQLite health check failed")?;
                Ok(())
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i32>("SELECT 1")
                    .fetch_one(pool)
                    .await
                    .context("PostgreSQL health check failed")?;
                Ok(())
            }
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
pub(crate) struct QueryResult {
    rows_affected: u64,
}

impl QueryResult {
    /// Number of rows affected by the query.
    #[must_use]
    pub(crate) fn rows_affected(&self) -> u64 {
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

/// Trait for errors that signal a transient conflict worth retrying.
///
/// Implemented for `anyhow::Error` (delegates to `is_retryable_db_error`) and for
/// `ServiceError` (only the dedicated `OccConflict` variant is retryable).  The
/// `with_dsql_retry!` macro calls `e.is_retryable()` instead of the old
/// `is_retryable_db_error(&e)` so that OCC version-bump conflicts from
/// `compare_and_update` are retried through the same bounded loop as DSQL
/// network-level serialization failures, without any change to the ~11 existing
/// non-transactional call sites (their error type is still `anyhow::Error`).
pub(crate) trait RetryableError {
    fn is_retryable(&self) -> bool;
}

impl RetryableError for anyhow::Error {
    fn is_retryable(&self) -> bool {
        is_retryable_db_error(self)
    }
}

/// Retry an async block on transient DSQL errors or OCC version conflicts.
///
/// Re-evaluates the body on each attempt (creating a fresh future),
/// so the operation is fully retried from scratch. Non-retryable
/// errors and successes pass through immediately.
///
/// The error type returned by `$body` must implement [`RetryableError`].
/// For `anyhow::Error` this is equivalent to the old `is_retryable_db_error`
/// check.  For `ServiceError`, only the `OccConflict` variant retries.
///
/// Usage: `with_dsql_retry!(async { ... }).await`
#[macro_export]
macro_rules! with_dsql_retry {
    ($body:expr) => {{
        let mut __attempt = 0u32;
        loop {
            match $body.await {
                Ok(val) => break Ok(val),
                Err(e)
                    if $crate::db::pool::RetryableError::is_retryable(&e)
                        && __attempt < $crate::db::pool::MAX_DSQL_RETRIES =>
                {
                    tracing::warn!(
                        attempt = __attempt,
                        error = %e,
                        "transient DSQL/OCC conflict, retrying"
                    );
                    tokio::time::sleep(
                        $crate::db::pool::retry_backoff(__attempt),
                    )
                    .await;
                    __attempt = __attempt.saturating_add(1);
                }
                Err(e) => break Err(e),
            }
        }
    }};
}

/// Execute a sea-query statement that returns no rows against the pool.
///
/// Builds parameterized SQL for the correct backend (SQLite/PostgreSQL)
/// using `sea-query-sqlx`, then executes via `sqlx::query_with`.
#[macro_export]
macro_rules! db_execute {
    ($pool:expr, $stmt:expr) => {
        match $pool {
            $crate::db::Pool::Sqlite(p) => {
                use sea_query_sqlx::SqlxBinder;
                let (sql, values) = $stmt.build_sqlx(sea_query::SqliteQueryBuilder);
                sqlx::query_with(sqlx::AssertSqlSafe(sql), values)
                    .execute(p)
                    .await
                    .map($crate::db::pool::QueryResult::from)
            }
            $crate::db::Pool::Postgres(p) => {
                use sea_query_sqlx::SqlxBinder;
                let (sql, values) = $stmt.build_sqlx(sea_query::PostgresQueryBuilder);
                sqlx::query_with(sqlx::AssertSqlSafe(sql), values)
                    .execute(p)
                    .await
                    .map($crate::db::pool::QueryResult::from)
            }
        }
    };
}

/// Fetch all rows from a sea-query statement against the pool.
#[macro_export]
macro_rules! db_fetch_all {
    ($pool:expr, $stmt:expr, $row_type:ty) => {
        match $pool {
            $crate::db::Pool::Sqlite(p) => {
                use sea_query_sqlx::SqlxBinder;
                let (sql, values) = $stmt.build_sqlx(sea_query::SqliteQueryBuilder);
                sqlx::query_as_with::<_, $row_type, _>(sqlx::AssertSqlSafe(sql), values)
                    .fetch_all(p)
                    .await
            }
            $crate::db::Pool::Postgres(p) => {
                use sea_query_sqlx::SqlxBinder;
                let (sql, values) = $stmt.build_sqlx(sea_query::PostgresQueryBuilder);
                sqlx::query_as_with::<_, $row_type, _>(sqlx::AssertSqlSafe(sql), values)
                    .fetch_all(p)
                    .await
            }
        }
    };
}

/// Fetch a single row from a sea-query statement against the pool.
#[macro_export]
macro_rules! db_fetch_one {
    ($pool:expr, $stmt:expr, $row_type:ty) => {
        match $pool {
            $crate::db::Pool::Sqlite(p) => {
                use sea_query_sqlx::SqlxBinder;
                let (sql, values) = $stmt.build_sqlx(sea_query::SqliteQueryBuilder);
                sqlx::query_as_with::<_, $row_type, _>(sqlx::AssertSqlSafe(sql), values)
                    .fetch_one(p)
                    .await
            }
            $crate::db::Pool::Postgres(p) => {
                use sea_query_sqlx::SqlxBinder;
                let (sql, values) = $stmt.build_sqlx(sea_query::PostgresQueryBuilder);
                sqlx::query_as_with::<_, $row_type, _>(sqlx::AssertSqlSafe(sql), values)
                    .fetch_one(p)
                    .await
            }
        }
    };
}

/// Fetch an optional row from a sea-query statement against the pool.
#[macro_export]
macro_rules! db_fetch_optional {
    ($pool:expr, $stmt:expr, $row_type:ty) => {
        match $pool {
            $crate::db::Pool::Sqlite(p) => {
                use sea_query_sqlx::SqlxBinder;
                let (sql, values) = $stmt.build_sqlx(sea_query::SqliteQueryBuilder);
                sqlx::query_as_with::<_, $row_type, _>(sqlx::AssertSqlSafe(sql), values)
                    .fetch_optional(p)
                    .await
            }
            $crate::db::Pool::Postgres(p) => {
                use sea_query_sqlx::SqlxBinder;
                let (sql, values) = $stmt.build_sqlx(sea_query::PostgresQueryBuilder);
                sqlx::query_as_with::<_, $row_type, _>(sqlx::AssertSqlSafe(sql), values)
                    .fetch_optional(p)
                    .await
            }
        }
    };
}

/// Execute a sea-query statement against a transaction.
#[macro_export]
macro_rules! tx_execute {
    ($tx:expr, $stmt:expr) => {
        match $tx {
            $crate::db::Transaction::Sqlite(ref mut t) => {
                use sea_query_sqlx::SqlxBinder;
                let (sql, values) = $stmt.build_sqlx(sea_query::SqliteQueryBuilder);
                sqlx::query_with(sqlx::AssertSqlSafe(sql), values)
                    .execute(&mut **t)
                    .await
                    .map($crate::db::pool::QueryResult::from)
            }
            $crate::db::Transaction::Postgres(ref mut t) => {
                use sea_query_sqlx::SqlxBinder;
                let (sql, values) = $stmt.build_sqlx(sea_query::PostgresQueryBuilder);
                sqlx::query_with(sqlx::AssertSqlSafe(sql), values)
                    .execute(&mut **t)
                    .await
                    .map($crate::db::pool::QueryResult::from)
            }
        }
    };
}

/// Fetch all rows from a sea-query statement against a transaction.
#[macro_export]
macro_rules! tx_fetch_all {
    ($tx:expr, $stmt:expr, $row_type:ty) => {
        match $tx {
            $crate::db::Transaction::Sqlite(ref mut t) => {
                use sea_query_sqlx::SqlxBinder;
                let (sql, values) = $stmt.build_sqlx(sea_query::SqliteQueryBuilder);
                sqlx::query_as_with::<_, $row_type, _>(sqlx::AssertSqlSafe(sql), values)
                    .fetch_all(&mut **t)
                    .await
            }
            $crate::db::Transaction::Postgres(ref mut t) => {
                use sea_query_sqlx::SqlxBinder;
                let (sql, values) = $stmt.build_sqlx(sea_query::PostgresQueryBuilder);
                sqlx::query_as_with::<_, $row_type, _>(sqlx::AssertSqlSafe(sql), values)
                    .fetch_all(&mut **t)
                    .await
            }
        }
    };
}

/// Fetch a single row from a sea-query statement against a transaction.
#[macro_export]
macro_rules! tx_fetch_one {
    ($tx:expr, $stmt:expr, $row_type:ty) => {
        match $tx {
            $crate::db::Transaction::Sqlite(ref mut t) => {
                use sea_query_sqlx::SqlxBinder;
                let (sql, values) = $stmt.build_sqlx(sea_query::SqliteQueryBuilder);
                sqlx::query_as_with::<_, $row_type, _>(sqlx::AssertSqlSafe(sql), values)
                    .fetch_one(&mut **t)
                    .await
            }
            $crate::db::Transaction::Postgres(ref mut t) => {
                use sea_query_sqlx::SqlxBinder;
                let (sql, values) = $stmt.build_sqlx(sea_query::PostgresQueryBuilder);
                sqlx::query_as_with::<_, $row_type, _>(sqlx::AssertSqlSafe(sql), values)
                    .fetch_one(&mut **t)
                    .await
            }
        }
    };
}

/// Fetch an optional row from a sea-query statement against a transaction.
#[macro_export]
macro_rules! tx_fetch_optional {
    ($tx:expr, $stmt:expr, $row_type:ty) => {
        match $tx {
            $crate::db::Transaction::Sqlite(ref mut t) => {
                use sea_query_sqlx::SqlxBinder;
                let (sql, values) = $stmt.build_sqlx(sea_query::SqliteQueryBuilder);
                sqlx::query_as_with::<_, $row_type, _>(sqlx::AssertSqlSafe(sql), values)
                    .fetch_optional(&mut **t)
                    .await
            }
            $crate::db::Transaction::Postgres(ref mut t) => {
                use sea_query_sqlx::SqlxBinder;
                let (sql, values) = $stmt.build_sqlx(sea_query::PostgresQueryBuilder);
                sqlx::query_as_with::<_, $row_type, _>(sqlx::AssertSqlSafe(sql), values)
                    .fetch_optional(&mut **t)
                    .await
            }
        }
    };
}

// ============================================================================
// Database URL Utilities
// ============================================================================

/// Redact the password from a database URL for safe logging.
///
/// - `postgres://user:secret@host/db` -> `postgres://user:***@host/db`
/// - `sqlite:path.db` -> `sqlite:path.db` (no password to redact)
pub(crate) fn redact_database_url(url: &str) -> String {
    // SQLite URLs use "sqlite:" prefix and never contain passwords
    if url.starts_with("sqlite:") {
        return url.to_string();
    }

    // Try to parse as a standard URL (postgres://, postgresql://)
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            if parsed.password().is_some() {
                // url::Url::set_password returns Result<(), ()>; failure is impossible
                // here because we just confirmed the URL is parsed.
                let _set = parsed.set_password(Some("***"));
            }
            parsed.to_string()
        }
        // If parsing fails, return the URL with a generic redaction
        Err(_) => url.to_string(),
    }
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
        let refresh_interval = Duration::from_mins(10);
        let region = dsql.region().to_string();

        tracing::info!(
            "DSQL token refresh task started (region={}, refresh_interval=10m)",
            region,
        );

        let mut interval = tokio::time::interval(refresh_interval);
        interval.tick().await; // skip the immediate first tick

        loop {
            tokio::select! {
                _ = pool.close_event() => {
                    tracing::debug!("DSQL pool closed, stopping token refresh task");
                    break;
                }
                _ = interval.tick() => {
                    // Reload AWS credentials (in case they've been rotated)
                    let sdk_config = load_sdk_config(Some(&region)).await;

                    match generate_dsql_token(
                        &sdk_config,
                        dsql.token_hostname(),
                        &region,
                        is_admin,
                    )
                    .await
                    {
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
            }
        }
    });
}

// ============================================================================
// DSQL Retry Helpers
// ============================================================================

/// Maximum number of retries for transient DSQL errors.
pub(crate) const MAX_DSQL_RETRIES: u32 = 3;

/// SQLSTATE codes that indicate a transient, retryable error.
///
/// Postgres/DSQL (5-char SQLSTATEs):
/// - `40001`: Serialization failure (standard SQL)
/// - `OC000`: Aurora DSQL optimistic concurrency conflict
/// - `OC001`: Aurora DSQL transaction conflict
///
/// SQLite primaries:
/// - `5`: `SQLITE_BUSY` — writer contention
/// - `6`: `SQLITE_LOCKED` — deadlock between concurrent transactions
///
/// SQLite extended codes for those primaries — sqlx returns these as the
/// integer literal (e.g. `"517"` for `SQLITE_BUSY_SNAPSHOT`), so we
/// enumerate the ones we want rather than masking. The full set is small
/// and stable.
/// - `261`: `SQLITE_BUSY_RECOVERY`
/// - `517`: `SQLITE_BUSY_SNAPSHOT`
/// - `773`: `SQLITE_BUSY_TIMEOUT`
/// - `262`: `SQLITE_LOCKED_SHAREDCACHE`
/// - `518`: `SQLITE_LOCKED_VTAB`
const RETRYABLE_SQL_STATES: &[&str] = &[
    "40001", "OC000", "OC001", "5", "6", "261", "517", "773", "262", "518",
];

/// Match `code` against [`RETRYABLE_SQL_STATES`] verbatim.
///
/// Earlier revisions masked numeric codes with `& 0xFF` to normalize
/// SQLite extended codes down to their primary, but that masked
/// Postgres SQLSTATEs too — `"22021"`, `"22022"`, and `"42501"` all
/// collide with SQLite `5`/`6` after masking (#454). Since SQLite's
/// retryable extended-code set is small and stable, we just list them.
fn is_retryable_code(code: &str) -> bool {
    RETRYABLE_SQL_STATES.contains(&code)
}

/// Check whether an error is a transient database error worth retrying.
///
/// Downcasts through `anyhow::Error` → `sqlx::Error::Database` and
/// inspects the SQLSTATE code.
pub(crate) fn is_retryable_db_error(err: &anyhow::Error) -> bool {
    if let Some(sqlx_err) = err.downcast_ref::<sqlx::Error>()
        && let sqlx::Error::Database(db_err) = sqlx_err
        && let Some(code) = db_err.code()
    {
        return is_retryable_code(code.as_ref());
    }
    false
}

/// Check whether an error is a unique/primary-key constraint violation.
///
/// Downcasts through `anyhow::Error` → `sqlx::Error::Database` and
/// inspects the structured error kind. Covers both UNIQUE and PRIMARY KEY
/// constraints across SQLite, PostgreSQL, and Aurora DSQL.
pub(crate) fn is_unique_violation(err: &anyhow::Error) -> bool {
    if let Some(sqlx_err) = err.downcast_ref::<sqlx::Error>()
        && let sqlx::Error::Database(db_err) = sqlx_err
    {
        return db_err.is_unique_violation();
    }
    false
}

/// Compute a jittered exponential backoff duration for the given attempt.
///
/// Base delay doubles each attempt (~100ms, ~200ms, ~400ms) with ±25% jitter.
pub(crate) fn retry_backoff(attempt: u32) -> Duration {
    let base_ms = 100u64.saturating_mul(1u64 << attempt);
    // ±25% jitter using simple xorshift on timestamp
    // 4 is non-zero; unwrap_or arm is unreachable.
    let jitter_range = base_ms.checked_div(4).unwrap_or(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let modulus = jitter_range.saturating_mul(2).saturating_add(1);
    // checked_rem returns None only if modulus is 0; saturating_add(1) is non-zero.
    let jitter = u64::from(nanos)
        .checked_rem(modulus)
        .unwrap_or(0)
        .saturating_sub(jitter_range);
    Duration::from_millis(base_ms.saturating_add(jitter))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
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
        let pool = Pool::connect("sqlite::memory:", &PoolConfig::default())
            .await
            .unwrap();
        assert_eq!(pool.db_type(), DatabaseType::Sqlite);
    }

    #[test]
    fn test_redact_database_url_sqlite() {
        assert_eq!(redact_database_url("sqlite::memory:"), "sqlite::memory:");
        assert_eq!(redact_database_url("sqlite:test.db"), "sqlite:test.db");
    }

    #[test]
    fn test_redact_database_url_postgres_with_password() {
        let redacted = redact_database_url("postgres://user:secret@host/db");
        assert!(redacted.contains("***"));
        assert!(!redacted.contains("secret"));
    }

    #[test]
    fn test_redact_database_url_postgres_without_password() {
        let url = "postgres://user@host/db";
        let redacted = redact_database_url(url);
        assert!(!redacted.contains("***"));
    }

    #[test]
    fn test_redact_database_url_invalid() {
        // Invalid URLs are returned as-is
        assert_eq!(redact_database_url("not-a-url"), "not-a-url");
    }

    #[test]
    fn test_is_retryable_db_error_non_db() {
        let err = anyhow::anyhow!("some random error");
        assert!(!is_retryable_db_error(&err));
    }

    /// Postgres/DSQL emit 5-char SQLSTATEs verbatim — exact match path.
    #[test]
    fn test_is_retryable_code_postgres_serialization_failure() {
        assert!(is_retryable_code("40001"));
    }

    #[test]
    fn test_is_retryable_code_dsql_occ_conflict() {
        assert!(is_retryable_code("OC000"));
        assert!(is_retryable_code("OC001"));
    }

    /// SQLite extended codes for `SQLITE_BUSY` (primary `5`). sqlx
    /// returns the integer literal, so each is listed verbatim in
    /// `RETRYABLE_SQL_STATES`. Listed individually so a future deletion
    /// fails the most relevant test.
    #[test]
    fn test_is_retryable_code_sqlite_busy_extended() {
        assert!(is_retryable_code("261")); // SQLITE_BUSY_RECOVERY
        assert!(is_retryable_code("517")); // SQLITE_BUSY_SNAPSHOT
        assert!(is_retryable_code("773")); // SQLITE_BUSY_TIMEOUT
    }

    /// SQLite extended codes for `SQLITE_LOCKED` (primary `6`).
    #[test]
    fn test_is_retryable_code_sqlite_locked_extended() {
        assert!(is_retryable_code("262")); // SQLITE_LOCKED_SHAREDCACHE
        assert!(is_retryable_code("518")); // SQLITE_LOCKED_VTAB
    }

    /// Primary `SQLITE_BUSY`/`SQLITE_LOCKED` as a bare digit also retries —
    /// catches both the documented intent of the constant and any sqlx
    /// version that ever returns the primary code directly.
    #[test]
    fn test_is_retryable_code_sqlite_primary_codes() {
        assert!(is_retryable_code("5"));
        assert!(is_retryable_code("6"));
    }

    /// Non-retryable SQLite codes must not match — `SQLITE_CONSTRAINT` (19)
    /// is a permanent error and must surface to the client.
    #[test]
    fn test_is_retryable_code_sqlite_constraint_not_retryable() {
        assert!(!is_retryable_code("19"));
    }

    /// `unique_violation` (Postgres 23505) is not retryable.
    #[test]
    fn test_is_retryable_code_postgres_unique_violation_not_retryable() {
        assert!(!is_retryable_code("23505"));
    }

    /// Garbage and empty strings must not match.
    #[test]
    fn test_is_retryable_code_garbage_inputs() {
        assert!(!is_retryable_code(""));
        assert!(!is_retryable_code("not-a-code"));
    }

    /// Regression for #454: Postgres SQLSTATEs that happen to share a low
    /// byte with `5`/`6` after `& 0xFF` masking were misclassified as
    /// retryable. Dropping the mask in favor of explicit enumeration
    /// eliminates the collision class.
    ///
    /// - `22021 & 0xFF = 5` (would have collided with `SQLITE_BUSY`)
    /// - `22022 & 0xFF = 6` (would have collided with `SQLITE_LOCKED`)
    /// - `42501 & 0xFF = 5` (would have collided with `SQLITE_BUSY`)
    #[test]
    fn test_is_retryable_code_no_postgres_false_positives() {
        assert!(!is_retryable_code("22021"));
        assert!(!is_retryable_code("22022"));
        assert!(!is_retryable_code("42501"));
    }

    /// Non-retryable Postgres SQLSTATEs continue to be rejected.
    #[test]
    fn test_is_retryable_code_numeric_postgres_does_not_alias() {
        assert!(!is_retryable_code("23505")); // unique_violation
        assert!(!is_retryable_code("42P07")); // duplicate_table
    }

    #[test]
    fn test_is_unique_violation_non_db() {
        let err = anyhow::anyhow!("some random error");
        assert!(!is_unique_violation(&err));
    }

    #[test]
    fn test_retry_backoff_increases() {
        let d0 = retry_backoff(0);
        let d1 = retry_backoff(1);
        let d2 = retry_backoff(2);
        // Base roughly doubles; allow wide range due to jitter
        assert!(d0.as_millis() <= 200);
        assert!(d1.as_millis() <= 400);
        assert!(d2.as_millis() <= 800);
    }

    // ========================================================================
    // RetryableError trait and with_dsql_retry! OCC tests
    // ========================================================================

    /// A minimal error type for testing with_dsql_retry! with a custom retryable variant.
    #[derive(Debug, PartialEq)]
    enum TestError {
        /// Retryable OCC conflict signal.
        OccConflict,
        /// Non-retryable business error.
        BusinessError(String),
    }

    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::OccConflict => write!(f, "OCC conflict"),
                Self::BusinessError(msg) => write!(f, "business error: {msg}"),
            }
        }
    }

    impl RetryableError for TestError {
        fn is_retryable(&self) -> bool {
            matches!(self, Self::OccConflict)
        }
    }

    /// Body returning OccConflict retries up to MAX_DSQL_RETRIES, then succeeds on
    /// a later attempt.
    #[tokio::test]
    async fn test_with_dsql_retry_occ_conflict_retries_then_succeeds() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let call_count = Arc::new(AtomicU32::new(0));
        let call_count2 = call_count.clone();

        // Fail with OccConflict on the first attempt, succeed on the second.
        let result: Result<u32, TestError> = crate::with_dsql_retry!(async {
            let n = call_count2.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                Err(TestError::OccConflict)
            } else {
                Ok(42)
            }
        });

        assert_eq!(result, Ok(42));
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            2,
            "must retry exactly once"
        );
    }

    /// Body returning a non-retryable BusinessError propagates immediately without retry.
    #[tokio::test]
    async fn test_with_dsql_retry_business_error_no_retry() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let call_count = Arc::new(AtomicU32::new(0));
        let call_count2 = call_count.clone();

        let result: Result<u32, TestError> = crate::with_dsql_retry!(async {
            call_count2.fetch_add(1, Ordering::SeqCst);
            Err(TestError::BusinessError("limit reached".to_string()))
        });

        assert_eq!(
            result,
            Err(TestError::BusinessError("limit reached".to_string()))
        );
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "must not retry on business error"
        );
    }

    /// anyhow::Error path: non-DB error is not retryable and propagates immediately.
    #[tokio::test]
    async fn test_with_dsql_retry_anyhow_non_retryable_propagates() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let call_count = Arc::new(AtomicU32::new(0));
        let call_count2 = call_count.clone();

        let result: Result<u32, anyhow::Error> = crate::with_dsql_retry!(async {
            call_count2.fetch_add(1, Ordering::SeqCst);
            Err(anyhow::anyhow!("some non-DB error"))
        });

        assert!(result.is_err());
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "must not retry on non-retryable anyhow error"
        );
    }

    /// OccConflict that never succeeds exhausts the retry budget and returns the error.
    #[tokio::test]
    async fn test_with_dsql_retry_occ_exhausts_budget() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let call_count = Arc::new(AtomicU32::new(0));
        let call_count2 = call_count.clone();

        let result: Result<u32, TestError> = crate::with_dsql_retry!(async {
            call_count2.fetch_add(1, Ordering::SeqCst);
            Err(TestError::OccConflict)
        });

        assert_eq!(result, Err(TestError::OccConflict));
        // Initial attempt + MAX_DSQL_RETRIES retries = MAX_DSQL_RETRIES + 1 total calls.
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            MAX_DSQL_RETRIES.saturating_add(1),
            "must attempt exactly MAX_DSQL_RETRIES + 1 times"
        );
    }
}
