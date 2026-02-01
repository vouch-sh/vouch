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
//! ```

use anyhow::{Result, bail};

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
    /// Connect to a database using the URL scheme to determine the backend.
    ///
    /// # Arguments
    ///
    /// * `url` - Database URL with scheme prefix (`sqlite:`, `postgres:`, or `postgresql:`)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The URL scheme is not supported
    /// - The connection fails
    pub async fn connect(url: &str) -> Result<Self> {
        let db_type = DatabaseType::from_url(url)?;

        match db_type {
            DatabaseType::Sqlite => {
                let pool = sqlx::SqlitePool::connect(url).await?;
                Ok(Self::Sqlite(pool))
            }
            DatabaseType::Postgres => {
                let pool = sqlx::PgPool::connect(url).await?;
                Ok(Self::Postgres(pool))
            }
        }
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
