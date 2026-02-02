// SPDX-License-Identifier: BUSL-1.1
//! Database type aliases and conversions for DSQL compatibility.
//!
//! This module provides types that work with both SQLite and PostgreSQL.
//! The key type is `DbTimestamp` which uses `jiff_sqlx::Timestamp` to handle
//! timestamp serialization/deserialization correctly for both databases.
//!
//! # Why This Exists
//!
//! SQLite stores timestamps as TEXT strings, while PostgreSQL uses TIMESTAMPTZ.
//! Using `String` for timestamp fields works with SQLite but fails with Postgres
//! because TIMESTAMPTZ doesn't auto-convert to String.
//!
//! `jiff_sqlx::Timestamp` implements `sqlx::Type`, `sqlx::Encode`, and `sqlx::Decode`
//! for both database backends, automatically handling the conversion.
//!
//! # Sea-Query Integration
//!
//! This module also provides the `BuildSql` trait for converting sea-query statements
//! to SQL strings for the appropriate database dialect.

use super::pool::DatabaseType;
use sea_query::{
    DeleteStatement, InsertStatement, PostgresQueryBuilder, SelectStatement, SqliteQueryBuilder,
    UpdateStatement,
};

/// Database timestamp type that works with both SQLite and PostgreSQL.
///
/// This type implements sqlx traits for both backends:
/// - SQLite: Stored as TEXT in RFC 3339 format
/// - PostgreSQL: Stored as TIMESTAMPTZ
///
/// # Usage
///
/// ```ignore
/// #[derive(sqlx::FromRow)]
/// pub struct MyRecord {
///     pub created_at: DbTimestamp,
///     pub expires_at: Option<DbTimestamp>,
/// }
/// ```
///
/// To convert to `jiff::Timestamp`:
/// ```ignore
/// let ts: jiff::Timestamp = record.created_at.to_jiff();
/// ```
///
/// To create from `jiff::Timestamp`:
/// ```ignore
/// use jiff_sqlx::ToSqlx;
/// let db_ts: DbTimestamp = jiff::Timestamp::now().to_sqlx();
/// ```
pub type DbTimestamp = jiff_sqlx::Timestamp;

/// Extension trait for converting jiff timestamps to database timestamps.
///
/// Re-exported from jiff_sqlx for convenience.
pub use jiff_sqlx::ToSqlx;

// ============================================================================
// Sea-Query Integration Helpers
// ============================================================================

/// Trait for converting sea-query statements to SQL strings based on database type.
pub trait BuildSql {
    /// Build the SQL string for the given database type.
    fn build_sql(&self, db_type: DatabaseType) -> String;
}

impl BuildSql for InsertStatement {
    fn build_sql(&self, db_type: DatabaseType) -> String {
        match db_type {
            DatabaseType::Sqlite => self.to_string(SqliteQueryBuilder),
            DatabaseType::Postgres => self.to_string(PostgresQueryBuilder),
        }
    }
}

impl BuildSql for SelectStatement {
    fn build_sql(&self, db_type: DatabaseType) -> String {
        match db_type {
            DatabaseType::Sqlite => self.to_string(SqliteQueryBuilder),
            DatabaseType::Postgres => self.to_string(PostgresQueryBuilder),
        }
    }
}

impl BuildSql for UpdateStatement {
    fn build_sql(&self, db_type: DatabaseType) -> String {
        match db_type {
            DatabaseType::Sqlite => self.to_string(SqliteQueryBuilder),
            DatabaseType::Postgres => self.to_string(PostgresQueryBuilder),
        }
    }
}

impl BuildSql for DeleteStatement {
    fn build_sql(&self, db_type: DatabaseType) -> String {
        match db_type {
            DatabaseType::Sqlite => self.to_string(SqliteQueryBuilder),
            DatabaseType::Postgres => self.to_string(PostgresQueryBuilder),
        }
    }
}
