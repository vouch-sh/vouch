// SPDX-License-Identifier: BUSL-1.1
//! Sea-Query integration helpers.
//!
//! Provides the `BuildSql` trait for converting sea-query statements to SQL
//! strings for the appropriate database dialect (SQLite or PostgreSQL).
//!
//! Timestamps are stored as ISO 8601 strings inside document JSON and the
//! `audit_events.created_at` column. The old `DbTimestamp` type alias
//! (`jiff_sqlx::Timestamp`) is no longer needed.

use super::pool::DatabaseType;
use sea_query::{
    DeleteStatement, InsertStatement, PostgresQueryBuilder, SelectStatement, SqliteQueryBuilder,
    UpdateStatement,
};

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
