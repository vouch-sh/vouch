// SPDX-License-Identifier: BUSL-1.1
//! Database compatibility layer for multi-database support.
//!
//! This module provides SQL syntax helpers that abstract over differences
//! between SQLite and PostgreSQL/Aurora DSQL at runtime.
//!
//! # SQLite vs PostgreSQL Syntax Differences
//!
//! | Feature | SQLite | PostgreSQL/DSQL |
//! |---------|--------|-----------------|
//! | Current timestamp | `strftime('%Y-%m-%dT%H:%M:%SZ', 'now')` | `NOW()` |
//! | Upsert ignore | `INSERT OR IGNORE` | `INSERT ... ON CONFLICT DO NOTHING` |
//! | Boolean literals | `0` / `1` | `FALSE` / `TRUE` |
//! | Parameter placeholders | `?` | `$1, $2, ...` |
//!
//! Note: SQLx handles parameter placeholder translation automatically,
//! so we only need to handle the other differences.
//!
//! # Sea-Query Integration
//!
//! This module also provides helpers for building type-safe queries using
//! `sea-query`. The `build_sql` function converts sea-query statements to
//! SQL strings for the appropriate database dialect.

use super::pool::DatabaseType;
use sea_query::{
    DeleteStatement, InsertStatement, PostgresQueryBuilder, SelectStatement, SqliteQueryBuilder,
    UpdateStatement,
};

/// Returns the SQL for inserting a row if it doesn't exist.
///
/// Returns the INSERT prefix to use. Caller must add the table, columns, and values.
///
/// - SQLite: `INSERT OR IGNORE INTO`
/// - PostgreSQL: `INSERT INTO` (requires `ON CONFLICT DO NOTHING` suffix)
#[must_use]
pub fn insert_or_ignore_prefix(db_type: DatabaseType) -> &'static str {
    match db_type {
        DatabaseType::Sqlite => "INSERT OR IGNORE INTO",
        DatabaseType::Postgres => "INSERT INTO",
    }
}

/// Returns the suffix needed for insert-or-ignore operations.
///
/// - SQLite: empty string (handled by INSERT OR IGNORE)
/// - PostgreSQL: `ON CONFLICT DO NOTHING`
#[must_use]
pub fn insert_or_ignore_suffix(db_type: DatabaseType) -> &'static str {
    match db_type {
        DatabaseType::Sqlite => "",
        DatabaseType::Postgres => " ON CONFLICT DO NOTHING",
    }
}

/// Builds a complete INSERT OR IGNORE statement.
///
/// # Arguments
///
/// * `db_type` - The database type to generate SQL for
/// * `table` - The table name
/// * `columns` - Comma-separated column names
/// * `values` - The VALUES clause (e.g., "?, ?, ?" or "$1, $2, $3")
///
/// # Example
///
/// ```ignore
/// let sql = build_insert_or_ignore(DatabaseType::Sqlite, "users", "id, email, name", "?, ?, ?");
/// // SQLite: "INSERT OR IGNORE INTO users (id, email, name) VALUES (?, ?, ?)"
///
/// let sql = build_insert_or_ignore(DatabaseType::Postgres, "users", "id, email", "?, ?");
/// // PostgreSQL: "INSERT INTO users (id, email) VALUES (?, ?) ON CONFLICT DO NOTHING"
/// ```
#[must_use]
pub fn build_insert_or_ignore(
    db_type: DatabaseType,
    table: &str,
    columns: &str,
    values: &str,
) -> String {
    format!(
        "{} {} ({}) VALUES ({}){}",
        insert_or_ignore_prefix(db_type),
        table,
        columns,
        values,
        insert_or_ignore_suffix(db_type)
    )
}

/// Builds an UPSERT statement (INSERT ... ON CONFLICT ... DO UPDATE).
///
/// # Arguments
///
/// * `db_type` - The database type to generate SQL for
/// * `table` - The table name
/// * `columns` - Comma-separated column names
/// * `values` - The VALUES clause placeholders
/// * `conflict_column` - The column(s) to check for conflicts
/// * `update_expr` - The SET clause for updates (e.g., "value = excluded.value")
///
/// # Example
///
/// ```ignore
/// let sql = build_upsert(
///     DatabaseType::Sqlite,
///     "server_config",
///     "key, value, updated_at",
///     "?, ?, datetime('now')",
///     "key",
///     "value = excluded.value, updated_at = excluded.updated_at"
/// );
/// ```
#[must_use]
pub fn build_upsert(
    _db_type: DatabaseType,
    table: &str,
    columns: &str,
    values: &str,
    conflict_column: &str,
    update_expr: &str,
) -> String {
    // Both SQLite and PostgreSQL use the same ON CONFLICT syntax for upsert
    format!(
        "INSERT INTO {} ({}) VALUES ({}) ON CONFLICT({}) DO UPDATE SET {}",
        table, columns, values, conflict_column, update_expr
    )
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_insert_or_ignore_sqlite() {
        let sql = build_insert_or_ignore(DatabaseType::Sqlite, "users", "id, email", "?, ?");
        assert_eq!(sql, "INSERT OR IGNORE INTO users (id, email) VALUES (?, ?)");
    }

    #[test]
    fn test_build_insert_or_ignore_postgres() {
        let sql = build_insert_or_ignore(DatabaseType::Postgres, "users", "id, email", "?, ?");
        assert_eq!(
            sql,
            "INSERT INTO users (id, email) VALUES (?, ?) ON CONFLICT DO NOTHING"
        );
    }

    #[test]
    fn test_build_upsert_sqlite() {
        let sql = build_upsert(
            DatabaseType::Sqlite,
            "config",
            "key, value",
            "?, ?",
            "key",
            "value = excluded.value",
        );
        assert_eq!(
            sql,
            "INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
        );
    }

    #[test]
    fn test_build_upsert_postgres() {
        let sql = build_upsert(
            DatabaseType::Postgres,
            "config",
            "key, value",
            "?, ?",
            "key",
            "value = excluded.value",
        );
        assert_eq!(
            sql,
            "INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
        );
    }
}
