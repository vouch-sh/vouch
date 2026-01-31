// SPDX-License-Identifier: BUSL-1.1
//! Database error types.
//!
//! Note: Currently the db module functions return `anyhow::Result` for compatibility
//! with the existing codebase. This module is prepared for future migration to
//! more specific error types.

/// Database operation errors.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// SQLx database error.
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    /// Entity not found.
    #[error("not found: {entity}")]
    NotFound {
        /// The type of entity that was not found.
        entity: &'static str,
    },

    /// Invalid data.
    #[error("invalid data: {0}")]
    InvalidData(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Result type for database operations.
pub type DbResult<T> = Result<T, DbError>;
