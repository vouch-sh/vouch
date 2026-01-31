// SPDX-License-Identifier: BUSL-1.1
//! Pending OAuth authorization database operations.
//!
//! Implements storage for OAuth authorization requests during browser login flow
//! per RFC 6749 and RFC 9700 security best practices.

use anyhow::Result;
use jiff::{Span, Timestamp};
use sqlx::SqlitePool;
use uuid::Uuid;

/// Pending OAuth authorization record.
///
/// Stores OAuth authorization request parameters server-side during the browser
/// login flow to prevent parameter tampering (RFC 9700).
#[derive(Debug, sqlx::FromRow)]
pub struct PendingOAuthAuthorization {
    pub id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub state: Option<String>,
    pub scope: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub consumed_at: Option<String>,
}

/// Parameters for creating a pending OAuth authorization.
#[derive(Debug)]
pub struct CreatePendingOAuthParams<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub response_type: &'a str,
    pub state: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
}

/// Create a pending OAuth authorization.
///
/// Returns the ID of the created record which should be passed to the login page.
/// The pending authorization expires after 10 minutes.
pub async fn create_pending_oauth_authorization(
    pool: &SqlitePool,
    params: CreatePendingOAuthParams<'_>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();
    let now = Timestamp::now();
    let expires_at = now
        .checked_add(Span::new().minutes(10))
        .unwrap_or(now)
        .to_string();

    sqlx::query(
        r"INSERT INTO pending_oauth_authorizations
            (id, client_id, redirect_uri, response_type, state, scope, nonce,
             code_challenge, code_challenge_method, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(params.client_id)
    .bind(params.redirect_uri)
    .bind(params.response_type)
    .bind(params.state)
    .bind(params.scope)
    .bind(params.nonce)
    .bind(params.code_challenge)
    .bind(params.code_challenge_method)
    .bind(&expires_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get a pending OAuth authorization by ID.
///
/// Returns None if not found, expired, or already consumed.
pub async fn get_pending_oauth_authorization(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<PendingOAuthAuthorization>> {
    let now = Timestamp::now().to_string();

    let record = sqlx::query_as::<_, PendingOAuthAuthorization>(
        r"SELECT id, client_id, redirect_uri, response_type, state, scope, nonce,
                 code_challenge, code_challenge_method, created_at, expires_at, consumed_at
         FROM pending_oauth_authorizations
         WHERE id = ? AND expires_at > ? AND consumed_at IS NULL",
    )
    .bind(id)
    .bind(&now)
    .fetch_optional(pool)
    .await?;

    Ok(record)
}

/// Consume a pending OAuth authorization (single-use).
///
/// Marks the authorization as consumed and returns it if valid.
/// Returns None if not found, expired, or already consumed.
pub async fn consume_pending_oauth_authorization(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<PendingOAuthAuthorization>> {
    let now = Timestamp::now().to_string();

    // First, get the record if it's valid
    let record = get_pending_oauth_authorization(pool, id).await?;

    if record.is_some() {
        // Mark as consumed
        sqlx::query("UPDATE pending_oauth_authorizations SET consumed_at = ? WHERE id = ?")
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await?;
    }

    Ok(record)
}

/// Delete expired pending OAuth authorizations.
///
/// Called by the cleanup task to remove old records.
pub async fn delete_expired_pending_oauth_authorizations(
    pool: &SqlitePool,
    now: &str,
) -> Result<u64> {
    let result = sqlx::query("DELETE FROM pending_oauth_authorizations WHERE expires_at < ?")
        .bind(now)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn test_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();

        sqlx::migrate!("./migrations").run(&pool).await.unwrap();

        pool
    }

    #[tokio::test]
    async fn test_create_and_get_pending_oauth() {
        let pool = test_pool().await;

        let params = CreatePendingOAuthParams {
            client_id: "test-client",
            redirect_uri: "https://example.com/callback",
            response_type: "code",
            state: Some("state123"),
            scope: Some("openid email"),
            nonce: Some("nonce456"),
            code_challenge: Some("challenge789"),
            code_challenge_method: Some("S256"),
        };

        let id = create_pending_oauth_authorization(&pool, params).await.unwrap();

        let record = get_pending_oauth_authorization(&pool, &id).await.unwrap();
        assert!(record.is_some());

        let record = record.unwrap();
        assert_eq!(record.client_id, "test-client");
        assert_eq!(record.redirect_uri, "https://example.com/callback");
        assert_eq!(record.state, Some("state123".to_string()));
        assert_eq!(record.code_challenge, Some("challenge789".to_string()));
    }

    #[tokio::test]
    async fn test_consume_pending_oauth_single_use() {
        let pool = test_pool().await;

        let params = CreatePendingOAuthParams {
            client_id: "test-client",
            redirect_uri: "https://example.com/callback",
            response_type: "code",
            state: None,
            scope: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
        };

        let id = create_pending_oauth_authorization(&pool, params).await.unwrap();

        // First consume should succeed
        let record = consume_pending_oauth_authorization(&pool, &id).await.unwrap();
        assert!(record.is_some());

        // Second consume should fail (already consumed)
        let record = consume_pending_oauth_authorization(&pool, &id).await.unwrap();
        assert!(record.is_none());
    }

    #[tokio::test]
    async fn test_get_nonexistent_pending_oauth() {
        let pool = test_pool().await;

        let record = get_pending_oauth_authorization(&pool, "nonexistent-id")
            .await
            .unwrap();
        assert!(record.is_none());
    }
}
