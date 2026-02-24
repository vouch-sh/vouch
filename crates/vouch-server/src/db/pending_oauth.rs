// SPDX-License-Identifier: BUSL-1.1
//! Pending OAuth authorization database operations.
//!
//! Implements storage for OAuth authorization requests during browser login flow
//! per RFC 6749 and RFC 9700 security best practices.

use super::Pool;
use super::schema::PendingOAuthAuthorizations;
use super::types::BuildSql;
use super::types::DbTimestamp;
use crate::{db_execute, db_fetch_optional};
use anyhow::Result;
use jiff::{Span, Timestamp};
use sea_query::{Expr, Query};
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
    pub created_at: DbTimestamp,
    pub expires_at: DbTimestamp,
    pub consumed_at: Option<DbTimestamp>,
    /// RFC 8707: Resource indicator from authorization request.
    pub resource: Option<String>,
    /// RFC 9470: Requested authentication context class references.
    pub acr_values: Option<String>,
    /// RFC 9470: Maximum authentication age in seconds.
    pub max_age: Option<i64>,
    /// RFC 9470: Requested prompt behavior (e.g., "login", "none").
    pub prompt: Option<String>,
    /// RFC 9449 / FAPI 2.0: DPoP key thumbprint bound at PAR time.
    ///
    /// Preserved from the original PAR record so that the DPoP key binding
    /// survives the browser login redirect and can be embedded in the
    /// authorization code at completion.
    pub dpop_jkt: Option<String>,
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
    /// RFC 8707: Resource indicator from authorization request.
    pub resource: Option<&'a str>,
    /// RFC 9470: Requested authentication context class references.
    pub acr_values: Option<&'a str>,
    /// RFC 9470: Maximum authentication age in seconds.
    pub max_age: Option<i64>,
    /// RFC 9470: Requested prompt behavior.
    pub prompt: Option<&'a str>,
    /// RFC 9449 / FAPI 2.0: DPoP key thumbprint for authorization code binding.
    pub dpop_jkt: Option<&'a str>,
}

/// Create a pending OAuth authorization.
///
/// Returns the ID of the created record which should be passed to the login page.
/// The pending authorization expires after 10 minutes.
///
/// # Errors
///
/// Returns an error if the database operation fails or if the time calculation overflows.
pub async fn create_pending_oauth_authorization(
    pool: &Pool,
    params: CreatePendingOAuthParams<'_>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();
    let db_type = pool.db_type();
    let now = Timestamp::now();
    let expires_at = now
        .checked_add(Span::new().minutes(10))
        .map_err(|_| anyhow::anyhow!("Time calculation overflow when computing expiration"))?
        .to_string();

    let created_at = now.to_string();
    let sql = {
        let query = Query::insert()
            .into_table(PendingOAuthAuthorizations::Table)
            .columns([
                PendingOAuthAuthorizations::Id,
                PendingOAuthAuthorizations::ClientId,
                PendingOAuthAuthorizations::RedirectUri,
                PendingOAuthAuthorizations::ResponseType,
                PendingOAuthAuthorizations::State,
                PendingOAuthAuthorizations::Scope,
                PendingOAuthAuthorizations::Nonce,
                PendingOAuthAuthorizations::CodeChallenge,
                PendingOAuthAuthorizations::CodeChallengeMethod,
                PendingOAuthAuthorizations::Resource,
                PendingOAuthAuthorizations::AcrValues,
                PendingOAuthAuthorizations::MaxAge,
                PendingOAuthAuthorizations::Prompt,
                PendingOAuthAuthorizations::DpopJkt,
                PendingOAuthAuthorizations::CreatedAt,
                PendingOAuthAuthorizations::ExpiresAt,
            ])
            .values_panic([
                id.clone().into(),
                params.client_id.into(),
                params.redirect_uri.into(),
                params.response_type.into(),
                params.state.into(),
                params.scope.into(),
                params.nonce.into(),
                params.code_challenge.into(),
                params.code_challenge_method.into(),
                params.resource.into(),
                params.acr_values.into(),
                params.max_age.into(),
                params.prompt.into(),
                params.dpop_jkt.into(),
                created_at.as_str().into(),
                expires_at.as_str().into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(id)
}

/// Get a pending OAuth authorization by ID.
///
/// Returns None if not found, expired, or already consumed.
pub async fn get_pending_oauth_authorization(
    pool: &Pool,
    id: &str,
) -> Result<Option<PendingOAuthAuthorization>> {
    let now = Timestamp::now().to_string();
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                PendingOAuthAuthorizations::Id,
                PendingOAuthAuthorizations::ClientId,
                PendingOAuthAuthorizations::RedirectUri,
                PendingOAuthAuthorizations::ResponseType,
                PendingOAuthAuthorizations::State,
                PendingOAuthAuthorizations::Scope,
                PendingOAuthAuthorizations::Nonce,
                PendingOAuthAuthorizations::CodeChallenge,
                PendingOAuthAuthorizations::CodeChallengeMethod,
                PendingOAuthAuthorizations::CreatedAt,
                PendingOAuthAuthorizations::ExpiresAt,
                PendingOAuthAuthorizations::ConsumedAt,
                PendingOAuthAuthorizations::Resource,
                PendingOAuthAuthorizations::AcrValues,
                PendingOAuthAuthorizations::MaxAge,
                PendingOAuthAuthorizations::Prompt,
                PendingOAuthAuthorizations::DpopJkt,
            ])
            .from(PendingOAuthAuthorizations::Table)
            .and_where(Expr::col(PendingOAuthAuthorizations::Id).eq(id))
            .and_where(Expr::col(PendingOAuthAuthorizations::ExpiresAt).gt(&now))
            .and_where(Expr::col(PendingOAuthAuthorizations::ConsumedAt).is_null())
            .to_owned();
        query.build_sql(db_type)
    };

    let record = db_fetch_optional!(pool, sqlx::query_as::<_, PendingOAuthAuthorization>(&sql))?;

    Ok(record)
}

/// Consume a pending OAuth authorization (single-use).
///
/// Atomically marks the authorization as consumed and returns it if valid.
/// Returns None if not found, expired, or already consumed.
///
/// This function uses an atomic UPDATE with WHERE clause to prevent TOCTOU
/// race conditions where two concurrent requests could both consume the same
/// authorization.
pub async fn consume_pending_oauth_authorization(
    pool: &Pool,
    id: &str,
) -> Result<Option<PendingOAuthAuthorization>> {
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    // Atomically attempt to consume the authorization.
    // The WHERE clause ensures only one request can succeed for a given ID.
    let update_sql = {
        let query = Query::update()
            .table(PendingOAuthAuthorizations::Table)
            .value(PendingOAuthAuthorizations::ConsumedAt, now.as_str())
            .and_where(Expr::col(PendingOAuthAuthorizations::Id).eq(id))
            .and_where(Expr::col(PendingOAuthAuthorizations::ExpiresAt).gt(now.as_str()))
            .and_where(Expr::col(PendingOAuthAuthorizations::ConsumedAt).is_null())
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&update_sql))?;

    // If no rows were affected, the authorization doesn't exist,
    // was expired, or was already consumed
    if result.rows_affected() == 0 {
        return Ok(None);
    }

    // Successfully consumed - now fetch the record
    let db_type = pool.db_type();
    let sql = {
        let query = Query::select()
            .columns([
                PendingOAuthAuthorizations::Id,
                PendingOAuthAuthorizations::ClientId,
                PendingOAuthAuthorizations::RedirectUri,
                PendingOAuthAuthorizations::ResponseType,
                PendingOAuthAuthorizations::State,
                PendingOAuthAuthorizations::Scope,
                PendingOAuthAuthorizations::Nonce,
                PendingOAuthAuthorizations::CodeChallenge,
                PendingOAuthAuthorizations::CodeChallengeMethod,
                PendingOAuthAuthorizations::CreatedAt,
                PendingOAuthAuthorizations::ExpiresAt,
                PendingOAuthAuthorizations::ConsumedAt,
                PendingOAuthAuthorizations::Resource,
                PendingOAuthAuthorizations::AcrValues,
                PendingOAuthAuthorizations::MaxAge,
                PendingOAuthAuthorizations::Prompt,
                PendingOAuthAuthorizations::DpopJkt,
            ])
            .from(PendingOAuthAuthorizations::Table)
            .and_where(Expr::col(PendingOAuthAuthorizations::Id).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };

    let record = db_fetch_optional!(pool, sqlx::query_as::<_, PendingOAuthAuthorization>(&sql))?;

    Ok(record)
}

/// Delete expired pending OAuth authorizations.
///
/// Called by the cleanup task to remove old records.
pub async fn delete_expired_pending_oauth_authorizations(pool: &Pool, now: &str) -> Result<u64> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::delete()
            .from_table(PendingOAuthAuthorizations::Table)
            .and_where(Expr::col(PendingOAuthAuthorizations::ExpiresAt).lt(now))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    async fn test_pool() -> Pool {
        let pool = Pool::connect("sqlite::memory:").await.unwrap();

        match &pool {
            Pool::Sqlite(p) => sqlx::migrate!("./migrations/sqlite").run(p).await.unwrap(),
            Pool::Postgres(p) => sqlx::migrate!("./migrations/postgres")
                .run(p)
                .await
                .unwrap(),
        }

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
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: None,
            dpop_jkt: None,
        };

        let id = create_pending_oauth_authorization(&pool, params)
            .await
            .unwrap();

        let record = get_pending_oauth_authorization(&pool, &id).await.unwrap();
        assert!(record.is_some());

        let record = record.unwrap();
        assert_eq!(record.client_id, "test-client");
        assert_eq!(record.redirect_uri, "https://example.com/callback");
        assert_eq!(record.state, Some("state123".to_string()));
        assert_eq!(record.code_challenge, Some("challenge789".to_string()));
        assert_eq!(record.dpop_jkt, None);
    }

    #[tokio::test]
    async fn test_pending_oauth_with_dpop_jkt() {
        let pool = test_pool().await;

        let params = CreatePendingOAuthParams {
            client_id: "test-client",
            redirect_uri: "https://example.com/callback",
            response_type: "code",
            state: None,
            scope: Some("openid"),
            nonce: None,
            code_challenge: Some("challenge"),
            code_challenge_method: Some("S256"),
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: None,
            dpop_jkt: Some("thumbprint123"),
        };

        let id = create_pending_oauth_authorization(&pool, params)
            .await
            .unwrap();

        let record = consume_pending_oauth_authorization(&pool, &id)
            .await
            .unwrap();
        assert!(record.is_some());

        let record = record.unwrap();
        assert_eq!(record.dpop_jkt, Some("thumbprint123".to_string()));
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
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: None,
            dpop_jkt: None,
        };

        let id = create_pending_oauth_authorization(&pool, params)
            .await
            .unwrap();

        // First consume should succeed
        let record = consume_pending_oauth_authorization(&pool, &id)
            .await
            .unwrap();
        assert!(record.is_some());

        // Second consume should fail (already consumed)
        let record = consume_pending_oauth_authorization(&pool, &id)
            .await
            .unwrap();
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
