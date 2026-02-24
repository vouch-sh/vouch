// SPDX-License-Identifier: BUSL-1.1
//! Pushed Authorization Request (PAR) database operations (RFC 9126).
//!
//! Stores authorization request parameters pushed by authenticated clients
//! before the browser-based authorization flow begins.

use super::Pool;
use super::schema::PushedAuthorizationRequests;
use super::types::BuildSql;
use super::types::DbTimestamp;
use crate::{db_execute, db_fetch_optional};
use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};
use sea_query::{Expr, Query};
use uuid::Uuid;

/// PAR lifetime in seconds (RFC 9126 Section 2.2).
///
/// 60 seconds is sufficient for the client to receive the `request_uri`
/// and redirect the user to the authorization endpoint.
pub const PAR_EXPIRES_IN: i64 = 60;

/// Pushed authorization request record.
///
/// Stores OAuth authorization request parameters server-side during the PAR
/// flow (RFC 9126). The `request_uri` is returned to the client and later
/// resolved at the authorization endpoint.
#[derive(Debug, sqlx::FromRow)]
pub struct PushedAuthorizationRequest {
    pub id: String,
    pub request_uri: String,
    pub client_id: String,
    pub response_type: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    /// RFC 8707: Resource indicator from authorization request.
    pub resource: Option<String>,
    /// RFC 9470: Requested authentication context class references.
    pub acr_values: Option<String>,
    /// RFC 9470: Maximum authentication age in seconds.
    pub max_age: Option<i64>,
    /// RFC 9470: Requested prompt behavior.
    pub prompt: Option<String>,
    pub created_at: DbTimestamp,
    pub expires_at: DbTimestamp,
    pub consumed_at: Option<DbTimestamp>,
}

/// Parameters for creating a pushed authorization request.
#[derive(Debug)]
pub struct CreateParParams<'a> {
    pub client_id: &'a str,
    pub response_type: &'a str,
    pub redirect_uri: &'a str,
    pub scope: Option<&'a str>,
    pub state: Option<&'a str>,
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
}

/// Generate a cryptographically random `request_uri` per RFC 9126 Section 2.2.
///
/// Format: `urn:ietf:params:oauth:request_uri:<base64url-encoded-random>`
///
/// Uses 32 bytes of randomness (256 bits) from `aws_lc_rs::rand` for
/// sufficient entropy to prevent guessing.
///
/// # Errors
///
/// Returns an error if the CSPRNG fails.
fn generate_request_uri() -> Result<String> {
    let mut buf = [0u8; 32];
    aws_lc_rs::rand::fill(&mut buf)
        .map_err(|_| anyhow::anyhow!("Failed to generate random bytes for request_uri"))?;
    let encoded = URL_SAFE_NO_PAD.encode(buf);
    Ok(format!("urn:ietf:params:oauth:request_uri:{encoded}"))
}

/// Create a pushed authorization request.
///
/// Returns `(id, request_uri)` for the created record.
/// The PAR expires after [`PAR_EXPIRES_IN`] seconds.
///
/// # Errors
///
/// Returns an error if the database operation fails or if the time
/// calculation overflows.
pub async fn create_pushed_authorization_request(
    pool: &Pool,
    params: CreateParParams<'_>,
) -> Result<(String, String)> {
    let id = Uuid::now_v7().to_string();
    let request_uri = generate_request_uri()?;
    let db_type = pool.db_type();
    let now = Timestamp::now();
    let expires_at = now
        .checked_add(Span::new().seconds(PAR_EXPIRES_IN))
        .map_err(|_| anyhow::anyhow!("Time calculation overflow when computing PAR expiration"))?
        .to_string();

    let created_at = now.to_string();
    let sql = {
        let query = Query::insert()
            .into_table(PushedAuthorizationRequests::Table)
            .columns([
                PushedAuthorizationRequests::Id,
                PushedAuthorizationRequests::RequestUri,
                PushedAuthorizationRequests::ClientId,
                PushedAuthorizationRequests::ResponseType,
                PushedAuthorizationRequests::RedirectUri,
                PushedAuthorizationRequests::Scope,
                PushedAuthorizationRequests::State,
                PushedAuthorizationRequests::Nonce,
                PushedAuthorizationRequests::CodeChallenge,
                PushedAuthorizationRequests::CodeChallengeMethod,
                PushedAuthorizationRequests::Resource,
                PushedAuthorizationRequests::AcrValues,
                PushedAuthorizationRequests::MaxAge,
                PushedAuthorizationRequests::Prompt,
                PushedAuthorizationRequests::CreatedAt,
                PushedAuthorizationRequests::ExpiresAt,
            ])
            .values_panic([
                id.clone().into(),
                request_uri.clone().into(),
                params.client_id.into(),
                params.response_type.into(),
                params.redirect_uri.into(),
                params.scope.into(),
                params.state.into(),
                params.nonce.into(),
                params.code_challenge.into(),
                params.code_challenge_method.into(),
                params.resource.into(),
                params.acr_values.into(),
                params.max_age.into(),
                params.prompt.into(),
                created_at.as_str().into(),
                expires_at.as_str().into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok((id, request_uri))
}

/// Consume a pushed authorization request (single-use).
///
/// Atomically marks the PAR as consumed and returns it if valid.
/// Returns `None` if not found, expired, already consumed, or bound to a
/// different client.
///
/// # Client Binding
///
/// RFC 9126 Section 2.3: The authorization server MUST validate that the
/// `client_id` form parameter matches the `client_id` that was used when
/// the `request_uri` was created. This prevents cross-client use.
pub async fn consume_pushed_authorization_request(
    pool: &Pool,
    request_uri: &str,
    client_id: &str,
) -> Result<Option<PushedAuthorizationRequest>> {
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    // Atomically attempt to consume the PAR.
    // The WHERE clause ensures only one request can succeed for a given request_uri
    // and validates client binding + expiry + single-use.
    let update_sql = {
        let query = Query::update()
            .table(PushedAuthorizationRequests::Table)
            .value(PushedAuthorizationRequests::ConsumedAt, now.as_str())
            .and_where(Expr::col(PushedAuthorizationRequests::RequestUri).eq(request_uri))
            .and_where(Expr::col(PushedAuthorizationRequests::ClientId).eq(client_id))
            .and_where(Expr::col(PushedAuthorizationRequests::ExpiresAt).gt(now.as_str()))
            .and_where(Expr::col(PushedAuthorizationRequests::ConsumedAt).is_null())
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&update_sql))?;

    // If no rows were affected, the PAR doesn't exist,
    // was expired, was already consumed, or had a different client_id
    if result.rows_affected() == 0 {
        return Ok(None);
    }

    // Successfully consumed — fetch the record
    let db_type = pool.db_type();
    let sql = {
        let query = Query::select()
            .columns([
                PushedAuthorizationRequests::Id,
                PushedAuthorizationRequests::RequestUri,
                PushedAuthorizationRequests::ClientId,
                PushedAuthorizationRequests::ResponseType,
                PushedAuthorizationRequests::RedirectUri,
                PushedAuthorizationRequests::Scope,
                PushedAuthorizationRequests::State,
                PushedAuthorizationRequests::Nonce,
                PushedAuthorizationRequests::CodeChallenge,
                PushedAuthorizationRequests::CodeChallengeMethod,
                PushedAuthorizationRequests::Resource,
                PushedAuthorizationRequests::AcrValues,
                PushedAuthorizationRequests::MaxAge,
                PushedAuthorizationRequests::Prompt,
                PushedAuthorizationRequests::CreatedAt,
                PushedAuthorizationRequests::ExpiresAt,
                PushedAuthorizationRequests::ConsumedAt,
            ])
            .from(PushedAuthorizationRequests::Table)
            .and_where(Expr::col(PushedAuthorizationRequests::RequestUri).eq(request_uri))
            .to_owned();
        query.build_sql(db_type)
    };

    let record = db_fetch_optional!(pool, sqlx::query_as::<_, PushedAuthorizationRequest>(&sql))?;

    Ok(record)
}

/// Delete expired pushed authorization requests.
///
/// Called by the cleanup task to remove old records.
pub async fn delete_expired_pushed_authorization_requests(pool: &Pool, now: &str) -> Result<u64> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::delete()
            .from_table(PushedAuthorizationRequests::Table)
            .and_where(Expr::col(PushedAuthorizationRequests::ExpiresAt).lt(now))
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
    async fn test_create_and_consume_par() {
        let pool = test_pool().await;

        let params = CreateParParams {
            client_id: "test-client",
            response_type: "code",
            redirect_uri: "https://example.com/callback",
            scope: Some("openid email"),
            state: Some("state123"),
            nonce: Some("nonce456"),
            code_challenge: Some("challenge789"),
            code_challenge_method: Some("S256"),
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: None,
        };

        let (_id, request_uri) = create_pushed_authorization_request(&pool, params)
            .await
            .unwrap();

        assert!(request_uri.starts_with("urn:ietf:params:oauth:request_uri:"));

        // Consume should succeed
        let record = consume_pushed_authorization_request(&pool, &request_uri, "test-client")
            .await
            .unwrap();
        assert!(record.is_some());

        let record = record.unwrap();
        assert_eq!(record.client_id, "test-client");
        assert_eq!(record.redirect_uri, "https://example.com/callback");
        assert_eq!(record.scope, Some("openid email".to_string()));
        assert_eq!(record.state, Some("state123".to_string()));
        assert_eq!(record.code_challenge, Some("challenge789".to_string()));
    }

    #[tokio::test]
    async fn test_par_single_use_enforcement() {
        let pool = test_pool().await;

        let params = CreateParParams {
            client_id: "test-client",
            response_type: "code",
            redirect_uri: "https://example.com/callback",
            scope: None,
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: None,
        };

        let (_id, request_uri) = create_pushed_authorization_request(&pool, params)
            .await
            .unwrap();

        // First consume should succeed
        let record = consume_pushed_authorization_request(&pool, &request_uri, "test-client")
            .await
            .unwrap();
        assert!(record.is_some());

        // Second consume should fail (already consumed)
        let record = consume_pushed_authorization_request(&pool, &request_uri, "test-client")
            .await
            .unwrap();
        assert!(record.is_none());
    }

    #[tokio::test]
    async fn test_par_client_binding() {
        let pool = test_pool().await;

        let params = CreateParParams {
            client_id: "client-a",
            response_type: "code",
            redirect_uri: "https://example.com/callback",
            scope: None,
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: None,
        };

        let (_id, request_uri) = create_pushed_authorization_request(&pool, params)
            .await
            .unwrap();

        // Consume with wrong client_id should fail
        let record = consume_pushed_authorization_request(&pool, &request_uri, "client-b")
            .await
            .unwrap();
        assert!(record.is_none());

        // Consume with correct client_id should succeed
        let record = consume_pushed_authorization_request(&pool, &request_uri, "client-a")
            .await
            .unwrap();
        assert!(record.is_some());
    }

    #[tokio::test]
    async fn test_par_nonexistent_request_uri() {
        let pool = test_pool().await;

        let record = consume_pushed_authorization_request(
            &pool,
            "urn:ietf:params:oauth:request_uri:nonexistent",
            "test-client",
        )
        .await
        .unwrap();
        assert!(record.is_none());
    }

    #[tokio::test]
    async fn test_generate_request_uri_format() {
        let uri = generate_request_uri().unwrap();
        assert!(uri.starts_with("urn:ietf:params:oauth:request_uri:"));
        // 32 bytes base64url-encoded = 43 chars
        let suffix = uri
            .strip_prefix("urn:ietf:params:oauth:request_uri:")
            .unwrap();
        assert_eq!(suffix.len(), 43);
    }
}
