// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OAuth Client Application database operations.

use super::audit::{AuditEventFilter, AuditStore};
use super::document_type::{Document, DocumentType};
use super::documents::audit::OAuthUsageData;
use super::documents::jwt_assertion_jti::JwtAssertionJtiDoc;
use super::documents::oauth::{
    AccessScope, FapiProfile, JwsAlgorithm, OAuthClientDoc, OAuthClientSecretDoc, OAuthClientType,
    RegistrationSource, TokenEndpointAuthMethod,
};
use super::store::DocumentStore;
use crate::services::error::ServiceError;
use anyhow::Result;
use axum::http::StatusCode;
use jiff::Timestamp;

/// Maximum number of active (non-revoked, non-expired) secrets per OAuth client.
///
/// Enforced inside `create_oauth_client_secret` via an OCC-guarded transaction
/// that version-bumps the owning `OAuthClientDoc`.  Both the guard and the secret
/// insert happen atomically, so concurrent adds collide on the client row and the
/// loser re-reads the updated count before deciding whether to insert or reject.
pub const MAX_ACTIVE_SECRETS: usize = 2;

// ============================================================================
// OAuth Client
// ============================================================================

/// OAuth client application record.
#[derive(Debug)]
pub struct OAuthClient {
    pub id: String,
    pub user_id: Option<String>,
    pub client_id: String,
    pub name: String,
    pub description: Option<String>,
    pub application_type: OAuthClientType,
    pub redirect_uris: Vec<String>,
    pub active: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub last_used_at: Option<Timestamp>,
    pub access_scope: AccessScope,
    pub org_id: Option<String>,
    pub resource_uris: Vec<String>,
    pub jwks: Option<serde_json::Value>,
    pub jwks_uri: Option<String>,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    pub request_object_signing_alg: Option<JwsAlgorithm>,
    pub require_signed_request_object: Option<bool>,
    pub fapi_profile: FapiProfile,
    pub dpop_bound_access_tokens: bool,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub software_id: Option<String>,
    pub software_version: Option<String>,
    pub registration_source: Option<RegistrationSource>,
    pub registration_access_token_hash: Option<String>,
    pub registration_metadata: Option<serde_json::Value>,
    pub id_token_signed_response_alg: JwsAlgorithm,
    /// RFC 8705: mTLS subject DN for tls_client_auth.
    pub tls_client_auth_subject_dn: Option<String>,
    /// RFC 8705: mTLS SAN DNS name.
    pub tls_client_auth_san_dns: Option<String>,
    /// RFC 8705: mTLS SAN URI.
    pub tls_client_auth_san_uri: Option<String>,
    /// RFC 8705: mTLS SAN IP.
    pub tls_client_auth_san_ip: Option<String>,
    /// RFC 8705: mTLS SAN email.
    pub tls_client_auth_san_email: Option<String>,
    /// RFC 8705: certificate-bound access tokens.
    pub tls_client_certificate_bound_access_tokens: bool,
    /// JARM: signing algorithm for authorization responses.
    pub authorization_signed_response_alg: Option<JwsAlgorithm>,
    /// RFC 9701: Introspection response signing algorithm.
    ///
    /// When `Some`, the introspection endpoint returns a signed JWT instead of plain JSON.
    pub introspection_signed_response_alg: Option<JwsAlgorithm>,
    /// OIDC Core Section 5.3.4: UserInfo response signing algorithm.
    pub userinfo_signed_response_alg: Option<JwsAlgorithm>,
    /// OIDC Core Section 6.2: Pre-registered request_uri allowlist.
    ///
    /// When `Some`, only the listed HTTPS URLs are accepted as `request_uri` values.
    /// When `None`, any HTTPS `request_uri` is accepted.
    pub request_uris: Option<Vec<String>>,
}

impl From<Document<OAuthClientDoc>> for OAuthClient {
    fn from(doc: Document<OAuthClientDoc>) -> Self {
        Self {
            id: doc.id,
            user_id: doc.data.user_id,
            client_id: doc.data.client_id,
            name: doc.data.name,
            description: doc.data.description,
            application_type: doc.data.application_type,
            redirect_uris: doc.data.redirect_uris,
            active: doc.data.active,
            created_at: doc.created_at,
            updated_at: doc.updated_at,
            last_used_at: doc.last_used_at,
            access_scope: doc.data.access_scope,
            org_id: doc.data.org_id,
            resource_uris: doc.data.resource_uris,
            jwks: doc.data.jwks,
            jwks_uri: doc.data.jwks_uri,
            token_endpoint_auth_method: doc.data.token_endpoint_auth_method,
            request_object_signing_alg: doc.data.request_object_signing_alg,
            require_signed_request_object: doc.data.require_signed_request_object,
            fapi_profile: doc.data.fapi_profile,
            dpop_bound_access_tokens: doc.data.dpop_bound_access_tokens,
            grant_types: doc.data.grant_types,
            response_types: doc.data.response_types,
            software_id: doc.data.software_id,
            software_version: doc.data.software_version,
            registration_source: doc.data.registration_source,
            registration_access_token_hash: doc.data.registration_access_token_hash,
            registration_metadata: doc.data.registration_metadata,
            id_token_signed_response_alg: doc.data.id_token_signed_response_alg,
            tls_client_auth_subject_dn: doc.data.tls_client_auth_subject_dn,
            tls_client_auth_san_dns: doc.data.tls_client_auth_san_dns,
            tls_client_auth_san_uri: doc.data.tls_client_auth_san_uri,
            tls_client_auth_san_ip: doc.data.tls_client_auth_san_ip,
            tls_client_auth_san_email: doc.data.tls_client_auth_san_email,
            tls_client_certificate_bound_access_tokens: doc
                .data
                .tls_client_certificate_bound_access_tokens,
            authorization_signed_response_alg: doc.data.authorization_signed_response_alg,
            introspection_signed_response_alg: doc.data.introspection_signed_response_alg,
            userinfo_signed_response_alg: doc.data.userinfo_signed_response_alg,
            request_uris: doc.data.request_uris,
        }
    }
}

impl OAuthClient {
    #[must_use]
    pub fn is_valid_redirect_uri(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|u| u == uri)
    }

    #[must_use]
    pub fn is_valid_resource_uri(&self, uri: &str) -> bool {
        if self.resource_uris.is_empty() {
            return true;
        }
        self.resource_uris.iter().any(|u| u == uri)
    }

    #[must_use]
    pub fn is_fapi(&self) -> bool {
        self.fapi_profile != FapiProfile::None
    }
}

/// Parameters for creating a new OAuth client application.
pub struct CreateOAuthClientParams<'a> {
    pub user_id: Option<&'a str>,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub application_type: OAuthClientType,
    pub redirect_uris: &'a [String],
    pub access_scope: AccessScope,
    pub org_id: Option<&'a str>,
    pub resource_uris: &'a [String],
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,
    pub jwks: Option<&'a serde_json::Value>,
    pub jwks_uri: Option<&'a str>,
    pub fapi_profile: Option<FapiProfile>,
    pub dpop_bound_access_tokens: Option<bool>,
    pub grant_types: Option<&'a [String]>,
    pub response_types: Option<&'a [String]>,
    pub software_id: Option<&'a str>,
    pub software_version: Option<&'a str>,
    pub registration_source: RegistrationSource,
    pub registration_access_token_hash: Option<&'a str>,
    pub registration_metadata: Option<&'a serde_json::Value>,
    pub id_token_signed_response_alg: JwsAlgorithm,
    /// RFC 8705 mTLS fields.
    pub tls_client_auth_subject_dn: Option<&'a str>,
    pub tls_client_auth_san_dns: Option<&'a str>,
    pub tls_client_auth_san_uri: Option<&'a str>,
    pub tls_client_auth_san_ip: Option<&'a str>,
    pub tls_client_auth_san_email: Option<&'a str>,
    pub tls_client_certificate_bound_access_tokens: Option<bool>,
    /// JARM: signing algorithm for authorization responses.
    pub authorization_signed_response_alg: Option<JwsAlgorithm>,
    /// RFC 9701: Introspection response signing algorithm.
    pub introspection_signed_response_alg: Option<JwsAlgorithm>,
    /// RFC 9101: Request object signing algorithm.
    pub request_object_signing_alg: Option<JwsAlgorithm>,
    /// RFC 9101: Whether signed request objects are required.
    pub require_signed_request_object: Option<bool>,
    /// OIDC Core Section 5.3.4: UserInfo response signing algorithm.
    pub userinfo_signed_response_alg: Option<JwsAlgorithm>,
    /// OIDC Core Section 6.2: Pre-registered request_uri allowlist.
    pub request_uris: Option<Vec<String>>,
}

/// Create a new OAuth client application.
pub async fn create_oauth_client(
    store: &DocumentStore,
    params: &CreateOAuthClientParams<'_>,
) -> Result<(OAuthClient, String)> {
    let client_id = uuid::Uuid::now_v7().to_string();

    let doc = OAuthClientDoc {
        user_id: params.user_id.map(String::from),
        client_id: client_id.clone(),
        name: params.name.to_string(),
        description: params.description.map(String::from),
        application_type: params.application_type,
        redirect_uris: params.redirect_uris.to_vec(),
        active: true,
        access_scope: params.access_scope,
        org_id: params.org_id.map(String::from),
        resource_uris: params.resource_uris.to_vec(),
        jwks: params.jwks.cloned(),
        jwks_uri: params.jwks_uri.map(String::from),
        token_endpoint_auth_method: params.token_endpoint_auth_method.unwrap_or_default(),
        request_object_signing_alg: params.request_object_signing_alg,
        require_signed_request_object: params.require_signed_request_object,
        fapi_profile: params.fapi_profile.unwrap_or_default(),
        dpop_bound_access_tokens: params.dpop_bound_access_tokens.unwrap_or(false),
        grant_types: params.grant_types.map(<[String]>::to_vec),
        response_types: params.response_types.map(<[String]>::to_vec),
        software_id: params.software_id.map(String::from),
        software_version: params.software_version.map(String::from),
        registration_source: Some(params.registration_source),
        registration_access_token_hash: params.registration_access_token_hash.map(String::from),
        registration_metadata: params.registration_metadata.cloned(),
        id_token_signed_response_alg: params.id_token_signed_response_alg,
        tls_client_auth_subject_dn: params.tls_client_auth_subject_dn.map(String::from),
        tls_client_auth_san_dns: params.tls_client_auth_san_dns.map(String::from),
        tls_client_auth_san_uri: params.tls_client_auth_san_uri.map(String::from),
        tls_client_auth_san_ip: params.tls_client_auth_san_ip.map(String::from),
        tls_client_auth_san_email: params.tls_client_auth_san_email.map(String::from),
        tls_client_certificate_bound_access_tokens: params
            .tls_client_certificate_bound_access_tokens
            .unwrap_or(false),
        authorization_signed_response_alg: params.authorization_signed_response_alg,
        introspection_signed_response_alg: params.introspection_signed_response_alg,
        userinfo_signed_response_alg: params.userinfo_signed_response_alg,
        request_uris: params.request_uris.clone(),
    };

    let result = store.insert(&doc).await?;
    let oauth_client = OAuthClient::from(result);

    Ok((oauth_client, client_id))
}

/// Get an OAuth client by internal ID.
pub async fn get_oauth_client_by_id(
    store: &DocumentStore,
    id: &str,
) -> Result<Option<OAuthClient>> {
    let doc = store.get::<OAuthClientDoc>(id).await?;
    Ok(doc.map(OAuthClient::from))
}

/// Get an OAuth client by public client_id.
pub async fn get_oauth_client_by_client_id(
    store: &DocumentStore,
    client_id: &str,
) -> Result<Option<OAuthClient>> {
    let doc = store
        .find_one::<OAuthClientDoc>("client_id", client_id)
        .await?;
    Ok(doc.map(OAuthClient::from))
}

/// Get all OAuth clients for a user.
pub async fn get_oauth_clients_for_user(
    store: &DocumentStore,
    user_id: &str,
) -> Result<Vec<OAuthClient>> {
    let docs = store.find_all::<OAuthClientDoc>("user_id", user_id).await?;
    Ok(docs.into_iter().map(OAuthClient::from).collect())
}

/// Parameters for updating an OAuth client.
pub struct UpdateOAuthClientParams<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub redirect_uris: &'a [String],
    pub access_scope: Option<AccessScope>,
    pub org_id: Option<&'a str>,
    pub resource_uris: &'a [String],
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    pub jwks: Option<&'a serde_json::Value>,
    pub jwks_uri: Option<&'a str>,
    pub fapi_profile: FapiProfile,
    pub dpop_bound_access_tokens: bool,
}

/// Update an OAuth client.
///
/// Uses [`DocumentStore::modify`] for read-modify-write with automatic
/// version-conflict retry.
pub async fn update_oauth_client(
    store: &DocumentStore,
    params: &UpdateOAuthClientParams<'_>,
) -> Result<()> {
    store
        .modify::<OAuthClientDoc, _>(params.id, |data| {
            data.name = params.name.to_string();
            data.description = params.description.map(String::from);
            data.redirect_uris = params.redirect_uris.to_vec();
            data.resource_uris = params.resource_uris.to_vec();
            data.token_endpoint_auth_method = params.token_endpoint_auth_method;
            data.jwks = params.jwks.cloned();
            data.jwks_uri = params.jwks_uri.map(String::from);
            data.fapi_profile = params.fapi_profile;
            data.dpop_bound_access_tokens = params.dpop_bound_access_tokens;

            if let Some(scope) = params.access_scope {
                data.access_scope = scope;
                data.org_id = params.org_id.map(String::from);
            }
        })
        .await?;
    Ok(())
}

/// Delete an OAuth client permanently.
///
/// Cascade deletes secrets and the client within a single transaction
/// so no orphaned secrets remain on partial failure.
pub async fn delete_oauth_client(store: &DocumentStore, id: &str) -> Result<u64> {
    let mut tx = store.begin().await?;

    // Delete secrets
    tx.delete_by_index::<OAuthClientSecretDoc>("oauth_client_id", id)
        .await?;

    // Delete JWKS cache (was embedded in OAuthClientDoc pre-refactor; must stay atomic)
    tx.delete(&super::jwks_cache::cache_id(id)).await?;

    // Delete the client
    tx.delete(id).await?;

    tx.commit().await?;
    Ok(1)
}

/// Update last used timestamp for an OAuth client.
///
/// Performs a lightweight column-level UPDATE (no encrypt/decrypt).
pub async fn update_oauth_client_last_used(store: &DocumentStore, id: &str) -> Result<()> {
    store.update_last_used_at(id).await
}

// ============================================================================
// OAuth Client Secrets
// ============================================================================

/// OAuth client secret record.
#[derive(Debug)]
pub struct OAuthClientSecret {
    pub id: String,
    pub oauth_client_id: String,
    pub secret_hash: String,
    pub description: Option<String>,
    pub created_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
}

impl From<Document<OAuthClientSecretDoc>> for OAuthClientSecret {
    fn from(doc: Document<OAuthClientSecretDoc>) -> Self {
        Self {
            id: doc.id,
            oauth_client_id: doc.data.oauth_client_id,
            secret_hash: doc.data.secret_hash,
            description: doc.data.description,
            created_at: doc.created_at,
            expires_at: doc.data.expires_at,
            revoked_at: doc.data.revoked_at,
        }
    }
}

impl OAuthClientSecret {
    /// Check if this secret is valid (not revoked/expired).
    #[must_use]
    pub fn is_valid(&self, now: &Timestamp) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }
        if let Some(expires) = self.expires_at
            && expires <= *now
        {
            return false;
        }
        true
    }
}

/// Create a new client secret, enforcing the ≤`MAX_ACTIVE_SECRETS` cap.
///
/// The entire operation runs inside a single transaction wrapped in
/// `with_dsql_retry!`.  The transaction:
///
/// 1. Loads the `OAuthClientDoc` and records its `version` — this is the
///    deliberate serialization point for all secret-set mutations on this client.
/// 2. Counts currently-valid (non-revoked, non-expired) secrets.
/// 3. If the count is already at the cap, returns a terminal 409 error that
///    is **not** retried (business logic, not a transient conflict).
/// 4. Inserts the new secret inside the transaction.
/// 5. Bumps the client doc version via `compare_and_update`.  If another writer
///    committed a secret-set mutation between our read and our commit, the version
///    won't match and `compare_and_update` returns `Ok(false)` — we surface this
///    as `ServiceError::OccConflict` so `with_dsql_retry!` re-runs the whole
///    block (re-counting, possibly rejecting at the cap on the second attempt).
///
/// This approach is correct on Aurora DSQL where the reverted #547 fix was not:
/// the reverted fix relied on snapshot isolation to reject a second concurrent
/// insert, but two adds write *distinct* rows and neither `SELECT FOR UPDATE` nor
/// `SERIALIZABLE` caught them.  Here, both writers also update the **same** client
/// row via `compare_and_update`, causing a write-write conflict (DSQL OC000) that
/// the loser retries at the application level.
///
/// Note: because this function version-bumps the `OAuthClientDoc`, concurrent
/// client metadata updates (e.g. `update_oauth_client`) may incur OCC retries
/// while a secret add is in flight, and vice versa.
///
/// # Errors
///
/// - `ServiceError::NotFound` — client does not exist.
/// - `ServiceError::Api(409 "max_secrets_reached")` — cap already reached (terminal).
/// - `ServiceError::Api(409 "conflict")` — OCC retry budget exhausted; caller may retry.
/// - `ServiceError::Internal` — unexpected database or serialization error.
pub async fn create_oauth_client_secret(
    store: &DocumentStore,
    oauth_client_id: &str,
    secret_hash: &str,
    description: Option<&str>,
    expires_at: Option<Timestamp>,
) -> Result<OAuthClientSecret, ServiceError> {
    // Capture parameters as owned values so the async block (re-run on retry) can
    // borrow them without lifetime conflicts.
    let oauth_client_id = oauth_client_id.to_string();
    let secret_hash = secret_hash.to_string();
    let description = description.map(String::from);

    // Map a DB error from any tx operation into either an OccConflict (if it
    // signals writer contention — Postgres serialization failure, Aurora DSQL
    // OC000/OC001, SQLite BUSY/LOCKED) or a generic 500.
    // OccConflict is retried by with_dsql_retry!; the 500 path propagates.
    let map_db_err = |e: anyhow::Error, msg: &'static str| -> ServiceError {
        tracing::error!("{msg}: {e}");
        if crate::db::pool::is_retryable_db_error(&e) {
            ServiceError::OccConflict
        } else {
            ServiceError::Internal(msg.to_string())
        }
    };

    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await.map_err(|e| {
            map_db_err(
                e,
                "Failed to begin transaction for create_oauth_client_secret",
            )
        })?;

        // Load the client doc.  Its version is the serialization point — a
        // concurrent secret-set mutation that commits between our read and our
        // compare_and_update will change the version and trigger a retry.
        let client_doc = tx
            .get::<OAuthClientDoc>(&oauth_client_id)
            .await
            .map_err(|e| map_db_err(e, "Failed to load OAuthClientDoc for secret create"))?
            .ok_or(ServiceError::NotFound("OAuth client"))?;

        // Count currently-active secrets by filtering (not SQL COUNT) because
        // soft-deleted rows are retained and a COUNT(*) would include them.
        let now = Timestamp::now();
        let all_secrets = tx
            .find_all::<OAuthClientSecretDoc>("oauth_client_id", &oauth_client_id)
            .await
            .map_err(|e| map_db_err(e, "Failed to list secrets for secret create"))?;

        // Filter directly on the doc fields to avoid a needless From conversion.
        // Mirrors the `is_valid` predicate: not revoked, not expired.
        let active_count = all_secrets
            .iter()
            .filter(|s| {
                if s.data.revoked_at.is_some() {
                    return false;
                }
                if let Some(exp) = s.data.expires_at
                    && exp <= now
                {
                    return false;
                }
                true
            })
            .count();

        if active_count >= MAX_ACTIVE_SECRETS {
            // Terminal business error — do not retry.
            return Err(ServiceError::api(
                axum::http::StatusCode::CONFLICT,
                "max_secrets_reached",
                "Maximum of 2 active secrets allowed",
            ));
        }

        // Insert the new secret inside the transaction.
        let new_secret_doc = OAuthClientSecretDoc {
            oauth_client_id: oauth_client_id.clone(),
            secret_hash: secret_hash.clone(),
            description: description.clone(),
            expires_at,
            revoked_at: None,
        };
        let inserted = tx
            .insert(&new_secret_doc)
            .await
            .map_err(|e| map_db_err(e, "Failed to insert secret"))?;

        // Version-bump the client doc.  This is the OCC serialization point:
        // any concurrent secret-set mutation on this client will have bumped the
        // version, causing compare_and_update to return Ok(false).
        let ok = tx
            .compare_and_update::<OAuthClientDoc>(
                &oauth_client_id,
                client_doc.version,
                &client_doc.data,
            )
            .await
            .map_err(|e| map_db_err(e, "Failed to version-bump client for secret create"))?;

        if !ok {
            // OCC conflict — another writer beat us to the client row.  Signal
            // with_dsql_retry! to re-run the entire block.
            return Err(ServiceError::OccConflict);
        }

        tx.commit()
            .await
            .map_err(|e| map_db_err(e, "Failed to commit create_oauth_client_secret"))?;

        Ok(OAuthClientSecret::from(inserted))
    })
    // `with_dsql_retry!` exhausts OccConflict after MAX_DSQL_RETRIES attempts.
    // Surface as 409 "conflict" (not 500) — mirrors the delete_key precedent.
    .map_err(|e| match e {
        ServiceError::OccConflict => ServiceError::api(
            axum::http::StatusCode::CONFLICT,
            "conflict",
            "Secret creation conflicted with a concurrent operation. Please retry.",
        ),
        other => other,
    })
}

/// Get all secrets for an OAuth client.
pub async fn get_oauth_client_secrets(
    store: &DocumentStore,
    oauth_client_id: &str,
) -> Result<Vec<OAuthClientSecret>> {
    let docs = store
        .find_all::<OAuthClientSecretDoc>("oauth_client_id", oauth_client_id)
        .await?;
    Ok(docs.into_iter().map(OAuthClientSecret::from).collect())
}

/// Get a secret by its hash.
pub async fn get_oauth_secret_by_hash(
    store: &DocumentStore,
    secret_hash: &str,
) -> Result<Option<OAuthClientSecret>> {
    let doc = store
        .find_one::<OAuthClientSecretDoc>("secret_hash", secret_hash)
        .await?;
    Ok(doc.map(OAuthClientSecret::from))
}

/// Revoke all secrets for an OAuth client.
pub async fn revoke_all_oauth_client_secrets(
    store: &DocumentStore,
    oauth_client_id: &str,
) -> Result<u64> {
    let now = Timestamp::now();
    let count = store
        .update_by_index::<OAuthClientSecretDoc, _>("oauth_client_id", oauth_client_id, |data| {
            if data.revoked_at.is_none() {
                data.revoked_at = Some(now);
            }
        })
        .await?;
    Ok(count)
}

/// Get a secret by its internal ID.
pub async fn get_oauth_client_secret_by_id(
    store: &DocumentStore,
    id: &str,
) -> Result<Option<OAuthClientSecret>> {
    let doc = store.get::<OAuthClientSecretDoc>(id).await?;
    Ok(doc.map(OAuthClientSecret::from))
}

/// Revoke a single secret (soft-delete), enforcing the ≥1 active floor.
///
/// The entire operation runs inside a single transaction wrapped in
/// `with_dsql_retry!`.  The transaction:
///
/// 1. Verifies the secret exists and belongs to the given client.
/// 2. Short-circuits with a terminal "not found" if the secret is already revoked.
/// 3. Loads the `OAuthClientDoc` to record its `version` (the serialization point
///    for all secret-set mutations on this client).
/// 4. Counts the *other* active secrets — those that would remain after this
///    revoke, excluding the target row itself (filter, not SQL COUNT — soft-deleted
///    rows are retained).  If none remain, returns a terminal 409 `last_secret`.
///    Excluding the target matters when it is expired-but-unrevoked: revoking it
///    must still be allowed while a different valid secret exists.
/// 5. Soft-deletes the secret (`revoked_at`) inside the transaction.
/// 6. Bumps the client version via `compare_and_update`.  If another concurrent
///    revoke committed between our read and our commit, the version won't match
///    and we surface `ServiceError::OccConflict` so the macro retries.  The
///    retried attempt re-counts and returns `last_secret` if appropriate.
///
/// Note: because this function version-bumps the `OAuthClientDoc`, concurrent
/// client metadata updates (e.g. `update_oauth_client`) may incur OCC retries
/// while a secret revocation is in flight, and vice versa.
///
/// # Errors
///
/// - `ServiceError::NotFound("Secret")` — secret does not exist, does not belong
///   to the given client, or is already revoked.
/// - `ServiceError::NotFound("OAuth client")` — the owning client does not exist.
/// - `ServiceError::Api(409 "last_secret")` — would leave zero active secrets (terminal).
/// - `ServiceError::Api(409 "conflict")` — OCC retry budget exhausted; caller may retry.
/// - `ServiceError::Internal` — unexpected database or serialization error.
pub async fn revoke_oauth_client_secret(
    store: &DocumentStore,
    secret_id: &str,
    oauth_client_id: &str,
) -> Result<(), ServiceError> {
    let secret_id = secret_id.to_string();
    let oauth_client_id = oauth_client_id.to_string();

    // Map a DB error from any tx operation into either an OccConflict (if it
    // signals writer contention — Postgres serialization failure, Aurora DSQL
    // OC000/OC001, SQLite BUSY/LOCKED) or a generic 500.
    // OccConflict is retried by with_dsql_retry!; the 500 path propagates.
    let map_db_err = |e: anyhow::Error, msg: &'static str| -> ServiceError {
        tracing::error!("{msg}: {e}");
        if crate::db::pool::is_retryable_db_error(&e) {
            ServiceError::OccConflict
        } else {
            ServiceError::Internal(msg.to_string())
        }
    };

    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await.map_err(|e| {
            map_db_err(
                e,
                "Failed to begin transaction for revoke_oauth_client_secret",
            )
        })?;

        // Verify the secret exists and belongs to this client.
        let secret_doc = tx
            .get::<OAuthClientSecretDoc>(&secret_id)
            .await
            .map_err(|e| map_db_err(e, "Failed to load secret for revoke"))?
            .ok_or(ServiceError::NotFound("Secret"))?;

        if secret_doc.data.oauth_client_id != oauth_client_id {
            return Err(ServiceError::NotFound("Secret"));
        }

        // Already revoked — idempotent short-circuit; caller should treat as not-found.
        if secret_doc.data.revoked_at.is_some() {
            return Err(ServiceError::NotFound("Secret"));
        }

        // Load the client doc — its version is the serialization point for all
        // secret-set mutations on this client.
        let client_doc = tx
            .get::<OAuthClientDoc>(&oauth_client_id)
            .await
            .map_err(|e| map_db_err(e, "Failed to load OAuthClientDoc for revoke"))?
            .ok_or(ServiceError::NotFound("OAuth client"))?;

        // Count active secrets (filter, not SQL COUNT — soft-deleted rows are retained).
        let now = Timestamp::now();
        let all_secrets = tx
            .find_all::<OAuthClientSecretDoc>("oauth_client_id", &oauth_client_id)
            .await
            .map_err(|e| map_db_err(e, "Failed to list secrets for revoke"))?;

        // Count the *other* active secrets — exclude the target row itself, so a
        // revoke that leaves a valid secret behind is allowed even when the target
        // is expired-but-unrevoked.  Mirrors the handler's pre-flight check.
        let other_active_count = all_secrets
            .iter()
            .filter(|s| {
                if s.id == secret_id {
                    return false;
                }
                if s.data.revoked_at.is_some() {
                    return false;
                }
                if let Some(exp) = s.data.expires_at
                    && exp <= now
                {
                    return false;
                }
                true
            })
            .count();

        // Floor guard: at least one *other* active secret must remain.
        if other_active_count == 0 {
            return Err(ServiceError::api(
                StatusCode::CONFLICT,
                "last_secret",
                "Cannot delete the last active secret",
            ));
        }

        // Soft-delete: set revoked_at on the target secret.
        let mut updated_data = secret_doc.data.clone();
        updated_data.revoked_at = Some(now);
        tx.update(&secret_id, &updated_data)
            .await
            .map_err(|e| map_db_err(e, "Failed to soft-delete secret"))?;

        // Version-bump the client doc.  This is the OCC serialization point.
        let ok = tx
            .compare_and_update::<OAuthClientDoc>(
                &oauth_client_id,
                client_doc.version,
                &client_doc.data,
            )
            .await
            .map_err(|e| map_db_err(e, "Failed to version-bump client for revoke"))?;

        if !ok {
            return Err(ServiceError::OccConflict);
        }

        tx.commit()
            .await
            .map_err(|e| map_db_err(e, "Failed to commit revoke_oauth_client_secret"))
    })
    // `with_dsql_retry!` exhausts OccConflict after MAX_DSQL_RETRIES attempts.
    // Surface as 409 "conflict" (not 500) — mirrors the delete_key precedent.
    .map_err(|e| match e {
        ServiceError::OccConflict => ServiceError::api(
            axum::http::StatusCode::CONFLICT,
            "conflict",
            "Secret revocation conflicted with a concurrent operation. Please retry.",
        ),
        other => other,
    })
}

// ============================================================================
// OAuth Usage Events (now via AuditStore)
// ============================================================================

/// OAuth usage event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthEventType {
    TokenIssued,
    TokenRefreshed,
    TokenRevoked,
    AuthSuccess,
    AuthFailure,
    ClientRegistered,
    ClientUpdated,
    ClientDeleted,
    SecretAdded,
    SecretRevoked,
}

impl OAuthEventType {
    /// Event variants included in usage stats and retention cleanup.
    pub const USAGE_EVENTS: [Self; 6] = [
        Self::TokenIssued,
        Self::TokenRefreshed,
        Self::TokenRevoked,
        Self::AuthSuccess,
        Self::AuthFailure,
        Self::ClientRegistered,
    ];

    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TokenIssued => "token_issued",
            Self::TokenRefreshed => "token_refreshed",
            Self::TokenRevoked => "token_revoked",
            Self::AuthSuccess => "auth_success",
            Self::AuthFailure => "auth_failure",
            Self::ClientRegistered => "client_registered",
            Self::ClientUpdated => "client_updated",
            Self::ClientDeleted => "client_deleted",
            Self::SecretAdded => "secret_added",
            Self::SecretRevoked => "secret_revoked",
        }
    }

    /// Audit event type stored in `audit_events.event_type`.
    #[must_use]
    pub fn audit_event_type(&self) -> &'static str {
        match self {
            Self::TokenIssued => "oauth_token_issued",
            Self::TokenRefreshed => "oauth_token_refreshed",
            Self::TokenRevoked => "oauth_token_revoked",
            Self::AuthSuccess => "oauth_auth_success",
            Self::AuthFailure => "oauth_auth_failure",
            Self::ClientRegistered => "oauth_client_registered",
            Self::ClientUpdated => "oauth_client_updated",
            Self::ClientDeleted => "oauth_client_deleted",
            Self::SecretAdded => "oauth_secret_added",
            Self::SecretRevoked => "oauth_secret_revoked",
        }
    }
}

/// Record an OAuth usage event via the audit store.
pub async fn record_oauth_event(
    audit: &AuditStore,
    oauth_client_id: &str,
    event_type: OAuthEventType,
    user_id: Option<&str>,
    ip_address: Option<std::net::IpAddr>,
    user_agent: Option<&str>,
    details: Option<&str>,
) -> Result<String> {
    let geo = ip_address.and_then(crate::geo::lookup);
    let data = OAuthUsageData {
        oauth_client_id: oauth_client_id.to_string(),
        details: details.map(String::from),
        client_ip: ip_address.map(|ip| ip.to_string()),
        user_agent: user_agent.map(String::from),
        country_code: geo.as_ref().map(|g| g.country_code.clone()),
        asn: geo.as_ref().and_then(|g| g.asn),
        org_name: geo.as_ref().and_then(|g| g.org_name.clone()),
    };
    let data_json = serde_json::to_string(&data)?;

    audit
        .insert_event(event_type.audit_event_type(), user_id, None, &data_json)
        .await
}

/// OAuth usage statistics.
#[derive(Debug)]
pub struct OAuthUsageStats {
    pub event_type: String,
    pub count: i64,
}

/// Get usage statistics for an OAuth client.
///
/// Queries audit events and counts occurrences per event type,
/// filtering to events matching the given `oauth_client_id`.
pub async fn get_oauth_usage_stats(
    audit: &AuditStore,
    oauth_client_id: &str,
    since: Option<&str>,
) -> Result<Vec<OAuthUsageStats>> {
    let mut stats: std::collections::HashMap<String, i64> = std::collections::HashMap::new();

    for event_type in OAuthEventType::USAGE_EVENTS {
        let audit_event_type = event_type.audit_event_type();
        let filter = AuditEventFilter {
            event_types: Some(vec![audit_event_type.to_string()]),
            since: since.map(String::from),
            ..AuditEventFilter::default()
        };
        let events = audit.query_events(&filter).await?;
        for event in &events {
            let Ok(data) = serde_json::from_str::<OAuthUsageData>(&event.data) else {
                continue;
            };
            if data.oauth_client_id == oauth_client_id {
                let entry: &mut i64 = stats.entry(audit_event_type.to_string()).or_default();
                *entry = entry.saturating_add(1);
            }
        }
    }

    Ok(stats
        .into_iter()
        .map(|(event_type, count)| OAuthUsageStats { event_type, count })
        .collect())
}

/// Delete old usage events (for retention policy).
pub async fn delete_old_oauth_usage_events(audit: &AuditStore, before: Timestamp) -> Result<u64> {
    let before_str = before.to_string();
    let mut total: u64 = 0;
    for event_type in OAuthEventType::USAGE_EVENTS {
        let deleted = audit
            .delete_old_events(event_type.audit_event_type(), &before_str)
            .await?;
        total = total.saturating_add(deleted);
    }
    Ok(total)
}

/// Test-only helpers for modifying OAuth clients.
#[cfg(test)]
pub(super) mod test_helpers {
    use super::*;

    /// Set an OAuth client's `active` flag. Used to simulate deactivated clients.
    pub async fn set_oauth_client_active(
        store: &DocumentStore,
        id: &str,
        active: bool,
    ) -> Result<()> {
        if let Some(doc) = store.get::<OAuthClientDoc>(id).await? {
            let mut data = doc.data;
            data.active = active;
            store.update(id, &data).await?;
        }
        Ok(())
    }

    /// Set the `userinfo_signed_response_alg` directly on an OAuth client.
    ///
    /// Bypasses registration validation to allow injection of normally-rejected values.
    pub async fn set_oauth_client_userinfo_alg(
        store: &DocumentStore,
        id: &str,
        alg: Option<JwsAlgorithm>,
    ) -> Result<()> {
        if let Some(doc) = store.get::<OAuthClientDoc>(id).await? {
            let mut data = doc.data;
            data.userinfo_signed_response_alg = alg;
            store.update(id, &data).await?;
        }
        Ok(())
    }
}

/// Parameters for updating a client via RFC 7592 PUT.
pub struct UpdateClientRegistrationParams<'a> {
    pub redirect_uris: &'a [String],
    pub grant_types: Option<&'a [String]>,
    pub response_types: Option<&'a [String]>,
    pub jwks: Option<&'a serde_json::Value>,
    pub jwks_uri: Option<&'a str>,
    pub registration_access_token_hash: &'a str,
    pub registration_metadata: Option<&'a serde_json::Value>,
    pub userinfo_signed_response_alg: Option<JwsAlgorithm>,
    pub request_uris: Option<&'a [String]>,
}

/// Update a dynamically registered OAuth client (RFC 7592 Section 2.2).
///
/// Updates mutable registration fields. Immutable fields (client_id,
/// token_endpoint_auth_method, fapi_profile) are preserved.
pub async fn update_oauth_client_registration(
    store: &DocumentStore,
    id: &str,
    params: &UpdateClientRegistrationParams<'_>,
) -> Result<OAuthClient> {
    // Check whether jwks_uri is changing BEFORE modifying the parent doc so we
    // can delete the stale cache first. A reader that races between the cache
    // delete and the parent update will re-fetch (safe). A reader that sees the
    // new URI with the old cache (reverse order) would validate the wrong keys
    // — hence delete-then-update ordering.
    // Bounded race: a concurrent JWKS refresh that completes between this delete
    // and the modify's internal re-fetch can repopulate the cache with old-URI
    // keys. Worst-case window is one TTL (~1h); next cache miss self-corrects.
    let jwks_uri_changing = store
        .get::<OAuthClientDoc>(id)
        .await?
        .is_some_and(|doc| doc.data.jwks_uri.as_deref() != params.jwks_uri);

    if jwks_uri_changing {
        super::jwks_cache::delete_jwks_cache(store, id).await?;
    }

    store
        .modify::<OAuthClientDoc, _>(id, |data| {
            data.redirect_uris = params.redirect_uris.to_vec();
            if let Some(gt) = params.grant_types {
                data.grant_types = Some(gt.to_vec());
            }
            if let Some(rt) = params.response_types {
                data.response_types = Some(rt.to_vec());
            }
            // RFC 7592: PUT is a full replacement — clear fields not present.
            data.jwks = params.jwks.cloned();
            data.jwks_uri = params.jwks_uri.map(String::from);
            data.registration_access_token_hash =
                Some(params.registration_access_token_hash.to_string());
            data.registration_metadata = params.registration_metadata.cloned();
            // RFC 7592: PUT is a full replacement — clear fields not present.
            data.userinfo_signed_response_alg = params.userinfo_signed_response_alg;
            data.request_uris = params.request_uris.map(|u| u.to_vec());
        })
        .await?;

    let updated = store
        .get::<OAuthClientDoc>(id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Client not found after update"))?;

    Ok(OAuthClient::from(updated))
}

// ============================================================================
// JWT Assertion JTI Operations (RFC 7523)
// ============================================================================

/// Maximum JTI length.
const MAX_JTI_LENGTH: usize = 256;

/// Derive a deterministic document ID from (jti, client_id).
///
/// Two concurrent inserts for the same JTI+client_id produce the same
/// document ID, so the second INSERT fails on the `documents` PRIMARY KEY
/// constraint. This eliminates the TOCTOU race without requiring elevated
/// transaction isolation or advisory locks.
fn deterministic_jti_id(jti: &str, client_id: &str) -> String {
    use aws_lc_rs::digest::{self, SHA256};

    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(b"jwt_assertion_jti\0");
    ctx.update(client_id.as_bytes());
    ctx.update(b"\0");
    ctx.update(jti.as_bytes());
    hex::encode(ctx.finish().as_ref())
}

/// Witness that the atomic JTI insert in [`store_jwt_assertion_jti`]
/// succeeded for a specific `(jti, client_id)` pair.
///
/// Construction is private to this module — the only way to obtain a
/// `JwtAssertionJtiClaim` is to call `store_jwt_assertion_jti` and receive
/// `Ok(_)`, which means the atomic INSERT serialized this caller as the
/// first/only one to claim the JTI. Callers that hold this witness can
/// rely on it as compile-time evidence that the RFC 7523 single-use
/// requirement was enforced for the corresponding assertion.
///
/// Intentionally not `Clone` or `Copy` — the witness represents a one-shot
/// claim. The `#[must_use]` ensures the value is bound at the call site
/// even when the caller does not yet thread it into a downstream consumer.
#[derive(Debug)]
#[must_use = "the JTI was atomically claimed; bind this witness so future code can require it"]
pub struct JwtAssertionJtiClaim {
    _private: (),
}

/// Store a JWT assertion JTI for replay prevention.
///
/// On success, returns a [`JwtAssertionJtiClaim`] witness — the atomic
/// INSERT with the PRIMARY KEY derived from `(jti, client_id)` serialized
/// this caller as the first to claim the JTI. Concurrent replayers receive
/// [`ClaimError::AlreadyConsumed`] regardless of transaction isolation
/// level or database backend.
pub async fn store_jwt_assertion_jti(
    store: &DocumentStore,
    jti: &str,
    client_id: &str,
    expires_at: Timestamp,
) -> std::result::Result<JwtAssertionJtiClaim, super::claim::ClaimError> {
    use super::claim::ClaimError;

    if jti.len() > MAX_JTI_LENGTH {
        return Err(ClaimError::InvalidInput(format!(
            "JTI exceeds maximum length ({MAX_JTI_LENGTH})"
        )));
    }

    let id = deterministic_jti_id(jti, client_id);
    let doc = JwtAssertionJtiDoc {
        jti: jti.to_string(),
        client_id: client_id.to_string(),
        expires_at,
    };

    match store.insert_with_id(&id, &doc).await {
        Ok(_) => Ok(JwtAssertionJtiClaim { _private: () }),
        Err(e) => {
            if super::pool::is_unique_violation(&e) {
                Err(ClaimError::AlreadyConsumed)
            } else {
                Err(ClaimError::Database(e.to_string()))
            }
        }
    }
}

/// Delete expired JWT assertion JTI entries.
pub async fn delete_expired_jwt_assertion_jtis(store: &DocumentStore) -> Result<u64> {
    store.delete_expired(JwtAssertionJtiDoc::DOC_TYPE).await
}

// ============================================================================
// Client Credential Validation
// ============================================================================

/// Validate client credentials (client_id + client_secret).
///
/// The presented secret is hashed by the caller (SHA-256, via `hash_token`)
/// and looked up by hash. There is no application-level `ct_eq` call
/// because the comparison happens inside the SQL engine on an indexed
/// column — the timing of "row found" vs "row not found" is not
/// distinguishable from the HTTP client's perspective, and we never see
/// the raw stored secret in application code. Do NOT replace this with
/// a fetch-then-compare pattern; that would reintroduce a timing channel.
pub async fn validate_oauth_client_credentials(
    store: &DocumentStore,
    client_id: &str,
    secret_hash: &str,
) -> Result<Option<OAuthClient>> {
    let Some(client) = get_oauth_client_by_client_id(store, client_id).await? else {
        return Ok(None);
    };

    if !client.active {
        return Ok(None);
    }

    let Some(secret) = get_oauth_secret_by_hash(store, secret_hash).await? else {
        return Ok(None);
    };

    if secret.oauth_client_id != client.id {
        return Ok(None);
    }

    let now = Timestamp::now();
    if !secret.is_valid(&now) {
        return Ok(None);
    }

    update_oauth_client_last_used(store, &client.id).await?;

    Ok(Some(client))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_access_scope_from_str() {
        let result: Result<AccessScope, _> = "organization".parse();
        assert_eq!(result, Ok(AccessScope::Organization));

        let result: Result<AccessScope, _> = "personal".parse();
        assert_eq!(result, Ok(AccessScope::Personal));

        let result: Result<AccessScope, _> = "public".parse();
        assert_eq!(result, Ok(AccessScope::Public));

        let result: Result<AccessScope, _> = "invalid".parse();
        assert!(result.is_err());

        let result: Result<AccessScope, _> = "".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_access_scope_from_str_case_insensitive() {
        let result: Result<AccessScope, _> = "ORGANIZATION".parse();
        assert_eq!(result, Ok(AccessScope::Organization));

        let result: Result<AccessScope, _> = "Personal".parse();
        assert_eq!(result, Ok(AccessScope::Personal));

        let result: Result<AccessScope, _> = "PUBLIC".parse();
        assert_eq!(result, Ok(AccessScope::Public));
    }

    #[test]
    fn test_access_scope_as_str() {
        assert_eq!(AccessScope::Organization.as_str(), "organization");
        assert_eq!(AccessScope::Personal.as_str(), "personal");
        assert_eq!(AccessScope::Public.as_str(), "public");
    }

    #[test]
    fn test_access_scope_default() {
        assert_eq!(AccessScope::default(), AccessScope::Personal);
    }

    #[test]
    fn test_access_scope_display_name() {
        assert_eq!(AccessScope::Organization.display_name(), "Organization");
        assert_eq!(AccessScope::Personal.display_name(), "Personal");
        assert_eq!(AccessScope::Public.display_name(), "Public");
    }

    #[test]
    fn test_access_scope_description() {
        assert!(
            AccessScope::Organization
                .description()
                .contains("organization")
        );
        assert!(AccessScope::Personal.description().contains("you"));
        assert!(AccessScope::Public.description().contains("Any"));
    }

    #[test]
    fn test_access_scope_display_roundtrip() {
        for scope in [
            AccessScope::Organization,
            AccessScope::Personal,
            AccessScope::Public,
        ] {
            let display_str = scope.to_string();
            let parsed: Result<AccessScope, _> = display_str.parse();
            assert_eq!(parsed, Ok(scope));
        }
    }

    #[test]
    fn test_token_endpoint_auth_method_from_str_basic() {
        let result: Result<TokenEndpointAuthMethod, _> = "client_secret_basic".parse();
        assert!(result.is_ok());
        assert_eq!(result, Ok(TokenEndpointAuthMethod::ClientSecretBasic));
    }

    #[test]
    fn test_token_endpoint_auth_method_from_str_post() {
        let result: Result<TokenEndpointAuthMethod, _> = "client_secret_post".parse();
        assert!(result.is_ok());
        assert_eq!(result, Ok(TokenEndpointAuthMethod::ClientSecretPost));
    }

    #[test]
    fn test_token_endpoint_auth_method_from_str_jwt() {
        let result: Result<TokenEndpointAuthMethod, _> = "private_key_jwt".parse();
        assert!(result.is_ok());
        assert_eq!(result, Ok(TokenEndpointAuthMethod::PrivateKeyJwt));
    }

    #[test]
    fn test_token_endpoint_auth_method_from_str_none() {
        let result: Result<TokenEndpointAuthMethod, _> = "none".parse();
        assert!(result.is_ok());
        assert_eq!(result, Ok(TokenEndpointAuthMethod::None));
    }

    #[test]
    fn test_token_endpoint_auth_method_rejects_unknown() {
        let result: Result<TokenEndpointAuthMethod, _> = "magic_auth".parse();
        assert!(result.is_err());

        let result2: Result<TokenEndpointAuthMethod, _> = "".parse();
        assert!(result2.is_err());
    }

    #[test]
    fn test_token_endpoint_auth_method_display_roundtrip() {
        let variants = [
            TokenEndpointAuthMethod::ClientSecretBasic,
            TokenEndpointAuthMethod::ClientSecretPost,
            TokenEndpointAuthMethod::PrivateKeyJwt,
            TokenEndpointAuthMethod::None,
        ];
        for variant in variants {
            let display_str = variant.to_string();
            let parsed: Result<TokenEndpointAuthMethod, _> = display_str.parse();
            assert_eq!(parsed, Ok(variant));
        }
    }

    #[test]
    fn test_fapi_profile_as_str() {
        assert_eq!(FapiProfile::None.as_str(), "none");
        assert_eq!(FapiProfile::Fapi2Security.as_str(), "fapi2_security");
    }

    #[test]
    fn test_fapi_profile_default() {
        assert_eq!(FapiProfile::default(), FapiProfile::None);
    }

    #[test]
    fn test_fapi_profile_serde_roundtrip() {
        let json =
            serde_json::to_string(&FapiProfile::Fapi2Security).expect("FapiProfile serialization");
        assert_eq!(json, r#""fapi2_security""#);

        let parsed: FapiProfile = serde_json::from_str(&json).expect("FapiProfile deserialization");
        assert_eq!(parsed, FapiProfile::Fapi2Security);

        let none_json =
            serde_json::to_string(&FapiProfile::None).expect("FapiProfile::None serialization");
        assert_eq!(none_json, r#""none""#);
    }

    // ========================================================================
    // Test Helpers
    // ========================================================================

    use std::sync::Arc;

    use crate::crypto::document_crypto::PlaintextDocumentCrypto;
    use crate::db::Pool;

    async fn test_store() -> DocumentStore {
        let pool = Pool::connect("sqlite::memory:", &crate::db::pool::PoolConfig::default())
            .await
            .expect("Failed to create test database");

        match &pool {
            Pool::Sqlite(p) => sqlx::migrate!("./migrations/sqlite")
                .run(p)
                .await
                .expect("Failed to run migrations"),
            Pool::Postgres(p) => sqlx::migrate!("./migrations/postgres")
                .run(p)
                .await
                .expect("Failed to run migrations"),
        }

        let crypto: Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
            Arc::new(PlaintextDocumentCrypto);
        DocumentStore::new(pool, crypto)
    }

    async fn create_client_and_secret(
        store: &DocumentStore,
    ) -> (OAuthClient, OAuthClientSecret, String) {
        let (client, _client_id) = create_oauth_client(
            store,
            &CreateOAuthClientParams {
                user_id: Some("test-user"),
                name: "Test App",
                description: None,
                application_type: OAuthClientType::Web,
                redirect_uris: &["https://example.com/callback".to_string()],
                access_scope: AccessScope::Public,
                org_id: None,
                resource_uris: &[],
                token_endpoint_auth_method: None,
                jwks: None,
                jwks_uri: None,
                fapi_profile: None,
                dpop_bound_access_tokens: None,
                grant_types: None,
                response_types: None,
                software_id: None,
                software_version: None,
                registration_source: RegistrationSource::Manual,
                registration_access_token_hash: None,
                registration_metadata: None,
                id_token_signed_response_alg: JwsAlgorithm::Rs256,
                tls_client_auth_subject_dn: None,
                tls_client_auth_san_dns: None,
                tls_client_auth_san_uri: None,
                tls_client_auth_san_ip: None,
                tls_client_auth_san_email: None,
                tls_client_certificate_bound_access_tokens: None,
                authorization_signed_response_alg: None,
                introspection_signed_response_alg: None,
                request_object_signing_alg: None,
                require_signed_request_object: None,
                userinfo_signed_response_alg: None,
                request_uris: None,
            },
        )
        .await
        .expect("create client");

        let secret_hash = "hash_abc123";
        let secret =
            create_oauth_client_secret(store, &client.id, secret_hash, Some("test secret"), None)
                .await
                .expect("create secret");

        (client, secret, secret_hash.to_string())
    }

    // ========================================================================
    // Secret Retrieval Tests
    // ========================================================================

    #[tokio::test]
    async fn test_get_secret_by_id() {
        let store = test_store().await;
        let (_client, secret, _hash) = create_client_and_secret(&store).await;

        let fetched = get_oauth_client_secret_by_id(&store, &secret.id)
            .await
            .expect("db query");

        assert!(fetched.is_some());
        let fetched = fetched.unwrap();
        assert_eq!(fetched.id, secret.id);
        assert_eq!(fetched.oauth_client_id, secret.oauth_client_id);
        assert_eq!(fetched.description.as_deref(), Some("test secret"));
    }

    #[tokio::test]
    async fn test_get_secret_by_id_not_found() {
        let store = test_store().await;

        let fetched = get_oauth_client_secret_by_id(&store, "nonexistent-id")
            .await
            .expect("db query");

        assert!(fetched.is_none());
    }

    // ========================================================================
    // Secret Revocation Tests
    // ========================================================================

    #[tokio::test]
    async fn test_revoke_secret_sets_revoked_at() {
        let store = test_store().await;
        let (client, secret, _hash) = create_client_and_secret(&store).await;

        assert!(secret.revoked_at.is_none());

        // Need a second active secret so the floor guard passes.
        let _second = create_oauth_client_secret(
            &store,
            &client.id,
            "hash_second_for_revoke_test",
            None,
            None,
        )
        .await
        .expect("create second secret");

        revoke_oauth_client_secret(&store, &secret.id, &client.id)
            .await
            .expect("revoke");

        let fetched = get_oauth_client_secret_by_id(&store, &secret.id)
            .await
            .expect("db query")
            .expect("secret exists");

        assert!(fetched.revoked_at.is_some());
    }

    // ========================================================================
    // is_valid Tests
    // ========================================================================

    #[tokio::test]
    async fn test_secret_is_valid_active() {
        let store = test_store().await;
        let (_client, secret, _hash) = create_client_and_secret(&store).await;

        let now = Timestamp::now();
        assert!(secret.is_valid(&now));
    }

    #[tokio::test]
    async fn test_secret_is_valid_revoked() {
        let store = test_store().await;
        let (client, secret, _hash) = create_client_and_secret(&store).await;

        // Need a second active secret so the floor guard passes.
        let _second = create_oauth_client_secret(
            &store,
            &client.id,
            "hash_second_for_valid_test",
            None,
            None,
        )
        .await
        .expect("create second secret");

        revoke_oauth_client_secret(&store, &secret.id, &client.id)
            .await
            .expect("revoke");

        let fetched = get_oauth_client_secret_by_id(&store, &secret.id)
            .await
            .expect("db query")
            .expect("secret exists");

        let now = Timestamp::now();
        assert!(!fetched.is_valid(&now));
    }

    #[tokio::test]
    async fn test_secret_is_valid_expired() {
        let store = test_store().await;
        let (client, _secret, _hash) = create_client_and_secret(&store).await;

        let past = Timestamp::now()
            .checked_sub(jiff::SignedDuration::from_hours(1))
            .expect("valid timestamp");

        let expired_secret = create_oauth_client_secret(
            &store,
            &client.id,
            "hash_expired",
            Some("expired"),
            Some(past),
        )
        .await
        .expect("create expired secret");

        let now = Timestamp::now();
        assert!(!expired_secret.is_valid(&now));
    }

    // ========================================================================
    // Multiple Secrets Tests
    // ========================================================================

    #[tokio::test]
    async fn test_multiple_secrets_for_client() {
        let store = test_store().await;
        let (client, _secret1, _hash1) = create_client_and_secret(&store).await;

        let _secret2 = create_oauth_client_secret(
            &store,
            &client.id,
            "hash_second",
            Some("second secret"),
            None,
        )
        .await
        .expect("create second secret");

        let secrets = get_oauth_client_secrets(&store, &client.id)
            .await
            .expect("list secrets");

        assert_eq!(secrets.len(), 2);
    }

    // ========================================================================
    // Credential Validation Tests
    // ========================================================================

    #[tokio::test]
    async fn test_validate_credentials_with_either_secret() {
        let store = test_store().await;
        let (client, _secret1, hash1) = create_client_and_secret(&store).await;

        let hash2 = "hash_second_secret";
        let _secret2 = create_oauth_client_secret(&store, &client.id, hash2, Some("second"), None)
            .await
            .expect("create second secret");

        let result1 = validate_oauth_client_credentials(&store, &client.client_id, &hash1)
            .await
            .expect("validate with first");
        assert!(result1.is_some());

        let result2 = validate_oauth_client_credentials(&store, &client.client_id, hash2)
            .await
            .expect("validate with second");
        assert!(result2.is_some());
    }

    #[tokio::test]
    async fn test_validate_credentials_revoked_fails() {
        let store = test_store().await;
        let (client, secret, hash) = create_client_and_secret(&store).await;

        // Need a second active secret so the floor guard passes.
        let _second = create_oauth_client_secret(
            &store,
            &client.id,
            "hash_second_revoke_validate",
            None,
            None,
        )
        .await
        .expect("create second secret");

        revoke_oauth_client_secret(&store, &secret.id, &client.id)
            .await
            .expect("revoke");

        let result = validate_oauth_client_credentials(&store, &client.client_id, &hash)
            .await
            .expect("validate");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_old_oauth_usage_events_covers_usage_event_variants() {
        let store = test_store().await;
        let audit = AuditStore::new(store.pool().clone(), store.crypto().clone());
        let usage_variants = OAuthEventType::USAGE_EVENTS;

        for event_type in usage_variants {
            record_oauth_event(
                &audit,
                "oauth-client-1",
                event_type,
                Some("user-1"),
                None,
                None,
                Some("coverage test"),
            )
            .await
            .expect("insert oauth usage event");
        }

        let before = jiff::Timestamp::now()
            .checked_add(jiff::SignedDuration::from_mins(5))
            .expect("valid timestamp arithmetic");

        let deleted = delete_old_oauth_usage_events(&audit, before)
            .await
            .expect("delete old oauth usage events");
        assert_eq!(
            deleted,
            usage_variants.len() as u64,
            "oauth usage cleanup must cover all usage event variants"
        );

        for event_type in usage_variants {
            let persisted = audit
                .query_events(&AuditEventFilter {
                    event_types: Some(vec![event_type.audit_event_type().to_string()]),
                    ..AuditEventFilter::default()
                })
                .await
                .expect("query oauth audit events");
            assert!(
                persisted.is_empty(),
                "event type {} should be deleted by retention cleanup",
                event_type.audit_event_type()
            );
        }
    }
}
