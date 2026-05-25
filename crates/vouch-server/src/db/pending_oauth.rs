// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Pending OAuth authorization database operations.

use super::claim::ClaimError;
use super::document_type::{Document, DocumentType};
use super::documents::pending_oauth::PendingOAuthAuthDoc;
use super::store::DocumentStore;
use anyhow::Result;
use jiff::{Span, Timestamp};

/// Pending OAuth authorization record.
#[derive(Debug)]
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
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub consumed_at: Option<Timestamp>,
    /// RFC 8707: Resource indicator.
    pub resource: Option<String>,
    /// RFC 9470: ACR values.
    pub acr_values: Option<String>,
    /// RFC 9470: Max age.
    pub max_age: Option<i64>,
    /// RFC 9470: Prompt.
    pub prompt: Option<String>,
    /// RFC 9449 / FAPI 2.0: DPoP key thumbprint.
    pub dpop_jkt: Option<String>,
    /// RFC 9396: Rich authorization details (JSON array).
    pub authorization_details: Option<serde_json::Value>,
    /// JARM: response_mode from the authorization request.
    pub response_mode: super::documents::oauth::ResponseMode,
    /// RFC 9126: PAR request_uri to consume when authorization completes.
    pub par_request_uri: Option<String>,
}

impl From<Document<PendingOAuthAuthDoc>> for PendingOAuthAuthorization {
    fn from(doc: Document<PendingOAuthAuthDoc>) -> Self {
        Self {
            id: doc.id,
            client_id: doc.data.client_id,
            redirect_uri: doc.data.redirect_uri,
            response_type: doc.data.response_type,
            state: doc.data.state,
            scope: doc.data.scope,
            nonce: doc.data.nonce,
            code_challenge: doc.data.code_challenge,
            code_challenge_method: doc.data.code_challenge_method,
            created_at: doc.created_at,
            expires_at: doc.data.expires_at,
            consumed_at: doc.data.consumed_at,
            resource: doc.data.resource,
            acr_values: doc.data.acr_values,
            max_age: doc.data.max_age,
            prompt: doc.data.prompt,
            dpop_jkt: doc.data.dpop_jkt,
            authorization_details: doc.data.authorization_details,
            response_mode: doc.data.response_mode,
            par_request_uri: doc.data.par_request_uri,
        }
    }
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
    pub resource: Option<&'a str>,
    pub acr_values: Option<&'a str>,
    pub max_age: Option<i64>,
    pub prompt: Option<&'a str>,
    pub dpop_jkt: Option<&'a str>,
    /// RFC 9396: Rich authorization details (JSON array).
    pub authorization_details: Option<&'a serde_json::Value>,
    /// JARM: response_mode from the authorization request.
    pub response_mode: super::documents::oauth::ResponseMode,
    /// RFC 9126: PAR request_uri to consume when authorization completes.
    pub par_request_uri: Option<&'a str>,
}

/// Create a pending OAuth authorization.
pub async fn create_pending_oauth_authorization(
    store: &DocumentStore,
    params: CreatePendingOAuthParams<'_>,
) -> Result<String> {
    let now = Timestamp::now();
    let expires_at = now
        .checked_add(Span::new().minutes(10))
        .map_err(|_| anyhow::anyhow!("Time calculation overflow computing expiration"))?;

    let doc = PendingOAuthAuthDoc {
        client_id: params.client_id.to_string(),
        redirect_uri: params.redirect_uri.to_string(),
        response_type: params.response_type.to_string(),
        state: params.state.map(String::from),
        scope: params.scope.map(String::from),
        nonce: params.nonce.map(String::from),
        code_challenge: params.code_challenge.map(String::from),
        code_challenge_method: params.code_challenge_method.map(String::from),
        expires_at,
        consumed_at: None,
        resource: params.resource.map(String::from),
        acr_values: params.acr_values.map(String::from),
        max_age: params.max_age,
        prompt: params.prompt.map(String::from),
        dpop_jkt: params.dpop_jkt.map(String::from),
        authorization_details: params.authorization_details.cloned(),
        response_mode: params.response_mode,
        par_request_uri: params.par_request_uri.map(String::from),
    };
    let result = store.insert(&doc).await?;
    Ok(result.id)
}

/// Get a pending OAuth authorization by ID.
///
/// Returns None if not found, expired, or already consumed.
pub async fn get_pending_oauth_authorization(
    store: &DocumentStore,
    id: &str,
) -> Result<Option<PendingOAuthAuthorization>> {
    let now = Timestamp::now();

    let doc = store.get::<PendingOAuthAuthDoc>(id).await?;
    match doc {
        Some(d) if d.data.consumed_at.is_none() && d.data.expires_at > now => {
            Ok(Some(PendingOAuthAuthorization::from(d)))
        }
        _ => Ok(None),
    }
}

/// Witness that a pending OAuth authorization was atomically consumed.
///
/// Construction is private to this module — the only path to an instance
/// is a successful return from [`consume_pending_oauth_authorization`],
/// which uses optimistic-concurrency `compare_and_update` to ensure at
/// most one concurrent caller succeeds.
///
/// Intentionally not `Clone`. The `#[must_use]` ensures the witness is
/// bound at the call site. Same shape as the other consume-once
/// witnesses (`AuthCodeClaim`, `ParStateClaim`, `OidcStateClaim`, etc.) —
/// the consumed record's data is returned alongside the witness rather
/// than carried inside it, matching the codebase convention.
#[must_use = "the pending OAuth authorization was atomically consumed; bind \
              this witness so downstream code can require it as a precondition"]
#[derive(Debug)]
pub(crate) struct PendingOauthClaim {
    _private: (),
}

/// Atomically consume a pending OAuth authorization (single-use).
///
/// Runs `get` + `compare_and_update` + `get` inside a single transaction
/// (same as the prior implementation, one round-trip). The
/// `compare_and_update` version check ensures at most one concurrent
/// caller wins the write, preventing a double-consume race regardless of
/// DB isolation level (the prior `tx.update` had no version predicate, so
/// two concurrent READ-COMMITTED transactions could both lost-update).
///
/// All "lost" cases (not found, expired, already consumed, concurrent
/// consumer won) map to [`ClaimError::AlreadyConsumed`] — deliberately
/// indistinguishable, each rejected as an invalid `pending_auth`.
pub(crate) async fn consume_pending_oauth_authorization(
    store: &DocumentStore,
    id: &str,
) -> std::result::Result<(PendingOAuthAuthorization, PendingOauthClaim), ClaimError> {
    let now = Timestamp::now();

    let doc = store
        .get::<PendingOAuthAuthDoc>(id)
        .await
        .map_err(|e| ClaimError::Database(e.to_string()))?;
    let Some(doc) = doc else {
        return Err(ClaimError::AlreadyConsumed);
    };

    if doc.data.consumed_at.is_some() || doc.data.expires_at <= now {
        return Err(ClaimError::AlreadyConsumed);
    }

    let created_at = doc.created_at;
    let version = doc.version;
    let mut data = doc.data;
    data.consumed_at = Some(now);
    let won = store
        .compare_and_update(id, version, &data)
        .await
        .map_err(|e| ClaimError::Database(e.to_string()))?;
    if !won {
        return Err(ClaimError::AlreadyConsumed);
    }

    // Build the result from the in-memory mutated `data` rather than
    // re-reading. The fields we care about are either already in `data`
    // (mutated copy of the row we read) or are the document metadata
    // (`id`, `created_at`) captured from the first read.
    let auth = PendingOAuthAuthorization {
        id: id.to_string(),
        client_id: data.client_id,
        redirect_uri: data.redirect_uri,
        response_type: data.response_type,
        state: data.state,
        scope: data.scope,
        nonce: data.nonce,
        code_challenge: data.code_challenge,
        code_challenge_method: data.code_challenge_method,
        created_at,
        expires_at: data.expires_at,
        consumed_at: data.consumed_at,
        resource: data.resource,
        acr_values: data.acr_values,
        max_age: data.max_age,
        prompt: data.prompt,
        dpop_jkt: data.dpop_jkt,
        authorization_details: data.authorization_details,
        response_mode: data.response_mode,
        par_request_uri: data.par_request_uri,
    };
    Ok((auth, PendingOauthClaim { _private: () }))
}

/// Delete expired pending OAuth authorizations.
pub async fn delete_expired_pending_oauth_authorizations(
    store: &DocumentStore,
    _now: &str,
) -> Result<u64> {
    store.delete_expired(PendingOAuthAuthDoc::DOC_TYPE).await
}
