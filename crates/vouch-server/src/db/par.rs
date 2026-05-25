// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Pushed Authorization Request (PAR) database operations (RFC 9126).
//!
//! Stores authorization request parameters pushed by authenticated clients
//! before the browser-based authorization flow begins.

use super::claim::ClaimError;
use super::document_type::{Document, DocumentType};
use super::documents::par::PushedAuthorizationRequestDoc;
use super::store::DocumentStore;
use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};

/// PAR lifetime in seconds (RFC 9126 Section 2.2).
///
/// 60 seconds is sufficient for the client to receive the `request_uri`
/// and redirect the user to the authorization endpoint.
pub const PAR_EXPIRES_IN: i64 = 60;

/// Pushed authorization request record.
#[derive(Debug)]
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
    /// RFC 9449 / FAPI 2.0: DPoP key thumbprint bound at PAR time.
    pub dpop_jkt: Option<String>,
    /// RFC 9396: Rich authorization details (JSON array).
    pub authorization_details: Option<serde_json::Value>,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub consumed_at: Option<Timestamp>,
    /// JARM: response mode requested by the client.
    pub response_mode: super::documents::oauth::ResponseMode,
}

impl From<Document<PushedAuthorizationRequestDoc>> for PushedAuthorizationRequest {
    fn from(doc: Document<PushedAuthorizationRequestDoc>) -> Self {
        Self {
            id: doc.id,
            request_uri: doc.data.request_uri,
            client_id: doc.data.client_id,
            response_type: doc.data.response_type,
            redirect_uri: doc.data.redirect_uri,
            scope: doc.data.scope,
            state: doc.data.state,
            nonce: doc.data.nonce,
            code_challenge: doc.data.code_challenge,
            code_challenge_method: doc.data.code_challenge_method,
            resource: doc.data.resource,
            acr_values: doc.data.acr_values,
            max_age: doc.data.max_age,
            prompt: doc.data.prompt,
            dpop_jkt: doc.data.dpop_jkt,
            authorization_details: doc.data.authorization_details,
            created_at: doc.created_at,
            expires_at: doc.data.expires_at,
            consumed_at: doc.data.consumed_at,
            response_mode: doc.data.response_mode,
        }
    }
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
    /// RFC 9449 / FAPI 2.0: DPoP key thumbprint for authorization code binding.
    pub dpop_jkt: Option<&'a str>,
    /// RFC 9396: Rich authorization details (JSON array).
    pub authorization_details: Option<&'a serde_json::Value>,
    /// JARM: response mode requested by the client.
    pub response_mode: super::documents::oauth::ResponseMode,
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
/// The `proof` parameter is a compile-time witness that the caller has
/// consumed the relevant single-use client-authentication primitive
/// (typically a JWT assertion JTI) before persisting the PAR record.
/// It is dropped immediately on entry — its only purpose is to make this
/// PAR storage chokepoint unforgeable from outside the crate.
pub(crate) async fn create_pushed_authorization_request(
    store: &DocumentStore,
    params: CreateParParams<'_>,
    proof: crate::services::auth::ParCreationProof,
) -> Result<(String, String)> {
    let crate::services::auth::ParCreationProof { client_auth } = proof;
    tracing::debug!(?client_auth, "PAR creation proof consumed");

    let request_uri = generate_request_uri()?;
    let now = Timestamp::now();
    let expires_at = now
        .checked_add(Span::new().seconds(PAR_EXPIRES_IN))
        .map_err(|_| anyhow::anyhow!("Time calculation overflow computing PAR expiration"))?;

    let doc = PushedAuthorizationRequestDoc {
        request_uri: request_uri.clone(),
        client_id: params.client_id.to_string(),
        response_type: params.response_type.to_string(),
        redirect_uri: params.redirect_uri.to_string(),
        scope: params.scope.map(String::from),
        state: params.state.map(String::from),
        nonce: params.nonce.map(String::from),
        code_challenge: params.code_challenge.map(String::from),
        code_challenge_method: params.code_challenge_method.map(String::from),
        resource: params.resource.map(String::from),
        acr_values: params.acr_values.map(String::from),
        max_age: params.max_age,
        prompt: params.prompt.map(String::from),
        dpop_jkt: params.dpop_jkt.map(String::from),
        expires_at,
        consumed_at: None,
        authorization_details: params.authorization_details.cloned(),
        response_mode: params.response_mode,
    };

    let result = store.insert(&doc).await?;
    Ok((result.id, request_uri))
}

/// Controls expiry enforcement when consuming a PAR (RFC 9126).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParConsumptionMode {
    /// Direct authorization: the user already has a session and the
    /// PAR is within its 60-second TTL. Enforce the expiry check.
    EnforceExpiry,
    /// Deferred authorization: the user completed login after the PAR
    /// TTL elapsed. Expiry was already validated at `/oauth/authorize`
    /// (FAPI 2.0 §5.3.2.2 Note 3). Skip the check.
    SkipExpiry,
}

/// Witness that a PAR record (RFC 9126) was atomically consumed by this
/// caller. Construction is private to this module — the only path to an
/// instance is a successful return from
/// [`consume_pushed_authorization_request`], whose
/// optimistic-concurrency `compare_and_update` guarantees that at most one
/// concurrent caller succeeds. Holding a `ParStateClaim` is compile-time
/// evidence that this caller's PAR consume "won" the OCC race.
///
/// Intentionally not `Clone`. The `#[must_use]` ensures the witness is
/// bound at the call site; today it is dropped immediately after
/// consumption (the immediate consumer issues an auth code rather than a
/// token), but the type exists so future code can require it as a
/// precondition for PAR-derived downstream operations.
#[must_use = "the PAR record was atomically consumed; bind this witness so \
              future code can require it as a precondition"]
#[derive(Debug)]
pub struct ParStateClaim {
    _private: (),
}

/// Consume a pushed authorization request (single-use).
///
/// On success returns a [`ParStateClaim`] witness — proof that this caller
/// won the optimistic-concurrency consume. On any "lost" case (PAR not
/// found, client_id mismatch, already consumed, or expired when expiry is
/// enforced) returns [`ClaimError::AlreadyConsumed`]. These cases are
/// deliberately indistinguishable from the caller's perspective: each is
/// rejected as an invalid request_uri.
///
/// # Client Binding
///
/// RFC 9126 Section 2.3: The authorization server MUST validate that the
/// `client_id` form parameter matches the `client_id` that was used when
/// the `request_uri` was created.
pub async fn consume_pushed_authorization_request(
    store: &DocumentStore,
    request_uri: &str,
    client_id: &str,
    mode: ParConsumptionMode,
) -> std::result::Result<ParStateClaim, ClaimError> {
    let now = Timestamp::now();

    let doc = store
        .find_one::<PushedAuthorizationRequestDoc>("request_uri", request_uri)
        .await
        .map_err(|e| ClaimError::Database(e.to_string()))?;

    let Some(doc) = doc else {
        return Err(ClaimError::AlreadyConsumed);
    };

    if doc.data.client_id != client_id || doc.data.consumed_at.is_some() {
        return Err(ClaimError::AlreadyConsumed);
    }

    if mode == ParConsumptionMode::EnforceExpiry && doc.data.expires_at <= now {
        return Err(ClaimError::AlreadyConsumed);
    }

    // Atomic consume via optimistic concurrency. If a concurrent caller
    // already consumed this PAR between our read and write,
    // compare_and_update returns false (version mismatch) — that caller
    // wins the race and we report AlreadyConsumed.
    let mut data = doc.data;
    data.consumed_at = Some(now);
    let won = store
        .compare_and_update(&doc.id, doc.version, &data)
        .await
        .map_err(|e| ClaimError::Database(e.to_string()))?;
    if won {
        Ok(ParStateClaim { _private: () })
    } else {
        Err(ClaimError::AlreadyConsumed)
    }
}

/// Look up a pushed authorization request without consuming it.
///
/// FAPI 2.0 Section 5.3.2.2 Note 3: request_uri values should be reusable
/// until the authorization request has been completed (code issued).
pub async fn get_pushed_authorization_request(
    store: &DocumentStore,
    request_uri: &str,
    client_id: &str,
) -> Result<Option<PushedAuthorizationRequest>> {
    let now = Timestamp::now();

    let doc = store
        .find_one::<PushedAuthorizationRequestDoc>("request_uri", request_uri)
        .await?;

    let Some(doc) = doc else {
        return Ok(None);
    };

    if doc.data.client_id != client_id
        || doc.data.consumed_at.is_some()
        || doc.data.expires_at <= now
    {
        return Ok(None);
    }

    Ok(Some(PushedAuthorizationRequest::from(doc)))
}

/// Delete expired pushed authorization requests.
pub async fn delete_expired_pushed_authorization_requests(
    store: &DocumentStore,
    _now: &str,
) -> Result<u64> {
    store
        .delete_expired(PushedAuthorizationRequestDoc::DOC_TYPE)
        .await
}
