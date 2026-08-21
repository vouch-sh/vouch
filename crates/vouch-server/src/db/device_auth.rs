// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device Authorization (RFC 8628) database operations.

use super::claim::ClaimError;
use super::document_type::Document;
use super::documents::device_auth::{DeviceAuthRequestDoc, OidcStateDoc};
use super::store::DocumentStore;
use anyhow::{Result, bail};
use jiff::Timestamp;

// Re-export DeviceAuthStatus from documents module
pub use super::documents::device_auth::DeviceAuthStatus;

/// Approval evidence recorded when a pending request is authorized.
///
/// Only [`state_from_stored`] constructs one, and only from a row whose
/// approval fields are all present — the device-code grant cannot reach
/// token issuance holding a partial approval.
#[derive(Debug, Clone)]
pub struct DeviceAuthApproval {
    pub user_id: String,
    pub user_email: String,
    /// Authenticator that approved the request.
    pub authenticator_id: String,
    /// Whether the approving browser session completed a WebAuthn ceremony.
    /// The device-code grant issues its token with this as the
    /// `hardware_verified` claim.
    pub hardware_verified: bool,
}

/// Domain state of a device authorization request. The stored document
/// keeps the status and the approval fields separate so rows stay readable
/// across a rolling deploy; this enum is what consumers see, and it has no
/// approval-less `Authorized`.
#[derive(Debug)]
pub enum DeviceAuthState {
    Pending,
    Authorized(DeviceAuthApproval),
    Denied,
    /// `user_id` is retained for replay revocation; `None` on rows written
    /// before approval attribution was recorded.
    Consumed {
        user_id: Option<String>,
    },
}

/// An `authorized` row whose approval fields are incomplete — the approving
/// authenticator was deleted before redemption — has no approval left to
/// redeem and reads as denied. RFC 8628 §3.5
/// (<https://www.rfc-editor.org/rfc/rfc8628#section-3.5>):
///
/// > access_denied
/// >    The authorization request was denied.
fn state_from_stored(data: &DeviceAuthRequestDoc) -> DeviceAuthState {
    match data.status {
        DeviceAuthStatus::Pending => DeviceAuthState::Pending,
        DeviceAuthStatus::Denied => DeviceAuthState::Denied,
        DeviceAuthStatus::Authorized => {
            match (&data.user_id, &data.user_email, &data.authenticator_id) {
                (Some(user_id), Some(user_email), Some(authenticator_id)) => {
                    DeviceAuthState::Authorized(DeviceAuthApproval {
                        user_id: user_id.clone(),
                        user_email: user_email.clone(),
                        authenticator_id: authenticator_id.clone(),
                        hardware_verified: data.hardware_verified,
                    })
                }
                _ => DeviceAuthState::Denied,
            }
        }
        DeviceAuthStatus::Consumed => DeviceAuthState::Consumed {
            user_id: data.user_id.clone(),
        },
    }
}

/// Device authorization request record.
#[derive(Debug)]
pub struct DeviceAuthRequest {
    pub id: String,
    pub device_code_hash: String,
    pub user_code: String,
    pub state: DeviceAuthState,
    /// OAuth client_id that initiated this device authorization.
    pub client_id: Option<String>,
    pub expires_at: Timestamp,
    pub interval_seconds: i32,
    pub last_poll_at: Option<Timestamp>,
    pub consumed_at: Option<Timestamp>,
}

impl From<Document<DeviceAuthRequestDoc>> for DeviceAuthRequest {
    fn from(doc: Document<DeviceAuthRequestDoc>) -> Self {
        let state = state_from_stored(&doc.data);
        Self {
            id: doc.id,
            device_code_hash: doc.data.device_code_hash,
            user_code: doc.data.user_code,
            state,
            client_id: doc.data.client_id,
            expires_at: doc.data.expires_at,
            interval_seconds: doc.data.interval_seconds,
            last_poll_at: doc.data.last_poll_at,
            consumed_at: doc.data.consumed_at,
        }
    }
}

/// OIDC state record.
#[derive(Debug)]
pub struct OidcState {
    pub id: String,
    pub state: String,
    /// ID of the CLI-initiated device authorization this flow approves.
    /// `None` for direct browser sign-ins.
    pub device_auth_id: Option<String>,
    pub nonce: String,
    /// PKCE code_verifier (RFC 7636).
    pub code_verifier: String,
    pub expires_at: Timestamp,
    /// Slug of the OIDC provider that initiated this flow (empty for SAML).
    pub provider_id: String,
}

/// The stored document keeps `device_auth_id` as a plain string — empty
/// meaning "no CLI device authorization" — so rows stay readable by older
/// servers during a rolling deploy; the API surface exposes the real shape.
fn stored_device_auth_id(stored: String) -> Option<String> {
    (!stored.is_empty()).then_some(stored)
}

impl From<Document<OidcStateDoc>> for OidcState {
    fn from(doc: Document<OidcStateDoc>) -> Self {
        Self {
            id: doc.id,
            state: doc.data.state,
            device_auth_id: stored_device_auth_id(doc.data.device_auth_id),
            nonce: doc.data.nonce,
            code_verifier: doc.data.code_verifier,
            expires_at: doc.data.expires_at,
            provider_id: doc.data.provider_id,
        }
    }
}

/// Witness that an OIDC state record was atomically transitioned to
/// `consumed_at = Some(now)` by this caller. Construction is private to
/// this module — the only path to an instance is a successful return from
/// [`try_consume_oidc_state`], whose optimistic-concurrency
/// `compare_and_update` guarantees that at most one concurrent caller
/// succeeds. Holding an `OidcStateClaim` is compile-time evidence that
/// this caller "won" the consume.
///
/// Intentionally not `Clone`. The `#[must_use]` ensures the witness is
/// bound at the call site (threaded into
/// `GrantProof::EnrollmentBootstrap(claim)`).
#[must_use = "the OIDC state was atomically consumed; bind this witness so \
              it can be threaded into TokenIssuanceProof"]
#[derive(Debug)]
pub struct OidcStateClaim {
    _private: (),
}

/// Create a new device authorization request.
pub async fn create_device_auth_request(
    store: &DocumentStore,
    device_code_hash: &str,
    user_code: &str,
    client_id: Option<&str>,
    expires_at: Timestamp,
    interval_seconds: i32,
) -> Result<String> {
    let doc = DeviceAuthRequestDoc {
        device_code_hash: device_code_hash.to_string(),
        user_code: user_code.to_string(),
        status: DeviceAuthStatus::Pending,
        client_id: client_id.map(String::from),
        user_id: None,
        user_email: None,
        authenticator_id: None,
        hardware_verified: false,
        expires_at,
        interval_seconds,
        last_poll_at: None,
        consumed_at: None,
    };
    let result = store.insert(&doc).await?;
    Ok(result.id)
}

/// Get a device auth request by device code hash.
pub async fn get_device_auth_by_code_hash(
    store: &DocumentStore,
    device_code_hash: &str,
) -> Result<Option<DeviceAuthRequest>> {
    let doc = store
        .find_one::<DeviceAuthRequestDoc>("device_code_hash", device_code_hash)
        .await?;
    Ok(doc.map(DeviceAuthRequest::from))
}

/// Get a device auth request by user code.
pub async fn get_device_auth_by_user_code(
    store: &DocumentStore,
    user_code: &str,
) -> Result<Option<DeviceAuthRequest>> {
    let doc = store
        .find_one::<DeviceAuthRequestDoc>("user_code", user_code)
        .await?;
    Ok(doc.map(DeviceAuthRequest::from))
}

/// Get a device auth request by ID.
#[allow(
    dead_code,
    reason = "API exposed for callers; lint fires inconsistently across compilation targets"
)]
pub(crate) async fn get_device_auth_by_id(
    store: &DocumentStore,
    id: &str,
) -> Result<Option<DeviceAuthRequest>> {
    let doc = store.get::<DeviceAuthRequestDoc>(id).await?;
    Ok(doc.map(DeviceAuthRequest::from))
}

/// Inputs for [`authorize_device_auth`].
pub struct AuthorizeDeviceAuthParams<'a> {
    /// ID of the pending device authorization request.
    pub id: &'a str,
    pub user_id: &'a str,
    pub user_email: &'a str,
    /// Authenticator that approved the request.
    pub authenticator_id: &'a str,
    /// Whether the approving browser session completed a WebAuthn ceremony.
    /// Recorded on the request so the device-code grant issues its token with
    /// a `hardware_verified` claim that reflects what actually happened.
    pub hardware_verified: bool,
}

/// Authorize a device auth request.
///
/// Uses `compare_and_update` (OCC) so two concurrent authorization
/// attempts cannot both succeed under PostgreSQL READ COMMITTED — the
/// loser sees a version mismatch and is reported as a conflict. The
/// blind `tx.update` it replaced would have let both writers commit,
/// each clobbering the other's user attribution.
pub async fn authorize_device_auth(
    store: &DocumentStore,
    params: AuthorizeDeviceAuthParams<'_>,
) -> Result<()> {
    let AuthorizeDeviceAuthParams {
        id,
        user_id,
        user_email,
        authenticator_id,
        hardware_verified,
    } = params;

    if id.is_empty() {
        bail!("authorize_device_auth called with empty id");
    }

    let doc = store.get::<DeviceAuthRequestDoc>(id).await?;
    let Some(doc) = doc else {
        bail!(
            "authorize_device_auth: no device auth request \
             found with id '{}'",
            id
        );
    };

    if doc.data.status != DeviceAuthStatus::Pending {
        bail!(
            "authorize_device_auth: device auth request '{}' \
             already has status '{:?}'",
            id,
            doc.data.status
        );
    }

    let version = doc.version;
    let mut data = doc.data;
    data.status = DeviceAuthStatus::Authorized;
    data.user_id = Some(user_id.to_string());
    data.user_email = Some(user_email.to_string());
    data.authenticator_id = Some(authenticator_id.to_string());
    data.hardware_verified = hardware_verified;
    let won = store.compare_and_update(id, version, &data).await?;
    if !won {
        bail!(
            "authorize_device_auth: device auth request '{}' was \
             concurrently modified",
            id
        );
    }

    Ok(())
}

/// Deny a device auth request.
///
/// Uses `compare_and_update` (OCC) for the same reason as
/// [`authorize_device_auth`]: two concurrent denials (or a concurrent
/// authorize + deny) cannot both win under READ COMMITTED.
///
/// Test-only: no production path denies explicitly — a request either gets
/// approved, expires, or is voided when its approving authenticator is
/// deleted (`delete_authenticator`).
#[cfg(test)]
pub async fn deny_device_auth(store: &DocumentStore, id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("deny_device_auth called with empty id");
    }

    let doc = store.get::<DeviceAuthRequestDoc>(id).await?;
    let Some(doc) = doc else {
        bail!(
            "deny_device_auth: no device auth request \
             found with id '{}'",
            id
        );
    };

    if doc.data.status != DeviceAuthStatus::Pending {
        bail!(
            "deny_device_auth: device auth request '{}' \
             already has status '{:?}'",
            id,
            doc.data.status
        );
    }

    let version = doc.version;
    let mut data = doc.data;
    data.status = DeviceAuthStatus::Denied;
    let won = store.compare_and_update(id, version, &data).await?;
    if !won {
        bail!(
            "deny_device_auth: device auth request '{}' was \
             concurrently modified",
            id
        );
    }

    Ok(())
}

/// Witness that an authorized device code (RFC 8628 Section 3.5) was
/// atomically transitioned to `Consumed` by this caller. Construction is
/// private to this module — the only path to an instance is a successful
/// return from [`try_consume_device_auth`], whose optimistic-concurrency
/// `compare_and_update` guarantees that at most one concurrent caller
/// succeeds. Holding a `DeviceCodeClaim` is compile-time evidence that
/// this caller "won" the consume.
///
/// Intentionally not `Clone`. The `#[must_use]` ensures the witness is
/// bound at the call site even when threaded into a downstream consumer
/// (e.g., `GrantProof::DeviceCode(claim)`).
#[must_use = "the device code was atomically consumed; bind this witness so \
              it can be threaded into TokenIssuanceProof"]
#[derive(Debug)]
pub struct DeviceCodeClaim {
    _private: (),
}

/// Try to consume an authorized device code (RFC 8628 Section 3.5).
///
/// On success returns the [`DeviceAuthApproval`] read in the same atomic
/// step plus a [`DeviceCodeClaim`] witness — proof that this caller won the
/// optimistic-concurrency consume. Token issuance takes its user
/// attribution from this approval, never from an earlier (raceable) read.
/// All "lost" cases (not found, no redeemable approval, expired, or
/// concurrent consumer won via version mismatch) map to
/// [`ClaimError::AlreadyConsumed`] — deliberately indistinguishable, each
/// rejected as an invalid_grant.
pub async fn try_consume_device_auth(
    store: &DocumentStore,
    device_code_hash: &str,
) -> std::result::Result<(DeviceAuthApproval, DeviceCodeClaim), ClaimError> {
    let now = Timestamp::now();

    let doc = store
        .find_one::<DeviceAuthRequestDoc>("device_code_hash", device_code_hash)
        .await
        .map_err(|e| ClaimError::Database(e.to_string()))?;
    let Some(doc) = doc else {
        return Err(ClaimError::AlreadyConsumed);
    };

    let DeviceAuthState::Authorized(approval) = state_from_stored(&doc.data) else {
        return Err(ClaimError::AlreadyConsumed);
    };
    if doc.data.expires_at <= now {
        return Err(ClaimError::AlreadyConsumed);
    }

    // Atomic transition: compare_and_update returns false on version mismatch
    // (a concurrent caller wrote a newer version first).
    let mut data = doc.data;
    data.status = DeviceAuthStatus::Consumed;
    data.consumed_at = Some(now);
    let won = store
        .compare_and_update(&doc.id, doc.version, &data)
        .await
        .map_err(|e| ClaimError::Database(e.to_string()))?;
    if won {
        Ok((approval, DeviceCodeClaim { _private: () }))
    } else {
        Err(ClaimError::AlreadyConsumed)
    }
}

/// Update the last poll time for a device auth request.
/// Returns true if poll was allowed, false if polling too fast.
pub async fn update_device_auth_poll_time(
    store: &DocumentStore,
    id: &str,
    interval_seconds: i32,
) -> Result<bool> {
    let now = jiff::Timestamp::now();

    let doc = store.get::<DeviceAuthRequestDoc>(id).await?;
    let Some(doc) = doc else {
        return Ok(false);
    };

    // Check if polling too fast
    if let Some(last_poll) = doc.data.last_poll_at {
        let elapsed = now.as_second().saturating_sub(last_poll.as_second());
        if elapsed < i64::from(interval_seconds) {
            return Ok(false);
        }
    }

    let mut data = doc.data;
    data.last_poll_at = Some(now);
    // Use compare_and_update to avoid blind overwrites that could
    // revert a concurrent status change (e.g. Consumed → Authorized).
    // A version conflict is harmless here — proceed as if poll was
    // allowed since the rate limit is a courtesy, not a security
    // control.
    let _updated = store.compare_and_update(id, doc.version, &data).await?;
    Ok(true)
}

/// Delete expired device auth requests.
///
/// Also deletes associated OIDC states.
pub async fn delete_expired_device_auth_requests(store: &DocumentStore, _now: &str) -> Result<u64> {
    use super::document_type::DocumentType;

    // Delete expired OIDC states first
    store.delete_expired(OidcStateDoc::DOC_TYPE).await?;
    // Then delete expired device auth requests
    store.delete_expired(DeviceAuthRequestDoc::DOC_TYPE).await
}

// ============================================================================
// OIDC State
// ============================================================================

/// Create a new OIDC state.
///
/// `device_auth_id` is the CLI-initiated device authorization this flow
/// will approve; pass `None` for direct browser sign-ins.
pub async fn create_oidc_state(
    store: &DocumentStore,
    state: &str,
    device_auth_id: Option<&str>,
    nonce: &str,
    code_verifier: &str,
    expires_at: Timestamp,
    provider_id: &str,
) -> Result<String> {
    let doc = OidcStateDoc {
        state: state.to_string(),
        device_auth_id: device_auth_id.unwrap_or_default().to_string(),
        nonce: nonce.to_string(),
        code_verifier: code_verifier.to_string(),
        expires_at,
        provider_id: provider_id.to_string(),
        consumed_at: None,
    };
    let result = store.insert(&doc).await?;
    Ok(result.id)
}

/// Get an OIDC state by state value.
pub async fn get_oidc_state(store: &DocumentStore, state: &str) -> Result<Option<OidcState>> {
    let doc = store.find_one::<OidcStateDoc>("state", state).await?;
    Ok(doc.map(OidcState::from))
}

/// Atomically consume an OIDC state record.
///
/// On success returns `(OidcState, OidcStateClaim)` — the state data
/// needed for downstream processing plus the witness proving this caller
/// won the OCC consume. All "lost" cases (state not found, already
/// consumed, expired, concurrent consumer won via version mismatch) map
/// to [`ClaimError::AlreadyConsumed`] — deliberately indistinguishable,
/// each rejected the same way at the handler.
///
/// This closes the read-vs-consume TOCTOU window that existed when
/// callers used `get_oidc_state` + `delete_oidc_state` as separate steps:
/// two concurrent enrollment-callback requests could both read the same
/// state, both pass validation, and both proceed to issue tokens before
/// either delete completed.
pub async fn try_consume_oidc_state(
    store: &DocumentStore,
    state: &str,
) -> std::result::Result<(OidcState, OidcStateClaim), ClaimError> {
    let now = Timestamp::now();

    let doc = store
        .find_one::<OidcStateDoc>("state", state)
        .await
        .map_err(|e| ClaimError::Database(e.to_string()))?;
    let Some(doc) = doc else {
        return Err(ClaimError::AlreadyConsumed);
    };

    if doc.data.consumed_at.is_some() || doc.data.expires_at <= now {
        return Err(ClaimError::AlreadyConsumed);
    }

    let mut data = doc.data;
    data.consumed_at = Some(now);
    let won = store
        .compare_and_update(&doc.id, doc.version, &data)
        .await
        .map_err(|e| ClaimError::Database(e.to_string()))?;
    if won {
        Ok((
            OidcState {
                id: doc.id,
                state: data.state,
                device_auth_id: stored_device_auth_id(data.device_auth_id),
                nonce: data.nonce,
                code_verifier: data.code_verifier,
                expires_at: data.expires_at,
                provider_id: data.provider_id,
            },
            OidcStateClaim { _private: () },
        ))
    } else {
        Err(ClaimError::AlreadyConsumed)
    }
}

/// Delete expired OIDC states.
pub async fn delete_expired_oidc_states(store: &DocumentStore, _now: &str) -> Result<u64> {
    use super::document_type::DocumentType;

    store.delete_expired(OidcStateDoc::DOC_TYPE).await
}
