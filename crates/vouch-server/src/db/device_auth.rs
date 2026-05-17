// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device Authorization (RFC 8628) database operations.

use super::document_type::Document;
use super::documents::device_auth::{DeviceAuthRequestDoc, OidcStateDoc};
use super::store::DocumentStore;
use anyhow::{Result, bail};
use jiff::Timestamp;

// Re-export DeviceAuthStatus from documents module
pub use super::documents::device_auth::DeviceAuthStatus;

/// Device authorization request record.
#[derive(Debug)]
pub struct DeviceAuthRequest {
    pub id: String,
    pub device_code_hash: String,
    pub user_code: String,
    pub status: DeviceAuthStatus,
    /// OAuth client_id that initiated this device authorization.
    pub client_id: Option<String>,
    pub user_id: Option<String>,
    pub user_email: Option<String>,
    pub authenticator_id: Option<String>,
    pub expires_at: Timestamp,
    pub interval_seconds: i32,
    pub last_poll_at: Option<Timestamp>,
    pub consumed_at: Option<Timestamp>,
}

impl From<Document<DeviceAuthRequestDoc>> for DeviceAuthRequest {
    fn from(doc: Document<DeviceAuthRequestDoc>) -> Self {
        Self {
            id: doc.id,
            device_code_hash: doc.data.device_code_hash,
            user_code: doc.data.user_code,
            status: doc.data.status,
            client_id: doc.data.client_id,
            user_id: doc.data.user_id,
            user_email: doc.data.user_email,
            authenticator_id: doc.data.authenticator_id,
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
    pub device_auth_id: String,
    pub nonce: String,
    /// PKCE code_verifier (RFC 7636).
    pub code_verifier: String,
    /// Slug of the IdP that initiated this state (empty for rows written
    /// before multi-IdP support landed).
    pub idp_slug: String,
    pub expires_at: Timestamp,
}

impl From<Document<OidcStateDoc>> for OidcState {
    fn from(doc: Document<OidcStateDoc>) -> Self {
        Self {
            id: doc.id,
            state: doc.data.state,
            device_auth_id: doc.data.device_auth_id,
            nonce: doc.data.nonce,
            code_verifier: doc.data.code_verifier,
            idp_slug: doc.data.idp_slug,
            expires_at: doc.data.expires_at,
        }
    }
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

/// Authorize a device auth request.
///
/// The read and status update execute within a single transaction so
/// concurrent authorization attempts are serialized correctly.
pub async fn authorize_device_auth(
    store: &DocumentStore,
    id: &str,
    user_id: &str,
    user_email: &str,
    authenticator_id: &str,
) -> Result<()> {
    if id.is_empty() {
        bail!("authorize_device_auth called with empty id");
    }

    let mut tx = store.begin().await?;

    let doc = tx.get::<DeviceAuthRequestDoc>(id).await?;
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

    let mut data = doc.data;
    data.status = DeviceAuthStatus::Authorized;
    data.user_id = Some(user_id.to_string());
    data.user_email = Some(user_email.to_string());
    data.authenticator_id = Some(authenticator_id.to_string());
    tx.update(id, &data).await?;

    tx.commit().await?;
    Ok(())
}

/// Deny a device auth request.
///
/// The read and status update execute within a single transaction so
/// concurrent denial attempts are serialized correctly.
pub async fn deny_device_auth(store: &DocumentStore, id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("deny_device_auth called with empty id");
    }

    let mut tx = store.begin().await?;

    let doc = tx.get::<DeviceAuthRequestDoc>(id).await?;
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

    let mut data = doc.data;
    data.status = DeviceAuthStatus::Denied;
    tx.update(id, &data).await?;

    tx.commit().await?;
    Ok(())
}

/// Try to consume an authorized device code (RFC 8628 Section 3.5).
///
/// Returns `true` if the code was successfully consumed (first use).
/// Returns `false` if already consumed, not authorized, expired,
/// or was concurrently consumed by another request (optimistic lock).
pub async fn try_consume_device_auth(
    store: &DocumentStore,
    device_code_hash: &str,
) -> Result<bool> {
    let now = Timestamp::now();

    let doc = store
        .find_one::<DeviceAuthRequestDoc>("device_code_hash", device_code_hash)
        .await?;
    let Some(doc) = doc else {
        return Ok(false);
    };

    // Only consume if currently Authorized and not expired
    if doc.data.status != DeviceAuthStatus::Authorized || doc.data.expires_at <= now {
        return Ok(false);
    }

    // Atomically transition to Consumed with optimistic concurrency.
    // If another request consumed between our read and write,
    // compare_and_update returns false (version mismatch).
    let mut data = doc.data;
    data.status = DeviceAuthStatus::Consumed;
    data.consumed_at = Some(now);
    store.compare_and_update(&doc.id, doc.version, &data).await
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
pub async fn create_oidc_state(
    store: &DocumentStore,
    state: &str,
    device_auth_id: &str,
    nonce: &str,
    code_verifier: &str,
    idp_slug: &str,
    expires_at: Timestamp,
) -> Result<String> {
    let doc = OidcStateDoc {
        state: state.to_string(),
        device_auth_id: device_auth_id.to_string(),
        nonce: nonce.to_string(),
        code_verifier: code_verifier.to_string(),
        idp_slug: idp_slug.to_string(),
        expires_at,
    };
    let result = store.insert(&doc).await?;
    Ok(result.id)
}

/// Get an OIDC state by state value.
pub async fn get_oidc_state(store: &DocumentStore, state: &str) -> Result<Option<OidcState>> {
    let doc = store.find_one::<OidcStateDoc>("state", state).await?;
    Ok(doc.map(OidcState::from))
}

/// Delete an OIDC state.
pub async fn delete_oidc_state(store: &DocumentStore, state: &str) -> Result<()> {
    store
        .delete_by_index::<OidcStateDoc>("state", state)
        .await?;
    Ok(())
}

/// Delete expired OIDC states.
pub async fn delete_expired_oidc_states(store: &DocumentStore, _now: &str) -> Result<u64> {
    use super::document_type::DocumentType;

    store.delete_expired(OidcStateDoc::DOC_TYPE).await
}
