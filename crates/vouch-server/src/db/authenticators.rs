// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authenticator (WebAuthn credential) database operations.

use super::document_type::Document;
use super::documents::authenticator::AuthenticatorDoc;
use super::documents::device_auth::{DeviceAuthRequestDoc, DeviceAuthStatus};
use super::documents::session::SessionDoc;
use super::store::{DocumentStore, StoreTransaction};
use super::users::User;
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;

/// Authenticator (credential) record.
#[derive(Debug)]
pub struct Authenticator {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    /// WebAuthn signature counter (32-bit per spec).
    pub counter: i32,
    pub created_at: Timestamp,
    /// AAGUID (Authenticator Attestation GUID).
    pub aaguid: Option<String>,
    /// User handle stored in discoverable credentials.
    pub user_handle: Option<Vec<u8>>,
    /// Whether the attestation was cryptographically verified via x5c chain.
    pub attestation_verified: bool,
}

impl TryFrom<Document<AuthenticatorDoc>> for Authenticator {
    type Error = anyhow::Error;

    fn try_from(doc: Document<AuthenticatorDoc>) -> Result<Self> {
        Ok(Self {
            id: doc.id,
            user_id: doc.data.user_id,
            name: doc.data.name,
            credential_id: URL_SAFE_NO_PAD
                .decode(&doc.data.credential_id)
                .context("invalid base64 in credential_id")?,
            public_key: URL_SAFE_NO_PAD
                .decode(&doc.data.public_key)
                .context("invalid base64 in public_key")?,
            counter: doc.data.counter,
            created_at: doc.created_at,
            aaguid: doc.data.aaguid,
            user_handle: doc
                .data
                .user_handle
                .map(|h| URL_SAFE_NO_PAD.decode(&h))
                .transpose()
                .context("invalid base64 in user_handle")?,
            attestation_verified: doc.data.attestation_verified,
        })
    }
}

/// Result of looking up an authenticator with its owning user.
///
/// Built from the denormalized `user_email` on `AuthenticatorDoc`,
/// so no JOIN is needed.
#[derive(Debug)]
pub struct AuthenticatorWithUser {
    pub authenticator: Authenticator,
    pub user: User,
}

/// Parameters for creating a new authenticator.
///
/// `user_email` is denormalized into the document to eliminate JOINs.
pub struct CreateAuthenticatorParams<'a> {
    pub user_id: &'a str,
    pub user_email: &'a str,
    pub name: &'a str,
    pub credential_id: &'a [u8],
    pub public_key: &'a [u8],
    pub aaguid: Option<&'a str>,
    pub user_handle: Option<&'a [u8]>,
    pub attestation_verified: bool,
    /// The verified `authData.signCount` from the registration ceremony
    /// (WebAuthn L2 §7.1 step 23: "Associate the `credentialId` with a new
    /// stored signature counter value initialized to the value of
    /// `authData.signCount`"). The first assertion's clone-detection guard
    /// (`webauthn_verify::verify_assertion_inner`) runs against this
    /// stored value, so it must reflect the registration `signCount` — not
    /// a hardcoded `0` — for the spec-permitted global-counter
    /// authenticator class that reports a non-zero value at make. `0` is
    /// the spec-correct value for per-credential-counter (CTAP 2.1+) and
    /// counter-less authenticators; pass it through unchanged for those.
    pub counter: u32,
}

/// Create a new authenticator.
pub async fn create_authenticator(
    store: &DocumentStore,
    params: &CreateAuthenticatorParams<'_>,
) -> Result<String> {
    let doc = AuthenticatorDoc {
        user_id: params.user_id.to_string(),
        user_email: params.user_email.to_string(),
        name: params.name.to_string(),
        credential_id: URL_SAFE_NO_PAD.encode(params.credential_id),
        public_key: URL_SAFE_NO_PAD.encode(params.public_key),
        // WebAuthn counter is u32; stored bit-identical as i32 (the column
        // type, see `AuthenticatorDoc::counter`). Real authenticators never
        // approach 2^31 uses, and the bitwise reinterpret preserves DB
        // monotonicity comparisons — see `update_authenticator_counter`'s
        // callers in `services/oidc/fido2_grant.rs` and
        // `handlers/browser_login.rs`, which use the same `cast_signed`
        // for assertion counters. The registration value initializes the
        // stored counter to `authData.signCount` (WebAuthn L2 §7.1 step
        // 23) rather than `0`, so the first assertion's clone-detection
        // check (`webauthn_verify::verify_assertion_inner` at the
        // `stored_counter != 0 && counter <= stored_counter` guard) runs
        // against a spec-correct baseline.
        counter: params.counter.cast_signed(),
        aaguid: params.aaguid.map(String::from),
        user_handle: params.user_handle.map(|h| URL_SAFE_NO_PAD.encode(h)),
        attestation_verified: params.attestation_verified,
    };
    let result = store.insert(&doc).await?;
    Ok(result.id)
}

/// Get authenticators for a user.
pub async fn get_authenticators_for_user(
    store: &DocumentStore,
    user_id: &str,
) -> Result<Vec<Authenticator>> {
    let docs = store
        .find_all::<AuthenticatorDoc>("user_id", user_id)
        .await?;
    docs.into_iter()
        .map(Authenticator::try_from)
        .collect::<Result<Vec<_>>>()
}

/// Get an authenticator by credential ID.
pub async fn get_authenticator_by_credential_id(
    store: &DocumentStore,
    credential_id: &[u8],
) -> Result<Option<Authenticator>> {
    let encoded = URL_SAFE_NO_PAD.encode(credential_id);
    let doc = store
        .find_one::<AuthenticatorDoc>("credential_id", &encoded)
        .await?;
    doc.map(Authenticator::try_from).transpose()
}

/// Get an authenticator and its owning user by credential ID.
///
/// Uses denormalized `user_email` in `AuthenticatorDoc` instead of a JOIN.
/// Falls back to user lookup by ID to populate full user record.
pub async fn get_authenticator_with_user_by_credential_id(
    store: &DocumentStore,
    credential_id: &[u8],
) -> Result<Option<AuthenticatorWithUser>> {
    let encoded = URL_SAFE_NO_PAD.encode(credential_id);
    let doc = store
        .find_one::<AuthenticatorDoc>("credential_id", &encoded)
        .await?;

    let Some(doc) = doc else {
        return Ok(None);
    };

    let user_id = doc.data.user_id.clone();
    let authenticator = Authenticator::try_from(doc)?;

    // Look up the full user record
    let user = super::users::get_user_by_id(store, &user_id).await?;
    let Some(user) = user else {
        return Ok(None);
    };

    Ok(Some(AuthenticatorWithUser {
        authenticator,
        user,
    }))
}

/// Get an authenticator by ID.
pub async fn get_authenticator_by_id(
    store: &DocumentStore,
    authenticator_id: &str,
) -> Result<Option<Authenticator>> {
    let doc = store.get::<AuthenticatorDoc>(authenticator_id).await?;
    doc.map(Authenticator::try_from).transpose()
}

/// Update authenticator counter.
///
/// Uses optimistic concurrency (`store.modify`) and takes the max of the
/// stored counter and the incoming value so that concurrent updates from
/// parallel authentication flows never regress the counter. A missing
/// authenticator is warned and ignored (the caller should not fail an
/// ongoing authentication solely due to a missing counter record).
pub async fn update_authenticator_counter(
    store: &DocumentStore,
    authenticator_id: &str,
    counter: i32,
) -> Result<()> {
    let found = store
        .modify::<AuthenticatorDoc, _>(authenticator_id, |data| {
            data.counter = std::cmp::max(data.counter, counter);
        })
        .await?;
    if !found {
        tracing::warn!(
            authenticator_id,
            "update_authenticator_counter: authenticator not found"
        );
    }
    Ok(())
}

/// Count the number of authenticators for a user.
pub async fn count_authenticators_for_user(store: &DocumentStore, user_id: &str) -> Result<i64> {
    store.count::<AuthenticatorDoc>("user_id", user_id).await
}

/// Void any approval that referenced a now-deleted authenticator. The
/// approval's evidence is gone, so an `authorized` request is denied
/// rather than left redeemable (RFC 8628 §3.5 `access_denied`); consumed
/// requests keep their attribution for replay revocation.
fn detach_authenticator_from_device_auth(d: &mut DeviceAuthRequestDoc) {
    d.authenticator_id = None;
    if d.status == DeviceAuthStatus::Authorized {
        d.status = DeviceAuthStatus::Denied;
    }
}

/// Delete an authenticator by ID, cascading to what referenced it.
///
/// Application-level cascade, in order:
/// 1. Void device_auth_request approvals that referenced this authenticator
/// 2. Delete sessions using this authenticator
/// 3. Delete the authenticator
///
/// Takes the caller's transaction because a half-applied cascade is a broken
/// state: sessions left alive for a key that no longer exists, or a key
/// removed while a device authorization still points at it. That, and so the
/// cascade composes with whatever invariant the caller holds around it — the
/// last-key guard and User-doc version bump in `services::keys::delete_key`,
/// the full account teardown in `delete_user`, or removing a member's whole
/// key set as one unit.
///
/// The detach step (1) is a `StoreTransaction::update_by_index`, whose every
/// write is guarded by the version read from the index. A `Consumed` row that
/// `try_consume_device_auth` committed between this transaction's read and
/// its write is therefore never overwritten with the stale `Authorized →
/// Denied` view — the guarded `UPDATE` matches zero rows, the operation
/// fails with a retryable `VersionConflict`, and the entry point's
/// `with_dsql_retry!` re-runs the whole cascade against the fresh row, which
/// `detach_authenticator_from_device_auth` leaves `Consumed`. Consumed
/// requests thus keep their attribution for the replay-revocation sweep
/// (`handlers::device::revoke_sessions_for_device_replay` only fires on
/// `Consumed`; RFC 6749 §10.5 defense-in-depth). Every caller must run
/// inside `with_dsql_retry!` — `services::keys::delete_key`, `delete_user`,
/// and the admin `revoke_member_credentials` handler all do.
pub async fn delete_authenticator(
    tx: &mut StoreTransaction<'_>,
    authenticator_id: &str,
) -> Result<()> {
    tx.update_by_index::<DeviceAuthRequestDoc, _>(
        "authenticator_id",
        authenticator_id,
        detach_authenticator_from_device_auth,
    )
    .await?;
    tx.delete_by_index::<SessionDoc>("authenticator_id", authenticator_id)
        .await?;
    tx.delete(authenticator_id).await?;
    Ok(())
}

/// Update an authenticator's name.
///
/// Uses optimistic concurrency (`store.modify`) so a concurrent counter update
/// cannot overwrite the name change, and vice versa.
pub async fn update_authenticator_name(
    store: &DocumentStore,
    authenticator_id: &str,
    name: &str,
) -> Result<bool> {
    let name_owned = name.to_string();
    store
        .modify::<AuthenticatorDoc, _>(authenticator_id, |data| {
            data.name = name_owned.clone();
        })
        .await
}
