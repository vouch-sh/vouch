// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authenticator (WebAuthn credential) database operations.

use super::document_type::Document;
use super::documents::authenticator::AuthenticatorDoc;
use super::documents::device_auth::DeviceAuthRequestDoc;
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
/// Replaces the old `AuthenticatorWithUser` JOIN type. Now uses
/// denormalized `user_email` from `AuthenticatorDoc`.
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
        counter: 0,
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

/// Delete an authenticator by ID.
///
/// Performs application-level cascade deletes:
/// 1. Clear authenticator_id references in device_auth_requests
/// 2. Delete sessions using this authenticator
/// 3. Delete the authenticator
pub async fn delete_authenticator(store: &DocumentStore, authenticator_id: &str) -> Result<u64> {
    // 1. Clear authenticator_id references in device_auth_requests
    store
        .update_by_index::<DeviceAuthRequestDoc, _>("authenticator_id", authenticator_id, |d| {
            d.authenticator_id = None;
        })
        .await?;

    // 2. Delete sessions using this authenticator
    store
        .delete_by_index::<SessionDoc>("authenticator_id", authenticator_id)
        .await?;

    // 3. Delete the authenticator
    store.delete(authenticator_id).await?;
    Ok(1)
}

/// Cascade-delete an authenticator within an open transaction.
///
/// Same steps as [`delete_authenticator`], but executed against a caller-owned
/// `StoreTransaction` so the cascade can be composed with additional checks
/// (e.g. last-key guard plus User-doc version bump) in a single atomic unit.
pub async fn delete_authenticator_in_tx(
    tx: &mut StoreTransaction<'_>,
    authenticator_id: &str,
) -> Result<()> {
    tx.update_by_index::<DeviceAuthRequestDoc, _>("authenticator_id", authenticator_id, |d| {
        d.authenticator_id = None;
    })
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
