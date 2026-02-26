// SPDX-License-Identifier: BUSL-1.1
//! Authenticator (WebAuthn credential) database operations.

use super::document_type::Document;
use super::documents::authenticator::AuthenticatorDoc;
use super::documents::device_auth::DeviceAuthRequestDoc;
use super::documents::session::SessionDoc;
use super::store::DocumentStore;
use super::users::User;
use anyhow::Result;
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
}

impl From<Document<AuthenticatorDoc>> for Authenticator {
    fn from(doc: Document<AuthenticatorDoc>) -> Self {
        Self {
            id: doc.id,
            user_id: doc.data.user_id,
            name: doc.data.name,
            credential_id: URL_SAFE_NO_PAD
                .decode(&doc.data.credential_id)
                .unwrap_or_default(),
            public_key: URL_SAFE_NO_PAD
                .decode(&doc.data.public_key)
                .unwrap_or_default(),
            counter: doc.data.counter,
            created_at: doc.created_at,
            aaguid: doc.data.aaguid,
            user_handle: doc
                .data
                .user_handle
                .and_then(|h| URL_SAFE_NO_PAD.decode(&h).ok()),
        }
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

/// Create a new authenticator.
///
/// `user_email` is denormalized into the document to eliminate JOINs.
#[allow(clippy::too_many_arguments)]
pub async fn create_authenticator(
    store: &DocumentStore,
    user_id: &str,
    user_email: &str,
    name: &str,
    credential_id: &[u8],
    public_key: &[u8],
    aaguid: Option<&str>,
    user_handle: Option<&[u8]>,
) -> Result<String> {
    let doc = AuthenticatorDoc {
        user_id: user_id.to_string(),
        user_email: user_email.to_string(),
        name: name.to_string(),
        credential_id: URL_SAFE_NO_PAD.encode(credential_id),
        public_key: URL_SAFE_NO_PAD.encode(public_key),
        counter: 0,
        aaguid: aaguid.map(String::from),
        user_handle: user_handle.map(|h| URL_SAFE_NO_PAD.encode(h)),
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
    Ok(docs.into_iter().map(Authenticator::from).collect())
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
    Ok(doc.map(Authenticator::from))
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
    let authenticator = Authenticator::from(doc);

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
    Ok(doc.map(Authenticator::from))
}

/// Update authenticator counter.
pub async fn update_authenticator_counter(
    store: &DocumentStore,
    authenticator_id: &str,
    counter: i32,
) -> Result<()> {
    if let Some(doc) = store.get::<AuthenticatorDoc>(authenticator_id).await? {
        let mut data = doc.data;
        data.counter = counter;
        store.update(authenticator_id, &data).await?;
    }
    Ok(())
}

/// Count the number of authenticators for a user.
pub async fn count_authenticators_for_user(store: &DocumentStore, user_id: &str) -> Result<i64> {
    store.count::<AuthenticatorDoc>("user_id", user_id).await
}

/// Count the number of sessions for an authenticator.
pub async fn count_sessions_for_authenticator(
    store: &DocumentStore,
    authenticator_id: &str,
) -> Result<i64> {
    store
        .count::<SessionDoc>("authenticator_id", authenticator_id)
        .await
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

/// Update an authenticator's name.
pub async fn update_authenticator_name(
    store: &DocumentStore,
    authenticator_id: &str,
    name: &str,
) -> Result<bool> {
    if let Some(doc) = store.get::<AuthenticatorDoc>(authenticator_id).await? {
        let mut data = doc.data;
        data.name = name.to_string();
        store.update(authenticator_id, &data).await?;
        Ok(true)
    } else {
        Ok(false)
    }
}
