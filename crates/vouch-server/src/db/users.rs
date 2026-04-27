// SPDX-License-Identifier: Apache-2.0 OR MIT
//! User database operations.

use super::document_type::Document;
use super::documents::user::UserDoc;
use super::store::DocumentStore;
use anyhow::{Context, Result};

/// User record.
#[derive(Debug)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub org_id: Option<String>,
    pub is_org_admin: bool,
    pub active: bool,
    pub external_id: Option<String>,
    pub github_id: Option<i64>,
    pub github_login: Option<String>,
    pub github_refresh_token: Option<String>,
}

impl From<Document<UserDoc>> for User {
    fn from(doc: Document<UserDoc>) -> Self {
        Self {
            id: doc.id,
            email: doc.data.email,
            name: doc.data.name,
            org_id: doc.data.org_id,
            is_org_admin: doc.data.is_org_admin,
            active: doc.data.active,
            external_id: doc.data.external_id,
            github_id: doc.data.github_id,
            github_login: doc.data.github_login,
            github_refresh_token: doc.data.github_refresh_token,
        }
    }
}

/// Create or find a user by email. Returns (user_id, was_created).
///
/// Note: Only used in tests. Production code uses the transactional
/// `enroll_user_with_org` function.
#[cfg(any(test, feature = "test-utils"))]
pub async fn upsert_user(
    store: &DocumentStore,
    email: &str,
    name: Option<&str>,
) -> Result<(String, bool)> {
    if let Some(doc) = store.find_one::<UserDoc>("email", email).await? {
        return Ok((doc.id, false));
    }
    let user_doc = UserDoc {
        email: email.to_string(),
        name: name.map(String::from),
        org_id: None,
        is_org_admin: false,
        active: true,
        external_id: None,
        github_id: None,
        github_login: None,
        github_refresh_token: None,
    };
    let doc = store.insert(&user_doc).await?;
    Ok((doc.id, true))
}

/// Create or find a user by email, with an organization.
///
/// Note: Only used in tests. Production code uses `enroll_user_with_org`.
#[cfg(any(test, feature = "test-utils"))]
pub async fn upsert_user_with_org(
    store: &DocumentStore,
    email: &str,
    name: Option<&str>,
    org_id: Option<&str>,
    is_org_admin: bool,
) -> Result<(String, bool)> {
    if let Some(doc) = store.find_one::<UserDoc>("email", email).await? {
        return Ok((doc.id, false));
    }
    let user_doc = UserDoc {
        email: email.to_string(),
        name: name.map(String::from),
        org_id: org_id.map(String::from),
        is_org_admin,
        active: true,
        external_id: None,
        github_id: None,
        github_login: None,
        github_refresh_token: None,
    };
    let doc = store.insert(&user_doc).await?;
    Ok((doc.id, true))
}

/// Look up a user by email within an organization.
///
/// Use this when you have org context (SCIM, OAuth flows tied to an org).
/// Returns at most one row — emails are unique per-org.
pub async fn get_user_by_email_in_org(
    store: &DocumentStore,
    email: &str,
    org_id: &str,
) -> Result<Option<User>> {
    let docs = store
        .find_by_indexes::<UserDoc>(&[("email", email), ("org_id", org_id)])
        .await?;
    Ok(docs.into_iter().next().map(User::from))
}

/// Look up a user by email without org scoping — for test use only.
///
/// Returns the first matching row by index insertion order.
/// Only available in test builds; production code must use `get_user_by_email_in_org`.
#[cfg(any(test, feature = "test-utils"))]
pub async fn get_user_by_email_global(store: &DocumentStore, email: &str) -> Result<Option<User>> {
    let doc = store.find_one::<UserDoc>("email", email).await?;
    Ok(doc.map(User::from))
}

/// Get a user by ID.
pub async fn get_user_by_id(store: &DocumentStore, user_id: &str) -> Result<Option<User>> {
    let doc = store.get::<UserDoc>(user_id).await?;
    Ok(doc.map(User::from))
}

/// Delete a user and all associated data atomically.
///
/// Wraps all cascade deletes in a single transaction so that a partial
/// failure leaves no orphaned records.
///
/// Steps performed:
/// 1. Delete sessions
/// 2. Delete enrollment sessions
/// 3. Delete authenticators (and their related device_auth refs)
/// 4. Delete SSH issued certificate records
/// 5. Delete token exchanges
/// 6. Unlink OAuth clients (set user_id to None)
/// 7. Delete the user
///
/// Note: SSH revocation records (`SshRevokedCertDoc`) are intentionally
/// NOT deleted — they must outlive the user so SSH servers can still
/// check the KRL. They expire naturally via `expires_at`.
pub async fn delete_user(store: &DocumentStore, user_id: &str) -> Result<bool> {
    use super::documents::authenticator::AuthenticatorDoc;
    use super::documents::credential::{EnrollmentSessionDoc, SshIssuedCertDoc};
    use super::documents::device_auth::DeviceAuthRequestDoc;
    use super::documents::oauth::OAuthClientDoc;
    use super::documents::oauth::TokenExchangeDoc;
    use super::documents::session::SessionDoc;

    let mut tx = store.begin().await?;

    // 1. Delete sessions
    tx.delete_by_index::<SessionDoc>("user_id", user_id).await?;

    // 2. Delete enrollment sessions
    tx.delete_by_index::<EnrollmentSessionDoc>("user_id", user_id)
        .await?;

    // 3. Clear authenticator_id references in device_auth_requests,
    //    then delete all authenticators in one batch.
    let authenticators = tx.find_all::<AuthenticatorDoc>("user_id", user_id).await?;
    for auth in &authenticators {
        tx.update_by_index::<DeviceAuthRequestDoc, _>("authenticator_id", &auth.id, |d| {
            d.authenticator_id = None;
        })
        .await?;
    }
    tx.delete_by_index::<AuthenticatorDoc>("user_id", user_id)
        .await?;

    // 4. Delete SSH issued certificate records
    tx.delete_by_index::<SshIssuedCertDoc>("user_id", user_id)
        .await?;

    // 5. Delete token exchanges
    tx.delete_by_index::<TokenExchangeDoc>("subject_user_id", user_id)
        .await?;

    // 6. Unlink OAuth clients (set user_id to None)
    tx.update_by_index::<OAuthClientDoc, _>("user_id", user_id, |d| {
        d.user_id = None;
    })
    .await?;

    // 7. Delete the user
    tx.delete(user_id).await?;

    tx.commit().await?;
    Ok(true)
}

/// Get users in an organization with cursor-based pagination.
///
/// Returns up to `limit` users ordered by ID. If `after_id` is `Some`,
/// only returns users with IDs after the cursor. The boolean indicates
/// whether more results exist.
pub async fn get_users_by_org_paginated(
    store: &DocumentStore,
    org_id: &str,
    after_id: Option<&str>,
    limit: u64,
) -> Result<(Vec<User>, bool)> {
    let (docs, has_more) = store
        .find_paginated::<UserDoc>("org_id", org_id, after_id, limit)
        .await?;
    let users = docs.into_iter().map(User::from).collect();
    Ok((users, has_more))
}

/// Update a user's org admin status.
pub async fn update_user_admin_status(
    store: &DocumentStore,
    user_id: &str,
    is_admin: bool,
) -> Result<bool> {
    if let Some(doc) = store.get::<UserDoc>(user_id).await? {
        let mut data = doc.data;
        data.is_org_admin = is_admin;
        store.update(user_id, &data).await?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Update a user's active status.
pub async fn update_user_active_status(
    store: &DocumentStore,
    user_id: &str,
    active: bool,
) -> Result<bool> {
    if let Some(doc) = store.get::<UserDoc>(user_id).await? {
        let mut data = doc.data;
        data.active = active;
        store.update(user_id, &data).await?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Update a user's GitHub identity.
pub async fn update_user_github_identity(
    store: &DocumentStore,
    user_id: &str,
    github_id: i64,
    github_login: &str,
    github_refresh_token: Option<&str>,
) -> Result<()> {
    let doc = store
        .get::<UserDoc>(user_id)
        .await?
        .context("user not found")?;
    let mut data = doc.data;
    data.github_id = Some(github_id);
    data.github_login = Some(github_login.to_string());
    data.github_refresh_token = github_refresh_token.map(String::from);
    store.update(user_id, &data).await?;
    Ok(())
}

/// Get a user's GitHub refresh token.
pub async fn get_user_github_refresh_token(
    store: &DocumentStore,
    user_id: &str,
) -> Result<Option<String>> {
    let doc = store.get::<UserDoc>(user_id).await?;
    Ok(doc.and_then(|d| d.data.github_refresh_token))
}

/// Clear a user's GitHub refresh token.
pub async fn clear_user_github_refresh_token(store: &DocumentStore, user_id: &str) -> Result<()> {
    if let Some(doc) = store.get::<UserDoc>(user_id).await? {
        let mut data = doc.data;
        data.github_refresh_token = None;
        store.update(user_id, &data).await?;
    }
    Ok(())
}
