// SPDX-License-Identifier: Apache-2.0 OR MIT
//! User database operations.

use std::collections::HashMap;

use super::document_type::Document;
use super::documents::user::UserDoc;
use super::store::DocumentStore;
use anyhow::Result;

/// User record.
pub struct User {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub org_id: Option<String>,
    /// The org's primary domain, copied from the org doc at creation.
    /// `None` on docs created before this field existed.
    pub org_domain: Option<String>,
    pub is_org_admin: bool,
    pub active: bool,
    pub external_id: Option<String>,
    pub github_id: Option<i64>,
    pub github_login: Option<String>,
    pub github_refresh_token: Option<secrecy::SecretString>,
}

// Custom Debug that redacts github_refresh_token to prevent accidental log
// exposure of a credential that mints new GitHub access tokens.
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("email", &self.email)
            .field("name", &self.name)
            .field("org_id", &self.org_id)
            .field("org_domain", &self.org_domain)
            .field("is_org_admin", &self.is_org_admin)
            .field("active", &self.active)
            .field("external_id", &self.external_id)
            .field("github_id", &self.github_id)
            .field("github_login", &self.github_login)
            .field("github_refresh_token", &"[REDACTED]")
            .finish()
    }
}

impl From<Document<UserDoc>> for User {
    fn from(doc: Document<UserDoc>) -> Self {
        Self {
            id: doc.id,
            email: doc.data.email.into_string(),
            name: doc.data.name,
            org_id: doc.data.org_id,
            org_domain: doc.data.org_domain,
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
///
/// Like the production enrollment path, `email` is normalized to ASCII
/// lowercase before lookup and storage so test fixtures match the same
/// case-insensitive uniqueness contract.
#[cfg(any(test, feature = "test-utils"))]
pub async fn upsert_user(
    store: &DocumentStore,
    email: &str,
    name: Option<&str>,
) -> Result<(String, bool)> {
    let email = crate::email::Email::new(email);
    if let Some(doc) = store.find_one::<UserDoc>("email", email.as_str()).await? {
        return Ok((doc.id, false));
    }
    let user_doc = UserDoc {
        email,
        name: name.map(String::from),
        org_id: None,
        org_domain: None,
        is_org_admin: false,
        active: true,
        external_id: None,
        github_id: None,
        github_login: None,
        github_refresh_token: None,
        idp_identities: Vec::new(),
    };
    let doc = store.insert(&user_doc).await?;
    Ok((doc.id, true))
}

/// Create or find a user by email, with an organization.
///
/// Note: Only used in tests. Production code uses `enroll_user_with_org`.
///
/// Like the production enrollment path, `email` is normalized to ASCII
/// lowercase before lookup and storage so test fixtures match the same
/// case-insensitive uniqueness contract.
#[cfg(any(test, feature = "test-utils"))]
pub async fn upsert_user_with_org(
    store: &DocumentStore,
    email: &str,
    name: Option<&str>,
    org_id: Option<&str>,
    is_org_admin: bool,
) -> Result<(String, bool)> {
    let email = crate::email::Email::new(email);
    if let Some(doc) = store.find_one::<UserDoc>("email", email.as_str()).await? {
        return Ok((doc.id, false));
    }
    let user_doc = UserDoc {
        email,
        name: name.map(String::from),
        org_id: org_id.map(String::from),
        // Test helper only: unlike the two production writers
        // (`resolve_user`, `create_scim_user`), this bypasses org lookup
        // entirely, so there's no domain in hand to stamp here. Callers that
        // exercise `org_domain` land on the same fallback-and-backfill path
        // as a pre-existing doc from before this field existed.
        org_domain: None,
        is_org_admin,
        active: true,
        external_id: None,
        github_id: None,
        github_login: None,
        github_refresh_token: None,
        idp_identities: Vec::new(),
    };
    let doc = store.insert(&user_doc).await?;
    Ok((doc.id, true))
}

/// Get a user by email.
///
/// `email` is normalized to ASCII lowercase before the indexed lookup so
/// callers may pass any casing; user emails are stored lowercase by
/// `enroll_user_with_org` and `create_scim_user`.
pub async fn get_user_by_email(store: &DocumentStore, email: &str) -> Result<Option<User>> {
    let email = crate::email::Email::new(email);
    let doc = store.find_one::<UserDoc>("email", email.as_str()).await?;
    Ok(doc.map(User::from))
}

/// Get a user by ID.
pub async fn get_user_by_id(store: &DocumentStore, user_id: &str) -> Result<Option<User>> {
    let doc = store.get::<UserDoc>(user_id).await?;
    Ok(doc.map(User::from))
}

/// An org user's org domain: `cached` (the value from their doc) when
/// present, otherwise a live lookup whose result is written back to the
/// doc so later calls skip it.
///
/// A stored value is used as-is — the primary domain is write-once (see
/// [`UserDoc::org_domain`]). The write-back is best-effort (`store.modify`,
/// OCC): a failure is logged and the looked-up domain is returned anyway,
/// so it can never fail the caller's grant.
pub async fn get_user_org_domain(
    store: &DocumentStore,
    user_id: &str,
    org_id: &str,
    cached: Option<&str>,
) -> Result<Option<String>> {
    if let Some(domain) = cached {
        return Ok(Some(domain.to_string()));
    }
    let domain = super::organizations::get_organization_domain(store, org_id).await?;
    if let Some(domain) = &domain {
        let backfill = domain.clone();
        if let Err(e) = store
            .modify::<UserDoc, _>(user_id, move |data| {
                data.org_domain = Some(backfill.clone());
            })
            .await
        {
            tracing::warn!(user_id, error = %e, "failed to backfill user org_domain");
        }
    }
    Ok(domain)
}

/// Get multiple users by ID in a single query.
///
/// Returns a map keyed by user ID. IDs with no matching user are simply
/// absent from the map — not an error. An empty `ids` slice returns an
/// empty map without issuing a query.
pub async fn get_users_by_ids(
    store: &DocumentStore,
    ids: &[String],
) -> Result<HashMap<String, User>> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let docs = store.get_by_ids::<UserDoc>(ids).await?;
    Ok(docs
        .into_iter()
        .map(|doc| (doc.id.clone(), User::from(doc)))
        .collect())
}

/// Failure modes of [`delete_user`].
#[derive(Debug, thiserror::Error)]
pub enum DeleteUserError {
    /// Another transaction changed the organization row while this delete was
    /// choosing a successor for the user's org-scoped applications.
    #[error("organization changed during delete")]
    OccConflict,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl super::pool::RetryableError for DeleteUserError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::OccConflict => true,
            Self::Other(e) => super::pool::is_retryable_db_error(e),
        }
    }
}

/// Pick the org admin that inherits a departing user's org-scoped
/// applications.
///
/// Returns the lowest-sorting active org admin in `org_id`, excluding
/// `departing_user_id`. Sorting by ID makes the choice deterministic, so
/// concurrent deletions in the same organization agree on a successor.
/// Returns `None` when the user has no org or the org has no other active
/// admin — in that case the caller unlinks rather than transfers.
async fn org_admin_successor(
    tx: &mut super::store::StoreTransaction<'_>,
    org_id: Option<&str>,
    departing_user_id: &str,
) -> Result<Option<String>> {
    let Some(org_id) = org_id else {
        return Ok(None);
    };

    let members = tx.find_all::<UserDoc>("org_id", org_id).await?;
    let mut admin_ids: Vec<String> = members
        .into_iter()
        .filter(|m| m.data.is_org_admin && m.data.active && m.id != departing_user_id)
        .map(|m| m.id)
        .collect();
    admin_ids.sort();
    Ok(admin_ids.into_iter().next())
}

/// The member change being applied by [`demote_or_deactivate_member`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberDowngrade {
    /// Clear `is_org_admin`, leaving the account active.
    Demote,
    /// Clear `active`, which also removes the account from the admin count.
    Deactivate,
}

/// Failure modes of [`demote_or_deactivate_member`].
#[derive(Debug, thiserror::Error)]
pub enum MemberDowngradeError {
    /// The change would leave the organization with no active admin.
    #[error("organization would be left with no active admin")]
    LastAdmin,
    /// Another transaction changed the organization row while this change was
    /// counting admins.
    #[error("organization changed during member downgrade")]
    OccConflict,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl super::pool::RetryableError for MemberDowngradeError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::OccConflict => true,
            Self::LastAdmin => false,
            Self::Other(e) => super::pool::is_retryable_db_error(e),
        }
    }
}

/// Demote or deactivate an org member, refusing to remove the last admin.
///
/// Returns `Ok(false)` when the target no longer exists.
///
/// "At least one active admin per organization" is a cross-row invariant: it
/// is a property of the member set, not of any single user document. The
/// handlers' own "cannot demote yourself" check enforces it only by accident
/// — it holds for one request at a time, and two admins who downgrade *each
/// other* simultaneously both pass it, because neither request can see the
/// other. Each write then lands on a different user document, so per-document
/// optimistic concurrency never notices, and the organization is left with no
/// admin and no way back in.
///
/// So the admin count and the write share one transaction, and the
/// organization row is version-bumped to serialize them (CLAUDE.md rule 10).
/// The org row is what concurrent downgrades collide on; DSQL is OCC-only and
/// has no `SELECT … FOR UPDATE`, so forcing writers onto one row is what makes
/// the guard atomic on every backend. The version is captured *before* the
/// member scan for the reason spelled out in [`delete_user`]: read afterwards,
/// it would already carry a sibling's bump and the compare-and-update would
/// wrongly succeed.
///
/// # Errors
///
/// [`MemberDowngradeError::LastAdmin`] when the target is the organization's
/// only remaining active admin, and [`MemberDowngradeError::OccConflict`] when
/// a concurrent change to the organization won the race — retried by
/// `with_dsql_retry!`, which re-runs the count against the committed state.
pub async fn demote_or_deactivate_member(
    store: &DocumentStore,
    user_id: &str,
    change: MemberDowngrade,
) -> std::result::Result<bool, MemberDowngradeError> {
    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await?;

        let Some(user_doc) = tx.get::<UserDoc>(user_id).await? else {
            return Ok(false);
        };
        let org_id = user_doc.data.org_id.clone();

        // Version first, then the predicate read it must guard.
        let org_doc = match org_id.as_deref() {
            Some(id) => {
                tx.get::<super::documents::organization::OrganizationDoc>(id)
                    .await?
            }
            None => None,
        };

        // Only a change that removes an *active admin* can breach the floor.
        // Demoting a plain member, or deactivating one, cannot.
        let removes_an_admin = user_doc.data.is_org_admin && user_doc.data.active;
        if removes_an_admin && let Some(id) = org_id.as_deref() {
            let members = tx.find_all::<UserDoc>("org_id", id).await?;
            let other_admins = members
                .iter()
                .filter(|m| m.data.is_org_admin && m.data.active && m.id != user_id)
                .count();
            if other_admins == 0 {
                return Err(MemberDowngradeError::LastAdmin);
            }
        }

        let mut updated = user_doc.data.clone();
        match change {
            MemberDowngrade::Demote => updated.is_org_admin = false,
            MemberDowngrade::Deactivate => updated.active = false,
        }
        // Guard the user row on the version this transaction read, so a
        // concurrent edit to the same member is not overwritten blindly.
        if !tx
            .compare_and_update(user_id, user_doc.version, &updated)
            .await?
        {
            return Err(MemberDowngradeError::OccConflict);
        }

        if let Some(id) = org_id.as_deref()
            && let Some(org_doc) = org_doc
        {
            let won = tx
                .compare_and_update(id, org_doc.version, &org_doc.data)
                .await?;
            if !won {
                return Err(MemberDowngradeError::OccConflict);
            }
        }

        tx.commit().await?;
        Ok(true)
    })
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
/// 6. Transfer org-scoped OAuth clients to an org admin; unlink the rest
/// 7. Delete the user
///
/// Note: SSH revocation records (`SshRevokedCertDoc`) are intentionally
/// NOT deleted — they must outlive the user so SSH servers can still
/// check the KRL. They expire naturally via `expires_at`.
///
/// # Returns
///
/// `Ok(true)` when the user existed and was deleted, `Ok(false)` when no
/// user with `user_id` was found — callers surface the latter as a 404 and
/// must not record a deletion audit event.
pub async fn delete_user(store: &DocumentStore, user_id: &str) -> Result<bool, DeleteUserError> {
    use super::documents::authenticator::AuthenticatorDoc;
    use super::documents::credential::{EnrollmentSessionDoc, SshIssuedCertDoc};
    use super::documents::oauth::OAuthClientDoc;
    use super::documents::oauth::TokenExchangeDoc;
    use super::documents::session::SessionDoc;

    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await?;

        // Test-only seam: let handler tests delete the target from a separate
        // transaction before the existence check, deterministically simulating
        // a concurrent delete that wins the race. Compiled out of non-test
        // builds, so production pays nothing.
        #[cfg(test)]
        store.run_delete_test_hook(user_id).await;

        // Return `false` when the user document is missing so callers can
        // surface a 404 and skip the audit event. `tx.delete` returns
        // `Ok(())` regardless of whether anything was removed, so this
        // existence check is the only signal that the user was already
        // gone. Mirrors `delete_scim_group` / `delete_custom_policy`.
        let Some(user_doc) = tx.get::<UserDoc>(user_id).await? else {
            return Ok(false);
        };
        let org_id = user_doc.data.org_id.clone();

        // 1. Delete sessions
        tx.delete_by_index::<SessionDoc>("user_id", user_id).await?;

        // 2. Delete enrollment sessions
        tx.delete_by_index::<EnrollmentSessionDoc>("user_id", user_id)
            .await?;

        // 3. Cascade-delete each authenticator (clears device_auth references,
        //    removes the authenticator doc). The helper also issues a session
        //    delete-by-index per authenticator; that is redundant here because
        //    step 1 already removed all the user's sessions, but the duplicate
        //    no-op delete is cheap and keeps the cascade logic in one place.
        let authenticators = tx.find_all::<AuthenticatorDoc>("user_id", user_id).await?;
        for auth in &authenticators {
            super::authenticators::delete_authenticator(&mut tx, &auth.id).await?;
        }

        // 4. Delete SSH issued certificate records
        tx.delete_by_index::<SshIssuedCertDoc>("user_id", user_id)
            .await?;

        // 5. Delete token exchanges
        tx.delete_by_index::<TokenExchangeDoc>("subject_user_id", user_id)
            .await?;

        // 6. Reassign org-scoped OAuth clients; unlink the rest.
        //
        // Application management is creator-only: every check compares the
        // caller against `Some(client.user_id)`. Clearing `user_id` therefore
        // strands an organization's applications permanently — no one can
        // rotate their secrets, update redirect URIs, or delete them. An
        // org-scoped application belongs to the organization rather than to
        // the individual, so it transfers to an active org admin, keeping it
        // both manageable and discoverable in that admin's normal list.
        // Personal and public applications have no other legitimate owner
        // and are unlinked.
        // The client doc's version is the serialization point for all
        // secret-set mutations (`update_oauth_client`,
        // `update_oauth_client_registration` write via `compare_and_update`).
        // `update_by_index` guards each write with the version it read, so a
        // client update committed between this read and the write is never
        // overwritten with the stale doc: the cascade fails with a retryable
        // `VersionConflict` and the entry-point `with_dsql_retry!` re-runs
        // it from a fresh read.
        // Capture the org row's version *before* the member scan that chooses
        // the successor. The scan is the predicate read this guard exists to
        // serialize, so the version has to be the one the scan saw. Reading it
        // afterwards defeats the guard: under PostgreSQL READ COMMITTED every
        // statement takes a fresh snapshot, so a sibling delete that committed
        // between the scan and the version read yields the already-bumped
        // version here, the compare-and-update below matches, and both
        // transactions commit having each chosen the other as successor.
        let org_doc = match org_id.as_deref() {
            Some(id) => {
                tx.get::<super::documents::organization::OrganizationDoc>(id)
                    .await?
            }
            None => None,
        };

        let successor = org_admin_successor(&mut tx, org_id.as_deref(), user_id).await?;
        tx.update_by_index::<OAuthClientDoc, _>("user_id", user_id, |d| {
            d.user_id = match (d.access_scope, successor.as_deref()) {
                (super::documents::oauth::AccessScope::Organization, Some(admin_id)) => {
                    Some(admin_id.to_string())
                }
                _ => None,
            };
        })
        .await?;

        // Serialize deletions within an organization on the org row.
        //
        // Choosing a successor reads the org's members, and a predicate read
        // is exactly what concurrent transactions do not conflict on under
        // READ COMMITTED. Two admins deleted at once would each pick the
        // other — both reads predate both deletions — and the applications
        // would land on a user row that no longer exists. Writing the org
        // row makes those transactions collide: the loser retries, re-reads
        // members without the winner, and picks someone who still exists.
        // Enrollment claims its admin slot against the same row for the same
        // reason.
        //
        // Every delete of a member of an org takes this write, not only the
        // ones that transfer: the user being deleted may itself be the
        // successor a concurrent delete just chose. Deleting a user is a rare
        // administrative action, so serializing per organization costs
        // little.
        if let Some(ref org_id) = org_id
            && let Some(org_doc) = org_doc
        {
            let won = tx
                .compare_and_update(org_id, org_doc.version, &org_doc.data)
                .await?;
            if !won {
                return Err(DeleteUserError::OccConflict);
            }
        }

        // 7. Delete the user
        tx.delete(user_id).await?;

        tx.commit().await?;
        Ok(true)
    })
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
///
/// Uses optimistic concurrency (`store.modify`) so concurrent field
/// mutations on the same user doc do not silently overwrite each other.
pub async fn update_user_admin_status(
    store: &DocumentStore,
    user_id: &str,
    is_admin: bool,
) -> Result<bool> {
    store
        .modify::<UserDoc, _>(user_id, |data| {
            data.is_org_admin = is_admin;
        })
        .await
}

/// Update a user's active status.
///
/// Uses optimistic concurrency (`store.modify`) so concurrent field
/// mutations on the same user doc do not silently overwrite each other.
pub async fn update_user_active_status(
    store: &DocumentStore,
    user_id: &str,
    active: bool,
) -> Result<bool> {
    store
        .modify::<UserDoc, _>(user_id, |data| {
            data.active = active;
        })
        .await
}

/// Update a user's GitHub identity.
///
/// Uses optimistic concurrency (`store.modify`) so a concurrent admin-status
/// change landing between the read and write is not silently lost.
///
/// A `None` refresh token means the response carried none, not that the stored
/// one should be discarded — GitHub omits `refresh_token` when the app has
/// expiring tokens disabled, so a re-link would otherwise erase a working
/// token and silently break background refresh. Clearing is done explicitly,
/// through [`super::credentials::revoke_user_credentials`].
pub async fn update_user_github_identity(
    store: &DocumentStore,
    user_id: &str,
    github_id: i64,
    github_login: &str,
    github_refresh_token: Option<&str>,
) -> Result<()> {
    let found = store
        .modify::<UserDoc, _>(user_id, |data| {
            data.github_id = Some(github_id);
            data.github_login = Some(github_login.to_string());
            if let Some(token) = github_refresh_token {
                data.github_refresh_token = Some(secrecy::SecretString::from(token));
            }
        })
        .await?;
    if found {
        Ok(())
    } else {
        Err(anyhow::anyhow!("user not found: {user_id}"))
    }
}

/// Get a user's GitHub refresh token.
pub async fn get_user_github_refresh_token(
    store: &DocumentStore,
    user_id: &str,
) -> Result<Option<secrecy::SecretString>> {
    let doc = store.get::<UserDoc>(user_id).await?;
    Ok(doc.and_then(|d| d.data.github_refresh_token))
}

/// Clear a user's GitHub refresh token.
///
/// Uses optimistic concurrency (`store.modify`) so concurrent field
/// mutations do not silently overwrite each other. A missing user is
/// silently ignored (idempotent clear semantics).
pub(in crate::db) async fn clear_user_github_refresh_token(
    store: &DocumentStore,
    user_id: &str,
) -> Result<()> {
    store
        .modify::<UserDoc, _>(user_id, |data| {
            data.github_refresh_token = None;
        })
        .await?;
    Ok(())
}
