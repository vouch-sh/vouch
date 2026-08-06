// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM 2.0 (RFC 7643/7644) database operations.

use super::audit::{AuditEventKind, AuditStore};
use super::document_type::{Document, DocumentType};
use super::documents::audit::ScimAuditData;
use super::documents::organization::OrganizationDoc;
use super::documents::scim::{ScimGroupDoc, ScimGroupMemberDoc, ScimTokenDoc};
use super::documents::user::UserDoc;
use super::store::DocumentStore;
use crate::error::ServiceError;
use anyhow::Result;
use jiff::Timestamp;

// ============================================================================
// SCIM Scopes
// ============================================================================

/// Individual permission scope for an organization API token.
///
/// Named `ScimScope` for historical reasons (SCIM was the first consumer);
/// the type now also carries non-SCIM scopes like [`Self::AuditRead`] as the
/// token type has generalized into a general-purpose org API token. See
/// `docs/src/admin/audit.md` for the org API token model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimScope {
    /// Read access to user resources.
    UsersRead,
    /// Write access to user resources.
    UsersWrite,
    /// Read access to group resources.
    GroupsRead,
    /// Write access to group resources.
    GroupsWrite,
    /// Read access to the organization's audit event log
    /// (`GET /api/v1/org/audit-events`).
    AuditRead,
}

impl ScimScope {
    /// Return the string representation for database storage.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UsersRead => "users:read",
            Self::UsersWrite => "users:write",
            Self::GroupsRead => "groups:read",
            Self::GroupsWrite => "groups:write",
            Self::AuditRead => "audit:read",
        }
    }

    /// Parse from a database string value.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "users:read" => Some(Self::UsersRead),
            "users:write" => Some(Self::UsersWrite),
            "groups:read" => Some(Self::GroupsRead),
            "groups:write" => Some(Self::GroupsWrite),
            "audit:read" => Some(Self::AuditRead),
            _ => None,
        }
    }
}

/// A set of SCIM permission scopes, stored as comma-separated
/// in the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimScopeSet {
    scopes: Vec<ScimScope>,
}

impl ScimScopeSet {
    /// Create a scope set containing the four SCIM provisioning scopes
    /// (full SCIM access). Does **not** include [`ScimScope::AuditRead`] —
    /// that scope is opt-in per token, granted via [`Self::from_scopes`].
    #[must_use]
    pub fn all() -> Self {
        Self {
            scopes: vec![
                ScimScope::UsersRead,
                ScimScope::UsersWrite,
                ScimScope::GroupsRead,
                ScimScope::GroupsWrite,
            ],
        }
    }

    /// Construct a scope set from an explicit list of scopes.
    #[must_use]
    pub fn from_scopes(scopes: Vec<ScimScope>) -> Self {
        Self { scopes }
    }

    /// Parse a comma-separated scope string from the database.
    ///
    /// Returns `None` if any scope component is invalid.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let scopes: Option<Vec<ScimScope>> = s
            .split(',')
            .map(|part| ScimScope::parse(part.trim()))
            .collect();
        scopes.map(|s| Self { scopes: s })
    }

    /// Serialize to a comma-separated string for database storage.
    #[must_use]
    pub fn as_db_string(&self) -> String {
        self.scopes
            .iter()
            .map(ScimScope::as_str)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Check if this set contains a specific scope.
    #[must_use]
    pub fn contains(&self, scope: ScimScope) -> bool {
        self.scopes.contains(&scope)
    }
}

impl Default for ScimScopeSet {
    fn default() -> Self {
        Self::all()
    }
}

// ============================================================================
// SCIM Tokens
// ============================================================================

/// SCIM token record.
#[derive(Debug)]
pub struct ScimToken {
    pub id: String,
    pub token_hash: String,
    pub org_id: Option<String>,
    pub description: Option<String>,
    pub created_at: Timestamp,
    pub last_used_at: Option<Timestamp>,
    pub expires_at: Option<Timestamp>,
    pub scope: String,
}

impl From<Document<ScimTokenDoc>> for ScimToken {
    fn from(doc: Document<ScimTokenDoc>) -> Self {
        Self {
            id: doc.id,
            token_hash: doc.data.token_hash,
            org_id: doc.data.org_id,
            description: doc.data.description,
            created_at: doc.created_at,
            last_used_at: doc.last_used_at,
            expires_at: doc.data.expires_at,
            scope: doc.data.scope,
        }
    }
}

/// Get a SCIM token by its hash.
///
/// Only returns tokens that are not expired. Tokens with no
/// expiration are always returned.
pub async fn get_scim_token_by_hash(
    store: &DocumentStore,
    token_hash: &str,
) -> Result<Option<ScimToken>> {
    let doc = store
        .find_one::<ScimTokenDoc>("token_hash", token_hash)
        .await?;

    let Some(doc) = doc else {
        return Ok(None);
    };

    // Check expiration
    let now = Timestamp::now();
    if let Some(expires_at) = doc.data.expires_at
        && expires_at <= now
    {
        return Ok(None);
    }

    Ok(Some(ScimToken::from(doc)))
}

/// Update SCIM token last used timestamp.
///
/// Performs a lightweight column-level UPDATE (no encrypt/decrypt).
pub async fn update_scim_token_last_used(store: &DocumentStore, token_id: &str) -> Result<()> {
    store.update_last_used_at(token_id).await
}

/// Maximum SCIM tokens an organization may hold at once (supports rotation).
pub(crate) const MAX_SCIM_TOKENS: usize = 2;

/// Parameters for creating an organization API token.
pub struct CreateScimTokenParams<'a> {
    pub org_id: &'a str,
    pub token_hash: &'a str,
    pub description: Option<&'a str>,
    pub expires_at: Option<Timestamp>,
    /// Scopes granted to the token. SCIM tokens minted before the
    /// [`ScimScope::AuditRead`] scope existed keep whatever scope string
    /// they were created with — this only governs new tokens.
    pub scope: ScimScopeSet,
}

/// Create an organization's API token, enforcing [`MAX_SCIM_TOKENS`] atomically.
///
/// The cap cannot be enforced by counting in the handler and then inserting:
/// two concurrent requests both observe `active < MAX_SCIM_TOKENS` and both
/// insert, leaving the organization over the limit. DSQL has no row locks, so
/// the organization document's version is the serialization point — every
/// creator must win a `compare_and_update` against it. Concurrent creators
/// therefore collide on one row, and the loser re-runs against fresh state.
///
/// # Errors
///
/// - `ServiceError::NotFound` — organization does not exist.
/// - `ServiceError::Api(409 "token_limit_reached")` — cap reached (terminal).
/// - `ServiceError::Api(409 "conflict")` — OCC retry budget exhausted; caller may retry.
pub async fn create_scim_token(
    store: &DocumentStore,
    params: &CreateScimTokenParams<'_>,
) -> Result<String, ServiceError> {
    // Owned copies so the async block, which re-runs on retry, can borrow them.
    let org_id = params.org_id.to_string();
    let token_hash = params.token_hash.to_string();
    let description = params.description.map(String::from);
    let expires_at = params.expires_at;
    let scope = params.scope.as_db_string();

    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await.map_err(|e| {
            ServiceError::from_db_contention(e, "Failed to begin transaction for SCIM token create")
        })?;

        let org_doc = tx
            .get::<OrganizationDoc>(&org_id)
            .await
            .map_err(|e| {
                ServiceError::from_db_contention(
                    e,
                    "Failed to load organization for SCIM token create",
                )
            })?
            .ok_or(ServiceError::NotFound("organization"))?;

        // Count by filtering rather than SQL COUNT: expired tokens are retained
        // until cleanup runs but cannot authenticate, so they must not consume a
        // slot. Matches the expiry rule in `get_scim_token_by_hash`.
        let now = Timestamp::now();
        let active = tx
            .find_all::<ScimTokenDoc>("org_id", &org_id)
            .await
            .map_err(|e| {
                ServiceError::from_db_contention(e, "Failed to list SCIM tokens for cap check")
            })?
            .iter()
            .filter(|doc| doc.data.expires_at.is_none_or(|exp| exp > now))
            .count();

        if active >= MAX_SCIM_TOKENS {
            // Terminal business error — retrying cannot help.
            return Err(ServiceError::api(
                axum::http::StatusCode::CONFLICT,
                "token_limit_reached",
                "Maximum of 2 SCIM tokens per organization. Revoke one before creating another.",
            ));
        }

        let doc = ScimTokenDoc {
            token_hash: token_hash.clone(),
            org_id: Some(org_id.clone()),
            description: description.clone(),
            expires_at,
            scope: scope.clone(),
        };
        let inserted = tx
            .insert(&doc)
            .await
            .map_err(|e| ServiceError::from_db_contention(e, "Failed to insert SCIM token"))?;

        // Version-bump the organization. This is what makes the cap atomic: a
        // concurrent creator that committed after our read changed the version,
        // so this returns Ok(false) and the whole block re-runs with its token
        // visible in the count.
        let won = tx
            .compare_and_update::<OrganizationDoc>(&org_id, org_doc.version, &org_doc.data)
            .await
            .map_err(|e| {
                ServiceError::from_db_contention(
                    e,
                    "Failed to version-bump org for SCIM token create",
                )
            })?;

        if !won {
            return Err(ServiceError::OccConflict);
        }

        tx.commit().await.map_err(|e| {
            ServiceError::from_db_contention(e, "Failed to commit SCIM token create")
        })?;

        Ok(inserted.id)
    })
    .map_err(|e| match e {
        ServiceError::OccConflict => ServiceError::api(
            axum::http::StatusCode::CONFLICT,
            "conflict",
            "SCIM token creation conflicted with a concurrent operation. Please retry.",
        ),
        other => other,
    })
}

/// Delete a SCIM token, scoped to the given organization.
///
/// Returns `Ok(true)` if a token was deleted, `Ok(false)` if no
/// matching token was found for the given org (prevents cross-org
/// deletion).
pub async fn delete_scim_token(
    store: &DocumentStore,
    token_id: &str,
    org_id: &str,
) -> Result<bool> {
    let Some(doc) = store.get::<ScimTokenDoc>(token_id).await? else {
        return Ok(false);
    };

    // Prevent cross-org deletion
    if doc.data.org_id.as_deref() != Some(org_id) {
        return Ok(false);
    }

    store.delete(token_id).await?;
    Ok(true)
}

/// List SCIM tokens, optionally filtered by organization.
pub async fn list_scim_tokens(
    store: &DocumentStore,
    org_id: Option<&str>,
) -> Result<Vec<ScimToken>> {
    let docs = if let Some(org_id) = org_id {
        store.find_all::<ScimTokenDoc>("org_id", org_id).await?
    } else {
        store.list_all::<ScimTokenDoc>().await?
    };
    Ok(docs.into_iter().map(ScimToken::from).collect())
}

/// Delete expired SCIM tokens. Returns count deleted.
pub async fn delete_expired_scim_tokens(store: &DocumentStore) -> Result<u64> {
    store.delete_expired(ScimTokenDoc::DOC_TYPE).await
}

// ============================================================================
// SCIM Audit → AuditStore
// ============================================================================

/// Insert SCIM audit log entry via AuditStore.
///
/// `org_domain` is the acting organization's primary email domain
/// ([`ScimAuth::org_domain`]). SCIM operations have no user/email of their
/// own, so without it the event is written with a NULL `email_domain` and
/// is invisible to org-scoped audit reads (`/admin/audit`,
/// `GET /api/v1/org/audit-events`).
pub async fn insert_scim_audit(
    audit: &AuditStore,
    operation: &str,
    resource_type: &str,
    resource_id: &str,
    actor_token_id: Option<&str>,
    details: Option<&str>,
    org_domain: Option<&str>,
) -> Result<String> {
    let data = ScimAuditData {
        operation: operation.to_string(),
        resource_type: resource_type.to_string(),
        resource_id: resource_id.to_string(),
        actor_token_id: actor_token_id.map(String::from),
        details: details.map(String::from),
    };
    let data_json = serde_json::to_string(&data)?;
    audit
        .insert_event_with_domain(AuditEventKind::ScimOperation, None, org_domain, &data_json)
        .await
}

// ============================================================================
// SCIM Users (operate on UserDoc via DocumentStore)
// ============================================================================

/// SCIM user record.
#[derive(Debug)]
pub struct ScimUserRecord {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub active: bool,
    pub external_id: Option<String>,
}

impl From<Document<UserDoc>> for ScimUserRecord {
    fn from(doc: Document<UserDoc>) -> Self {
        Self {
            id: doc.id,
            email: doc.data.email,
            name: doc.data.name,
            created_at: doc.created_at,
            updated_at: doc.updated_at,
            active: doc.data.active,
            external_id: doc.data.external_id,
        }
    }
}

/// List users for SCIM with optional filter.
///
/// Returns `(records, total_count)` where `total_count` is the total number of
/// matching users (before pagination).
///
/// # Errors
///
/// Returns [`ScimFilterError::FilterTooBroad`] for non-indexed filters on
/// tables with >10 000 rows. Returns [`ScimFilterError::OffsetTooLarge`]
/// when the computed offset exceeds 10 000.
pub async fn list_scim_users(
    store: &DocumentStore,
    org_id: &str,
    filter: Option<&str>,
    start_index: usize,
    count: usize,
) -> Result<(Vec<ScimUserRecord>, usize)> {
    let offset = start_index.saturating_sub(1); // SCIM 1-indexed

    // Try indexed AND-lookup first (single query combining email/externalId
    // with org_id at the DB level — no per-row scope check).
    if let Some(f) = filter
        && let Some(result) = try_indexed_user_lookup(store, org_id, f).await?
    {
        let total = result.len();
        let page = result.into_iter().skip(offset).take(count).collect();
        return Ok((page, total));
    }

    // Non-indexed filter: must load org-scoped rows and filter in-app.
    // Bounded by 10k so an org with millions of users does not load every
    // record into memory for an unrecognized filter expression.
    if filter.is_some() {
        let total_in_org = store.count::<UserDoc>("org_id", org_id).await?;
        if total_in_org > 10_000 {
            return Err(ScimFilterError::FilterTooBroad.into());
        }
        let all = store.find_all::<UserDoc>("org_id", org_id).await?;
        let mut records: Vec<ScimUserRecord> = all.into_iter().map(ScimUserRecord::from).collect();
        if let Some(f) = filter {
            records = apply_scim_user_filter(records, f)?;
        }
        records.sort_by(|a, b| a.email.cmp(&b.email));
        let total = records.len();
        let page = records.into_iter().skip(offset).take(count).collect();
        return Ok((page, total));
    }

    // Unfiltered: push pagination to the DB so an org with millions of
    // users does not load every record into memory.
    if offset > 10_000 {
        return Err(ScimFilterError::OffsetTooLarge.into());
    }
    let (docs, total_count) = store
        .find_paginated_with_count::<UserDoc>("org_id", org_id, offset as u64, count as u64)
        .await?;
    Ok((
        docs.into_iter().map(ScimUserRecord::from).collect(),
        usize::try_from(total_count).unwrap_or(usize::MAX),
    ))
}

/// Try indexed eq lookups for SCIM user filters, scoped to org.
async fn try_indexed_user_lookup(
    store: &DocumentStore,
    org_id: &str,
    filter: &str,
) -> Result<Option<Vec<ScimUserRecord>>> {
    // userName/email eq → find_by_indexes combining email + org_id at DB level.
    //
    // `userName` and `email` are both `caseExact: false` per RFC 7643, and
    // emails are stored ASCII-lowercase by `create_scim_user` /
    // `enroll_user_with_org`. Normalize the filter value to match the stored
    // index; otherwise a mixed-case filter like `userName eq "Alice@example.com"`
    // misses the user stored as `alice@example.com`.
    for attr in &["userName", "email"] {
        if let Some(f) = parse_scim_filter(filter, attr)?
            && f.op == ScimFilterOp::Eq
        {
            let email_lower = f.value.to_ascii_lowercase();
            let docs = store
                .find_by_indexes::<UserDoc>(&[("email", &email_lower), ("org_id", org_id)])
                .await?;
            return Ok(Some(docs.into_iter().map(ScimUserRecord::from).collect()));
        }
    }

    // externalId eq → find_by_indexes combining external_id + org_id
    // (externalId has caseExact: true per RFC 7643 Section 3.1, so the
    // case-sensitive indexed lookup below is correct and must not be
    // lowercased.)
    if let Some(f) = parse_scim_filter(filter, "externalId")?
        && f.op == ScimFilterOp::Eq
    {
        let docs = store
            .find_by_indexes::<UserDoc>(&[("external_id", &f.value), ("org_id", org_id)])
            .await?;
        return Ok(Some(docs.into_iter().map(ScimUserRecord::from).collect()));
    }

    Ok(None)
}

/// Apply SCIM filter to user records in application code.
fn apply_scim_user_filter(
    records: Vec<ScimUserRecord>,
    filter: &str,
) -> Result<Vec<ScimUserRecord>> {
    for attr in &["userName", "email"] {
        if let Some(f) = parse_scim_filter(filter, attr)? {
            return Ok(records
                .into_iter()
                .filter(|r| match_filter_value(&r.email, &f))
                .collect());
        }
    }

    if let Some(f) = parse_scim_filter(filter, "externalId")? {
        return Ok(records
            .into_iter()
            .filter(|r| {
                r.external_id
                    .as_deref()
                    .is_some_and(|eid| match_filter_value(eid, &f))
            })
            .collect());
    }

    // No recognized filter — return all
    Ok(records)
}

/// Check if a value matches a SCIM filter.
fn match_filter_value(value: &str, filter: &ScimFilter) -> bool {
    let value_lower = value.to_lowercase();
    let filter_lower = filter.value.to_lowercase();
    match filter.op {
        ScimFilterOp::Eq => value_lower == filter_lower,
        ScimFilterOp::Co => value_lower.contains(&filter_lower),
        ScimFilterOp::Sw => value_lower.starts_with(&filter_lower),
    }
}

/// Get a user by ID for SCIM, scoped to the caller's org.
///
/// Returns `None` if the user doesn't exist OR belongs to a different
/// org. Treating cross-org as not-found avoids leaking existence.
pub async fn get_scim_user(
    store: &DocumentStore,
    user_id: &str,
    org_id: &str,
) -> Result<Option<ScimUserRecord>> {
    let Some(doc) = store.get::<UserDoc>(user_id).await? else {
        return Ok(None);
    };
    if doc.data.org_id.as_deref() != Some(org_id) {
        return Ok(None);
    }
    Ok(Some(ScimUserRecord::from(doc)))
}

/// Errors returned by [`create_scim_user`].
///
/// Business-rejection variants are terminal (not retried); `OccConflict` and
/// DB-retryable `Other` errors are re-run by `with_dsql_retry!`.
#[derive(Debug, thiserror::Error)]
pub enum CreateScimUserError {
    /// The email's domain is not a verified domain of the calling org.
    ///
    /// Returned when `org_id` is `Some` and either the org does not exist or
    /// the email's domain is not in the org's verified-domain set. The SCIM
    /// handler maps this to `400 invalidValue`.
    #[error("email domain is not verified for this organization")]
    DomainNotOwned,
    /// A user with the same (normalized) email already exists.
    ///
    /// Surfaced from both the explicit pre-check and the deterministic-ID
    /// primary-key collision. The SCIM handler maps this to `409 uniqueness`.
    #[error("UNIQUE constraint failed: user with email already exists")]
    DuplicateEmail,
    /// OCC version race on the org doc; retried by `with_dsql_retry!`, reaches
    /// callers only when the retry budget is exhausted.
    #[error("organization was modified concurrently; please retry")]
    OccConflict,
    /// Database or unexpected infrastructure failure.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl crate::db::pool::RetryableError for CreateScimUserError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::OccConflict => true,
            Self::Other(e) => crate::db::pool::is_retryable_db_error(e),
            Self::DomainNotOwned | Self::DuplicateEmail => false,
        }
    }
}

/// Create a user via SCIM, bound to the given org (or org-less for
/// the certification test path which passes `None`).
///
/// When `org_id` is `Some`, the email's domain is validated against the
/// org's verified-domain set **inside the same transaction** as the user
/// insert, and the org doc is version-bumped via `compare_and_update` to
/// force an OCC conflict with any concurrent domain removal. This closes
/// the TOCTOU race window that existed when the domain-ownership check ran
/// as a separate non-transactional read before user creation: a concurrent
/// `remove_additional_domain` could commit between the check and the insert,
/// letting a user be created on a domain the org no longer owned. The
/// version-bump makes the two writers collide on the org doc's row, so
/// `with_dsql_retry!` re-runs the loser against fresh state — mirroring the
/// pattern established by [`create_scim_token`] for the token-cap invariant.
///
/// Returns [`CreateScimUserError::DuplicateEmail`] if a user with the same
/// email already exists (application-level uniqueness enforcement, global
/// because emails are globally unique by design).
///
/// # Email normalization
///
/// `email` is normalized to ASCII lowercase before lookup and storage,
/// matching [`crate::db::enroll_user_with_org`]. This makes the
/// application-level uniqueness check case-insensitive so that a SCIM
/// provision of `Alice@example.com` and a later OIDC enrollment as
/// `alice@example.com` resolve to the same user instead of producing a
/// duplicate. The stored `UserDoc.email` and the returned
/// [`ScimUserRecord.email`] are always lowercase.
///
/// # Race safety
///
/// The user ID is derived deterministically from the *normalized* email via
/// [`deterministic_user_id`](crate::db::documents::user::deterministic_user_id)
/// (a version-8 SHA-256-based UUID) and inserted with
/// [`StoreTransaction::insert_with_id`]. Two concurrent `create_scim_user`
/// calls for the same email — in any casing — therefore compute the same
/// primary key: the winning insert commits, and the loser's insert fails
/// with a primary-key violation. `is_unique_violation` catches that and
/// surfaces the same [`CreateScimUserError::DuplicateEmail`] returned by the
/// explicit pre-check, so the SCIM handler maps both paths to `409 Conflict`.
///
/// This closes the check-then-act TOCTOU window that existed when each insert
/// used a fresh random UUID v7: two transactions could both observe "no user
/// exists" and then commit distinct rows, because neither `SERIALIZABLE`
/// isolation nor a `SELECT FOR UPDATE` catches two concurrent inserts of
/// *distinct* primary keys (documented in `db/oauth.rs` for the analogous JTI
/// case). The deterministic ID makes the keys collide, forcing serialization
/// at the `documents` PRIMARY KEY constraint. The same pattern is used by
/// `deterministic_org_id`, `deterministic_jti_id`, and
/// `deterministic_challenge_state_id`.
///
/// The domain-ownership invariant is additionally guarded by a
/// `compare_and_update` version-bump on the org doc: a concurrent
/// `remove_additional_domain` that commits between this transaction's org-doc
/// read and its CAS changes the version, so the CAS returns `Ok(false)` and
/// the whole block re-runs with fresh state (re-reading the org doc, which
/// now reflects the removed domain, and rejecting with
/// [`CreateScimUserError::DomainNotOwned`]). Without the version-bump, the
/// in-transaction read alone would not close the race under READ COMMITTED
/// (Postgres default) or SQLite deferred transactions, because the user
/// insert touches a different row and would not conflict with the org-doc
/// update.
pub async fn create_scim_user(
    store: &DocumentStore,
    org_id: Option<&str>,
    email: &str,
    name: Option<&str>,
    external_id: Option<&str>,
    active: bool,
) -> Result<ScimUserRecord, CreateScimUserError> {
    use super::documents::user::deterministic_user_id;

    // Normalize email to ASCII lowercase so the duplicate check and the
    // stored row match the casing used by `enroll_user_with_org`. Without
    // this, a SCIM provision of `Alice@example.com` would not collide with
    // a subsequent OIDC enrollment as `alice@example.com`, producing two
    // user records for the same person.
    let email = email.to_ascii_lowercase();
    let email = email.as_str();

    // Derived once outside the retried block: stable across retries and
    // identical for concurrent callers passing the same email in any casing.
    // `deterministic_user_id` lowercases internally as well, so the
    // primary-key collision holds even if a future caller skips the
    // normalization above — which is still required here so the stored
    // `UserDoc.email` and its index row match the lowercase convention.
    let user_id = deterministic_user_id(email);

    // Owned `Option<String>` so the retried async block can borrow it
    // without borrowing `org_id` (a `&str` from the caller's stack frame).
    let org_id_owned = org_id.map(String::from);

    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await?;

        // Validate domain ownership inside the transaction and capture the
        // org doc version for the OCC version-bump below. When `org_id` is
        // `None` (certification test path), there is no org to validate
        // against and no version-bump to perform — the user is created
        // org-less, matching the prior behavior.
        let org_snapshot = match &org_id_owned {
            Some(oid) => {
                let org_doc = tx
                    .get::<OrganizationDoc>(oid)
                    .await?
                    .ok_or(CreateScimUserError::DomainNotOwned)?;
                // Extract the domain from the already-lowercased email so the
                // comparison matches the lowercase convention used by
                // `OrganizationDoc::verified_domains` (additional domains are
                // stored verbatim from `normalize_domain`, which lowercases;
                // the primary domain is lowercased by `get_or_create_org`).
                let (_, candidate_domain) = email.rsplit_once('@').ok_or_else(|| {
                    CreateScimUserError::Other(anyhow::anyhow!(
                        "invalid email format: no '@' separator"
                    ))
                })?;
                let domain_owned = org_doc
                    .data
                    .verified_domains()
                    .any(|d| d.eq_ignore_ascii_case(candidate_domain));
                if !domain_owned {
                    return Err(CreateScimUserError::DomainNotOwned);
                }
                Some((org_doc.id, org_doc.version, org_doc.data))
            }
            None => None,
        };

        // Pre-check by email index. This is the fast path for the common
        // "user already exists" case: it returns the existing-user error
        // without attempting an insert and without relying on the primary-key
        // collision. It also catches the case where a user was created by a
        // *different* code path (e.g. `enroll_user_with_org`) that did not use
        // the deterministic ID, so their row has a random UUID v7 ID and would
        // not collide with `user_id`.
        if tx.find_one::<UserDoc>("email", email).await?.is_some() {
            return Err(CreateScimUserError::DuplicateEmail);
        }

        let doc = UserDoc {
            email: email.to_string(),
            name: name.map(String::from),
            org_id: org_id_owned.clone(),
            is_org_admin: false,
            active,
            external_id: external_id.map(String::from),
            github_id: None,
            github_login: None,
            github_refresh_token: None,
            idp_identities: Vec::new(),
        };
        // insert_with_id: the loser of a concurrent create race fails here with
        // a primary-key violation (SQLSTATE 23505 / SQLite SQLITE_CONSTRAINT_PRIMARYKEY).
        // 23505 is not retryable, so with_dsql_retry! surfaces it as Err(e) and
        // the `is_unique_violation` arm below maps it to the same error the
        // handler expects.
        let result = match tx.insert_with_id(&user_id, &doc).await {
            Ok(result) => result,
            Err(e) if super::pool::is_unique_violation(&e) => {
                return Err(CreateScimUserError::DuplicateEmail);
            }
            Err(e) => return Err(CreateScimUserError::Other(e)),
        };

        // Version-bump the organization doc (same data, new version) to force
        // an OCC conflict with any concurrent writer that modified the org
        // between our read above and this CAS — most importantly
        // `remove_additional_domain`. If the domain was removed in that
        // window, the CAS returns `Ok(false)` (version mismatch) and
        // `with_dsql_retry!` re-runs the whole block: the re-read sees the
        // removed domain and rejects with `DomainNotOwned`. Without this
        // version-bump, the in-transaction read alone would not close the
        // TOCTOU race under READ COMMITTED, because the user insert touches a
        // different row and would not conflict with the org-doc update.
        if let Some((org_doc_id, org_version, org_data)) = org_snapshot {
            let won = tx
                .compare_and_update::<OrganizationDoc>(&org_doc_id, org_version, &org_data)
                .await?;
            if !won {
                return Err(CreateScimUserError::OccConflict);
            }
        }

        tx.commit().await?;
        Ok(ScimUserRecord::from(result))
    })
}

/// Update a user via SCIM, scoped to the caller's org.
///
/// Returns `Ok(false)` if the user doesn't exist, belongs to a
/// different org, or if a concurrent org-ownership change races with
/// the modify loop and causes the mutation to be skipped (rather than
/// reporting silent success). `Ok(true)` on a successful update.
///
/// Uses optimistic concurrency (`store.modify`) so concurrent field
/// mutations (e.g. a GitHub identity update) landing between the org
/// check and the write do not silently overwrite each other.
pub async fn update_scim_user(
    store: &DocumentStore,
    user_id: &str,
    org_id: &str,
    name: Option<&str>,
    external_id: Option<&str>,
    active: bool,
) -> Result<bool> {
    // Org ownership check: read before entering the modify loop.
    let Some(doc) = store.get::<UserDoc>(user_id).await? else {
        return Ok(false);
    };
    if doc.data.org_id.as_deref() != Some(org_id) {
        return Ok(false);
    }

    // Use modify for optimistic concurrency — re-check org ownership
    // inside the closure so a concurrent org migration cannot smuggle
    // a cross-org write through a version win.
    //
    // `AtomicBool` is used to signal from the `Fn` closure back to the caller
    // whether the mutation was applied (org still matched) or skipped.
    let applied = std::sync::atomic::AtomicBool::new(false);
    let found = store
        .modify::<UserDoc, _>(user_id, |data| {
            // Reset at the top of every attempt: if an earlier OCC retry set
            // this flag but then lost the version race, the closure runs again
            // and org ownership must be re-evaluated from scratch.
            applied.store(false, std::sync::atomic::Ordering::Relaxed);
            if data.org_id.as_deref() == Some(org_id) {
                data.name = name.map(String::from);
                data.external_id = external_id.map(String::from);
                data.active = active;
                applied.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        })
        .await?;
    // found=true but applied=false means a concurrent org-ownership change
    // raced between our pre-check and the modify loop. Report it as
    // not-found rather than silent success so the caller sees the right signal.
    Ok(found && applied.load(std::sync::atomic::Ordering::Relaxed))
}

// ============================================================================
// SCIM Filter Parsing (RFC 7644 Section 3.4.2)
// ============================================================================

/// SCIM filter operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScimFilterOp {
    /// Equal — exact match.
    Eq,
    /// Contains — substring match.
    Co,
    /// Starts with — prefix match.
    Sw,
}

/// Parsed SCIM filter result.
#[derive(Debug)]
pub(crate) struct ScimFilter {
    /// The filter operator.
    pub op: ScimFilterOp,
    /// The quoted value from the filter expression.
    pub value: String,
}

/// Error from SCIM filter or pagination operations.
#[derive(Debug)]
pub enum ScimFilterError {
    /// The filter uses an operator we don't support.
    UnsupportedOperator(String),
    /// Non-indexed filter against a table with >10 000 rows.
    FilterTooBroad,
    /// Requested offset exceeds the 10 000-row cap.
    OffsetTooLarge,
}

impl std::fmt::Display for ScimFilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedOperator(op) => {
                write!(f, "unsupported filter operator '{op}'")
            }
            Self::FilterTooBroad => {
                write!(f, "filter is too broad for the current dataset size")
            }
            Self::OffsetTooLarge => {
                write!(f, "startIndex exceeds maximum supported offset")
            }
        }
    }
}

impl std::error::Error for ScimFilterError {}

/// Parse a SCIM filter expression for the given attribute.
///
/// Supports `eq`, `co`, and `sw` operators (RFC 7644 Section
/// 3.4.2). Returns `Ok(Some(filter))` on match, `Ok(None)` if
/// the attribute doesn't match, and `Err` for unsupported
/// operators.
pub(crate) fn parse_scim_filter(
    filter: &str,
    attr: &str,
) -> Result<Option<ScimFilter>, ScimFilterError> {
    let filter_lower = filter.to_lowercase();
    let attr_lower = attr.to_lowercase();

    let Some(attr_pos) = filter_lower.find(&attr_lower) else {
        return Ok(None);
    };

    let after_attr = filter_lower
        .get(attr_pos.saturating_add(attr_lower.len())..)
        .unwrap_or("");
    let after_attr_trimmed = after_attr.trim_start();

    let Some(space_end) = after_attr_trimmed.find(' ') else {
        return Ok(None);
    };
    let Some(op_word) = after_attr_trimmed.get(..space_end) else {
        return Ok(None);
    };

    let op = match op_word {
        "eq" => ScimFilterOp::Eq,
        "co" => ScimFilterOp::Co,
        "sw" => ScimFilterOp::Sw,
        other => return Err(ScimFilterError::UnsupportedOperator(other.to_string())),
    };

    // Extract quoted value from the original filter (preserving case).
    //
    // We search in `filter_lower` for consistent byte offsets, then map
    // back to the original `filter` using `char_indices` so that any
    // multibyte characters that change byte length under `to_lowercase()`
    // don't cause offset misalignment.
    let pattern_lower = format!("{attr_lower} {op_word} ");

    if let Some(lower_pos) = filter_lower.find(&pattern_lower) {
        let lower_end = lower_pos.saturating_add(pattern_lower.len());

        // Map byte offset in filter_lower back to the original filter
        // by counting characters up to that offset, then converting
        // back to a byte offset in the original string.
        let char_offset = filter_lower.get(..lower_end).map(|s| s.chars().count());

        if let Some(orig_byte_pos) =
            char_offset.and_then(|n| filter.char_indices().nth(n).map(|(i, _)| i))
            && let Some(rest_str) = filter.get(orig_byte_pos..)
            && let Some(unquoted) = rest_str.strip_prefix('"')
            && let Some(end) = unquoted.find('"')
            && let Some(val) = unquoted.get(..end)
        {
            return Ok(Some(ScimFilter {
                op,
                value: val.to_string(),
            }));
        }
    }

    Ok(None)
}

// ============================================================================
// SCIM Groups
// ============================================================================

/// SCIM Group record.
#[derive(Debug)]
pub struct ScimGroupRecord {
    pub id: String,
    pub display_name: String,
    pub external_id: Option<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl From<Document<ScimGroupDoc>> for ScimGroupRecord {
    fn from(doc: Document<ScimGroupDoc>) -> Self {
        Self {
            id: doc.id,
            display_name: doc.data.display_name,
            external_id: doc.data.external_id,
            created_at: doc.created_at,
            updated_at: doc.updated_at,
        }
    }
}

/// Create a new SCIM group bound to the caller's org.
pub async fn create_scim_group(
    store: &DocumentStore,
    org_id: &str,
    display_name: &str,
    external_id: Option<&str>,
) -> Result<ScimGroupRecord> {
    let doc = ScimGroupDoc {
        org_id: org_id.to_string(),
        display_name: display_name.to_string(),
        external_id: external_id.map(String::from),
    };
    let result = store.insert(&doc).await?;
    Ok(ScimGroupRecord::from(result))
}

/// Get a SCIM group by ID, scoped to the caller's org.
pub async fn get_scim_group(
    store: &DocumentStore,
    id: &str,
    org_id: &str,
) -> Result<Option<ScimGroupRecord>> {
    let Some(doc) = store.get::<ScimGroupDoc>(id).await? else {
        return Ok(None);
    };
    if doc.data.org_id != org_id {
        return Ok(None);
    }
    Ok(Some(ScimGroupRecord::from(doc)))
}

/// List SCIM groups with pagination.
///
/// Returns `(records, total_count)` where `total_count` is the total number of
/// matching groups (before pagination).
///
/// # Errors
///
/// Returns [`ScimFilterError::FilterTooBroad`] for non-indexed filters on
/// tables with >10 000 rows. Returns [`ScimFilterError::OffsetTooLarge`]
/// when the computed offset exceeds 10 000.
pub async fn list_scim_groups(
    store: &DocumentStore,
    org_id: &str,
    filter: Option<&str>,
    start_index: usize,
    count: usize,
) -> Result<(Vec<ScimGroupRecord>, usize)> {
    let offset = start_index.saturating_sub(1); // SCIM 1-indexed

    if let Some(f) = filter
        && let Some(result) = try_indexed_group_lookup(store, org_id, f).await?
    {
        let total = result.len();
        let page = result.into_iter().skip(offset).take(count).collect();
        return Ok((page, total));
    }

    // Non-indexed filter: bounded by 10k so a large org does not load
    // every group into memory for an unrecognized filter expression.
    if filter.is_some() {
        let total_in_org = store.count::<ScimGroupDoc>("org_id", org_id).await?;
        if total_in_org > 10_000 {
            return Err(ScimFilterError::FilterTooBroad.into());
        }
        let all = store.find_all::<ScimGroupDoc>("org_id", org_id).await?;
        let mut records: Vec<ScimGroupRecord> =
            all.into_iter().map(ScimGroupRecord::from).collect();
        if let Some(f) = filter {
            records = apply_scim_group_filter(records, f)?;
        }
        records.sort_by_key(|b| std::cmp::Reverse(b.created_at));
        let total = records.len();
        let page = records.into_iter().skip(offset).take(count).collect();
        return Ok((page, total));
    }

    // Unfiltered: push pagination to the DB.
    if offset > 10_000 {
        return Err(ScimFilterError::OffsetTooLarge.into());
    }
    let (docs, total_count) = store
        .find_paginated_with_count::<ScimGroupDoc>("org_id", org_id, offset as u64, count as u64)
        .await?;
    Ok((
        docs.into_iter().map(ScimGroupRecord::from).collect(),
        usize::try_from(total_count).unwrap_or(usize::MAX),
    ))
}

/// Try indexed eq lookups for SCIM group filters, scoped to org.
async fn try_indexed_group_lookup(
    store: &DocumentStore,
    org_id: &str,
    filter: &str,
) -> Result<Option<Vec<ScimGroupRecord>>> {
    if let Some(f) = parse_scim_filter(filter, "displayName")?
        && f.op == ScimFilterOp::Eq
    {
        let docs = store
            .find_by_indexes::<ScimGroupDoc>(&[("display_name", &f.value), ("org_id", org_id)])
            .await?;
        return Ok(Some(docs.into_iter().map(ScimGroupRecord::from).collect()));
    }

    if let Some(f) = parse_scim_filter(filter, "externalId")?
        && f.op == ScimFilterOp::Eq
    {
        let docs = store
            .find_by_indexes::<ScimGroupDoc>(&[("external_id", &f.value), ("org_id", org_id)])
            .await?;
        return Ok(Some(docs.into_iter().map(ScimGroupRecord::from).collect()));
    }

    Ok(None)
}

/// Apply SCIM filter to group records in application code.
fn apply_scim_group_filter(
    records: Vec<ScimGroupRecord>,
    filter: &str,
) -> Result<Vec<ScimGroupRecord>> {
    if let Some(f) = parse_scim_filter(filter, "displayName")? {
        return Ok(records
            .into_iter()
            .filter(|r| match_filter_value(&r.display_name, &f))
            .collect());
    }

    if let Some(f) = parse_scim_filter(filter, "externalId")? {
        return Ok(records
            .into_iter()
            .filter(|r| {
                r.external_id
                    .as_deref()
                    .is_some_and(|eid| match_filter_value(eid, &f))
            })
            .collect());
    }

    Ok(records)
}

/// Update a SCIM group, scoped to the caller's org.
///
/// Returns `Ok(false)` if the group doesn't exist, belongs to a different org,
/// or if a concurrent org-ownership change races with the modify loop and causes
/// the mutation to be skipped. `Ok(true)` on a successful update.
///
/// Uses optimistic concurrency (`store.modify`) so concurrent field mutations
/// do not silently overwrite each other. The org-scope check is re-evaluated
/// inside the closure on each OCC retry.
pub async fn update_scim_group(
    store: &DocumentStore,
    id: &str,
    org_id: &str,
    display_name: Option<&str>,
    external_id: Option<&str>,
) -> Result<bool> {
    // Pre-check: return not-found quickly without entering the modify loop
    // if the group is absent or belongs to a different org.
    let Some(doc) = store.get::<ScimGroupDoc>(id).await? else {
        return Ok(false);
    };
    if doc.data.org_id != org_id {
        return Ok(false);
    }

    // Owned copies for the Fn closure.
    let display_name_owned = display_name.map(String::from);
    let external_id_owned = external_id.map(String::from);

    let applied = std::sync::atomic::AtomicBool::new(false);
    let found = store
        .modify::<ScimGroupDoc, _>(id, |data| {
            // Reset at the top of every attempt: if an earlier OCC retry set
            // this flag but then lost the version race, the closure runs again
            // and org ownership must be re-evaluated from scratch.
            applied.store(false, std::sync::atomic::Ordering::Relaxed);
            // Re-check org ownership inside the closure so a concurrent
            // org migration cannot smuggle a cross-org write through a version win.
            if data.org_id != org_id {
                return;
            }
            if let Some(ref name) = display_name_owned {
                data.display_name = name.clone();
            }
            if let Some(ref ext_id) = external_id_owned {
                data.external_id = Some(ext_id.clone());
            }
            applied.store(true, std::sync::atomic::Ordering::Relaxed);
        })
        .await?;

    Ok(found && applied.load(std::sync::atomic::Ordering::Relaxed))
}

/// Delete a SCIM group atomically, scoped to the caller's org.
///
/// Returns `Ok(false)` if the group doesn't exist OR belongs to a
/// different org. Otherwise deletes memberships and the group within
/// a single transaction.
pub async fn delete_scim_group(store: &DocumentStore, id: &str, org_id: &str) -> Result<bool> {
    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await?;

        let Some(doc) = tx.get::<ScimGroupDoc>(id).await? else {
            return Ok(false);
        };
        if doc.data.org_id != org_id {
            return Ok(false);
        }

        tx.delete_by_index::<ScimGroupMemberDoc>("group_id", id)
            .await?;
        tx.delete(id).await?;

        tx.commit().await?;
        Ok(true)
    })
}

/// Add a member to a SCIM group, scoped to the caller's org.
///
/// Verifies the group is in the caller's org (single indexed lookup,
/// not per-user) and then inserts the membership row. Cross-org
/// `user_id` values become inert references — they are filtered out
/// when reading the group's members.
///
/// Returns `Ok(false)` if the group doesn't exist OR belongs to a
/// different org.
pub async fn add_scim_group_member(
    store: &DocumentStore,
    group_id: &str,
    org_id: &str,
    user_id: &str,
) -> Result<bool> {
    if get_scim_group(store, group_id, org_id).await?.is_none() {
        return Ok(false);
    }

    let existing = store
        .find_by_indexes::<ScimGroupMemberDoc>(&[("group_id", group_id), ("user_id", user_id)])
        .await?;

    if existing.is_empty() {
        let doc = ScimGroupMemberDoc {
            group_id: group_id.to_string(),
            user_id: user_id.to_string(),
        };
        store.insert(&doc).await?;
    }

    Ok(true)
}

/// Remove a member from a SCIM group, scoped to the caller's org.
///
/// Returns `Ok(false)` if the group doesn't exist, belongs to a
/// different org, or the user is not a member.
pub async fn remove_scim_group_member(
    store: &DocumentStore,
    group_id: &str,
    org_id: &str,
    user_id: &str,
) -> Result<bool> {
    if get_scim_group(store, group_id, org_id).await?.is_none() {
        return Ok(false);
    }

    let existing = store
        .find_by_indexes::<ScimGroupMemberDoc>(&[("group_id", group_id), ("user_id", user_id)])
        .await?;

    if let Some(doc) = existing.into_iter().next() {
        store.delete(&doc.id).await?;
        return Ok(true);
    }
    Ok(false)
}

/// Get all members of a SCIM group, scoped to the caller's org.
///
/// Returns the group's members filtered to those that belong to the
/// caller's org. Cross-org user_ids in the membership table (from
/// shadow-add attempts) are silently filtered out at read time.
///
/// Returns `Ok(None)` if the group doesn't exist OR belongs to a
/// different org.
pub async fn get_scim_group_members(
    store: &DocumentStore,
    group_id: &str,
    org_id: &str,
) -> Result<Option<Vec<ScimUserRecord>>> {
    if get_scim_group(store, group_id, org_id).await?.is_none() {
        return Ok(None);
    }

    let member_docs = store
        .find_all::<ScimGroupMemberDoc>("group_id", group_id)
        .await?;

    let mut users = Vec::with_capacity(member_docs.len());
    for member in &member_docs {
        if let Some(user_doc) = store.get::<UserDoc>(&member.data.user_id).await?
            && user_doc.data.org_id.as_deref() == Some(org_id)
        {
            users.push(ScimUserRecord::from(user_doc));
        }
    }

    users.sort_by(|a, b| a.email.cmp(&b.email));
    Ok(Some(users))
}

/// Replace all members of a SCIM group atomically, scoped to the
/// caller's org.
///
/// Verifies the group is in the caller's org (single indexed lookup,
/// not per-user). Cross-org `user_id` values in `user_ids` become
/// inert references that are filtered out at read time.
///
/// Returns `Ok(false)` if the group doesn't exist OR belongs to a
/// different org.
pub async fn replace_scim_group_members(
    store: &DocumentStore,
    group_id: &str,
    org_id: &str,
    user_ids: &[String],
) -> Result<bool> {
    if get_scim_group(store, group_id, org_id).await?.is_none() {
        return Ok(false);
    }

    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await?;

        tx.delete_by_index::<ScimGroupMemberDoc>("group_id", group_id)
            .await?;

        for user_id in user_ids {
            let doc = ScimGroupMemberDoc {
                group_id: group_id.to_string(),
                user_id: user_id.clone(),
            };
            tx.insert(&doc).await?;
        }

        tx.commit().await?;
        Ok(true)
    })
}
