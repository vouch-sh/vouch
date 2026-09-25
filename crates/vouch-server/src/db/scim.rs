// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM 2.0 (RFC 7643/7644) database operations.

use super::audit::{AuditEventKind, AuditStore};
use super::document_type::{Document, DocumentType};
use super::documents::audit::ScimAuditData;
use super::documents::organization::OrganizationDoc;
use super::documents::scim::{ScimGroupDoc, ScimGroupMemberDoc, ScimTokenDoc};
use super::documents::user::{UserDoc, UserOrg};
use super::store::DocumentStore;
use crate::error::ServiceError;
use crate::scim_filter::{AttrExp, CompareOp, FilterError};
use anyhow::Result;
use jiff::Timestamp;
use std::collections::BTreeSet;

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
    now: Timestamp,
) -> Result<Option<ScimToken>> {
    let doc = store
        .find_one::<ScimTokenDoc>("token_hash", token_hash)
        .await?;

    let Some(doc) = doc else {
        return Ok(None);
    };

    // Check expiration
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
#[expect(
    clippy::disallowed_methods,
    reason = "stamps the token's created_at, and the cap count re-reads per OCC attempt"
)]
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
/// Returns `Ok(true)` only when this call removed the token. `Ok(false)` covers
/// a token that does not exist, belongs to another org, or was removed by a
/// concurrent delete, so exactly one of several concurrent deletes reports
/// success and gets audited.
pub async fn delete_scim_token(
    store: &DocumentStore,
    token_id: &str,
    org_id: &str,
) -> Result<bool> {
    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await?;

        let Some(doc) = tx.get::<ScimTokenDoc>(token_id).await? else {
            return Ok(false);
        };
        if doc.data.org_id.as_deref() != Some(org_id) {
            return Ok(false);
        }

        let removed = tx.delete(token_id).await?;
        tx.commit().await?;
        Ok(removed)
    })
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

/// Record a SCIM audit log entry via AuditStore; best-effort.
///
/// `org_domain` is the acting organization's primary email domain
/// ([`ScimAuth::org_domain`]). SCIM operations have no user/email of their
/// own, so without it the event is written with a NULL `email_domain` and
/// is invisible to org-scoped audit reads (`/admin/audit`,
/// `GET /api/v1/org/audit-events`).
pub async fn record_scim_audit(
    audit: &AuditStore,
    data: &ScimAuditData<'_>,
    org_domain: Option<&str>,
) {
    audit
        .record_event_with_domain(AuditEventKind::ScimOperation, None, org_domain, data)
        .await;
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
            email: doc.data.email.into_string(),
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
pub(crate) async fn list_scim_users(
    store: &DocumentStore,
    org_id: &str,
    filter: Option<&UserListFilter>,
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

    // Non-indexed filter (`co`/`sw`): must load org-scoped rows and filter
    // in-app. Bounded by 10k so an org with millions of users does not load
    // every record into memory.
    if let Some(f) = filter {
        let total_in_org = store.count::<UserDoc>("org_id", org_id).await?;
        if total_in_org > 10_000 {
            return Err(ScimFilterError::FilterTooBroad.into());
        }
        let all = store.find_all::<UserDoc>("org_id", org_id).await?;
        let mut records: Vec<ScimUserRecord> = all
            .into_iter()
            .map(ScimUserRecord::from)
            .filter(|r| f.matches(r))
            .collect();
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

/// Try indexed eq lookups for SCIM user filters, scoped to org. `None` for
/// an operator the indexes cannot answer (`co`, `sw`).
async fn try_indexed_user_lookup(
    store: &DocumentStore,
    org_id: &str,
    filter: &UserListFilter,
) -> Result<Option<Vec<ScimUserRecord>>> {
    let docs = match filter {
        // `userName` is `caseExact: false` per RFC 7643, and emails are stored
        // ASCII-lowercase by `create_scim_user` / `enroll_user_with_org`.
        // Normalize the filter value to match the stored index; otherwise a
        // mixed-case filter like `userName eq "Alice@example.com"` misses the
        // user stored as `alice@example.com`.
        UserListFilter::UserName(f) if f.op == ScimFilterOp::Eq => {
            let email = crate::email::Email::new(&f.value);
            store
                .find_by_indexes::<UserDoc>(&[("email", email.as_str()), ("org_id", org_id)])
                .await?
        }
        // externalId has caseExact: true per RFC 7643 Section 3.1, so the
        // case-sensitive indexed lookup is correct and must not be lowercased.
        UserListFilter::ExternalId(f) if f.op == ScimFilterOp::Eq => {
            store
                .find_by_indexes::<UserDoc>(&[("external_id", &f.value), ("org_id", org_id)])
                .await?
        }
        UserListFilter::UserName(_) | UserListFilter::ExternalId(_) => return Ok(None),
    };
    Ok(Some(docs.into_iter().map(ScimUserRecord::from).collect()))
}

/// Check if a value matches a SCIM filter.
///
/// Per RFC 7644 Section 3.4.2.2, the case sensitivity of string comparisons
/// "SHALL be determined by the attribute's 'caseExact' characteristic". When
/// `case_exact` is true (e.g. `externalId`, see RFC 7643 Section 3.1),
/// comparisons are case-sensitive for all operators. When false (e.g.
/// `userName`, `email`, `displayName`), comparisons are case-insensitive.
fn match_filter_value(value: &str, filter: &ScimFilter, case_exact: bool) -> bool {
    if case_exact {
        match filter.op {
            ScimFilterOp::Eq => value == filter.value,
            ScimFilterOp::Co => value.contains(&filter.value),
            ScimFilterOp::Sw => value.starts_with(&filter.value),
        }
    } else {
        let value_lower = value.to_lowercase();
        let filter_lower = filter.value.to_lowercase();
        match filter.op {
            ScimFilterOp::Eq => value_lower == filter_lower,
            ScimFilterOp::Co => value_lower.contains(&filter_lower),
            ScimFilterOp::Sw => value_lower.starts_with(&filter_lower),
        }
    }
}

/// Get a user by ID for SCIM, scoped to the caller's org.
///
/// Returns `None` if the user doesn't exist OR belongs to a different
/// org. Treating cross-org as not-found avoids leaking existence.
///
/// Every id Vouch issues is a UUID, so an id that does not parse as one
/// names no resource and returns `None` without a store read.
pub async fn get_scim_user(
    store: &DocumentStore,
    user_id: &str,
    org_id: &str,
) -> Result<Option<ScimUserRecord>> {
    if uuid::Uuid::try_parse(user_id).is_err() {
        return Ok(None);
    }
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

    // Canonicalize so the duplicate check and the stored row match the
    // casing used by `enroll_user_with_org`. Without this, a SCIM provision
    // of `Alice@example.com` would not collide with a subsequent OIDC
    // enrollment as `alice@example.com`, producing two user records for the
    // same person.
    let email = crate::email::Email::new(email);

    // Derived once outside the retried block: stable across retries and
    // identical for concurrent callers passing the same email in any casing
    // (`Email` is canonical by construction).
    let user_id = deterministic_user_id(&email);

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
                // `Email::domain` is already canonical (lowercase), matching
                // the convention used by `OrganizationDoc::verified_domains`
                // (additional domains are stored verbatim from
                // `Domain::parse`, which lowercases; the primary domain is
                // lowercased by `get_or_create_org`).
                let candidate_domain = email.domain().ok_or_else(|| {
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
        if tx
            .find_one::<UserDoc>("email", email.as_str())
            .await?
            .is_some()
        {
            return Err(CreateScimUserError::DuplicateEmail);
        }

        // `id` and `domain` come from the one `org_snapshot` read above
        // (the domain-ownership check already required it), so one can't be
        // stamped without the other.
        let user_org = org_snapshot.as_ref().map(|(id, _, data)| UserOrg {
            id,
            domain: data.domain.as_str(),
        });

        let doc = UserDoc {
            email: email.clone(),
            name: name.map(String::from),
            org_id: user_org.map(|o| o.id.to_string()),
            org_domain: user_org.map(|o| o.domain.to_string()),
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
/// Returns `Ok(false)` if the user doesn't exist, belongs to a different org,
/// or if a concurrent org-ownership change races with this transaction and
/// causes the mutation to be skipped (rather than reporting silent success).
/// `Ok(true)` on a successful update.
///
/// # Errors
///
/// [`ScimUpdateError::LastAdmin`] when the write would clear `active` on the
/// organization's only active admin. `active=false` reaching an admin removes
/// them from the admin count exactly as
/// [`crate::db::demote_or_deactivate_member`] does, so it takes the same floor
/// — otherwise a `UsersWrite` token could `PATCH active=false` across every
/// admin in turn.
///
/// The count, the write, and the organization row's version bump share one
/// transaction. That is what makes the floor atomic on every backend: DSQL is
/// OCC-only with no `SELECT … FOR UPDATE`, so concurrent deactivations have to
/// be forced to collide on the org row (CLAUDE.md rule 10).
pub async fn update_scim_user(
    store: &DocumentStore,
    user_id: &str,
    org_id: &str,
    name: Option<&str>,
    external_id: Option<&str>,
    active: bool,
) -> std::result::Result<bool, ScimUpdateError> {
    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await?;

        // Test-only seam, before the first read so a write it commits is
        // visible to the last-admin count below.
        #[cfg(test)]
        store.run_last_admin_count_test_hook(user_id).await;

        let Some(user_doc) = tx.get::<UserDoc>(user_id).await? else {
            return Ok(false);
        };
        // Re-checked inside the transaction so a concurrent org migration
        // cannot smuggle a cross-org write through a version win.
        if user_doc.data.org_id.as_deref() != Some(org_id) {
            return Ok(false);
        }

        // Version first, then the predicate read it must guard — read
        // afterwards it would already carry a sibling's bump and the
        // compare-and-update below would wrongly succeed. Same ordering and
        // same reason as `demote_or_deactivate_member` and `delete_user`.
        let org_doc = tx
            .get::<super::documents::organization::OrganizationDoc>(org_id)
            .await?;

        // Only clearing `active` on a currently-active admin can breach the
        // floor. Renames, external_id changes, and `active=true` cannot.
        if !active
            && user_doc.data.is_org_admin
            && user_doc.data.active
            && super::users::other_active_admins(&mut tx, org_id, user_id).await? == 0
        {
            return Err(ScimUpdateError::LastAdmin);
        }

        // A deactivated user can no longer manage their applications: their
        // RFC 7592 registration access tokens are revoked on every client they
        // own, and org-scoped applications move to an active admin, as on
        // delete and on admin deactivation.
        if !active && user_doc.data.active {
            if !super::users::revoke_owner_registration_tokens(&mut tx, user_id).await? {
                return Err(ScimUpdateError::OccConflict);
            }
            if !super::users::transfer_org_clients(&mut tx, Some(org_id), user_id).await? {
                return Err(ScimUpdateError::OccConflict);
            }
        }

        let mut updated = user_doc.data.clone();
        updated.name = name.map(String::from);
        updated.external_id = external_id.map(String::from);
        updated.active = active;
        if !tx
            .compare_and_update(user_id, user_doc.version, &updated)
            .await?
        {
            return Err(ScimUpdateError::OccConflict);
        }

        if let Some(org_doc) = org_doc
            && !tx
                .compare_and_update(org_id, org_doc.version, &org_doc.data)
                .await?
        {
            return Err(ScimUpdateError::OccConflict);
        }

        tx.commit().await?;
        Ok(true)
    })
}

/// Failure modes of [`update_scim_user`].
#[derive(Debug, thiserror::Error)]
pub enum ScimUpdateError {
    /// The write would leave the organization with no active admin.
    #[error("organization would be left with no active admin")]
    LastAdmin,
    /// Another transaction changed the organization or the user row while this
    /// update was counting admins.
    #[error("organization changed during SCIM user update")]
    OccConflict,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl super::pool::RetryableError for ScimUpdateError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::OccConflict => true,
            Self::LastAdmin => false,
            Self::Other(e) => super::pool::is_retryable_db_error(e),
        }
    }
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

/// One supported comparison: an operator and its decoded string value.
#[derive(Debug)]
pub(crate) struct ScimFilter {
    /// The filter operator.
    pub op: ScimFilterOp,
    /// The comparison value, with its JSON escapes resolved.
    pub value: String,
}

impl TryFrom<&AttrExp<'_>> for ScimFilter {
    type Error = FilterError;

    /// `eq`, `co`, and `sw` with a string value; every other operator is
    /// "the specified attribute and filter comparison combination is not
    /// supported" (RFC 7644 §3.12 Table 9).
    fn try_from(exp: &AttrExp<'_>) -> Result<Self, FilterError> {
        let op = match exp.op {
            CompareOp::Eq => ScimFilterOp::Eq,
            CompareOp::Co => ScimFilterOp::Co,
            CompareOp::Sw => ScimFilterOp::Sw,
            CompareOp::Ne
            | CompareOp::Ew
            | CompareOp::Gt
            | CompareOp::Lt
            | CompareOp::Ge
            | CompareOp::Le => return Err(exp.unsupported()),
        };
        Ok(Self {
            op,
            value: exp.string_value()?.to_owned(),
        })
    }
}

/// A Users list filter Vouch evaluates, built from a parsed [`AttrExp`].
/// Any other attribute is declined, never widened to every user.
#[derive(Debug)]
pub(crate) enum UserListFilter {
    /// `userName`, or its alias `email`: the stored email, `caseExact: false`.
    UserName(ScimFilter),
    /// `externalId`, `caseExact: true` (RFC 7643 Section 3.1).
    ExternalId(ScimFilter),
}

impl TryFrom<AttrExp<'_>> for UserListFilter {
    type Error = FilterError;

    fn try_from(exp: AttrExp<'_>) -> Result<Self, FilterError> {
        if exp.is("userName") || exp.is("email") {
            Ok(Self::UserName(ScimFilter::try_from(&exp)?))
        } else if exp.is("externalId") {
            Ok(Self::ExternalId(ScimFilter::try_from(&exp)?))
        } else {
            Err(exp.unsupported())
        }
    }
}

impl UserListFilter {
    /// Whether `record` matches, for the in-memory path. Case sensitivity
    /// follows each attribute's `caseExact` (RFC 7644 §3.4.2.2).
    fn matches(&self, record: &ScimUserRecord) -> bool {
        match self {
            Self::UserName(f) => match_filter_value(&record.email, f, false),
            Self::ExternalId(f) => record
                .external_id
                .as_deref()
                .is_some_and(|eid| match_filter_value(eid, f, true)),
        }
    }
}

/// A Groups list filter Vouch evaluates, built from a parsed [`AttrExp`].
/// Any other attribute is declined, never widened to every group.
#[derive(Debug)]
pub(crate) enum GroupListFilter {
    /// `displayName`, `caseExact: false` (RFC 7643 Section 8.7.2).
    DisplayName(ScimFilter),
    /// `externalId`, `caseExact: true` (RFC 7643 Section 3.1).
    ExternalId(ScimFilter),
}

impl TryFrom<AttrExp<'_>> for GroupListFilter {
    type Error = FilterError;

    fn try_from(exp: AttrExp<'_>) -> Result<Self, FilterError> {
        if exp.is("displayName") {
            Ok(Self::DisplayName(ScimFilter::try_from(&exp)?))
        } else if exp.is("externalId") {
            Ok(Self::ExternalId(ScimFilter::try_from(&exp)?))
        } else {
            Err(exp.unsupported())
        }
    }
}

impl GroupListFilter {
    /// Whether `record` matches, for the in-memory path.
    fn matches(&self, record: &ScimGroupRecord) -> bool {
        match self {
            Self::DisplayName(f) => match_filter_value(&record.display_name, f, false),
            Self::ExternalId(f) => record
                .external_id
                .as_deref()
                .is_some_and(|eid| match_filter_value(eid, f, true)),
        }
    }
}

/// Error from SCIM filter or pagination operations.
#[derive(Debug)]
pub enum ScimFilterError {
    /// Non-indexed filter against a table with >10 000 rows.
    FilterTooBroad,
    /// Requested offset exceeds the 10 000-row cap.
    OffsetTooLarge,
}

impl std::fmt::Display for ScimFilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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

/// Create a SCIM group bound to the caller's org, with its members.
///
/// The group and every membership row commit in one transaction, so a failed
/// member insert (a NUL byte in a user id, say) leaves no group behind for a
/// retried POST to duplicate. Repeated user ids collapse to one row.
/// Cross-org user ids become inert references, filtered out when members are
/// read.
pub async fn create_scim_group(
    store: &DocumentStore,
    org_id: &str,
    display_name: &str,
    external_id: Option<&str>,
    members: &[String],
) -> Result<ScimGroupRecord> {
    let members: BTreeSet<&str> = members.iter().map(String::as_str).collect();
    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await?;
        let group = tx
            .insert(&ScimGroupDoc {
                org_id: org_id.to_string(),
                display_name: display_name.to_string(),
                external_id: external_id.map(String::from),
            })
            .await?;
        for user_id in &members {
            tx.insert_with_id(
                &deterministic_group_member_id(&group.id, user_id),
                &ScimGroupMemberDoc {
                    group_id: group.id.clone(),
                    user_id: (*user_id).to_string(),
                },
            )
            .await?;
        }
        tx.commit().await?;
        Ok(ScimGroupRecord::from(group))
    })
}

/// Get a SCIM group by ID, scoped to the caller's org.
///
/// Every id Vouch issues is a UUID, so an id that does not parse as one
/// names no resource and returns `None` without a store read.
pub async fn get_scim_group(
    store: &DocumentStore,
    id: &str,
    org_id: &str,
) -> Result<Option<ScimGroupRecord>> {
    if uuid::Uuid::try_parse(id).is_err() {
        return Ok(None);
    }
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
pub(crate) async fn list_scim_groups(
    store: &DocumentStore,
    org_id: &str,
    filter: Option<&GroupListFilter>,
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

    // Non-indexed filter (`co`/`sw`): bounded by 10k so a large org does not
    // load every group into memory.
    if let Some(f) = filter {
        let total_in_org = store.count::<ScimGroupDoc>("org_id", org_id).await?;
        if total_in_org > 10_000 {
            return Err(ScimFilterError::FilterTooBroad.into());
        }
        let all = store.find_all::<ScimGroupDoc>("org_id", org_id).await?;
        let mut records: Vec<ScimGroupRecord> = all
            .into_iter()
            .map(ScimGroupRecord::from)
            .filter(|r| f.matches(r))
            .collect();
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

/// Try indexed eq lookups for SCIM group filters, scoped to org. `None` for
/// an operator the indexes cannot answer (`co`, `sw`).
async fn try_indexed_group_lookup(
    store: &DocumentStore,
    org_id: &str,
    filter: &GroupListFilter,
) -> Result<Option<Vec<ScimGroupRecord>>> {
    let docs = match filter {
        // `displayName` is `caseExact: false` per RFC 7643 Section 8.7.2, and
        // `ScimGroupDoc::index_entries` stores the value ASCII-lowercased. Normalize
        // the filter value to match the lowercased index; otherwise a mixed-case
        // filter like `displayName eq "engineering"` misses a group stored as
        // "Engineering". The `co`/`sw` operators are already case-insensitive via
        // the in-memory fallback in `list_scim_groups`.
        //
        // An empty result is returned as `Some(vec![])`, matching the `externalId`
        // branch below and the user lookup: the indexed path is authoritative, so
        // "no such group" is an answer rather than a reason to rescan. Falling
        // through to the unindexed scan instead would hand every miss to the
        // 10k `FilterTooBroad` guard in `list_scim_groups`, and a miss is the
        // normal case — Okta and Entra both query `displayName eq` to check
        // whether a group exists before creating it, so above 10k groups the
        // common provisioning path would start returning 400.
        GroupListFilter::DisplayName(f) if f.op == ScimFilterOp::Eq => {
            let display_name_lower = f.value.to_ascii_lowercase();
            store
                .find_by_indexes::<ScimGroupDoc>(&[
                    ("display_name", &display_name_lower),
                    ("org_id", org_id),
                ])
                .await?
        }
        GroupListFilter::ExternalId(f) if f.op == ScimFilterOp::Eq => {
            store
                .find_by_indexes::<ScimGroupDoc>(&[("external_id", &f.value), ("org_id", org_id)])
                .await?
        }
        GroupListFilter::DisplayName(_) | GroupListFilter::ExternalId(_) => return Ok(None),
    };
    Ok(Some(docs.into_iter().map(ScimGroupRecord::from).collect()))
}

/// A SCIM group's attributes and member user ids, as [`update_scim_group`]
/// hands them to an edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimGroupState {
    pub display_name: String,
    pub external_id: Option<String>,
    /// User ids of the group's membership rows, including cross-org ids that
    /// reads filter out.
    pub members: BTreeSet<String>,
}

/// Failure modes of [`update_scim_group`].
#[derive(Debug)]
pub enum ScimGroupUpdateError<E> {
    /// The edit rejected the update; nothing was written.
    Rejected(E),
    /// Another transaction changed the group while this one was editing it.
    OccConflict,
    Other(anyhow::Error),
}

impl<E> From<anyhow::Error> for ScimGroupUpdateError<E> {
    fn from(err: anyhow::Error) -> Self {
        Self::Other(err)
    }
}

impl<E> std::fmt::Display for ScimGroupUpdateError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(_) => f.write_str("SCIM group update rejected"),
            Self::OccConflict => f.write_str("SCIM group changed during update"),
            Self::Other(err) => write!(f, "{err}"),
        }
    }
}

impl<E> super::pool::RetryableError for ScimGroupUpdateError<E> {
    fn is_retryable(&self) -> bool {
        match self {
            Self::OccConflict => true,
            Self::Rejected(_) => false,
            Self::Other(e) => super::pool::is_retryable_db_error(e),
        }
    }
}

/// Apply `edit` to a SCIM group's attributes and members in one transaction,
/// scoped to the caller's org.
///
/// RFC 7644 §3.5.2: "A PATCH request, regardless of the number of operations,
/// SHALL be treated as atomic." `edit` runs against the stored state and the
/// result is written whole or not at all: a rejection writes nothing, and the
/// attribute change and every membership insert and delete commit together.
///
/// Only the difference is written, so an edit that changes nothing writes
/// nothing and leaves `meta.lastModified` alone (RFC 7644 §3.5.2.1). Any
/// change version-bumps the group document first; concurrent updates of the
/// same group collide on it and retry against the winner's state, so neither
/// loses the other's members. `edit` is `Fn` because a retry runs it again.
///
/// Returns `Ok(false)` if the group doesn't exist or belongs to a different
/// org.
pub async fn update_scim_group<E, F>(
    store: &DocumentStore,
    id: &str,
    org_id: &str,
    edit: F,
) -> std::result::Result<bool, ScimGroupUpdateError<E>>
where
    F: Fn(&mut ScimGroupState) -> std::result::Result<(), E>,
{
    if uuid::Uuid::try_parse(id).is_err() {
        return Ok(false);
    }
    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await?;
        let Some(doc) = tx.get::<ScimGroupDoc>(id).await? else {
            return Ok(false);
        };
        if doc.data.org_id != org_id {
            return Ok(false);
        }
        let member_docs = tx.find_all::<ScimGroupMemberDoc>("group_id", id).await?;

        let stored = ScimGroupState {
            display_name: doc.data.display_name.clone(),
            external_id: doc.data.external_id.clone(),
            members: member_docs
                .iter()
                .map(|member| member.data.user_id.clone())
                .collect(),
        };
        let mut edited = stored.clone();
        edit(&mut edited).map_err(ScimGroupUpdateError::Rejected)?;
        if edited == stored {
            return Ok(true);
        }

        let updated = ScimGroupDoc {
            org_id: doc.data.org_id.clone(),
            display_name: edited.display_name.clone(),
            external_id: edited.external_id.clone(),
        };
        if !tx.compare_and_update(id, doc.version, &updated).await? {
            return Err(ScimGroupUpdateError::OccConflict);
        }
        // Every row for a removed user goes, including legacy rows written
        // before membership ids were deterministic.
        for member in &member_docs {
            if !edited.members.contains(&member.data.user_id) {
                tx.delete(&member.id).await?;
            }
        }
        for user_id in edited.members.difference(&stored.members) {
            tx.insert_with_id(
                &deterministic_group_member_id(id, user_id),
                &ScimGroupMemberDoc {
                    group_id: id.to_string(),
                    user_id: user_id.clone(),
                },
            )
            .await?;
        }

        tx.commit().await?;
        Ok(true)
    })
}

/// Delete a SCIM group atomically, scoped to the caller's org.
///
/// Returns `Ok(false)` if the group doesn't exist OR belongs to a
/// different org. Otherwise deletes memberships and the group within
/// a single transaction.
pub async fn delete_scim_group(store: &DocumentStore, id: &str, org_id: &str) -> Result<bool> {
    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await?;

        // Test-only seam: a concurrent delete landing before the existence check.
        #[cfg(test)]
        store.run_delete_test_hook(id).await;

        let Some(doc) = tx.get::<ScimGroupDoc>(id).await? else {
            return Ok(false);
        };
        if doc.data.org_id != org_id {
            return Ok(false);
        }

        tx.delete_by_index::<ScimGroupMemberDoc>("group_id", id)
            .await?;
        let removed = tx.delete(id).await?;

        tx.commit().await?;
        Ok(removed)
    })
}

/// Derive a deterministic document ID from `(group_id, user_id)`.
///
/// A membership row for a given group and user always has the same document
/// ID, so no interleaving of writers can store the pair twice: a second
/// insert fails on the `documents` PRIMARY KEY constraint instead.
///
/// Same SHA-256-with-domain-separator construction as
/// `deterministic_org_id` (`db/enrollment.rs`), [`deterministic_user_id`]
/// (`db/documents/user.rs`), `deterministic_jti_id` (`db/oauth.rs`), and
/// `deterministic_challenge_state_id` (`db/challenge_states.rs`). The NUL
/// separators cannot appear in a UUID (the shape of every `group_id` and
/// `user_id` in the system), so distinct `(group_id, user_id)` pairs never
/// collide.
fn deterministic_group_member_id(group_id: &str, user_id: &str) -> String {
    use aws_lc_rs::digest::{self, SHA256};

    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(b"scim_group_member\0");
    ctx.update(group_id.as_bytes());
    ctx.update(b"\0");
    ctx.update(user_id.as_bytes());
    hex::encode(ctx.finish().as_ref())
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

#[cfg(test)]
mod tests {
    use super::deterministic_group_member_id;

    #[test]
    fn deterministic_group_member_id_collides_on_equal_pairs() {
        // Two callers passing the same (group_id, user_id) must produce the
        // same document ID — this is what makes the losing concurrent insert
        // surface a primary-key violation instead of silently creating a
        // second membership row.
        assert_eq!(
            deterministic_group_member_id("group-1", "user-1"),
            deterministic_group_member_id("group-1", "user-1"),
        );
    }

    #[test]
    fn deterministic_group_member_id_differs_for_distinct_pairs() {
        assert_ne!(
            deterministic_group_member_id("group-1", "user-1"),
            deterministic_group_member_id("group-1", "user-2"),
        );
        assert_ne!(
            deterministic_group_member_id("group-1", "user-1"),
            deterministic_group_member_id("group-2", "user-1"),
        );
    }

    #[test]
    fn deterministic_group_member_id_boundary_is_unambiguous() {
        // The NUL separator inside the digest makes the encoding unambiguous:
        // shifting characters across the group_id/user_id boundary must not
        // collide. Without the separator, ("g", "u1") and ("g1", "u") would
        // both hash "gu1" and produce the same ID.
        assert_ne!(
            deterministic_group_member_id("g", "u1"),
            deterministic_group_member_id("g1", "u"),
        );
        assert_ne!(
            deterministic_group_member_id("group-1x", "user-1"),
            deterministic_group_member_id("group-1", "xuser-1"),
        );
    }

    #[test]
    fn deterministic_group_member_id_is_plain_hex() {
        // Postgres and Aurora DSQL reject NUL in a text value, and the
        // document ID is stored as text. The hex encoding must contain no
        // control characters so it is storable across every backend.
        let id = deterministic_group_member_id("group-1", "user-1");
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit()),
            "document ID must be plain hex, got {id:?}"
        );
        assert_eq!(
            id.len(),
            64,
            "SHA-256 hex digest must be 64 chars, got {}",
            id.len()
        );
    }

    #[test]
    fn deterministic_group_member_id_differs_from_other_deterministic_ids() {
        // The "scim_group_member\0" domain separator prevents cross-type ID
        // collisions with deterministic IDs derived for other document types
        // (users, orgs, JTIs, challenge states). A user ID and a group-member
        // ID derived from the same underlying bytes must not match.
        use crate::db::documents::user::deterministic_user_id;
        use crate::email::Email;

        let member_id =
            deterministic_group_member_id("01928374-5a6b-7c8d-9e0f-1a2b3c4d5e6f", "user-id-bytes");
        let user_id = deterministic_user_id(&Email::new("user-id-bytes@example.com"));
        assert_ne!(
            member_id, user_id,
            "group-member ID must not collide with a user ID"
        );
    }
}
