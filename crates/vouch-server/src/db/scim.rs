// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM 2.0 (RFC 7643/7644) database operations.

use super::audit::AuditStore;
use super::document_type::Document;
use super::documents::audit::ScimAuditData;
use super::documents::scim::{ScimGroupDoc, ScimGroupMemberDoc, ScimTokenDoc};
use super::documents::user::UserDoc;
use super::store::DocumentStore;
use anyhow::Result;
use jiff::Timestamp;

// ============================================================================
// SCIM Scopes
// ============================================================================

/// Individual SCIM permission scope.
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
    /// Create a scope set containing all four scopes (full access).
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

/// Create a new SCIM token.
pub async fn create_scim_token(
    store: &DocumentStore,
    token_hash: &str,
    description: Option<&str>,
    expires_at: Option<Timestamp>,
    org_id: Option<&str>,
    scope: Option<&ScimScopeSet>,
) -> Result<String> {
    let default_scope = ScimScopeSet::default();
    let scope_val = scope.unwrap_or(&default_scope).as_db_string();

    let doc = ScimTokenDoc {
        token_hash: token_hash.to_string(),
        org_id: org_id.map(String::from),
        description: description.map(String::from),
        expires_at,
        scope: scope_val,
    };
    let result = store.insert(&doc).await?;
    Ok(result.id)
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

// ============================================================================
// SCIM Audit → AuditStore
// ============================================================================

/// Insert SCIM audit log entry via AuditStore.
pub async fn insert_scim_audit(
    audit: &AuditStore,
    operation: &str,
    resource_type: &str,
    resource_id: &str,
    actor_token_id: Option<&str>,
    details: Option<&str>,
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
        .insert_event("scim_operation", None, None, &data_json)
        .await
}

/// Delete SCIM audit log entries older than the given timestamp.
pub async fn delete_old_scim_audit_logs(audit: &AuditStore, before: Timestamp) -> Result<u64> {
    let before_str = before.to_string();
    audit.delete_old_events("scim_operation", &before_str).await
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
    // userName/email eq → find_by_indexes combining email + org_id at DB level
    for attr in &["userName", "email"] {
        if let Some(f) = parse_scim_filter(filter, attr)?
            && f.op == ScimFilterOp::Eq
        {
            let docs = store
                .find_by_indexes::<UserDoc>(&[("email", &f.value), ("org_id", org_id)])
                .await?;
            return Ok(Some(docs.into_iter().map(ScimUserRecord::from).collect()));
        }
    }

    // externalId eq → find_by_indexes combining external_id + org_id
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

/// Create a user via SCIM, bound to the given org (or org-less for
/// the certification test path which passes `None`).
///
/// Returns an error containing "UNIQUE" if a user with the same
/// email already exists (application-level uniqueness enforcement,
/// global because emails are globally unique by design).
pub async fn create_scim_user(
    store: &DocumentStore,
    org_id: Option<&str>,
    email: &str,
    name: Option<&str>,
    external_id: Option<&str>,
    active: bool,
) -> Result<ScimUserRecord> {
    let mut tx = store.begin().await?;

    if tx.find_one::<UserDoc>("email", email).await?.is_some() {
        anyhow::bail!("UNIQUE constraint failed: user with email already exists");
    }

    let doc = UserDoc {
        email: email.to_string(),
        name: name.map(String::from),
        org_id: org_id.map(String::from),
        is_org_admin: false,
        active,
        external_id: external_id.map(String::from),
        github_id: None,
        github_login: None,
        github_refresh_token: None,
    };
    let result = tx.insert(&doc).await?;

    tx.commit().await?;
    Ok(ScimUserRecord::from(result))
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

/// SCIM Group member record.
#[derive(Debug)]
pub struct ScimGroupMemberRecord {
    pub group_id: String,
    pub user_id: String,
    pub created_at: Timestamp,
}

impl From<Document<ScimGroupMemberDoc>> for ScimGroupMemberRecord {
    fn from(doc: Document<ScimGroupMemberDoc>) -> Self {
        Self {
            group_id: doc.data.group_id,
            user_id: doc.data.user_id,
            created_at: doc.created_at,
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

/// Get a SCIM group by display name, scoped to the caller's org.
pub async fn get_scim_group_by_name(
    store: &DocumentStore,
    org_id: &str,
    display_name: &str,
) -> Result<Option<ScimGroupRecord>> {
    let docs = store
        .find_by_indexes::<ScimGroupDoc>(&[("display_name", display_name), ("org_id", org_id)])
        .await?;
    Ok(docs.into_iter().next().map(ScimGroupRecord::from))
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

/// Get all groups a user belongs to, scoped to the caller's org.
pub async fn get_user_scim_groups(
    store: &DocumentStore,
    user_id: &str,
    org_id: &str,
) -> Result<Vec<ScimGroupRecord>> {
    let member_docs = store
        .find_all::<ScimGroupMemberDoc>("user_id", user_id)
        .await?;

    let mut groups = Vec::with_capacity(member_docs.len());
    for member in &member_docs {
        if let Some(group_doc) = store.get::<ScimGroupDoc>(&member.data.group_id).await?
            && group_doc.data.org_id == org_id
        {
            groups.push(ScimGroupRecord::from(group_doc));
        }
    }

    groups.sort_by(|a, b| a.display_name.cmp(&b.display_name));
    Ok(groups)
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
}
