// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Audit event store for write-once security events.
//!
//! [`AuditStore`] manages the `audit_events` table — a separate, unencrypted
//! table for security-relevant events. Email addresses are masked to
//! domain-only with an HMAC column for programmatic correlation.

use std::sync::Arc;

use anyhow::{Context, Result};
use jiff::Timestamp;
use sea_query::{Expr, ExprTrait, Iden, Order, Query};

use serde::Serialize;

use super::documents::audit::{CredentialAuditDetails, CredentialAuditEnvelope};
use super::pool::Pool;
use crate::crypto::document_crypto::DocumentCrypto;

// ============================================================================
// Schema Iden Enum
// ============================================================================

#[derive(Iden)]
enum AuditEvents {
    Table,
    Id,
    EventType,
    UserId,
    EmailDomain,
    EmailHmac,
    Data,
    CreatedAt,
}

// ============================================================================
// Event Kind Registry
// ============================================================================

/// Retention class for an audit event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retention {
    /// Governed by `VOUCH_AUTH_EVENTS_RETENTION_DAYS`.
    AuthEvents,
    /// Governed by `VOUCH_OAUTH_EVENTS_RETENTION_DAYS`.
    OAuthEvents,
    /// Never deleted by the cleanup task — a deliberate choice for
    /// administrative and organization-lifecycle records, not a default.
    Keep,
}

/// Defines [`AuditEventKind`] with its wire string and retention class in one
/// place, so a variant cannot exist without both.
macro_rules! audit_event_kinds {
    ($($(#[$attr:meta])* $variant:ident => $name:literal, $retention:ident;)+) => {
        /// Every audit event type the server writes.
        ///
        /// This is the single registry: [`AuditStore::insert_event`] only
        /// accepts these kinds, the cleanup task derives retention from
        /// [`Self::retention`], and `tests/audit_event_docs.rs` fails when a
        /// variant is missing from the operator documentation
        /// (`docs/src/admin/audit.md`).
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum AuditEventKind {
            $($(#[$attr])* $variant,)+
        }

        impl AuditEventKind {
            /// Every variant, for retention sweeps and completeness tests.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            /// The `event_type` string stored in `audit_events`.
            #[must_use]
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $name,)+ }
            }

            /// Parse a wire string (the stored `event_type` column value)
            /// back into a kind. Returns `None` for strings that don't
            /// match any registered kind — callers must not 500 on this,
            /// since it can be reached from caller-supplied filters
            /// (`event_type` query parameter) as well as from stored rows.
            #[must_use]
            pub fn from_wire(s: &str) -> Option<Self> {
                match s { $($name => Some(Self::$variant),)+ _ => None }
            }

            /// Which retention class governs this event.
            #[must_use]
            pub fn retention(self) -> Retention {
                match self { $(Self::$variant => Retention::$retention,)+ }
            }
        }
    };
}

audit_event_kinds! {
    // Authentication and key lifecycle
    LoginSuccess => "login_success", AuthEvents;
    LoginFailed => "login_failed", AuthEvents;
    Enrollment => "enrollment", AuthEvents;
    Logout => "logout", AuthEvents;
    KeyRegistered => "key_registered", AuthEvents;
    KeyRemoved => "key_removed", AuthEvents;
    DeviceAuthApproved => "device_auth_approved", AuthEvents;
    KeyRegistrationReplay => "key_registration_replay", AuthEvents;
    // Upstream identity binding (issuer/subject account linking)
    IdentityBound => "identity_bound", AuthEvents;
    IdentityBindRefused => "identity_bind_refused", AuthEvents;
    // SCIM provisioning operations
    ScimOperation => "scim_operation", AuthEvents;
    // Credential issuance
    SshCredential => "ssh_credential", OAuthEvents;
    AwsCredential => "aws_credential", OAuthEvents;
    GitHubCredential => "github_credential", OAuthEvents;
    TokenExchange => "token_exchange", OAuthEvents;
    // OAuth client usage (high volume) and lifecycle (kept)
    OauthTokenIssued => "oauth_token_issued", OAuthEvents;
    OauthTokenRevoked => "oauth_token_revoked", OAuthEvents;
    OauthClientRegistered => "oauth_client_registered", OAuthEvents;
    OauthClientUpdated => "oauth_client_updated", Keep;
    OauthClientDeleted => "oauth_client_deleted", Keep;
    OauthSecretAdded => "oauth_secret_added", Keep;
    OauthSecretRevoked => "oauth_secret_revoked", Keep;
    // Administrative member actions
    AdminPromote => "admin_promote", Keep;
    AdminDemote => "admin_demote", Keep;
    AdminDeactivate => "admin_deactivate", Keep;
    AdminActivate => "admin_activate", Keep;
    AdminRevokeCredentials => "admin_revoke_credentials", Keep;
    AdminRemoveUser => "admin_remove_user", Keep;
    // Posture policies
    // A denied decision is the evidence trail for the policy gate; it is
    // deliberately NOT ingested as temporal history (a denial feeding a
    // count policy would amplify denials).
    PolicyDenied => "policy_denied", AuthEvents;
    AdminPolicyToggle => "admin_policy_toggle", Keep;
    AdminPolicyCreate => "admin_policy_create", Keep;
    AdminPolicyUpdate => "admin_policy_update", Keep;
    AdminPolicyDelete => "admin_policy_delete", Keep;
    // SCIM token lifecycle
    AdminCreateScimToken => "admin_create_scim_token", Keep;
    AdminDeleteScimToken => "admin_delete_scim_token", Keep;
    AdminRevokeScimToken => "admin_revoke_scim_token", Keep;
    // Organization domains, subdomains, and issuer keys
    OrgDomainAdded => "org_domain_added", Keep;
    OrgDomainVerified => "org_domain_verified", Keep;
    OrgDomainRemoved => "org_domain_removed", Keep;
    OrgDomainExpired => "org_domain_expired", Keep;
    OrgDomainUnverified => "org_domain_unverified", Keep;
    OrgSubdomainClaimed => "org_subdomain_claimed", Keep;
    OrgSubdomainReleased => "org_subdomain_released", Keep;
    OrgIssuerKeyRotated => "org_issuer_key_rotated", Keep;
    OrgIssuerKeyRevoked => "org_issuer_key_revoked", Keep;
    OrgIssuerKeyEmergencyRotation => "org_issuer_key_emergency_rotation", Keep;
}

// ============================================================================
// Raw Row Types (for sqlx FromRow)
// ============================================================================

/// Raw row from the `audit_events` table.
#[derive(sqlx::FromRow)]
struct RawAuditRow {
    id: String,
    event_type: String,
    user_id: Option<String>,
    email_domain: Option<String>,
    email_hmac: Option<String>,
    data: String,
    created_at: String,
}

// ============================================================================
// Public Types
// ============================================================================

/// An audit event retrieved from the store.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// UUID v7 event ID.
    pub id: String,
    /// Event type (e.g., "login_success", "scim_operation") — the
    /// [`AuditEventKind::as_str`] value the event was written with.
    pub event_type: String,
    /// User ID (nullable for system events).
    pub user_id: Option<String>,
    /// Domain portion of the email (e.g., "example.com").
    pub email_domain: Option<String>,
    /// HMAC of the full email for correlation.
    pub email_hmac: Option<String>,
    /// JSON event data.
    pub data: String,
    /// Creation timestamp (parsed from the stored RFC 3339 string).
    pub created_at: Timestamp,
}

/// Filter criteria for querying audit events.
#[derive(Debug, Default, Clone)]
pub struct AuditEventFilter {
    /// Filter by event types (matches any in the list).
    pub event_types: Option<Vec<String>>,
    /// Filter by user ID.
    pub user_id: Option<String>,
    /// Filter by email (computes HMAC for lookup).
    pub email: Option<String>,
    /// Filter by email domain(s) — matches any domain in the list via `IN`.
    /// Used for org scoping: callers pass the org's primary domain plus any
    /// verified additional domains (see `Organization::matching_email_domains`),
    /// not a single caller-chosen domain.
    pub email_domains: Option<Vec<String>>,
    /// Filter events created strictly after this timestamp (RFC 3339,
    /// matching [`jiff::Timestamp::to_string`] output).
    pub since: Option<String>,
    /// Filter events created strictly before this timestamp (RFC 3339,
    /// matching [`jiff::Timestamp::to_string`] output).
    pub until: Option<String>,
    /// Cursor for pagination: only return events with ID less than this
    /// (events are ordered newest-first, so "before" means older events).
    pub before_id: Option<String>,
    /// Cursor for forward pagination: only return events with ID greater
    /// than this, ordered oldest-first. Used by pollers walking the log
    /// forward; set this and `before_id` is ignored.
    pub after_id: Option<String>,
    /// Maximum number of events to return.
    pub limit: Option<u64>,
}

// ============================================================================
// AuditStore
// ============================================================================

/// Store for write-once audit events.
///
/// Events are stored unencrypted for queryability. Emails are masked to
/// domain-only, with an HMAC column for programmatic correlation.
#[derive(Clone)]
pub struct AuditStore {
    pool: Pool,
    crypto: Arc<dyn DocumentCrypto>,
}

impl AuditStore {
    /// Create a new audit store.
    #[must_use]
    pub fn new(pool: Pool, crypto: Arc<dyn DocumentCrypto>) -> Self {
        Self { pool, crypto }
    }

    /// Blind-index HMAC of an email address, canonicalized first.
    ///
    /// The single policy for email correlation keys: insert and query must
    /// both HMAC the canonical form (`crate::email::Email`) or the same
    /// address keys differently depending on the casing the IdP or caller
    /// supplied.
    fn email_hmac(&self, email: &str) -> String {
        self.crypto
            .hmac_index(crate::email::Email::new(email).as_str())
    }

    /// Insert a new audit event.
    ///
    /// `email` is masked to domain-only and HMAC-hashed for correlation.
    /// `data_json` is the serialized event-specific payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the database write fails.
    pub async fn insert_event(
        &self,
        kind: AuditEventKind,
        user_id: Option<&str>,
        email: Option<&str>,
        data_json: &str,
    ) -> Result<String> {
        let email_domain = email.and_then(crate::email::Email::domain_of);
        let email_hmac = email.map(|e| self.email_hmac(e));

        self.insert_event_raw(
            kind,
            user_id,
            email_domain.as_deref(),
            email_hmac.as_deref(),
            jiff::Timestamp::now(),
            data_json,
        )
        .await
    }

    /// Insert a new audit event with an explicit `email_domain`, bypassing
    /// the email→domain derivation in [`Self::insert_event`].
    ///
    /// Used by write sites that act on behalf of an organization rather
    /// than a specific user — SCIM operations, org-lifecycle cleanup
    /// events — and so have no email to derive a domain from. Without
    /// this, those events are written with a NULL `email_domain` and are
    /// invisible to org-scoped audit reads.
    ///
    /// # Errors
    ///
    /// Returns an error if the database write fails.
    pub async fn insert_event_with_domain(
        &self,
        kind: AuditEventKind,
        user_id: Option<&str>,
        email_domain: Option<&str>,
        data_json: &str,
    ) -> Result<String> {
        self.insert_event_raw(
            kind,
            user_id,
            email_domain,
            None,
            jiff::Timestamp::now(),
            data_json,
        )
        .await
    }

    /// Insert an audit event with an explicit `created_at`.
    ///
    /// Test-only: backdates events past the audit events API's 30-second
    /// lag window ([`crate::handlers::admin::audit_api`]) without a test
    /// needing to actually wait.
    ///
    /// # Errors
    ///
    /// Returns an error if the database write fails.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn insert_event_for_test(
        &self,
        kind: AuditEventKind,
        email_domain: Option<&str>,
        created_at: jiff::Timestamp,
        data_json: &str,
    ) -> Result<String> {
        self.insert_event_raw(kind, None, email_domain, None, created_at, data_json)
            .await
    }

    /// Test-only: like [`Self::insert_event_for_test`] but with a user id,
    /// for seeding per-principal temporal policy history.
    ///
    /// # Errors
    ///
    /// Returns an error if the database write fails.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn insert_user_event_for_test(
        &self,
        kind: AuditEventKind,
        user_id: &str,
        created_at: jiff::Timestamp,
        data_json: &str,
    ) -> Result<String> {
        self.insert_event_raw(kind, Some(user_id), None, None, created_at, data_json)
            .await
    }

    /// Shared insert path for [`Self::insert_event`],
    /// [`Self::insert_event_with_domain`], and (test-only)
    /// [`Self::insert_event_for_test`].
    async fn insert_event_raw(
        &self,
        kind: AuditEventKind,
        user_id: Option<&str>,
        email_domain: Option<&str>,
        email_hmac: Option<&str>,
        created_at: jiff::Timestamp,
        data_json: &str,
    ) -> Result<String> {
        let event_type = kind.as_str();
        let id = uuid::Uuid::now_v7().to_string();
        let created_at = created_at.to_string();

        let stmt = Query::insert()
            .into_table(AuditEvents::Table)
            .columns([
                AuditEvents::Id,
                AuditEvents::EventType,
                AuditEvents::UserId,
                AuditEvents::EmailDomain,
                AuditEvents::EmailHmac,
                AuditEvents::Data,
                AuditEvents::CreatedAt,
            ])
            .values([
                id.as_str().into(),
                event_type.into(),
                user_id.into(),
                email_domain.into(),
                email_hmac.into(),
                data_json.into(),
                created_at.as_str().into(),
            ])?
            .to_owned();

        crate::db_execute!(&self.pool, stmt)?;

        Ok(id)
    }

    /// Log a credential-issuance audit event: the shared envelope flattened
    /// with the kind-specific details, written under the details' registry
    /// kind ([`CredentialAuditDetails::KIND`]).
    ///
    /// Best-effort: audit writes must never fail the credential operation
    /// that already succeeded, so failures are logged and swallowed here
    /// instead of at every call site.
    pub async fn log_credential_event<D: CredentialAuditDetails>(
        &self,
        user_id: &str,
        user_email: &str,
        envelope: CredentialAuditEnvelope,
        details: &D,
    ) {
        #[derive(serde::Serialize)]
        struct Payload<'a, D: Serialize> {
            #[serde(flatten)]
            envelope: &'a CredentialAuditEnvelope,
            #[serde(flatten)]
            details: &'a D,
        }

        let result = match serde_json::to_string(&Payload {
            envelope: &envelope,
            details,
        }) {
            Ok(data_json) => {
                self.insert_event(D::KIND, Some(user_id), Some(user_email), &data_json)
                    .await
            }
            Err(e) => Err(e.into()),
        };
        if let Err(e) = result {
            tracing::warn!(
                error = %e,
                event_type = D::KIND.as_str(),
                "failed to write credential audit event"
            );
        }
    }

    /// Query audit events with optional filters.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn query_events(&self, filter: &AuditEventFilter) -> Result<Vec<AuditEvent>> {
        // Scope the query builder so it drops before await
        let stmt = {
            let mut q = Query::select();
            q.columns([
                AuditEvents::Id,
                AuditEvents::EventType,
                AuditEvents::UserId,
                AuditEvents::EmailDomain,
                AuditEvents::EmailHmac,
                AuditEvents::Data,
                AuditEvents::CreatedAt,
            ])
            .from(AuditEvents::Table);

            if let Some(ref types) = filter.event_types {
                q.and_where(
                    Expr::col(AuditEvents::EventType).is_in(types.iter().map(String::as_str)),
                );
            }
            if let Some(ref uid) = filter.user_id {
                q.and_where(Expr::col(AuditEvents::UserId).eq(uid.as_str()));
            }
            if let Some(ref email) = filter.email {
                // Same canonicalizing HMAC as insert time, so lookups
                // correlate regardless of the casing supplied by the caller
                // or returned by the IdP.
                let hmac = self.email_hmac(email);
                q.and_where(Expr::col(AuditEvents::EmailHmac).eq(hmac));
            }
            if let Some(ref domains) = filter.email_domains {
                q.and_where(
                    Expr::col(AuditEvents::EmailDomain).is_in(domains.iter().map(String::as_str)),
                );
            }
            if let Some(ref since) = filter.since {
                q.and_where(Expr::col(AuditEvents::CreatedAt).gt(normalize_timestamp_bound(since)));
            }
            if let Some(ref until) = filter.until {
                q.and_where(Expr::col(AuditEvents::CreatedAt).lt(normalize_timestamp_bound(until)));
            }

            // `after_id` (forward/ascending polling) takes precedence over
            // `before_id` (backward/descending browsing) when both are set —
            // callers are expected to use one or the other.
            if let Some(ref after) = filter.after_id {
                q.and_where(Expr::col(AuditEvents::Id).gt(after.as_str()));
                q.order_by(AuditEvents::Id, Order::Asc);
            } else {
                if let Some(ref before) = filter.before_id {
                    q.and_where(Expr::col(AuditEvents::Id).lt(before.as_str()));
                }
                q.order_by(AuditEvents::Id, Order::Desc);
            }

            if let Some(limit) = filter.limit {
                q.limit(limit);
            }

            q.to_owned()
        };
        let rows: Vec<RawAuditRow> = crate::db_fetch_all!(&self.pool, stmt, RawAuditRow)?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            events.push(raw_to_audit_event(row)?);
        }
        Ok(events)
    }

    /// Query audit events with pagination support.
    ///
    /// Wraps `query_events` and uses the limit+1 trick to detect more pages.
    /// Returns the events and a boolean indicating whether more results exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn query_events_paginated(
        &self,
        filter: &AuditEventFilter,
        page_size: u64,
    ) -> Result<(Vec<AuditEvent>, bool)> {
        let f = AuditEventFilter {
            limit: Some(page_size.saturating_add(1)),
            ..filter.clone()
        };
        let mut events = self.query_events(&f).await?;
        let has_more = events.len() as u64 > page_size;
        if has_more {
            events.pop();
        }
        Ok((events, has_more))
    }

    /// Delete old events of a given kind before a timestamp.
    ///
    /// Returns the number of events deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete fails.
    pub async fn delete_old_events(&self, kind: AuditEventKind, before: &str) -> Result<u64> {
        let stmt = Query::delete()
            .from_table(AuditEvents::Table)
            .and_where(Expr::col(AuditEvents::EventType).eq(kind.as_str()))
            .and_where(Expr::col(AuditEvents::CreatedAt).lt(normalize_timestamp_bound(before)))
            .to_owned();

        let result = crate::db_execute!(&self.pool, stmt)?;
        Ok(result.rows_affected())
    }

    /// Delete expired events for every registered kind per its retention
    /// class. A `None` cutoff means that retention knob is disabled;
    /// [`Retention::Keep`] kinds are never deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if a delete fails.
    pub async fn delete_expired_events(
        &self,
        auth_cutoff: Option<Timestamp>,
        oauth_cutoff: Option<Timestamp>,
    ) -> Result<u64> {
        let mut total: u64 = 0;
        for kind in AuditEventKind::ALL {
            let cutoff = match kind.retention() {
                Retention::AuthEvents => auth_cutoff,
                Retention::OAuthEvents => oauth_cutoff,
                Retention::Keep => None,
            };
            if let Some(cutoff) = cutoff {
                let deleted = self.delete_old_events(*kind, &cutoff.to_string()).await?;
                total = total.saturating_add(deleted);
            }
        }
        Ok(total)
    }
}

// Implement Debug manually to avoid exposing crypto internals.
impl std::fmt::Debug for AuditStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditStore")
            .field("pool", &self.pool)
            .field("crypto", &"<DocumentCrypto>")
            .finish()
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Normalize a `since`/`until`/cleanup-cutoff timestamp bound for
/// lexicographic comparison against the `created_at` column, by truncating
/// it to whole-second precision (dropping any fractional-second component
/// and the trailing `Z`).
///
/// `created_at` is stored as [`jiff::Timestamp::to_string`] output, which
/// trims trailing zero fractional-second digits to a *variable* width — one
/// row might store `...T00:00:00.5Z` (500ms) and another `...T00:00:00Z`
/// (exactly on the second) or `...T00:00:00.537239482Z` (full nanosecond
/// precision). Comparing two such strings lexicographically is only
/// guaranteed correct when one is a zero-padding-equivalent prefix of the
/// other; it silently breaks whenever the digits actually differ at a
/// shared position. Concrete counterexample: bound `...16.537239482` (no Z)
/// vs row `...16.5Z` — chronologically 0.5 < 0.537239482, so the row is
/// *earlier*, but lexicographically `'Z'` (0x5A) > `'3'` (0x33) at the
/// second differing character, so the row compares as *greater*. Because
/// the id-based forward cursor never retries a skipped id, a row wrongly
/// excluded from an `until`/lag-window comparison this way is lost
/// permanently, not just delayed.
///
/// Truncating the *bound* to whole seconds sidesteps the ambiguity
/// entirely: a bound with no fractional part at all is always a strict
/// string prefix of every `created_at` value in that same second
/// (fractional or not), which sorts correctly on both sides of the
/// comparison. The cost is that rows within the bound's own second are
/// compared at second granularity — for `until`, this makes the effective
/// cutoff up to ~1s more conservative (never less), which only strengthens
/// the "never return events newer than the lag window" guarantee and
/// self-corrects on the next poll as `now` advances; for `since`, it makes
/// the filter up to ~1s more inclusive at the boundary, never lossy.
fn normalize_timestamp_bound(bound: &str) -> &str {
    let bound = bound.strip_suffix('Z').unwrap_or(bound);
    match bound.split_once('.') {
        Some((whole_seconds, _fraction)) => whole_seconds,
        None => bound,
    }
}

/// Convert a raw row to an `AuditEvent`.
fn raw_to_audit_event(row: RawAuditRow) -> Result<AuditEvent> {
    let created_at: Timestamp = row
        .created_at
        .parse()
        .context("failed to parse audit event created_at timestamp")?;
    Ok(AuditEvent {
        id: row.id,
        event_type: row.event_type,
        user_id: row.user_id,
        email_domain: row.email_domain,
        email_hmac: row.email_hmac,
        data: row.data,
        created_at,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::unreachable,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::crypto::document_crypto::PlaintextDocumentCrypto;

    async fn test_audit() -> AuditStore {
        let pool = Pool::connect("sqlite::memory:", &crate::db::pool::PoolConfig::default())
            .await
            .unwrap();

        // Tests always use SQLite — execute raw DDL directly
        let Pool::Sqlite(ref p) = pool else {
            unreachable!()
        };
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                user_id TEXT,
                email_domain TEXT,
                email_hmac TEXT,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            )",
        )
        .execute(p)
        .await
        .unwrap();

        let crypto = Arc::new(PlaintextDocumentCrypto);
        AuditStore::new(pool, crypto)
    }

    #[tokio::test]
    async fn insert_and_query_event() {
        let audit = test_audit().await;

        let id = audit
            .insert_event(
                AuditEventKind::LoginSuccess,
                Some("user-123"),
                Some("alice@example.com"),
                r#"{"success":true}"#,
            )
            .await
            .unwrap();
        assert!(!id.is_empty());

        let events = audit
            .query_events(&AuditEventFilter {
                event_types: Some(vec!["login_success".to_string()]),
                ..AuditEventFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "login_success");
        assert_eq!(events[0].user_id.as_deref(), Some("user-123"));
        assert_eq!(events[0].email_domain.as_deref(), Some("example.com"));
    }

    #[tokio::test]
    async fn query_by_email_hmac() {
        let audit = test_audit().await;

        audit
            .insert_event(
                AuditEventKind::LoginSuccess,
                Some("user-1"),
                Some("bob@test.com"),
                "{}",
            )
            .await
            .unwrap();
        audit
            .insert_event(
                AuditEventKind::LoginSuccess,
                Some("user-2"),
                Some("carol@test.com"),
                "{}",
            )
            .await
            .unwrap();

        let events = audit
            .query_events(&AuditEventFilter {
                email: Some("bob@test.com".to_string()),
                ..AuditEventFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].user_id.as_deref(), Some("user-1"));
    }

    #[tokio::test]
    async fn delete_old_events() {
        let audit = test_audit().await;

        audit
            .insert_event(AuditEventKind::LoginSuccess, None, None, "{}")
            .await
            .unwrap();

        // Delete events before far future should delete everything
        let deleted = audit
            .delete_old_events(AuditEventKind::LoginSuccess, "2099-01-01T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(deleted, 1);

        let events = audit
            .query_events(&AuditEventFilter::default())
            .await
            .unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn filter_by_user_id() {
        let audit = test_audit().await;

        audit
            .insert_event(AuditEventKind::LoginSuccess, Some("user-a"), None, "{}")
            .await
            .unwrap();
        audit
            .insert_event(AuditEventKind::LoginSuccess, Some("user-b"), None, "{}")
            .await
            .unwrap();

        let events = audit
            .query_events(&AuditEventFilter {
                user_id: Some("user-a".to_string()),
                ..AuditEventFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn query_with_limit() {
        let audit = test_audit().await;

        for _ in 0..5 {
            audit
                .insert_event(AuditEventKind::LoginSuccess, None, None, "{}")
                .await
                .unwrap();
        }

        let events = audit
            .query_events(&AuditEventFilter {
                limit: Some(2),
                ..AuditEventFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(events.len(), 2);
    }

    #[tokio::test]
    async fn query_by_email_domain_is_case_insensitive() {
        let audit = test_audit().await;

        // Event inserted with a mixed-case email domain, as an IdP might
        // return. The admin audit page queries by the org's stored domain,
        // which is always lowercase (see OIDC/SAML normalization).
        audit
            .insert_event(
                AuditEventKind::LoginSuccess,
                Some("user-1"),
                Some("Alice@CORP.Example.COM"),
                "{}",
            )
            .await
            .unwrap();

        let events = audit
            .query_events(&AuditEventFilter {
                email_domains: Some(vec!["corp.example.com".to_string()]),
                ..AuditEventFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(
            events.len(),
            1,
            "querying by lowercase domain should find event inserted with mixed-case email domain"
        );
        assert_eq!(events[0].email_domain.as_deref(), Some("corp.example.com"));
    }

    #[tokio::test]
    async fn query_by_email_is_case_insensitive() {
        let audit = test_audit().await;

        audit
            .insert_event(
                AuditEventKind::LoginSuccess,
                Some("user-1"),
                Some("Alice@CORP.Example.COM"),
                "{}",
            )
            .await
            .unwrap();

        // Querying with the lowercase variant of the same email must find
        // the event written under the mixed-case variant.
        let events = audit
            .query_events(&AuditEventFilter {
                email: Some("alice@corp.example.com".to_string()),
                ..AuditEventFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(
            events.len(),
            1,
            "querying lowercase email should find event inserted with mixed-case email"
        );
        assert_eq!(events[0].user_id.as_deref(), Some("user-1"));
    }

    #[tokio::test]
    async fn query_by_email_correlates_across_cases() {
        let audit = test_audit().await;

        // Two events for the same user, written under different casings of
        // the same email (e.g. an IdP config change over time). Both must be
        // correlated by the email HMAC filter.
        audit
            .insert_event(
                AuditEventKind::LoginSuccess,
                Some("user-1"),
                Some("Alice@CORP.Example.COM"),
                "{}",
            )
            .await
            .unwrap();
        audit
            .insert_event(
                AuditEventKind::LoginFailed,
                Some("user-1"),
                Some("alice@corp.example.com"),
                "{}",
            )
            .await
            .unwrap();

        let events = audit
            .query_events(&AuditEventFilter {
                email: Some("ALICE@Corp.Example.Com".to_string()),
                ..AuditEventFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(
            events.len(),
            2,
            "querying by email should correlate both mixed-case and lowercase variants"
        );
    }

    #[tokio::test]
    async fn email_normalization_does_not_conflate_distinct_emails() {
        // Only the casing of the same email should be normalized; emails
        // that differ in their domain must remain distinct.
        let audit = test_audit().await;

        audit
            .insert_event(
                AuditEventKind::LoginSuccess,
                Some("user-1"),
                Some("alice@corp.example.com"),
                "{}",
            )
            .await
            .unwrap();
        audit
            .insert_event(
                AuditEventKind::LoginSuccess,
                Some("user-2"),
                Some("alice@other.example.com"),
                "{}",
            )
            .await
            .unwrap();

        let events = audit
            .query_events(&AuditEventFilter {
                email: Some("ALICE@Corp.Example.Com".to_string()),
                ..AuditEventFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(
            events.len(),
            1,
            "case normalization must not conflate emails with different domains"
        );
        assert_eq!(events[0].user_id.as_deref(), Some("user-1"));
    }

    #[tokio::test]
    async fn insert_event_with_domain_stamps_domain_without_email() {
        let audit = test_audit().await;

        let id = audit
            .insert_event_with_domain(
                AuditEventKind::ScimOperation,
                None,
                Some("example.com"),
                "{}",
            )
            .await
            .unwrap();
        assert!(!id.is_empty());

        let events = audit
            .query_events(&AuditEventFilter::default())
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].email_domain.as_deref(), Some("example.com"));
        assert_eq!(
            events[0].email_hmac, None,
            "no email was supplied, so no HMAC should be computed"
        );
    }

    #[tokio::test]
    async fn email_domains_filter_matches_any_domain_in_list() {
        let audit = test_audit().await;

        audit
            .insert_event(AuditEventKind::LoginSuccess, None, Some("a@one.com"), "{}")
            .await
            .unwrap();
        audit
            .insert_event(AuditEventKind::LoginSuccess, None, Some("b@two.com"), "{}")
            .await
            .unwrap();
        audit
            .insert_event(
                AuditEventKind::LoginSuccess,
                None,
                Some("c@three.com"),
                "{}",
            )
            .await
            .unwrap();

        let events = audit
            .query_events(&AuditEventFilter {
                email_domains: Some(vec!["one.com".to_string(), "two.com".to_string()]),
                ..AuditEventFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(
            events.len(),
            2,
            "is_in should match either listed domain and exclude the third"
        );
    }

    #[tokio::test]
    async fn after_id_cursor_walks_forward_without_gap_or_duplicate() {
        let audit = test_audit().await;

        let mut ids = Vec::new();
        for _ in 0..5 {
            let id = audit
                .insert_event(AuditEventKind::LoginSuccess, None, None, "{}")
                .await
                .unwrap();
            ids.push(id);
        }

        // Page through with a page size smaller than the total count and
        // confirm the union of pages is exactly the inserted set, in
        // ascending (oldest-first) order, with no gap or duplicate. Seed
        // the cursor with an empty string (sorts before every real UUID)
        // rather than `None`: `after_id: None` falls back to the store's
        // default descending order (what the `/admin/audit` UI wants),
        // not forward polling — an `Some(_)` cursor is what selects
        // ascending order, even on the very first page.
        let mut seen = Vec::new();
        let mut cursor: Option<String> = Some(String::new());
        loop {
            let (page, has_more) = audit
                .query_events_paginated(
                    &AuditEventFilter {
                        after_id: cursor.clone(),
                        ..AuditEventFilter::default()
                    },
                    2,
                )
                .await
                .unwrap();
            if page.is_empty() {
                break;
            }
            for e in &page {
                seen.push(e.id.clone());
            }
            cursor = Some(seen.last().unwrap().clone());
            if !has_more {
                break;
            }
        }

        assert_eq!(
            seen, ids,
            "forward pagination must reproduce insert order with no gap or dupe"
        );
    }

    #[tokio::test]
    async fn until_filter_excludes_events_after_bound() {
        let audit = test_audit().await;

        audit
            .insert_event(AuditEventKind::LoginSuccess, None, None, "{}")
            .await
            .unwrap();

        // A bound far in the past excludes everything.
        let events = audit
            .query_events(&AuditEventFilter {
                until: Some("2000-01-01T00:00:00Z".to_string()),
                ..AuditEventFilter::default()
            })
            .await
            .unwrap();
        assert!(
            events.is_empty(),
            "until in the past must exclude all events"
        );

        // A bound far in the future includes it.
        let events = audit
            .query_events(&AuditEventFilter {
                until: Some("2999-01-01T00:00:00Z".to_string()),
                ..AuditEventFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(
            events.len(),
            1,
            "until in the future must include the event"
        );
    }

    #[tokio::test]
    async fn since_at_whole_second_bound_includes_fractional_second_row() {
        // Regression test for the lexicographic timestamp-bound bug: jiff
        // trims trailing zero fractional digits, so a whole-second stored
        // row ("...00Z") and a fractional one ("...00.123Z") in the same
        // second must both compare correctly against a whole-second bound.
        let audit = test_audit().await;

        // Insert directly via SQL so the stored `created_at` is exactly
        // controlled, rather than depending on `Timestamp::now()` landing
        // on a particular fraction.
        let Pool::Sqlite(ref pool) = audit.pool else {
            unreachable!("tests always run on sqlite")
        };
        sqlx::query(
            "INSERT INTO audit_events (id, event_type, user_id, email_domain, email_hmac, data, created_at) \
             VALUES (?, 'login_success', NULL, NULL, NULL, '{}', ?)",
        )
        .bind("00000000000000000000000001")
        .bind("2026-01-01T00:00:00.123Z")
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO audit_events (id, event_type, user_id, email_domain, email_hmac, data, created_at) \
             VALUES (?, 'login_success', NULL, NULL, NULL, '{}', ?)",
        )
        .bind("00000000000000000000000002")
        .bind("2026-01-01T00:00:00Z")
        .execute(pool)
        .await
        .unwrap();

        // since = exactly the whole-second bound. Before the fix, the
        // fractional row sorted lexicographically *below* the bound and was
        // wrongly dropped. The exact-equal (zero-fraction) row is also
        // included by the prefix comparison the fix uses — over-inclusive
        // by one exact-boundary instant is the accepted trade-off for a
        // security audit log, versus silently dropping sub-second events.
        let events = audit
            .query_events(&AuditEventFilter {
                since: Some("2026-01-01T00:00:00Z".to_string()),
                ..AuditEventFilter::default()
            })
            .await
            .unwrap();
        let ids: Vec<&str> = events.iter().map(|e| e.id.as_str()).collect();
        assert!(
            ids.contains(&"00000000000000000000000001"),
            "the fractional-second row must not be dropped by a whole-second bound; got {ids:?}"
        );
    }

    #[tokio::test]
    async fn until_defers_same_second_rows_but_never_loses_them() {
        // Regression test for the timestamp-bound fix, using a
        // counterexample found in review: a bound that itself has a fractional part (as
        // every lag-window cutoff computed from `Timestamp::now()` does)
        // compared against a row with a *shorter* trimmed fraction in the
        // same second. Before truncating the bound to whole seconds,
        // comparing "...16.537239482" (bound, no Z) against "...16.5Z"
        // (row) lexicographically found 'Z' (0x5A) > '3' (0x33) at the
        // second differing character, wrongly excluding the row even
        // though 0.5 < 0.537239482 chronologically — and because the
        // id-based forward cursor never retries a skipped id, that
        // exclusion was permanent, not just delayed.
        //
        // Truncating the bound to whole seconds fixes the *permanence*:
        // rows in the bound's own second are conservatively deferred
        // (excluded until `until` advances past that second), never lost.
        // This asserts both halves — deferred now, visible once `until`
        // moves to the next second — since asserting only "eventually
        // visible" wouldn't catch a regression back to the old bug (which
        // also let it through, just via a coin-flip on the digits).
        let audit = test_audit().await;

        let Pool::Sqlite(ref pool) = audit.pool else {
            unreachable!("tests always run on sqlite")
        };
        sqlx::query(
            "INSERT INTO audit_events (id, event_type, user_id, email_domain, email_hmac, data, created_at) \
             VALUES (?, 'login_success', NULL, NULL, NULL, '{}', ?)",
        )
        .bind("00000000000000000000000003")
        .bind("2026-01-01T00:00:16.5Z")
        .execute(pool)
        .await
        .unwrap();

        let events = audit
            .query_events(&AuditEventFilter {
                until: Some("2026-01-01T00:00:16.537239482Z".to_string()),
                ..AuditEventFilter::default()
            })
            .await
            .unwrap();
        assert!(
            events.is_empty(),
            "a row must be deferred (not immediately visible) under an until bound in its own \
             second; got {events:?}"
        );

        let events = audit
            .query_events(&AuditEventFilter {
                until: Some("2026-01-01T00:00:17.000000000Z".to_string()),
                ..AuditEventFilter::default()
            })
            .await
            .unwrap();
        let ids: Vec<&str> = events.iter().map(|e| e.id.as_str()).collect();
        assert!(
            ids.contains(&"00000000000000000000000003"),
            "the row must become visible once until advances past its whole second — \
             deferred, not permanently lost; got {ids:?}"
        );
    }

    #[test]
    fn from_wire_round_trips_every_kind() {
        for kind in AuditEventKind::ALL {
            assert_eq!(AuditEventKind::from_wire(kind.as_str()), Some(*kind));
        }
    }

    #[test]
    fn from_wire_rejects_unknown_string() {
        assert_eq!(AuditEventKind::from_wire("not_a_real_event_type"), None);
        assert_eq!(AuditEventKind::from_wire(""), None);
    }
}
