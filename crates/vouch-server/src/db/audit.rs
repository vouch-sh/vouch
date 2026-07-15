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
        /// (`docs/src/deployment/monitoring.md`).
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
#[derive(Debug, Default)]
pub struct AuditEventFilter {
    /// Filter by event types (matches any in the list).
    pub event_types: Option<Vec<String>>,
    /// Filter by user ID.
    pub user_id: Option<String>,
    /// Filter by email (computes HMAC for lookup).
    pub email: Option<String>,
    /// Filter by email domain (plaintext match on domain portion).
    pub email_domain: Option<String>,
    /// Filter events created after this timestamp.
    pub since: Option<String>,
    /// Cursor for pagination: only return events with ID less than this
    /// (events are ordered newest-first, so "before" means older events).
    pub before_id: Option<String>,
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
        let event_type = kind.as_str();
        let id = uuid::Uuid::now_v7().to_string();
        let now = jiff::Timestamp::now().to_string();

        let email_domain = email.and_then(extract_domain);
        let email_hmac = email.map(|e| self.crypto.hmac_index(e));

        let domain_ref: Option<&str> = email_domain.as_deref();
        let hmac_ref: Option<&str> = email_hmac.as_deref();

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
                domain_ref.into(),
                hmac_ref.into(),
                data_json.into(),
                now.as_str().into(),
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
                let hmac = self.crypto.hmac_index(email);
                q.and_where(Expr::col(AuditEvents::EmailHmac).eq(hmac));
            }
            if let Some(ref domain) = filter.email_domain {
                q.and_where(Expr::col(AuditEvents::EmailDomain).eq(domain.as_str()));
            }
            if let Some(ref since) = filter.since {
                q.and_where(Expr::col(AuditEvents::CreatedAt).gt(since.as_str()));
            }
            if let Some(ref before) = filter.before_id {
                q.and_where(Expr::col(AuditEvents::Id).lt(before.as_str()));
            }

            q.order_by(AuditEvents::Id, Order::Desc);

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
            event_types: filter.event_types.clone(),
            user_id: filter.user_id.clone(),
            email: filter.email.clone(),
            email_domain: filter.email_domain.clone(),
            since: filter.since.clone(),
            before_id: filter.before_id.clone(),
            limit: Some(page_size.saturating_add(1)),
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
            .and_where(Expr::col(AuditEvents::CreatedAt).lt(before))
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

/// Extract the domain portion of an email address.
fn extract_domain(email: &str) -> Option<String> {
    email.rsplit_once('@').map(|(_, domain)| domain.to_string())
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

    #[test]
    fn extract_domain_works() {
        assert_eq!(
            extract_domain("alice@example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(extract_domain("nodomain"), None);
        assert_eq!(
            extract_domain("user@sub.domain.com"),
            Some("sub.domain.com".to_string())
        );
    }
}
