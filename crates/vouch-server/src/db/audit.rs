// SPDX-License-Identifier: BUSL-1.1
//! Audit event store for write-once security events.
//!
//! [`AuditStore`] manages the `audit_events` table — a separate, unencrypted
//! table for security-relevant events. Email addresses are masked to
//! domain-only with an HMAC column for programmatic correlation.

use std::sync::Arc;

use anyhow::Result;
use sea_query::{Expr, Iden, Order, Query};

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
    /// Event type (e.g., "auth_login", "scim_operation").
    pub event_type: String,
    /// User ID (nullable for system events).
    pub user_id: Option<String>,
    /// Domain portion of the email (e.g., "example.com").
    pub email_domain: Option<String>,
    /// HMAC of the full email for correlation.
    pub email_hmac: Option<String>,
    /// JSON event data.
    pub data: String,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
}

/// Filter criteria for querying audit events.
#[derive(Debug, Default)]
pub struct AuditEventFilter {
    /// Filter by event type.
    pub event_type: Option<String>,
    /// Filter by user ID.
    pub user_id: Option<String>,
    /// Filter by email (computes HMAC for lookup).
    pub email: Option<String>,
    /// Filter events created after this timestamp.
    pub since: Option<String>,
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
        event_type: &str,
        user_id: Option<&str>,
        email: Option<&str>,
        data_json: &str,
    ) -> Result<String> {
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

            if let Some(ref et) = filter.event_type {
                q.and_where(Expr::col(AuditEvents::EventType).eq(et.as_str()));
            }
            if let Some(ref uid) = filter.user_id {
                q.and_where(Expr::col(AuditEvents::UserId).eq(uid.as_str()));
            }
            if let Some(ref email) = filter.email {
                let hmac = self.crypto.hmac_index(email);
                q.and_where(Expr::col(AuditEvents::EmailHmac).eq(hmac));
            }
            if let Some(ref since) = filter.since {
                q.and_where(Expr::col(AuditEvents::CreatedAt).gt(since.as_str()));
            }

            q.order_by(AuditEvents::CreatedAt, Order::Desc);

            if let Some(limit) = filter.limit {
                q.limit(limit);
            }

            q.to_owned()
        };
        let rows: Vec<RawAuditRow> = crate::db_fetch_all!(&self.pool, stmt, RawAuditRow)?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            events.push(raw_to_audit_event(row));
        }
        Ok(events)
    }

    /// Delete old events of a given type before a timestamp.
    ///
    /// Returns the number of events deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete fails.
    pub async fn delete_old_events(&self, event_type: &str, before: &str) -> Result<u64> {
        let stmt = Query::delete()
            .from_table(AuditEvents::Table)
            .and_where(Expr::col(AuditEvents::EventType).eq(event_type))
            .and_where(Expr::col(AuditEvents::CreatedAt).lt(before))
            .to_owned();

        let result = crate::db_execute!(&self.pool, stmt)?;
        Ok(result.rows_affected())
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
fn raw_to_audit_event(row: RawAuditRow) -> AuditEvent {
    AuditEvent {
        id: row.id,
        event_type: row.event_type,
        user_id: row.user_id,
        email_domain: row.email_domain,
        email_hmac: row.email_hmac,
        data: row.data,
        created_at: row.created_at,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::crypto::document_crypto::PlaintextDocumentCrypto;

    async fn test_audit() -> AuditStore {
        let pool = Pool::connect("sqlite::memory:").await.unwrap();

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
                "auth_login",
                Some("user-123"),
                Some("alice@example.com"),
                r#"{"success":true}"#,
            )
            .await
            .unwrap();
        assert!(!id.is_empty());

        let events = audit
            .query_events(&AuditEventFilter {
                event_type: Some("auth_login".to_string()),
                ..AuditEventFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "auth_login");
        assert_eq!(events[0].user_id.as_deref(), Some("user-123"));
        assert_eq!(events[0].email_domain.as_deref(), Some("example.com"));
    }

    #[tokio::test]
    async fn query_by_email_hmac() {
        let audit = test_audit().await;

        audit
            .insert_event("auth_login", Some("user-1"), Some("bob@test.com"), "{}")
            .await
            .unwrap();
        audit
            .insert_event("auth_login", Some("user-2"), Some("carol@test.com"), "{}")
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
            .insert_event("auth_login", None, None, "{}")
            .await
            .unwrap();

        // Delete events before far future should delete everything
        let deleted = audit
            .delete_old_events("auth_login", "2099-01-01T00:00:00Z")
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
            .insert_event("auth_login", Some("user-a"), None, "{}")
            .await
            .unwrap();
        audit
            .insert_event("auth_login", Some("user-b"), None, "{}")
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
                .insert_event("auth_login", None, None, "{}")
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
