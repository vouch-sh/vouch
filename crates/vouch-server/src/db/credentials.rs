// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Credential-related database operations (SSH revocation, enrollment,
//! token exchange, cloud integrations).

use super::document_type::{Document, DocumentType};
use super::documents::credential::{EnrollmentSessionDoc, SshIssuedCertDoc, SshRevokedCertDoc};
use super::documents::oauth::{DelegationPolicyDoc, TokenExchangeDoc};
use super::store::DocumentStore;
use anyhow::Result;
use jiff::Timestamp;

// ============================================================
// Token Exchange (RFC 8693)
// ============================================================

/// Insert a token exchange audit record.
#[expect(
    clippy::too_many_arguments,
    reason = "token-exchange audit row requires all RFC 8693 fields"
)]
pub async fn insert_token_exchange(
    store: &DocumentStore,
    subject_user_id: &str,
    subject_token_hash: &str,
    actor_user_id: Option<&str>,
    issued_token_hash: &str,
    requested_audience: Option<&str>,
    granted_scope: Option<&str>,
    expires_at: Timestamp,
) -> Result<String> {
    let doc = TokenExchangeDoc {
        subject_user_id: subject_user_id.to_string(),
        subject_token_hash: subject_token_hash.to_string(),
        actor_user_id: actor_user_id.map(String::from),
        issued_token_hash: issued_token_hash.to_string(),
        requested_audience: requested_audience.map(String::from),
        granted_scope: granted_scope.map(String::from),
        expires_at,
    };
    let result = store.insert(&doc).await?;
    Ok(result.id)
}

/// Delete expired token exchange records.
pub async fn delete_old_token_exchanges(store: &DocumentStore) -> Result<u64> {
    store.delete_expired(TokenExchangeDoc::DOC_TYPE).await
}

/// Token exchange audit record.
#[derive(Debug)]
pub struct TokenExchangeRecord {
    pub id: String,
    pub subject_user_id: String,
    pub subject_token_hash: String,
    pub actor_user_id: Option<String>,
    pub issued_token_hash: String,
    pub requested_audience: Option<String>,
    pub granted_scope: Option<String>,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
}

impl From<Document<TokenExchangeDoc>> for TokenExchangeRecord {
    fn from(doc: Document<TokenExchangeDoc>) -> Self {
        Self {
            id: doc.id,
            subject_user_id: doc.data.subject_user_id,
            subject_token_hash: doc.data.subject_token_hash,
            actor_user_id: doc.data.actor_user_id,
            issued_token_hash: doc.data.issued_token_hash,
            requested_audience: doc.data.requested_audience,
            granted_scope: doc.data.granted_scope,
            created_at: doc.created_at,
            expires_at: doc.data.expires_at,
        }
    }
}

/// Get token exchange records for a user.
pub async fn get_token_exchanges_for_user(
    store: &DocumentStore,
    user_id: &str,
    _limit: i64,
) -> Result<Vec<TokenExchangeRecord>> {
    let docs = store
        .find_all::<TokenExchangeDoc>("subject_user_id", user_id)
        .await?;
    Ok(docs.into_iter().map(TokenExchangeRecord::from).collect())
}

// ============================================================
// Delegation Policies
// ============================================================

/// Delegation policy record.
#[derive(Debug)]
pub struct DelegationPolicy {
    pub id: String,
    pub name: String,
    pub grantor_pattern: String,
    pub grantee_pattern: String,
    pub allowed_scopes: Option<String>,
    pub max_ttl_seconds: Option<i32>,
    pub enabled: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl From<Document<DelegationPolicyDoc>> for DelegationPolicy {
    fn from(doc: Document<DelegationPolicyDoc>) -> Self {
        Self {
            id: doc.id,
            name: doc.data.name,
            grantor_pattern: doc.data.grantor_pattern,
            grantee_pattern: doc.data.grantee_pattern,
            allowed_scopes: doc.data.allowed_scopes,
            max_ttl_seconds: doc.data.max_ttl_seconds,
            enabled: doc.data.enabled,
            created_at: doc.created_at,
            updated_at: doc.updated_at,
        }
    }
}

/// Check if a delegation is allowed by any policy.
pub async fn check_delegation_policy(
    store: &DocumentStore,
    grantor_email: &str,
    grantee_audience: Option<&str>,
) -> Result<Option<DelegationPolicy>> {
    let docs = store
        .find_all::<DelegationPolicyDoc>("enabled", "true")
        .await?;

    for doc in docs {
        let policy = DelegationPolicy::from(doc);

        if !pattern_matches(&policy.grantor_pattern, grantor_email) {
            continue;
        }

        if let Some(audience) = grantee_audience
            && !pattern_matches(&policy.grantee_pattern, audience)
        {
            continue;
        }

        return Ok(Some(policy));
    }

    Ok(None)
}

/// Check if a pattern matches a value.
fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if let Some(domain) = pattern.strip_prefix("*@") {
        if let Some(email_domain) = value.rsplit('@').next() {
            return email_domain.eq_ignore_ascii_case(domain);
        }
        return false;
    }

    pattern.eq_ignore_ascii_case(value)
}

/// Get all delegation policies.
pub async fn get_delegation_policies(store: &DocumentStore) -> Result<Vec<DelegationPolicy>> {
    let docs = store.list_all::<DelegationPolicyDoc>().await?;
    Ok(docs.into_iter().map(DelegationPolicy::from).collect())
}

/// Update a delegation policy's enabled status.
pub async fn set_delegation_policy_enabled(
    store: &DocumentStore,
    id: &str,
    enabled: bool,
) -> Result<bool> {
    if let Some(doc) = store.get::<DelegationPolicyDoc>(id).await? {
        let mut data = doc.data;
        data.enabled = enabled;
        store.update(id, &data).await?;
        return Ok(true);
    }
    Ok(false)
}

/// Delete a delegation policy.
pub async fn delete_delegation_policy(store: &DocumentStore, id: &str) -> Result<bool> {
    store.delete(id).await?;
    Ok(true)
}

// ============================================================
// Enrollment Sessions
// ============================================================

/// Enrollment session record (for key management during enrollment).
#[derive(Debug)]
pub struct EnrollmentSession {
    pub id: String,
    pub user_id: String,
    pub user_email: String,
    pub session_token_hash: String,
    pub device_auth_id: Option<String>,
    pub expires_at: Timestamp,
    pub created_at: Timestamp,
    pub last_used_at: Option<Timestamp>,
}

impl From<Document<EnrollmentSessionDoc>> for EnrollmentSession {
    fn from(doc: Document<EnrollmentSessionDoc>) -> Self {
        Self {
            id: doc.id,
            user_id: doc.data.user_id,
            user_email: doc.data.user_email,
            session_token_hash: doc.data.session_token_hash,
            device_auth_id: doc.data.device_auth_id,
            expires_at: doc.data.expires_at,
            created_at: doc.created_at,
            last_used_at: doc.last_used_at,
        }
    }
}

/// Create a new enrollment session.
pub async fn create_enrollment_session(
    store: &DocumentStore,
    user_id: &str,
    user_email: &str,
    session_token_hash: &str,
    device_auth_id: Option<&str>,
    expires_at: Timestamp,
) -> Result<String> {
    let doc = EnrollmentSessionDoc {
        user_id: user_id.to_string(),
        user_email: user_email.to_string(),
        session_token_hash: session_token_hash.to_string(),
        device_auth_id: device_auth_id.map(String::from),
        expires_at,
    };
    let result = store.insert(&doc).await?;
    Ok(result.id)
}

/// Get an enrollment session by token hash.
pub async fn get_enrollment_session_by_token_hash(
    store: &DocumentStore,
    token_hash: &str,
) -> Result<Option<EnrollmentSession>> {
    let doc = store
        .find_one::<EnrollmentSessionDoc>("session_token_hash", token_hash)
        .await?;
    Ok(doc.map(EnrollmentSession::from))
}

/// Delete expired enrollment sessions.
pub async fn delete_expired_enrollment_sessions(store: &DocumentStore) -> Result<u64> {
    store.delete_expired(EnrollmentSessionDoc::DOC_TYPE).await
}

// ============================================================
// SSH Issued Certificate Tracking
// ============================================================

/// Record of an issued SSH certificate.
#[derive(Debug)]
pub struct IssuedSshCertificate {
    pub id: String,
    pub serial: String,
    pub user_id: String,
    pub user_email: String,
    pub principals: Vec<String>,
    pub expires_at: Timestamp,
}

impl From<Document<SshIssuedCertDoc>> for IssuedSshCertificate {
    fn from(doc: Document<SshIssuedCertDoc>) -> Self {
        Self {
            id: doc.id,
            serial: doc.data.serial,
            user_id: doc.data.user_id,
            user_email: doc.data.user_email,
            principals: doc.data.principals,
            expires_at: doc.data.expires_at,
        }
    }
}

/// Record an SSH certificate issuance for revocation tracking.
pub async fn record_ssh_certificate_issuance(
    store: &DocumentStore,
    serial: u64,
    user_id: &str,
    user_email: &str,
    principals: &[String],
    expires_at: Timestamp,
) -> Result<String> {
    let doc = SshIssuedCertDoc {
        serial: serial.to_string(),
        user_id: user_id.to_string(),
        user_email: user_email.to_string(),
        principals: principals.to_vec(),
        expires_at,
    };
    let result = store.insert(&doc).await?;
    Ok(result.id)
}

/// Get all non-expired issued SSH certificates for a user.
pub async fn get_issued_ssh_certificates_for_user(
    store: &DocumentStore,
    user_id: &str,
) -> Result<Vec<IssuedSshCertificate>> {
    let docs = store
        .find_all::<SshIssuedCertDoc>("user_id", user_id)
        .await?;
    let now = Timestamp::now();
    Ok(docs
        .into_iter()
        .filter(|d| d.data.expires_at > now)
        .map(IssuedSshCertificate::from)
        .collect())
}

/// Delete expired SSH issued certificate records.
pub async fn delete_expired_ssh_issued_certs(store: &DocumentStore) -> Result<u64> {
    store.delete_expired(SshIssuedCertDoc::DOC_TYPE).await
}

// ============================================================
// SSH Certificate Revocation
// ============================================================

/// Revoked SSH certificate record.
#[derive(Debug)]
pub struct RevokedSshCertificate {
    pub id: String,
    pub serial: String,
    pub user_id: String,
    pub reason: Option<String>,
    pub revoked_at: Timestamp,
    pub expires_at: Timestamp,
    pub revoked_by: Option<String>,
}

impl From<Document<SshRevokedCertDoc>> for RevokedSshCertificate {
    fn from(doc: Document<SshRevokedCertDoc>) -> Self {
        Self {
            id: doc.id,
            serial: doc.data.serial,
            user_id: doc.data.user_id,
            reason: doc.data.reason,
            revoked_at: doc.data.revoked_at,
            expires_at: doc.data.expires_at,
            revoked_by: doc.data.revoked_by,
        }
    }
}

/// Revoke an SSH certificate.
pub async fn revoke_ssh_certificate(
    store: &DocumentStore,
    serial: &str,
    user_id: &str,
    expires_at: Timestamp,
    reason: Option<&str>,
    revoked_by: Option<&str>,
) -> Result<String> {
    let now = Timestamp::now();

    let doc = SshRevokedCertDoc {
        serial: serial.to_string(),
        user_id: user_id.to_string(),
        reason: reason.map(String::from),
        revoked_at: now,
        expires_at,
        revoked_by: revoked_by.map(String::from),
    };
    let result = store.insert(&doc).await?;
    Ok(result.id)
}

/// Check if an SSH certificate is revoked.
pub async fn is_ssh_certificate_revoked(store: &DocumentStore, serial: &str) -> Result<bool> {
    let count = store.count::<SshRevokedCertDoc>("serial", serial).await?;
    Ok(count > 0)
}

/// Get all revoked SSH certificates (for KRL generation).
pub async fn get_revoked_ssh_certificates(
    store: &DocumentStore,
) -> Result<Vec<RevokedSshCertificate>> {
    let docs = store.list_all::<SshRevokedCertDoc>().await?;
    let now = Timestamp::now();
    Ok(docs
        .into_iter()
        .filter(|d| d.data.expires_at > now)
        .map(RevokedSshCertificate::from)
        .collect())
}

/// Revoke all SSH certificates for a user by looking up issued certs
/// and inserting a revocation record for each real serial.
pub async fn revoke_all_ssh_certificates_for_user(
    store: &DocumentStore,
    user_id: &str,
    reason: Option<&str>,
    revoked_by: Option<&str>,
) -> Result<u64> {
    let issued = get_issued_ssh_certificates_for_user(store, user_id).await?;
    if issued.is_empty() {
        return Ok(0);
    }

    let now = Timestamp::now();
    let mut tx = store.begin().await?;
    let mut count: u64 = 0;
    for cert in &issued {
        let doc = SshRevokedCertDoc {
            serial: cert.serial.clone(),
            user_id: user_id.to_string(),
            reason: reason.map(String::from),
            revoked_at: now,
            expires_at: cert.expires_at,
            revoked_by: revoked_by.map(String::from),
        };
        tx.insert(&doc).await?;
        count = count.saturating_add(1);
    }
    tx.commit().await?;
    Ok(count)
}

/// Delete expired SSH certificate revocations.
pub async fn delete_expired_ssh_revocations(store: &DocumentStore) -> Result<u64> {
    store.delete_expired(SshRevokedCertDoc::DOC_TYPE).await
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::crypto::document_crypto::PlaintextDocumentCrypto;
    use crate::db::pool::Pool;
    use crate::db::store::DocumentStore;
    use std::sync::Arc;

    /// Create an in-memory test store with SQLite migrations applied.
    async fn test_store() -> DocumentStore {
        let pool = Pool::connect("sqlite::memory:", &crate::db::pool::PoolConfig::default())
            .await
            .expect("connect");
        match &pool {
            Pool::Sqlite(p) => sqlx::migrate!("./migrations/sqlite")
                .run(p)
                .await
                .expect("migrate"),
            Pool::Postgres(_) => panic!("unexpected pool type in unit tests"),
        }
        let crypto: Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
            Arc::new(PlaintextDocumentCrypto);
        DocumentStore::new(pool, crypto)
    }

    /// Helper: insert an issued SSH certificate and return its serial as a string.
    async fn insert_issued(store: &DocumentStore, user_id: &str, serial: u64) -> String {
        let expires_at = Timestamp::now()
            .checked_add(jiff::Span::new().hours(8))
            .expect("future timestamp");
        record_ssh_certificate_issuance(
            store,
            serial,
            user_id,
            "user@example.com",
            &["user".to_string()],
            expires_at,
        )
        .await
        .expect("record issuance");
        serial.to_string()
    }

    // ────────────────────────────────────────────────────────────
    // record_ssh_certificate_issuance
    // ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_record_ssh_certificate_issuance_stores_correct_serial() {
        let store = test_store().await;
        let serial: u64 = 9_876_543_210;
        let stored_serial = insert_issued(&store, "user-1", serial).await;

        assert_eq!(stored_serial, serial.to_string());

        // Verify the record is retrievable.
        let certs = get_issued_ssh_certificates_for_user(&store, "user-1")
            .await
            .expect("get issued");
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].serial, serial.to_string());
    }

    #[tokio::test]
    async fn test_record_ssh_certificate_issuance_serial_is_numeric_string() {
        // The core invariant: serials must be stored as decimal u64 strings,
        // never as synthetic "user:{id}" values or any non-numeric form.
        let store = test_store().await;
        let serial: u64 = 12_345;
        insert_issued(&store, "user-numeric", serial).await;

        let certs = get_issued_ssh_certificates_for_user(&store, "user-numeric")
            .await
            .expect("get issued");

        let stored = &certs[0].serial;
        assert!(
            stored.parse::<u64>().is_ok(),
            "stored serial '{stored}' must parse as u64"
        );
        assert_eq!(stored, "12345");
    }

    #[tokio::test]
    async fn test_record_ssh_certificate_issuance_max_u64() {
        let store = test_store().await;
        let serial = u64::MAX;
        insert_issued(&store, "user-max", serial).await;

        let certs = get_issued_ssh_certificates_for_user(&store, "user-max")
            .await
            .expect("get issued");
        assert_eq!(certs[0].serial, u64::MAX.to_string());
    }

    // ────────────────────────────────────────────────────────────
    // get_issued_ssh_certificates_for_user
    // ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_issued_ssh_certificates_filters_expired() {
        let store = test_store().await;

        // Insert one expired cert (in the past)
        let expired_at = Timestamp::now()
            .checked_sub(jiff::Span::new().hours(1))
            .expect("past timestamp");
        record_ssh_certificate_issuance(
            &store,
            1001,
            "user-exp",
            "user@example.com",
            &["user".to_string()],
            expired_at,
        )
        .await
        .expect("record expired");

        // Insert one valid cert (in the future)
        insert_issued(&store, "user-exp", 1002).await;

        let certs = get_issued_ssh_certificates_for_user(&store, "user-exp")
            .await
            .expect("get issued");

        // Only the valid cert should be returned.
        assert_eq!(certs.len(), 1, "only non-expired cert should be returned");
        assert_eq!(certs[0].serial, "1002");
    }

    #[tokio::test]
    async fn test_get_issued_ssh_certificates_returns_empty_for_unknown_user() {
        let store = test_store().await;

        let certs = get_issued_ssh_certificates_for_user(&store, "nonexistent-user")
            .await
            .expect("get issued");

        assert!(certs.is_empty());
    }

    #[tokio::test]
    async fn test_get_issued_ssh_certificates_multiple_certs() {
        let store = test_store().await;

        let serials = [111_u64, 222, 333];
        for &s in &serials {
            insert_issued(&store, "user-multi", s).await;
        }

        let certs = get_issued_ssh_certificates_for_user(&store, "user-multi")
            .await
            .expect("get issued");

        assert_eq!(certs.len(), 3);
        let mut returned: Vec<u64> = certs
            .iter()
            .map(|c| c.serial.parse::<u64>().expect("numeric serial"))
            .collect();
        returned.sort_unstable();
        assert_eq!(returned, vec![111, 222, 333]);
    }

    // ────────────────────────────────────────────────────────────
    // revoke_all_ssh_certificates_for_user — core security property
    // ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_revoke_all_creates_revocations_with_real_numeric_serials() {
        // SECURITY: This test verifies the fix for GH#249.
        // Prior to the fix, revoke_all_ssh_certificates_for_user inserted a
        // synthetic "user:{user_id}" serial that could never match the real u64
        // serial stored in the SSH certificate.  The fix must look up issued
        // certificate records and revoke each real serial.
        let store = test_store().await;

        let serial_a: u64 = 5_000_000;
        let serial_b: u64 = 9_999_999;
        insert_issued(&store, "user-revoke", serial_a).await;
        insert_issued(&store, "user-revoke", serial_b).await;

        let count = revoke_all_ssh_certificates_for_user(&store, "user-revoke", None, None)
            .await
            .expect("revoke all");

        assert_eq!(count, 2, "should have revoked exactly 2 certs");

        // Each revocation record must carry a real numeric serial.
        let revoked = get_revoked_ssh_certificates(&store)
            .await
            .expect("get revoked");

        let mut revoked_serials: Vec<u64> = revoked
            .iter()
            .filter(|r| r.user_id == "user-revoke")
            .map(|r| r.serial.parse::<u64>().expect("serial must be numeric u64"))
            .collect();
        revoked_serials.sort_unstable();

        assert_eq!(
            revoked_serials,
            vec![serial_a, serial_b],
            "revoked serials must exactly match the issued serials"
        );
    }

    #[tokio::test]
    async fn test_revoke_all_returns_zero_when_no_issued_certs() {
        let store = test_store().await;

        let count = revoke_all_ssh_certificates_for_user(&store, "user-none", None, None)
            .await
            .expect("revoke all");

        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_revoke_all_does_not_revoke_expired_certs() {
        // Expired certs are filtered by get_issued_ssh_certificates_for_user
        // and must not generate revocation records (they have already expired).
        let store = test_store().await;

        let expired_at = Timestamp::now()
            .checked_sub(jiff::Span::new().hours(1))
            .expect("past");
        record_ssh_certificate_issuance(
            &store,
            7001,
            "user-exp-revoke",
            "user@example.com",
            &["user".to_string()],
            expired_at,
        )
        .await
        .expect("record expired");

        let count = revoke_all_ssh_certificates_for_user(&store, "user-exp-revoke", None, None)
            .await
            .expect("revoke all");

        assert_eq!(count, 0, "expired certs should not generate revocations");
    }

    #[tokio::test]
    async fn test_revoke_all_propagates_reason_and_revoked_by() {
        let store = test_store().await;
        insert_issued(&store, "user-meta", 42).await;

        revoke_all_ssh_certificates_for_user(
            &store,
            "user-meta",
            Some("scim_deprovisioning"),
            Some("admin@example.com"),
        )
        .await
        .expect("revoke all");

        let revoked = get_revoked_ssh_certificates(&store)
            .await
            .expect("get revoked");

        let record = revoked
            .iter()
            .find(|r| r.user_id == "user-meta")
            .expect("revocation record must exist");

        assert_eq!(record.reason.as_deref(), Some("scim_deprovisioning"));
        assert_eq!(record.revoked_by.as_deref(), Some("admin@example.com"));
    }

    // ────────────────────────────────────────────────────────────
    // Revoked serial appears in KRL (is_ssh_certificate_revoked)
    // ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_revoked_serial_is_detected_by_krl_check() {
        // After revoke_all, each real serial must be visible through
        // is_ssh_certificate_revoked (the check used by SSH servers).
        let store = test_store().await;
        let serial: u64 = 1_234_567_890;
        insert_issued(&store, "user-krl", serial).await;

        revoke_all_ssh_certificates_for_user(&store, "user-krl", None, None)
            .await
            .expect("revoke all");

        let is_revoked = is_ssh_certificate_revoked(&store, &serial.to_string())
            .await
            .expect("check revocation");

        assert!(
            is_revoked,
            "serial {serial} must be reported as revoked after revoke_all"
        );
    }

    #[tokio::test]
    async fn test_non_revoked_serial_is_not_in_krl() {
        let store = test_store().await;

        let is_revoked = is_ssh_certificate_revoked(&store, "99999999")
            .await
            .expect("check revocation");

        assert!(!is_revoked);
    }

    // ────────────────────────────────────────────────────────────
    // delete_expired_ssh_issued_certs
    // ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_delete_expired_ssh_issued_certs_removes_expired() {
        let store = test_store().await;

        // Insert expired cert
        let expired_at = Timestamp::now()
            .checked_sub(jiff::Span::new().hours(1))
            .expect("past");
        record_ssh_certificate_issuance(
            &store,
            8001,
            "user-cleanup",
            "user@example.com",
            &["user".to_string()],
            expired_at,
        )
        .await
        .expect("record expired");

        // Insert valid cert
        insert_issued(&store, "user-cleanup", 8002).await;

        let deleted = delete_expired_ssh_issued_certs(&store)
            .await
            .expect("delete expired");

        assert_eq!(deleted, 1, "only the expired cert record should be removed");

        // Valid cert is still there
        let remaining = get_issued_ssh_certificates_for_user(&store, "user-cleanup")
            .await
            .expect("get issued");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].serial, "8002");
    }
}
