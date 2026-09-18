// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Credential-related database operations (SSH revocation, enrollment,
//! token exchange, cloud integrations).

use super::document_type::{Document, DocumentType};
use super::documents::credential::{EnrollmentSessionDoc, SshIssuedCertDoc, SshRevokedCertDoc};
use super::documents::oauth::TokenExchangeDoc;
use super::documents::user::UserDoc;
use super::store::DocumentStore;
use anyhow::Result;
use jiff::Timestamp;

// ============================================================
// Token Exchange (RFC 8693)
// ============================================================

/// Parameters for a token exchange audit record (RFC 8693).
pub struct InsertTokenExchangeParams<'a> {
    pub subject_user_id: &'a str,
    pub subject_token_hash: &'a str,
    pub actor_user_id: Option<&'a str>,
    pub issued_token_hash: &'a str,
    pub requested_audience: Option<&'a str>,
    pub granted_scope: Option<&'a str>,
    pub expires_at: Timestamp,
}

/// Insert a token exchange audit record.
pub async fn insert_token_exchange(
    store: &DocumentStore,
    params: &InsertTokenExchangeParams<'_>,
) -> Result<String> {
    let doc = TokenExchangeDoc {
        subject_user_id: params.subject_user_id.to_string(),
        subject_token_hash: params.subject_token_hash.to_string(),
        actor_user_id: params.actor_user_id.map(String::from),
        issued_token_hash: params.issued_token_hash.to_string(),
        requested_audience: params.requested_audience.map(String::from),
        granted_scope: params.granted_scope.map(String::from),
        expires_at: params.expires_at,
    };
    let result = store.insert(&doc).await?;
    Ok(result.id)
}

/// Delete expired token exchange records.
pub async fn delete_old_token_exchanges(store: &DocumentStore) -> Result<u64> {
    store.delete_expired(TokenExchangeDoc::DOC_TYPE).await
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
///
/// The issued-cert insert and a version bump of the owning [`UserDoc`] run in
/// a single transaction so that a concurrent
/// [`revoke_all_ssh_certificates_for_user`] — which bumps the same owner row
/// inside its revocation transaction — collides with this write via optimistic
/// concurrency. Whichever commits first causes the other's
/// `compare_and_update` to lose the version race; `with_dsql_retry!` then
/// re-runs the loser against the fresh row.
///
/// On each (re-)attempt the issuer re-reads the user doc and rejects when
/// `active` is `false`: a deactivation that persisted `active = false` since
/// the caller's `load_active_user` gate makes the retried attempt refuse to
/// record the certificate, closing the window in which a certificate issued
/// concurrently with deactivation escaped revocation.
///
/// # Errors
///
/// Returns an error if the user doc is missing, the user is not `active`, or
/// the database write fails after retries.
pub async fn record_ssh_certificate_issuance(
    store: &DocumentStore,
    serial: u64,
    user_id: &str,
    user_email: &str,
    principals: &[String],
    expires_at: Timestamp,
) -> Result<String> {
    let user_id = user_id.to_string();
    let user_email = user_email.to_string();
    let principals = principals.to_vec();
    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await?;

        // The user doc is the OCC owner row shared with revocation. Reading
        // it in-transaction also re-validates `active` on every attempt: a
        // revocation whose `persist` step committed `active = false` since
        // the caller's gate makes this attempt reject, so a cert issued
        // concurrently with a deactivation is never left unrevoked.
        let user_doc = tx.get::<UserDoc>(&user_id).await?.ok_or_else(|| {
            anyhow::anyhow!("user {user_id} not found during SSH certificate issuance")
        })?;
        if !user_doc.data.active {
            anyhow::bail!(
                "user {user_id} is not active; refusing to record SSH certificate issuance"
            );
        }
        let version = user_doc.version;

        // Version-bump the owner row before inserting the issued-cert row.
        // This is the OCC collision point: a concurrent revocation that
        // already bumped the user doc makes this `compare_and_update` return
        // `Ok(false)`, which is surfaced as a `VersionConflict` so the macro
        // re-runs the whole block (re-reading `active`). Bumping first also
        // keeps this transaction's first write at the CAS, so a test seam
        // firing here cannot deadlock against a concurrent hookless writer.
        let ok = tx
            .compare_and_update::<UserDoc>(&user_id, version, &user_doc.data)
            .await?;
        if !ok {
            return Err(super::store::VersionConflict {
                id: user_id.clone(),
                expected: version,
            }
            .into());
        }

        let cert_doc = SshIssuedCertDoc {
            serial: serial.to_string(),
            user_id: user_id.clone(),
            user_email: user_email.clone(),
            principals: principals.clone(),
            expires_at,
        };
        let inserted = tx.insert(&cert_doc).await?;
        tx.commit().await?;
        Ok(inserted.id)
    })
}

/// Get all non-expired issued SSH certificates for a user.
#[expect(
    clippy::disallowed_methods,
    reason = "filters a listing, not a request accept/reject"
)]
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

/// Check if an SSH certificate is revoked.
pub async fn is_ssh_certificate_revoked(store: &DocumentStore, serial: &str) -> Result<bool> {
    let count = store.count::<SshRevokedCertDoc>("serial", serial).await?;
    Ok(count > 0)
}

/// Get all revoked SSH certificates (for KRL generation).
#[expect(
    clippy::disallowed_methods,
    reason = "filters a KRL listing, not a request accept/reject"
)]
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

/// Revoke all SSH certificates for a user by looking up issued certs and
/// inserting a revocation record for each real serial.
///
/// The issued-certs snapshot is read **inside** the revocation transaction,
/// and the transaction also version-bumps the owning [`UserDoc`]. That owner
/// row is the same row [`record_ssh_certificate_issuance`] bumps, so issuance
/// and revocation serialize through optimistic concurrency: whichever commits
/// first causes the other's `compare_and_update` to lose the version race, and
/// `with_dsql_retry!` re-runs the loser. On a retry the revoker re-reads the
/// snapshot, which now includes any serial a racing issuer committed before
/// the owner-row bump — closing the TOCTOU window where a certificate issued
/// between a stale (out-of-transaction) snapshot and the revocation commit was
/// left off the revocation list.
///
/// A missing user doc (e.g. a user hard-deleted before this call) skips the
/// owner-row bump: no concurrent issuance can be authenticating for a
/// hard-deleted user, so the snapshot alone is authoritative and the existing
/// issued certs are still revoked.
///
/// # Errors
///
/// Returns an error if the database read or write fails after retries.
#[expect(
    clippy::disallowed_methods,
    reason = "OCC retry re-reads the clock per attempt to stamp the revocation rows"
)]
pub(in crate::db) async fn revoke_all_ssh_certificates_for_user(
    store: &DocumentStore,
    user_id: &str,
    reason: Option<&str>,
    revoked_by: Option<&str>,
) -> Result<u64> {
    let user_id = user_id.to_string();
    let reason = reason.map(String::from);
    let revoked_by = revoked_by.map(String::from);
    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await?;

        // The user doc is the OCC owner row shared with issuance. Bumping
        // its version inside this transaction forces a concurrent
        // `record_ssh_certificate_issuance` that read an earlier version to
        // lose its `compare_and_update` and retry (re-reading `active`).
        let user_doc = tx.get::<UserDoc>(&user_id).await?;

        let now = Timestamp::now();
        // Read the issued-certs snapshot inside the transaction; a concurrent
        // issuance that commits before the owner-row bump is visible on the
        // retry's re-read rather than escaping through a stale snapshot taken
        // outside the transaction.
        let docs = tx.find_all::<SshIssuedCertDoc>("user_id", &user_id).await?;

        // Bump the owner row before inserting revocation rows so this
        // transaction's first write is the CAS — a test seam firing there
        // cannot deadlock against a concurrent hookless writer, and a racing
        // issuer that already bumped the row makes this CAS lose (retrying
        // against a fresh snapshot that includes its serial).
        if let Some(user_doc) = user_doc.as_ref() {
            let ok = tx
                .compare_and_update::<UserDoc>(&user_id, user_doc.version, &user_doc.data)
                .await?;
            if !ok {
                return Err(super::store::VersionConflict {
                    id: user_id.clone(),
                    expected: user_doc.version,
                }
                .into());
            }
        }

        let mut count: u64 = 0;
        for doc in &docs {
            // Skip already-expired certs — they cannot be used, so no
            // revocation row is needed. Matches `get_issued_ssh_certificates_for_user`.
            if doc.data.expires_at <= now {
                continue;
            }
            let revoked = SshRevokedCertDoc {
                serial: doc.data.serial.clone(),
                user_id: user_id.clone(),
                reason: reason.clone(),
                revoked_at: now,
                expires_at: doc.data.expires_at,
                revoked_by: revoked_by.clone(),
            };
            tx.insert(&revoked).await?;
            count = count.saturating_add(1);
        }

        tx.commit().await?;
        Ok(count)
    })
}

/// Delete expired SSH certificate revocations.
pub async fn delete_expired_ssh_revocations(store: &DocumentStore) -> Result<u64> {
    store.delete_expired(SshRevokedCertDoc::DOC_TYPE).await
}

/// Revoke every long-lived credential belonging to a user: their issued SSH
/// certificates and their stored GitHub refresh token.
///
/// This is the only way to reach either write. They are deliberately not
/// individually callable, because "revoke the certificates but not the token"
/// is never the intent, and revoking one while silently failing the other
/// reports a withdrawal of access that did not happen. Per
/// `references/ssh-certs-not-revocable.md` the KRL is the only server-side
/// lever for a certificate, so a dropped error leaves a working credential on
/// no revocation list.
///
/// Callers should prefer `services::auth::revoke_user_access`, which also
/// deletes sessions and invalidates the session cache.
///
/// `reason` and `revoked_by` are recorded on the revocation records.
///
/// # Errors
///
/// Returns an error if either write fails. Both are idempotent, so retrying
/// the whole operation converges.
pub async fn revoke_user_credentials(
    store: &DocumentStore,
    user_id: &str,
    reason: Option<&str>,
    revoked_by: Option<&str>,
) -> Result<()> {
    revoke_all_ssh_certificates_for_user(store, user_id, reason, revoked_by).await?;
    super::users::clear_user_github_refresh_token(store, user_id).await?;
    Ok(())
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
    use crate::db::upsert_user;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

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

    /// Create a file-backed SQLite test store with WAL journaling, kept alive
    /// for the test's duration by the returned [`tempfile::TempDir`].
    ///
    /// The TOCTOU race tests need a reader transaction and a concurrent writer
    /// (driven by the `compare_and_update_test_hook` seam) to both make
    /// progress at once. In-memory SQLite falls back to MEMORY journaling (WAL
    /// is silently ignored for in-memory databases), where a read
    /// transaction's SHARED lock blocks the concurrent hook writer's EXCLUSIVE
    /// commit — a deadlock instead of the OCC retry the test wants to force.
    /// A file-backed database honors WAL, whose readers do not block writers,
    /// so the hook's commit lands and the revoker's CAS loses, deterministically
    /// exercising the `with_dsql_retry!` re-read of the snapshot.
    async fn test_store_wal() -> (DocumentStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("vouch-ssh-occ.db");
        let opts = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(db_path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .auto_vacuum(sqlx::sqlite::SqliteAutoVacuum::Incremental)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .busy_timeout(std::time::Duration::from_secs(5))
            .pragma("analysis_limit", "400");
        let sqlite_pool = sqlx::SqlitePool::connect_with(opts)
            .await
            .expect("connect wal store");
        sqlx::migrate!("./migrations/sqlite")
            .run(&sqlite_pool)
            .await
            .expect("migrate");
        let pool = Pool::Sqlite(sqlite_pool);
        let crypto: Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
            Arc::new(PlaintextDocumentCrypto);
        (DocumentStore::new(pool, crypto), dir)
    }

    /// Helper: create an active test user and return its id. `UserDoc` is the
    /// OCC owner row shared by issuance and revocation, so every test that
    /// records or revokes a cert needs a real user doc.
    async fn create_user(store: &DocumentStore, email: &str) -> String {
        let (user_id, _created) = upsert_user(store, email, Some("Test User"))
            .await
            .expect("create test user");
        user_id
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
        let user_id = create_user(&store, "stores-correct@example.com").await;
        let serial: u64 = 9_876_543_210;
        let stored_serial = insert_issued(&store, &user_id, serial).await;

        assert_eq!(stored_serial, serial.to_string());

        // Verify the record is retrievable.
        let certs = get_issued_ssh_certificates_for_user(&store, &user_id)
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
        let user_id = create_user(&store, "numeric@example.com").await;
        let serial: u64 = 12_345;
        insert_issued(&store, &user_id, serial).await;

        let certs = get_issued_ssh_certificates_for_user(&store, &user_id)
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
        let user_id = create_user(&store, "max@example.com").await;
        let serial = u64::MAX;
        insert_issued(&store, &user_id, serial).await;

        let certs = get_issued_ssh_certificates_for_user(&store, &user_id)
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
        let user_id = create_user(&store, "issued-filters@example.com").await;

        // Insert one expired cert (in the past)
        let expired_at = Timestamp::now()
            .checked_sub(jiff::Span::new().hours(1))
            .expect("past timestamp");
        record_ssh_certificate_issuance(
            &store,
            1001,
            &user_id,
            "user@example.com",
            &["user".to_string()],
            expired_at,
        )
        .await
        .expect("record expired");

        // Insert one valid cert (in the future)
        insert_issued(&store, &user_id, 1002).await;

        let certs = get_issued_ssh_certificates_for_user(&store, &user_id)
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
        let user_id = create_user(&store, "multi@example.com").await;

        let serials = [111_u64, 222, 333];
        for &s in &serials {
            insert_issued(&store, &user_id, s).await;
        }

        let certs = get_issued_ssh_certificates_for_user(&store, &user_id)
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
        let user_id = create_user(&store, "revoke@example.com").await;

        let serial_a: u64 = 5_000_000;
        let serial_b: u64 = 9_999_999;
        insert_issued(&store, &user_id, serial_a).await;
        insert_issued(&store, &user_id, serial_b).await;

        let count = revoke_all_ssh_certificates_for_user(&store, &user_id, None, None)
            .await
            .expect("revoke all");

        assert_eq!(count, 2, "should have revoked exactly 2 certs");

        // Each revocation record must carry a real numeric serial.
        let revoked = get_revoked_ssh_certificates(&store)
            .await
            .expect("get revoked");

        let mut revoked_serials: Vec<u64> = revoked
            .iter()
            .filter(|r| r.user_id == user_id)
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
    async fn test_revoke_all_bumps_user_doc_version() {
        // The revoker must version-bump the owning `UserDoc` (the OCC owner
        // row shared with issuance) even when there are no issued certs to
        // revoke, so a concurrent `record_ssh_certificate_issuance` that read
        // an earlier version loses its CAS and retries against `active`.
        let store = test_store().await;
        let user_id = create_user(&store, "bump@example.com").await;

        let before = store
            .get::<UserDoc>(&user_id)
            .await
            .expect("read user before")
            .expect("user exists")
            .version;

        let count = revoke_all_ssh_certificates_for_user(&store, &user_id, None, None)
            .await
            .expect("revoke all");
        assert_eq!(count, 0, "no certs to revoke");

        let after = store
            .get::<UserDoc>(&user_id)
            .await
            .expect("read user after")
            .expect("user still exists")
            .version;

        assert!(
            after > before,
            "revocation must bump the user doc version (the OCC owner row) so a concurrent issuance collides"
        );
    }

    #[tokio::test]
    async fn test_revoke_all_returns_zero_when_no_issued_certs() {
        let store = test_store().await;
        let user_id = create_user(&store, "no-certs@example.com").await;

        let count = revoke_all_ssh_certificates_for_user(&store, &user_id, None, None)
            .await
            .expect("revoke all");

        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_revoke_all_does_not_revoke_expired_certs() {
        // Expired certs are filtered by the snapshot read and must not
        // generate revocation records (they have already expired).
        let store = test_store().await;
        let user_id = create_user(&store, "exp-revoke@example.com").await;

        let expired_at = Timestamp::now()
            .checked_sub(jiff::Span::new().hours(1))
            .expect("past");
        record_ssh_certificate_issuance(
            &store,
            7001,
            &user_id,
            "user@example.com",
            &["user".to_string()],
            expired_at,
        )
        .await
        .expect("record expired");

        let count = revoke_all_ssh_certificates_for_user(&store, &user_id, None, None)
            .await
            .expect("revoke all");

        assert_eq!(count, 0, "expired certs should not generate revocations");
    }

    #[tokio::test]
    async fn test_revoke_all_propagates_reason_and_revoked_by() {
        let store = test_store().await;
        let user_id = create_user(&store, "meta@example.com").await;
        insert_issued(&store, &user_id, 42).await;

        revoke_all_ssh_certificates_for_user(
            &store,
            &user_id,
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
            .find(|r| r.user_id == user_id)
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
        let user_id = create_user(&store, "krl@example.com").await;
        let serial: u64 = 1_234_567_890;
        insert_issued(&store, &user_id, serial).await;

        revoke_all_ssh_certificates_for_user(&store, &user_id, None, None)
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
        let user_id = create_user(&store, "cleanup@example.com").await;

        // Insert expired cert
        let expired_at = Timestamp::now()
            .checked_sub(jiff::Span::new().hours(1))
            .expect("past");
        record_ssh_certificate_issuance(
            &store,
            8001,
            &user_id,
            "user@example.com",
            &["user".to_string()],
            expired_at,
        )
        .await
        .expect("record expired");

        // Insert valid cert
        insert_issued(&store, &user_id, 8002).await;

        let deleted = delete_expired_ssh_issued_certs(&store)
            .await
            .expect("delete expired");

        assert_eq!(deleted, 1, "only the expired cert record should be removed");

        // Valid cert is still there
        let remaining = get_issued_ssh_certificates_for_user(&store, &user_id)
            .await
            .expect("get issued");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].serial, "8002");
    }

    // ────────────────────────────────────────────────────────────
    // TOCTOU race: issuance concurrent with revocation (the bug)
    // ────────────────────────────────────────────────────────────

    /// Regression for the TOCTOU race this change fixes.
    ///
    /// `revoke_all_ssh_certificates_for_user` used to read the issued-certs
    /// snapshot with an autocommit `find_all` OUTSIDE the revocation
    /// transaction, then insert revocation rows inside a separate transaction
    /// for only that stale list. An SSH certificate issued concurrently —
    /// whose `record_ssh_certificate_issuance` insert committed after the
    /// snapshot — was never written to the revocation table, so it stayed
    /// valid for the full cert lifetime and was absent from both the KRL and
    /// the per-serial revocation endpoint.
    ///
    /// The fix moves the snapshot inside the transaction and version-bumps the
    /// owning `UserDoc` so issuance and revocation collide via OCC. This test
    /// deterministically reproduces the race with the
    /// `compare_and_update_test_hook` seam: right when the revoker's owner-row
    /// CAS runs, a hookless writer commits a new issued cert and bumps the
    /// user doc — exactly what a concurrent `record_ssh_certificate_issuance`
    /// that won the version race looks like to the revoker. The revoker's CAS
    /// must lose and `with_dsql_retry!` must re-run it against a fresh
    /// snapshot that now includes the racing serial.
    #[tokio::test]
    async fn test_revoke_all_re_reads_snapshot_when_issuance_wins_occ_race() {
        let (mut store, _dir) = test_store_wal().await;
        let user_id = create_user(&store, "occ-race@example.com").await;
        // Pre-existing cert, present in the revoker's first snapshot.
        insert_issued(&store, &user_id, 100).await;

        // Hookless writer the hook drives to simulate the winning issuer.
        let writer = store.clone();
        let calls = Arc::new(AtomicU32::new(0));
        let uid_for_hook = user_id.clone();
        let calls_hook = Arc::clone(&calls);
        store.set_compare_and_update_test_hook(Arc::new(move |doc_id: &str| {
            let writer = writer.clone();
            let uid = uid_for_hook.clone();
            let calls = Arc::clone(&calls_hook);
            let doc_id = doc_id.to_string();
            Box::pin(async move {
                // Only act on the user-doc CAS — `get` filters by `doc_type`,
                // so defensively ignore any other compare_and_update.
                if doc_id != uid {
                    return;
                }
                // Count every CAS attempt so the test can tell a single
                // successful pass from a retry. Do the concurrent write only
                // on the first attempt, so the retry's CAS succeeds.
                let n = calls.fetch_add(1, Ordering::SeqCst);
                if n != 0 {
                    return;
                }
                // Simulate a concurrent `record_ssh_certificate_issuance`
                // committing after the revoker's snapshot read: insert the
                // racing serial and bump the owner row. `store.insert` and
                // `store.update` do not fire the compare_and_update hook, so
                // there is no recursion.
                let expires_at = Timestamp::now()
                    .checked_add(jiff::Span::new().hours(8))
                    .expect("future");
                let cert = SshIssuedCertDoc {
                    serial: "200".to_string(),
                    user_id: uid.clone(),
                    user_email: "occ-race@example.com".to_string(),
                    principals: vec!["user".to_string()],
                    expires_at,
                };
                writer
                    .insert::<SshIssuedCertDoc>(&cert)
                    .await
                    .expect("hook insert racing cert");
                let Some(user) = writer.get::<UserDoc>(&uid).await.expect("hook read user") else {
                    return;
                };
                writer
                    .update::<UserDoc>(&uid, &user.data)
                    .await
                    .expect("hook bump user doc");
            })
        }));

        let count = revoke_all_ssh_certificates_for_user(&store, &user_id, None, None)
            .await
            .expect("revoke all");

        // Both the pre-existing cert (100) and the racing cert (200) must be
        // revoked: the revoker re-read the snapshot after losing the OCC race.
        assert_eq!(
            count, 2,
            "both the pre-existing and racing serials must be revoked"
        );
        assert!(
            is_ssh_certificate_revoked(&store, "100")
                .await
                .expect("check 100"),
            "pre-existing serial must be revoked"
        );
        assert!(
            is_ssh_certificate_revoked(&store, "200")
                .await
                .expect("check 200"),
            "racing serial inserted after the snapshot must be revoked after the OCC retry re-reads the snapshot"
        );
        let revoked = get_revoked_ssh_certificates(&store)
            .await
            .expect("get revoked");
        assert!(
            revoked.iter().any(|r| r.serial == "100"),
            "KRL path must include the pre-existing serial"
        );
        assert!(
            revoked.iter().any(|r| r.serial == "200"),
            "KRL path must include the racing serial"
        );
        // The revoker's CAS lost once (the hook bumped the owner row) and
        // `with_dsql_retry!` re-ran it: two CAS attempts, the second against a
        // fresh snapshot that includes the racing serial.
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the revoker must retry the CAS after losing the owner-row race"
        );
    }

    /// Regression for the issuer side of the same TOCTOU fix.
    ///
    /// `record_ssh_certificate_issuance` now bumps the owning `UserDoc` in
    /// the same transaction as the issued-cert insert, so a concurrent
    /// `revoke_all_ssh_certificates_for_user` that wins the owner-row CAS
    /// forces the issuer to retry. On retry the issuer re-reads the user doc
    /// and must reject when `active` has since been set to `false` (the
    /// deactivation's persist step), so a certificate issued concurrently with
    /// a deactivation is never left unrevoked.
    #[tokio::test]
    async fn test_record_issuance_rejects_when_user_deactivated_on_occ_retry() {
        let (mut store, _dir) = test_store_wal().await;
        let user_id = create_user(&store, "deactivate@example.com").await;

        let writer = store.clone();
        let calls = Arc::new(AtomicU32::new(0));
        let uid_for_hook = user_id.clone();
        let calls_hook = Arc::clone(&calls);
        store.set_compare_and_update_test_hook(Arc::new(move |doc_id: &str| {
            let writer = writer.clone();
            let uid = uid_for_hook.clone();
            let calls = Arc::clone(&calls_hook);
            let doc_id = doc_id.to_string();
            Box::pin(async move {
                if doc_id != uid {
                    return;
                }
                // Count CAS attempts; only the first deactivates the user.
                let n = calls.fetch_add(1, Ordering::SeqCst);
                if n != 0 {
                    return;
                }
                // Simulate the revoker+persist winning the race: bump the
                // owner row AND deactivate the user, so the issuer's retried
                // read sees active=false and rejects.
                let Some(mut user) = writer.get::<UserDoc>(&uid).await.expect("hook read user")
                else {
                    return;
                };
                user.data.active = false;
                writer
                    .update::<UserDoc>(&uid, &user.data)
                    .await
                    .expect("hook deactivate user");
            })
        }));

        let expires_at = Timestamp::now()
            .checked_add(jiff::Span::new().hours(8))
            .expect("future");
        let result = record_ssh_certificate_issuance(
            &store,
            555,
            &user_id,
            "deactivate@example.com",
            &["user".to_string()],
            expires_at,
        )
        .await;

        assert!(
            result.is_err(),
            "issuance must reject when the user is concurrently deactivated"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the issuer's owner-row CAS must be attempted (and lose) before the retry rejects"
        );
        let certs = get_issued_ssh_certificates_for_user(&store, &user_id)
            .await
            .expect("get issued");
        assert!(
            certs.is_empty(),
            "no cert should be recorded for a user deactivated during issuance"
        );
    }

    /// Control for the OCC race test: when both certs are issued before the
    /// revoker takes its snapshot, both are revoked in a single pass with no
    /// OCC retry. Confirms the race test's assertion is about the snapshot
    /// boundary (the racing serial landing after the snapshot), not some
    /// other mechanism.
    #[tokio::test]
    async fn test_revoke_all_catches_certs_issued_before_snapshot() {
        let mut store = test_store().await;
        let user_id = create_user(&store, "before-snapshot@example.com").await;
        insert_issued(&store, &user_id, 100).await;
        insert_issued(&store, &user_id, 200).await;

        // Count owner-row CAS attempts: a single successful pass is exactly
        // one attempt; a retry (as in the race test) would be two.
        let calls = Arc::new(AtomicU32::new(0));
        let calls_hook = Arc::clone(&calls);
        store.set_compare_and_update_test_hook(Arc::new(move |_doc_id: &str| {
            let calls = Arc::clone(&calls_hook);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
            })
        }));

        let count = revoke_all_ssh_certificates_for_user(&store, &user_id, None, None)
            .await
            .expect("revoke all");

        assert_eq!(count, 2);
        assert!(
            is_ssh_certificate_revoked(&store, "100")
                .await
                .expect("check 100"),
        );
        assert!(
            is_ssh_certificate_revoked(&store, "200")
                .await
                .expect("check 200"),
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "no OCC retry should occur when all certs predate the snapshot"
        );
    }
}
