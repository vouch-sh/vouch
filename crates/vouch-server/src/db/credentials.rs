// SPDX-License-Identifier: BUSL-1.1
//! Credential-related database operations (SSH revocation, enrollment,
//! token exchange, cloud integrations).

use super::document_type::{Document, DocumentType};
use super::documents::credential::{EnrollmentSessionDoc, SshRevokedCertDoc};
use super::documents::oauth::{DelegationPolicyDoc, TokenExchangeDoc};
use super::store::DocumentStore;
use anyhow::Result;
use jiff::Timestamp;

// ============================================================
// Token Exchange (RFC 8693)
// ============================================================

/// Insert a token exchange audit record.
#[allow(clippy::too_many_arguments)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
    #[allow(dead_code)]
    pub session_token_hash: String,
    pub device_auth_id: Option<String>,
    pub expires_at: Timestamp,
    #[allow(dead_code)]
    pub created_at: Timestamp,
    #[allow(dead_code)]
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
// SSH Certificate Revocation
// ============================================================

/// Revoked SSH certificate record.
#[derive(Debug)]
pub struct RevokedSshCertificate {
    #[allow(dead_code)]
    pub id: String,
    pub serial: String,
    #[allow(dead_code)]
    pub user_id: String,
    #[allow(dead_code)]
    pub reason: Option<String>,
    #[allow(dead_code)]
    pub revoked_at: Timestamp,
    #[allow(dead_code)]
    pub expires_at: Timestamp,
    #[allow(dead_code)]
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
#[allow(dead_code)]
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

/// Revoke all SSH certificates for a user.
pub async fn revoke_all_ssh_certificates_for_user(
    store: &DocumentStore,
    user_id: &str,
    reason: Option<&str>,
    revoked_by: Option<&str>,
) -> Result<u64> {
    let now = Timestamp::now();
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().years(1))
        .map_err(|_| anyhow::anyhow!("Time calculation overflow"))?;

    let doc = SshRevokedCertDoc {
        serial: format!("user:{user_id}"),
        user_id: user_id.to_string(),
        reason: reason.map(String::from),
        revoked_at: now,
        expires_at,
        revoked_by: revoked_by.map(String::from),
    };
    store.insert(&doc).await?;
    Ok(1)
}

/// Delete expired SSH certificate revocations.
pub async fn delete_expired_ssh_revocations(store: &DocumentStore) -> Result<u64> {
    store.delete_expired(SshRevokedCertDoc::DOC_TYPE).await
}
