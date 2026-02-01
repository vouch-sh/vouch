// SPDX-License-Identifier: BUSL-1.1
//! Credential-related database operations (SSH revocation, enrollment, token exchange, cloud integrations).

use super::Pool;
use super::compat::{BuildSql, now_expr};
use super::schema::SshRevokedCertificates;
use crate::{db_execute, db_fetch_all, db_fetch_one, db_fetch_optional};
use anyhow::Result;
use sea_query::{OnConflict, Query};
use uuid::Uuid;

// ============================================================================
// Token Exchange (RFC 8693)
// ============================================================================

/// Insert a token exchange audit record.
#[allow(clippy::too_many_arguments)]
pub async fn insert_token_exchange(
    pool: &Pool,
    subject_user_id: &str,
    subject_token_hash: &str,
    actor_user_id: Option<&str>,
    issued_token_hash: &str,
    requested_audience: Option<&str>,
    granted_scope: Option<&str>,
    expires_at: &str,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    db_execute!(
        pool,
        sqlx::query(
            "INSERT INTO token_exchanges (id, subject_user_id, subject_token_hash, actor_user_id, issued_token_hash, requested_audience, granted_scope, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&id)
        .bind(subject_user_id)
        .bind(subject_token_hash)
        .bind(actor_user_id)
        .bind(issued_token_hash)
        .bind(requested_audience)
        .bind(granted_scope)
        .bind(expires_at)
    )?;

    Ok(id)
}

/// Get token exchange records for a user.
#[allow(dead_code)]
pub async fn get_token_exchanges_for_user(
    pool: &Pool,
    user_id: &str,
    limit: i64,
) -> Result<Vec<TokenExchangeRecord>> {
    let records = db_fetch_all!(
        pool,
        sqlx::query_as::<_, TokenExchangeRecord>(
            "SELECT id, subject_user_id, subject_token_hash, actor_user_id, issued_token_hash, requested_audience, granted_scope, created_at, expires_at
         FROM token_exchanges WHERE subject_user_id = ? ORDER BY created_at DESC LIMIT ?"
        )
        .bind(user_id)
        .bind(limit)
    )?;

    Ok(records)
}

/// Token exchange audit record.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct TokenExchangeRecord {
    pub id: String,
    pub subject_user_id: String,
    pub subject_token_hash: String,
    pub actor_user_id: Option<String>,
    pub issued_token_hash: String,
    pub requested_audience: Option<String>,
    pub granted_scope: Option<String>,
    pub created_at: String,
    pub expires_at: String,
}

// ============================================================================
// Delegation Policies
// ============================================================================

/// Delegation policy record.
#[allow(dead_code)]
#[derive(Debug, sqlx::FromRow)]
pub struct DelegationPolicy {
    pub id: String,
    pub name: String,
    pub grantor_pattern: String,
    pub grantee_pattern: String,
    pub allowed_scopes: Option<String>,
    pub max_ttl_seconds: Option<i64>,
    pub enabled: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// Check if a delegation is allowed by any policy.
///
/// Returns the matching policy if delegation is allowed, None otherwise.
pub async fn check_delegation_policy(
    pool: &Pool,
    grantor_email: &str,
    grantee_audience: Option<&str>,
) -> Result<Option<DelegationPolicy>> {
    // Get all enabled policies
    let policies = db_fetch_all!(
        pool,
        sqlx::query_as::<_, DelegationPolicy>(
            "SELECT id, name, grantor_pattern, grantee_pattern, allowed_scopes, max_ttl_seconds, enabled, created_at, updated_at
         FROM delegation_policies WHERE enabled = 1 ORDER BY created_at ASC"
        )
    )?;

    for policy in policies {
        // Check grantor pattern
        if !pattern_matches(&policy.grantor_pattern, grantor_email) {
            continue;
        }

        // Check grantee pattern (audience)
        if let Some(audience) = grantee_audience
            && !pattern_matches(&policy.grantee_pattern, audience)
        {
            continue;
        }

        // Policy matches
        return Ok(Some(policy));
    }

    Ok(None)
}

/// Check if a pattern matches a value.
///
/// Patterns can be:
/// - "*" matches anything
/// - "*@domain.com" matches emails with the specified domain
/// - Exact string match
fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if let Some(domain) = pattern.strip_prefix("*@") {
        // Domain pattern
        if let Some(email_domain) = value.rsplit('@').next() {
            return email_domain.eq_ignore_ascii_case(domain);
        }
        return false;
    }

    // Exact match
    pattern.eq_ignore_ascii_case(value)
}

/// Create a delegation policy.
#[allow(dead_code)]
pub async fn create_delegation_policy(
    pool: &Pool,
    name: &str,
    grantor_pattern: &str,
    grantee_pattern: &str,
    allowed_scopes: Option<&str>,
    max_ttl_seconds: Option<i64>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    db_execute!(
        pool,
        sqlx::query(
            "INSERT INTO delegation_policies (id, name, grantor_pattern, grantee_pattern, allowed_scopes, max_ttl_seconds)
         VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(&id)
        .bind(name)
        .bind(grantor_pattern)
        .bind(grantee_pattern)
        .bind(allowed_scopes)
        .bind(max_ttl_seconds)
    )?;

    Ok(id)
}

/// Get all delegation policies.
pub async fn get_delegation_policies(pool: &Pool) -> Result<Vec<DelegationPolicy>> {
    let policies = db_fetch_all!(
        pool,
        sqlx::query_as::<_, DelegationPolicy>(
            "SELECT id, name, grantor_pattern, grantee_pattern, allowed_scopes, max_ttl_seconds, enabled, created_at, updated_at
         FROM delegation_policies ORDER BY created_at DESC"
        )
    )?;

    Ok(policies)
}

/// Update a delegation policy's enabled status.
#[allow(dead_code)]
pub async fn set_delegation_policy_enabled(pool: &Pool, id: &str, enabled: bool) -> Result<bool> {
    let db_type = pool.db_type();
    let now = now_expr(db_type);
    let sql =
        format!("UPDATE delegation_policies SET enabled = ?, updated_at = {now} WHERE id = ?");

    let result = db_execute!(
        pool,
        sqlx::query(&sql).bind(if enabled { 1 } else { 0 }).bind(id)
    )?;

    Ok(result.rows_affected() > 0)
}

/// Delete a delegation policy.
#[allow(dead_code)]
pub async fn delete_delegation_policy(pool: &Pool, id: &str) -> Result<bool> {
    let result = db_execute!(
        pool,
        sqlx::query("DELETE FROM delegation_policies WHERE id = ?").bind(id)
    )?;

    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Enrollment Sessions
// ============================================================================

/// Enrollment session record (for key management during enrollment).
#[derive(Debug, sqlx::FromRow)]
pub struct EnrollmentSession {
    pub id: String,
    pub user_id: String,
    pub user_email: String,
    #[allow(dead_code)]
    pub session_token_hash: String,
    pub device_auth_id: Option<String>,
    pub expires_at: String,
    #[allow(dead_code)]
    pub created_at: String,
    #[allow(dead_code)]
    pub last_used_at: String,
}

/// Create a new enrollment session.
pub async fn create_enrollment_session(
    pool: &Pool,
    user_id: &str,
    user_email: &str,
    session_token_hash: &str,
    device_auth_id: Option<&str>,
    expires_at: &str,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();

    db_execute!(
        pool,
        sqlx::query(
            "INSERT INTO enrollment_sessions (id, user_id, user_email, session_token_hash, device_auth_id, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(&id)
        .bind(user_id)
        .bind(user_email)
        .bind(session_token_hash)
        .bind(device_auth_id)
        .bind(expires_at)
    )?;

    Ok(id)
}

/// Get an enrollment session by token hash.
pub async fn get_enrollment_session_by_token_hash(
    pool: &Pool,
    token_hash: &str,
) -> Result<Option<EnrollmentSession>> {
    let session = db_fetch_optional!(
        pool,
        sqlx::query_as::<_, EnrollmentSession>(
            "SELECT id, user_id, user_email, session_token_hash, device_auth_id, expires_at, created_at, last_used_at
         FROM enrollment_sessions
         WHERE session_token_hash = ?"
        )
        .bind(token_hash)
    )?;

    Ok(session)
}

/// Update enrollment session last used timestamp.
pub async fn touch_enrollment_session(pool: &Pool, id: &str) -> Result<()> {
    let db_type = pool.db_type();
    let now = now_expr(db_type);
    let sql = format!("UPDATE enrollment_sessions SET last_used_at = {now} WHERE id = ?");

    db_execute!(pool, sqlx::query(&sql).bind(id))?;

    Ok(())
}

/// Delete an enrollment session.
pub async fn delete_enrollment_session(pool: &Pool, id: &str) -> Result<bool> {
    let result = db_execute!(
        pool,
        sqlx::query("DELETE FROM enrollment_sessions WHERE id = ?").bind(id)
    )?;

    Ok(result.rows_affected() > 0)
}

/// Delete expired enrollment sessions (for cleanup task).
pub async fn delete_expired_enrollment_sessions(pool: &Pool) -> Result<u64> {
    let db_type = pool.db_type();
    let now = now_expr(db_type);
    let sql = format!("DELETE FROM enrollment_sessions WHERE expires_at < {now}");

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected())
}

// ============================================================================
// SSH Certificate Revocation
// ============================================================================

/// Revoked SSH certificate record.
#[derive(Debug, sqlx::FromRow)]
pub struct RevokedSshCertificate {
    #[allow(dead_code)]
    pub id: String,
    pub serial: String,
    #[allow(dead_code)]
    pub user_id: String,
    #[allow(dead_code)]
    pub reason: Option<String>,
    #[allow(dead_code)]
    pub revoked_at: String,
    #[allow(dead_code)]
    pub expires_at: String,
    #[allow(dead_code)]
    pub revoked_by: Option<String>,
}

/// Revoke an SSH certificate.
#[allow(dead_code)]
pub async fn revoke_ssh_certificate(
    pool: &Pool,
    serial: &str,
    user_id: &str,
    expires_at: &str,
    reason: Option<&str>,
    revoked_by: Option<&str>,
) -> Result<String> {
    let id = Uuid::now_v7().to_string();
    let db_type = pool.db_type();

    // Build SQL in a block to ensure query is dropped before await
    let sql = {
        let query = Query::insert()
            .into_table(SshRevokedCertificates::Table)
            .columns([
                SshRevokedCertificates::Id,
                SshRevokedCertificates::Serial,
                SshRevokedCertificates::UserId,
                SshRevokedCertificates::ExpiresAt,
                SshRevokedCertificates::Reason,
                SshRevokedCertificates::RevokedBy,
            ])
            .values_panic([
                id.clone().into(),
                serial.into(),
                user_id.into(),
                expires_at.into(),
                reason.into(),
                revoked_by.into(),
            ])
            .on_conflict(OnConflict::new().do_nothing().to_owned())
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(id)
}

/// Check if an SSH certificate is revoked.
pub async fn is_ssh_certificate_revoked(pool: &Pool, serial: &str) -> Result<bool> {
    let result: (i64,) = db_fetch_one!(
        pool,
        sqlx::query_as("SELECT COUNT(*) FROM ssh_revoked_certificates WHERE serial = ?")
            .bind(serial)
    )?;

    Ok(result.0 > 0)
}

/// Get all revoked SSH certificates (for KRL generation).
pub async fn get_revoked_ssh_certificates(pool: &Pool) -> Result<Vec<RevokedSshCertificate>> {
    let db_type = pool.db_type();
    let now = now_expr(db_type);
    let sql = format!(
        "SELECT id, serial, user_id, reason, revoked_at, expires_at, revoked_by
         FROM ssh_revoked_certificates
         WHERE expires_at > {now}
         ORDER BY revoked_at DESC"
    );

    let certs = db_fetch_all!(pool, sqlx::query_as::<_, RevokedSshCertificate>(&sql))?;

    Ok(certs)
}

/// Revoke all SSH certificates for a user.
pub async fn revoke_all_ssh_certificates_for_user(
    pool: &Pool,
    user_id: &str,
    reason: Option<&str>,
    revoked_by: Option<&str>,
) -> Result<u64> {
    // Note: This only marks future certificates as needing revocation check.
    // Existing issued certificates are tracked separately via serial numbers.
    // The caller should also add any known serials to the revocation list.
    let db_type = pool.db_type();

    // Compute expiry (1 year from now)
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().years(1))
        .map_err(|_| anyhow::anyhow!("Time calculation overflow"))?
        .to_string();

    // Build SQL in a block to ensure query is dropped before await
    let sql = {
        let query = Query::insert()
            .into_table(SshRevokedCertificates::Table)
            .columns([
                SshRevokedCertificates::Id,
                SshRevokedCertificates::Serial,
                SshRevokedCertificates::UserId,
                SshRevokedCertificates::ExpiresAt,
                SshRevokedCertificates::Reason,
                SshRevokedCertificates::RevokedBy,
            ])
            .values_panic([
                Uuid::now_v7().to_string().into(),
                format!("user:{user_id}").into(),
                user_id.into(),
                expires_at.into(),
                reason.into(),
                revoked_by.into(),
            ])
            .on_conflict(OnConflict::new().do_nothing().to_owned())
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected())
}

/// Delete expired SSH certificate revocations (cleanup).
pub async fn delete_expired_ssh_revocations(pool: &Pool) -> Result<u64> {
    let db_type = pool.db_type();
    let now = now_expr(db_type);
    let sql = format!("DELETE FROM ssh_revoked_certificates WHERE expires_at < {now}");

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected())
}

// ============================================================================
// Cloud Provider Integrations (GCP, AWS)
// ============================================================================

/// Cloud provider integration configuration record.
#[derive(Debug, sqlx::FromRow)]
pub struct CloudIntegration {
    pub id: String,
    pub org_id: String,
    pub provider: String,
    pub config: String,
    pub created_at: String,
    pub updated_at: String,
    pub created_by_user_id: Option<String>,
}

/// Get cloud integration config for an organization and provider.
pub async fn get_cloud_integration(
    pool: &Pool,
    org_id: &str,
    provider: &str,
) -> Result<Option<CloudIntegration>> {
    let integration = db_fetch_optional!(
        pool,
        sqlx::query_as::<_, CloudIntegration>(
            "SELECT id, org_id, provider, config, created_at, updated_at, created_by_user_id
         FROM cloud_integrations WHERE org_id = ? AND provider = ?"
        )
        .bind(org_id)
        .bind(provider)
    )?;

    Ok(integration)
}

/// Create or update cloud integration config for an organization.
pub async fn upsert_cloud_integration(
    pool: &Pool,
    org_id: &str,
    provider: &str,
    config: &str,
    user_id: &str,
) -> Result<CloudIntegration> {
    let id = Uuid::now_v7().to_string();
    let db_type = pool.db_type();
    let now = now_expr(db_type);

    let sql = format!(
        "INSERT INTO cloud_integrations (id, org_id, provider, config, created_by_user_id)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(org_id, provider) DO UPDATE SET
             config = excluded.config,
             updated_at = {now}"
    );

    db_execute!(
        pool,
        sqlx::query(&sql)
            .bind(&id)
            .bind(org_id)
            .bind(provider)
            .bind(config)
            .bind(user_id)
    )?;

    // Return the integration (may be newly created or updated)
    get_cloud_integration(pool, org_id, provider)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to retrieve cloud integration after upsert"))
}

/// Delete cloud integration config for an organization.
pub async fn delete_cloud_integration(pool: &Pool, org_id: &str, provider: &str) -> Result<bool> {
    let result = db_execute!(
        pool,
        sqlx::query("DELETE FROM cloud_integrations WHERE org_id = ? AND provider = ?")
            .bind(org_id)
            .bind(provider)
    )?;

    Ok(result.rows_affected() > 0)
}
