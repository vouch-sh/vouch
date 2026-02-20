// SPDX-License-Identifier: BUSL-1.1
//! Credential-related database operations (SSH revocation, enrollment, token exchange, cloud integrations).

use super::Pool;
use super::schema::{
    CloudIntegrations, DelegationPolicies, EnrollmentSessions, SshRevokedCertificates,
    TokenExchanges,
};
use super::types::BuildSql;
use super::types::DbTimestamp;
use crate::{db_execute, db_fetch_all, db_fetch_one, db_fetch_optional};
use anyhow::Result;
use jiff::Timestamp;
use sea_query::{Expr, OnConflict, Order, Query};
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
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::insert()
            .into_table(TokenExchanges::Table)
            .columns([
                TokenExchanges::Id,
                TokenExchanges::SubjectUserId,
                TokenExchanges::SubjectTokenHash,
                TokenExchanges::ActorUserId,
                TokenExchanges::IssuedTokenHash,
                TokenExchanges::RequestedAudience,
                TokenExchanges::GrantedScope,
                TokenExchanges::ExpiresAt,
                TokenExchanges::CreatedAt,
            ])
            .values_panic([
                id.clone().into(),
                subject_user_id.into(),
                subject_token_hash.into(),
                actor_user_id.into(),
                issued_token_hash.into(),
                requested_audience.into(),
                granted_scope.into(),
                expires_at.into(),
                now.as_str().into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(id)
}

/// Delete token exchange records older than the specified timestamp.
pub async fn delete_old_token_exchanges(pool: &Pool, before: &str) -> Result<u64> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::delete()
            .from_table(TokenExchanges::Table)
            .and_where(Expr::col(TokenExchanges::CreatedAt).lt(before))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected())
}

/// Get token exchange records for a user.
#[allow(dead_code)]
pub async fn get_token_exchanges_for_user(
    pool: &Pool,
    user_id: &str,
    limit: i64,
) -> Result<Vec<TokenExchangeRecord>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                TokenExchanges::Id,
                TokenExchanges::SubjectUserId,
                TokenExchanges::SubjectTokenHash,
                TokenExchanges::ActorUserId,
                TokenExchanges::IssuedTokenHash,
                TokenExchanges::RequestedAudience,
                TokenExchanges::GrantedScope,
                TokenExchanges::CreatedAt,
                TokenExchanges::ExpiresAt,
            ])
            .from(TokenExchanges::Table)
            .and_where(Expr::col(TokenExchanges::SubjectUserId).eq(user_id))
            .order_by(TokenExchanges::CreatedAt, Order::Desc)
            .limit(limit as u64)
            .to_owned();
        query.build_sql(db_type)
    };

    let records = db_fetch_all!(pool, sqlx::query_as::<_, TokenExchangeRecord>(&sql))?;

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
    pub created_at: DbTimestamp,
    pub expires_at: DbTimestamp,
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
    pub max_ttl_seconds: Option<i32>,
    pub enabled: bool,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
}

/// Check if a delegation is allowed by any policy.
///
/// Returns the matching policy if delegation is allowed, None otherwise.
pub async fn check_delegation_policy(
    pool: &Pool,
    grantor_email: &str,
    grantee_audience: Option<&str>,
) -> Result<Option<DelegationPolicy>> {
    let db_type = pool.db_type();

    // Get all enabled policies
    let sql = {
        let query = Query::select()
            .columns([
                DelegationPolicies::Id,
                DelegationPolicies::Name,
                DelegationPolicies::GrantorPattern,
                DelegationPolicies::GranteePattern,
                DelegationPolicies::AllowedScopes,
                DelegationPolicies::MaxTtlSeconds,
                DelegationPolicies::Enabled,
                DelegationPolicies::CreatedAt,
                DelegationPolicies::UpdatedAt,
            ])
            .from(DelegationPolicies::Table)
            .and_where(Expr::col(DelegationPolicies::Enabled).eq(true))
            .order_by(DelegationPolicies::CreatedAt, Order::Asc)
            .to_owned();
        query.build_sql(db_type)
    };

    let policies = db_fetch_all!(pool, sqlx::query_as::<_, DelegationPolicy>(&sql))?;

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

/// Get all delegation policies.
pub async fn get_delegation_policies(pool: &Pool) -> Result<Vec<DelegationPolicy>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                DelegationPolicies::Id,
                DelegationPolicies::Name,
                DelegationPolicies::GrantorPattern,
                DelegationPolicies::GranteePattern,
                DelegationPolicies::AllowedScopes,
                DelegationPolicies::MaxTtlSeconds,
                DelegationPolicies::Enabled,
                DelegationPolicies::CreatedAt,
                DelegationPolicies::UpdatedAt,
            ])
            .from(DelegationPolicies::Table)
            .order_by(DelegationPolicies::CreatedAt, Order::Desc)
            .to_owned();
        query.build_sql(db_type)
    };

    let policies = db_fetch_all!(pool, sqlx::query_as::<_, DelegationPolicy>(&sql))?;

    Ok(policies)
}

/// Update a delegation policy's enabled status.
#[allow(dead_code)]
pub async fn set_delegation_policy_enabled(pool: &Pool, id: &str, enabled: bool) -> Result<bool> {
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::update()
            .table(DelegationPolicies::Table)
            .value(DelegationPolicies::Enabled, enabled)
            .value(DelegationPolicies::UpdatedAt, now.as_str())
            .and_where(Expr::col(DelegationPolicies::Id).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected() > 0)
}

/// Delete a delegation policy.
#[allow(dead_code)]
pub async fn delete_delegation_policy(pool: &Pool, id: &str) -> Result<bool> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::delete()
            .from_table(DelegationPolicies::Table)
            .and_where(Expr::col(DelegationPolicies::Id).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

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
    pub expires_at: DbTimestamp,
    #[allow(dead_code)]
    pub created_at: DbTimestamp,
    #[allow(dead_code)]
    pub last_used_at: DbTimestamp,
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
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::insert()
            .into_table(EnrollmentSessions::Table)
            .columns([
                EnrollmentSessions::Id,
                EnrollmentSessions::UserId,
                EnrollmentSessions::UserEmail,
                EnrollmentSessions::SessionTokenHash,
                EnrollmentSessions::DeviceAuthId,
                EnrollmentSessions::ExpiresAt,
                EnrollmentSessions::CreatedAt,
                EnrollmentSessions::LastUsedAt,
            ])
            .values_panic([
                id.clone().into(),
                user_id.into(),
                user_email.into(),
                session_token_hash.into(),
                device_auth_id.into(),
                expires_at.into(),
                now.as_str().into(),
                now.as_str().into(),
            ])
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(id)
}

/// Get an enrollment session by token hash.
pub async fn get_enrollment_session_by_token_hash(
    pool: &Pool,
    token_hash: &str,
) -> Result<Option<EnrollmentSession>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                EnrollmentSessions::Id,
                EnrollmentSessions::UserId,
                EnrollmentSessions::UserEmail,
                EnrollmentSessions::SessionTokenHash,
                EnrollmentSessions::DeviceAuthId,
                EnrollmentSessions::ExpiresAt,
                EnrollmentSessions::CreatedAt,
                EnrollmentSessions::LastUsedAt,
            ])
            .from(EnrollmentSessions::Table)
            .and_where(Expr::col(EnrollmentSessions::SessionTokenHash).eq(token_hash))
            .to_owned();
        query.build_sql(db_type)
    };

    let session = db_fetch_optional!(pool, sqlx::query_as::<_, EnrollmentSession>(&sql))?;

    Ok(session)
}

/// Update enrollment session last used timestamp.
pub async fn touch_enrollment_session(pool: &Pool, id: &str) -> Result<()> {
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::update()
            .table(EnrollmentSessions::Table)
            .value(EnrollmentSessions::LastUsedAt, now.as_str())
            .and_where(Expr::col(EnrollmentSessions::Id).eq(id))
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    Ok(())
}

/// Delete expired enrollment sessions (for cleanup task).
pub async fn delete_expired_enrollment_sessions(pool: &Pool) -> Result<u64> {
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::delete()
            .from_table(EnrollmentSessions::Table)
            .and_where(Expr::col(EnrollmentSessions::ExpiresAt).lt(now.as_str()))
            .to_owned();
        query.build_sql(db_type)
    };

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
    pub revoked_at: DbTimestamp,
    #[allow(dead_code)]
    pub expires_at: DbTimestamp,
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
    let now = Timestamp::now().to_string();

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
                SshRevokedCertificates::RevokedAt,
            ])
            .values_panic([
                id.clone().into(),
                serial.into(),
                user_id.into(),
                expires_at.into(),
                reason.into(),
                revoked_by.into(),
                now.as_str().into(),
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
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .expr(Expr::col(SshRevokedCertificates::Id).count())
            .from(SshRevokedCertificates::Table)
            .and_where(Expr::col(SshRevokedCertificates::Serial).eq(serial))
            .to_owned();
        query.build_sql(db_type)
    };

    let result: (i64,) = db_fetch_one!(pool, sqlx::query_as(&sql))?;

    Ok(result.0 > 0)
}

/// Get all revoked SSH certificates (for KRL generation).
pub async fn get_revoked_ssh_certificates(pool: &Pool) -> Result<Vec<RevokedSshCertificate>> {
    let db_type = pool.db_type();
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::select()
            .columns([
                SshRevokedCertificates::Id,
                SshRevokedCertificates::Serial,
                SshRevokedCertificates::UserId,
                SshRevokedCertificates::Reason,
                SshRevokedCertificates::RevokedAt,
                SshRevokedCertificates::ExpiresAt,
                SshRevokedCertificates::RevokedBy,
            ])
            .from(SshRevokedCertificates::Table)
            .and_where(Expr::col(SshRevokedCertificates::ExpiresAt).gt(now.as_str()))
            .order_by(SshRevokedCertificates::RevokedAt, Order::Desc)
            .to_owned();
        query.build_sql(db_type)
    };

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
    let now = Timestamp::now().to_string();

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
                SshRevokedCertificates::RevokedAt,
            ])
            .values_panic([
                Uuid::now_v7().to_string().into(),
                format!("user:{user_id}").into(),
                user_id.into(),
                expires_at.into(),
                reason.into(),
                revoked_by.into(),
                now.as_str().into(),
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
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::delete()
            .from_table(SshRevokedCertificates::Table)
            .and_where(Expr::col(SshRevokedCertificates::ExpiresAt).lt(now.as_str()))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected())
}

// ============================================================================
// Cloud Provider Integrations (AWS)
// ============================================================================

/// Cloud provider integration configuration record.
#[derive(Debug, sqlx::FromRow)]
pub struct CloudIntegration {
    pub id: String,
    pub org_id: String,
    pub provider: String,
    pub config: String,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub created_by_user_id: Option<String>,
}

/// Get cloud integration config for an organization and provider.
pub async fn get_cloud_integration(
    pool: &Pool,
    org_id: &str,
    provider: &str,
) -> Result<Option<CloudIntegration>> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::select()
            .columns([
                CloudIntegrations::Id,
                CloudIntegrations::OrgId,
                CloudIntegrations::Provider,
                CloudIntegrations::Config,
                CloudIntegrations::CreatedAt,
                CloudIntegrations::UpdatedAt,
                CloudIntegrations::CreatedByUserId,
            ])
            .from(CloudIntegrations::Table)
            .and_where(Expr::col(CloudIntegrations::OrgId).eq(org_id))
            .and_where(Expr::col(CloudIntegrations::Provider).eq(provider))
            .to_owned();
        query.build_sql(db_type)
    };

    let integration = db_fetch_optional!(pool, sqlx::query_as::<_, CloudIntegration>(&sql))?;

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
    let now = Timestamp::now().to_string();

    let sql = {
        let query = Query::insert()
            .into_table(CloudIntegrations::Table)
            .columns([
                CloudIntegrations::Id,
                CloudIntegrations::OrgId,
                CloudIntegrations::Provider,
                CloudIntegrations::Config,
                CloudIntegrations::CreatedByUserId,
                CloudIntegrations::CreatedAt,
                CloudIntegrations::UpdatedAt,
            ])
            .values_panic([
                id.into(),
                org_id.into(),
                provider.into(),
                config.into(),
                user_id.into(),
                now.as_str().into(),
                now.as_str().into(),
            ])
            .on_conflict(
                OnConflict::columns([CloudIntegrations::OrgId, CloudIntegrations::Provider])
                    .update_column(CloudIntegrations::Config)
                    .value(CloudIntegrations::UpdatedAt, now.as_str())
                    .to_owned(),
            )
            .to_owned();
        query.build_sql(db_type)
    };

    db_execute!(pool, sqlx::query(&sql))?;

    // Return the integration (may be newly created or updated)
    get_cloud_integration(pool, org_id, provider)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to retrieve cloud integration after upsert"))
}

/// Delete cloud integration config for an organization.
pub async fn delete_cloud_integration(pool: &Pool, org_id: &str, provider: &str) -> Result<bool> {
    let db_type = pool.db_type();

    let sql = {
        let query = Query::delete()
            .from_table(CloudIntegrations::Table)
            .and_where(Expr::col(CloudIntegrations::OrgId).eq(org_id))
            .and_where(Expr::col(CloudIntegrations::Provider).eq(provider))
            .to_owned();
        query.build_sql(db_type)
    };

    let result = db_execute!(pool, sqlx::query(&sql))?;

    Ok(result.rows_affected() > 0)
}
