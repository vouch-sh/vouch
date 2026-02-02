// SPDX-License-Identifier: BUSL-1.1
//! Database schema definitions using sea-query Iden enums.
//!
//! This module provides type-safe table and column identifiers for all database
//! tables, enabling compile-time verification of query construction.

use sea_query::Iden;

/// Organizations table for domain-based multi-tenancy.
#[derive(Iden)]
pub enum Organizations {
    Table,
    Id,
    Domain,
    Name,
    CreatedAt,
    CreatedByUserId,
}

/// Users table.
#[derive(Iden)]
pub enum Users {
    Table,
    Id,
    Email,
    Name,
    CreatedAt,
    Active,
    ExternalId,
    OrgId,
    IsOrgAdmin,
    #[iden = "github_id"]
    GitHubId,
    #[iden = "github_login"]
    GitHubLogin,
    #[iden = "github_refresh_token"]
    GitHubRefreshToken,
}

/// Authenticators (WebAuthn credentials) table.
#[derive(Iden)]
pub enum Authenticators {
    Table,
    Id,
    UserId,
    Name,
    CredentialId,
    PublicKey,
    Counter,
    CreatedAt,
    Aaguid,
    UserHandle,
}

/// Sessions table.
#[derive(Iden)]
pub enum Sessions {
    Table,
    Id,
    UserId,
    TokenHash,
    AuthenticatorId,
    ExpiresAt,
    CreatedAt,
}

/// Device authorization requests table (OAuth 2.0 Device Authorization Grant).
#[derive(Iden)]
pub enum DeviceAuthRequests {
    Table,
    Id,
    DeviceCodeHash,
    UserCode,
    Status,
    UserId,
    UserEmail,
    AuthenticatorId,
    ExpiresAt,
    IntervalSeconds,
    LastPollAt,
    CreatedAt,
}

/// OIDC states for device authorization.
#[derive(Iden)]
pub enum OidcStates {
    Table,
    Id,
    State,
    DeviceAuthId,
    Nonce,
    ExpiresAt,
    CreatedAt,
}

/// Server configuration table.
#[derive(Iden)]
pub enum ServerConfig {
    Table,
    Key,
    Value,
    UpdatedAt,
}

/// Authentication events for audit logging.
#[derive(Iden)]
pub enum AuthEvents {
    Table,
    Id,
    UserId,
    EventType,
    AuthenticatorId,
    ClientIp,
    UserAgent,
    ClientHostname,
    ClientOs,
    ClientArch,
    ClientVersion,
    Success,
    FailureReason,
    CreatedAt,
}

/// SCIM tokens for provisioning.
#[derive(Iden)]
pub enum ScimTokens {
    Table,
    Id,
    TokenHash,
    OrgId,
    Description,
    CreatedAt,
    LastUsedAt,
    ExpiresAt,
}

/// SCIM audit log.
#[derive(Iden)]
pub enum ScimAuditLog {
    Table,
    Id,
    Operation,
    ResourceType,
    ResourceId,
    ActorTokenId,
    Details,
    CreatedAt,
}

/// SCIM groups table.
#[derive(Iden)]
pub enum ScimGroups {
    Table,
    Id,
    DisplayName,
    ExternalId,
    CreatedAt,
    UpdatedAt,
}

/// SCIM group membership table.
#[derive(Iden)]
pub enum ScimGroupMembers {
    Table,
    GroupId,
    UserId,
    CreatedAt,
}

/// OAuth clients table.
#[derive(Iden)]
pub enum OAuthClients {
    #[iden = "oauth_clients"]
    Table,
    Id,
    UserId,
    ClientId,
    Name,
    Description,
    ApplicationType,
    RedirectUris,
    Active,
    CreatedAt,
    UpdatedAt,
    LastUsedAt,
    AccessScope,
    OrgId,
}

/// OAuth client secrets table.
#[derive(Iden)]
pub enum OAuthClientSecrets {
    #[iden = "oauth_client_secrets"]
    Table,
    Id,
    #[iden = "oauth_client_id"]
    OAuthClientId,
    SecretHash,
    Description,
    CreatedAt,
    ExpiresAt,
    RevokedAt,
}

/// OAuth usage events table.
#[derive(Iden)]
pub enum OAuthUsageEvents {
    #[iden = "oauth_usage_events"]
    Table,
    Id,
    #[iden = "oauth_client_id"]
    OAuthClientId,
    EventType,
    UserId,
    IpAddress,
    UserAgent,
    Details,
    CreatedAt,
}

/// Pending OAuth authorizations table.
#[derive(Iden)]
pub enum PendingOAuthAuthorizations {
    #[iden = "pending_oauth_authorizations"]
    Table,
    Id,
    ClientId,
    RedirectUri,
    ResponseType,
    State,
    Scope,
    Nonce,
    CodeChallenge,
    CodeChallengeMethod,
    CreatedAt,
    ExpiresAt,
    ConsumedAt,
}

/// DPoP nonces table.
#[derive(Iden)]
pub enum DpopNonces {
    Table,
    Id,
    Nonce,
    CreatedAt,
    ExpiresAt,
}

/// DPoP JTI cache table.
#[derive(Iden)]
pub enum DpopJtiCache {
    Table,
    Jti,
    CreatedAt,
    ExpiresAt,
}

/// Token exchanges table (RFC 8693).
#[derive(Iden)]
pub enum TokenExchanges {
    Table,
    Id,
    SubjectUserId,
    SubjectTokenHash,
    ActorUserId,
    IssuedTokenHash,
    RequestedAudience,
    GrantedScope,
    CreatedAt,
    ExpiresAt,
}

/// Delegation policies table.
#[derive(Iden)]
pub enum DelegationPolicies {
    Table,
    Id,
    Name,
    GrantorPattern,
    GranteePattern,
    AllowedScopes,
    MaxTtlSeconds,
    Enabled,
    CreatedAt,
    UpdatedAt,
}

/// SSH revoked certificates table.
#[derive(Iden)]
pub enum SshRevokedCertificates {
    Table,
    Id,
    Serial,
    UserId,
    Reason,
    RevokedAt,
    ExpiresAt,
    RevokedBy,
}

/// Enrollment sessions table.
#[derive(Iden)]
pub enum EnrollmentSessions {
    Table,
    Id,
    UserId,
    UserEmail,
    SessionTokenHash,
    DeviceAuthId,
    ExpiresAt,
    CreatedAt,
    LastUsedAt,
}

/// GitHub installations table.
#[derive(Iden)]
pub enum GitHubInstallations {
    #[iden = "github_installations"]
    Table,
    Id,
    OrgId,
    InstallationId,
    #[iden = "github_account_login"]
    GitHubAccountLogin,
    #[iden = "github_account_type"]
    GitHubAccountType,
    Permissions,
    RepositorySelection,
    InstalledAt,
    InstalledByUserId,
    SuspendedAt,
    Repositories,
}

/// GitHub credential events table.
#[derive(Iden)]
pub enum GitHubCredentialEvents {
    #[iden = "github_credential_events"]
    Table,
    Id,
    EventType,
    UserId,
    UserEmail,
    OrgId,
    InstallationId,
    SessionId,
    AuthenticatorId,
    Repositories,
    Permissions,
    TokenExpiresAt,
    Success,
    ErrorCode,
    IpAddress,
    UserAgent,
    CreatedAt,
}

/// Cloud integrations table.
#[derive(Iden)]
pub enum CloudIntegrations {
    Table,
    Id,
    OrgId,
    Provider,
    Config,
    CreatedAt,
    UpdatedAt,
    CreatedByUserId,
}
