// SPDX-License-Identifier: BUSL-1.1
//! Database queries organized by domain.
//!
//! This module provides database operations for the Vouch server, organized
//! into domain-specific submodules for maintainability.
//!
//! # Multi-Database Support
//!
//! This module supports both SQLite and PostgreSQL backends via feature flags:
//! - `sqlite` (default): Uses SQLite for development and testing
//! - `postgres`: Uses PostgreSQL/Aurora DSQL for production
//!
//! Use the `Pool` type alias for database operations to work with either backend.

mod authenticators;
pub mod compat;
mod config;
mod credentials;
mod device_auth;
mod error;
mod github;
mod oauth;
mod organizations;
mod pending_oauth;
mod pool;
pub mod schema;
mod scim;
mod sessions;
mod users;

// Re-export Pool, DatabaseType, and Transaction for use throughout the application
pub use pool::{DatabaseType, Pool, Transaction};

// Re-export error types
pub use error::{DbError, DbResult};

// Re-export user types and functions
pub use users::{
    User, UserWithAuthCount, delete_user, get_user_by_email, get_user_by_id,
    list_users_with_auth_count, list_users_with_auth_count_by_org, upsert_user,
    upsert_user_with_org,
};

// Re-export session types and functions
pub use sessions::{
    Session, create_session, delete_expired_sessions, delete_session_by_token_hash,
    delete_sessions_for_user, get_session_by_token_hash,
};

// Re-export authenticator types and functions
pub use authenticators::{
    Authenticator, count_authenticators_for_user, count_sessions_for_authenticator,
    create_authenticator, delete_authenticator, get_authenticator_by_credential_id,
    get_authenticator_by_id, get_authenticators_for_user, update_authenticator_counter,
    update_authenticator_name,
};

// Re-export organization types and functions
pub use organizations::{
    Organization, count_users_in_org, create_organization, get_or_create_org_by_domain,
    get_org_by_domain, get_org_by_id, list_organizations, set_user_org,
};

// Re-export device auth types and functions
pub use device_auth::{
    DeviceAuthRequest, DeviceAuthStatus, OidcState, authorize_device_auth,
    create_device_auth_request, create_oidc_state, delete_expired_device_auth_requests,
    delete_expired_oidc_states, delete_oidc_state, deny_device_auth, get_device_auth_by_code_hash,
    get_device_auth_by_id, get_device_auth_by_user_code, get_oidc_state,
    update_device_auth_poll_time,
};

// Re-export config and auth event types and functions
pub use config::{
    AuthEvent, AuthEventParams, AuthEventQuery, AuthEventType, ServerConfigRow, delete_config,
    delete_old_auth_events, get_all_config, get_auth_events, get_config, insert_auth_event,
    set_config,
};

// Re-export SCIM types and functions
pub use scim::{
    ScimGroupMemberRecord, ScimGroupRecord, ScimToken, ScimUserRecord, add_scim_group_member,
    count_scim_groups, count_scim_users, create_scim_group, create_scim_token, create_scim_user,
    delete_scim_group, delete_scim_token, get_scim_group, get_scim_group_by_name,
    get_scim_group_members, get_scim_token_by_hash, get_scim_user, get_user_scim_groups,
    insert_scim_audit, list_scim_groups, list_scim_tokens, list_scim_users,
    remove_scim_group_member, replace_scim_group_members, update_scim_group,
    update_scim_token_last_used, update_scim_user,
};

// Re-export OAuth types and functions
pub use oauth::{
    AccessScope, OAuthClient, OAuthClientSecret, OAuthClientType, OAuthEventType, OAuthUsageEvent,
    OAuthUsageStats, create_oauth_client, create_oauth_client_secret, deactivate_oauth_client,
    delete_oauth_client, delete_old_oauth_usage_events, get_oauth_client_by_client_id,
    get_oauth_client_by_id, get_oauth_client_secrets, get_oauth_clients_for_user,
    get_oauth_secret_by_hash, get_oauth_usage_events, get_oauth_usage_stats,
    reactivate_oauth_client, record_oauth_event, revoke_all_oauth_client_secrets,
    revoke_oauth_client_secret, update_oauth_client, update_oauth_client_last_used,
    validate_oauth_client_credentials,
};

// Re-export credentials types and functions
pub use credentials::{
    CloudIntegration, DelegationPolicy, EnrollmentSession, RevokedSshCertificate,
    TokenExchangeRecord, check_delegation_policy, create_delegation_policy,
    create_enrollment_session, delete_cloud_integration, delete_delegation_policy,
    delete_enrollment_session, delete_expired_enrollment_sessions, delete_expired_ssh_revocations,
    get_cloud_integration, get_delegation_policies, get_enrollment_session_by_token_hash,
    get_revoked_ssh_certificates, get_token_exchanges_for_user, insert_token_exchange,
    is_ssh_certificate_revoked, revoke_all_ssh_certificates_for_user, revoke_ssh_certificate,
    set_delegation_policy_enabled, touch_enrollment_session, upsert_cloud_integration,
};

// Re-export GitHub types and functions
pub use github::{
    GitHubCredentialEventParams, GitHubInstallation, create_github_installation,
    delete_github_installation_by_installation_id, delete_old_github_credential_events,
    get_github_installation_by_installation_id, get_github_installation_by_org_and_account,
    get_github_installations_by_org, log_github_credential_event, suspend_github_installation,
    unsuspend_github_installation, update_github_installation_repos,
    update_github_installation_repos_delta,
};

// Re-export pending OAuth types and functions (RFC 6749, RFC 9700)
pub use pending_oauth::{
    CreatePendingOAuthParams, PendingOAuthAuthorization, consume_pending_oauth_authorization,
    create_pending_oauth_authorization, delete_expired_pending_oauth_authorizations,
    get_pending_oauth_authorization,
};

#[cfg(test)]
mod tests;
