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
mod authorization_codes;
mod config;
mod credentials;
mod device_auth;
mod dpop;
pub mod dsql;
mod enrollment;
mod github;
mod jwt_issuer;
pub mod migrations;
mod oauth;
mod organizations;
pub(crate) mod par;
mod pending_oauth;
pub(crate) mod pool;
pub(crate) mod schema;
mod scim;
mod sessions;
pub(crate) mod types;
mod users;

// Re-export Pool, DatabaseType, and Transaction for use throughout the application
pub use pool::{DatabaseType, Pool, Transaction};

// Re-export user types and functions
pub use users::{
    User, clear_user_github_refresh_token, delete_user, get_user_by_email, get_user_by_id,
    get_user_github_refresh_token, update_user_github_identity,
};

// Re-export user test helpers (only available in tests)
#[cfg(any(test, feature = "test-utils"))]
pub use users::{upsert_user, upsert_user_with_org};

// Re-export session types and functions
pub use sessions::{
    Session, SessionPurpose, create_session, delete_expired_sessions,
    delete_oauth_sessions_for_user, delete_session_by_token_hash, delete_sessions_for_user,
    get_session_by_token_hash,
};

// Re-export authenticator types and functions
pub use authenticators::{
    Authenticator, AuthenticatorWithUser, count_authenticators_for_user,
    count_sessions_for_authenticator, create_authenticator, delete_authenticator,
    get_authenticator_by_credential_id, get_authenticator_by_id,
    get_authenticator_with_user_by_credential_id, get_authenticators_for_user,
    update_authenticator_counter, update_authenticator_name,
};

// Re-export organization types and functions
pub use organizations::{Organization, delete_organization, get_organization_domain};

// Re-export organization test helpers (only available in tests)
#[cfg(any(test, feature = "test-utils"))]
pub use organizations::create_organization;

// Re-export device auth types and functions
pub use device_auth::{
    DeviceAuthRequest, DeviceAuthStatus, OidcState, authorize_device_auth,
    create_device_auth_request, create_oidc_state, delete_expired_device_auth_requests,
    delete_expired_oidc_states, delete_oidc_state, deny_device_auth, get_device_auth_by_code_hash,
    get_device_auth_by_user_code, get_oidc_state, update_device_auth_poll_time,
};

// Re-export device auth test helpers (only available in tests)
#[cfg(test)]
pub use device_auth::get_device_auth_by_id;

// Re-export config and auth event types and functions
pub use config::{
    AuthEvent, AuthEventParams, AuthEventQuery, AuthEventType, delete_old_auth_events,
    get_auth_events, insert_auth_event,
};

// Re-export SCIM types and functions
pub use scim::{
    ScimFilterError, ScimGroupRecord, ScimScope, ScimScopeSet, ScimToken, ScimUserRecord,
    add_scim_group_member, count_scim_groups, count_scim_users, create_scim_group,
    create_scim_token, create_scim_user, delete_old_scim_audit_logs, delete_scim_group,
    delete_scim_token, get_scim_group, get_scim_group_members, get_scim_token_by_hash,
    get_scim_user, insert_scim_audit, list_scim_groups, list_scim_tokens, list_scim_users,
    remove_scim_group_member, replace_scim_group_members, update_scim_group,
    update_scim_token_last_used, update_scim_user,
};

// Re-export OAuth types and functions
pub use oauth::{
    AccessScope, CreateOAuthClientParams, FapiProfile, OAuthClient, OAuthClientType,
    OAuthEventType, OAuthUsageStats, RegistrationSource, TokenEndpointAuthMethod,
    UpdateOAuthClientParams, create_oauth_client, create_oauth_client_secret,
    delete_expired_jwt_assertion_jtis, delete_oauth_client, delete_old_oauth_usage_events,
    get_client_jwks, get_oauth_client_by_client_id, get_oauth_client_by_id,
    get_oauth_client_secrets, get_oauth_clients_for_user, get_oauth_usage_stats,
    record_oauth_event, revoke_all_oauth_client_secrets, store_jwt_assertion_jti,
    update_client_jwks_cache, update_oauth_client, update_oauth_client_last_used,
    validate_oauth_client_credentials,
};

// Re-export test-only OAuth client helpers
#[cfg(test)]
pub use oauth::test_helpers::{
    update_oauth_client_auth_method, update_oauth_client_fapi_settings,
    update_oauth_client_jar_settings, update_oauth_client_jwks,
};

// Re-export JWT issuer types and functions (RFC 7523)
pub use jwt_issuer::{
    TrustedJwtIssuer, create_trusted_jwt_issuer, delete_trusted_jwt_issuer,
    get_trusted_jwt_issuer_by_issuer, list_trusted_jwt_issuers, update_issuer_jwks_cache,
    update_trusted_jwt_issuer,
};

// Re-export DPoP types and functions (RFC 9449)
pub use dpop::{
    check_and_store_dpop_jti, delete_expired_dpop_jtis, delete_expired_dpop_nonces,
    generate_dpop_nonce, validate_and_consume_dpop_nonce,
};

// Re-export credentials types and functions
pub use credentials::{
    CloudIntegration, EnrollmentSession, check_delegation_policy, create_enrollment_session,
    delete_cloud_integration, delete_expired_enrollment_sessions, delete_expired_ssh_revocations,
    delete_old_token_exchanges, get_cloud_integration, get_delegation_policies,
    get_enrollment_session_by_token_hash, get_revoked_ssh_certificates, insert_token_exchange,
    is_ssh_certificate_revoked, revoke_all_ssh_certificates_for_user, revoke_ssh_certificate,
    touch_enrollment_session, upsert_cloud_integration,
};

// Re-export GitHub types and functions
pub use github::{
    GitHubCredentialEventParams, GitHubInstallation, create_github_installation,
    delete_github_installation_by_installation_id, delete_old_github_credential_events,
    get_all_linked_installation_ids, get_github_installation_by_installation_id,
    get_github_installation_by_org_and_account, get_github_installations_by_org,
    log_github_credential_event, suspend_github_installation, unsuspend_github_installation,
    update_github_installation_repos, update_github_installation_repos_delta,
};

// Re-export PAR types and functions (RFC 9126)
pub use par::{
    CreateParParams, PushedAuthorizationRequest, consume_pushed_authorization_request,
    create_pushed_authorization_request, delete_expired_pushed_authorization_requests,
};

// Re-export pending OAuth types and functions (RFC 6749, RFC 9700)
pub use pending_oauth::{
    CreatePendingOAuthParams, PendingOAuthAuthorization, consume_pending_oauth_authorization,
    create_pending_oauth_authorization, delete_expired_pending_oauth_authorizations,
    get_pending_oauth_authorization,
};

// Re-export authorization code functions (RFC 6749 Section 10.5)
pub use authorization_codes::{
    delete_expired_authorization_codes, get_authorization_code_owner, get_consumed_code_owner,
    is_authorization_code_consumed, store_authorization_code, try_consume_authorization_code,
};

// Re-export enrollment types and functions
pub use enrollment::{EnrolledUser, EnrollmentResult, enroll_user_with_org};

#[cfg(test)]
mod tests;
