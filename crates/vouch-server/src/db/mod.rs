// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Database queries organized by domain.
//!
//! This module provides database operations for the Vouch server,
//! organized into domain-specific submodules. Data is stored in a
//! 3-table encrypted document store (`documents`, `document_indexes`,
//! `audit_events`) via [`store::DocumentStore`] and
//! [`audit::AuditStore`].
//!
//! # Multi-Database Support
//!
//! The underlying storage supports both SQLite and PostgreSQL
//! backends via feature flags:
//! - `sqlite` (default): Uses SQLite for development and testing
//! - `postgres`: Uses PostgreSQL/Aurora DSQL for production

pub(crate) mod audit;
mod authenticators;
mod authorization_codes;
mod challenge_states;
pub(crate) mod claim;
mod config;
mod credentials;
mod device_auth;
pub(crate) mod document_type;
pub(crate) mod documents;
mod dpop;
pub(crate) mod dsql;
mod enrollment;
mod github;
mod jwks_cache;
pub(crate) mod migrations;
mod oauth;
mod organizations;
pub(crate) mod par;
mod pending_oauth;
pub(crate) mod pool;
mod posture_policies;
mod scim;
mod sessions;
pub(crate) mod store;
mod users;

// Re-export Pool, DatabaseType, Transaction, and StoreTransaction
pub use pool::{DatabaseType, Pool, Transaction};
pub use store::StoreTransaction;

// Re-export user types and functions
pub use users::{
    User, clear_user_github_refresh_token, delete_user, get_user_by_email, get_user_by_id,
    get_user_github_refresh_token, get_users_by_org_paginated, update_user_active_status,
    update_user_admin_status, update_user_github_identity,
};

// Re-export user test helpers (only available in tests)
#[cfg(any(test, feature = "test-utils"))]
pub use users::{upsert_user, upsert_user_with_org};

// Re-export session types and functions
pub use sessions::{
    CreateSessionParams, Session, SessionCache, SessionPurpose, create_session,
    delete_expired_sessions, delete_oauth_sessions_for_user, delete_session_by_token_hash,
    delete_sessions_for_user, get_session_by_token_hash,
};

// Re-export authenticator types and functions
pub use authenticators::{
    Authenticator, AuthenticatorWithUser, CreateAuthenticatorParams, count_authenticators_for_user,
    count_sessions_for_authenticator, create_authenticator, delete_authenticator,
    delete_authenticator_in_tx, get_authenticator_by_credential_id, get_authenticator_by_id,
    get_authenticator_with_user_by_credential_id, get_authenticators_for_user,
    update_authenticator_counter, update_authenticator_name,
};

// Re-export organization types and functions
pub use documents::organization::{AdditionalDomain, UNVERIFY_FAILURE_THRESHOLD};
pub use organizations::{
    AddedDomain, DomainRemovalSummary, MAX_ADDITIONAL_DOMAINS, Organization, RecheckEffect,
    RecheckOutcome, StaleDomainRemoval, VerifiedDomainRecord, add_additional_domain,
    cleanup_stale_additional_domains, delete_organization, get_organization,
    get_organization_domain, get_verification_token, list_additional_domains,
    list_all_verified_additional_domains, mark_additional_domain_verified, normalize_domain,
    record_recheck_result, remove_additional_domain, unicode_form,
};

// Re-export organization test helpers (only available in tests)
#[cfg(any(test, feature = "test-utils"))]
pub use organizations::create_organization;

// Re-export device auth types and functions
pub use device_auth::{
    DeviceAuthRequest, DeviceAuthStatus, OidcState, authorize_device_auth,
    create_device_auth_request, create_oidc_state, delete_expired_device_auth_requests,
    delete_expired_oidc_states, delete_oidc_state, deny_device_auth, get_device_auth_by_code_hash,
    get_device_auth_by_user_code, get_oidc_state, try_consume_device_auth, try_consume_oidc_state,
    update_device_auth_poll_time,
};
pub(crate) use device_auth::{DeviceCodeClaim, OidcStateClaim};

// Re-export device auth test helpers (only available in tests)
#[cfg(test)]
pub(crate) use device_auth::get_device_auth_by_id;

// Re-export config and auth event types and functions
pub use config::{AuthEventParams, AuthEventType, delete_old_auth_events, spawn_audit_event};

// Re-export SCIM types and functions
pub use scim::{
    ScimFilterError, ScimGroupMemberRecord, ScimGroupRecord, ScimScope, ScimScopeSet, ScimToken,
    ScimUserRecord, add_scim_group_member, create_scim_group, create_scim_token, create_scim_user,
    delete_old_scim_audit_logs, delete_scim_group, delete_scim_token, get_scim_group,
    get_scim_group_by_name, get_scim_group_members, get_scim_token_by_hash, get_scim_user,
    get_user_scim_groups, insert_scim_audit, list_scim_groups, list_scim_tokens, list_scim_users,
    remove_scim_group_member, replace_scim_group_members, update_scim_group,
    update_scim_token_last_used, update_scim_user,
};

// Re-export OAuth enum types from the document layer (single source of truth)
pub use documents::audit::GitHubCredentialAuditData;
pub use documents::oauth::{
    AccessScope, FapiProfile, JwsAlgorithm, OAuthClientType, RegistrationSource, ResponseMode,
    TokenEndpointAuthMethod,
};

// Re-export OAuth domain types and functions
pub(crate) use oauth::JwtAssertionJtiClaim;
pub use oauth::{
    CreateOAuthClientParams, MAX_ACTIVE_SECRETS, MAX_POST_LOGOUT_REDIRECT_URIS, OAuthClient,
    OAuthClientSecret, OAuthEventType, OAuthUsageStats, UpdateClientRegistrationParams,
    UpdateOAuthClientParams, create_oauth_client, create_oauth_client_secret,
    delete_expired_jwt_assertion_jtis, delete_oauth_client, delete_old_oauth_usage_events,
    get_oauth_client_by_client_id, get_oauth_client_by_id, get_oauth_client_secret_by_id,
    get_oauth_client_secrets, get_oauth_clients_for_user, get_oauth_secret_by_hash,
    get_oauth_usage_stats, is_valid_post_logout_redirect_uri_str, record_oauth_event,
    revoke_all_oauth_client_secrets, revoke_oauth_client_secret, store_jwt_assertion_jti,
    update_oauth_client, update_oauth_client_last_used, update_oauth_client_registration,
    validate_oauth_client_credentials,
};

// Re-export test-only OAuth client helpers
#[cfg(test)]
pub use oauth::test_helpers::{set_oauth_client_active, set_oauth_client_userinfo_alg};

// Re-export JWKS cache functions
pub use jwks_cache::{
    delete_expired_jwks_caches, delete_jwks_cache, get_jwks_cache, upsert_jwks_cache,
};

// Re-export DPoP types and functions (RFC 9449)
pub use dpop::{
    check_and_store_dpop_jti, delete_expired_dpop_jtis, delete_expired_dpop_nonces,
    generate_dpop_nonce, validate_and_consume_dpop_nonce,
};

// Re-export credentials types and functions
pub use credentials::{
    EnrollmentSession, InsertTokenExchangeParams, IssuedSshCertificate, RevokedSshCertificate,
    TokenExchangeRecord, create_enrollment_session, delete_expired_enrollment_sessions,
    delete_expired_ssh_issued_certs, delete_expired_ssh_revocations, delete_old_token_exchanges,
    get_enrollment_session_by_token_hash, get_issued_ssh_certificates_for_user,
    get_revoked_ssh_certificates, get_token_exchanges_for_user, insert_token_exchange,
    is_ssh_certificate_revoked, record_ssh_certificate_issuance,
    revoke_all_ssh_certificates_for_user, revoke_ssh_certificate,
};

// Re-export GitHub types and functions
pub use github::{
    CreateGitHubInstallationParams, GitHubInstallation, create_github_installation,
    delete_github_installation_by_installation_id, delete_old_github_credential_events,
    get_all_linked_installation_ids, get_github_installation_by_installation_id,
    get_github_installation_by_org_and_account, get_github_installations_by_org,
    log_github_credential_event, suspend_github_installation, unsuspend_github_installation,
    update_github_installation_repos, update_github_installation_repos_delta,
};

// Re-export PAR types and functions (RFC 9126)
pub(crate) use par::create_pushed_authorization_request;
pub use par::{
    CreateParParams, PAR_EXPIRES_IN, ParConsumptionMode, PushedAuthorizationRequest,
    consume_pushed_authorization_request, delete_expired_pushed_authorization_requests,
    extend_par_expiration, get_pushed_authorization_request,
};

// Re-export pending OAuth types and functions (RFC 6749, RFC 9700)
pub(crate) use pending_oauth::consume_pending_oauth_authorization;
pub use pending_oauth::{
    CreatePendingOAuthParams, PendingOAuthAuthorization, create_pending_oauth_authorization,
    delete_expired_pending_oauth_authorizations, get_pending_oauth_authorization,
};

// Re-export challenge state functions (FIDO2 single-use enforcement)
pub(crate) use challenge_states::ChallengeStateClaim;
pub use challenge_states::{delete_expired_challenge_states, try_consume_challenge_state};

// Re-export claim error type so handlers can pattern-match on it.
pub(crate) use claim::ClaimError;

// Re-export authorization code functions (RFC 6749 Section 10.5)
pub(crate) use authorization_codes::AuthCodeClaim;
pub use authorization_codes::{
    delete_expired_authorization_codes, get_authorization_code_details,
    get_authorization_code_owner, get_consumed_code_owner, is_authorization_code_consumed,
    store_authorization_code, try_consume_authorization_code,
};

// Re-export enrollment types and functions
pub use enrollment::{EnrolledUser, EnrollmentResult, enroll_user_with_org};

// Re-export posture policy types and functions
pub use posture_policies::{
    CreateCustomPolicyParams, CustomPosturePolicy, FieldUpdate, UpdateCustomPolicyParams,
    create_custom_policy, delete_custom_policy, get_active_custom_policies,
    get_active_preconfigured_slugs, get_custom_policy, list_custom_policies,
    set_preconfigured_active, update_custom_policy,
};

#[cfg(test)]
mod tests;
