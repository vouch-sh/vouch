// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Token endpoint operations.
//!
//! Implements:
//! - RFC 6749 Section 4.1 - Authorization Code Grant
//! - RFC 7636 - PKCE (Proof Key for Code Exchange)
//! - RFC 9449 - DPoP (Demonstrating Proof of Possession)

use super::authorization_details::AuthorizationDetails;
use super::dpop::{self, CnfClaim, DpopError, ValidatedDpopProof};
use super::scope::{OAuthScope, ScopeSet};
use crate::AppState;
use crate::assurance::{ACR_AAL3, AuthMethod, HardwareVerification};
use crate::crypto::hash_token;
use crate::db::{self, Authenticator, OAuthClient, User};
use crate::error::{OAuthErrorCode, ServiceError, ServiceResult};
use crate::infra::jwks::JwksOrigin;
use crate::redact_email;
use crate::services::auth::{
    ClientAuthProof, CreateOAuthTokenParams, GrantProof, SenderConstraintProof, TokenBinding,
    TokenIssuanceProof, create_oauth_access_token, decode_token,
};
use aws_lc_rs::digest::{self, SHA256};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use subtle::ConstantTimeEq;

use super::authorization::{AuthorizationCode, decode_authorization_code};

/// Parameters for exchanging an authorization code for tokens (RFC 6749 Section 4.1.3).
///
/// The handler runs all client authentication (JWT, mTLS, secret, public-client
/// validation) BEFORE calling `exchange_authorization_code`, then passes the
/// fully-resolved [`AuthenticatedClient`] here. The exchange function only
/// re-checks that the authenticated client matches the auth code's recorded
/// client_id — it never runs an authentication step of its own.
#[derive(Debug)]
pub struct AuthCodeExchangeParams<'a> {
    /// RFC 6749 Section 4.1.3: The authorization code received from the authorization server.
    pub code: &'a str,
    /// RFC 6749 Section 4.1.3: The redirect URI (REQUIRED if included in authorization request).
    pub redirect_uri: Option<&'a str>,
    /// RFC 6749 Section 2.3 / RFC 7523 Section 2.2 / RFC 8705 Section 2:
    /// The client resolved by the handler, regardless of which
    /// authentication method (`client_secret_basic`/`client_secret_post`,
    /// `private_key_jwt`, `tls_client_auth`/`self_signed_tls_client_auth`,
    /// or public-client validation) succeeded. The handler runs all
    /// authentication so that `exchange_authorization_code` receives a
    /// fully-resolved `AuthenticatedClient` and never re-runs an auth
    /// step. `None` only when the handler was unable to determine the
    /// client — exchange treats that as invalid_client.
    pub authenticated_client: Option<&'a AuthenticatedClient>,
    /// RFC 7636 Section 4.5: The PKCE code verifier.
    pub code_verifier: Option<&'a str>,
    /// RFC 9449 §6 / RFC 8705 §3: how the issued token is bound.
    pub binding: TokenBinding<'a>,
    /// RFC 8725 §3.9: Client ID for audience validation of the authorization code.
    pub client_id: &'a str,
    /// RFC 8707 Section 2: Target resource indicator (OPTIONAL).
    pub resource: Option<&'a str>,
    /// RFC 9396 Section 6: Authorization details for downscoping.
    pub authorization_details: Option<&'a str>,
}

/// Client credentials for authentication (RFC 6749 Section 2.3).
///
/// Supports `client_secret_basic` (RFC 6749 Section 2.3.1) and
/// `client_secret_post` (RFC 6749 Section 2.3.1) authentication methods.
///
/// The client secret is wrapped in `SecretString` to prevent accidental logging
/// and ensure it is zeroized on drop.
#[derive(Debug)]
pub struct ClientCredentials {
    /// Client ID (RFC 6749 Section 2.2).
    pub client_id: String,
    /// Client secret (optional for public clients per RFC 6749 Section 2.1).
    pub client_secret: Option<SecretString>,
}

/// Result of exchanging an authorization code.
pub struct AuthCodeExchangeResult {
    /// The access token.
    pub access_token: SecretString,
    /// Token type ([`protocol::ACCESS_TOKEN_TYPE_BEARER`] or
    /// [`protocol::ACCESS_TOKEN_TYPE_DPOP`]).
    pub token_type: String,
    /// Expiration in seconds.
    pub expires_in: u64,
    /// The ID token (JWT).
    pub id_token: SecretString,
    /// Granted scope.
    pub scope: ScopeSet,
    /// RFC 9396: Rich authorization details.
    pub authorization_details: Option<AuthorizationDetails>,
}

// Custom Debug that redacts access_token and id_token to prevent accidental
// log exposure of bearer credentials (matches the AwsTokenResult pattern).
impl std::fmt::Debug for AuthCodeExchangeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthCodeExchangeResult")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("id_token", &"[REDACTED]")
            .field("scope", &self.scope)
            .field("authorization_details", &self.authorization_details)
            .finish()
    }
}

/// Authenticated client information.
#[derive(Debug)]
pub struct AuthenticatedClient {
    /// The OAuth client record.
    pub client: OAuthClient,
    /// Whether this is a public client (no secret required).
    pub is_public: bool,
}

/// Witness that an OAuth client successfully authenticated via
/// `client_secret_basic` / `client_secret_post` (RFC 6749 Section 2.3.1).
///
/// Construction is private to this module — the only path to an instance
/// is a successful return from [`authenticate_client`] when the client's
/// stored secret hash matched the constant-time comparison against the
/// caller-supplied secret. Holding this witness is compile-time evidence
/// that secret-based client auth succeeded for this request.
///
/// Intentionally not `Clone`. The `#[must_use]` ensures the witness is
/// bound at the call site (typically threaded into
/// `ClientAuthProof::ClientSecret(verification)`).
#[must_use = "client_secret authentication succeeded; bind this witness so \
              it can be threaded into the ClientAuthProof"]
#[derive(Debug)]
pub struct ClientSecretVerification {
    _private: (),
}

/// Witness that an OAuth client successfully authenticated via mTLS
/// (RFC 8705 Section 2) — either PKI (`tls_client_auth`) or self-signed
/// (`self_signed_tls_client_auth`).
///
/// Construction is private to this module — the only path to an instance
/// is a successful return from [`authenticate_client_mtls`] after the
/// presented certificate validated against the client's registered
/// identity (subject DN / SAN) or its self-signed x5c JWKS entry.
///
/// Intentionally not `Clone`. The `#[must_use]` ensures the witness is
/// bound at the call site (typically threaded into
/// `ClientAuthProof::MutualTls(verification)`).
#[must_use = "mTLS client authentication succeeded; bind this witness so \
              it can be threaded into the ClientAuthProof"]
#[derive(Debug)]
pub struct MtlsCertVerification {
    _private: (),
}

impl MtlsCertVerification {
    /// Test-only constructor. Production code must obtain a verification via
    /// [`authenticate_client_mtls`].
    #[cfg(test)]
    pub(crate) fn for_testing() -> Self {
        Self { _private: () }
    }
}

/// Client authentication error.
#[derive(Debug)]
pub enum ClientAuthError {
    /// Missing client_id parameter.
    MissingClientId,
    /// Client not found or inactive.
    InvalidClient,
    /// Invalid client credentials.
    InvalidCredentials,
    /// Client requires secret but none provided.
    SecretRequired,
    /// Database error.
    DatabaseError(String),
    /// mTLS certificate verification failed.
    MtlsVerificationFailed(String),
}

/// A failed database call is a server fault, never a statement about the
/// client's credentials.
///
/// This exists so `?` on a database call yields [`ClientAuthError::DatabaseError`]
/// — which maps to `server_error` / HTTP 500, letting the client retry — rather
/// than requiring every call site to remember. Reporting a transient outage as
/// `invalid_client` tells a client its credentials are wrong, so it stops
/// retrying and may discard them; that is how the JWKS cache read came to fail
/// authentication for clients that never needed the cache.
impl From<anyhow::Error> for ClientAuthError {
    fn from(err: anyhow::Error) -> Self {
        Self::DatabaseError(err.to_string())
    }
}

impl ClientAuthError {
    /// Convert to `ServiceError`.
    #[must_use]
    pub fn into_service_error(self) -> ServiceError {
        match self {
            Self::MissingClientId => ServiceError::oauth(
                OAuthErrorCode::InvalidRequest,
                "Missing client_id parameter",
            ),
            Self::InvalidClient
            | Self::InvalidCredentials
            | Self::SecretRequired
            | Self::MtlsVerificationFailed(_) => ServiceError::oauth(
                OAuthErrorCode::InvalidClient,
                "Client authentication failed",
            ),
            Self::DatabaseError(msg) => ServiceError::Internal(msg),
        }
    }
}

/// OIDC ID Token claims (OIDC Core Section 2).
#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// OIDC Core Section 2: Issuer Identifier.
    pub iss: String,
    /// OIDC Core Section 2: Subject Identifier (stable user ID, not email).
    pub sub: String,
    /// OIDC Core Section 2: Audience(s).
    pub aud: String,
    /// OIDC Core Section 2: Expiration time.
    pub exp: i64,
    /// OIDC Core Section 2: Issued at time.
    pub iat: i64,
    /// OIDC Core Section 2: Time when the End-User authentication occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    /// OIDC Core Section 3.1.2.1: Nonce value from the authorization request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// OIDC Core Section 5.1: User email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// OIDC Core Section 5.1: Whether the email has been verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Custom claim: Hardware verification flag (FIDO2 presence proof).
    ///
    /// Excluded from standard OIDC id_tokens for conformance. Set to `None`
    /// here. `OidcIdTokenClaims` (cloud federation) retains this claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_verified: Option<bool>,
    /// Custom claim: Hardware authenticator AAGUID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_aaguid: Option<String>,
    /// RFC 9449 Section 6: DPoP token binding confirmation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<CnfClaim>,
    /// RFC 9068 Section 2.2 / RFC 8176: Authentication methods used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<AuthMethod>>,
    /// RFC 9068 Section 2.2: Authentication context class reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// OIDC Core Section 3.1.3.6: Access Token hash value.
    /// Base64url encoding of the left half of SHA-256(access_token).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
}

/// The [`IdTokenClaims`] fields advertised in discovery's
/// `claims_supported`, kept next to the struct they mirror. The custom
/// claims (`hardware_verified`, `hardware_aaguid`) and `cnf` are emitted
/// but deliberately not advertised. A drift test serializes a fully
/// populated [`IdTokenClaims`] and checks its keys against this list.
pub(crate) const ADVERTISED_ID_TOKEN_CLAIMS: &[&str] = &[
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "at_hash",
    "email",
    "email_verified",
    "amr",
    "acr",
];

/// Exchange an authorization code for tokens.
///
/// # Arguments
/// * `state` - Application state
/// * `params` - Exchange parameters
///
/// # Returns
/// The token response.
///
/// # Errors
/// Returns `ServiceError` for invalid requests.
pub(crate) async fn exchange_authorization_code(
    state: &Arc<AppState>,
    params: AuthCodeExchangeParams<'_>,
    client_auth: ClientAuthProof,
    sender_constraint: SenderConstraintProof,
) -> ServiceResult<AuthCodeExchangeResult> {
    // Decode and validate the authorization code
    let auth_code = decode_authorization_code(state, params.code, params.client_id).await?;

    // RFC 6749 Section 10.5: Enforce single-use authorization codes.
    // This MUST happen before any other validation to ensure codes are always
    // consumed, enabling replay detection regardless of subsequent check outcomes.
    // The returned witness is the structural proof threaded into the
    // TokenIssuanceProof below — the only path to `GrantProof::AuthorizationCode`.
    let code_hash = hash_token(params.code);
    let auth_code_claim = enforce_single_use_code(state, &code_hash, &auth_code).await?;

    let user = load_and_validate_grant_subject(state, &auth_code).await?;

    let authenticated_client = params.authenticated_client;
    verify_client_matches_code(authenticated_client, &auth_code)?;

    // Validate redirect_uri, PKCE, DPoP binding, and ACR
    validate_code_bindings(
        &auth_code,
        params.redirect_uri,
        params.code_verifier,
        params.binding.dpop_proof(),
    )?;

    // RFC 9396 + RFC 8707: Resolve authorization details and resource audience
    let grants = resolve_authorization_details(
        state,
        &code_hash,
        params.authorization_details,
        &auth_code,
        params.resource,
    )
    .await?;

    // Org domain, read once at session creation for the federation claims.
    let org_domain = match user.org_id.as_deref() {
        Some(org_id) => {
            db::get_user_org_domain(&state.store, &user.id, org_id, user.org_domain.as_deref())
                .await
                .map_err(|e| ServiceError::Internal(e.to_string()))?
        }
        None => None,
    };

    // Generate access token as an RFC 9068 JWT (ES256, verifiable via JWKS).
    // Build the chokepoint proof here: `GrantProof::AuthorizationCode` can
    // only be constructed by code that holds an AuthCodeClaim, which is
    // produced by `enforce_single_use_code` above.
    let proof = TokenIssuanceProof {
        grant: GrantProof::AuthorizationCode(auth_code_claim),
        client_auth,
        sender_constraint,
    };
    let session_result = create_oauth_access_token(
        state,
        CreateOAuthTokenParams {
            user_id: &auth_code.user_id,
            email: &auth_code.email,
            authenticator_id: Some(&auth_code.authenticator_id),
            client_id: &auth_code.client_id,
            scope: Some(auth_code.scope.clone()),
            binding: params.binding,
            act: None,
            audience: grants.audience.as_deref(),
            max_lifetime_secs: None,
            hardware_verification: HardwareVerification::Verified {
                auth_time: auth_code.auth_time,
            },
            session_purpose: db::SessionPurpose::OAuthAccessToken,
            authorization_details: grants.authorization_details_value.as_ref(),
            hardware_aaguid: auth_code.aaguid.as_deref(),
            org_domain: org_domain.as_deref(),
            // Link this session to the consumed authorization code so replay
            // detection (enforce_single_use_code above) can revoke only this
            // code's tokens per RFC 6749 Section 10.5.
            source_code_hash: Some(&code_hash),
        },
        proof,
    )
    .await?;
    let access_token = session_result.token;
    let expires_in = session_result.expires_in;

    // Extract the per-client ID token signing algorithm.
    // Public/unauthenticated clients fall back to "RS256" per OIDC Core default.
    let id_token_alg =
        authenticated_client.map_or("RS256", |c| c.client.id_token_signed_response_alg.as_str());

    // Generate ID token (with at_hash computed from the access token)
    let id_token = generate_id_token(
        state,
        IdTokenParams {
            client_id: &auth_code.client_id,
            user_id: &auth_code.user_id,
            email: &auth_code.email,
            nonce: auth_code.nonce.as_deref(),
            expires_in,
            binding: params.binding,
            scope: &auth_code.scope,
            hardware_verification: HardwareVerification::Verified {
                auth_time: auth_code.auth_time,
            },
            access_token: Some(access_token.expose_secret()),
            id_token_alg,
        },
    )
    .await?;

    // Record usage event for registered clients
    if let Some(auth_client) = authenticated_client {
        // The user-org half of `resolve_event_org_domain`'s "prefer user,
        // fall back to client" rule was already resolved above for the
        // session claims, so it's reused here rather than re-derived; the
        // client-org fallback still runs its own lookup when the user has no
        // org, using the client already in scope instead of re-fetching it
        // by id.
        let audit_org_domain = db::resolve_event_org_domain(
            &state.store,
            org_domain.as_deref(),
            auth_client.client.org_id.as_deref(),
        )
        .await;
        db::record_oauth_event(
            &state.audit,
            &state.store,
            &db::RecordOAuthEventParams {
                oauth_client_id: &auth_client.client.id,
                event_type: db::OAuthEventType::TokenIssued,
                user_id: Some(&auth_code.user_id),
                ip_address: None,
                user_agent: None,
                details: params
                    .binding
                    .dpop_proof()
                    .map(|p| format!("dpop_jkt={}", p.jkt))
                    .as_deref(),
                org_domain: db::RecordedOrgDomain::Known(audit_org_domain.as_deref()),
            },
        )
        .await;
    }

    if let Some(proof) = params.binding.dpop_proof() {
        tracing::info!(
            "Issued DPoP-bound token for user {} with jkt={}",
            redact_email(&auth_code.email),
            proof.jkt
        );
    }

    Ok(AuthCodeExchangeResult {
        access_token,
        token_type: session_result.token_type.to_string(),
        expires_in,
        id_token: id_token.into(),
        scope: auth_code.scope,
        authorization_details: grants.authorization_details,
    })
}

/// Load the authorization code's subject and reject grants whose user is
/// deactivated or whose authenticator has been revoked or deleted (GH#272).
///
/// # Errors
/// Returns `invalid_grant` when the user or authenticator no longer
/// qualifies for token issuance.
async fn load_and_validate_grant_subject(
    state: &Arc<AppState>,
    auth_code: &AuthorizationCode,
) -> ServiceResult<db::User> {
    // Reject deactivated users before issuing tokens
    let user = db::get_user_by_id(&state.store, &auth_code.user_id)
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))?
        .ok_or(ServiceError::oauth(
            OAuthErrorCode::InvalidGrant,
            "User not found",
        ))?;
    if !user.active {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidGrant,
            "User account is deactivated",
        ));
    }

    // Reject tokens for revoked/deleted authenticators (GH#272)
    db::get_authenticator_by_id(&state.store, &auth_code.authenticator_id)
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))?
        .ok_or(ServiceError::oauth(
            OAuthErrorCode::InvalidGrant,
            "Authenticator not found",
        ))?;

    Ok(user)
}

/// RFC 6749 Section 4.1.3: Verify the handler-authenticated client matches
/// the authorization code's recorded client_id, and that PKCE (RFC 7636) is
/// present when required for this client type. Client authentication itself
/// (RFC 6749 §2.3 / RFC 7523 §2.2 / RFC 8705) ran at the handler before
/// `exchange_authorization_code` was called; this only checks consistency
/// with the auth code.
///
/// # Errors
/// Returns `invalid_grant` on client mismatch and `invalid_request` when a
/// required PKCE challenge is absent.
fn verify_client_matches_code(
    authenticated_client: Option<&AuthenticatedClient>,
    auth_code: &AuthorizationCode,
) -> ServiceResult<()> {
    if let Some(client) = authenticated_client
        && client.client.client_id != auth_code.client_id
    {
        tracing::warn!(
            "Client ID mismatch: token request from {} but code was issued to {}",
            client.client.client_id,
            auth_code.client_id
        );
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidGrant,
            "Client ID mismatch",
        ));
    }
    if let Some(client) = authenticated_client {
        let pkce_required = client.is_public || client.client.application_type.requires_pkce();
        if pkce_required && auth_code.code_challenge.is_none() {
            tracing::warn!(
                "Client {} requires PKCE but no code_challenge was present",
                client.client.client_id
            );
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequest,
                "PKCE required for this client type",
            ));
        }
    }
    Ok(())
}

/// Result of resolving authorization details and resource audience.
struct ResolvedGrants {
    authorization_details: Option<AuthorizationDetails>,
    authorization_details_value: Option<serde_json::Value>,
    audience: Option<String>,
}

/// RFC 6749 Section 10.5: Enforce single-use authorization codes.
///
/// Atomically consumes the code; on success returns an [`crate::db::AuthCodeClaim`]
/// witness. On a replay (`ClaimError::AlreadyConsumed`), revokes only the tokens
/// issued from **that** authorization code (RFC 6749 Section 10.5) before
/// returning the OAuth `invalid_grant` error.
///
/// The consume here and the session insert in
/// [`exchange_authorization_code`] are separate writes, so a replay arriving
/// between them finds no session carrying the code hash and revokes nothing —
/// the legitimate exchange then completes and its token survives. Closing the
/// window means issuing the session in the same transaction that consumes the
/// code, which DSQL's optimistic concurrency cannot express across the two
/// document types. Section 10.5 states the revocation as a SHOULD ("the
/// authorization server SHOULD attempt to revoke"), and the MUST — denying the
/// replayed request — holds regardless, since the deny is driven by the
/// consume, not by the revocation.
async fn enforce_single_use_code(
    state: &Arc<AppState>,
    code_hash: &str,
    auth_code: &AuthorizationCode,
) -> ServiceResult<crate::db::AuthCodeClaim> {
    match db::try_consume_authorization_code(&state.store, code_hash).await {
        Ok(claim) => Ok(claim),
        Err(db::claim::ClaimError::AlreadyConsumed) => {
            tracing::warn!(
                target: "security",
                client_id = %auth_code.client_id,
                user_id = %auth_code.user_id,
                "Authorization code replay detected — code already consumed"
            );
            // RFC 6749 Section 10.5: revoke "all access tokens already granted
            // based on the compromised authorization code" — which bounds the
            // revocation to this code rather than widening it to every session
            // for the user. Sessions store `source_code_hash = code_hash` at
            // issuance, so this targets exactly the compromised code's tokens
            // and leaves the user's other sessions (other codes, FIDO2,
            // browser login, …) intact.
            match db::delete_sessions_for_code_replay(&state.store, code_hash).await {
                Ok(token_hashes) if !token_hashes.is_empty() => {
                    for token_hash in &token_hashes {
                        state.session_cache.invalidate(token_hash);
                    }
                    tracing::warn!(
                        target: "security",
                        user_id = %auth_code.user_id,
                        revoked_count = token_hashes.len(),
                        "Revoked OAuth tokens issued from the replayed authorization code"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::error!("Failed to revoke tokens during replay detection: {e}");
                }
            }
            Err(ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "Authorization code has already been used",
            ))
        }
        Err(e) => {
            tracing::error!("Failed to consume authorization code: {}", e);
            Err(ServiceError::Internal(
                "Failed to validate authorization code".to_string(),
            ))
        }
    }
}

/// Validate redirect URI, PKCE, DPoP binding, and ACR constraints.
fn validate_code_bindings(
    auth_code: &AuthorizationCode,
    redirect_uri: Option<&str>,
    code_verifier: Option<&str>,
    dpop_proof: Option<&ValidatedDpopProof>,
) -> ServiceResult<()> {
    // RFC 6749 Section 4.1.3: redirect_uri must match if present in authorization request
    if !auth_code.redirect_uri.is_empty() {
        match redirect_uri {
            Some(uri) if uri != auth_code.redirect_uri => {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidGrant,
                    "Redirect URI mismatch",
                ));
            }
            None => {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidRequest,
                    "redirect_uri is required when it was included \
                     in the authorization request",
                ));
            }
            _ => {}
        }
    }

    auth_code.validate_pkce(code_verifier)?;

    // FAPI 2.0 / RFC 9449 Section 10: Verify DPoP authorization code binding
    if let Some(ref bound_jkt) = auth_code.dpop_jkt {
        let proof_jkt = match dpop_proof {
            Some(proof) => &proof.jkt,
            None => {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidGrant,
                    "Authorization code is bound to a DPoP key \
                     but no DPoP proof was provided",
                ));
            }
        };
        let is_match: bool = bound_jkt.as_bytes().ct_eq(proof_jkt.as_bytes()).into();
        if !is_match {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "DPoP key does not match the key bound during authorization",
            ));
        }
    }

    // RFC 9470 Section 4: Defense-in-depth ACR validation
    if let Some(ref acr_values) = auth_code.acr_values {
        let acr_ok = acr_values.split_whitespace().any(|v| v == ACR_AAL3);
        if !acr_ok {
            return Err(ServiceError::oauth(
                OAuthErrorCode::UnmetAuthenticationRequirements,
                "The requested authentication context class cannot be satisfied",
            ));
        }
    }

    Ok(())
}

/// Resolve authorization details and resource audience for the token.
///
/// Retrieves granted authorization details from storage, validates any
/// downscoping request, and verifies resource indicator consistency.
async fn resolve_authorization_details(
    state: &Arc<AppState>,
    code_hash: &str,
    requested_ad_raw: Option<&str>,
    auth_code: &AuthorizationCode,
    requested_resource: Option<&str>,
) -> ServiceResult<ResolvedGrants> {
    let granted_ad_value = db::get_authorization_code_details(&state.store, code_hash)
        .await
        .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?;
    let granted_ad = granted_ad_value
        .as_ref()
        .and_then(|v| AuthorizationDetails::try_from(v).ok());

    // RFC 9396 Section 6: Validate downscoping if requested
    let (authorization_details, authorization_details_value);
    if let Some(raw) = requested_ad_raw {
        let requested_ad = AuthorizationDetails::parse(raw)?;
        match &granted_ad {
            Some(granted) => {
                if !requested_ad.is_subset_of(granted) {
                    return Err(ServiceError::oauth(
                        OAuthErrorCode::InvalidAuthorizationDetails,
                        "Requested authorization_details is not a \
                         subset of the granted authorization_details",
                    ));
                }
            }
            None => {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidAuthorizationDetails,
                    "authorization_details was not granted \
                     during authorization",
                ));
            }
        }
        authorization_details_value = Some(serde_json::Value::from(&requested_ad));
        authorization_details = Some(requested_ad);
    } else {
        authorization_details_value = granted_ad_value;
        authorization_details = granted_ad;
    }

    // RFC 8707: Resource narrowing
    let audience = match (auth_code.resource.as_deref(), requested_resource) {
        (Some(granted), Some(requested)) if granted != requested => {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidTarget,
                "Resource parameter does not match the value \
                 from the authorization request",
            ));
        }
        (Some(granted), _) => Some(granted.to_string()),
        (None, Some(_)) => {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidTarget,
                "Resource was not requested during authorization",
            ));
        }
        (None, None) => None,
    };

    Ok(ResolvedGrants {
        authorization_details,
        authorization_details_value,
        audience,
    })
}

impl AuthorizationCode {
    /// Validate PKCE code verifier against code challenge (RFC 7636 Section 4.6).
    ///
    /// Uses constant-time comparison to prevent timing side-channel attacks.
    ///
    /// RFC 9700 §4.8.2: "Beyond this, to prevent PKCE downgrade attacks, the
    /// authorization server MUST ensure that if there was no code_challenge in
    /// the authorization request, a request to the token endpoint containing a
    /// code_verifier is rejected." A `code_verifier` the client believes it
    /// sent a challenge for, arriving against a code that carries none, is the
    /// observable signature of the stripped-parameter attack in §4.8.1 — so it
    /// fails rather than being ignored.
    fn validate_pkce(&self, code_verifier: Option<&str>) -> ServiceResult<()> {
        let Some(code_challenge) = &self.code_challenge else {
            if code_verifier.is_some() {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidGrant,
                    "code_verifier was sent but the authorization request \
                     carried no code_challenge",
                ));
            }
            return Ok(());
        };

        let code_verifier = code_verifier.ok_or_else(|| {
            ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Missing code_verifier")
        })?;

        let computed_challenge = {
            let hash = digest::digest(&SHA256, code_verifier.as_bytes());
            URL_SAFE_NO_PAD.encode(hash.as_ref())
        };

        // Use constant-time comparison to prevent timing side-channel attacks
        let is_valid: bool = computed_challenge
            .as_bytes()
            .ct_eq(code_challenge.as_bytes())
            .into();

        if !is_valid {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "Invalid code_verifier",
            ));
        }

        Ok(())
    }
}

/// Authenticate an OAuth client using client credentials (RFC 6749 Section 2.3).
///
/// Supports:
/// - Confidential clients with `client_secret` (RFC 6749 Section 2.3.1)
/// - Public clients (native/SPA) without secret (must use PKCE per RFC 7636)
///
/// The returned `Option<ClientSecretVerification>` is `Some` only when the
/// client_secret was validated against its stored hash. For mTLS-registered
/// clients (whose secret is intentionally skipped here and the cert
/// validated separately by [`authenticate_client_mtls`]) and public
/// clients (no auth), the option is `None`.
pub async fn authenticate_client(
    state: &Arc<AppState>,
    credentials: &ClientCredentials,
) -> Result<(AuthenticatedClient, Option<ClientSecretVerification>), ClientAuthError> {
    // Look up the client
    let client = db::get_oauth_client_by_client_id(&state.store, &credentials.client_id)
        .await?
        .ok_or(ClientAuthError::InvalidClient)?;

    // Check if client is active
    if !client.active {
        return Err(ClientAuthError::InvalidClient);
    }

    // Determine if this client type requires a secret
    let requires_secret = client.application_type.requires_secret();

    // RFC 8705: mTLS clients authenticate via certificate, not secret.
    // When a confidential client uses tls_client_auth or self_signed_tls_client_auth,
    // the secret is not required — the certificate is validated separately.
    let is_mtls_auth = matches!(
        client.token_endpoint_auth_method,
        crate::db::TokenEndpointAuthMethod::TlsClientAuth
            | crate::db::TokenEndpointAuthMethod::SelfSignedTlsClientAuth
    );

    if requires_secret && is_mtls_auth {
        // mTLS client — skip secret validation, return as confidential.
        // The certificate will be validated by authenticate_client_mtls().
        if let Err(e) = db::update_oauth_client_last_used(&state.store, &client.id).await {
            tracing::warn!("Failed to update OAuth client last_used: {e}");
        }
        return Ok((
            AuthenticatedClient {
                client,
                is_public: false,
            },
            None,
        ));
    }

    if requires_secret {
        // Secret is required - validate it
        let secret = credentials
            .client_secret
            .as_ref()
            .ok_or(ClientAuthError::SecretRequired)?;

        // Hash the provided secret and validate against stored hash
        let secret_hash = hash_token(secret.expose_secret());

        // Validate credentials
        let validated = db::validate_oauth_client_credentials(
            &state.store,
            &credentials.client_id,
            &secret_hash,
        )
        .await?;

        if validated.is_none() {
            return Err(ClientAuthError::InvalidCredentials);
        }

        Ok((
            AuthenticatedClient {
                client,
                is_public: false,
            },
            Some(ClientSecretVerification { _private: () }),
        ))
    } else {
        // Public client - no secret required, but PKCE should be used
        // Update last used timestamp
        if let Err(e) = db::update_oauth_client_last_used(&state.store, &client.id).await {
            tracing::warn!("Failed to update OAuth client last_used: {e}");
        }

        Ok((
            AuthenticatedClient {
                client,
                is_public: true,
            },
            None,
        ))
    }
}

/// Compute `at_hash` per OIDC Core Section 3.1.3.6.
///
/// Returns the base64url encoding (no padding) of the left half of SHA-256
/// of the access token string. For SHA-256 (32 bytes), the left half is 16 bytes,
/// producing a 22-character base64url string.
fn compute_at_hash(access_token: &str) -> Option<String> {
    let hash = digest::digest(&SHA256, access_token.as_bytes());
    let left_half = hash.as_ref().get(..16)?;
    Some(URL_SAFE_NO_PAD.encode(left_half))
}

/// Parameters for ID token generation.
struct IdTokenParams<'a> {
    client_id: &'a str,
    user_id: &'a str,
    email: &'a str,
    nonce: Option<&'a str>,
    expires_in: u64,
    /// RFC 9449 §6 / RFC 8705 §3 / RFC 7800 §3.1: how this ID token is bound.
    /// The same binding the access token carries, so a client that proved a
    /// key receives the same confirmation on both tokens of one response.
    binding: TokenBinding<'a>,
    scope: &'a ScopeSet,
    /// Authentication assurance level — bundles `auth_time`, `amr`, and `acr`,
    /// so the `auth_time` claim cannot outlive the assertion that earned it.
    hardware_verification: HardwareVerification,
    /// Access token string, used to compute `at_hash` (OIDC Core Section 3.1.3.6).
    access_token: Option<&'a str>,
    /// OIDC Core: Algorithm for signing this ID token.
    id_token_alg: &'a str,
}

/// Generate an OIDC ID token.
async fn generate_id_token(
    state: &Arc<AppState>,
    params: IdTokenParams<'_>,
) -> ServiceResult<String> {
    let now = Timestamp::now();
    let expires_seconds = i64::try_from(params.expires_in)
        .map_err(|_| ServiceError::Internal("Invalid expires_in value".to_string()))?;
    let exp = now
        .as_second()
        .checked_add(expires_seconds)
        .ok_or_else(|| ServiceError::Internal("Expiration time overflow".to_string()))?;

    // RFC 9449 / RFC 8705 / RFC 7800 §3.1: the ID token goes to the client
    // that proved the key, so it carries the same confirmation as the access
    // token issued beside it — `jkt` for DPoP, `x5t#S256` for mTLS.
    let cnf = params.binding.cnf();

    let has_email = params.scope.contains(OAuthScope::Email);

    let claims = IdTokenClaims {
        iss: state.config().base_url.to_string(),
        sub: params.user_id.to_string(),
        aud: params.client_id.to_string(),
        exp,
        iat: now.as_second(),
        auth_time: params.hardware_verification.auth_time(),
        nonce: params.nonce.map(String::from),
        email: if has_email {
            Some(params.email.to_string())
        } else {
            None
        },
        email_verified: if has_email { Some(true) } else { None },
        hardware_verified: None,
        hardware_aaguid: None,
        cnf,
        amr: params.hardware_verification.amr(),
        acr: params.hardware_verification.acr(),
        at_hash: params.access_token.and_then(compute_at_hash),
    };

    // Use RS256 if requested and an RSA key is available; otherwise fall back to ES256.
    // The registration endpoint already rejects RS256 when no RSA key is configured,
    // but manually-created clients and older records carry the RS256 default and must
    // not cause a 500 when no RSA key is provisioned.
    if params.id_token_alg == "RS256" {
        if let Some(rsa_key) = state.oidc_rsa_key.as_ref() {
            return rsa_key
                .sign_jwt(&claims)
                .await
                .map_err(|e| ServiceError::Internal(format!("Failed to generate ID token: {e}")));
        }
        tracing::warn!(
            "RS256 requested but no RSA key configured; falling back to ES256 for ID token"
        );
    }
    state
        .oidc_key
        .sign_jwt(&claims)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to generate ID token: {e}")))
}

/// Resolve a `self_signed_tls_client_auth` client's JWKS as the raw
/// `serde_json::Value` [`crate::services::oidc::mtls::verify_self_signed_tls_client_auth`]
/// expects, reporting whether resolution fetched.
///
/// Mirrors the inline-vs-`jwks_uri` resolution the RFC 7523 client-assertion
/// path uses (`jwt_bearer::jwks::resolve_client_jwks`): an inline `jwks`
/// wins outright; otherwise the client's cached/fetched `jwks_uri` document
/// is resolved via [`crate::infra::jwks::resolve_cached_jwks`] — the same
/// TTL, stale-while-revalidate, and SSRF-guarded fetch primitive, so this
/// path gets those guarantees for free rather than re-implementing them.
/// [`crate::infra::jwks::JwksOrigin`] is that function's own report of
/// whether it fetched, not re-derived here.
async fn resolve_self_signed_jwks(
    state: &Arc<AppState>,
    client: &crate::db::OAuthClient,
    jwks_cache: Option<&crate::db::documents::jwks_cache::JwksCacheDoc>,
) -> ServiceResult<(serde_json::Value, JwksOrigin)> {
    if let Some(jwks) = client.keys.as_ref().and_then(crate::db::ClientKeys::inline) {
        return Ok((
            serde_json::to_value(jwks).unwrap_or_default(),
            JwksOrigin::NoFetch,
        ));
    }
    let Some(uri) = client.keys.as_ref().and_then(crate::db::ClientKeys::uri) else {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "self_signed_tls_client_auth requires jwks or jwks_uri",
        ));
    };
    let allow_loopback = !state.config().tls_configured();
    crate::infra::jwks::resolve_cached_jwks(
        &state.store,
        &client.id,
        uri,
        jwks_cache,
        allow_loopback,
        &state.http_client,
    )
    .await
}

/// Authenticate a client using mTLS certificate (RFC 8705 Section 2).
///
/// Dispatches to the appropriate verification method based on the client's
/// registered `token_endpoint_auth_method`. `tls_client_auth` verifies
/// against the client's registered PKI identity fields and never touches a
/// JWKS. `self_signed_tls_client_auth` resolves its own JWKS cache/fetch —
/// callers no longer pre-load it.
pub(crate) async fn authenticate_client_mtls(
    state: &Arc<AppState>,
    client: &crate::db::OAuthClient,
    cert: &crate::services::oidc::mtls::ClientCertificate,
) -> Result<MtlsCertVerification, ClientAuthError> {
    match client.token_endpoint_auth_method {
        crate::db::TokenEndpointAuthMethod::TlsClientAuth => {
            crate::services::oidc::mtls::verify_tls_client_auth(
                cert,
                client.tls_client_auth_subject_dn.as_deref(),
                client.tls_client_auth_san_dns.as_deref(),
                client.tls_client_auth_san_email.as_deref(),
                client.tls_client_auth_san_uri.as_deref(),
                client.tls_client_auth_san_ip.as_deref(),
            )
            .map(|()| MtlsCertVerification { _private: () })
            .map_err(|e| ClientAuthError::MtlsVerificationFailed(e.to_string()))
        }
        crate::db::TokenEndpointAuthMethod::SelfSignedTlsClientAuth => {
            // The cache read is only useful for a `jwks_uri` client — an
            // inline-only client never consults it (matches
            // `resolve_client_decoding_key`'s same gate for the RFC 7523
            // path). The cache is an optimization, not a dependency even
            // when read: a lookup failure degrades to an uncached fetch
            // rather than failing authentication (same reasoning).
            let jwks_cache = if client
                .keys
                .as_ref()
                .and_then(crate::db::ClientKeys::uri)
                .is_none()
            {
                None
            } else {
                db::get_jwks_cache(&state.store, &client.id)
                    .await
                    .map_err(|e| {
                        tracing::debug!("JWKS cache lookup failed for client {}: {e}", client.id);
                    })
                    .ok()
                    .flatten()
            };

            let (jwks, origin) = resolve_self_signed_jwks(state, client, jwks_cache.as_ref())
                .await
                .map_err(|e| ClientAuthError::MtlsVerificationFailed(e.to_string()))?;

            match crate::services::oidc::mtls::verify_self_signed_tls_client_auth(cert, &jwks) {
                Ok(()) => Ok(MtlsCertVerification { _private: () }),
                Err(e) => {
                    // On a certificate miss, force-refresh a `jwks_uri`-backed
                    // client's JWKS and retry once — mirrors
                    // `find_matching_key_with_refresh_client`'s kid-miss
                    // policy for the same reason: the client may have rotated
                    // its certificate since the cache was last populated.
                    // Only meaningful when the JWKS just verified against
                    // came from the cache: if resolution above already
                    // fetched (`JwksOrigin::Fetched`), a further attempt
                    // would just repeat it. This bounds every auth attempt
                    // to at most one fetch, including against a permanently
                    // unreachable host, whose `cached_at` never advances and
                    // so cannot drive a freshness-based rate limit. No
                    // cross-request throttle is applied beyond that bound —
                    // repeated attempts across requests still cost one fetch
                    // each, bounded upstream by the per-IP auth rate limiter.
                    let Some(uri) = client.keys.as_ref().and_then(crate::db::ClientKeys::uri)
                    else {
                        return Err(ClientAuthError::MtlsVerificationFailed(e.to_string()));
                    };
                    if matches!(origin, JwksOrigin::Fetched) {
                        return Err(ClientAuthError::MtlsVerificationFailed(e.to_string()));
                    }
                    // A failed refetch falls back to the original error
                    // rather than surfacing the fetch failure — same shape
                    // as `find_matching_key_with_refresh_client`, so the
                    // caller sees a consistent "certificate not registered"
                    // rather than a raw network error. A successful refetch
                    // re-verifies against the fresh JWKS and returns
                    // whatever that produces, success or a new mismatch.
                    let allow_loopback = !state.config().tls_configured();
                    let Ok(fresh_jwks) = crate::infra::jwks::fetch_and_cache(
                        &state.store,
                        &client.id,
                        uri,
                        allow_loopback,
                        &state.http_client,
                    )
                    .await
                    .inspect_err(|fetch_err| {
                        tracing::warn!(
                            "JWKS force-refresh failed for client {}: {fetch_err}",
                            client.id
                        );
                    }) else {
                        return Err(ClientAuthError::MtlsVerificationFailed(e.to_string()));
                    };
                    crate::services::oidc::mtls::verify_self_signed_tls_client_auth(
                        cert,
                        &fresh_jwks,
                    )
                    .map(|()| MtlsCertVerification { _private: () })
                    .map_err(|fresh_err| {
                        ClientAuthError::MtlsVerificationFailed(fresh_err.to_string())
                    })
                }
            }
        }
        _ => Err(ClientAuthError::MtlsVerificationFailed(
            "client not registered for mTLS authentication".to_string(),
        )),
    }
}

/// Validate DPoP proof if present in the request.
///
/// # Arguments
/// * `state` - Application state
/// * `dpop_header` - The DPoP header value (if present)
/// * `method` - HTTP method
/// * `uri` - Request URI
///
/// # Returns
/// - `Ok(Some(proof))` if DPoP header was present and valid
/// - `Ok(None)` if DPoP header was not present (use Bearer token)
/// - `Err(DpopError::UseNonce(nonce))` if the server requires a nonce
/// - `Err(...)` if DPoP header was present but invalid
pub async fn validate_dpop_if_present(
    state: &AppState,
    dpop_header: Option<&str>,
    method: &str,
    uri: &str,
) -> Result<Option<ValidatedDpopProof>, DpopError> {
    let dpop_proof = match dpop_header {
        Some(proof) => proof,
        None => return Ok(None), // No DPoP header, use Bearer token
    };

    // Construct valid URIs for DPoP htu validation. Clients may send
    // the DPoP proof with htu pointing to either the canonical endpoint
    // or the mtls_endpoint_aliases URL (RFC 8705 Section 4).
    let config = state.config();
    let canonical_uri = format!("{}{}", config.base_url, uri);
    let mut accepted_uris = vec![canonical_uri.clone()];
    if config.tls_configured()
        && let Ok(mut url) = url::Url::parse(&config.base_url)
    {
        // url::Url::set_port returns Result<(), ()>; failure means non-special URL,
        // already validated upstream.
        let _set = url.set_port(Some(config.mtls_port));
        let mtls_uri = format!("{}{}", url.as_str().trim_end_matches('/'), uri);
        accepted_uris.push(mtls_uri);
    }

    // Validate the DPoP proof
    match dpop::validate_dpop_proof(
        dpop_proof,
        method,
        &accepted_uris,
        &state.store,
        config.dpop_max_age_seconds,
    )
    .await
    {
        Ok(validated) => {
            tracing::debug!(
                "DPoP proof validated: jkt={}, jti={}",
                validated.jkt,
                validated.jti
            );
            Ok(Some(validated))
        }
        Err(e) => {
            if matches!(&e, DpopError::UseNonce(_)) {
                tracing::debug!("DPoP nonce required, returning use_dpop_nonce error");
            } else {
                tracing::warn!("DPoP validation failed: {}", e);
            }
            Err(e)
        }
    }
}

/// Result of validating a session token for OIDC endpoints.
pub struct OidcValidatedSession {
    /// The authenticated user.
    pub user: User,
    /// The authenticator used to create the session, if any.
    /// `None` for OIDC-only enrollment sessions that lack a hardware key.
    ///
    /// Presence means only that the user has a key on record — an enrollment
    /// bootstrap session for a returning user carries one while no assertion
    /// has occurred. Read [`Self::hardware_verified`] to learn whether a
    /// ceremony actually happened.
    pub authenticator: Option<Authenticator>,
    /// Whether a FIDO2 assertion backs this session, from the access token's
    /// `hardware_verified` claim.
    pub hardware_verified: bool,
    /// When that assertion happened, from the access token's `auth_time`
    /// claim (OIDC Core §2).
    ///
    /// Independent of [`Self::hardware_verified`]: a token exchanged under
    /// RFC 8693 inherits the subject's verification but not its instant, and
    /// tokens issued before the instant was recorded carry none. `None`
    /// means "cannot say when", and nothing may substitute a nearby
    /// timestamp for it.
    pub auth_time: Option<i64>,
    /// Granted OAuth scope from the access token JWT.
    pub scope: Option<ScopeSet>,
    /// The OAuth client_id from the access token (used for signed userinfo lookup).
    pub client_id: Option<String>,
}

/// Validate a session token and return the user, session, and authenticator.
///
/// Accepts ES256 RFC 9068 access tokens only. The `authenticator_id` is
/// looked up from the server-side session record (not from the JWT).
pub async fn validate_session_token(
    state: &Arc<AppState>,
    token: &str,
) -> ServiceResult<Option<OidcValidatedSession>> {
    // Decode the token as an ES256 RFC 9068 access token
    let config = state.config();
    let decoded = match decode_token(token, &state.oidc_key, &config.base_url) {
        Some(d) => d,
        None => return Ok(None),
    };

    // Verify session exists in database
    let token_hash = hash_token(token);
    let session = match state
        .session_cache
        .get_session_by_token_hash(&state.store, &token_hash)
        .await
        .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
    {
        Some(s) => s,
        None => return Ok(None),
    };

    // M2M tokens (client_credentials grant) are not valid at user-facing endpoints.
    // Reject them explicitly rather than relying on get_user_by_id returning None.
    if session.session_type == db::SessionPurpose::M2MAccessToken {
        return Ok(None);
    }

    // Get user from the sub claim
    let user = match db::get_user_by_id(&state.store, decoded.sub())
        .await
        .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
    {
        Some(u) => u,
        None => return Ok(None),
    };

    // Deactivation and session deletion commit in separate transactions, so a
    // deactivated user can retain live sessions. Refuse to validate them here
    // so downstream consumers (userinfo, authorize) cannot serve a deactivated
    // account — mirroring the `user.active` guards on the other token paths.
    if !user.active {
        return Ok(None);
    }

    // Get authenticator from the server-side session record.
    // The authenticator_id is stored server-side and is NOT included in the JWT
    // to prevent information leakage.
    let authenticator_id = session.authenticator_id.as_deref();

    // If the session references an authenticator that no longer exists (deleted/revoked),
    // the session is invalid — this implements key revocation.
    let authenticator = match authenticator_id {
        Some(id) => {
            match db::get_authenticator_by_id(&state.store, id)
                .await
                .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
            {
                Some(a) => Some(a),
                None => return Ok(None), // authenticator revoked → session invalid
            }
        }
        None => None,
    };

    let (client_id, hardware_verified, auth_time) = match &decoded {
        crate::services::auth::DecodedToken::AccessToken(c) => {
            (Some(c.client_id.clone()), c.hardware_verified, c.auth_time)
        }
    };

    Ok(Some(OidcValidatedSession {
        user,
        authenticator,
        scope: decoded.scope().cloned(),
        client_id,
        hardware_verified,
        auth_time,
    }))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::super::authorization::CodeChallengeMethod;
    use super::*;

    fn assert_oauth_error<T: std::fmt::Debug>(
        result: Result<T, ServiceError>,
        expected: OAuthErrorCode,
    ) {
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == expected),
            "Expected {expected:?}",
        );
    }

    // =========================================================================
    // validate_code_bindings — redirect_uri
    // =========================================================================

    fn make_auth_code(redirect_uri: &str) -> AuthorizationCode {
        AuthorizationCode {
            iss: "https://test.example.com".to_string(),
            aud: "test".to_string(),
            client_id: "test".to_string(),
            redirect_uri: redirect_uri.to_string(),
            user_id: "user1".to_string(),
            email: "test@example.com".to_string(),
            authenticator_id: "auth1".to_string(),
            aaguid: None,
            scope: ScopeSet::parse("openid"),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            iat: 0,
            exp: i64::MAX,
            auth_time: None,
        }
    }

    // RFC 6749 §4.1.3: redirect_uri must match the one in the authorization request.
    #[test]
    fn test_validate_code_bindings_redirect_uri_match() {
        let auth_code = make_auth_code("https://example.com/callback");
        let result =
            validate_code_bindings(&auth_code, Some("https://example.com/callback"), None, None);
        assert!(
            result.is_ok(),
            "Matching redirect_uri must succeed: {result:?}"
        );
    }

    // RFC 6749 §4.1.3: a redirect_uri that differs is rejected.
    #[test]
    fn test_validate_code_bindings_redirect_uri_mismatch() {
        let auth_code = make_auth_code("https://example.com/callback");
        let result =
            validate_code_bindings(&auth_code, Some("https://attacker.com/steal"), None, None);
        assert_oauth_error(result, OAuthErrorCode::InvalidGrant);
    }

    // RFC 6749 §4.1.3: redirect_uri is required when it was in the authorization request.
    #[test]
    fn test_validate_code_bindings_redirect_uri_missing_when_required() {
        let auth_code = make_auth_code("https://example.com/callback");
        let result = validate_code_bindings(&auth_code, None, None, None);
        assert_oauth_error(result, OAuthErrorCode::InvalidRequest);
    }

    // RFC 6749 §3.1.2: with no registered redirection URI there is nothing to compare.
    #[test]
    fn test_validate_code_bindings_empty_redirect_uri_skips_check() {
        // When auth_code.redirect_uri is empty, no redirect_uri check is performed.
        let auth_code = make_auth_code("");
        let result = validate_code_bindings(&auth_code, None, None, None);
        assert!(
            result.is_ok(),
            "Empty redirect_uri in auth_code must skip the check: {result:?}"
        );
    }

    // =========================================================================
    // validate_code_bindings — DPoP binding
    // =========================================================================

    fn make_auth_code_with_dpop_jkt(jkt: &str) -> AuthorizationCode {
        AuthorizationCode {
            dpop_jkt: Some(jkt.to_string()),
            ..make_auth_code("")
        }
    }

    fn make_dpop_proof(jkt: &str) -> ValidatedDpopProof {
        ValidatedDpopProof::for_testing(jkt.to_string(), "jti-value".to_string(), None)
    }

    // RFC 9449 §5: a DPoP-bound code requires a proof at the token endpoint.
    #[test]
    fn test_validate_code_bindings_dpop_bound_no_proof() {
        let auth_code = make_auth_code_with_dpop_jkt("some-key-thumbprint");
        let result = validate_code_bindings(&auth_code, None, None, None);
        assert_oauth_error(result, OAuthErrorCode::InvalidGrant);
    }

    // RFC 9449 §5: the proof key must be the one the code was bound to.
    #[test]
    fn test_validate_code_bindings_dpop_jkt_mismatch() {
        let auth_code = make_auth_code_with_dpop_jkt("correct-thumbprint");
        let proof = make_dpop_proof("wrong-thumbprint");
        let result = validate_code_bindings(&auth_code, None, None, Some(&proof));
        assert_oauth_error(result, OAuthErrorCode::InvalidGrant);
    }

    // RFC 9449 §5: a proof for the bound key is accepted.
    #[test]
    fn test_validate_code_bindings_dpop_jkt_match() {
        let auth_code = make_auth_code_with_dpop_jkt("matching-thumbprint");
        let proof = make_dpop_proof("matching-thumbprint");
        let result = validate_code_bindings(&auth_code, None, None, Some(&proof));
        assert!(result.is_ok(), "Matching DPoP jkt must succeed: {result:?}");
    }

    // RFC 9449 §5: a proof for an unbound code does not bind it retroactively.
    #[test]
    fn test_validate_code_bindings_dpop_not_bound_but_proof_provided() {
        // Auth code has no dpop_jkt; providing a proof anyway is allowed (bearer fallback).
        let auth_code = make_auth_code("");
        let proof = make_dpop_proof("some-thumbprint");
        let result = validate_code_bindings(&auth_code, None, None, Some(&proof));
        assert!(
            result.is_ok(),
            "Proof on unbound code must not fail: {result:?}"
        );
    }

    // =========================================================================
    // validate_code_bindings — ACR values
    // =========================================================================

    fn make_auth_code_with_acr(acr_values: &str) -> AuthorizationCode {
        AuthorizationCode {
            acr_values: Some(acr_values.to_string()),
            ..make_auth_code("")
        }
    }

    // RFC 9470 §4: the acr the client demanded must be the one that was met.
    #[test]
    fn test_validate_code_bindings_acr_contains_aal3() {
        let auth_code = make_auth_code_with_acr("urn:nist:authentication:assurance-level:aal3");
        let result = validate_code_bindings(&auth_code, None, None, None);
        assert!(result.is_ok(), "AAL3 present must succeed: {result:?}");
    }

    // RFC 9470 §4: one satisfied acr value from the requested set is enough.
    #[test]
    fn test_validate_code_bindings_acr_multiple_values_includes_aal3() {
        let auth_code = make_auth_code_with_acr(
            "urn:nist:authentication:assurance-level:aal1 urn:nist:authentication:assurance-level:aal3",
        );
        let result = validate_code_bindings(&auth_code, None, None, None);
        assert!(
            result.is_ok(),
            "AAL3 among multiple ACR values must succeed: {result:?}"
        );
    }

    // RFC 9470 §4: an unmet acr demand fails the exchange.
    #[test]
    fn test_validate_code_bindings_acr_missing_aal3() {
        let auth_code = make_auth_code_with_acr("urn:nist:authentication:assurance-level:aal1");
        let result = validate_code_bindings(&auth_code, None, None, None);
        assert_oauth_error(result, OAuthErrorCode::UnmetAuthenticationRequirements);
    }

    // RFC 9470 §4: no acr demand imposes no acr constraint.
    #[test]
    fn test_validate_code_bindings_no_acr_values() {
        // No acr_values in the code — skip ACR check.
        let auth_code = make_auth_code("");
        let result = validate_code_bindings(&auth_code, None, None, None);
        assert!(
            result.is_ok(),
            "Absent acr_values must skip ACR check: {result:?}"
        );
    }

    // RFC 7636 §4.6: the server verifies code_verifier against the stored challenge.
    #[test]
    fn test_pkce_s256_validation() {
        // RFC 7636 Appendix B test vector
        let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        let auth_code = AuthorizationCode {
            iss: "https://test.example.com".to_string(),
            aud: "test".to_string(),
            client_id: "test".to_string(),
            redirect_uri: "https://example.com".to_string(),
            user_id: "user1".to_string(),
            email: "test@example.com".to_string(),
            authenticator_id: "auth1".to_string(),
            aaguid: None,
            scope: ScopeSet::parse("openid"),
            nonce: None,
            code_challenge: Some(expected_challenge.to_string()),
            code_challenge_method: Some(CodeChallengeMethod::S256),
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            iat: 0,
            exp: i64::MAX,
            auth_time: None,
        };

        let result = auth_code.validate_pkce(Some(code_verifier));
        assert!(result.is_ok(), "RFC 7636 test vector should validate");
    }

    // RFC 7636 §4.6: a verifier that does not transform to the challenge is rejected.
    #[test]
    fn test_pkce_invalid_verifier() {
        let auth_code = AuthorizationCode {
            iss: "https://test.example.com".to_string(),
            aud: "test".to_string(),
            client_id: "test".to_string(),
            redirect_uri: "https://example.com".to_string(),
            user_id: "user1".to_string(),
            email: "test@example.com".to_string(),
            authenticator_id: "auth1".to_string(),
            aaguid: None,
            scope: ScopeSet::parse("openid"),
            nonce: None,
            code_challenge: Some("expected_challenge".to_string()),
            code_challenge_method: Some(CodeChallengeMethod::S256),
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            iat: 0,
            exp: i64::MAX,
            auth_time: None,
        };

        let result = auth_code.validate_pkce(Some("wrong_verifier"));
        assert!(result.is_err());
    }

    // RFC 7636 §4.6: a stored challenge requires a verifier.
    #[test]
    fn test_pkce_missing_verifier() {
        let auth_code = AuthorizationCode {
            iss: "https://test.example.com".to_string(),
            aud: "test".to_string(),
            client_id: "test".to_string(),
            redirect_uri: "https://example.com".to_string(),
            user_id: "user1".to_string(),
            email: "test@example.com".to_string(),
            authenticator_id: "auth1".to_string(),
            aaguid: None,
            scope: ScopeSet::parse("openid"),
            nonce: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some(CodeChallengeMethod::S256),
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            iat: 0,
            exp: i64::MAX,
            auth_time: None,
        };

        let result = auth_code.validate_pkce(None);
        // RFC 7636 Section 4.6: missing code_verifier when a challenge was registered
        // must return invalid_grant, not invalid_request or any other error code.
        assert_oauth_error(result, OAuthErrorCode::InvalidGrant);
    }

    // RFC 7636 §4.6: with no stored challenge there is nothing to verify.
    #[test]
    fn test_pkce_no_challenge() {
        // No PKCE challenge - should succeed
        let auth_code = AuthorizationCode {
            iss: "https://test.example.com".to_string(),
            aud: "test".to_string(),
            client_id: "test".to_string(),
            redirect_uri: "https://example.com".to_string(),
            user_id: "user1".to_string(),
            email: "test@example.com".to_string(),
            authenticator_id: "auth1".to_string(),
            aaguid: None,
            scope: ScopeSet::parse("openid"),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            iat: 0,
            exp: i64::MAX,
            auth_time: None,
        };

        let result = auth_code.validate_pkce(None);
        assert!(result.is_ok());
    }

    // OIDC Core §3.1.3.6: at_hash is a base64url value derived from the access token.
    #[test]
    fn test_hash_token_produces_consistent_base64url() {
        // Regression test: hash_token must produce base64url-encoded SHA-256 output.
        // A previous bug used hex encoding at creation time but base64url at validation,
        // causing client secret authentication to always fail.
        let input = "vouch_test_secret_value";
        let hash1 = hash_token(input);
        let hash2 = hash_token(input);

        // Must be deterministic
        assert_eq!(hash1, hash2);

        // SHA-256 produces 32 bytes; base64url-no-pad encodes that as 43 characters
        assert_eq!(hash1.len(), 43, "base64url(SHA-256) should be 43 chars");

        // Must contain only URL-safe base64 characters (no padding)
        assert!(
            hash1
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "hash must use URL-safe base64 characters only"
        );

        // Must NOT be hex-encoded (hex would be 64 chars)
        assert_ne!(hash1.len(), 64, "hash must not be hex-encoded");
    }

    // OIDC Core §3.1.3.6: at_hash is deterministic for a given token.
    #[test]
    fn test_compute_at_hash_deterministic() {
        // at_hash should be deterministic for the same input
        let token = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9.test.sig";
        let hash1 = compute_at_hash(token);
        let hash2 = compute_at_hash(token);
        assert!(hash1.is_some());
        assert_eq!(hash1, hash2);
    }

    // OIDC Core §3.1.3.6: at_hash is the left half of the hash, base64url encoded.
    #[test]
    fn test_compute_at_hash_format() {
        // SHA-256 left half = 16 bytes → base64url-no-pad = 22 characters
        let token = "some-access-token-string";
        let hash = compute_at_hash(token).expect("should produce hash");
        assert_eq!(
            hash.len(),
            22,
            "at_hash should be 22 chars (16 bytes base64url)"
        );
        // Must contain only base64url characters (no padding)
        assert!(
            hash.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "at_hash must use URL-safe base64 characters only"
        );
    }

    // OIDC Core §3.1.3.6: distinct tokens produce distinct at_hash values.
    #[test]
    fn test_compute_at_hash_different_tokens() {
        let hash1 = compute_at_hash("token-a").expect("hash");
        let hash2 = compute_at_hash("token-b").expect("hash");
        assert_ne!(
            hash1, hash2,
            "different tokens should produce different hashes"
        );
    }

    // =========================================================================
    // IdTokenClaims nonce serialization
    //
    // OIDC Core Section 3.1.3.7: the nonce claim MUST be present in the ID
    // token if it was in the authorization request, and MUST be absent (not
    // null) when no nonce was requested.
    // =========================================================================

    fn minimal_id_token_claims(nonce: Option<String>) -> IdTokenClaims {
        IdTokenClaims {
            iss: "https://test.example.com".to_string(),
            sub: "user-1".to_string(),
            aud: "client-1".to_string(),
            exp: 9_999_999_999,
            iat: 0,
            auth_time: None,
            nonce,
            email: None,
            email_verified: None,
            hardware_verified: None,
            hardware_aaguid: None,
            cnf: None,
            amr: None,
            acr: None,
            at_hash: None,
        }
    }

    // OIDC Core §2: nonce is present in the ID Token only if it was in the request.
    #[test]
    fn test_id_token_claims_nonce_none_omitted_from_json() {
        // When nonce is None the field must be absent from the serialized JSON,
        // not present as `"nonce": null`. The `skip_serializing_if` attribute
        // on IdTokenClaims.nonce enforces this; this test guards against
        // accidental removal of that attribute.
        let claims = minimal_id_token_claims(None);
        let value = serde_json::to_value(&claims).expect("serialization must succeed");
        assert!(
            value.get("nonce").is_none(),
            "nonce: None must serialize to a missing field, not null"
        );
    }

    // OIDC Core §2: a requested nonce is returned in the ID Token.
    #[test]
    fn test_id_token_claims_nonce_some_included_in_json() {
        // When nonce is Some the field must be present with the correct value.
        let claims = minimal_id_token_claims(Some("test-nonce-value".to_string()));
        let value = serde_json::to_value(&claims).expect("serialization must succeed");
        assert_eq!(
            value.get("nonce").and_then(|v| v.as_str()),
            Some("test-nonce-value"),
            "nonce: Some should serialize as the nonce string"
        );
    }

    // =========================================================================
    // authenticate_client_mtls — RFC 8705 Section 2 mTLS client authentication
    // =========================================================================

    use crate::db::{AccessScope, FapiProfile, OAuthClientType, TokenEndpointAuthMethod};

    fn make_mtls_client(
        auth_method: TokenEndpointAuthMethod,
        subject_dn: Option<&str>,
    ) -> crate::db::OAuthClient {
        let now = jiff::Timestamp::now();
        crate::db::OAuthClient {
            id: "test-mtls-id".to_string(),
            user_id: Some("test-user".to_string()),
            client_id: "mtls-client-id".to_string(),
            name: "mTLS Test Client".to_string(),
            description: None,
            application_type: OAuthClientType::Service,
            redirect_uris: vec![],
            active: true,
            created_at: now,
            updated_at: now,
            last_used_at: None,
            access_scope: AccessScope::Organization,
            org_id: None,
            resource_uris: vec![],
            keys: None,
            token_endpoint_auth_method: auth_method,
            request_object_signing_alg: None,
            require_signed_request_object: None,
            fapi_profile: FapiProfile::None,
            dpop_bound_access_tokens: false,
            grant_types: None,
            response_types: None,
            software_id: None,
            software_version: None,
            registration_source: None,
            registration_access_token_hash: None,
            registration_metadata: None,
            id_token_signed_response_alg: crate::crypto::alg::JwsAlgorithm::Rs256,
            tls_client_auth_subject_dn: subject_dn.map(String::from),
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,
            tls_client_certificate_bound_access_tokens: false,
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: None,
            userinfo_signed_response_alg: None,
            request_uris: None,
            post_logout_redirect_uris: None,
        }
    }

    fn make_cert_with_cn(cn: &str) -> crate::services::oidc::mtls::ClientCertificate {
        let der = make_self_signed_cert_der(cn);
        crate::services::oidc::mtls::parse_client_certificate(&der).expect("parse cert")
    }

    /// Generate a self-signed DER certificate with the given CN.
    fn make_self_signed_cert_der(cn: &str) -> Vec<u8> {
        use der::{Decode, Encode};
        use p256::ecdsa::SigningKey;
        use spki::EncodePublicKey;
        use x509_cert::builder::{Builder as _, CertificateBuilder, Profile};
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let cn_oid = der::oid::ObjectIdentifier::new_unwrap("2.5.4.3");
        let cn_value = der::asn1::Utf8StringRef::new(cn).expect("CN");
        let atv = x509_cert::attr::AttributeTypeAndValue {
            oid: cn_oid,
            value: der::asn1::Any::from(cn_value),
        };
        let mut rdn = der::asn1::SetOfVec::new();
        rdn.insert(atv).expect("rdn");
        let subject =
            x509_cert::name::RdnSequence(vec![x509_cert::name::RelativeDistinguishedName(rdn)]);
        let validity =
            Validity::from_now(core::time::Duration::from_secs(86400)).expect("validity");
        let serial = SerialNumber::new(&[1u8]).expect("serial");
        let spki_der = key.verifying_key().to_public_key_der().expect("spki");
        let spki =
            spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_ref()).expect("parse spki");

        let builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer: subject.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            serial,
            validity,
            subject,
            spki,
            &key,
        )
        .expect("builder");

        builder
            .build::<p256::ecdsa::DerSignature>()
            .expect("build")
            .to_der()
            .expect("der")
    }

    /// TlsClientAuth client with matching subject_dn must authenticate successfully.
    // RFC 8705 §2.1.2: the certificate subject must match the registered value.
    #[tokio::test]
    async fn test_authenticate_client_mtls_tls_client_auth_matching() {
        let state = crate::test_utils::test_app_state().await;
        let cert = make_cert_with_cn("test-mtls-client");
        let subject_dn = cert.subject_dn.as_deref().expect("cert has subject_dn");
        let client = make_mtls_client(TokenEndpointAuthMethod::TlsClientAuth, Some(subject_dn));

        let result = authenticate_client_mtls(&state, &client, &cert).await;
        assert!(
            result.is_ok(),
            "matching subject_dn must authenticate successfully, got: {result:?}"
        );
    }

    /// TlsClientAuth client with non-matching subject_dn must fail authentication.
    // RFC 8705 §2.1.2: a certificate naming another subject does not authenticate.
    #[tokio::test]
    async fn test_authenticate_client_mtls_tls_client_auth_mismatch() {
        let state = crate::test_utils::test_app_state().await;
        let cert = make_cert_with_cn("actual-client");
        let client = make_mtls_client(
            TokenEndpointAuthMethod::TlsClientAuth,
            Some("CN=expected-different-client"),
        );

        let result = authenticate_client_mtls(&state, &client, &cert).await;
        assert!(
            result.is_err(),
            "non-matching subject_dn must fail authentication"
        );
        assert!(
            matches!(result, Err(ClientAuthError::MtlsVerificationFailed(_))),
            "must return MtlsVerificationFailed, got: {result:?}"
        );
    }

    /// Client with ClientSecretBasic auth method cannot use mTLS authentication.
    // RFC 8705 §2.1.2: the registered authentication method decides how the certificate is checked.
    #[tokio::test]
    async fn test_authenticate_client_mtls_wrong_method() {
        let state = crate::test_utils::test_app_state().await;
        let cert = make_cert_with_cn("wrong-method-client");
        let client = make_mtls_client(TokenEndpointAuthMethod::ClientSecretBasic, None);

        let result = authenticate_client_mtls(&state, &client, &cert).await;
        assert!(
            result.is_err(),
            "non-mTLS auth method must fail mTLS authentication"
        );
        assert!(
            matches!(result, Err(ClientAuthError::MtlsVerificationFailed(_))),
            "must return MtlsVerificationFailed for wrong auth method, got: {result:?}"
        );
    }

    /// `SelfSignedTlsClientAuth` succeeds when the client JWKS contains an x5c
    /// entry matching the presented certificate (RFC 8705 Section 2.2).
    // RFC 8705 §2.2: the certificate must be one of the client's registered keys.
    #[tokio::test]
    async fn test_authenticate_client_mtls_self_signed_matching() {
        use base64::Engine;

        let state = crate::test_utils::test_app_state().await;
        let cert_der = make_self_signed_cert_der("self-signed-client");
        let cert =
            crate::services::oidc::mtls::parse_client_certificate(&cert_der).expect("parse cert");

        // Build JWKS with matching x5c (standard base64 per RFC 7517 §4.7)
        let x5c_b64 = base64::engine::general_purpose::STANDARD.encode(&cert_der);
        let jwks = serde_json::json!({
            "keys": [{ "kty": "EC", "crv": "P-256", "x5c": [x5c_b64] }]
        });

        let mut client = make_mtls_client(TokenEndpointAuthMethod::SelfSignedTlsClientAuth, None);
        client.keys = Some(crate::db::ClientKeys::Inline(
            crate::db::parse_jwks_set(&jwks).expect("valid test JWKS"),
        ));

        let result = authenticate_client_mtls(&state, &client, &cert).await;
        assert!(
            result.is_ok(),
            "matching x5c must authenticate successfully: {result:?}"
        );
    }

    /// `SelfSignedTlsClientAuth` fails when the client has no JWKS configured.
    // RFC 8705 §2.2: self-signed authentication needs registered keys.
    #[tokio::test]
    async fn test_authenticate_client_mtls_self_signed_no_jwks() {
        let state = crate::test_utils::test_app_state().await;
        let cert = make_cert_with_cn("self-signed-no-jwks");
        let client = make_mtls_client(TokenEndpointAuthMethod::SelfSignedTlsClientAuth, None);
        // client.jwks is None (default from make_mtls_client)

        let result = authenticate_client_mtls(&state, &client, &cert).await;
        assert!(
            matches!(result, Err(ClientAuthError::MtlsVerificationFailed(_))),
            "missing JWKS must return MtlsVerificationFailed: {result:?}"
        );
    }

    /// `SelfSignedTlsClientAuth` fails when the JWKS x5c contains a different cert.
    // RFC 8705 §2.2: a certificate absent from the registered keys does not authenticate.
    #[tokio::test]
    async fn test_authenticate_client_mtls_self_signed_mismatch() {
        use base64::Engine;

        let state = crate::test_utils::test_app_state().await;
        let cert_der = make_self_signed_cert_der("self-signed-cert");
        let other_der = make_self_signed_cert_der("self-signed-other");
        let cert =
            crate::services::oidc::mtls::parse_client_certificate(&cert_der).expect("parse cert");

        // JWKS contains the *other* cert's DER, not the presented cert
        let x5c_b64 = base64::engine::general_purpose::STANDARD.encode(&other_der);
        let jwks = serde_json::json!({
            "keys": [{ "kty": "EC", "crv": "P-256", "x5c": [x5c_b64] }]
        });

        let mut client = make_mtls_client(TokenEndpointAuthMethod::SelfSignedTlsClientAuth, None);
        client.keys = Some(crate::db::ClientKeys::Inline(
            crate::db::parse_jwks_set(&jwks).expect("valid test JWKS"),
        ));

        let result = authenticate_client_mtls(&state, &client, &cert).await;
        assert!(
            matches!(result, Err(ClientAuthError::MtlsVerificationFailed(_))),
            "non-matching x5c must return MtlsVerificationFailed: {result:?}"
        );
    }

    // =========================================================================
    // authenticate_client_mtls — self_signed_tls_client_auth jwks_uri fetch/cache
    //
    // No test harness in this codebase serves a JWKS over a live mock HTTPS
    // server (`fetch_jwks` requires `https://` unconditionally; `wiremock`
    // here only serves plain HTTP). These tests use the same technique the
    // sibling RFC 7523 tests use instead (`infra::jwks::tests::cache_doc`,
    // `find_matching_key_with_refresh_*`): a directly-seeded `JwksCacheDoc`
    // proves cache consumption, and an unreachable `https://` URI proves a
    // fetch attempt fails cleanly without ever needing a real network call.
    // =========================================================================

    /// Directly seed a `JwksCacheDoc` at the age this test needs — the public
    /// `db::upsert_jwks_cache` always stamps `cached_at: now`, so TTL/rate-limit
    /// boundary tests need this instead.
    async fn seed_jwks_cache(
        store: &crate::db::store::DocumentStore,
        parent_id: &str,
        value: serde_json::Value,
        age_seconds: i64,
    ) {
        let doc = crate::db::documents::jwks_cache::JwksCacheDoc {
            value,
            cached_at: jiff::Timestamp::now()
                .checked_sub(jiff::SignedDuration::from_secs(age_seconds))
                .expect("cache age must be representable"),
        };
        store
            .upsert(&format!("jwks_cache:{parent_id}"), &doc)
            .await
            .expect("seed jwks cache");
    }

    /// An unreachable JWKS host, standing in for a fetch failure without a
    /// real network dependency. `test_app_state()` has no TLS configured, so
    /// `allow_loopback` is `true` here (unlike `infra::jwks::tests`, which
    /// tests the SSRF guard itself with `allow_loopback: false`) — the SSRF
    /// guard permits this loopback destination, the connection is actually
    /// dialed, and it fails on connection-refused (nothing listens on port 1).
    const UNREACHABLE_JWKS_URI: &str = "https://127.0.0.1:1/jwks.json";

    // RFC 8705 §2.2: registered keys may be held by reference.
    #[tokio::test]
    async fn test_authenticate_client_mtls_self_signed_jwks_uri_uses_fresh_cache_without_fetching()
    {
        use base64::Engine;

        let state = crate::test_utils::test_app_state().await;
        let cert_der = make_self_signed_cert_der("self-signed-cached");
        let cert =
            crate::services::oidc::mtls::parse_client_certificate(&cert_der).expect("parse cert");
        let x5c_b64 = base64::engine::general_purpose::STANDARD.encode(&cert_der);
        let jwks = serde_json::json!({"keys": [{"kty": "EC", "crv": "P-256", "x5c": [x5c_b64]}]});

        let mut client = make_mtls_client(TokenEndpointAuthMethod::SelfSignedTlsClientAuth, None);
        client.keys = Some(crate::db::ClientKeys::Uri(UNREACHABLE_JWKS_URI.to_string()));
        seed_jwks_cache(&state.store, &client.id, jwks, 60).await;

        // Success proves the cached JWKS was used — the URI would fail if dialed.
        let result = authenticate_client_mtls(&state, &client, &cert).await;
        assert!(
            result.is_ok(),
            "a fresh cache must authenticate without a fetch: {result:?}"
        );
    }

    // RFC 8705 §2.2: an unreachable key set fails authentication rather than admitting it.
    #[tokio::test]
    async fn test_authenticate_client_mtls_self_signed_jwks_uri_fetch_failure_is_clean() {
        let state = crate::test_utils::test_app_state().await;
        let cert = make_cert_with_cn("self-signed-fetch-failure");

        let mut client = make_mtls_client(TokenEndpointAuthMethod::SelfSignedTlsClientAuth, None);
        client.keys = Some(crate::db::ClientKeys::Uri(UNREACHABLE_JWKS_URI.to_string()));
        // No cache row: this exercises first-ever resolution, not the
        // post-verification retry path.

        let result = authenticate_client_mtls(&state, &client, &cert).await;
        assert!(
            matches!(result, Err(ClientAuthError::MtlsVerificationFailed(_))),
            "a fetch failure must resolve to a clean MtlsVerificationFailed, not a raw \
             network error, a panic, or a hang: {result:?}"
        );
    }

    // RFC 8705 §2.2: a key set with no certificate cannot match one.
    #[tokio::test]
    async fn test_authenticate_client_mtls_self_signed_certificate_less_jwks_at_uri_fails_cleanly()
    {
        let state = crate::test_utils::test_app_state().await;
        let cert = make_cert_with_cn("self-signed-no-x5c-at-uri");

        let mut client = make_mtls_client(TokenEndpointAuthMethod::SelfSignedTlsClientAuth, None);
        client.keys = Some(crate::db::ClientKeys::Uri(UNREACHABLE_JWKS_URI.to_string()));
        // Cached JWKS has key material but no x5c — same "accepted at
        // registration, unusable forever after" class PR 4 closed for the
        // write path, now proven at the runtime verification path too.
        let certificate_less = serde_json::json!({"keys": [{"kty": "RSA", "n": "n", "e": "AQAB"}]});
        seed_jwks_cache(&state.store, &client.id, certificate_less, 60).await;

        let result = authenticate_client_mtls(&state, &client, &cert).await;
        assert!(
            matches!(result, Err(ClientAuthError::MtlsVerificationFailed(_))),
            "a certificate-less JWKS resolved via jwks_uri must fail the same way as inline: \
             {result:?}"
        );
    }

    /// Extract the text of a `ClientAuthError::MtlsVerificationFailed`, or
    /// panic — the retry tests below assert on it to distinguish a
    /// fallback-to-original-error from a leaked fetch-failure message.
    fn expect_mtls_verification_failed_text(
        result: &Result<MtlsCertVerification, ClientAuthError>,
    ) -> &str {
        match result {
            Err(ClientAuthError::MtlsVerificationFailed(msg)) => msg,
            other => panic!("expected MtlsVerificationFailed, got {other:?}"),
        }
    }

    // RFC 8705 §2.2: a stale cache must not reject a newly registered certificate.
    #[tokio::test]
    async fn test_authenticate_client_mtls_self_signed_retries_after_cache_hit_on_certificate_miss()
    {
        use base64::Engine;

        let state = crate::test_utils::test_app_state().await;
        let cert_der = make_self_signed_cert_der("self-signed-rotated");
        let other_der = make_self_signed_cert_der("self-signed-pre-rotation");
        let cert =
            crate::services::oidc::mtls::parse_client_certificate(&cert_der).expect("parse cert");

        let mut client = make_mtls_client(TokenEndpointAuthMethod::SelfSignedTlsClientAuth, None);
        client.keys = Some(crate::db::ClientKeys::Uri(UNREACHABLE_JWKS_URI.to_string()));
        // Cached cert predates a rotation but is well within the 1-hour TTL,
        // so resolution serves it from cache (`JwksOrigin::NoFetch`) and the
        // retry gate lets the force-refresh attempt proceed.
        let other_x5c = base64::engine::general_purpose::STANDARD.encode(&other_der);
        let stale_jwks =
            serde_json::json!({"keys": [{"kty": "EC", "crv": "P-256", "x5c": [other_x5c]}]});
        seed_jwks_cache(&state.store, &client.id, stale_jwks, 60).await;

        // The retry attempt hits the unreachable URI and fails, falling back
        // to the original certificate-mismatch error — never a panic, a
        // hang, or a leaked "failed to fetch" message (kills the mutation
        // where the fetch error is surfaced instead of the fallback).
        let result = authenticate_client_mtls(&state, &client, &cert).await;
        assert!(
            expect_mtls_verification_failed_text(&result).contains("certificate not registered"),
            "a failed retry must fall back to the original mismatch error: {result:?}"
        );
    }

    // RFC 8705 §2.2: a freshly fetched key set is not fetched twice.
    #[tokio::test]
    async fn test_authenticate_client_mtls_self_signed_skips_retry_when_resolution_already_fetched()
    {
        use base64::Engine;

        let state = crate::test_utils::test_app_state().await;
        let cert_der = make_self_signed_cert_der("self-signed-fresh-miss");
        let other_der = make_self_signed_cert_der("self-signed-fresh-other");
        let cert =
            crate::services::oidc::mtls::parse_client_certificate(&cert_der).expect("parse cert");

        let mut client = make_mtls_client(TokenEndpointAuthMethod::SelfSignedTlsClientAuth, None);
        client.keys = Some(crate::db::ClientKeys::Uri(UNREACHABLE_JWKS_URI.to_string()));
        // Cache is past the 1-hour TTL but within the 24-hour stale window:
        // resolution attempts a fetch (fails against the unreachable URI)
        // and falls back to serving this stale, mismatched document —
        // `JwksOrigin::Fetched`. The retry-consideration branch must skip
        // the force-refetch entirely rather than attempt a second one this
        // request. Structural coverage, not a mutation-killing assertion for
        // that specific gate: a skipped retry and an attempted-then-failed
        // retry both fall back to the same original-error text by design,
        // so this codebase has no way to distinguish them without a
        // network-call-counting harness, which doesn't exist here — the
        // gate itself is a 3-line, directly-readable early return
        // (`resolve_self_signed_jwks_reports_fetched_for_stale_cache` above
        // proves the flag it reads is computed correctly).
        let other_x5c = base64::engine::general_purpose::STANDARD.encode(&other_der);
        let mismatched_jwks =
            serde_json::json!({"keys": [{"kty": "EC", "crv": "P-256", "x5c": [other_x5c]}]});
        seed_jwks_cache(&state.store, &client.id, mismatched_jwks, 7200).await;

        let result = authenticate_client_mtls(&state, &client, &cert).await;
        assert!(
            expect_mtls_verification_failed_text(&result).contains("certificate not registered"),
            "a stale-fallback certificate miss must still resolve cleanly: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_resolve_self_signed_jwks_reports_no_fetch_for_fresh_cache() {
        let state = crate::test_utils::test_app_state().await;
        let mut client = make_mtls_client(TokenEndpointAuthMethod::SelfSignedTlsClientAuth, None);
        client.keys = Some(crate::db::ClientKeys::Uri(UNREACHABLE_JWKS_URI.to_string()));
        let jwks = serde_json::json!({"keys": [{"kty": "EC", "kid": "k1"}]});
        seed_jwks_cache(&state.store, &client.id, jwks.clone(), 60).await;

        let cache = crate::db::get_jwks_cache(&state.store, &client.id)
            .await
            .expect("get_jwks_cache failed");
        let (value, origin) = resolve_self_signed_jwks(&state, &client, cache.as_ref())
            .await
            .expect("resolution must succeed from a fresh cache");
        assert_eq!(value, jwks);
        assert!(
            matches!(origin, JwksOrigin::NoFetch),
            "a cache within the TTL must not fetch"
        );
    }

    #[tokio::test]
    async fn test_resolve_self_signed_jwks_reports_fetched_for_stale_cache() {
        let state = crate::test_utils::test_app_state().await;
        let mut client = make_mtls_client(TokenEndpointAuthMethod::SelfSignedTlsClientAuth, None);
        client.keys = Some(crate::db::ClientKeys::Uri(UNREACHABLE_JWKS_URI.to_string()));
        let jwks = serde_json::json!({"keys": [{"kty": "EC", "kid": "k1"}]});
        // Past the 1-hour TTL, within the 24-hour stale window: resolution
        // attempts a fetch (fails against the unreachable URI) and falls
        // back to this cached value.
        seed_jwks_cache(&state.store, &client.id, jwks.clone(), 7200).await;

        let cache = crate::db::get_jwks_cache(&state.store, &client.id)
            .await
            .expect("get_jwks_cache failed");
        let (value, origin) = resolve_self_signed_jwks(&state, &client, cache.as_ref())
            .await
            .expect("a failed fetch within the stale window must fall back to the cache");
        assert_eq!(value, jwks);
        assert!(
            matches!(origin, JwksOrigin::Fetched),
            "a cache past the TTL must attempt a fetch"
        );
    }

    #[tokio::test]
    /// An inline key set resolves without a network call.
    ///
    /// This used to also assert that inline wins over a `jwks_uri` on the same
    /// client. `ClientKeys` cannot hold both, so there is no precedence left to
    /// assert — RFC 7591 §2 says the two "MUST NOT both be present".
    async fn test_resolve_self_signed_jwks_reports_no_fetch_for_inline_jwks() {
        let state = crate::test_utils::test_app_state().await;
        let mut client = make_mtls_client(TokenEndpointAuthMethod::SelfSignedTlsClientAuth, None);
        let jwks = serde_json::json!({"keys": [{"kty": "EC", "kid": "inline"}]});
        client.keys = Some(crate::db::ClientKeys::Inline(
            crate::db::parse_jwks_set(&jwks.clone()).expect("valid test JWKS"),
        ));

        let (value, origin) = resolve_self_signed_jwks(&state, &client, None)
            .await
            .expect("inline jwks must resolve");
        assert_eq!(value, jwks);
        assert!(
            matches!(origin, JwksOrigin::NoFetch),
            "an inline key set never fetches"
        );
    }

    // =========================================================================
    // verify_client_matches_code
    // =========================================================================

    // RFC 6749 §4.1.3: a code issued without a client imposes no client binding.
    #[test]
    fn test_verify_client_matches_code_no_client_ok() {
        let auth_code = make_auth_code("");
        assert!(verify_client_matches_code(None, &auth_code).is_ok());
    }

    // RFC 6749 §4.1.3: the code must be redeemed by the client it was issued to.
    #[test]
    fn test_verify_client_matches_code_matching_confidential_client_ok() {
        let client = AuthenticatedClient {
            client: make_mtls_client(TokenEndpointAuthMethod::ClientSecretBasic, None),
            is_public: false,
        };
        let auth_code = AuthorizationCode {
            client_id: client.client.client_id.clone(),
            ..make_auth_code("")
        };
        // Service client, not public: PKCE is not required.
        assert!(verify_client_matches_code(Some(&client), &auth_code).is_ok());
    }

    // RFC 6749 §4.1.3: another client may not redeem the code.
    #[test]
    fn test_verify_client_matches_code_rejects_client_id_mismatch() {
        let client = AuthenticatedClient {
            client: make_mtls_client(TokenEndpointAuthMethod::ClientSecretBasic, None),
            is_public: false,
        };
        // make_auth_code uses client_id "test", which differs from the client's.
        let auth_code = make_auth_code("");
        let result = verify_client_matches_code(Some(&client), &auth_code);
        assert_oauth_error(result, OAuthErrorCode::InvalidGrant);
    }

    // RFC 7636 §4.6: a public client's code is redeemed with a verifier.
    #[test]
    fn test_verify_client_matches_code_public_client_requires_pkce() {
        let client = AuthenticatedClient {
            client: make_mtls_client(TokenEndpointAuthMethod::ClientSecretBasic, None),
            is_public: true,
        };
        let auth_code = AuthorizationCode {
            client_id: client.client.client_id.clone(),
            ..make_auth_code("")
        };
        let result = verify_client_matches_code(Some(&client), &auth_code);
        assert_oauth_error(result, OAuthErrorCode::InvalidRequest);
    }

    // RFC 7636 §4.6: a public client presenting a verifier may redeem the code.
    #[test]
    fn test_verify_client_matches_code_public_client_with_pkce_ok() {
        let client = AuthenticatedClient {
            client: make_mtls_client(TokenEndpointAuthMethod::ClientSecretBasic, None),
            is_public: true,
        };
        let auth_code = AuthorizationCode {
            client_id: client.client.client_id.clone(),
            code_challenge: Some("a-code-challenge".to_string()),
            code_challenge_method: Some(CodeChallengeMethod::S256),
            ..make_auth_code("")
        };
        assert!(verify_client_matches_code(Some(&client), &auth_code).is_ok());
    }

    // =========================================================================
    // load_and_validate_grant_subject
    // =========================================================================

    use crate::test_utils::{create_test_authenticator, create_test_user, test_app_state};

    #[tokio::test]
    async fn test_grant_subject_active_user_ok() {
        let state = test_app_state().await;
        let user = create_test_user(&state.store, "grant-ok@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;

        let auth_code = AuthorizationCode {
            user_id: user.id.clone(),
            authenticator_id: auth_id,
            ..make_auth_code("")
        };
        let result = load_and_validate_grant_subject(&state, &auth_code).await;
        let loaded = result.expect("active user with authenticator must pass");
        assert_eq!(loaded.id, user.id);
    }

    #[tokio::test]
    async fn test_grant_subject_rejects_unknown_user() {
        let state = test_app_state().await;
        let auth_code = AuthorizationCode {
            user_id: "no-such-user".to_string(),
            ..make_auth_code("")
        };
        let result = load_and_validate_grant_subject(&state, &auth_code).await;
        assert_oauth_error(result, OAuthErrorCode::InvalidGrant);
    }

    #[tokio::test]
    async fn test_grant_subject_rejects_deactivated_user() {
        let state = test_app_state().await;
        let user = create_test_user(&state.store, "grant-inactive@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        db::update_user_active_status(&state.store, &user.id, false)
            .await
            .expect("deactivate user");

        let auth_code = AuthorizationCode {
            user_id: user.id.clone(),
            authenticator_id: auth_id,
            ..make_auth_code("")
        };
        let result = load_and_validate_grant_subject(&state, &auth_code).await;
        assert_oauth_error(result, OAuthErrorCode::InvalidGrant);
    }

    #[tokio::test]
    async fn test_grant_subject_rejects_missing_authenticator() {
        let state = test_app_state().await;
        let user = create_test_user(&state.store, "grant-no-auth@example.com").await;

        let auth_code = AuthorizationCode {
            user_id: user.id.clone(),
            authenticator_id: "revoked-and-deleted".to_string(),
            ..make_auth_code("")
        };
        let result = load_and_validate_grant_subject(&state, &auth_code).await;
        assert_oauth_error(result, OAuthErrorCode::InvalidGrant);
    }

    // =========================================================================
    // AuthCodeExchangeResult Debug redaction
    //
    // access_token and id_token are bearer credentials and must never appear
    // in `{:?}` output (defense in depth — matches AwsTokenResult).
    // =========================================================================

    #[test]
    fn test_auth_code_exchange_result_debug_redacts_tokens() {
        let result = AuthCodeExchangeResult {
            access_token: "eyJhbGciOiJFUzI1NiJ9.access-secret-token".into(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            id_token: "eyJhbGciOiJFUzI1NiJ9.id-secret-token".into(),
            scope: ScopeSet::parse("openid"),
            authorization_details: None,
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("[REDACTED]"), "{debug}");
        assert!(!debug.contains("access-secret-token"), "{debug}");
        assert!(!debug.contains("id-secret-token"), "{debug}");
        // Non-sensitive fields remain visible.
        assert!(debug.contains("Bearer"), "{debug}");
        assert!(debug.contains("3600"), "{debug}");
        assert!(debug.contains("AuthCodeExchangeResult"), "{debug}");
    }
}
