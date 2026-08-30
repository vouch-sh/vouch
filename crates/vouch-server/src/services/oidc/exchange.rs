// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Token exchange operations (RFC 8693).
//!
//! Implements:
//! - RFC 8693 - OAuth 2.0 Token Exchange

use crate::AppState;
use crate::crypto::hash_token;
use crate::db;
use crate::error::{OAuthErrorCode, ServiceError, ServiceResult};
use crate::redact_email;
use crate::services::auth::{
    ActorClaim, CreateOAuthTokenParams, MAX_DELEGATION_DEPTH, TokenBinding, TokenIssuanceProof,
    create_oauth_access_token, decode_token,
};
use crate::services::oidc::ScopeSet;
use crate::services::oidc::authorization_details::AuthorizationDetails;
use crate::services::oidc::claims::OidcIdTokenClaimsBuilder;
use jiff::Timestamp;
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use vouch_common::protocol;

/// An RFC 8693 §3 token type identifier this server accepts.
///
/// The URN spellings live in [`vouch_common::protocol`] so the CLI's exchange
/// requests are spelled from the same constants the server matches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    /// [`protocol::TOKEN_TYPE_ACCESS_TOKEN`].
    AccessToken,
    /// [`protocol::TOKEN_TYPE_ID_TOKEN`].
    IdToken,
    /// [`protocol::TOKEN_TYPE_JWT`].
    Jwt,
}

impl TokenType {
    /// The RFC 8693 §3 URN identifying this type on the wire.
    #[must_use]
    pub fn as_urn(self) -> &'static str {
        match self {
            Self::AccessToken => protocol::TOKEN_TYPE_ACCESS_TOKEN,
            Self::IdToken => protocol::TOKEN_TYPE_ID_TOKEN,
            Self::Jwt => protocol::TOKEN_TYPE_JWT,
        }
    }

    /// Parse an RFC 8693 §3 URN, or `None` for a type this server neither
    /// accepts nor issues (`saml1`, `saml2`, `refresh_token`).
    #[must_use]
    pub fn parse(urn: &str) -> Option<Self> {
        match urn {
            protocol::TOKEN_TYPE_ACCESS_TOKEN => Some(Self::AccessToken),
            protocol::TOKEN_TYPE_ID_TOKEN => Some(Self::IdToken),
            protocol::TOKEN_TYPE_JWT => Some(Self::Jwt),
            _ => None,
        }
    }
}

/// RFC 8693 §2.1 `subject_token` with the `subject_token_type` declared for it.
/// Both parameters are REQUIRED, so they are one value: a request missing
/// either cannot be turned into [`TokenExchangeParams`].
///
/// Every [`TokenType`] is accepted here. All three URNs denote a JWT this
/// server issued, and [`decode_token`] does not branch on the declared type.
///
/// The token stays wrapped in [`SecretString`] so that [`TokenExchangeParams`],
/// which derives `Debug`, cannot print a bearer credential.
#[derive(Debug)]
pub struct SubjectToken<'a> {
    /// The token representing the party the exchange is performed for.
    pub token: &'a SecretString,
    /// The type the client declared for it.
    pub token_type: TokenType,
}

impl<'a> SubjectToken<'a> {
    /// Pair the token with its declared type. Both parameters are REQUIRED,
    /// so the caller resolves their presence and this takes them by value.
    ///
    /// # Errors
    ///
    /// `invalid_request` when the declared type is one this server does not
    /// accept.
    pub fn new(token: &'a SecretString, urn: &str) -> ServiceResult<Self> {
        let token_type = TokenType::parse(urn).ok_or_else(|| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidRequest,
                "Unsupported subject_token_type",
            )
        })?;
        Ok(Self { token, token_type })
    }
}

/// RFC 8693 §2.1 `actor_token` with the `actor_token_type` declared for it:
///
/// > actor_token_type
/// >    An identifier, as described in Section 3, that indicates the type
/// >    of the security token in the "actor_token" parameter.  This is
/// >    REQUIRED when the "actor_token" parameter is present in the
/// >    request but MUST NOT be included otherwise.
///
/// Carrying both in one value is what stops the two parameters from existing
/// independently. The variants are the accepted `actor_token_type` subset:
/// [`TokenType::IdToken`] has none because an ID token asserts who a user is,
/// not who is acting, so admitting it would take a new variant here rather
/// than an edit to a list shared with the other two parameters.
///
/// As with [`SubjectToken`], the token stays wrapped in [`SecretString`].
#[derive(Debug)]
pub enum ActorToken<'a> {
    /// `actor_token_type=urn:ietf:params:oauth:token-type:access_token`.
    AccessToken(&'a SecretString),
    /// `actor_token_type=urn:ietf:params:oauth:token-type:jwt`.
    Jwt(&'a SecretString),
}

impl<'a> ActorToken<'a> {
    /// The `actor_token` value.
    #[must_use]
    pub fn token(&self) -> &'a SecretString {
        match *self {
            Self::AccessToken(token) | Self::Jwt(token) => token,
        }
    }

    /// Pair the two wire parameters, or `None` when the request carries
    /// neither and is therefore not a delegation.
    ///
    /// # Errors
    ///
    /// `invalid_request` when only one of the pair is present, or when the
    /// declared type is outside the subset above. RFC 8693 §2.1 addresses the
    /// lone `actor_token_type` to the client rather than to us, so rejecting
    /// it is our choice, taken under RFC 6749 §5.2 — `invalid_request` covers
    /// a request that "is otherwise malformed". Accepting and dropping it
    /// would hide the client bug that produced it.
    pub fn from_params(
        token: Option<&'a SecretString>,
        token_type: Option<&str>,
    ) -> ServiceResult<Option<Self>> {
        match (token, token_type) {
            (None, None) => Ok(None),
            (Some(token), Some(urn)) => match TokenType::parse(urn) {
                Some(TokenType::AccessToken) => Ok(Some(Self::AccessToken(token))),
                Some(TokenType::Jwt) => Ok(Some(Self::Jwt(token))),
                Some(TokenType::IdToken) | None => Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidRequest,
                    "Invalid actor_token_type",
                )),
            },
            (Some(_), None) => Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequest,
                "actor_token_type is required when actor_token is present",
            )),
            (None, Some(_)) => Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequest,
                "actor_token_type must not be present without actor_token",
            )),
        }
    }
}

/// Default lifetime for an exchanged OIDC ID token
/// (`requested_token_type=id_token`). Short because the token is presented
/// immediately as a federation assertion (Kubernetes, Claude/OpenAI WIF) and
/// then discarded. The effective lifetime is further capped by the subject
/// token's remaining TTL, so this is only a ceiling.
const DEFAULT_ID_TOKEN_EXPIRES_SECS: u64 = 600;

/// Parameters for token exchange (RFC 8693 Section 2.1).
#[derive(Debug)]
pub struct TokenExchangeParams<'a> {
    /// RFC 8693 Section 2.1: The subject token and its declared type (REQUIRED).
    pub subject: SubjectToken<'a>,
    /// RFC 8693 Section 2.1: The actor token and its declared type, for
    /// delegation chains (OPTIONAL).
    pub actor: Option<ActorToken<'a>>,
    /// RFC 8693 Section 2.1: The logical name of the target service (OPTIONAL).
    pub audience: Option<&'a str>,
    /// RFC 8693 Section 2.1: The requested scope for the new token (OPTIONAL).
    pub scope: Option<&'a str>,
    /// RFC 8693 Section 2.1: The desired type of the requested security token (OPTIONAL).
    pub requested_token_type: Option<TokenType>,
    /// OAuth client_id of the requesting client.
    pub client_id: &'a str,
    /// RFC 9449 §6 / RFC 8705 §3: how the issued token is bound. The DPoP
    /// witness travels instead of its thumbprint so an exchanged token cannot
    /// be sender-constrained to a key that was never proven.
    pub binding: TokenBinding<'a>,
    /// Client IP from the TCP peer socket, for temporal policy correlation
    /// (e.g. the exchange-IP-consistency policy).
    pub client_ip: Option<std::net::IpAddr>,
    /// RFC 9396 Section 6: Authorization details for narrowing.
    pub authorization_details: Option<&'a str>,
}

/// Result of a token exchange (RFC 8693 Section 2.2).
pub struct TokenExchangeResult {
    /// The security token issued by the authorization server.
    pub access_token: secrecy::SecretString,
    /// RFC 8693 Section 2.2.1: The type of the issued security token.
    pub issued_token_type: String,
    /// RFC 6749 Section 7.1: The type of the token issued (e.g.
    /// [`protocol::ACCESS_TOKEN_TYPE_BEARER`]).
    pub token_type: String,
    /// The lifetime in seconds of the access token.
    pub expires_in: u64,
    /// RFC 8693 Section 2.2: Granted scope (may be subset of requested).
    pub scope: Option<ScopeSet>,
    /// RFC 9396: Rich authorization details (inherited from subject token).
    pub authorization_details: Option<AuthorizationDetails>,
}

// Custom Debug that redacts access_token to prevent accidental log exposure of
// bearer credentials. The `access_token` field may hold either an RFC 9068
// access token or an OIDC ID token (when `requested_token_type=id_token`).
impl std::fmt::Debug for TokenExchangeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenExchangeResult")
            .field("access_token", &"[REDACTED]")
            .field("issued_token_type", &self.issued_token_type)
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("authorization_details", &self.authorization_details)
            .finish()
    }
}

/// Exchange a token for a new token (RFC 8693).
///
/// Supports both HS256 FIDO2 session tokens and ES256 OAuth access tokens
/// as subject tokens via the dual-decode helper.
///
/// # Arguments
/// * `state` - Application state
/// * `params` - Exchange parameters
///
/// # Returns
/// The exchanged token response.
///
/// # Errors
/// Returns `ServiceError` for invalid requests.
#[expect(
    clippy::too_many_lines,
    reason = "RFC 8693 token exchange: validate all params, resolve subject, issue tokens"
)]
pub(crate) async fn exchange_token(
    state: &Arc<AppState>,
    params: TokenExchangeParams<'_>,
    proof: TokenIssuanceProof,
) -> ServiceResult<TokenExchangeResult> {
    // Reject `actor_token` with `requested_token_type=id_token`. The ID-token
    // path issues a clean OIDC claim set and does not carry the `act` claim,
    // so honoring `actor_token` here would silently drop the delegation chain.
    // Refuse the combination explicitly rather than ignore the input.
    if params.requested_token_type == Some(TokenType::IdToken) && params.actor.is_some() {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequest,
            "actor_token is not supported with requested_token_type=id_token",
        ));
    }

    // Decode and validate the subject token (supports both HS256 and ES256)
    let config = state.config();
    let subject_token = params.subject.token.expose_secret();
    let subject_decoded = decode_token(subject_token, &state.oidc_key, &config.base_url)
        .ok_or_else(|| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "Invalid or expired subject token",
            )
        })?;

    // Verify the subject token's session exists
    let subject_token_hash = hash_token(subject_token);
    let subject_session = state
        .session_cache
        .get_session_by_token_hash(&state.store, &subject_token_hash)
        .await
        .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
        .ok_or_else(|| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "Subject token session not found",
            )
        })?;

    // Look up the user to get the email for the exchanged token. For access
    // tokens, the email may not be in the JWT (e.g., when only "openid" scope
    // was granted), so we always use the canonical email from the user record.
    let subject_user = db::get_user_by_id(&state.store, &subject_session.user_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
        .ok_or_else(|| {
            ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Subject token user not found")
        })?;

    if !subject_user.active {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidGrant,
            "User account is deactivated",
        ));
    }

    // Temporal policy gate (WIF/agent credential path): active exchange
    // policies — step-up recency, IP consistency, logout-invalidates —
    // are enforced here, before any token is minted.
    if let Some(ref org_id) = subject_user.org_id {
        crate::services::policy::evaluate_exchange_policies(
            state,
            org_id,
            &subject_user.id,
            &subject_user.email,
            params.client_ip,
            params.client_id,
            params.audience,
        )
        .await?;
    }

    let subject_email = &subject_user.email;

    // Handle actor token if present (for delegation chains)
    let actor_claim = if let Some(actor) = params.actor {
        let actor_token = actor.token().expose_secret();

        // Decode actor token (supports both HS256 and ES256)
        let actor_decoded = decode_token(actor_token, &state.oidc_key, &config.base_url)
            .ok_or_else(|| {
                ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Invalid actor token")
            })?;

        // Block self-delegation: actor and subject must be different users
        if actor_decoded.sub() == subject_decoded.sub() {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequest,
                "Self-delegation is not permitted",
            ));
        }

        // Verify the actor token's session exists in the database
        let actor_token_hash = hash_token(actor_token);
        if !matches!(
            state
                .session_cache
                .get_session_by_token_hash(&state.store, &actor_token_hash)
                .await,
            Ok(Some(_))
        ) {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "Actor token session not found or revoked",
            ));
        }

        // Always load the actor user to check the active flag (#550).
        // Also use the canonical email from the DB when it is absent from the JWT.
        let actor_user = db::get_user_by_id(&state.store, actor_decoded.sub())
            .await
            .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
            .ok_or_else(|| {
                ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Actor token user not found")
            })?;
        if !actor_user.active {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "User account is deactivated",
            ));
        }
        let actor_email = actor_decoded
            .email()
            .map(str::to_string)
            .unwrap_or(actor_user.email);

        // Preserve the existing actor chain from the subject token (if any)
        // to correctly track multi-hop delegation. The new actor wraps the
        // existing chain from the subject token's `act` claim.
        let existing_chain = subject_decoded.act().cloned().map(Box::new);

        let actor = ActorClaim {
            sub: actor_email,
            actor: existing_chain,
        };

        // Check delegation depth limit
        if actor.depth() > MAX_DELEGATION_DEPTH {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequest,
                "Delegation chain exceeds maximum depth",
            ));
        }

        Some(actor)
    } else {
        None
    };

    // Calculate granted scope (intersection of requested and available).
    // For FIDO2 sessions (scope: None), require explicit scope in the request
    // rather than defaulting to ScopeSet::all() to prevent scope escalation.
    let granted_scope = calculate_granted_scope(params.scope, subject_decoded.scope());

    // Cap exchanged-token lifetime by subject token's remaining TTL
    // (RFC 8693 Section 2.2).
    let mut expires_in = state.config().session_hours.saturating_mul(3600);

    if let Some(subject_exp) = subject_decoded.exp() {
        let now = Timestamp::now().as_second();
        let remaining = subject_exp.saturating_sub(now);
        if remaining > 0
            && let Ok(remaining_u64) = u64::try_from(remaining)
        {
            expires_in = expires_in.min(remaining_u64);
        }
    }

    // RFC 9068: Audience is the explicit audience param (target resource server),
    // falling back to client_id if no audience specified.
    let audience = params.audience;

    // Get authenticator_id from the session record (server-side, not from JWT)
    let authenticator_id = subject_session.authenticator_id.as_deref();

    // RFC 8693 Section 2.1: When the client requests an ID token
    // (`requested_token_type=urn:ietf:params:oauth:token-type:id_token`), mint
    // a clean OIDC ID token for federation with an external relying party
    // (Kubernetes API server, Claude/OpenAI Workload Identity Federation)
    // instead of an RFC 9068 access token. The ID token carries only the
    // standard OIDC claim set, is never persisted as a session, and is
    // short-lived. `expires_in` is already capped by the subject token's
    // remaining TTL at this point; `issue_id_token`
    // additionally caps it at `DEFAULT_ID_TOKEN_EXPIRES_SECS` (600s), so the
    // value passed in is an upper bound that the federation ceiling will
    // tighten further if needed — never bypassable.
    //
    // The issued ID token claims `hardware_verified: true` unconditionally
    // (see `OidcIdTokenClaimsBuilder::build`). To prevent a non-hardware
    // subject token (e.g., an enrollment bootstrap session created after
    // upstream SSO but before FIDO2 registration) from minting a WIF
    // assertion that downstream relying parties trust as hardware-attested,
    // gate the fork on the subject token's hardware verification level.
    if params.requested_token_type == Some(TokenType::IdToken) {
        if !subject_decoded.hardware_verification().hardware_verified() {
            return Err(ServiceError::oauth(
                OAuthErrorCode::AccessDenied,
                "ID token exchange requires a hardware-verified subject token",
            ));
        }
        return issue_id_token(
            state,
            IdTokenContext {
                user_id: &subject_session.user_id,
                email: subject_email,
                subject_token_hash: &subject_token_hash,
                audience,
                expires_in,
                hardware_aaguid: subject_session.hardware_aaguid.as_deref(),
                org_domain: subject_session.org_domain.as_deref(),
                client_id: params.client_id,
            },
        )
        .await;
    }

    // RFC 9396: Inherit authorization_details from subject token session.
    let inherited_ad_value = subject_session.authorization_details.as_ref();
    let inherited_ad_parsed =
        inherited_ad_value.and_then(|v| AuthorizationDetails::try_from(v).ok());

    // RFC 9396 Section 6: If the exchange request includes
    // authorization_details, it must be a subset of the inherited set.
    let (effective_ad, effective_ad_value);
    if let Some(requested_raw) = params.authorization_details {
        let requested_ad = AuthorizationDetails::parse(requested_raw)?;
        match &inherited_ad_parsed {
            Some(inherited) => {
                if !requested_ad.is_subset_of(inherited) {
                    return Err(ServiceError::oauth(
                        OAuthErrorCode::InvalidAuthorizationDetails,
                        "Requested authorization_details is not a \
                         subset of the inherited authorization_details",
                    ));
                }
            }
            None => {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidAuthorizationDetails,
                    "No authorization_details to narrow — \
                     subject token has none",
                ));
            }
        }
        effective_ad_value = Some(serde_json::Value::from(&requested_ad));
        effective_ad = Some(requested_ad);
    } else {
        effective_ad = inherited_ad_parsed;
        effective_ad_value = inherited_ad_value.cloned();
    }

    // Generate the exchanged token as an RFC 9068 access token (ES256)
    let session_result = create_oauth_access_token(
        state,
        CreateOAuthTokenParams {
            user_id: &subject_session.user_id,
            email: subject_email,
            authenticator_id,
            client_id: params.client_id,
            scope: granted_scope.clone(),
            binding: params.binding,
            act: actor_claim,
            audience,
            // Token exchange does not carry auth_time from the subject token
            auth_time: None,
            // Propagate hardware verification from the subject token so
            // non-FIDO2 tokens (e.g., JWT bearer) cannot be laundered into
            // hardware-verified tokens via exchange.
            hardware_verification: subject_decoded.hardware_verification(),
            session_purpose: crate::db::SessionPurpose::OAuthAccessToken,
            authorization_details: effective_ad_value.as_ref(),
            // Propagate the subject session's federation snapshot so the
            // exchanged session reports the original authenticator/org even
            // after the user rotates keys or changes orgs.
            hardware_aaguid: subject_session.hardware_aaguid.as_deref(),
            org_domain: subject_session.org_domain.as_deref(),
            // RFC 6749 Section 10.5 asks the server to revoke "all access
            // tokens already granted based on the compromised authorization
            // code". An exchanged token derives its authority from the subject
            // token, so it inherits the subject's code and is revoked with it;
            // inheriting rather than clearing also keeps a chain of exchanges
            // linked back to the code that started it.
            source_code_hash: subject_session.source_code_hash.as_deref(),
        },
        proof,
    )
    .await?;

    // Log the token exchange for audit (best-effort — failures are non-fatal)
    let now = Timestamp::now();
    let issued_token_hash = hash_token(session_result.token.expose_secret());
    let scope_string = granted_scope.as_ref().map(|s| s.to_space_separated());
    let expires_at = if let Ok(expires_seconds) = i64::try_from(expires_in)
        && let Some(exp) = now.as_second().checked_add(expires_seconds)
        && let Ok(ts) = Timestamp::from_second(exp)
    {
        ts
    } else {
        tracing::warn!(
            "token exchange audit: expires_at overflow ({expires_in}s from {}), \
             recording `now` instead",
            now.as_second()
        );
        now
    };
    if let Err(e) = db::insert_token_exchange(
        &state.store,
        &db::InsertTokenExchangeParams {
            subject_user_id: &subject_session.user_id,
            subject_token_hash: &subject_token_hash,
            actor_user_id: None,
            issued_token_hash: &issued_token_hash,
            requested_audience: params.audience,
            granted_scope: scope_string.as_deref(),
            expires_at,
        },
    )
    .await
    {
        tracing::warn!("Failed to log token exchange: {e}");
    }
    state
        .audit
        .log_credential_event(
            &subject_session.user_id,
            subject_email,
            db::CredentialAuditEnvelope {
                event_type: "token_issued".to_string(),
                success: true,
                ..Default::default()
            },
            &db::TokenExchangeDetails {
                client_id: params.client_id.to_string(),
                audience: params.audience.map(String::from),
                scope: scope_string.clone(),
                issued_token_type: TokenType::AccessToken.as_urn().to_string(),
                token_expires_at: Some(expires_at.to_string()),
            },
        )
        .await;

    tracing::info!(
        "Token exchanged for user {} (audience: {:?})",
        redact_email(subject_email),
        params.audience
    );

    Ok(TokenExchangeResult {
        access_token: session_result.token.clone(),
        issued_token_type: TokenType::AccessToken.as_urn().to_string(),
        token_type: session_result.token_type.to_string(),
        expires_in,
        scope: granted_scope,
        authorization_details: effective_ad,
    })
}

/// Inputs for issuing an exchanged OIDC ID token ([`issue_id_token`]).
struct IdTokenContext<'a> {
    /// Subject user's ID, for the token-exchange audit record.
    user_id: &'a str,
    /// Subject user's canonical email (`sub`/`email` claims).
    email: &'a str,
    /// Hash of the subject token, for the audit record.
    subject_token_hash: &'a str,
    /// Requested audience (`aud` claim); falls back to the issuer URL.
    audience: Option<&'a str>,
    /// Lifetime ceiling in seconds, already capped by subject TTL and policy.
    expires_in: u64,
    /// AAGUID snapshot from the subject session (`hardware_aaguid` claim).
    hardware_aaguid: Option<&'a str>,
    /// Organization domain snapshot from the subject session (`hd` claim).
    org_domain: Option<&'a str>,
    /// OAuth client performing the exchange, for the audit event.
    client_id: &'a str,
}

/// Mint a clean OIDC ID token (ES256) for an RFC 8693 exchange where the
/// client requested `requested_token_type=id_token`.
///
/// The token carries only the standard OIDC claim set (no AWS tags, no
/// `authorization_details`) and is never persisted as a session — it is
/// meant to be presented immediately to an external relying party.
///
/// [`IdTokenContext`] carries no [`TokenBinding`], which is the rule rather
/// than an omission: an ID token is bound when it goes to the party that
/// proved the key, and this one is minted as an assertion for a third party
/// (Kubernetes, Vault, AWS/GCP/Azure workload identity) that cannot check a
/// confirmation — there is no DPoP proof in this exchange for a consumer to
/// verify a thumbprint against. What protects it is its TTL, its audience,
/// and TLS. Having no binding to pass is what keeps that decision from
/// drifting.
async fn issue_id_token(
    state: &Arc<AppState>,
    ctx: IdTokenContext<'_>,
) -> ServiceResult<TokenExchangeResult> {
    let config = state.config();

    // Resolve the caller's org so the exchanged token uses the org's issuer and
    // its own signing key when a subdomain is claimed — giving every OIDC
    // federation consumer (GCP/Azure workload identity, Kubernetes, Vault, any
    // RP) the same per-tenant isolation as the AWS path.
    let user = db::get_user_by_id(&state.store, ctx.user_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("load user for token exchange: {e}")))?;
    let org = match user.and_then(|u| u.org_id) {
        Some(org_id) => db::get_organization(&state.store, &org_id)
            .await
            .map_err(|e| ServiceError::Internal(format!("load org for token exchange: {e}")))?,
        None => None,
    };
    let issuer = super::org_keys::org_issuer_or_base(&config, org.as_ref())?;
    let audience = ctx.audience.unwrap_or(&issuer);
    let expires_in = ctx.expires_in.min(DEFAULT_ID_TOKEN_EXPIRES_SECS);

    // `hardware_aaguid` and `hd` are session-time snapshots — they reflect the
    // authenticator/org state at session creation and survive later rotations
    // of the user's keys or organization membership.
    let claims = OidcIdTokenClaimsBuilder::for_audience(&issuer, ctx.email, audience)
        .hardware_aaguid(ctx.hardware_aaguid.map(String::from))
        .hd(ctx.org_domain.map(String::from))
        .valid_for_seconds(expires_in)
        .build()
        .map_err(|e| ServiceError::Internal(format!("Failed to build ID token claims: {e}")))?;

    let org_keys = super::org_keys::resolve_org_keys(state, org.as_ref())
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to resolve org signing key: {e}")))?;
    let signing_key = org_keys
        .as_deref()
        .map_or(&state.oidc_key, |k| &k.signers.es256);
    let id_token = signing_key
        .sign_jwt(&claims)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to sign ID token: {e}")))?;

    // Log the exchange for audit (best-effort — failures are non-fatal).
    let now = Timestamp::now();
    let issued_token_hash = hash_token(&id_token);
    let expires_at = i64::try_from(expires_in)
        .ok()
        .and_then(|s| now.as_second().checked_add(s))
        .and_then(|s| Timestamp::from_second(s).ok())
        .unwrap_or_else(|| {
            tracing::warn!(
                "ID token audit: expires_at overflow ({expires_in}s from {}), \
                 recording `now` instead",
                now.as_second()
            );
            now
        });
    if let Err(e) = db::insert_token_exchange(
        &state.store,
        &db::InsertTokenExchangeParams {
            subject_user_id: ctx.user_id,
            subject_token_hash: ctx.subject_token_hash,
            actor_user_id: None,
            issued_token_hash: &issued_token_hash,
            requested_audience: ctx.audience,
            // ID tokens do not carry OAuth scope
            granted_scope: None,
            expires_at,
        },
    )
    .await
    {
        tracing::warn!("Failed to log ID token exchange: {e}");
    }
    state
        .audit
        .log_credential_event(
            ctx.user_id,
            ctx.email,
            db::CredentialAuditEnvelope {
                event_type: "token_issued".to_string(),
                success: true,
                ..Default::default()
            },
            &db::TokenExchangeDetails {
                client_id: ctx.client_id.to_string(),
                audience: ctx.audience.map(String::from),
                scope: None,
                issued_token_type: TokenType::IdToken.as_urn().to_string(),
                token_expires_at: Some(expires_at.to_string()),
            },
        )
        .await;

    crate::infra::metrics::record_credential_issuance("oidc");

    tracing::info!(
        "Issued OIDC ID token via exchange for {} (audience: {audience})",
        redact_email(ctx.email),
    );

    Ok(TokenExchangeResult {
        access_token: id_token.into(),
        issued_token_type: TokenType::IdToken.as_urn().to_string(),
        // RFC 8693 §2.2.1: "If the issued token is not an access token or
        // usable as an access token, then the "token_type" value "N_A" is
        // used". This token is a federation assertion presented to an external
        // relying party, not a credential the client presents here.
        token_type: protocol::TOKEN_TYPE_NOT_APPLICABLE.to_string(),
        expires_in,
        scope: None,
        authorization_details: None,
    })
}

/// Calculate the granted scope based on requested and available scopes.
///
/// For FIDO2 sessions (available = `None`), require explicit scope in the
/// exchange request to prevent scope escalation. Only tokens with an
/// explicit scope set propagate their scope.
fn calculate_granted_scope(
    requested: Option<&str>,
    available: Option<&ScopeSet>,
) -> Option<ScopeSet> {
    let available_set = match available {
        Some(s) => s.clone(),
        // FIDO2 sessions don't carry scope — intersect request with all known
        // scopes to prevent escalation beyond what the server supports.
        None => {
            if let Some(requested) = requested {
                let requested_set = ScopeSet::parse(requested);
                let granted = requested_set.intersection(&ScopeSet::all());
                return if granted.is_empty() {
                    None
                } else {
                    Some(granted)
                };
            }
            // No scope in subject token and no explicit request — grant openid only
            return Some(ScopeSet::parse("openid"));
        }
    };

    if let Some(requested) = requested {
        let requested_set = ScopeSet::parse(requested);
        let granted = requested_set.intersection(&available_set);
        if granted.is_empty() {
            None
        } else {
            Some(granted)
        }
    } else if available_set.is_empty() {
        None
    } else {
        Some(available_set)
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_granted_scope_with_available() {
        let available = ScopeSet::parse("openid email");
        let result = calculate_granted_scope(None, Some(&available));
        assert_eq!(result, Some(ScopeSet::parse("openid email")));
    }

    #[test]
    fn test_calculate_granted_scope_subset() {
        let available = ScopeSet::parse("openid email profile");
        let result = calculate_granted_scope(Some("openid email"), Some(&available));
        assert_eq!(result, Some(ScopeSet::parse("openid email")));
    }

    #[test]
    fn test_calculate_granted_scope_invalid() {
        let available = ScopeSet::parse("openid");
        let result = calculate_granted_scope(Some("admin superuser"), Some(&available));
        assert_eq!(result, None);
    }

    #[test]
    fn test_calculate_granted_scope_mixed() {
        let available = ScopeSet::parse("openid email");
        let result = calculate_granted_scope(Some("openid admin email"), Some(&available));
        assert_eq!(result, Some(ScopeSet::parse("openid email")));
    }

    #[test]
    fn test_calculate_granted_scope_respects_available() {
        let available = ScopeSet::parse("openid");
        let result = calculate_granted_scope(Some("openid email"), Some(&available));
        assert_eq!(result, Some(ScopeSet::parse("openid")));
    }

    #[test]
    fn test_calculate_granted_scope_no_request_uses_available() {
        let available = ScopeSet::parse("openid");
        let result = calculate_granted_scope(None, Some(&available));
        assert_eq!(result, Some(ScopeSet::parse("openid")));
    }

    #[test]
    fn test_calculate_granted_scope_fido2_no_scope_defaults_openid() {
        // FIDO2 sessions have no scope — should default to openid
        let result = calculate_granted_scope(None, None);
        assert_eq!(result, Some(ScopeSet::parse("openid")));
    }

    #[test]
    fn test_calculate_granted_scope_fido2_with_explicit_request() {
        // FIDO2 sessions with explicit scope request
        let result = calculate_granted_scope(Some("openid email"), None);
        assert_eq!(result, Some(ScopeSet::parse("openid email")));
    }

    /// Each [`TokenType`] must map to the matching `protocol` constant in both
    /// directions. Swapped match arms would still compile and would still
    /// carry the RFC 8693 §3 prefix, so the prefix alone proves nothing.
    #[test]
    fn test_token_type_urns_match_protocol_constants() {
        use vouch_common::protocol;

        assert_eq!(
            TokenType::AccessToken.as_urn(),
            protocol::TOKEN_TYPE_ACCESS_TOKEN
        );
        assert_eq!(TokenType::IdToken.as_urn(), protocol::TOKEN_TYPE_ID_TOKEN);
        assert_eq!(TokenType::Jwt.as_urn(), protocol::TOKEN_TYPE_JWT);

        assert_eq!(
            TokenType::parse(protocol::TOKEN_TYPE_ACCESS_TOKEN),
            Some(TokenType::AccessToken)
        );
        assert_eq!(
            TokenType::parse(protocol::TOKEN_TYPE_ID_TOKEN),
            Some(TokenType::IdToken)
        );
        assert_eq!(
            TokenType::parse(protocol::TOKEN_TYPE_JWT),
            Some(TokenType::Jwt)
        );
    }

    /// RFC 8693 §3 lists types this server does not accept; they must not
    /// parse into a [`TokenType`] at all.
    #[test]
    fn test_token_type_rejects_unsupported_urns() {
        for urn in [
            "urn:ietf:params:oauth:token-type:saml1",
            "urn:ietf:params:oauth:token-type:saml2",
            "urn:ietf:params:oauth:token-type:refresh_token",
            "",
            "access_token",
        ] {
            assert_eq!(TokenType::parse(urn), None, "{urn} must not parse");
        }
    }

    // =========================================================================
    // RFC 8693 §2.1 parameter pairing
    //
    // `actor_token_type` "is REQUIRED when the `actor_token` parameter is
    // present in the request but MUST NOT be included otherwise", so every
    // combination of the two has exactly one outcome.
    // =========================================================================

    #[test]
    fn test_actor_token_absent_is_not_a_delegation() {
        let actor = ActorToken::from_params(None, None).expect("neither parameter is valid");
        assert!(actor.is_none());
    }

    #[test]
    fn test_actor_token_pairs_with_declared_type() {
        let token = SecretString::from("tok");

        let actor = ActorToken::from_params(Some(&token), Some(protocol::TOKEN_TYPE_ACCESS_TOKEN))
            .expect("access_token is an accepted actor type")
            .expect("the pair is a delegation");
        assert!(matches!(actor, ActorToken::AccessToken(_)));
        assert_eq!(actor.token().expose_secret(), "tok");

        let actor = ActorToken::from_params(Some(&token), Some(protocol::TOKEN_TYPE_JWT))
            .expect("jwt is an accepted actor type")
            .expect("the pair is a delegation");
        assert!(matches!(actor, ActorToken::Jwt(_)));
        assert_eq!(actor.token().expose_secret(), "tok");
    }

    /// The subset that diverges from `subject_token_type`: an ID token asserts
    /// who a user is, not who is acting.
    #[test]
    fn test_actor_token_rejects_id_token_type() {
        let token = SecretString::from("tok");
        let err = ActorToken::from_params(Some(&token), Some(protocol::TOKEN_TYPE_ID_TOKEN))
            .expect_err("id_token is not an accepted actor type");
        assert!(
            format!("{err:?}").contains("Invalid actor_token_type"),
            "{err:?}"
        );
    }

    #[test]
    fn test_actor_token_without_type_is_rejected() {
        let token = SecretString::from("tok");
        ActorToken::from_params(Some(&token), None)
            .expect_err("actor_token_type is REQUIRED when actor_token is present");
    }

    /// The case this pairing exists to catch: before it, the type check lived
    /// inside `if let Some(actor_token)`, so a lone `actor_token_type` was
    /// accepted and dropped.
    #[test]
    fn test_actor_token_type_without_token_is_rejected() {
        ActorToken::from_params(None, Some(protocol::TOKEN_TYPE_ACCESS_TOKEN))
            .expect_err("actor_token_type MUST NOT be included without actor_token");
    }

    /// Every [`TokenType`] is accepted as a subject type — this is the subset
    /// that must stay wider than [`ActorToken`]'s.
    #[test]
    fn test_subject_token_accepts_every_token_type() {
        let token = SecretString::from("tok");
        for token_type in [TokenType::AccessToken, TokenType::IdToken, TokenType::Jwt] {
            let subject = SubjectToken::new(&token, token_type.as_urn())
                .expect("every token type is a valid subject type");
            assert_eq!(subject.token_type, token_type);
            assert_eq!(subject.token.expose_secret(), "tok");
        }
    }

    #[test]
    fn test_subject_token_rejects_unsupported_type() {
        let token = SecretString::from("tok");
        SubjectToken::new(&token, "urn:ietf:params:oauth:token-type:saml2")
            .expect_err("saml2 is not a subject type this server accepts");
    }

    /// [`TokenExchangeParams`] derives `Debug`; holding the tokens as
    /// [`SecretString`] is what keeps a bearer credential out of that output.
    #[test]
    fn test_subject_and_actor_tokens_are_redacted_in_debug() {
        let token = SecretString::from("exchange-secret-token");
        let subject =
            SubjectToken::new(&token, protocol::TOKEN_TYPE_JWT).expect("valid subject pair");
        let actor = ActorToken::from_params(Some(&token), Some(protocol::TOKEN_TYPE_JWT))
            .expect("valid actor pair");

        let debug = format!("{subject:?} {actor:?}");
        assert!(!debug.contains("exchange-secret-token"), "{debug}");
    }

    // =========================================================================
    // TokenExchangeResult Debug redaction
    //
    // access_token is a bearer credential (RFC 9068 access token or OIDC ID
    // token when requested_token_type=id_token) and must never appear in
    // `{:?}` output (defense in depth — matches AwsTokenResult).
    // =========================================================================

    #[test]
    fn test_token_exchange_result_debug_redacts_access_token() {
        let result = TokenExchangeResult {
            access_token: "eyJhbGciOiJFUzI1NiJ9.exchange-secret-token".into(),
            issued_token_type: TokenType::AccessToken.as_urn().to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            scope: Some(ScopeSet::parse("openid")),
            authorization_details: None,
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("[REDACTED]"), "{debug}");
        assert!(!debug.contains("exchange-secret-token"), "{debug}");
        // Non-sensitive fields remain visible.
        assert!(debug.contains("Bearer"), "{debug}");
        assert!(debug.contains("3600"), "{debug}");
        assert!(debug.contains("TokenExchangeResult"), "{debug}");
    }
}
