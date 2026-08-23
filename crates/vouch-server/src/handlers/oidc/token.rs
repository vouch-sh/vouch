// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Token endpoint handler.

use super::client_auth::{
    ClientAuthFields, ClientAuthPresentation, ExtractedClientAuth, complete_client_auth,
    extract_client_auth, extract_client_credentials, with_client_auth_challenge,
};
use crate::AppState;
use crate::db::JwtAssertionJtiClaim;
use crate::error::OAuthErrorResponse;
use crate::error::{OAuthErrorCode, ServiceError};
use crate::services::auth::{
    ClientAuthProof, GrantProof, SenderConstraintProof, TokenIssuanceProof,
};
use crate::services::oidc::{
    ScopeSet,
    client_credentials::{ClientCredentialsBindings, exchange_client_credentials},
    exchange::{TokenExchangeParams, exchange_token},
    grant_type::{OAuthGrantType, ParseOAuthGrantTypeError},
    jwt_bearer::client_auth::{PendingJti, authenticate_client_jwt},
    token::{AuthCodeExchangeParams, exchange_authorization_code, validate_dpop_if_present},
};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vouch_common::protocol;

/// Token response (RFC 6749 Section 5.1).
#[derive(Serialize)]
pub(super) struct TokenResponse {
    /// The access token issued by the authorization server.
    #[serde(serialize_with = "vouch_common::serialize_secret_string")]
    pub access_token: SecretString,
    /// The type of the token issued ([`protocol::ACCESS_TOKEN_TYPE_BEARER`]
    /// or [`protocol::ACCESS_TOKEN_TYPE_DPOP`]).
    pub token_type: String,
    /// The lifetime in seconds of the access token.
    pub expires_in: u64,
    /// OIDC Core Section 3.1.3.3: The ID Token.
    #[serde(serialize_with = "vouch_common::serialize_opt_secret_string")]
    pub id_token: Option<SecretString>,
    /// RFC 6749 Section 3.3: The scope of the access token.
    pub scope: Option<ScopeSet>,
    /// User email (included in FIDO2 assertion grant responses).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// RFC 9396: Rich authorization details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<serde_json::Value>,
}

// Custom Debug that redacts tokens to prevent accidental log exposure.
impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("id_token", &"[REDACTED]")
            .field("scope", &self.scope)
            .field("email", &self.email)
            .field("authorization_details", &self.authorization_details)
            .finish()
    }
}

/// Token request for all grant types (RFC 6749 Section 4.1.3, RFC 8628 Section 3.4, RFC 8693 Section 2.1).
#[derive(Deserialize)]
pub(crate) struct TokenRequest {
    /// RFC 6749 Section 4.1.3: The grant type.
    pub grant_type: String,
    /// RFC 6749 Section 4.1.3: The authorization code received from the authorization server.
    #[serde(default)]
    pub code: Option<String>,
    /// RFC 6749 Section 4.1.3: The redirect URI used in the authorization request.
    #[serde(default)]
    pub redirect_uri: Option<String>,
    /// RFC 6749 Section 4.1.3: The client identifier.
    #[serde(default)]
    pub client_id: Option<String>,
    /// RFC 6749 Section 2.3.1: Client secret (wrapped in `SecretString` to prevent accidental logging).
    #[serde(default)]
    pub client_secret: Option<SecretString>,
    /// RFC 7636 Section 4.5: The code verifier for PKCE.
    #[serde(default)]
    pub code_verifier: Option<String>,
    /// RFC 8628 Section 3.4: The device verification code.
    #[serde(default)]
    pub device_code: Option<String>,
    /// RFC 8693 Section 2.1: The subject token to exchange.
    #[serde(default)]
    pub subject_token: Option<SecretString>,
    /// RFC 8693 Section 2.1: Type identifier for the subject token.
    #[serde(default)]
    pub subject_token_type: Option<String>,
    /// RFC 8693 Section 2.1: Optional actor token (for delegation).
    #[serde(default)]
    pub actor_token: Option<SecretString>,
    /// RFC 8693 Section 2.1: Type identifier for the actor token.
    #[serde(default)]
    pub actor_token_type: Option<String>,
    /// RFC 8693 Section 2.1: The target audience for the requested token.
    #[serde(default)]
    pub audience: Option<String>,
    /// RFC 6749 Section 3.3: The requested scope.
    #[serde(default)]
    pub scope: Option<String>,
    /// RFC 8693 Section 2.1: The desired type of the requested security token (OPTIONAL).
    #[serde(default)]
    pub requested_token_type: Option<String>,
    /// RFC 8707 Section 2: Target resource indicator (OPTIONAL).
    #[serde(default)]
    pub resource: Option<String>,
    /// RFC 7521 Section 4.2: Client assertion for JWT client authentication.
    #[serde(default)]
    pub client_assertion: Option<SecretString>,
    /// RFC 7521 Section 4.2: Client assertion type.
    #[serde(default)]
    pub client_assertion_type: Option<String>,
    /// RFC 7521 Section 4.1: The assertion for JWT bearer grants.
    #[serde(default)]
    pub assertion: Option<SecretString>,
    /// RFC 9396: Rich authorization details (JSON array).
    #[serde(default)]
    pub authorization_details: Option<String>,
}

// Custom Debug that redacts secrets to prevent accidental log exposure.
impl std::fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenRequest")
            .field("grant_type", &self.grant_type)
            .field("code", &self.code)
            .field("redirect_uri", &self.redirect_uri)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("code_verifier", &"[REDACTED]")
            .field("device_code", &self.device_code)
            .field("subject_token", &"[REDACTED]")
            .field("subject_token_type", &self.subject_token_type)
            .field("actor_token", &"[REDACTED]")
            .field("actor_token_type", &self.actor_token_type)
            .field("audience", &self.audience)
            .field("scope", &self.scope)
            .field("requested_token_type", &self.requested_token_type)
            .field("resource", &self.resource)
            .field("client_assertion", &"[REDACTED]")
            .field("client_assertion_type", &self.client_assertion_type)
            .field("assertion", &"[REDACTED]")
            .field("authorization_details", &self.authorization_details)
            .finish()
    }
}

/// Token request with a typed `grant_type` validated at the request boundary.
#[derive(Debug)]
struct ParsedTokenRequest {
    grant_type: OAuthGrantType,
    request: TokenRequest,
}

impl TokenRequest {
    fn parse(self) -> Result<ParsedTokenRequest, ParseOAuthGrantTypeError> {
        let grant_type = self.grant_type.parse::<OAuthGrantType>()?;
        Ok(ParsedTokenRequest {
            grant_type,
            request: self,
        })
    }
}

/// Token exchange response (RFC 8693 Section 2.2).
#[derive(Serialize)]
pub(super) struct TokenExchangeResponse {
    /// The security token issued by the authorization server.
    #[serde(serialize_with = "vouch_common::serialize_secret_string")]
    pub access_token: SecretString,
    /// RFC 8693 Section 2.2.1: The type of the issued security token.
    pub issued_token_type: String,
    /// The type of the token issued (e.g. [`protocol::ACCESS_TOKEN_TYPE_BEARER`]).
    pub token_type: String,
    /// The lifetime in seconds of the access token.
    pub expires_in: u64,
    /// RFC 6749 Section 3.3: The scope of the access token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeSet>,
    /// RFC 9396: Rich authorization details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<serde_json::Value>,
}

// Custom Debug that redacts access_token to prevent accidental log exposure.
impl std::fmt::Debug for TokenExchangeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenExchangeResponse")
            .field("access_token", &"[REDACTED]")
            .field("issued_token_type", &self.issued_token_type)
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("authorization_details", &self.authorization_details)
            .finish()
    }
}

// Maximum lengths for token request parameters.
const MAX_TOKEN_REDIRECT_URI_LEN: usize = 2048;
const MAX_TOKEN_CLIENT_ID_LEN: usize = 256;
const MAX_TOKEN_SCOPE_LEN: usize = 512;
const MAX_TOKEN_RESOURCE_LEN: usize = 2048;
/// Maximum length for JWT assertions (RFC 7521).
const MAX_ASSERTION_LEN: usize = 8192;

/// POST /oauth/token
///
/// Unified token endpoint (RFC 6749 Section 3.2) that handles:
/// - `authorization_code` grant (RFC 6749 Section 4.1.3)
/// - `urn:ietf:params:oauth:grant-type:device_code` grant (RFC 8628 Section 3.4)
/// - `urn:ietf:params:oauth:grant-type:token-exchange` grant (RFC 8693 Section 2.1)
pub(crate) async fn token(
    State(state): State<Arc<AppState>>,
    client_info: crate::db::ClientInfo,
    client_cert: crate::handlers::extractors::OptionalClientCert,
    headers: HeaderMap,
    axum::Form(params): axum::Form<TokenRequest>,
) -> Response {
    // Input length validation — reject oversized parameters early.
    if let Some(ref v) = params.code_verifier
        && !is_valid_pkce_verifier(v)
    {
        return token_error_response(
            OAuthErrorCode::InvalidRequest,
            "code_verifier must be 43-128 characters and contain only [A-Za-z0-9\\-._~]",
        );
    }
    if let Some(ref v) = params.redirect_uri
        && v.len() > MAX_TOKEN_REDIRECT_URI_LEN
    {
        return token_error_response(
            OAuthErrorCode::InvalidRequest,
            &format!("redirect_uri exceeds maximum length of {MAX_TOKEN_REDIRECT_URI_LEN}"),
        );
    }
    if let Some(ref v) = params.client_id
        && v.len() > MAX_TOKEN_CLIENT_ID_LEN
    {
        return token_error_response(
            OAuthErrorCode::InvalidRequest,
            &format!("client_id exceeds maximum length of {MAX_TOKEN_CLIENT_ID_LEN}"),
        );
    }
    if let Some(ref v) = params.scope
        && v.len() > MAX_TOKEN_SCOPE_LEN
    {
        return token_error_response(
            OAuthErrorCode::InvalidRequest,
            &format!("scope exceeds maximum length of {MAX_TOKEN_SCOPE_LEN}"),
        );
    }
    if let Some(ref v) = params.resource
        && v.len() > MAX_TOKEN_RESOURCE_LEN
    {
        return token_error_response(
            OAuthErrorCode::InvalidRequest,
            &format!("resource exceeds maximum length of {MAX_TOKEN_RESOURCE_LEN}"),
        );
    }
    if let Some(ref v) = params.client_assertion
        && v.expose_secret().len() > MAX_ASSERTION_LEN
    {
        return token_error_response(
            OAuthErrorCode::InvalidRequest,
            &format!("client_assertion exceeds maximum length of {MAX_ASSERTION_LEN}"),
        );
    }
    if let Some(ref v) = params.assertion
        && v.expose_secret().len() > MAX_ASSERTION_LEN
    {
        return token_error_response(
            OAuthErrorCode::InvalidRequest,
            &format!("assertion exceeds maximum length of {MAX_ASSERTION_LEN}"),
        );
    }
    // RFC 9396: authorization_details size limit (same as MAX_ASSERTION_LEN = 8192)
    if let Some(ref v) = params.authorization_details
        && v.len() > MAX_ASSERTION_LEN
    {
        return token_error_response(
            OAuthErrorCode::InvalidAuthorizationDetails,
            &format!("authorization_details exceeds maximum length of {MAX_ASSERTION_LEN}"),
        );
    }

    // RFC 6749 Section 5.2: Return unsupported_grant_type error for unknown grants.
    let ParsedTokenRequest {
        grant_type,
        request: params,
    } = match params.parse() {
        Ok(parsed) => parsed,
        Err(_) => {
            let supported = OAuthGrantType::supported_wire_values().join(", ");
            return token_error_response(
                OAuthErrorCode::UnsupportedGrantType,
                &format!("Supported grant types: {supported}"),
            );
        }
    };

    match grant_type {
        OAuthGrantType::AuthorizationCode => {
            handle_authorization_code_grant(State(state), client_cert, headers, params).await
        }
        OAuthGrantType::ClientCredentials => {
            handle_client_credentials_grant(State(state), client_info, client_cert, headers, params)
                .await
        }
        OAuthGrantType::DeviceCode => {
            handle_device_code_grant(State(state), client_info, client_cert, headers, params).await
        }
        OAuthGrantType::TokenExchange => {
            handle_token_exchange_grant(State(state), client_info, client_cert, headers, params)
                .await
        }
        OAuthGrantType::Fido2Assertion => {
            handle_fido2_assertion_grant(State(state), client_info, client_cert, headers, params)
                .await
        }
    }
}

/// Commit an optional pending JTI and translate failures to a response-ready
/// `Response`. Shared by the token-issuance handlers so per-grant logging and
/// error mapping stay consistent across grants.
///
/// The MUST-run-before-grant-state-persistence invariant (issue #391) is
/// enforced by the type system: the returned `Option<JwtAssertionJtiClaim>` is
/// the only path to building a `ClientAuthProof::PrivateKeyJwt`, which is the
/// only path to a `TokenIssuanceProof` carrying that client-auth method.
async fn commit_optional_jti(
    state: &Arc<AppState>,
    pending: Option<PendingJti>,
    grant_name: &'static str,
) -> Result<Option<JwtAssertionJtiClaim>, Response> {
    let Some(p) = pending else {
        return Ok(None);
    };
    p.commit(state).await.map_err(|e| {
        tracing::warn!("JTI commit failed for {grant_name}: {e:?}");
        e.into_service_error().into_oauth_response().into_response()
    })
}

/// Resolve non-JWT client authentication for the `authorization_code`
/// grant. Returns the resolved client paired with a fully-formed
/// [`ClientAuthProof`] (one of `ClientSecret`, `MutualTls`, `NoAuth`)
/// on success, or a response-ready `Response` on any auth failure
/// (unknown client, invalid secret, missing required cert, confidential
/// client presented without auth, etc.).
async fn resolve_non_jwt_auth(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    params: &TokenRequest,
    client_cert: &crate::handlers::extractors::OptionalClientCert,
) -> Result<
    (
        crate::services::oidc::token::AuthenticatedClient,
        ClientAuthProof,
    ),
    Response,
> {
    let creds = extract_client_credentials(
        headers,
        params.client_id.as_deref(),
        params.client_secret.clone(),
    );
    let Some((c, _presentation)) = creds else {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "Client authentication or client_id required",
        )
        .into_oauth_response()
        .into_response());
    };

    // If a secret was presented, try secret auth first. `authenticate_client`
    // returns `Ok((client, None))` for mTLS-registered clients (RFC 8705 §2:
    // mTLS is the auth method — the secret is intentionally NOT validated).
    // In that case we fall through to the mTLS dispatch below.
    let secret_auth_outcome = if c.client_secret.is_some() {
        match crate::services::oidc::token::authenticate_client(state, &c).await {
            Ok((auth_client, Some(verification))) => {
                return Ok((auth_client, ClientAuthProof::ClientSecret(verification)));
            }
            Ok((auth_client, None)) => Some(auth_client),
            Err(e) => {
                return Err(e.into_service_error().into_oauth_response().into_response());
            }
        }
    } else {
        None
    };

    // No verified client_secret. Dispatch on the client's registered
    // `token_endpoint_auth_method` — RFC 8705 §2 for mTLS-registered
    // clients, RFC 6749 §2.1 for public. If `secret_auth_outcome` is
    // `Some`, we already loaded the client; otherwise look it up.
    let client = match secret_auth_outcome {
        Some(auth_client) => auth_client.client,
        None => {
            // Fail closed: a DB error is a transient failure (→ 500), not a
            // missing client (→ invalid_client). Collapsing DB-Err + None +
            // inactive into one `invalid_client` masked connectivity problems.
            let db_result = crate::db::get_oauth_client_by_client_id(&state.store, &c.client_id)
                .await
                .map_err(|e| {
                    tracing::error!(
                        client_id = %c.client_id,
                        "DB error looking up OAuth client: {e}"
                    );
                    ServiceError::Internal("Database error".to_string())
                        .into_oauth_response()
                        .into_response()
                })?;
            match db_result.filter(|oc| oc.active) {
                Some(client) => client,
                None => {
                    return Err(ServiceError::oauth(
                        OAuthErrorCode::InvalidClient,
                        "Unknown client_id",
                    )
                    .into_oauth_response()
                    .into_response());
                }
            }
        }
    };
    let is_mtls_registered = matches!(
        client.token_endpoint_auth_method,
        crate::db::TokenEndpointAuthMethod::TlsClientAuth
            | crate::db::TokenEndpointAuthMethod::SelfSignedTlsClientAuth
    );
    if is_mtls_registered {
        let Some(cert) = client_cert.0.as_ref() else {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClient,
                "mTLS client certificate required",
            )
            .into_oauth_response()
            .into_response());
        };
        return match crate::services::oidc::token::authenticate_client_mtls(state, &client, cert)
            .await
        {
            Ok(verification) => Ok((
                crate::services::oidc::token::AuthenticatedClient {
                    client,
                    is_public: false,
                },
                ClientAuthProof::MutualTls(verification),
            )),
            Err(e) => Err(e.into_service_error().into_oauth_response().into_response()),
        };
    }
    // Not mTLS-registered, no secret presented — must be a public client.
    // `for_public_client` errors if the client is confidential, closing
    // the "developer forgot to authenticate" hole at the type system level.
    let witness = match crate::services::auth::NoClientAuth::for_public_client(&client) {
        Ok(w) => w,
        Err(svc) => return Err(svc.into_oauth_response().into_response()),
    };
    Ok((
        crate::services::oidc::token::AuthenticatedClient {
            client,
            is_public: true,
        },
        ClientAuthProof::NoAuth(witness),
    ))
}

/// Handle authorization code grant.
async fn handle_authorization_code_grant(
    State(state): State<Arc<AppState>>,
    client_cert: crate::handlers::extractors::OptionalClientCert,
    headers: HeaderMap,
    params: TokenRequest,
) -> Response {
    // RFC 6749 Section 4.1.3: The "code" parameter is REQUIRED
    let code = match &params.code {
        Some(c) => c,
        None => {
            return token_error_response(OAuthErrorCode::InvalidRequest, "Missing code parameter");
        }
    };

    // Extract client credentials from headers or body (including JWT assertion)
    let has_jwt_assertion = params.client_assertion.is_some();

    // For JWT assertion, authenticate and extract the client
    let (jwt_authenticated, jwt_pending_jti, jwt_auth) = if has_jwt_assertion {
        let client_auth = match extract_client_auth(&headers, &params) {
            Ok(auth) => auth,
            Err(resp) => return resp,
        };
        if let ExtractedClientAuth::JwtAssertion {
            client_assertion,
            client_id,
        } = client_auth
        {
            match authenticate_client_jwt(&state, &client_assertion, client_id.as_deref()).await {
                Ok((client, pending_jti, auth)) => (Some(client), Some(pending_jti), Some(auth)),
                Err(e) => return e.into_service_error().into_oauth_response().into_response(),
            }
        } else {
            (None, None, None)
        }
    } else {
        (None, None, None)
    };

    // RFC 9449 Section 5: Validate DPoP proof if present. Must happen
    // BEFORE client-auth resolution so the `use_dpop_nonce` recovery
    // path (nonce header in the response) fires regardless of whether
    // the request also has invalid client auth.
    let dpop_header = headers
        .get(protocol::HEADER_DPOP)
        .and_then(|v| v.to_str().ok());
    let dpop_proof =
        match validate_dpop_if_present(&state, dpop_header, "POST", "/oauth/token").await {
            Ok(proof) => proof,
            Err(crate::services::oidc::dpop::DpopError::UseNonce(nonce)) => {
                return dpop_use_nonce_response(&nonce);
            }
            Err(e @ crate::services::oidc::dpop::DpopError::Database(_)) => {
                return ServiceError::oauth(OAuthErrorCode::ServerError, e.to_string())
                    .into_oauth_response()
                    .into_response();
            }
            Err(e) => {
                return ServiceError::oauth(OAuthErrorCode::InvalidDpopProof, e.to_string())
                    .into_oauth_response()
                    .into_response();
            }
        };

    // For non-JWT auth, resolve `(AuthenticatedClient, ClientAuthProof)`
    // directly. The handler runs ALL non-JWT authentication itself so
    // the constructed `ClientAuthProof` is fully resolved before the
    // exchange — no transitional placeholders or downstream promotion.
    let non_jwt_auth = if has_jwt_assertion {
        None
    } else {
        match resolve_non_jwt_auth(&state, &headers, &params, &client_cert).await {
            Ok(pair) => Some(pair),
            // RFC 6749 §5.2: every failure inside `resolve_non_jwt_auth` is a
            // client-authentication failure, so a client that used
            // `Authorization: Basic` is owed the matching challenge on the 401.
            Err(resp) => {
                return with_client_auth_challenge(ClientAuthPresentation::of(&headers), resp);
            }
        }
    };

    // Commit the JTI (if any) and resolve `(authenticated_client,
    // client_auth)` in one move from both auth paths. Each branch
    // carries a sealed witness produced by the upstream auth step —
    // there is no path that produces a `ClientAuthProof` without a real
    // witness, which is the chokepoint guarantee.
    let jti_claim = match commit_optional_jti(&state, jwt_pending_jti, "authorization_code").await {
        Ok(c) => c,
        Err(r) => return r,
    };
    // RFC 7523 §3: `jti` is OPTIONAL. Gate on `jwt_auth` (the auth-succeeded
    // witness), not on `jti_claim` — a non-FAPI client may legitimately omit
    // `jti`, in which case `jti_claim == None` but JWT auth still succeeded.
    let (authenticated_client, client_auth) = match (jwt_authenticated, jwt_auth, non_jwt_auth) {
        (Some(client), Some(auth), _) => (
            client,
            ClientAuthProof::PrivateKeyJwt(crate::services::auth::JwtClientAuthProof::new(
                auth, jti_claim,
            )),
        ),
        (_, _, Some(pair)) => pair,
        _ => {
            return ServiceError::oauth(
                OAuthErrorCode::InvalidClient,
                "Client authentication required",
            )
            .into_oauth_response()
            .into_response();
        }
    };

    // RFC 8705 Section 2: Validate mTLS client auth for JWT-authenticated clients
    // that are also registered for mTLS (e.g., FAPI clients using both).
    let has_mtls_cert = client_cert.0.is_some();
    if !matches!(client_auth, ClientAuthProof::MutualTls(_))
        && matches!(client_auth, ClientAuthProof::PrivateKeyJwt(_))
        && let Err(resp) =
            validate_mtls_client_auth(&state, &authenticated_client, &client_cert).await
    {
        return *resp;
    }

    // Every sender-constraint requirement registered for this client.
    let sender_constraint = match SenderConstraintProof::validate(
        &authenticated_client.client,
        crate::services::oidc::fapi::SenderConstraints {
            dpop: dpop_proof.is_some(),
            mtls_cert: has_mtls_cert,
        },
    ) {
        Ok(witness) => witness,
        Err(e) => return e.into_oauth_response().into_response(),
    };

    // RFC 8705 Section 3: Bind access token to cert thumbprint only when opted in.
    let mtls_thumbprint = extract_mtls_thumbprint(&authenticated_client, &client_cert);

    // Exchange the authorization code. `authenticated_client` is the
    // client_id used for RFC 8725 §3.9 audience validation.
    let exchange_params = AuthCodeExchangeParams {
        code,
        redirect_uri: params.redirect_uri.as_deref(),
        authenticated_client: Some(&authenticated_client),
        code_verifier: params.code_verifier.as_deref(),
        dpop_proof,
        client_id: &authenticated_client.client.client_id,
        resource: params.resource.as_deref(),
        authorization_details: params.authorization_details.as_deref(),
        mtls_cert_thumbprint: mtls_thumbprint.as_deref(),
    };

    match exchange_authorization_code(&state, exchange_params, client_auth, sender_constraint).await
    {
        Ok(result) => {
            crate::infra::metrics::record_auth_event("authorization_code_success");
            token_success_response(TokenResponse {
                access_token: result.access_token,
                token_type: result.token_type,
                expires_in: result.expires_in,
                id_token: Some(result.id_token),
                scope: Some(result.scope),
                email: None,
                authorization_details: result
                    .authorization_details
                    .as_ref()
                    .map(serde_json::Value::from),
            })
        }
        Err(e) => e.into_oauth_response().into_response(),
    }
}

/// Handle client credentials grant (RFC 6749 Section 4.4).
///
/// Requires client authentication via `client_secret_basic` or `client_secret_post`.
/// Issues an access token with `hardware_verified: false` and no ID token.
async fn handle_client_credentials_grant(
    State(state): State<Arc<AppState>>,
    client_info: crate::db::ClientInfo,
    client_cert: crate::handlers::extractors::OptionalClientCert,
    headers: HeaderMap,
    params: TokenRequest,
) -> Response {
    // RFC 6749 Section 4.4.2: Client authentication is REQUIRED
    let client_auth = match extract_client_auth(&headers, &params) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };

    let Some(any_auth) = (match complete_client_auth(&state, client_auth).await {
        Ok(result) => result,
        Err(resp) => return resp,
    }) else {
        return ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "Client authentication required for client_credentials grant",
        )
        .into_oauth_response()
        .into_response();
    };
    let authenticated_client = any_auth.client;
    let pending_jti = any_auth.pending_jti;
    let jwt_auth = any_auth.jwt_auth;
    let secret_verification = any_auth.secret_verification;

    // RFC 6749 Section 4.4: client_credentials requires a confidential client
    if authenticated_client.is_public {
        return ServiceError::oauth(
            OAuthErrorCode::UnauthorizedClient,
            "Public clients are not allowed to use client_credentials grant",
        )
        .into_oauth_response()
        .into_response();
    }

    // RFC 8705 Section 2: Validate mTLS client auth if the client uses it.
    let mtls_verification =
        match validate_mtls_client_auth(&state, &authenticated_client, &client_cert).await {
            Ok(v) => v,
            Err(resp) => return *resp,
        };

    // RFC 8705 Section 3: Bind access token to cert thumbprint only when opted in.
    let mtls_thumbprint = extract_mtls_thumbprint(&authenticated_client, &client_cert);

    // RFC 9449 Section 5: Validate the DPoP proof if present so the issued
    // token carries a `cnf.jkt` binding.
    let dpop_header = headers
        .get(protocol::HEADER_DPOP)
        .and_then(|v| v.to_str().ok());
    let dpop_proof =
        match validate_dpop_if_present(&state, dpop_header, "POST", "/oauth/token").await {
            Ok(proof) => proof,
            Err(crate::services::oidc::dpop::DpopError::UseNonce(nonce)) => {
                return dpop_use_nonce_response(&nonce);
            }
            Err(e @ crate::services::oidc::dpop::DpopError::Database(_)) => {
                return ServiceError::oauth(OAuthErrorCode::ServerError, e.to_string())
                    .into_oauth_response()
                    .into_response();
            }
            Err(e) => {
                return ServiceError::oauth(OAuthErrorCode::InvalidDpopProof, e.to_string())
                    .into_oauth_response()
                    .into_response();
            }
        };

    // FAPI 2.0 Section 5.3.2.1: sender-constrained access tokens required
    // (DPoP or mTLS), same as every other grant a FAPI client can reach.
    let sender_constraint = match SenderConstraintProof::validate(
        &authenticated_client.client,
        crate::services::oidc::fapi::SenderConstraints {
            dpop: dpop_proof.is_some(),
            mtls_cert: client_cert.0.is_some(),
        },
    ) {
        Ok(witness) => witness,
        Err(e) => return e.into_oauth_response().into_response(),
    };

    let jti_claim = match commit_optional_jti(&state, pending_jti, "client_credentials").await {
        Ok(c) => c,
        Err(r) => return r,
    };
    // Client-credentials grant: the client MUST authenticate (RFC 6749
    // §4.4). Resolve the client-auth proof by precedence: JWT → secret
    // → mTLS. If none succeeded, validate that the client is registered
    // as public via `NoClientAuth::for_public_client` (which fails if
    // the client is confidential — closing the "developer forgot to
    // authenticate" hole).
    //
    // RFC 7523 §3: `jti` is OPTIONAL — gate the JWT arm on `jwt_auth`,
    // not on `jti_claim`, so a non-FAPI client without `jti` is accepted.
    let client_auth = if let Some(auth) = jwt_auth {
        ClientAuthProof::PrivateKeyJwt(crate::services::auth::JwtClientAuthProof::new(
            auth, jti_claim,
        ))
    } else {
        match (secret_verification, mtls_verification) {
            (Some(_), Some(_)) => {
                return ServiceError::oauth(
                    OAuthErrorCode::InvalidClient,
                    "client presented multiple authentication methods \
                     (RFC 6749 §2.3 violation)",
                )
                .into_oauth_response()
                .into_response();
            }
            (Some(s), None) => ClientAuthProof::ClientSecret(s),
            (None, Some(m)) => ClientAuthProof::MutualTls(m),
            (None, None) => {
                let witness = match crate::services::auth::NoClientAuth::for_public_client(
                    &authenticated_client.client,
                ) {
                    Ok(w) => w,
                    Err(svc) => return svc.into_oauth_response().into_response(),
                };
                ClientAuthProof::NoAuth(witness)
            }
        }
    };
    let proof = TokenIssuanceProof {
        grant: GrantProof::ClientCredentials,
        client_auth,
        sender_constraint,
    };

    match exchange_client_credentials(
        &state,
        &authenticated_client.client,
        params.scope.as_deref(),
        ClientCredentialsBindings {
            dpop_proof: dpop_proof.as_ref(),
            mtls_cert_thumbprint: mtls_thumbprint.as_deref(),
        },
        proof,
    )
    .await
    {
        Ok(result) => {
            // Record audit event
            crate::db::record_oauth_event(
                &state.audit,
                &state.store,
                &crate::db::RecordOAuthEventParams {
                    oauth_client_id: &authenticated_client.client.id,
                    event_type: crate::db::OAuthEventType::TokenIssued,
                    user_id: None,
                    ip_address: client_info.client_ip,
                    user_agent: client_info.user_agent.as_deref(),
                    details: Some("grant_type=client_credentials"),
                },
            )
            .await;

            token_success_response(TokenResponse {
                access_token: result.access_token,
                token_type: result.token_type,
                expires_in: result.expires_in,
                id_token: None,
                scope: result.scope,
                email: None,
                authorization_details: None,
            })
        }
        Err(e) => e.into_oauth_response().into_response(),
    }
}

/// Handle device code grant.
async fn handle_device_code_grant(
    State(state): State<Arc<AppState>>,
    client_info: crate::db::ClientInfo,
    client_cert: crate::handlers::extractors::OptionalClientCert,
    headers: HeaderMap,
    params: TokenRequest,
) -> Response {
    let device_req = vouch_common::DeviceTokenRequest {
        grant_type: params.grant_type,
        device_code: params.device_code.unwrap_or_default(),
    };
    match super::super::device::device_token(
        State(state),
        client_info,
        client_cert,
        headers,
        Json(device_req),
    )
    .await
    {
        Ok(resp) => resp.into_response(),
        Err(resp) => resp,
    }
}

/// Handle token exchange grant (RFC 8693).
///
/// RFC 8693 Section 2.1: The token exchange grant requires client
/// authentication. The client_id in the authenticated credentials must
/// match any client_id provided in the request body.
async fn handle_token_exchange_grant(
    State(state): State<Arc<AppState>>,
    client_info: crate::db::ClientInfo,
    client_cert: crate::handlers::extractors::OptionalClientCert,
    headers: HeaderMap,
    params: TokenRequest,
) -> Response {
    // Extract client authentication (supports secret-based and JWT assertion)
    let client_auth = match extract_client_auth(&headers, &params) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };

    // Authenticate client (required for token exchange)
    let Some(any_auth) = (match complete_client_auth(&state, client_auth).await {
        Ok(result) => result,
        Err(resp) => return resp,
    }) else {
        return ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "Client authentication required for token exchange",
        )
        .into_oauth_response()
        .into_response();
    };
    let authenticated_client = any_auth.client;
    let pending_jti = any_auth.pending_jti;
    let jwt_auth = any_auth.jwt_auth;
    let secret_verification = any_auth.secret_verification;

    // RFC 9449 Section 5: Validate DPoP proof if present at the token endpoint
    let dpop_header = headers
        .get(protocol::HEADER_DPOP)
        .and_then(|v| v.to_str().ok());
    let dpop_proof =
        match validate_dpop_if_present(&state, dpop_header, "POST", "/oauth/token").await {
            Ok(proof) => proof,
            Err(crate::services::oidc::dpop::DpopError::UseNonce(nonce)) => {
                return dpop_use_nonce_response(&nonce);
            }
            Err(e @ crate::services::oidc::dpop::DpopError::Database(_)) => {
                return ServiceError::oauth(OAuthErrorCode::ServerError, e.to_string())
                    .into_oauth_response()
                    .into_response();
            }
            Err(e) => {
                return ServiceError::oauth(OAuthErrorCode::InvalidDpopProof, e.to_string())
                    .into_oauth_response()
                    .into_response();
            }
        };

    // RFC 8705 Section 2: Validate mTLS client auth if the client uses it.
    let mtls_verification =
        match validate_mtls_client_auth(&state, &authenticated_client, &client_cert).await {
            Ok(v) => v,
            Err(resp) => return *resp,
        };

    // RFC 8705 Section 3: Bind access token to cert thumbprint only when opted in.
    let mtls_thumbprint = extract_mtls_thumbprint(&authenticated_client, &client_cert);

    // FAPI 2.0 Section 5.3.2.1: sender-constrained access tokens required
    // (DPoP or mTLS) on every grant a FAPI client can use — without this, a
    // FAPI client could exchange a bound subject_token for an unbound one.
    // Mirrors `handle_authorization_code_grant`.
    let sender_constraint = match SenderConstraintProof::validate(
        &authenticated_client.client,
        crate::services::oidc::fapi::SenderConstraints {
            dpop: dpop_proof.is_some(),
            mtls_cert: client_cert.0.is_some(),
        },
    ) {
        Ok(witness) => witness,
        Err(e) => return e.into_oauth_response().into_response(),
    };

    // RFC 8707: If resource is present, use it as audience (unless audience is explicitly set).
    // If both are present, they must match.
    let effective_audience = match (params.audience.as_deref(), params.resource.as_deref()) {
        (Some(aud), Some(res)) if aud != res => {
            return ServiceError::oauth(
                OAuthErrorCode::InvalidTarget,
                "resource and audience parameters must match when both are provided",
            )
            .into_oauth_response()
            .into_response();
        }
        (Some(aud), _) => Some(aud),
        (None, Some(res)) => Some(res),
        (None, None) => None,
    };

    let exchange_params = TokenExchangeParams {
        subject_token: params
            .subject_token
            .as_ref()
            .map_or("", |s| s.expose_secret()),
        subject_token_type: params.subject_token_type.as_deref().unwrap_or_default(),
        actor_token: params.actor_token.as_ref().map(|s| s.expose_secret()),
        actor_token_type: params.actor_token_type.as_deref(),
        audience: effective_audience,
        scope: params.scope.as_deref(),
        requested_token_type: params.requested_token_type.as_deref(),
        client_id: &authenticated_client.client.client_id,
        dpop_proof: dpop_proof.as_ref(),
        authorization_details: params.authorization_details.as_deref(),
        mtls_cert_thumbprint: mtls_thumbprint.as_deref(),
        client_ip: client_info.client_ip,
    };

    let jti_claim = match commit_optional_jti(&state, pending_jti, "token_exchange").await {
        Ok(c) => c,
        Err(r) => return r,
    };
    // Token exchange: same precedence + public-client validation as
    // client_credentials. Token exchange does not mandate confidential
    // clients per RFC 8693, but `NoClientAuth::for_public_client` is
    // still the right check for the "no method succeeded" case — a
    // confidential client must authenticate.
    //
    // RFC 7523 §3: `jti` is OPTIONAL — gate the JWT arm on `jwt_auth`,
    // not on `jti_claim`, so a non-FAPI client without `jti` is accepted.
    let client_auth = if let Some(auth) = jwt_auth {
        ClientAuthProof::PrivateKeyJwt(crate::services::auth::JwtClientAuthProof::new(
            auth, jti_claim,
        ))
    } else {
        match (secret_verification, mtls_verification) {
            (Some(_), Some(_)) => {
                return ServiceError::oauth(
                    OAuthErrorCode::InvalidClient,
                    "client presented multiple authentication methods \
                     (RFC 6749 §2.3 violation)",
                )
                .into_oauth_response()
                .into_response();
            }
            (Some(s), None) => ClientAuthProof::ClientSecret(s),
            (None, Some(m)) => ClientAuthProof::MutualTls(m),
            (None, None) => {
                let witness = match crate::services::auth::NoClientAuth::for_public_client(
                    &authenticated_client.client,
                ) {
                    Ok(w) => w,
                    Err(svc) => return svc.into_oauth_response().into_response(),
                };
                ClientAuthProof::NoAuth(witness)
            }
        }
    };
    let proof = TokenIssuanceProof {
        grant: GrantProof::TokenExchange,
        client_auth,
        sender_constraint,
    };

    match exchange_token(&state, exchange_params, proof).await {
        Ok(result) => token_success_response(TokenExchangeResponse {
            access_token: result.access_token,
            issued_token_type: result.issued_token_type,
            token_type: result.token_type,
            expires_in: result.expires_in,
            scope: result.scope,
            authorization_details: result
                .authorization_details
                .as_ref()
                .map(serde_json::Value::from),
        }),
        Err(e) => e.into_oauth_response().into_response(),
    }
}

/// Implement `ClientAuthFields` for `TokenRequest` to enable shared client
/// authentication extraction.
impl ClientAuthFields for TokenRequest {
    fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    fn client_secret(&self) -> Option<SecretString> {
        self.client_secret.clone()
    }

    fn client_assertion(&self) -> Option<&str> {
        self.client_assertion.as_ref().map(|s| s.expose_secret())
    }

    fn client_assertion_type(&self) -> Option<&str> {
        self.client_assertion_type.as_deref()
    }
}

/// Handle FIDO2 assertion grant.
///
/// Requires `private_key_jwt` client authentication and a FIDO2 assertion
/// in the `assertion` parameter. Optionally requires DPoP for FAPI clients.
async fn handle_fido2_assertion_grant(
    State(state): State<Arc<AppState>>,
    client_info: crate::db::ClientInfo,
    client_cert: crate::handlers::extractors::OptionalClientCert,
    headers: HeaderMap,
    params: TokenRequest,
) -> Response {
    // The assertion parameter is REQUIRED
    let assertion = match &params.assertion {
        Some(a) => a.clone(),
        None => {
            return token_error_response(
                OAuthErrorCode::InvalidRequest,
                "Missing assertion parameter for fido2-assertion grant",
            );
        }
    };

    // Extract and authenticate client via private_key_jwt
    let client_auth = match extract_client_auth(&headers, &params) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };

    let (jwt_authenticated, jwt_pending_jti, jwt_auth) = match client_auth {
        ExtractedClientAuth::JwtAssertion {
            client_assertion,
            client_id,
        } => match authenticate_client_jwt(&state, &client_assertion, client_id.as_deref()).await {
            Ok((client, pending_jti, auth)) => (client, pending_jti, auth),
            Err(e) => return e.into_service_error().into_oauth_response().into_response(),
        },
        _ => {
            return token_error_response(
                OAuthErrorCode::InvalidClient,
                "fido2-assertion grant requires private_key_jwt client authentication",
            );
        }
    };

    // Validate DPoP proof if present
    let dpop_header = headers
        .get(protocol::HEADER_DPOP)
        .and_then(|v| v.to_str().ok());
    let dpop_proof =
        match validate_dpop_if_present(&state, dpop_header, "POST", "/oauth/token").await {
            Ok(proof) => proof,
            Err(crate::services::oidc::dpop::DpopError::UseNonce(nonce)) => {
                return dpop_use_nonce_response(&nonce);
            }
            Err(e @ crate::services::oidc::dpop::DpopError::Database(_)) => {
                return ServiceError::oauth(OAuthErrorCode::ServerError, e.to_string())
                    .into_oauth_response()
                    .into_response();
            }
            Err(e) => {
                return ServiceError::oauth(OAuthErrorCode::InvalidDpopProof, e.to_string())
                    .into_oauth_response()
                    .into_response();
            }
        };

    let has_mtls_cert = client_cert.0.is_some();

    // FAPI 2.0: Require sender-constrained tokens (DPoP or mTLS)
    let sender_constraint = match SenderConstraintProof::validate(
        &jwt_authenticated.client,
        crate::services::oidc::fapi::SenderConstraints {
            dpop: dpop_proof.is_some(),
            mtls_cert: has_mtls_cert,
        },
    ) {
        Ok(witness) => witness,
        Err(e) => return e.into_oauth_response().into_response(),
    };

    // RFC 8705 Section 3: Bind access token to cert thumbprint only when opted in.
    let mtls_thumbprint = extract_mtls_thumbprint(&jwt_authenticated, &client_cert);

    // Exchange the FIDO2 assertion for an access token
    let exchange_params = crate::services::oidc::fido2_grant::Fido2AssertionParams {
        assertion: assertion.expose_secret(),
        client: &crate::services::oidc::token::AuthenticatedClient {
            client: jwt_authenticated.client,
            is_public: false,
        },
        dpop_proof,
        scope: params.scope.as_deref(),
        authorization_details: params.authorization_details.as_deref(),
        client_info,
        mtls_cert_thumbprint: mtls_thumbprint.as_deref(),
    };

    // FIDO2 assertion grant requires `private_key_jwt` client auth (the
    // CLI signs assertions with its FAPI key). The CLI is a FAPI client
    // and therefore always emits `jti`, so `jti_claim` is expected to be
    // `Some` — but the proof construction does not depend on it:
    // `jwt_auth` is the structural witness for "RFC 7523 §3 validation
    // passed", and `jti` is an additive replay-prevention witness.
    let jti_claim =
        match commit_optional_jti(&state, Some(jwt_pending_jti), "fido2_assertion").await {
            Ok(c) => c,
            Err(r) => return r,
        };
    let client_auth = ClientAuthProof::PrivateKeyJwt(
        crate::services::auth::JwtClientAuthProof::new(jwt_auth, jti_claim),
    );

    match crate::services::oidc::fido2_grant::exchange_fido2_assertion(
        &state,
        exchange_params,
        client_auth,
        sender_constraint,
    )
    .await
    {
        Ok(result) => {
            crate::infra::metrics::record_auth_event("fido2_login_success");
            token_success_response(TokenResponse {
                access_token: result.access_token,
                token_type: result.token_type,
                expires_in: result.expires_in,
                id_token: None,
                scope: result.scope,
                email: Some(result.email),
                authorization_details: result.authorization_details,
            })
        }
        Err(e) => {
            crate::infra::metrics::record_auth_event("fido2_login_failure");
            e.into_oauth_response().into_response()
        }
    }
}

/// Validate mTLS client authentication when the client uses `tls_client_auth`
/// or `self_signed_tls_client_auth` (RFC 8705 Section 2).
///
/// Returns `Ok(None)` if the auth method is not mTLS-based (no verification
/// performed); `Ok(Some(verification))` if the cert validated successfully.
/// Returns `Err(Box<Response>)` with a 401-equivalent OAuth error if the
/// cert is absent or invalid.
async fn validate_mtls_client_auth(
    state: &Arc<AppState>,
    client: &crate::services::oidc::token::AuthenticatedClient,
    client_cert: &crate::handlers::extractors::OptionalClientCert,
) -> Result<Option<crate::services::oidc::token::MtlsCertVerification>, Box<Response>> {
    if client.client.token_endpoint_auth_method != crate::db::TokenEndpointAuthMethod::TlsClientAuth
        && client.client.token_endpoint_auth_method
            != crate::db::TokenEndpointAuthMethod::SelfSignedTlsClientAuth
    {
        return Ok(None);
    }
    let Some(ref cert) = client_cert.0 else {
        return Err(Box::new(
            ServiceError::oauth(
                OAuthErrorCode::InvalidClient,
                "mTLS client certificate required",
            )
            .into_oauth_response()
            .into_response(),
        ));
    };
    crate::services::oidc::token::authenticate_client_mtls(state, &client.client, cert)
        .await
        .map(Some)
        .map_err(|e| Box::new(e.into_service_error().into_oauth_response().into_response()))
}

/// Extract mTLS certificate thumbprint for certificate-bound access tokens
/// (RFC 8705 Section 3).
///
/// Returns `Some(thumbprint)` only when the client has opted in via
/// `tls_client_certificate_bound_access_tokens` **and** a cert is present.
fn extract_mtls_thumbprint(
    client: &crate::services::oidc::token::AuthenticatedClient,
    client_cert: &crate::handlers::extractors::OptionalClientCert,
) -> Option<String> {
    if client.client.tls_client_certificate_bound_access_tokens {
        client_cert.0.as_ref().map(|c| c.thumbprint.clone())
    } else {
        None
    }
}

/// Validate PKCE code_verifier format per RFC 7636 Section 4.1.
///
/// The verifier must be 43-128 characters long and contain only unreserved
/// characters: `[A-Za-z0-9\-._~]`.
fn is_valid_pkce_verifier(verifier: &str) -> bool {
    verifier.len() >= 43
        && verifier.len() <= 128
        && verifier.bytes().all(
            |b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'),
        )
}

/// Build a token success response with RFC 6749 §5.1 cache headers.
///
/// RFC 6749 §5.1: "The authorization server MUST include the HTTP
/// `Cache-Control` response header field with a value of `no-store`
/// in any response containing tokens, credentials, or other sensitive
/// information, as well as the `Pragma` response header field with a
/// value of `no-cache`."
fn token_success_response(body: impl Serialize) -> Response {
    (
        StatusCode::OK,
        [
            ("cache-control", "no-cache, no-store, must-revalidate"),
            ("pragma", "no-cache"),
            ("expires", "0"),
        ],
        Json(body),
    )
        .into_response()
}

/// Build a `use_dpop_nonce` error response with the `DPoP-Nonce` header.
///
/// RFC 9449 Section 8: when the authorization server requires a nonce, the
/// error response MUST include the `DPoP-Nonce` header so the client can
/// retry. Shared with the device-flow token path (`handlers::device`).
pub(crate) fn dpop_use_nonce_response(nonce: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(
            axum::http::header::HeaderName::from_static(protocol::HEADER_DPOP_NONCE),
            nonce.to_string(),
        )],
        Json(OAuthErrorResponse {
            error: OAuthErrorCode::UseDpopNonce.as_str().to_string(),
            error_description: Some(
                "Authorization server requires nonce in DPoP proof".to_string(),
            ),
            error_uri: None,
        }),
    )
        .into_response()
}

/// Build an OAuth error response for parameter validation failures.
fn token_error_response(code: OAuthErrorCode, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(OAuthErrorResponse {
            error: code.as_str().to_string(),
            error_description: Some(description.to_string()),
            error_uri: None,
        }),
    )
        .into_response()
}
