// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Session extraction and cookie management for HTTP handlers.

use crate::AppState;
use crate::crypto::hash_token;
use crate::db;
use crate::error::ServiceError;
use crate::services::auth::ValidatedResourceToken;
use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use time::Duration;
use vouch_common::protocol;

// ============================================================================
// Authentication Context for Templates
// ============================================================================

/// Authentication context for templates and handlers.
///
/// Provides a consistent way to pass auth state to templates and handlers.
/// This struct is used by the `header_auth` template macro.
pub(crate) struct AuthContext {
    /// Whether the user is authenticated.
    pub authenticated: bool,
    /// The user's ID if authenticated (for authorization checks).
    pub user_id: Option<String>,
    /// The user's email if authenticated.
    pub user_email: Option<String>,
    /// Whether the user belongs to an organization.
    /// Used to show/hide org-specific features like Applications.
    pub has_org: bool,
    /// Whether the user is an organization admin.
    /// Used to show/hide org admin features like connecting GitHub.
    pub is_org_admin: bool,
}

impl AuthContext {
    /// Create an unauthenticated auth context.
    #[must_use]
    pub(crate) fn unauthenticated() -> Self {
        Self {
            authenticated: false,
            user_id: None,
            user_email: None,
            has_org: false,
            is_org_admin: false,
        }
    }
}

// ============================================================================
// OAuth Resource Token Extraction (FAPI 2.0)
// ============================================================================

/// Extract and validate an OAuth access token from the request.
///
/// Supports three token sources (in order of precedence):
/// 1. `Authorization: DPoP <token>` — DPoP-bound token (FAPI 2.0)
/// 2. `Authorization: Bearer <token>` — standard Bearer token
/// 3. `__Host-vouch_session` cookie — browser sessions
///
/// Validates the token as ES256 `at+jwt` (RFC 9068), enforces audience
/// coverage for resource-narrowed tokens (RFC 8707 / RFC 8725 §3.9 — a
/// token whose `aud` differs from its `client_id` is accepted only when
/// the audience covers this deployment and request path; see
/// [`crate::services::oidc::resource::audience_covers_resource`]), verifies
/// session existence in DB, and validates DPoP proof if the token is
/// sender-constrained.
///
/// `method` and `uri` are the actual HTTP method and path of the request,
/// used for DPoP proof validation and audience coverage. Pass empty strings
/// for cookie-only paths where DPoP validation is skipped (an empty `uri`
/// means only deployment-root audiences pass the coverage check).
#[expect(
    clippy::too_many_lines,
    reason = "linear FAPI 2.0 resource-token validation: decode, audience, session, DPoP, mTLS"
)]
async fn extract_resource_token(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    jar: &CookieJar,
    method: &str,
    uri: &str,
    client_cert: Option<&crate::services::oidc::mtls::ClientCertificate>,
) -> Result<ValidatedResourceToken, ServiceError> {
    // Track DPoP source claim (custom claim for MCP attribution)
    let mut dpop_source: Option<String> = None;

    // 1. Extract token from Authorization header or cookie
    let (token, auth_scheme) = extract_token_from_request(headers, jar)?;

    // 2. Decode as ES256 at+jwt using the OIDC signing key
    let config = state.config();
    let decoded = crate::services::auth::decode_token(&token, &state.oidc_key, &config.base_url)
        .ok_or_else(|| {
            ServiceError::api(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Invalid or expired access token",
            )
        })?;

    let crate::services::auth::DecodedToken::AccessToken(access_claims) = decoded;

    // 2b. Audience coverage for resource-narrowed tokens.
    enforce_audience_coverage(&access_claims, &config.base_url, uri)?;

    // 3. Verify session exists in DB via token_hash
    let token_hash = hash_token(&token);
    let session = state
        .session_cache
        .get_session_by_token_hash(&state.store, &token_hash)
        .await?
        .ok_or_else(|| {
            ServiceError::api(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Session not found or revoked",
            )
        })?;

    // 4. DPoP validation for sender-constrained tokens
    if let Some(ref cnf) = access_claims.cnf
        && cnf.jkt.is_some()
    {
        // Token has cnf.jkt → it's DPoP sender-constrained
        match auth_scheme {
            AuthScheme::DPoP => {
                // Validate DPoP proof header against cnf.jkt
                let dpop_header = headers
                    .get(protocol::HEADER_DPOP)
                    .and_then(|v| v.to_str().ok());
                if let Some(proof) = dpop_header {
                    let full_uri = format!("{}{}", config.base_url, uri);
                    match crate::services::oidc::dpop::validate_dpop_at_resource(
                        &token,
                        proof,
                        method,
                        &full_uri,
                        &state.store,
                        config.dpop_max_age_seconds,
                    )
                    .await
                    {
                        Ok(validated) => {
                            // Verify jkt matches
                            let jkt = cnf.jkt.as_deref().unwrap_or("");
                            let is_match: bool =
                                validated.jkt.as_bytes().ct_eq(jkt.as_bytes()).into();
                            if !is_match {
                                return Err(ServiceError::api(
                                    StatusCode::UNAUTHORIZED,
                                    "invalid_token",
                                    "DPoP proof key does not match token binding",
                                ));
                            }
                            dpop_source = validated.source;
                        }
                        Err(e @ crate::services::oidc::dpop::DpopError::Database(_)) => {
                            tracing::error!("DPoP backend failure: {e}");
                            return Err(ServiceError::api(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "server_error",
                                "DPoP validation backend error",
                            ));
                        }
                        Err(crate::services::oidc::dpop::DpopError::UseNonce(nonce)) => {
                            // RFC 9449 §7.2: When the server requires (or
                            // reissues) a nonce, the error response MUST carry
                            // a fresh `DPoP-Nonce` header so the client can
                            // retry the proof. At resource endpoints this fires
                            // when a client replays an already-consumed nonce;
                            // the fresh nonce lets the caller retry once.
                            return Err(ServiceError::api_with_header(
                                StatusCode::UNAUTHORIZED,
                                crate::error::OAuthErrorCode::UseDpopNonce.as_str(),
                                "Authorization server requires nonce in DPoP proof",
                                (protocol::HEADER_DPOP_NONCE, nonce.as_str()),
                            ));
                        }
                        Err(e) => {
                            tracing::debug!("DPoP validation failed: {e}");
                            return Err(ServiceError::api(
                                StatusCode::UNAUTHORIZED,
                                "invalid_token",
                                "Invalid DPoP proof",
                            ));
                        }
                    }
                } else {
                    return Err(ServiceError::api(
                        StatusCode::UNAUTHORIZED,
                        "invalid_token",
                        "Missing DPoP proof header for sender-constrained token",
                    ));
                }
            }
            AuthScheme::Bearer => {
                // RFC 9449: Token has cnf.jkt but sent as Bearer → reject
                tracing::debug!(
                    sub = %access_claims.sub,
                    uri = %uri,
                    "Rejected Bearer auth for sender-constrained token \
                     (client must use DPoP scheme)"
                );
                return Err(ServiceError::api(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "Sender-constrained tokens must use DPoP authorization scheme",
                ));
            }
            AuthScheme::Cookie => {
                // A token with cnf.jkt is sender-constrained and must be
                // presented with a DPoP proof. If it arrives via cookie,
                // either the token was stolen or misused — reject it.
                return Err(ServiceError::api(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "Sender-constrained tokens cannot be used via cookie",
                ));
            }
        }
    }

    // 4b. mTLS certificate binding validation (RFC 8705 Section 3)
    if let Some(ref cnf) = access_claims.cnf
        && cnf.x5t_s256.is_some()
        && cnf.jkt.is_none()
    // DPoP takes precedence
    {
        let expected_thumbprint = cnf.x5t_s256.as_deref().unwrap_or("");
        match client_cert {
            Some(cert) => {
                let is_match: bool = cert
                    .thumbprint
                    .as_str()
                    .as_bytes()
                    .ct_eq(expected_thumbprint.as_bytes())
                    .into();
                if !is_match {
                    return Err(ServiceError::api(
                        StatusCode::UNAUTHORIZED,
                        "invalid_token",
                        "Client certificate does not match token binding",
                    ));
                }
            }
            None => {
                return Err(ServiceError::api(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "mTLS certificate required for certificate-bound token",
                ));
            }
        }
    }

    // 5. Surface the session-time federation snapshot (avoids per-request DB
    //    lookups in handlers that need `hardware_aaguid` or `hd`).
    Ok(ValidatedResourceToken {
        sub: access_claims.sub,
        email: access_claims.email,
        client_id: access_claims.client_id,
        aud: access_claims.aud,
        scope: access_claims.scope,
        authenticator_id: session.authenticator_id,
        hardware_verified: access_claims.hardware_verified,
        auth_time: access_claims.auth_time,
        token_hash,
        dpop_source,
        hardware_aaguid: session.hardware_aaguid,
        org_domain: session.org_domain,
    })
}

/// Reject a resource-narrowed access token whose audience does not cover
/// the requested resource (RFC 8725 §3.9 / RFC 8707).
///
/// Tokens with the default audience (`aud == client_id`, i.e. never
/// resource-narrowed) are deployment-wide and always pass. Narrowed tokens
/// pass only when
/// [`crate::services::oidc::resource::audience_covers_resource`] accepts
/// the audience for this deployment and request path.
fn enforce_audience_coverage(
    access_claims: &crate::services::auth::AccessTokenClaims,
    base_url: &str,
    uri: &str,
) -> Result<(), ServiceError> {
    if access_claims.aud == access_claims.client_id
        || crate::services::oidc::resource::audience_covers_resource(
            &access_claims.aud,
            base_url,
            uri,
        )
    {
        return Ok(());
    }

    tracing::warn!(
        client_id = %access_claims.client_id,
        aud = %access_claims.aud,
        path = %uri,
        "rejected access token: audience does not cover resource"
    );
    Err(ServiceError::api(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "Access token audience does not cover this resource",
    ))
}

// ============================================================================
// Token Extractors
// ============================================================================
//
// `extract_resource_token` is private to this module. The only ways a handler
// can obtain a validated token are the two extractors below, so the strength of
// authentication a route accepts is stated in its signature rather than left to
// a check the handler remembers to write. `HardwareVerifiedToken` is the reason
// the split exists: credential issuance must not run on a session that never
// exercised the security key.

/// An access token that passed validation.
///
/// Says nothing about *how* the user authenticated — an enrollment bootstrap
/// session satisfies this. Handlers that mint credentials want
/// [`HardwareVerifiedToken`] instead.
pub(crate) struct AuthenticatedToken(pub(crate) ValidatedResourceToken);

/// An access token whose session proved possession of the user's security key.
///
/// The only constructor is the extractor below, which rejects the request when
/// the `hardware_verified` claim is false. A handler naming this type cannot
/// run without the proof.
///
/// The gate is on `hardware_verified` rather than `authenticator_id`: the latter
/// only means the user has a key on record, which an enrollment session carries
/// while `hardware_verified` is false.
pub(crate) struct HardwareVerifiedToken(pub(crate) ValidatedResourceToken);

/// Run the shared validation for both extractors.
///
/// The path comes from `OriginalUri` so it is the path the client actually
/// requested: `extract_resource_token` feeds it to RFC 8707 audience coverage
/// and to the DPoP `htu` comparison, both of which must see the request as sent
/// rather than a matched route template.
async fn extract_token_from_parts(
    parts: &mut http::request::Parts,
    state: &Arc<AppState>,
) -> Result<ValidatedResourceToken, ServiceError> {
    let axum::extract::OriginalUri(uri) =
        axum::extract::OriginalUri::from_request_parts(parts, state)
            .await
            .unwrap_or_else(|infallible| match infallible {});
    let client_cert = super::extractors::OptionalClientCert::from_request_parts(parts, state)
        .await
        .unwrap_or_else(|infallible| match infallible {});
    let jar = CookieJar::from_headers(&parts.headers);

    extract_resource_token(
        state,
        &parts.headers,
        &jar,
        parts.method.as_str(),
        uri.path(),
        client_cert.0.as_ref(),
    )
    .await
}

impl axum::extract::FromRequestParts<Arc<AppState>> for AuthenticatedToken {
    type Rejection = ServiceError;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(extract_token_from_parts(parts, state).await?))
    }
}

/// An access token when the request offered one, for endpoints where
/// authentication is optional (RFC 7591 open client registration).
///
/// `None` means no `Authorization` header was sent. A header carrying an
/// invalid token is an **error**, not an absence — otherwise a rejected token
/// would silently downgrade to an anonymous request. `Option<AuthenticatedToken>`
/// cannot express this, which is why this is its own type.
///
/// Only the `Authorization` header is consulted: a browser session cookie must
/// not authenticate a client registration.
pub(crate) struct OptionalAuthenticatedToken(pub(crate) Option<ValidatedResourceToken>);

impl axum::extract::FromRequestParts<Arc<AppState>> for OptionalAuthenticatedToken {
    type Rejection = ServiceError;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        if !parts
            .headers
            .contains_key(axum::http::header::AUTHORIZATION)
        {
            return Ok(Self(None));
        }
        let axum::extract::OriginalUri(uri) =
            axum::extract::OriginalUri::from_request_parts(parts, state)
                .await
                .unwrap_or_else(|infallible| match infallible {});
        let client_cert = super::extractors::OptionalClientCert::from_request_parts(parts, state)
            .await
            .unwrap_or_else(|infallible| match infallible {});
        let token = extract_resource_token(
            state,
            &parts.headers,
            &CookieJar::default(),
            parts.method.as_str(),
            uri.path(),
            client_cert.0.as_ref(),
        )
        .await?;
        Ok(Self(Some(token)))
    }
}

impl axum::extract::FromRequestParts<Arc<AppState>> for HardwareVerifiedToken {
    type Rejection = ServiceError;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_token_from_parts(parts, state).await?;
        if !token.hardware_verified {
            tracing::warn!(
                target: "security",
                path = %parts.uri.path(),
                "Refusing a session that is not hardware-verified"
            );
            return Err(ServiceError::api(
                StatusCode::FORBIDDEN,
                "hardware_required",
                "This credential requires a hardware-verified session - run 'vouch login' to authenticate with your security key",
            ));
        }
        Ok(Self(token))
    }
}

/// Email for a validated token: the `email` claim when present, else the user
/// record.
pub(super) async fn resolve_token_email(
    state: &AppState,
    token: &ValidatedResourceToken,
) -> Result<String, ServiceError> {
    if let Some(ref email) = token.email {
        return Ok(email.clone());
    }
    let user = db::get_user_by_id(&state.store, &token.sub)
        .await?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "user_not_found", "User not found")
        })?;
    Ok(user.email)
}

/// Extract and validate an OAuth access token from the session cookie only.
///
/// Used by browser UI handlers (enrollment, GitHub, applications) where the
/// Authorization header is not available. The cookie contains an OAuth access token
/// set by `browser_login_complete` or `oidc_callback`.
///
/// # Errors
///
/// Returns an error response if no valid session cookie is present.
pub(crate) async fn extract_session_from_cookie(
    state: &AppState,
    jar: &CookieJar,
) -> Result<ValidatedResourceToken, ServiceError> {
    // Use an empty header map — cookie path only.
    // DPoP validation is skipped for the Cookie auth scheme, so method and uri
    // are not used and can be empty strings.
    let empty_headers = axum::http::HeaderMap::new();
    extract_resource_token(state, &empty_headers, jar, "", "", None).await
}

/// Authorization scheme detected from the request.
#[derive(Debug, Clone, Copy)]
enum AuthScheme {
    /// `Authorization: DPoP <token>`
    DPoP,
    /// `Authorization: Bearer <token>`
    Bearer,
    /// Token read from session cookie
    Cookie,
}

/// Extract token and auth scheme from the request.
///
/// Checks Authorization header first (DPoP then Bearer), then cookie.
/// Returns an owned `String` to avoid lifetime issues between headers and jar.
fn extract_token_from_request(
    headers: &axum::http::HeaderMap,
    jar: &CookieJar,
) -> Result<(String, AuthScheme), ServiceError> {
    use axum::http::header::AUTHORIZATION;

    // Check Authorization header
    if let Some(auth_value) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(token) = crate::http::strip_auth_scheme(auth_value, protocol::AUTH_SCHEME_DPOP)
        {
            return Ok((token.to_string(), AuthScheme::DPoP));
        }
        if let Some(token) =
            crate::http::strip_auth_scheme(auth_value, protocol::AUTH_SCHEME_BEARER)
        {
            return Ok((token.to_string(), AuthScheme::Bearer));
        }
    }

    // Fall back to cookie
    if let Some(cookie) = jar.get(vouch_common::SESSION_COOKIE_NAME) {
        return Ok((cookie.value().to_string(), AuthScheme::Cookie));
    }

    Err(ServiceError::api(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "Missing access token",
    ))
}

// ============================================================================
// Shared Auth Extraction Helpers
// ============================================================================

/// Load the user for a validated token subject, rejecting missing or
/// deactivated accounts.
///
/// This is the single enforcement point for the account-active invariant on
/// the session path: every extractor that turns a validated token or cookie
/// into a user must obtain that user through here, so a deactivated account
/// cannot authenticate anywhere — including during the window between
/// `update_user_active_status` and `delete_sessions_for_user`, which commit
/// in separate transactions.
pub(crate) async fn load_active_user(
    state: &AppState,
    user_id: &str,
) -> Result<db::User, ServiceError> {
    let user = db::get_user_by_id(&state.store, user_id)
        .await?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::UNAUTHORIZED, "unauthorized", "User not found")
        })?;

    if !user.active {
        return Err(ServiceError::api(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "User account is deactivated",
        ));
    }

    Ok(user)
}

/// Extract authenticated user and their org_id.
///
/// Returns `(user, org_id)` or an error if not authenticated or no org.
pub(crate) async fn extract_user_with_org(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    jar: &CookieJar,
    method: &str,
    uri: &str,
    client_cert: Option<&crate::services::oidc::mtls::ClientCertificate>,
) -> Result<(db::User, String), ServiceError> {
    let token = extract_resource_token(state, headers, jar, method, uri, client_cert).await?;
    let user = load_active_user(state, &token.sub).await?;

    let org_id = user.org_id.clone().ok_or_else(|| {
        ServiceError::api(
            StatusCode::FORBIDDEN,
            "no_organization",
            "Cloud integrations require organization membership",
        )
    })?;

    Ok((user, org_id))
}

/// Extract and validate an org admin from the access token.
///
/// Returns the user and their org_id if they are an org admin.
/// Reuses `extract_user_with_org` for token validation and the
/// active-user lookup, then adds the admin-role check.
pub(crate) async fn extract_org_admin(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    jar: &CookieJar,
    method: &str,
    uri: &str,
    client_cert: Option<&crate::services::oidc::mtls::ClientCertificate>,
) -> Result<(db::User, String), ServiceError> {
    let (user, org_id) =
        extract_user_with_org(state, headers, jar, method, uri, client_cert).await?;

    if !user.is_org_admin {
        return Err(ServiceError::api(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Organization admin access required",
        ));
    }

    Ok((user, org_id))
}

/// Create a session cookie.
///
/// Returns a Cookie configured with proper security attributes.
/// `SameSite::Lax` (not `Strict`) is required because the OIDC callback
/// flow redirects from an external IdP (e.g. Google) → `/oauth/callback`
/// → `/enroll/keys`. With `Strict`, the browser treats the entire redirect
/// chain as cross-site and refuses to send the cookie on the final hop.
#[must_use]
pub(crate) fn create_session_cookie(token: &str, max_age_seconds: i64) -> Cookie<'static> {
    Cookie::build((vouch_common::SESSION_COOKIE_NAME, token.to_owned()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(max_age_seconds))
        .build()
}

/// Create a cookie that clears the session.
///
/// Returns a Cookie that expires the session cookie.
#[must_use]
pub(crate) fn clear_session_cookie() -> Cookie<'static> {
    Cookie::build((vouch_common::SESSION_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::ZERO)
        .build()
}

/// Helper to extract auth context from cookie jar using OAuth tokens.
pub(crate) async fn get_resource_auth_context(state: &AppState, jar: &CookieJar) -> AuthContext {
    // Try to extract token from cookie
    let token = match jar.get(vouch_common::SESSION_COOKIE_NAME) {
        Some(c) => c.value(),
        None => return AuthContext::unauthenticated(),
    };

    // Decode using ES256 access token path only
    let config = state.config();
    let decoded =
        match crate::services::auth::decode_token(token, &state.oidc_key, &config.base_url) {
            Some(d) => d,
            None => return AuthContext::unauthenticated(),
        };

    // Verify session exists in DB. This helper returns an infallible
    // `AuthContext`, so a store failure can only be reported as
    // unauthenticated — log it so an outage is distinguishable from a
    // revoked session rather than surfacing as a silently logged-out UI.
    let token_hash = hash_token(token);
    match state
        .session_cache
        .get_session_by_token_hash(&state.store, &token_hash)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return AuthContext::unauthenticated(),
        Err(e) => {
            tracing::error!(error = %e, "Session lookup failed; treating UI request as unauthenticated");
            return AuthContext::unauthenticated();
        }
    }

    let user_id = decoded.sub().to_string();
    let user_email = decoded.email().map(String::from);

    // Look up user to check active status, org membership, and admin status.
    // A deactivated or deleted user is an ordinary unauthenticated outcome;
    // only a store failure (`Internal`) is worth an error line.
    let user = match load_active_user(state, &user_id).await {
        Ok(user) => user,
        Err(e) => {
            if matches!(e, ServiceError::Internal(_)) {
                tracing::error!(error = %e, "User lookup failed; treating UI request as unauthenticated");
            }
            return AuthContext::unauthenticated();
        }
    };
    let (has_org, is_org_admin) = (user.org_id.is_some(), user.is_org_admin);

    AuthContext {
        authenticated: true,
        user_id: Some(user_id),
        user_email,
        has_org,
        is_org_admin,
    }
}

/// Alias for `get_resource_auth_context` to retain a consistent name used
/// by templates and browser UI handlers.
///
/// Both names refer to the same OAuth-token-based auth context extraction.
pub(crate) async fn get_auth_context(state: &AppState, jar: &CookieJar) -> AuthContext {
    get_resource_auth_context(state, jar).await
}

#[cfg(test)]
mod tests;
