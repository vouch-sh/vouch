// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Session extraction and cookie management for HTTP handlers.

use crate::AppState;
use crate::crypto::hash_token;
use crate::db;
use crate::services::error::ServiceError;
use axum::http::StatusCode;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use subtle::ConstantTimeEq;
use time::Duration;

// ============================================================================
// Authentication Context for Templates
// ============================================================================

/// Authentication context for templates and handlers.
///
/// Provides a consistent way to pass auth state to templates and handlers.
/// This struct is used by the `header_auth` template macro.
pub struct AuthContext {
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
    pub fn unauthenticated() -> Self {
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

/// Validated OAuth resource token information.
#[derive(Debug)]
pub struct ValidatedResourceToken {
    /// User ID (`sub` claim from the access token).
    pub sub: String,
    /// User email (from `email` claim if present, or DB lookup).
    pub email: Option<String>,
    /// OAuth client_id from the access token.
    pub client_id: String,
    /// Granted OAuth scope.
    pub scope: Option<crate::services::oidc::scope::ScopeSet>,
    /// Authenticator ID from the server-side session record (not in JWT).
    pub authenticator_id: Option<String>,
    /// Authentication time (`auth_time` claim).
    pub auth_time: Option<i64>,
    /// SHA-256 hash of the access token (for DB lookups/revocation).
    pub token_hash: String,
}

/// Extract and validate an OAuth access token from the request.
///
/// Supports three token sources (in order of precedence):
/// 1. `Authorization: DPoP <token>` — DPoP-bound token (FAPI 2.0)
/// 2. `Authorization: Bearer <token>` — standard Bearer token
/// 3. `__Host-vouch_session` cookie — browser sessions
///
/// Validates the token as ES256 `at+jwt` (RFC 9068), verifies session
/// existence in DB, and validates DPoP proof if the token is sender-constrained.
///
/// `method` and `uri` are the actual HTTP method and path of the request,
/// used for DPoP proof validation. Pass empty strings for cookie-only paths
/// where DPoP validation is skipped.
pub async fn extract_resource_token(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    jar: &CookieJar,
    method: &str,
    uri: &str,
    client_cert: Option<&crate::services::oidc::mtls::ClientCertificate>,
) -> Result<ValidatedResourceToken, ServiceError> {
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
                let dpop_header = headers.get("DPoP").and_then(|v| v.to_str().ok());
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

    // 5. Look up authenticator_id from DB session record
    let authenticator_id = session.authenticator_id;

    Ok(ValidatedResourceToken {
        sub: access_claims.sub,
        email: access_claims.email,
        client_id: access_claims.client_id,
        scope: access_claims.scope,
        authenticator_id,
        auth_time: access_claims.auth_time,
        token_hash,
    })
}

/// Extract resource token and also fetch the user email from DB.
///
/// Convenience function for handlers that need the user email.
pub async fn extract_resource_token_with_email(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    jar: &CookieJar,
    method: &str,
    uri: &str,
    client_cert: Option<&crate::services::oidc::mtls::ClientCertificate>,
) -> Result<(ValidatedResourceToken, String), ServiceError> {
    let token = extract_resource_token(state, headers, jar, method, uri, client_cert).await?;

    // If token already has email, use it; otherwise look up from DB
    let email = if let Some(ref email) = token.email {
        email.clone()
    } else {
        let user = db::get_user_by_id(&state.store, &token.sub)
            .await?
            .ok_or_else(|| {
                ServiceError::api(StatusCode::NOT_FOUND, "user_not_found", "User not found")
            })?;
        user.email
    };

    Ok((token, email))
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
pub async fn extract_session_from_cookie(
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
        if let Some(token) = auth_value.strip_prefix("DPoP ") {
            return Ok((token.to_string(), AuthScheme::DPoP));
        }
        if let Some(token) = auth_value.strip_prefix("Bearer ") {
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

/// Extract authenticated user and their org_id.
///
/// Returns `(user, org_id)` or an error if not authenticated or no org.
pub async fn extract_user_with_org(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    jar: &CookieJar,
    method: &str,
    uri: &str,
    client_cert: Option<&crate::services::oidc::mtls::ClientCertificate>,
) -> Result<(db::User, String), ServiceError> {
    let token = extract_resource_token(state, headers, jar, method, uri, client_cert).await?;

    let user = db::get_user_by_id(&state.store, &token.sub)
        .await?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::UNAUTHORIZED, "unauthorized", "User not found")
        })?;

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
/// Reuses `extract_user_with_org` for token validation and user lookup,
/// then adds active-status and admin-role checks.
pub async fn extract_org_admin(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    jar: &CookieJar,
    method: &str,
    uri: &str,
    client_cert: Option<&crate::services::oidc::mtls::ClientCertificate>,
) -> Result<(db::User, String), ServiceError> {
    let (user, org_id) =
        extract_user_with_org(state, headers, jar, method, uri, client_cert).await?;

    if !user.active {
        return Err(ServiceError::api(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "User account is deactivated",
        ));
    }

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
pub fn create_session_cookie(token: &str, max_age_seconds: i64) -> Cookie<'static> {
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
pub fn clear_session_cookie() -> Cookie<'static> {
    Cookie::build((vouch_common::SESSION_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::ZERO)
        .build()
}

/// Helper to extract auth context from cookie jar using OAuth tokens.
pub async fn get_resource_auth_context(state: &AppState, jar: &CookieJar) -> AuthContext {
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

    // Verify session exists in DB
    let token_hash = hash_token(token);
    let session_exists = matches!(
        state
            .session_cache
            .get_session_by_token_hash(&state.store, &token_hash)
            .await,
        Ok(Some(_))
    );

    if !session_exists {
        return AuthContext::unauthenticated();
    }

    let user_id = decoded.sub().to_string();
    let user_email = decoded.email().map(String::from);

    // Look up user to check active status, org membership, and admin status
    let (has_org, is_org_admin) = match db::get_user_by_id(&state.store, &user_id).await {
        Ok(Some(user)) if user.active => (user.org_id.is_some(), user.is_org_admin),
        _ => return AuthContext::unauthenticated(),
    };

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
pub async fn get_auth_context(state: &AppState, jar: &CookieJar) -> AuthContext {
    get_resource_auth_context(state, jar).await
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use axum::http::StatusCode;

    use crate::test_utils::*;

    /// Generate a self-signed DER certificate with the given CN for test use.
    fn make_test_cert_der(cn: &str) -> Vec<u8> {
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

        CertificateBuilder::new(
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
        .expect("builder")
        .build::<p256::ecdsa::DerSignature>()
        .expect("build")
        .to_der()
        .expect("der")
    }

    /// Normal (non-DPoP) token via cookie should succeed.
    #[tokio::test]
    async fn test_cookie_session_normal_token_succeeds() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "cookie-ok@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

        let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);
        let (status, _body) = http_get(&app, "/api/v1/applications", &[("Cookie", &cookie)]).await;

        assert_eq!(status, StatusCode::OK);
    }

    /// DPoP-bound token (with cnf.jkt) via cookie must be rejected.
    #[tokio::test]
    async fn test_cookie_session_dpop_bound_token_rejected() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "cookie-dpop@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with_dpop(
            &state,
            &user.id,
            &user.email,
            &auth_id,
            "fake-jkt-thumbprint",
        )
        .await;

        let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);
        let (status, body) = http_get(&app, "/api/v1/applications", &[("Cookie", &cookie)]).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
        assert!(
            body.contains("Sender-constrained"),
            "Error should mention sender-constrained tokens, got: {body}"
        );
    }

    /// DPoP-bound token via Bearer header (without DPoP proof) should also
    /// be rejected, but with a different message than the cookie case.
    #[tokio::test]
    async fn test_bearer_dpop_bound_token_rejected() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "bearer-dpop@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with_dpop(
            &state,
            &user.id,
            &user.email,
            &auth_id,
            "fake-jkt-thumbprint",
        )
        .await;

        let auth = format!("Bearer {token}");
        let (status, body) =
            http_get(&app, "/api/v1/applications", &[("Authorization", &auth)]).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
        assert!(
            body.contains("DPoP authorization scheme"),
            "Error should mention DPoP scheme requirement, got: {body}"
        );
    }

    /// mTLS-bound token (with cnf.x5t#S256) presented via Bearer without a
    /// client certificate must be rejected. The server cannot verify the
    /// certificate binding since no cert was presented.
    #[tokio::test]
    async fn test_mtls_bound_token_without_cert_rejected() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "bearer-mtls@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with_mtls(
            &state,
            &user.id,
            &user.email,
            &auth_id,
            "fake-cert-thumbprint-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        )
        .await;

        // Present the mTLS-bound token as a plain Bearer token (no client cert)
        let auth = format!("Bearer {token}");
        let (status, body) =
            http_get(&app, "/api/v1/applications", &[("Authorization", &auth)]).await;

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "mTLS-bound token without cert must be rejected: {body}"
        );
    }

    /// mTLS-bound token presented with the matching client certificate must succeed.
    #[tokio::test]
    async fn test_mtls_bound_token_with_matching_cert_succeeds() {
        let (_app, state) = test_app().await;
        let user = create_test_user(&state.store, "mtls-match@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;

        // Generate a self-signed client certificate for binding
        let cert_der = make_test_cert_der("test-mtls");
        let cert =
            crate::services::oidc::mtls::parse_client_certificate(&cert_der).expect("parse cert");

        // Issue a token bound to this cert's thumbprint
        let token = create_test_session_with_mtls(
            &state,
            &user.id,
            &user.email,
            &auth_id,
            &cert.thumbprint,
        )
        .await;

        // Call extract_resource_token directly with the matching cert
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("header value"),
        );
        let jar = axum_extra::extract::cookie::CookieJar::new();
        let result = crate::handlers::session::extract_resource_token(
            &state,
            &headers,
            &jar,
            "GET",
            "/api/v1/applications",
            Some(&cert),
        )
        .await;

        assert!(
            result.is_ok(),
            "mTLS-bound token with matching cert must succeed, got: {:?}",
            result.err()
        );
        assert_eq!(result.expect("ok").sub, user.id);
    }

    /// mTLS-bound token presented with the wrong client certificate must be rejected.
    #[tokio::test]
    async fn test_mtls_bound_token_with_wrong_cert_rejected() {
        let (_app, state) = test_app().await;
        let user = create_test_user(&state.store, "mtls-wrong@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;

        // Generate two separate self-signed certs — the token is bound to cert_a's
        // thumbprint but we present cert_b.
        let cert_a_der = make_test_cert_der("client-a");
        let cert_b_der = make_test_cert_der("client-b");
        let cert_a = crate::services::oidc::mtls::parse_client_certificate(&cert_a_der)
            .expect("parse cert A");
        let cert_b = crate::services::oidc::mtls::parse_client_certificate(&cert_b_der)
            .expect("parse cert B");

        // Token is bound to cert_a's thumbprint
        let token = create_test_session_with_mtls(
            &state,
            &user.id,
            &user.email,
            &auth_id,
            &cert_a.thumbprint,
        )
        .await;

        // Present cert_b (wrong cert)
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("header value"),
        );
        let jar = axum_extra::extract::cookie::CookieJar::new();
        let result = crate::handlers::session::extract_resource_token(
            &state,
            &headers,
            &jar,
            "GET",
            "/api/v1/applications",
            Some(&cert_b),
        )
        .await;

        let err = result.expect_err("wrong cert should be rejected");
        assert!(
            matches!(
                &err,
                crate::services::error::ServiceError::Api { status, .. }
                if *status == StatusCode::UNAUTHORIZED
            ),
            "Expected 401, got: {err:?}"
        );
    }

    /// A token with both cnf.jkt (DPoP) and cnf.x5t#S256 (mTLS) — DPoP takes precedence.
    ///
    /// The current implementation checks `jkt.is_some()` first, so a DPoP-bound token
    /// sent as Bearer should be rejected for the DPoP reason, not the mTLS reason.
    #[tokio::test]
    async fn test_dpop_takes_precedence_over_mtls() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "dpop-precedence@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;

        // Create a DPoP-bound token (jkt is set; mTLS thumbprint is not set via
        // create_oauth_access_token because dpop_jkt takes precedence)
        let token = create_test_session_with_dpop(
            &state,
            &user.id,
            &user.email,
            &auth_id,
            "fake-dpop-jkt-thumbprint",
        )
        .await;

        // Present as plain Bearer without DPoP proof
        let auth = format!("Bearer {token}");
        let (status, body) =
            http_get(&app, "/api/v1/applications", &[("Authorization", &auth)]).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
        // The error must mention DPoP, not mTLS — DPoP check runs first
        assert!(
            body.contains("DPoP") || body.contains("sender-constrained"),
            "Error must mention DPoP (not mTLS), got: {body}"
        );
    }
}
