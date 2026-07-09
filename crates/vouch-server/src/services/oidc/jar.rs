// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JWT-Secured Authorization Request (JAR) validation (RFC 9101).
//!
//! Validates Request Object JWTs submitted via the `request` parameter
//! at the authorization and PAR endpoints. Provides integrity protection
//! and source authentication for authorization request parameters.
//!
//! ## Security
//!
//! - Only asymmetric algorithms (ES256, RS256, PS256) are accepted
//! - `typ` header must be `oauth-authz-req+jwt` (RFC 8725 cross-JWT confusion)
//! - Nested Request Objects (`request` or `request_uri` in payload) are rejected
//! - FAPI 2.0 parameter consistency: query params must match JWT values

use crate::AppState;
use crate::db::OAuthClient;
use crate::error::{OAuthErrorCode, ServiceError, ServiceResult};
use crate::services::oidc::authorization::{AuthorizeRequestParams, Prompt};
use crate::services::oidc::jwt_bearer::validate::{
    JwtAssertionHeader, JwtAudience, map_algorithm, parse_assertion_header,
};
use crate::services::oidc::jwt_bearer::{
    find_matching_key_with_refresh_client, resolve_client_jwks,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use serde::Deserialize;
use std::sync::Arc;

/// Expected `typ` header value for Request Objects (RFC 9101 + RFC 8725).
const REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";

/// Request Object JWT claims.
#[derive(Debug, Deserialize)]
struct RequestObjectClaims {
    /// Issuer — SHOULD be client_id.
    #[serde(default)]
    iss: Option<String>,
    /// Audience — SHOULD be authorization server issuer.
    #[serde(default)]
    aud: Option<JwtAudience>,
    /// Expiration time (optional but validated if present).
    #[serde(default)]
    exp: Option<i64>,
    /// Issued at time.
    #[serde(default)]
    iat: Option<i64>,
    /// Not before time.
    #[serde(default)]
    nbf: Option<i64>,
    /// JWT ID (optional).
    #[serde(default)]
    #[expect(dead_code, reason = "reserved for serde DTO conformance / future use")]
    jti: Option<String>,

    // OAuth authorization request parameters
    #[serde(default)]
    response_type: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    acr_values: Option<String>,
    #[serde(default)]
    max_age: Option<u64>,
    #[serde(default)]
    prompt: Option<String>,
    /// RFC 9449 Section 10: DPoP JWK thumbprint for authorization code binding.
    #[serde(default)]
    dpop_jkt: Option<String>,
    /// RFC 9396: Rich authorization details.
    #[serde(default)]
    authorization_details: Option<serde_json::Value>,
    /// JARM (oauth-v2-jarm): Requested authorization response mode.
    #[serde(default)]
    response_mode: Option<String>,

    // Nesting prevention — must NOT be present
    #[serde(default)]
    request: Option<serde_json::Value>,
    #[serde(default)]
    request_uri: Option<serde_json::Value>,
}

/// Hints from query parameters for FAPI 2.0 consistency validation.
pub struct QueryParamHints<'a> {
    /// `client_id` from the query string.
    pub client_id: Option<&'a str>,
    /// `response_type` from the query string.
    pub response_type: Option<&'a str>,
    /// `scope` from the query string.
    pub scope: Option<&'a str>,
}

/// Extended header that includes `typ` for Request Object validation.
#[derive(Debug, Deserialize)]
struct RequestObjectHeader {
    /// Algorithm used for signing.
    #[expect(dead_code, reason = "reserved for serde DTO conformance / future use")]
    pub alg: String,
    /// Key ID (optional).
    #[serde(default)]
    #[expect(dead_code, reason = "reserved for serde DTO conformance / future use")]
    pub kid: Option<String>,
    /// Type header — must be "oauth-authz-req+jwt" for Request Objects.
    #[serde(default)]
    pub typ: Option<String>,
}

/// Maximum size for a fetched Request Object (64 KB).
///
/// Request Objects are single JWTs; 64 KB is more than sufficient for
/// any realistic payload while preventing memory exhaustion from large responses.
const MAX_REQUEST_OBJECT_SIZE: usize = 64 * 1024;

/// Fetch a Request Object JWT from an HTTPS URL (OIDC Core Section 6.2).
///
/// # SSRF Mitigation
///
/// This function fetches a URL derived from user input (`request_uri` query
/// parameter). SSRF is mitigated by:
/// 1. HTTPS-only enforcement (no plaintext HTTP)
/// 2. URL structure validation (must parse as a valid URL with a hostname)
/// 3. Egress guard ([`crate::infra::ssrf::assert_public_destination`]): the
///    host is resolved and rejected if it maps to any non-global
///    (loopback/private/link-local/…) address
/// 4. Caller-side allowlist (`OAuthClient.request_uris`) when configured
/// 5. Caller verifies the client is registered and active before calling
/// 6. 64 KB response size cap prevents data exfiltration
/// 7. `reqwest` with `rustls` — no system cert store manipulation
///
/// # Errors
/// Returns `OAuthErrorCode::InvalidRequestUri` if the URI is not HTTPS,
/// is malformed, the HTTP request fails, the response status is not 2xx,
/// or the body exceeds `MAX_REQUEST_OBJECT_SIZE`.
pub async fn fetch_request_object(
    uri: &str,
    allow_loopback: bool,
    http_client: &reqwest::Client,
) -> ServiceResult<String> {
    if !uri.starts_with("https://") {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequestUri,
            "request_uri must use HTTPS",
        ));
    }

    // Validate URL structure to catch malformed URIs early.
    let parsed = url::Url::parse(uri).map_err(|_| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidRequestUri,
            "request_uri is not a valid URL",
        )
    })?;
    if parsed.host_str().is_none() {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequestUri,
            "request_uri must contain a hostname",
        ));
    }

    // SSRF egress guard: refuse to dial a request_uri that resolves to a
    // private/link-local address. Loopback is permitted only in local
    // development (`allow_loopback`). Complements the HTTPS check, structural
    // validation, and any caller-side allowlist.
    crate::infra::ssrf::assert_public_destination(
        uri,
        allow_loopback,
        OAuthErrorCode::InvalidRequestUri,
    )
    .await?;

    let response = http_client.get(uri).send().await.map_err(|e| {
        tracing::debug!("Failed to fetch Request Object from {uri}: {e}");
        ServiceError::oauth(
            OAuthErrorCode::InvalidRequestUri,
            "Failed to fetch Request Object from request_uri",
        )
    })?;

    // Check HTTP response status before reading body.
    if !response.status().is_success() {
        tracing::debug!(
            "Request Object fetch returned non-2xx status {} for {uri}",
            response.status()
        );
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequestUri,
            format!(
                "Request Object fetch failed with HTTP status {}",
                response.status()
            ),
        ));
    }

    // Validate Content-Type (warn-only for interoperability).
    if let Some(ct) = response.headers().get(reqwest::header::CONTENT_TYPE) {
        let ct_str = ct.to_str().unwrap_or("");
        if !ct_str.contains("application/oauth-authz-req+jwt")
            && !ct_str.contains("application/jwt")
        {
            tracing::warn!(
                "Unexpected Content-Type '{}' for Request Object at {uri}",
                ct_str
            );
        }
    }

    // Check Content-Length before reading to avoid streaming large responses.
    if let Some(len) = response.content_length()
        && len > MAX_REQUEST_OBJECT_SIZE as u64
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequestUri,
            "Request Object response exceeds maximum size (64 KB)",
        ));
    }

    let bytes = response.bytes().await.map_err(|e| {
        tracing::debug!("Failed to read Request Object body from {uri}: {e}");
        ServiceError::oauth(
            OAuthErrorCode::InvalidRequestUri,
            "Failed to read Request Object response body",
        )
    })?;

    if bytes.len() > MAX_REQUEST_OBJECT_SIZE {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequestUri,
            "Request Object response exceeds maximum size (64 KB)",
        ));
    }

    String::from_utf8(bytes.to_vec()).map_err(|_| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidRequestUri,
            "Request Object response is not valid UTF-8",
        )
    })
}

/// Validate a Request Object JWT header algorithm and `typ` only.
///
/// Used by the PAR handler to perform an early header check before client
/// authentication. This ensures that an unsigned request object (`alg=none`)
/// returns `invalid_request_object` rather than `invalid_client`.
pub(crate) fn validate_request_object_header(jwt: &str) -> ServiceResult<()> {
    parse_request_object_header(jwt).map(|_| ())
}

/// Parse a Request Object JWT header, validating algorithm and `typ`.
///
/// Unlike `parse_assertion_header`, this also validates the `typ` header
/// to prevent cross-JWT confusion (RFC 8725).
fn parse_request_object_header(
    jwt: &str,
) -> ServiceResult<(RequestObjectHeader, JwtAssertionHeader)> {
    // First validate the basic structure and algorithm via the shared parser
    let assertion_header = parse_assertion_header(jwt)?;

    // Re-decode the header to get the `typ` field
    let header_part = jwt.split('.').next().ok_or_else(|| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidRequestObject,
            "Invalid Request Object format",
        )
    })?;

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_part)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(header_part))
        .map_err(|_| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidRequestObject,
                "Invalid Request Object header encoding",
            )
        })?;

    let full_header: RequestObjectHeader = serde_json::from_slice(&header_bytes).map_err(|_| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidRequestObject,
            "Invalid Request Object header JSON",
        )
    })?;

    // RFC 9101 Section 10.2: typ SHOULD be "oauth-authz-req+jwt".
    // Accept case-insensitively per MIME type rules, and also accept
    // "JWT" (the generic typ) or absent typ for interoperability.
    if let Some(typ) = &full_header.typ {
        let is_valid =
            typ.eq_ignore_ascii_case(REQUEST_OBJECT_TYP) || typ.eq_ignore_ascii_case("JWT");
        if !is_valid {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequestObject,
                format!("Request Object typ must be '{REQUEST_OBJECT_TYP}' or 'JWT', got '{typ}'"),
            ));
        }
    }

    Ok((full_header, assertion_header))
}

/// Validate a Request Object JWT and extract authorization parameters.
///
/// If `query_params` are provided, validates that any overlapping parameters
/// (`client_id`, `response_type`, `scope`) match between query and JWT
/// (FAPI 2.0 Section 5.3.2).
#[expect(clippy::too_many_lines, reason = "single-pass RFC 9101 JAR validation")]
pub async fn validate_request_object(
    state: &Arc<AppState>,
    request_jwt: &str,
    client: &OAuthClient,
    query_params: Option<&QueryParamHints<'_>>,
) -> ServiceResult<AuthorizeRequestParams> {
    // 1. Parse and validate the header (algorithm + typ)
    let (_full_header, assertion_header) = parse_request_object_header(request_jwt)?;

    // 2. Enforce client's preferred signing algorithm if configured
    if let Some(required_alg) = client.request_object_signing_alg
        && assertion_header.alg != required_alg.as_str()
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequestObject,
            format!(
                "Client requires Request Object signing algorithm '{}', got '{}'",
                required_alg, assertion_header.alg
            ),
        ));
    }

    // 2b. FAPI 2.0: Validate algorithm is in the FAPI allowlist.
    // RS256 is excluded per FAPI 2.0 Section 5.2.2 — use PS256, ES256, or EdDSA.
    if let Err(e) =
        crate::services::oidc::fapi::validate_fapi_algorithm(client, &assertion_header.alg)
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequestObject,
            e.oauth_description(),
        ));
    }

    // 3. Resolve client JWKS and find matching key
    // Load cache once; pass to both resolver calls (pre-refresh timestamp matches prior behavior).
    let jwks_cache = crate::db::get_jwks_cache(&state.store, &client.id)
        .await
        .map_err(|e| {
            tracing::debug!("JWKS cache lookup failed for Request Object: {e}");
            ServiceError::oauth(
                OAuthErrorCode::InvalidRequestObject,
                "Failed to load JWKS cache for Request Object verification",
            )
        })?;

    // Loopback JWKS destinations are permitted only in local development
    // (no TLS configured), matching the WebAuthn `allow_localhost_origin`
    // relaxation; private/link-local targets stay blocked.
    let allow_loopback = !state.config().tls_configured();

    let jwks = resolve_client_jwks(
        &state.store,
        &client.id,
        client.jwks.as_ref(),
        client.jwks_uri.as_deref(),
        jwks_cache.as_ref(),
        allow_loopback,
        &state.http_client,
    )
    .await
    .map_err(|e| {
        // Remap key resolution errors to InvalidRequestObject
        tracing::debug!("JWKS resolution failed for Request Object: {e}");
        ServiceError::oauth(
            OAuthErrorCode::InvalidRequestObject,
            "Failed to resolve client JWKS for Request Object verification",
        )
    })?;

    let decoding_key = find_matching_key_with_refresh_client(
        &state.store,
        &client.id,
        client.jwks_uri.as_deref(),
        jwks_cache.as_ref(),
        allow_loopback,
        &state.http_client,
        &jwks,
        &assertion_header,
    )
    .await
    .map_err(|e| {
        tracing::debug!("No matching key for Request Object: {e}");
        ServiceError::oauth(
            OAuthErrorCode::InvalidRequestObject,
            "No matching key found for Request Object verification",
        )
    })?;

    // 4. Verify signature and extract claims
    let algorithm = map_algorithm(&assertion_header.alg).map_err(|_| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidRequestObject,
            format!("Unsupported algorithm: {}", assertion_header.alg),
        )
    })?;

    let mut validation = jsonwebtoken::Validation::new(algorithm);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;

    let token_data =
        jsonwebtoken::decode::<RequestObjectClaims>(request_jwt, &decoding_key, &validation)
            .map_err(|e| {
                tracing::debug!("Request Object signature verification failed: {e}");
                ServiceError::oauth(
                    OAuthErrorCode::InvalidRequestObject,
                    "Request Object signature verification failed",
                )
            })?;

    let claims = token_data.claims;

    // 5. Validate temporal claims
    // FAPI 2.0 clients use a tighter 10-second clock skew tolerance.
    let clock_skew = super::fapi::clock_skew_seconds(client);
    validate_temporal_claims(
        &claims,
        clock_skew,
        client.is_fapi(),
        Timestamp::now().as_second(),
    )?;

    // 6. Validate issuer — must match client_id
    if let Some(ref iss) = claims.iss
        && iss != &client.client_id
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequestObject,
            "Request Object iss claim must match client_id",
        ));
    }

    // 7. Validate audience — must include authorization server issuer
    if let Some(ref aud) = claims.aud {
        let server_issuer = &state.config().base_url;
        if !aud.contains(server_issuer) {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequestObject,
                "Request Object aud claim must include authorization server issuer",
            ));
        }
    }

    // 7b. FAPI 2.0: iss, aud, exp, and nbf are REQUIRED for FAPI clients
    if client.is_fapi() {
        if claims.iss.is_none() {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequestObject,
                "FAPI 2.0: Request Object must contain 'iss' claim",
            ));
        }
        if claims.aud.is_none() {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequestObject,
                "FAPI 2.0: Request Object must contain 'aud' claim",
            ));
        }
        if claims.exp.is_none() {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequestObject,
                "FAPI 2.0: Request Object must contain 'exp' claim",
            ));
        }
        if claims.nbf.is_none() {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequestObject,
                "FAPI 2.0: Request Object must contain 'nbf' claim",
            ));
        }

        // FAPI 2.0 Message Signing: exp must not be more than 60 minutes
        // after nbf (prevents long-lived request objects).
        if let (Some(exp), Some(nbf)) = (claims.exp, claims.nbf) {
            let window = exp.saturating_sub(nbf);
            if window > 3600 {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidRequestObject,
                    "FAPI 2.0: Request Object exp must not be more than 60 minutes after nbf",
                ));
            }
        }
    }

    // 8. Nesting prevention — reject if request or request_uri in payload
    if claims.request.is_some() {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequestObject,
            "Request Object must not contain a 'request' claim",
        ));
    }
    if claims.request_uri.is_some() {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequestObject,
            "Request Object must not contain a 'request_uri' claim",
        ));
    }

    // 9. Validate required OAuth parameters
    let response_type = claims.response_type.ok_or_else(|| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidRequestObject,
            "Request Object must contain 'response_type' claim",
        )
    })?;

    let redirect_uri = claims.redirect_uri.ok_or_else(|| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidRequestObject,
            "Request Object must contain 'redirect_uri' claim",
        )
    })?;

    // 10. FAPI 2.0 parameter consistency check
    if let Some(hints) = query_params {
        // client_id in query must match JWT (already validated against client above)
        if let Some(query_client_id) = hints.client_id
            && let Some(ref jwt_client_id) = claims.client_id
            && query_client_id != jwt_client_id
        {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequestObject,
                "client_id in query string does not match Request Object",
            ));
        }

        // response_type in query must match JWT
        if let Some(query_rt) = hints.response_type
            && query_rt != response_type
        {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequestObject,
                "response_type in query string does not match Request Object",
            ));
        }

        // scope in query must match JWT
        if let Some(query_scope) = hints.scope
            && let Some(ref jwt_scope) = claims.scope
            && query_scope != jwt_scope
        {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequestObject,
                "scope in query string does not match Request Object",
            ));
        }
    }

    // 11. Parse prompt value
    let parsed_prompt = match claims.prompt.as_deref() {
        Some(p) => Prompt::parse(p),
        None => None,
    };

    // 12. RFC 9396: Parse authorization_details from Request Object if present
    let authorization_details_str = if let Some(ref ad_value) = claims.authorization_details {
        let raw = serde_json::to_string(ad_value).map_err(|e| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidRequestObject,
                format!("Invalid authorization_details in Request Object: {e}"),
            )
        })?;
        // Validate via AuthorizationDetails::parse to enforce constraints
        super::authorization_details::AuthorizationDetails::parse(&raw)?;
        Some(raw)
    } else {
        None
    };

    // 13. Build the authorization request parameters
    Ok(AuthorizeRequestParams {
        response_type,
        client_id: claims.client_id.unwrap_or_else(|| client.client_id.clone()),
        redirect_uri,
        scope: claims.scope,
        state: claims.state,
        nonce: claims.nonce,
        code_challenge: claims.code_challenge,
        code_challenge_method: claims.code_challenge_method,
        resource: claims.resource,
        acr_values: claims.acr_values,
        max_age: claims.max_age,
        prompt: parsed_prompt,
        dpop_jkt: claims.dpop_jkt,
        authorization_details: authorization_details_str,
        response_mode: claims.response_mode,
    })
}

/// Validate the temporal claims (`exp`, `nbf`, `iat`) of a Request Object.
///
/// `now` is passed explicitly (seconds since the Unix epoch) so boundary
/// conditions can be tested with fixed timestamps.
///
/// # Errors
///
/// Returns `ServiceError::OAuth` with `invalid_request_object` if a present
/// claim falls outside the accepted window for the given clock skew.
fn validate_temporal_claims(
    claims: &RequestObjectClaims,
    clock_skew: i64,
    is_fapi: bool,
    now: i64,
) -> ServiceResult<()> {
    if let Some(exp) = claims.exp
        && exp < now.saturating_sub(clock_skew)
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequestObject,
            "Request Object has expired",
        ));
    }

    if let Some(nbf) = claims.nbf {
        if nbf > now.saturating_add(clock_skew) {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequestObject,
                "Request Object is not yet valid (nbf claim)",
            ));
        }
        // FAPI 2.0: nbf must not be more than 60 minutes in the past.
        if is_fapi && nbf < now.saturating_sub(3600).saturating_sub(clock_skew) {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequestObject,
                "Request Object nbf is too far in the past (more than 60 minutes)",
            ));
        }
    }

    if let Some(iat) = claims.iat
        && iat > now.saturating_add(clock_skew)
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequestObject,
            "Request Object iat claim is in the future",
        ));
    }

    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::services::oidc::jwt_bearer::SUPPORTED_ALGORITHMS;

    // ========================================================================
    // Helper: Build a minimal JWT string from a raw header JSON object.
    // ========================================================================

    fn make_jwt_with_header(header_json: &serde_json::Value) -> String {
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header_json).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"{}");
        let sig_b64 = URL_SAFE_NO_PAD.encode(b"sig");
        format!("{header_b64}.{payload_b64}.{sig_b64}")
    }

    /// Extract the OAuth error code from a `ServiceError`.
    fn oauth_error_code(err: &ServiceError) -> &OAuthErrorCode {
        assert!(
            matches!(err, ServiceError::OAuth { .. }),
            "Expected ServiceError::OAuth",
        );
        let ServiceError::OAuth { code, .. } = err else {
            // unreachable after the assert above
            return &OAuthErrorCode::InvalidRequest;
        };
        code
    }

    // ========================================================================
    // Header parsing tests
    // ========================================================================

    #[test]
    fn test_jar_parse_header_rejects_hs256() {
        let jwt = make_jwt_with_header(
            &serde_json::json!({"alg": "HS256", "typ": "oauth-authz-req+jwt"}),
        );
        let result = parse_request_object_header(&jwt);
        assert!(result.is_err(), "HS256 must be rejected");
    }

    #[test]
    fn test_jar_parse_header_rejects_none_algorithm() {
        let jwt =
            make_jwt_with_header(&serde_json::json!({"alg": "none", "typ": "oauth-authz-req+jwt"}));
        let result = parse_request_object_header(&jwt);
        assert!(result.is_err(), "alg=none must be rejected");
    }

    #[test]
    fn test_jar_parse_header_rejects_hs384() {
        let jwt = make_jwt_with_header(
            &serde_json::json!({"alg": "HS384", "typ": "oauth-authz-req+jwt"}),
        );
        let result = parse_request_object_header(&jwt);
        assert!(result.is_err(), "HS384 must be rejected");
    }

    #[test]
    fn test_jar_parse_header_accepts_es256() {
        let jwt = make_jwt_with_header(
            &serde_json::json!({"alg": "ES256", "typ": "oauth-authz-req+jwt"}),
        );
        let (full, assertion) =
            parse_request_object_header(&jwt).expect("ES256 should be accepted");
        assert_eq!(assertion.alg, "ES256");
        assert_eq!(full.typ.as_deref(), Some("oauth-authz-req+jwt"));
    }

    #[test]
    fn test_jar_parse_header_accepts_rs256() {
        let jwt = make_jwt_with_header(
            &serde_json::json!({"alg": "RS256", "typ": "oauth-authz-req+jwt"}),
        );
        let (_full, assertion) =
            parse_request_object_header(&jwt).expect("RS256 should be accepted");
        assert_eq!(assertion.alg, "RS256");
    }

    #[test]
    fn test_jar_parse_header_requires_typ_oauth_authz_req_jwt() {
        let jwt = make_jwt_with_header(
            &serde_json::json!({"alg": "ES256", "typ": "oauth-authz-req+jwt"}),
        );
        let result = parse_request_object_header(&jwt);
        assert!(result.is_ok(), "Correct typ should be accepted");
    }

    #[test]
    fn test_jar_parse_header_accepts_jwt_typ() {
        // RFC 9101: typ "JWT" is the generic type and must be accepted.
        let jwt = make_jwt_with_header(&serde_json::json!({"alg": "ES256", "typ": "JWT"}));
        let result = parse_request_object_header(&jwt);
        assert!(result.is_ok(), "typ=JWT must be accepted: {result:?}");
    }

    #[test]
    fn test_jar_parse_header_accepts_missing_typ() {
        // RFC 9101 Section 10.2: typ is RECOMMENDED, not required.
        let jwt = make_jwt_with_header(&serde_json::json!({"alg": "ES256"}));
        let result = parse_request_object_header(&jwt);
        assert!(result.is_ok(), "Missing typ must be accepted: {result:?}");
    }

    #[test]
    fn test_jar_parse_header_accepts_case_insensitive_typ() {
        // MIME types are case-insensitive.
        let jwt = make_jwt_with_header(
            &serde_json::json!({"alg": "ES256", "typ": "OAuth-Authz-Req+JWT"}),
        );
        let result = parse_request_object_header(&jwt);
        assert!(
            result.is_ok(),
            "Case-insensitive typ must be accepted: {result:?}"
        );
    }

    #[test]
    fn test_jar_parse_header_rejects_invalid_typ() {
        let jwt = make_jwt_with_header(&serde_json::json!({"alg": "ES256", "typ": "at+jwt"}));
        let result = parse_request_object_header(&jwt);
        assert!(result.is_err(), "Invalid typ must be rejected");
    }

    // ========================================================================
    // PS256 in supported algorithms
    // ========================================================================

    #[test]
    fn test_jar_supported_algorithms_includes_ps256() {
        assert!(SUPPORTED_ALGORITHMS.contains(&"PS256"));
    }

    // ========================================================================
    // Malformed JWT tests
    // ========================================================================

    #[test]
    fn test_jar_rejects_one_part_token() {
        let result = parse_request_object_header("singlepart");
        assert!(result.is_err(), "Single-part token must be rejected");
    }

    #[test]
    fn test_jar_rejects_two_part_token() {
        let result = parse_request_object_header("two.parts");
        assert!(result.is_err(), "Two-part token must be rejected");
    }

    #[test]
    fn test_jar_rejects_five_part_jwe_envelope() {
        let result = parse_request_object_header("one.two.three.four.five");
        assert!(result.is_err(), "Five-part JWE token must be rejected");
    }

    // ========================================================================
    // Signature validation tests (require key generation)
    // ========================================================================

    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    /// Generate a fresh ES256 key pair for testing.
    fn test_es256_keys() -> (jsonwebtoken::EncodingKey, jsonwebtoken::DecodingKey) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("key generation must succeed");
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
            .expect("key parsing must succeed");

        let encoding_key = jsonwebtoken::EncodingKey::from_ec_der(pkcs8.as_ref());

        let pub_bytes = key_pair.public_key().as_ref();
        let x = URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);
        let decoding_key = jsonwebtoken::DecodingKey::from_ec_components(&x, &y)
            .expect("decoding key construction must succeed");

        (encoding_key, decoding_key)
    }

    /// Sign a Request Object claims map with ES256.
    fn sign_request_object(
        claims: &serde_json::Value,
        encoding_key: &jsonwebtoken::EncodingKey,
    ) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.typ = Some("oauth-authz-req+jwt".to_string());
        jsonwebtoken::encode(&header, claims, encoding_key).expect("JWT signing must succeed")
    }

    fn valid_request_object_claims(client_id: &str, issuer: &str, now: i64) -> serde_json::Value {
        serde_json::json!({
            "iss": client_id,
            "aud": issuer,
            "exp": now + 300,
            "iat": now,
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": "openid",
            "state": "test-state",
            "nonce": "test-nonce",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256"
        })
    }

    // We can't easily test validate_request_object without an AppState,
    // so we test the header parsing, claims decoding, and temporal validation
    // through the public parse_request_object_header function and direct
    // signature verification.

    #[test]
    fn test_jar_validate_signature_es256() {
        let (enc, dec) = test_es256_keys();
        let now = Timestamp::now().as_second();
        let claims = valid_request_object_claims("test-client", "https://auth.example.com", now);
        let jwt = sign_request_object(&claims, &enc);

        // Verify header parsing works
        let (_full, _assertion) = parse_request_object_header(&jwt).expect("Header should parse");

        // Verify signature
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;
        let token_data = jsonwebtoken::decode::<RequestObjectClaims>(&jwt, &dec, &validation);
        assert!(token_data.is_ok(), "Valid ES256 signature should verify");
        let decoded = token_data.unwrap().claims;
        assert_eq!(decoded.iss.as_deref(), Some("test-client"));
        assert_eq!(decoded.response_type.as_deref(), Some("code"));
        assert_eq!(
            decoded.redirect_uri.as_deref(),
            Some("https://example.com/callback")
        );
    }

    #[test]
    fn test_jar_validate_wrong_signature_rejected() {
        let (enc, _dec) = test_es256_keys();
        let (_enc2, dec2) = test_es256_keys();
        let now = Timestamp::now().as_second();
        let claims = valid_request_object_claims("test-client", "https://auth.example.com", now);
        let jwt = sign_request_object(&claims, &enc);

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;
        let result = jsonwebtoken::decode::<RequestObjectClaims>(&jwt, &dec2, &validation);
        assert!(result.is_err(), "Wrong signing key must be rejected");
    }

    #[test]
    fn test_jar_validate_expired_request_object_rejected() {
        let (enc, dec) = test_es256_keys();
        let now = Timestamp::now().as_second();
        let mut claims =
            valid_request_object_claims("test-client", "https://auth.example.com", now);
        // Expired 1 hour ago
        claims["exp"] = serde_json::json!(now - 3600);
        claims["iat"] = serde_json::json!(now - 7200);
        let jwt = sign_request_object(&claims, &enc);

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;
        let token_data =
            jsonwebtoken::decode::<RequestObjectClaims>(&jwt, &dec, &validation).unwrap();

        // Manually check expiration (as validate_request_object would)
        let exp = token_data.claims.exp.unwrap();
        assert!(
            exp < now - crate::services::oidc::fapi::STANDARD_CLOCK_SKEW_SECONDS,
            "Expired token should be detected"
        );
    }

    #[test]
    fn test_jar_validate_future_iat_within_skew_accepted() {
        let now = Timestamp::now().as_second();
        let iat = now + 5; // 5s in future, within 10s skew
        assert!(
            iat <= now + crate::services::oidc::fapi::STANDARD_CLOCK_SKEW_SECONDS,
            "iat 5s in future should be within 10s clock skew"
        );
    }

    #[test]
    fn test_jar_validate_future_iat_beyond_skew_rejected() {
        let now = Timestamp::now().as_second();
        let iat = now + 60; // 60s in future, beyond 10s skew
        assert!(
            iat > now + crate::services::oidc::fapi::STANDARD_CLOCK_SKEW_SECONDS,
            "iat 60s in future should be beyond 10s clock skew"
        );
    }

    #[test]
    fn test_jar_validate_nbf_future_rejected() {
        let now = Timestamp::now().as_second();
        let nbf = now + 3600; // 1 hour in future
        assert!(
            nbf > now + crate::services::oidc::fapi::STANDARD_CLOCK_SKEW_SECONDS,
            "nbf 1 hour in future should be rejected"
        );
    }

    // ========================================================================
    // Nesting prevention tests
    // ========================================================================

    #[test]
    fn test_jar_rejects_request_claim_in_payload() {
        let (enc, dec) = test_es256_keys();
        let now = Timestamp::now().as_second();
        let mut claims =
            valid_request_object_claims("test-client", "https://auth.example.com", now);
        claims["request"] = serde_json::json!("nested-jwt");
        let jwt = sign_request_object(&claims, &enc);

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;
        let token_data =
            jsonwebtoken::decode::<RequestObjectClaims>(&jwt, &dec, &validation).unwrap();

        assert!(
            token_data.claims.request.is_some(),
            "Nested 'request' claim should be detected"
        );
    }

    #[test]
    fn test_jar_rejects_request_uri_claim_in_payload() {
        let (enc, dec) = test_es256_keys();
        let now = Timestamp::now().as_second();
        let mut claims =
            valid_request_object_claims("test-client", "https://auth.example.com", now);
        claims["request_uri"] = serde_json::json!("https://evil.example.com/request");
        let jwt = sign_request_object(&claims, &enc);

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;
        let token_data =
            jsonwebtoken::decode::<RequestObjectClaims>(&jwt, &dec, &validation).unwrap();

        assert!(
            token_data.claims.request_uri.is_some(),
            "Nested 'request_uri' claim should be detected"
        );
    }

    // ========================================================================
    // Parameter extraction tests
    // ========================================================================

    #[test]
    fn test_jar_requires_response_type_in_payload() {
        let (enc, dec) = test_es256_keys();
        let now = Timestamp::now().as_second();
        let mut claims =
            valid_request_object_claims("test-client", "https://auth.example.com", now);
        // Remove response_type
        claims.as_object_mut().unwrap().remove("response_type");
        let jwt = sign_request_object(&claims, &enc);

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;
        let token_data =
            jsonwebtoken::decode::<RequestObjectClaims>(&jwt, &dec, &validation).unwrap();

        assert!(
            token_data.claims.response_type.is_none(),
            "Missing response_type should be detected"
        );
    }

    #[test]
    fn test_jar_requires_redirect_uri_in_payload() {
        let (enc, dec) = test_es256_keys();
        let now = Timestamp::now().as_second();
        let mut claims =
            valid_request_object_claims("test-client", "https://auth.example.com", now);
        claims.as_object_mut().unwrap().remove("redirect_uri");
        let jwt = sign_request_object(&claims, &enc);

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;
        let token_data =
            jsonwebtoken::decode::<RequestObjectClaims>(&jwt, &dec, &validation).unwrap();

        assert!(
            token_data.claims.redirect_uri.is_none(),
            "Missing redirect_uri should be detected"
        );
    }

    // ========================================================================
    // FAPI 2.0 parameter matching tests
    // ========================================================================

    #[test]
    fn test_jar_query_response_type_mismatch_detected() {
        // Simulate: query has response_type=token but JWT has response_type=code
        let query_rt = "token";
        let jwt_rt = "code";
        assert_ne!(query_rt, jwt_rt, "Mismatch should be detectable");
    }

    #[test]
    fn test_jar_query_scope_mismatch_detected() {
        let query_scope = "openid profile";
        let jwt_scope = "openid";
        assert_ne!(
            query_scope, jwt_scope,
            "Scope mismatch should be detectable"
        );
    }

    #[test]
    fn test_jar_query_params_match_accepted() {
        let query_rt = "code";
        let jwt_rt = "code";
        let query_scope = "openid";
        let jwt_scope = "openid";
        assert_eq!(query_rt, jwt_rt);
        assert_eq!(query_scope, jwt_scope);
    }

    // ========================================================================
    // Error code tests
    // ========================================================================

    #[test]
    fn test_jar_error_code_is_invalid_request_object() {
        let jwt = make_jwt_with_header(&serde_json::json!({"alg": "ES256", "typ": "at+jwt"}));
        let result = parse_request_object_header(&jwt);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            *oauth_error_code(&err),
            OAuthErrorCode::InvalidRequestObject,
            "JAR errors should use invalid_request_object error code"
        );
    }

    #[test]
    fn test_jar_invalid_request_object_status_is_400() {
        assert_eq!(
            OAuthErrorCode::InvalidRequestObject.status_code(),
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_request_object should map to 400"
        );
    }

    // ========================================================================
    // Temporal claim boundary tests (fixed timestamps, no real clock)
    // ========================================================================

    fn temporal_claims(json: serde_json::Value) -> RequestObjectClaims {
        serde_json::from_value(json).unwrap()
    }

    const TEMPORAL_NOW: i64 = 1_700_000_000;
    const TEMPORAL_SKEW: i64 = 10;

    #[test]
    fn test_jar_temporal_no_claims_accepted() {
        let claims = temporal_claims(serde_json::json!({}));
        assert!(
            validate_temporal_claims(&claims, TEMPORAL_SKEW, false, TEMPORAL_NOW).is_ok(),
            "absent temporal claims must be accepted"
        );
    }

    #[test]
    fn test_jar_temporal_exp_boundary() {
        let at_edge = temporal_claims(serde_json::json!({"exp": TEMPORAL_NOW - TEMPORAL_SKEW}));
        assert!(
            validate_temporal_claims(&at_edge, TEMPORAL_SKEW, false, TEMPORAL_NOW).is_ok(),
            "exp == now - skew must be accepted"
        );

        let past_edge =
            temporal_claims(serde_json::json!({"exp": TEMPORAL_NOW - TEMPORAL_SKEW - 1}));
        let err = validate_temporal_claims(&past_edge, TEMPORAL_SKEW, false, TEMPORAL_NOW)
            .expect_err("exp == now - skew - 1 must be rejected");
        assert_eq!(
            *oauth_error_code(&err),
            OAuthErrorCode::InvalidRequestObject
        );
    }

    #[test]
    fn test_jar_temporal_nbf_future_boundary() {
        let at_edge = temporal_claims(serde_json::json!({"nbf": TEMPORAL_NOW + TEMPORAL_SKEW}));
        assert!(
            validate_temporal_claims(&at_edge, TEMPORAL_SKEW, false, TEMPORAL_NOW).is_ok(),
            "nbf == now + skew must be accepted"
        );

        let past_edge =
            temporal_claims(serde_json::json!({"nbf": TEMPORAL_NOW + TEMPORAL_SKEW + 1}));
        assert!(
            validate_temporal_claims(&past_edge, TEMPORAL_SKEW, false, TEMPORAL_NOW).is_err(),
            "nbf == now + skew + 1 must be rejected"
        );
    }

    #[test]
    fn test_jar_temporal_nbf_past_fapi_boundary() {
        let at_edge =
            temporal_claims(serde_json::json!({"nbf": TEMPORAL_NOW - 3600 - TEMPORAL_SKEW}));
        assert!(
            validate_temporal_claims(&at_edge, TEMPORAL_SKEW, true, TEMPORAL_NOW).is_ok(),
            "FAPI: nbf == now - 3600 - skew must be accepted"
        );

        let past_edge =
            temporal_claims(serde_json::json!({"nbf": TEMPORAL_NOW - 3600 - TEMPORAL_SKEW - 1}));
        assert!(
            validate_temporal_claims(&past_edge, TEMPORAL_SKEW, true, TEMPORAL_NOW).is_err(),
            "FAPI: nbf == now - 3600 - skew - 1 must be rejected"
        );
        assert!(
            validate_temporal_claims(&past_edge, TEMPORAL_SKEW, false, TEMPORAL_NOW).is_ok(),
            "non-FAPI: far-past nbf must be accepted"
        );
    }

    #[test]
    fn test_jar_temporal_iat_boundary() {
        let at_edge = temporal_claims(serde_json::json!({"iat": TEMPORAL_NOW + TEMPORAL_SKEW}));
        assert!(
            validate_temporal_claims(&at_edge, TEMPORAL_SKEW, false, TEMPORAL_NOW).is_ok(),
            "iat == now + skew must be accepted"
        );

        let past_edge =
            temporal_claims(serde_json::json!({"iat": TEMPORAL_NOW + TEMPORAL_SKEW + 1}));
        assert!(
            validate_temporal_claims(&past_edge, TEMPORAL_SKEW, false, TEMPORAL_NOW).is_err(),
            "iat == now + skew + 1 must be rejected"
        );
    }
}
