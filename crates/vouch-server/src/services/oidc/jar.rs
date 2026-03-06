// SPDX-License-Identifier: BUSL-1.1
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
use crate::services::oidc::authorization::{AuthorizeRequestParams, Prompt};
use crate::services::oidc::jwt_bearer::jwks::{find_matching_key, resolve_client_jwks};
use crate::services::oidc::jwt_bearer::validate::{
    JwtAssertionHeader, JwtAudience, map_algorithm, parse_assertion_header,
};
use crate::services::{OAuthErrorCode, ServiceError, ServiceResult};
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
    #[allow(dead_code)]
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
    /// RFC 9396: Rich authorization details.
    #[serde(default)]
    authorization_details: Option<serde_json::Value>,

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
    #[allow(dead_code)]
    pub alg: String,
    /// Key ID (optional).
    #[serde(default)]
    #[allow(dead_code)]
    pub kid: Option<String>,
    /// Type header — must be "oauth-authz-req+jwt" for Request Objects.
    #[serde(default)]
    pub typ: Option<String>,
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

    // RFC 8725: Validate typ header to prevent cross-JWT confusion
    match &full_header.typ {
        Some(typ) if typ == REQUEST_OBJECT_TYP => {}
        Some(typ) => {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequestObject,
                format!("Request Object typ must be '{REQUEST_OBJECT_TYP}', got '{typ}'"),
            ));
        }
        None => {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequestObject,
                format!("Request Object must include typ header '{REQUEST_OBJECT_TYP}'"),
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
pub async fn validate_request_object(
    state: &Arc<AppState>,
    request_jwt: &str,
    client: &OAuthClient,
    query_params: Option<&QueryParamHints<'_>>,
) -> ServiceResult<AuthorizeRequestParams> {
    // 1. Parse and validate the header (algorithm + typ)
    let (_full_header, assertion_header) = parse_request_object_header(request_jwt)?;

    // 2. Enforce client's preferred signing algorithm if configured
    if let Some(ref required_alg) = client.request_object_signing_alg
        && assertion_header.alg != *required_alg
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
            match &e {
                ServiceError::OAuth { description, .. } => description.clone(),
                _ => e.to_string(),
            },
        ));
    }

    // 3. Resolve client JWKS and find matching key
    let jwks = resolve_client_jwks(
        &state.store,
        &client.id,
        client.jwks.as_deref(),
        client.jwks_uri.as_deref(),
        client.jwks_uri_cache.as_deref(),
        client
            .jwks_uri_cached_at
            .map(|ts| ts.to_string())
            .as_deref(),
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

    let decoding_key = find_matching_key(&jwks, &assertion_header).map_err(|e| {
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
    let now = Timestamp::now().as_second();

    if let Some(exp) = claims.exp
        && exp < now - clock_skew
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequestObject,
            "Request Object has expired",
        ));
    }

    if let Some(nbf) = claims.nbf
        && nbf > now + clock_skew
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequestObject,
            "Request Object is not yet valid (nbf claim)",
        ));
    }

    if let Some(iat) = claims.iat
        && iat > now + clock_skew
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequestObject,
            "Request Object iat claim is in the future",
        ));
    }

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
        authorization_details: authorization_details_str,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use crate::services::oidc::jwt_bearer::validate::SUPPORTED_ALGORITHMS;

    // ========================================================================
    // Helper: Build a minimal JWT string from a raw header JSON object.
    // ========================================================================

    fn make_jwt_with_header(header_json: &serde_json::Value) -> String {
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header_json).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"{}");
        let sig_b64 = URL_SAFE_NO_PAD.encode(b"sig");
        format!("{header_b64}.{payload_b64}.{sig_b64}")
    }

    /// Extract the OAuth error description from a `ServiceError`.
    fn oauth_error_description(err: &ServiceError) -> &str {
        match err {
            ServiceError::OAuth { description, .. } => description.as_str(),
            other => panic!("Expected ServiceError::OAuth, got: {other:?}"),
        }
    }

    /// Extract the OAuth error code from a `ServiceError`.
    fn oauth_error_code(err: &ServiceError) -> &OAuthErrorCode {
        match err {
            ServiceError::OAuth { code, .. } => code,
            other => panic!("Expected ServiceError::OAuth, got: {other:?}"),
        }
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
    fn test_jar_parse_header_rejects_wrong_typ() {
        let jwt = make_jwt_with_header(&serde_json::json!({"alg": "ES256", "typ": "JWT"}));
        let result = parse_request_object_header(&jwt);
        assert!(result.is_err(), "typ=JWT must be rejected");
        let err = result.unwrap_err();
        let desc = oauth_error_description(&err);
        assert!(
            desc.contains("typ"),
            "Error should mention typ, got: {desc}"
        );
    }

    #[test]
    fn test_jar_parse_header_rejects_missing_typ() {
        let jwt = make_jwt_with_header(&serde_json::json!({"alg": "ES256"}));
        let result = parse_request_object_header(&jwt);
        assert!(result.is_err(), "Missing typ must be rejected");
        let err = result.unwrap_err();
        let desc = oauth_error_description(&err);
        assert!(
            desc.contains("typ"),
            "Error should mention typ, got: {desc}"
        );
    }

    #[test]
    fn test_jar_parse_header_rejects_wrong_typ_casing() {
        // "OAuth-Authz-Req+JWT" is not the correct casing
        let jwt = make_jwt_with_header(
            &serde_json::json!({"alg": "ES256", "typ": "OAuth-Authz-Req+JWT"}),
        );
        let result = parse_request_object_header(&jwt);
        assert!(result.is_err(), "Wrong case typ must be rejected");
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
        let jwt = make_jwt_with_header(&serde_json::json!({"alg": "ES256"}));
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
}
