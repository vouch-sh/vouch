// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Core JWT assertion validation for RFC 7523.
//!
//! Provides shared validation logic used by both JWT client authentication
//! (Section 2.2) and JWT authorization grants (Section 2.1).

use crate::db::JwsAlgorithm;
use crate::error::{OAuthErrorCode, ServiceError, ServiceResult};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use vouch_common::protocol;

/// Clock skew tolerance in seconds.
///
/// 10 seconds is the FAPI 2.0 recommended tolerance. Modern NTP-synced
/// systems should not drift beyond this.
const CLOCK_SKEW_SECONDS: i64 = 10;

/// JWT assertion claims (RFC 7523 Section 3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtAssertionClaims {
    /// Issuer — identifies the principal that issued the JWT.
    pub iss: String,
    /// Subject — identifies the principal that is the subject of the JWT.
    pub sub: String,
    /// Audience — the authorization server's token endpoint URL.
    pub aud: JwtAudience,
    /// Expiration time.
    pub exp: i64,
    /// Issued at time (optional per RFC but we require it).
    #[serde(default)]
    pub iat: Option<i64>,
    /// Not before time (optional).
    #[serde(default)]
    pub nbf: Option<i64>,
    /// JWT ID — unique identifier for replay prevention.
    #[serde(default)]
    pub jti: Option<String>,
}

/// JWT `aud` claim can be a single string or an array of strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JwtAudience {
    /// Single audience string.
    Single(String),
    /// Array of audience strings.
    Multiple(Vec<String>),
}

impl JwtAudience {
    /// Check if the audience contains the expected value.
    pub fn contains(&self, expected: &str) -> bool {
        match self {
            Self::Single(s) => s == expected,
            Self::Multiple(v) => v.iter().any(|s| s == expected),
        }
    }

    /// Returns true if the audience is a single string (not an array).
    pub fn is_single(&self) -> bool {
        matches!(self, Self::Single(_))
    }
}

/// Decoded JWT header fields we need for validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtAssertionHeader {
    /// Algorithm used for signing.
    pub alg: String,
    /// Key ID (optional, used to select the verification key from JWKS).
    #[serde(default)]
    pub kid: Option<String>,
}

/// Validated JWT assertion result.
#[derive(Debug)]
pub struct ValidatedJwtAssertion {
    /// The verified claims.
    pub claims: JwtAssertionClaims,
    /// Key ID from the header (if present).
    pub kid: Option<String>,
    /// Algorithm from the header.
    pub alg: String,
}

/// Parse a JWT assertion header without signature verification.
///
/// Extracts the algorithm and optional key ID for key resolution.
pub fn parse_assertion_header(assertion: &str) -> ServiceResult<JwtAssertionHeader> {
    let header_part = assertion.split('.').next().ok_or_else(|| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "Invalid JWT assertion format",
        )
    })?;

    // Verify the JWT has exactly 3 parts
    if assertion.split('.').count() != 3 {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "JWT assertion must have 3 parts",
        ));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_part)
        .or_else(|_| {
            // Try with padding
            base64::engine::general_purpose::STANDARD.decode(header_part)
        })
        .map_err(|_| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidClient,
                "Invalid JWT assertion header encoding",
            )
        })?;

    let header: JwtAssertionHeader = serde_json::from_slice(&header_bytes).map_err(|_| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "Invalid JWT assertion header JSON",
        )
    })?;

    // Structural algorithm check: only asymmetric algorithms are ever accepted.
    // HS* and "none" are unconditionally rejected to prevent symmetric key
    // confusion attacks (RFC 7523 Section 3). This does not consider the
    // presenting client — the per-client-profile allowlist (e.g. excluding
    // RS256 for FAPI clients) is applied later via
    // `validate_client_assertion_algorithm`, once the client is resolved.
    if header.alg.parse::<JwsAlgorithm>().is_err() {
        let supported = JwsAlgorithm::CLIENT_ASSERTION_ALLOWED
            .iter()
            .map(JwsAlgorithm::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            format!(
                "Unsupported JWT assertion algorithm: {}. Supported: {supported}",
                header.alg
            ),
        ));
    }

    Ok(header)
}

/// Validate that a client assertion's algorithm is permitted for the presenting
/// client's profile.
///
/// Distinct from the structural check in [`parse_assertion_header`] (which only
/// rejects symmetric/`none` algorithms): this enforces the per-client allowlist,
/// e.g. FAPI 2.0 clients restricted to [`JwsAlgorithm::FAPI_ALLOWED`]. Callers
/// select `allowed` via `client.fapi_profile.client_assertion_algorithms()`
/// (`crate::db::FapiProfile::client_assertion_algorithms`).
///
/// # Errors
/// Returns `ServiceError::OAuth` with `invalid_client` if `alg` is not in `allowed`.
pub fn validate_client_assertion_algorithm(
    alg: &str,
    allowed: &[JwsAlgorithm],
) -> ServiceResult<()> {
    let permitted = alg
        .parse::<JwsAlgorithm>()
        .is_ok_and(|parsed| allowed.contains(&parsed));
    if !permitted {
        let allowed_list = allowed
            .iter()
            .map(JwsAlgorithm::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            format!(
                "Client assertion algorithm '{alg}' is not permitted for this client. \
                 Allowed: {allowed_list}"
            ),
        ));
    }

    Ok(())
}

/// Validate a JWT assertion's signature and claims.
///
/// # Arguments
/// * `assertion` - The raw JWT assertion string
/// * `header` - The pre-parsed JWT header (from `parse_assertion_header`)
/// * `decoding_key` - The key to verify the signature with
/// * `algorithm` - The expected algorithm
/// * `expected_audiences` - Acceptable audience values (token endpoint URL, base URL, etc.)
/// * `max_lifetime_seconds` - Maximum allowed assertion lifetime
///
/// # Returns
/// The validated assertion claims.
pub fn validate_jwt_assertion(
    assertion: &str,
    header: &JwtAssertionHeader,
    decoding_key: &jsonwebtoken::DecodingKey,
    algorithm: jsonwebtoken::Algorithm,
    expected_audiences: &[&str],
    max_lifetime_seconds: i64,
) -> ServiceResult<ValidatedJwtAssertion> {
    // Build validation settings
    let mut validation = jsonwebtoken::Validation::new(algorithm);
    validation.required_spec_claims.clear();
    // We validate exp, aud, and other claims manually for better error messages
    validation.validate_exp = false;
    validation.validate_aud = false;

    // Verify signature and extract claims
    let token_data =
        jsonwebtoken::decode::<JwtAssertionClaims>(assertion, decoding_key, &validation).map_err(
            |e| {
                tracing::debug!("JWT assertion signature verification failed: {e}");
                ServiceError::oauth(
                    OAuthErrorCode::InvalidClient,
                    "JWT assertion signature verification failed",
                )
            },
        )?;

    let claims = token_data.claims;
    let now = Timestamp::now().as_second();

    // Validate expiration (RFC 7523 Section 3: MUST reject expired JWTs)
    if claims.exp < now.saturating_sub(CLOCK_SKEW_SECONDS) {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "JWT assertion has expired",
        ));
    }

    // Validate not-before if present
    if let Some(nbf) = claims.nbf
        && nbf > now.saturating_add(CLOCK_SKEW_SECONDS)
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "JWT assertion is not yet valid (nbf claim)",
        ));
    }

    // Validate iat if present
    if let Some(iat) = claims.iat
        && iat > now.saturating_add(CLOCK_SKEW_SECONDS)
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "JWT assertion iat claim is in the future",
        ));
    }

    // Validate max lifetime: exp - iat (or exp - now if no iat)
    let effective_iat = claims.iat.unwrap_or(now);
    let lifetime = claims.exp.saturating_sub(effective_iat);
    if lifetime > max_lifetime_seconds {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            format!(
                "JWT assertion lifetime ({lifetime}s) exceeds maximum ({max_lifetime_seconds}s)"
            ),
        ));
    }

    // Validate audience (RFC 7523 Section 3: MUST reject if aud doesn't match)
    let audience_matches = expected_audiences
        .iter()
        .any(|expected| claims.aud.contains(expected));
    if !audience_matches {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "JWT assertion audience does not match authorization server",
        ));
    }

    Ok(ValidatedJwtAssertion {
        claims,
        kid: header.kid.clone(),
        alg: header.alg.clone(),
    })
}

/// Decode JWT claims without signature verification.
///
/// Only used to extract iss/sub before we have the verification key.
/// Both client auth and grant flows need this for key/issuer lookup.
pub fn decode_claims_unverified(assertion: &str) -> ServiceResult<JwtAssertionClaims> {
    let parts: Vec<&str> = assertion.split('.').collect();
    let payload = parts.get(1).ok_or_else(|| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "Invalid JWT assertion format",
        )
    })?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(payload))
        .map_err(|_| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidClient,
                "Invalid JWT assertion payload encoding",
            )
        })?;

    serde_json::from_slice(&payload_bytes).map_err(|_| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "Invalid JWT assertion payload JSON",
        )
    })
}

/// Map a JWT algorithm string to a `jsonwebtoken::Algorithm`.
pub fn map_algorithm(alg: &str) -> ServiceResult<jsonwebtoken::Algorithm> {
    match alg {
        protocol::JWS_ALG_ES256 => Ok(jsonwebtoken::Algorithm::ES256),
        "RS256" => Ok(jsonwebtoken::Algorithm::RS256),
        "PS256" => Ok(jsonwebtoken::Algorithm::PS256),
        "EdDSA" => Ok(jsonwebtoken::Algorithm::EdDSA),
        _ => Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            format!("Unsupported algorithm: {alg}"),
        )),
    }
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

    // RFC 8725 §3.9: the audience claim may be a single string.
    #[test]
    fn test_jwt_audience_single() {
        let aud = JwtAudience::Single("https://example.com/token".to_string());
        assert!(aud.contains("https://example.com/token"));
        assert!(!aud.contains("https://other.com/token"));
    }

    // RFC 8725 §3.9: the audience claim may be an array.
    #[test]
    fn test_jwt_audience_multiple() {
        let aud = JwtAudience::Multiple(vec![
            "https://example.com/token".to_string(),
            "https://example.com".to_string(),
        ]);
        assert!(aud.contains("https://example.com/token"));
        assert!(aud.contains("https://example.com"));
        assert!(!aud.contains("https://other.com"));
    }

    // RFC 8725 §3.1: the algorithm is checked against what the client registered.
    //
    // RFC 7518 §3.6: "In order to mitigate downgrade attacks, applications
    // MUST NOT signal acceptance of Unsecured JWSs at a global level."
    // `JwsAlgorithm` has no `none` variant, so the wire string never parses
    // and no advertised algorithm list (discovery's
    // `*_signing_alg_values_supported`, all typed `Vec<JwsAlgorithm>`) can
    // name it.
    #[test]
    fn test_structural_algorithm_gate_matches_client_assertion_allowed() {
        // parse_assertion_header's structural gate accepts exactly the algorithms
        // JwsAlgorithm can parse — the same four CLIENT_ASSERTION_ALLOWED names.
        for alg in JwsAlgorithm::CLIENT_ASSERTION_ALLOWED {
            assert!(
                alg.as_str().parse::<JwsAlgorithm>().is_ok(),
                "{alg} must be structurally accepted"
            );
        }
        assert!("HS256".parse::<JwsAlgorithm>().is_err());
        assert!("none".parse::<JwsAlgorithm>().is_err());
    }

    // RFC 7523 §3: a client assertion is a JWS with three parts.
    #[test]
    fn test_parse_assertion_header_rejects_invalid_format() {
        let result = parse_assertion_header("not.a.valid.jwt");
        assert!(result.is_err());
    }

    // RFC 7523 §3: a client assertion is a JWS with three parts.
    #[test]
    fn test_parse_assertion_header_rejects_two_parts() {
        let result = parse_assertion_header("two.parts");
        assert!(result.is_err());
    }

    // ========================================================================
    // Helper: Build a minimal JWT string from a raw header JSON object.
    //
    // The payload and signature parts are dummy values — only the header
    // matters for `parse_assertion_header` tests.
    // ========================================================================

    fn make_jwt_with_header(header_json: &serde_json::Value) -> String {
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header_json).unwrap());
        // Payload and signature are arbitrary but present so the 3-part check passes.
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"{}");
        let sig_b64 = URL_SAFE_NO_PAD.encode(b"sig");
        format!("{header_b64}.{payload_b64}.{sig_b64}")
    }

    // ========================================================================
    // parse_assertion_header tests
    // ========================================================================

    /// Extract the OAuth error description from a `ServiceError`.
    fn oauth_error_description(err: &ServiceError) -> &str {
        let ServiceError::OAuth { description, .. } = err else {
            return "NOT_AN_OAUTH_ERROR";
        };
        description.as_str()
    }

    // RFC 8725 §3.2: a symmetric algorithm is not accepted for client authentication.
    #[test]
    fn test_parse_assertion_header_rejects_hs256() {
        let jwt = make_jwt_with_header(&serde_json::json!({"alg": "HS256"}));
        let result = parse_assertion_header(&jwt);
        assert!(result.is_err(), "HS256 must be rejected");
        let err = result.unwrap_err();
        let desc = oauth_error_description(&err);
        assert!(
            desc.contains("Unsupported JWT assertion algorithm"),
            "Error should mention unsupported algorithm, got: {desc}"
        );
    }

    // RFC 8725 §3.2 and RFC 7518 §3.6: the none algorithm is not accepted.
    //
    // RFC 7518 §3.6: "Implementations MUST NOT accept Unsecured JWSs by
    // default." A client assertion authenticates the client, so accepting an
    // Unsecured JWS here would let anyone authenticate as any client.
    #[test]
    fn test_parse_assertion_header_rejects_none_algorithm() {
        let jwt = make_jwt_with_header(&serde_json::json!({"alg": "none"}));
        let result = parse_assertion_header(&jwt);
        assert!(result.is_err(), "alg=none must be rejected");
    }

    // RFC 7518 §3.6: an Unsecured JWS "MUST use the empty octet sequence as
    // its JWS Signature value". The well-formed unsecured assertion is
    // rejected on its algorithm, before the empty signature is examined.
    #[test]
    fn test_parse_assertion_header_rejects_well_formed_unsecured_jws() {
        let header_b64 = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&serde_json::json!({"alg": "none"})).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"{}");
        // Empty signature segment: the empty octet sequence.
        let unsecured = format!("{header_b64}.{payload_b64}.");

        let result = parse_assertion_header(&unsecured);
        assert!(
            result.is_err(),
            "an Unsecured JWS with an empty signature must still be rejected"
        );
    }

    // RFC 7523 §3: an asymmetrically signed assertion is accepted.
    #[test]
    fn test_parse_assertion_header_accepts_eddsa() {
        let jwt = make_jwt_with_header(&serde_json::json!({"alg": "EdDSA"}));
        let header = parse_assertion_header(&jwt).expect("EdDSA should be accepted");
        assert_eq!(header.alg, "EdDSA");
    }

    // RFC 7523 §3: an asymmetrically signed assertion is accepted.
    #[test]
    fn test_parse_assertion_header_accepts_es256() {
        let jwt = make_jwt_with_header(&serde_json::json!({"alg": "ES256"}));
        let header = parse_assertion_header(&jwt).expect("ES256 should be accepted");
        assert_eq!(header.alg, "ES256");
        assert!(header.kid.is_none());
    }

    // RFC 7523 §3: an asymmetrically signed assertion is accepted.
    #[test]
    fn test_parse_assertion_header_accepts_rs256() {
        let jwt = make_jwt_with_header(&serde_json::json!({"alg": "RS256"}));
        let header = parse_assertion_header(&jwt).expect("RS256 should be accepted");
        assert_eq!(header.alg, "RS256");
    }

    // RFC 7517 §4: kid selects the key that verifies the assertion.
    #[test]
    fn test_parse_assertion_header_with_kid() {
        let jwt =
            make_jwt_with_header(&serde_json::json!({"alg": "ES256", "kid": "my-key-id-123"}));
        let header = parse_assertion_header(&jwt).expect("Should parse header with kid");
        assert_eq!(header.alg, "ES256");
        assert_eq!(header.kid.as_deref(), Some("my-key-id-123"));
    }

    // ========================================================================
    // Helper: Generate an ES256 key pair and produce a signed JWT.
    //
    // Returns (jwt_string, decoding_key) so tests can call
    // `validate_jwt_assertion` directly.
    // ========================================================================

    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    /// Generate a fresh ES256 key pair and return the `jsonwebtoken`
    /// encoding/decoding keys.
    fn test_es256_keys() -> (jsonwebtoken::EncodingKey, jsonwebtoken::DecodingKey) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("key generation must succeed");
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
            .expect("key parsing must succeed");

        let encoding_key = jsonwebtoken::EncodingKey::from_ec_der(pkcs8.as_ref());

        // Build decoding key from the public point (uncompressed: 0x04 || x || y).
        let pub_bytes = key_pair.public_key().as_ref();
        let x = URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);
        let decoding_key = jsonwebtoken::DecodingKey::from_ec_components(&x, &y)
            .expect("decoding key construction must succeed");

        (encoding_key, decoding_key)
    }

    /// Sign a `JwtAssertionClaims` with ES256, returning the compact JWT string.
    fn sign_test_jwt(
        claims: &JwtAssertionClaims,
        encoding_key: &jsonwebtoken::EncodingKey,
    ) -> String {
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        jsonwebtoken::encode(&header, claims, encoding_key).expect("JWT signing must succeed")
    }

    /// Build default valid claims centered around `now`.
    fn valid_claims(now: i64) -> JwtAssertionClaims {
        JwtAssertionClaims {
            iss: "https://client.example.com".to_string(),
            sub: "https://client.example.com".to_string(),
            aud: JwtAudience::Single("https://auth.example.com/oauth/token".to_string()),
            exp: now + 300,
            iat: Some(now),
            nbf: None,
            jti: Some("unique-jti-123".to_string()),
        }
    }

    const TEST_AUDIENCES: &[&str] = &[
        "https://auth.example.com/oauth/token",
        "https://auth.example.com",
    ];
    const MAX_LIFETIME: i64 = 600;

    // ========================================================================
    // validate_jwt_assertion tests
    // ========================================================================

    // RFC 7523 §3.2: a conformant client assertion authenticates the client.
    #[test]
    fn test_validate_jwt_assertion_valid() {
        let (enc, dec) = test_es256_keys();
        let now = Timestamp::now().as_second();
        let claims = valid_claims(now);
        let jwt = sign_test_jwt(&claims, &enc);

        let header = parse_assertion_header(&jwt).expect("header should parse");
        let result = validate_jwt_assertion(
            &jwt,
            &header,
            &dec,
            jsonwebtoken::Algorithm::ES256,
            TEST_AUDIENCES,
            MAX_LIFETIME,
        );

        let validated = result.expect("valid JWT assertion should pass");
        assert_eq!(validated.claims.iss, "https://client.example.com");
        assert_eq!(validated.claims.sub, "https://client.example.com");
        assert_eq!(validated.alg, "ES256");
    }

    // RFC 7523 §3: an assertion past its exp is rejected.
    #[test]
    fn test_validate_jwt_assertion_rejects_expired() {
        let (enc, dec) = test_es256_keys();
        let now = Timestamp::now().as_second();
        // Expired 1 hour ago — well beyond 30s clock skew tolerance.
        let mut claims = valid_claims(now);
        claims.iat = Some(now - 7200);
        claims.exp = now - 3600;

        let jwt = sign_test_jwt(&claims, &enc);
        let header = parse_assertion_header(&jwt).expect("header should parse");

        let result = validate_jwt_assertion(
            &jwt,
            &header,
            &dec,
            jsonwebtoken::Algorithm::ES256,
            TEST_AUDIENCES,
            MAX_LIFETIME,
        );

        assert!(result.is_err(), "Expired JWT must be rejected");
        let err = result.unwrap_err();
        let desc = oauth_error_description(&err);
        assert!(
            desc.contains("expired"),
            "Error should mention expiry, got: {desc}"
        );
    }

    // RFC 7523 §3: a bounded clock skew allowance is applied.
    #[test]
    fn test_validate_jwt_assertion_accepts_within_clock_skew() {
        let (enc, dec) = test_es256_keys();
        let now = Timestamp::now().as_second();
        // exp is 5 seconds in the past — within the 10s clock skew window.
        let mut claims = valid_claims(now);
        claims.iat = Some(now - 300);
        claims.exp = now - 5;

        let jwt = sign_test_jwt(&claims, &enc);
        let header = parse_assertion_header(&jwt).expect("header should parse");

        let result = validate_jwt_assertion(
            &jwt,
            &header,
            &dec,
            jsonwebtoken::Algorithm::ES256,
            TEST_AUDIENCES,
            MAX_LIFETIME,
        );

        assert!(
            result.is_ok(),
            "JWT expired by 5s should be accepted (10s skew), got: {:?}",
            result.unwrap_err()
        );
    }

    // RFC 7523 §3: an assertion before its nbf is rejected.
    #[test]
    fn test_validate_jwt_assertion_rejects_future_nbf() {
        let (enc, dec) = test_es256_keys();
        let now = Timestamp::now().as_second();
        let mut claims = valid_claims(now);
        // nbf 1 hour in the future — well beyond clock skew.
        claims.nbf = Some(now + 3600);

        let jwt = sign_test_jwt(&claims, &enc);
        let header = parse_assertion_header(&jwt).expect("header should parse");

        let result = validate_jwt_assertion(
            &jwt,
            &header,
            &dec,
            jsonwebtoken::Algorithm::ES256,
            TEST_AUDIENCES,
            MAX_LIFETIME,
        );

        assert!(result.is_err(), "Future nbf must be rejected");
        let err = result.unwrap_err();
        let desc = oauth_error_description(&err);
        assert!(
            desc.contains("not yet valid"),
            "Error should mention nbf, got: {desc}"
        );
    }

    // RFC 7523 §3: a bounded clock skew allowance is applied to nbf.
    #[test]
    fn test_validate_jwt_assertion_accepts_nbf_within_clock_skew() {
        let (enc, dec) = test_es256_keys();
        let now = Timestamp::now().as_second();
        let mut claims = valid_claims(now);
        // nbf 5 seconds in the future — within 10s clock skew.
        claims.nbf = Some(now + 5);

        let jwt = sign_test_jwt(&claims, &enc);
        let header = parse_assertion_header(&jwt).expect("header should parse");

        let result = validate_jwt_assertion(
            &jwt,
            &header,
            &dec,
            jsonwebtoken::Algorithm::ES256,
            TEST_AUDIENCES,
            MAX_LIFETIME,
        );

        assert!(
            result.is_ok(),
            "nbf 5s in future should be accepted (10s skew), got: {:?}",
            result.unwrap_err()
        );
    }

    // RFC 7523 §3: an assertion issued in the future is rejected.
    #[test]
    fn test_validate_jwt_assertion_rejects_future_iat() {
        let (enc, dec) = test_es256_keys();
        let now = Timestamp::now().as_second();
        let mut claims = valid_claims(now);
        // iat 1 hour in the future.
        claims.iat = Some(now + 3600);
        claims.exp = now + 7200;

        let jwt = sign_test_jwt(&claims, &enc);
        let header = parse_assertion_header(&jwt).expect("header should parse");

        let result = validate_jwt_assertion(
            &jwt,
            &header,
            &dec,
            jsonwebtoken::Algorithm::ES256,
            TEST_AUDIENCES,
            MAX_LIFETIME,
        );

        assert!(result.is_err(), "Future iat must be rejected");
        let err = result.unwrap_err();
        let desc = oauth_error_description(&err);
        assert!(
            desc.contains("iat") && desc.contains("future"),
            "Error should mention iat in the future, got: {desc}"
        );
    }

    // RFC 7523 §3: an assertion's lifetime is bounded.
    #[test]
    fn test_validate_jwt_assertion_rejects_excessive_lifetime() {
        let (enc, dec) = test_es256_keys();
        let now = Timestamp::now().as_second();
        let mut claims = valid_claims(now);
        // exp - iat = 600s but max_lifetime = 300s.
        claims.iat = Some(now);
        claims.exp = now + 600;
        let max_lifetime = 300;

        let jwt = sign_test_jwt(&claims, &enc);
        let header = parse_assertion_header(&jwt).expect("header should parse");

        let result = validate_jwt_assertion(
            &jwt,
            &header,
            &dec,
            jsonwebtoken::Algorithm::ES256,
            TEST_AUDIENCES,
            max_lifetime,
        );

        assert!(result.is_err(), "Excessive lifetime must be rejected");
        let err = result.unwrap_err();
        let desc = oauth_error_description(&err);
        assert!(
            desc.contains("lifetime") && desc.contains("exceeds"),
            "Error should mention lifetime exceeding maximum, got: {desc}"
        );
    }

    // RFC 7523 §3: the lifetime boundary is exact.
    #[test]
    fn test_validate_jwt_assertion_accepts_exactly_max_lifetime() {
        let (enc, dec) = test_es256_keys();
        let now = Timestamp::now().as_second();
        let mut claims = valid_claims(now);
        // exp - iat = 300s exactly, max_lifetime = 300s — should pass.
        claims.iat = Some(now);
        claims.exp = now + 300;
        let max_lifetime = 300;

        let jwt = sign_test_jwt(&claims, &enc);
        let header = parse_assertion_header(&jwt).expect("header should parse");

        let result = validate_jwt_assertion(
            &jwt,
            &header,
            &dec,
            jsonwebtoken::Algorithm::ES256,
            TEST_AUDIENCES,
            max_lifetime,
        );

        assert!(
            result.is_ok(),
            "Lifetime exactly at max should be accepted, got: {:?}",
            result.unwrap_err()
        );
    }

    // RFC 8725 §3.9: an assertion addressed elsewhere is rejected.
    #[test]
    fn test_validate_jwt_assertion_rejects_wrong_audience() {
        let (enc, dec) = test_es256_keys();
        let now = Timestamp::now().as_second();
        let mut claims = valid_claims(now);
        claims.aud = JwtAudience::Single("https://wrong.example.com".to_string());

        let jwt = sign_test_jwt(&claims, &enc);
        let header = parse_assertion_header(&jwt).expect("header should parse");

        let result = validate_jwt_assertion(
            &jwt,
            &header,
            &dec,
            jsonwebtoken::Algorithm::ES256,
            TEST_AUDIENCES,
            MAX_LIFETIME,
        );

        assert!(result.is_err(), "Wrong audience must be rejected");
        let err = result.unwrap_err();
        let desc = oauth_error_description(&err);
        assert!(
            desc.contains("audience"),
            "Error should mention audience mismatch, got: {desc}"
        );
    }

    // ========================================================================
    // FAPI 2.0 Section 5.3.2.1-8: aud MUST be the issuer URL only.
    //
    // When allowed_audiences contains only the base URL (issuer), a JWT
    // assertion whose aud is the token endpoint URL must be rejected.
    // ========================================================================

    // FAPI 2.0 §5.3.2.1: authorization servers accept only their issuer identifier in the aud claim
    // of a client authentication assertion.
    #[test]
    fn test_validate_jwt_assertion_fapi_rejects_token_endpoint_audience() {
        let (enc, dec) = test_es256_keys();
        let now = Timestamp::now().as_second();
        let mut claims = valid_claims(now);
        // Client sets aud to the token endpoint URL — invalid for FAPI clients
        // where only the issuer (base) URL is accepted.
        claims.aud = JwtAudience::Single("https://example.com/oauth/token".to_string());

        let jwt = sign_test_jwt(&claims, &enc);
        let header = parse_assertion_header(&jwt).expect("header should parse");

        // FAPI restriction: allowed_audiences contains only the issuer URL,
        // NOT the token endpoint URL.
        let fapi_audiences: &[&str] = &["https://example.com"];

        let result = validate_jwt_assertion(
            &jwt,
            &header,
            &dec,
            jsonwebtoken::Algorithm::ES256,
            fapi_audiences,
            MAX_LIFETIME,
        );

        assert!(
            result.is_err(),
            "Token endpoint URL must be rejected when FAPI audiences allow issuer URL only"
        );
        let err = result.unwrap_err();
        let desc = oauth_error_description(&err);
        assert!(
            desc.contains("audience"),
            "Error should mention audience mismatch, got: {desc}"
        );
    }

    // FAPI 2.0 §5.3.2.1: the issuer identifier is the accepted audience.
    #[test]
    fn test_validate_jwt_assertion_fapi_accepts_issuer_url_audience() {
        let (enc, dec) = test_es256_keys();
        let now = Timestamp::now().as_second();
        let mut claims = valid_claims(now);
        // Client correctly uses the issuer URL as aud for a FAPI client.
        claims.aud = JwtAudience::Single("https://example.com".to_string());

        let jwt = sign_test_jwt(&claims, &enc);
        let header = parse_assertion_header(&jwt).expect("header should parse");

        let fapi_audiences: &[&str] = &["https://example.com"];

        let result = validate_jwt_assertion(
            &jwt,
            &header,
            &dec,
            jsonwebtoken::Algorithm::ES256,
            fapi_audiences,
            MAX_LIFETIME,
        );

        assert!(
            result.is_ok(),
            "Issuer URL audience must be accepted for FAPI client, got: {:?}",
            result.unwrap_err()
        );
    }

    // RFC 8725 §3.9: the audience may be an array containing the expected value.
    #[test]
    fn test_validate_jwt_assertion_accepts_audience_as_array() {
        let (enc, dec) = test_es256_keys();
        let now = Timestamp::now().as_second();
        let mut claims = valid_claims(now);
        // Array with one wrong and one correct audience value.
        claims.aud = JwtAudience::Multiple(vec![
            "https://wrong.example.com".to_string(),
            "https://auth.example.com/oauth/token".to_string(),
        ]);

        let jwt = sign_test_jwt(&claims, &enc);
        let header = parse_assertion_header(&jwt).expect("header should parse");

        let result = validate_jwt_assertion(
            &jwt,
            &header,
            &dec,
            jsonwebtoken::Algorithm::ES256,
            TEST_AUDIENCES,
            MAX_LIFETIME,
        );

        assert!(
            result.is_ok(),
            "Array audience with a matching value should be accepted, got: {:?}",
            result.unwrap_err()
        );
    }

    // RFC 7523 §3.2: an assertion that does not verify does not authenticate.
    #[test]
    fn test_validate_jwt_assertion_rejects_wrong_signature() {
        let (enc, _dec) = test_es256_keys();
        let (_enc2, dec2) = test_es256_keys(); // Different key pair
        let now = Timestamp::now().as_second();
        let claims = valid_claims(now);

        // Sign with key 1, verify with key 2.
        let jwt = sign_test_jwt(&claims, &enc);
        let header = parse_assertion_header(&jwt).expect("header should parse");

        let result = validate_jwt_assertion(
            &jwt,
            &header,
            &dec2,
            jsonwebtoken::Algorithm::ES256,
            TEST_AUDIENCES,
            MAX_LIFETIME,
        );

        assert!(result.is_err(), "Wrong signing key must be rejected");
        let err = result.unwrap_err();
        let desc = oauth_error_description(&err);
        assert!(
            desc.contains("signature"),
            "Error should mention signature verification, got: {desc}"
        );
    }

    // ========================================================================
    // decode_claims_unverified tests
    // ========================================================================

    // RFC 7523 §3: iss and sub identify the client.
    #[test]
    fn test_decode_claims_unverified_extracts_iss_and_sub() {
        let (enc, _dec) = test_es256_keys();
        let now = Timestamp::now().as_second();
        let claims = JwtAssertionClaims {
            iss: "https://my-app.example.com".to_string(),
            sub: "service-account-42".to_string(),
            aud: JwtAudience::Single("https://auth.example.com/oauth/token".to_string()),
            exp: now + 300,
            iat: Some(now),
            nbf: None,
            jti: Some("jti-abc".to_string()),
        };

        let jwt = sign_test_jwt(&claims, &enc);
        let decoded =
            decode_claims_unverified(&jwt).expect("Should decode claims without verification");

        assert_eq!(decoded.iss, "https://my-app.example.com");
        assert_eq!(decoded.sub, "service-account-42");
        assert_eq!(decoded.exp, claims.exp);
        assert_eq!(decoded.iat, Some(now));
        assert_eq!(decoded.jti.as_deref(), Some("jti-abc"));
    }

    // RFC 7523 §3: a malformed assertion yields no claims.
    #[test]
    fn test_decode_claims_unverified_rejects_malformed() {
        let result = decode_claims_unverified("not-a-jwt");
        assert!(result.is_err(), "Malformed input must be rejected");
    }

    // RFC 7523 §3: an empty assertion yields no claims.
    #[test]
    fn test_decode_claims_unverified_rejects_empty_string() {
        let result = decode_claims_unverified("");
        assert!(result.is_err(), "Empty string must be rejected");
    }

    // RFC 7523 §3: JWS parts are base64url encoded.
    #[test]
    fn test_decode_claims_unverified_with_invalid_base64_payload() {
        // Valid-looking structure but second segment is not valid base64.
        let result = decode_claims_unverified("eyJhbGciOiJFUzI1NiJ9.!!!invalid!!!.sig");
        assert!(result.is_err(), "Invalid base64 payload must be rejected");
    }

    // ========================================================================
    // map_algorithm tests
    // ========================================================================

    // RFC 8725 §3.1: the alg header names the verification algorithm.
    #[test]
    fn test_map_algorithm_es256() {
        let alg = map_algorithm("ES256").expect("ES256 should be mapped");
        assert_eq!(alg, jsonwebtoken::Algorithm::ES256);
    }

    // RFC 8725 §3.1: the alg header names the verification algorithm.
    #[test]
    fn test_map_algorithm_rs256() {
        let alg = map_algorithm("RS256").expect("RS256 should be mapped");
        assert_eq!(alg, jsonwebtoken::Algorithm::RS256);
    }

    // RFC 8725 §3.1: the alg header names the verification algorithm.
    #[test]
    fn test_map_algorithm_eddsa() {
        let alg = map_algorithm("EdDSA").expect("EdDSA should be mapped");
        assert_eq!(alg, jsonwebtoken::Algorithm::EdDSA);
    }

    // RFC 8725 §3.2: a symmetric algorithm is not accepted.
    #[test]
    fn test_map_algorithm_rejects_hs256() {
        let result = map_algorithm("HS256");
        assert!(result.is_err(), "HS256 must be rejected by map_algorithm");
    }

    // RFC 8725 §3.1: an unrecognized alg is not resolved to an algorithm.
    #[test]
    fn test_map_algorithm_rejects_unknown() {
        let result = map_algorithm("FOOBAR");
        assert!(result.is_err(), "Unknown algorithm must be rejected");
    }

    // RFC 8725 §3.1: an empty alg is not resolved to an algorithm.
    #[test]
    fn test_map_algorithm_rejects_empty_string() {
        let result = map_algorithm("");
        assert!(result.is_err(), "Empty string must be rejected");
    }

    // RFC 8725 §3.1: algorithm names are matched exactly.
    #[test]
    fn test_map_algorithm_is_case_sensitive() {
        // "es256" (lowercase) is not a valid algorithm identifier.
        let result = map_algorithm("es256");
        assert!(result.is_err(), "Algorithm matching must be case-sensitive");
    }

    // ====================================================================
    // PS256 support (RFC 9101 / FAPI 2.0)
    // ====================================================================

    // RFC 7523 §3: an asymmetrically signed assertion is accepted.
    #[test]
    fn test_parse_assertion_header_accepts_ps256() {
        let header_json = serde_json::json!({"alg": "PS256", "typ": "JWT"});
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header_json).unwrap());
        let jwt = format!(
            "{}.{}.sig",
            header_b64,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}"),
        );
        let result = parse_assertion_header(&jwt);
        assert!(result.is_ok(), "PS256 should be accepted: {result:?}");
        assert_eq!(result.unwrap().alg, "PS256");
    }

    // RFC 8725 §3.1: the alg header names the verification algorithm.
    #[test]
    fn test_map_algorithm_ps256() {
        let alg = map_algorithm("PS256").expect("PS256 should be mapped");
        assert_eq!(alg, jsonwebtoken::Algorithm::PS256);
    }

    // ====================================================================
    // validate_client_assertion_algorithm tests (#1003)
    // ====================================================================

    // RFC 8725 §3.1: the algorithm must be one the client registered.
    #[test]
    fn test_validate_client_assertion_algorithm_allows_listed() {
        assert!(validate_client_assertion_algorithm("ES256", &JwsAlgorithm::FAPI_ALLOWED).is_ok());
        assert!(validate_client_assertion_algorithm("PS256", &JwsAlgorithm::FAPI_ALLOWED).is_ok());
        assert!(validate_client_assertion_algorithm("EdDSA", &JwsAlgorithm::FAPI_ALLOWED).is_ok());
    }

    // RFC 8725 §3.1: an algorithm the client did not register is rejected.
    #[test]
    fn test_validate_client_assertion_algorithm_rejects_unlisted() {
        let result = validate_client_assertion_algorithm("RS256", &JwsAlgorithm::FAPI_ALLOWED);
        assert!(
            result.is_err(),
            "RS256 must be rejected against FAPI_ALLOWED"
        );
        let err = result.unwrap_err();
        let desc = oauth_error_description(&err);
        assert!(
            desc.contains("Allowed: ES256, PS256, EdDSA"),
            "error message must list the allowed set, got: {desc}"
        );
    }

    // RFC 8725 §3.1: a wider registered set admits more algorithms.
    #[test]
    fn test_validate_client_assertion_algorithm_allows_rs256_in_wider_set() {
        assert!(
            validate_client_assertion_algorithm("RS256", &JwsAlgorithm::CLIENT_ASSERTION_ALLOWED)
                .is_ok()
        );
    }

    // RFC 8725 §3.1: an unparseable registered algorithm admits nothing.
    #[test]
    fn test_validate_client_assertion_algorithm_rejects_unparseable() {
        let result = validate_client_assertion_algorithm("HS256", &JwsAlgorithm::FAPI_ALLOWED);
        assert!(result.is_err(), "HS256 must be rejected outright");
    }
}
