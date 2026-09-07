// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9421 HTTP Message Signature key resolver for vouch-server.
//!
//! Implements [`vouch_httpsig::middleware::KeyResolver`] by extracting
//! `client_id` from the access token in the `Authorization` header,
//! looking up the OAuth client's JWKS, and finding the P-256 public key
//! matching the signature's `keyid`.

use std::sync::Arc;

use p256::elliptic_curve::sec1::ToEncodedPoint;

use vouch_common::protocol;
use vouch_httpsig::algorithm::VerifyingAlgorithm;
use vouch_httpsig::algorithm::ecdsa_p256::EcdsaP256Verifier;
use vouch_httpsig::middleware::KeyResolver;

use crate::AppState;

/// Key resolver that finds P-256 public keys from OAuth client JWKS.
///
/// Resolution flow:
/// 1. Extracts the access token from the `Authorization` header
/// 2. Decodes the JWT to get `client_id`
/// 3. Looks up the OAuth client by `client_id`
/// 4. Searches the client's JWKS for a key matching `keyid`
/// 5. Reconstructs the P-256 public key from JWK (x, y) coordinates
pub struct OAuthClientKeyResolver {
    state: Arc<AppState>,
}

impl OAuthClientKeyResolver {
    /// Create a new resolver backed by the application state.
    #[must_use]
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

/// Nonce validity in seconds (5 minutes, matching signature max_age).
const NONCE_VALIDITY_SECONDS: i64 = 300;

impl KeyResolver for OAuthClientKeyResolver {
    fn resolve(
        &self,
        keyid: &str,
        headers: &http::HeaderMap,
    ) -> impl std::future::Future<Output = Option<Arc<dyn VerifyingAlgorithm>>> + Send + '_ {
        // Extract client_id synchronously (JWT payload parsing is CPU-only)
        let client_id = extract_client_id(headers, &self.state);
        let keyid = keyid.to_string();

        async move {
            let client_id = client_id?;

            // `KeyResolver` returns an `Option`, so a lookup failure and an
            // unknown client are indistinguishable to the caller and both
            // reject the request. Failing closed is right — an unresolvable
            // key cannot verify a signature — but the cause has to be visible,
            // or a database outage reads as a flood of signature failures.
            let client = match crate::db::get_oauth_client_by_client_id(
                &self.state.store,
                &client_id,
            )
            .await
            {
                Ok(client) => client?,
                Err(e) => {
                    tracing::warn!(
                        "Client lookup failed for {client_id} during signature verification: {e}"
                    );
                    return None;
                }
            };

            // Only clients registered with `jwks_uri` need the cached fetch —
            // skip the extra DB round trip for the inline case.
            let resolved;
            let inline;
            let jwks_value = match client.keys.as_ref()? {
                crate::db::ClientKeys::Inline(jwks) => {
                    inline = serde_json::to_value(jwks).ok()?;
                    &inline
                }
                crate::db::ClientKeys::Uri(uri) => {
                    let cached = crate::db::get_jwks_cache(&self.state.store, &client.id)
                        .await
                        .map_err(|e| {
                            tracing::warn!(
                                "JWKS cache lookup failed for HTTP signature verification: {e}"
                            );
                        })
                        .ok()
                        .flatten();

                    // Honor the cache TTL rather than trusting whatever was stored:
                    // reading it verbatim let a key the client had already rotated
                    // out keep verifying signatures until the row happened to be
                    // replaced.
                    // This path doesn't act on whether the resolution fetched —
                    // that distinction only matters to the mTLS force-refetch
                    // retry gate (services/oidc/token.rs).
                    let (value, _origin) = crate::infra::jwks::resolve_cached_jwks(
                        &self.state.store,
                        &client.id,
                        uri,
                        cached.as_ref(),
                        !self.state.config().tls_configured(),
                        &self.state.http_client,
                    )
                    .await
                    .map_err(|e| {
                        tracing::warn!(
                            "JWKS resolution failed for HTTP signature verification: {e}"
                        );
                    })
                    .ok()?;
                    resolved = value;
                    &resolved
                }
            };
            let keys = jwks_value.get("keys")?.as_array()?;

            for jwk in keys {
                let Some(kid) = jwk.get("kid").and_then(|v| v.as_str()) else {
                    continue; // skip JWKs without kid
                };
                if kid == keyid {
                    // A kid-matching JWK that is not a well-formed P-256 key
                    // must not abort the scan: RFC 7517 §4.5 makes `kid`
                    // uniqueness a SHOULD, so a later key carrying the same
                    // `kid` can still verify the signature (same candidate-skip
                    // rule as the JWT bearer and upstream-IdP key searches).
                    let Some(public_key) = jwk_to_p256_public_key(jwk) else {
                        continue;
                    };
                    let verifier = EcdsaP256Verifier::new(&public_key);
                    let arc: Arc<dyn VerifyingAlgorithm> = Arc::new(verifier);
                    return Some(arc);
                }
            }

            None
        }
    }

    async fn generate_nonce(&self) -> Option<String> {
        crate::db::generate_dpop_nonce(&self.state.store, NONCE_VALIDITY_SECONDS)
            .await
            .ok()
    }

    /// Validate and consume a signature nonce against the shared nonce store.
    ///
    /// HTTP signature nonces deliberately share the DPoP nonce store and
    /// issuance path (`generate_dpop_nonce`): both are opaque random
    /// single-use values with the same validity window, and the atomic
    /// delete-if-not-expired gives single-use semantics on every backend.
    fn validate_nonce(
        &self,
        nonce: &str,
    ) -> impl std::future::Future<Output = vouch_httpsig::middleware::NonceValidation> + Send + '_
    {
        use vouch_httpsig::middleware::NonceValidation;

        // Own the nonce: the returned future may only borrow `self`.
        let nonce = nonce.to_string();
        async move {
            match crate::db::validate_and_consume_dpop_nonce(&self.state.store, &nonce).await {
                Ok(()) => NonceValidation::Valid,
                Err(
                    crate::db::ClaimError::AlreadyConsumed | crate::db::ClaimError::InvalidInput(_),
                ) => NonceValidation::Invalid,
                Err(crate::db::ClaimError::Database(msg)) => {
                    tracing::error!("signature nonce validation DB failure: {msg}");
                    NonceValidation::Error
                }
            }
        }
    }
}

/// Extract `client_id` from the access token in the `Authorization` header.
///
/// Parses the JWT payload without signature verification — the handler
/// performs full validation later. This avoids redundant crypto work and
/// prevents misleading errors (e.g., expired token producing "unknown key ID"
/// instead of proper 401 with step-up/nonce challenge headers).
fn extract_client_id(headers: &http::HeaderMap, _state: &AppState) -> Option<String> {
    let auth_header = headers.get("authorization")?.to_str().ok()?;

    // Accepts the same schemes as `extract_token_from_request` — both go
    // through the shared matcher, so they cannot drift.
    let token = crate::http::strip_auth_scheme(auth_header, protocol::AUTH_SCHEME_DPOP)
        .or_else(|| crate::http::strip_auth_scheme(auth_header, protocol::AUTH_SCHEME_BEARER))?;

    // Parse the JWT payload without verification. Going through `Jws` keeps
    // this pre-parse on the same splitting and decoding as every other JWS
    // path — including the RFC 7515 Section 4.1.11 `crit` refusal, so a token
    // the verifying paths would reject never resolves a signing key here.
    let claims: serde_json::Value = crate::crypto::jwt::Jws::parse(token)
        .and_then(|jws| jws.claims_as())
        .ok()?;
    claims.get("client_id")?.as_str().map(String::from)
}

/// Convert a P-256 EC JWK to a 65-byte uncompressed SEC1 public key.
///
/// Returns `None` if the JWK is not a valid P-256 key or the coordinates
/// are not a point on the curve.
fn jwk_to_p256_public_key(jwk: &serde_json::Value) -> Option<Vec<u8>> {
    // JwkEcKey rejects unknown members (kid, use, alg), so hand it only the
    // EC members of the JWKS entry.
    let ec_members = serde_json::json!({
        "kty": jwk.get("kty")?,
        "crv": jwk.get("crv")?,
        "x": jwk.get("x")?,
        "y": jwk.get("y")?,
    });
    let ec_jwk: p256::elliptic_curve::JwkEcKey = serde_json::from_value(ec_members).ok()?;
    let public_key = ec_jwk.to_public_key::<p256::NistP256>().ok()?;
    Some(public_key.to_encoded_point(false).as_bytes().to_vec())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn auth_headers(value: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", value.parse().expect("valid header value"));
        headers
    }

    /// Unsigned JWT-shaped token whose payload carries the given `client_id`.
    fn jwt_with_client_id(client_id: &str) -> String {
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::json!({ "client_id": client_id }).to_string());
        format!("eyJhbGciOiJFUzI1NiJ9.{payload}.sig")
    }

    /// RFC 9110 Section 11.1: the auth-scheme token is case-insensitive, so
    /// `BEARER`, `bearer`, `DPOP`, and `dpop` must all match. If this
    /// resolver rejected casings that `extract_token_from_request` accepts,
    /// a request with a non-canonical scheme would pass token auth but fail
    /// signature key resolution on signature-required `/v1/*` routes.
    #[tokio::test]
    async fn extract_client_id_accepts_scheme_case_variants() {
        let state = crate::test_utils::test_app_state().await;
        let token = jwt_with_client_id("client-123");

        for scheme in ["Bearer", "BEARER", "bearer", "DPoP", "DPOP", "dpop"] {
            let headers = auth_headers(&format!("{scheme} {token}"));
            assert_eq!(
                extract_client_id(&headers, &state).as_deref(),
                Some("client-123"),
                "{scheme} scheme must be accepted (RFC 9110 case-insensitivity)"
            );
        }
    }

    #[tokio::test]
    async fn extract_client_id_rejects_unrecognized_scheme() {
        let state = crate::test_utils::test_app_state().await;
        let token = jwt_with_client_id("client-123");

        for value in [format!("Basic {token}"), "Bearer".to_string()] {
            let headers = auth_headers(&value);
            assert_eq!(extract_client_id(&headers, &state), None);
        }
    }

    #[test]
    fn test_jwk_to_p256_public_key_valid() {
        let point = p256::SecretKey::from_slice(&[7u8; 32])
            .unwrap()
            .public_key()
            .to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
            "kid": "test-key"
        });

        let key = jwk_to_p256_public_key(&jwk).unwrap();
        assert_eq!(key, point.as_bytes());
    }

    #[test]
    fn test_jwk_to_p256_public_key_rejects_off_curve_point() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode([1u8; 32]),
            "y": URL_SAFE_NO_PAD.encode([2u8; 32]),
        });
        assert!(jwk_to_p256_public_key(&jwk).is_none());
    }

    #[test]
    fn test_jwk_to_p256_public_key_wrong_curve() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-384",
            "x": URL_SAFE_NO_PAD.encode([1u8; 32]),
            "y": URL_SAFE_NO_PAD.encode([2u8; 32]),
        });
        assert!(jwk_to_p256_public_key(&jwk).is_none());
    }

    #[test]
    fn test_jwk_to_p256_public_key_wrong_kty() {
        let jwk = serde_json::json!({
            "kty": "RSA",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode([1u8; 32]),
            "y": URL_SAFE_NO_PAD.encode([2u8; 32]),
        });
        assert!(jwk_to_p256_public_key(&jwk).is_none());
    }

    // RFC 7518 §6.2.1: "The following members MUST be present for all
    // Elliptic Curve public keys: o "crv" o "x"".
    #[test]
    fn test_jwk_to_p256_public_key_missing_x() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "y": URL_SAFE_NO_PAD.encode([2u8; 32]),
        });
        assert!(jwk_to_p256_public_key(&jwk).is_none());
    }

    // RFC 7518 §6.2.1.2: "The length of this octet string MUST be the full
    // size of a coordinate for the curve specified in the "crv" parameter."
    // A 16-octet x is half a P-256 coordinate, so the key is refused rather
    // than zero-extended into a different point.
    #[test]
    fn test_jwk_to_p256_public_key_wrong_coordinate_length() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode([1u8; 16]),
            "y": URL_SAFE_NO_PAD.encode([2u8; 32]),
        });
        assert!(jwk_to_p256_public_key(&jwk).is_none());
    }

    /// A server-issued nonce validates once and is then consumed (#718):
    /// the second presentation is Invalid, and a random string never
    /// issued is Invalid too.
    #[tokio::test]
    async fn test_validate_nonce_single_use() {
        use vouch_httpsig::middleware::{KeyResolver, NonceValidation};

        let state = crate::test_utils::test_app_state().await;
        let resolver = OAuthClientKeyResolver::new(state.clone());

        let nonce = resolver.generate_nonce().await.expect("issue nonce");
        assert_eq!(
            resolver.validate_nonce(&nonce).await,
            NonceValidation::Valid,
            "first use of a fresh nonce must be accepted"
        );
        assert_eq!(
            resolver.validate_nonce(&nonce).await,
            NonceValidation::Invalid,
            "a consumed nonce must be rejected"
        );
        assert_eq!(
            resolver.validate_nonce("never-issued-nonce").await,
            NonceValidation::Invalid,
            "an unknown nonce must be rejected"
        );
    }
}
