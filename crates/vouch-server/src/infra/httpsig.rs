// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9421 HTTP Message Signature key resolver for vouch-server.
//!
//! Implements [`vouch_httpsig::middleware::KeyResolver`] by extracting
//! `client_id` from the access token in the `Authorization` header,
//! looking up the OAuth client's JWKS, and finding the P-256 public key
//! matching the signature's `keyid`.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

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

            let client = crate::db::get_oauth_client_by_client_id(&self.state.store, &client_id)
                .await
                .ok()
                .flatten()?;

            let jwks_cache = crate::db::get_jwks_cache(&self.state.store, &client.id)
                .await
                .map_err(|e| {
                    tracing::warn!("JWKS cache lookup failed for HTTP signature verification: {e}");
                })
                .ok()
                .flatten();
            let jwks_value = client
                .jwks
                .as_ref()
                .or_else(|| jwks_cache.as_ref().map(|c| &c.value))?;
            let keys = jwks_value.get("keys")?.as_array()?;

            for jwk in keys {
                let Some(kid) = jwk.get("kid").and_then(|v| v.as_str()) else {
                    continue; // skip JWKs without kid
                };
                if kid == keyid {
                    let public_key = jwk_to_p256_public_key(jwk)?;
                    let verifier = EcdsaP256Verifier::new(&public_key, &keyid);
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
}

/// Extract `client_id` from the access token in the `Authorization` header.
///
/// Parses the JWT payload without signature verification — the handler
/// performs full validation later. This avoids redundant crypto work and
/// prevents misleading errors (e.g., expired token producing "unknown key ID"
/// instead of proper 401 with step-up/nonce challenge headers).
fn extract_client_id(headers: &http::HeaderMap, _state: &AppState) -> Option<String> {
    let auth_header = headers.get("authorization")?.to_str().ok()?;

    let token = auth_header
        .strip_prefix("DPoP ")
        .or_else(|| auth_header.strip_prefix("Bearer "))?;

    // Parse JWT payload (second segment) without verification
    let parts: Vec<&str> = token.split('.').collect();
    let payload_b64 = parts.get(1)?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    claims.get("client_id")?.as_str().map(String::from)
}

/// Convert a P-256 EC JWK to a 65-byte uncompressed SEC1 public key.
///
/// Returns `None` if the JWK is not a valid P-256 key.
fn jwk_to_p256_public_key(jwk: &serde_json::Value) -> Option<Vec<u8>> {
    let kty = jwk.get("kty")?.as_str()?;
    let crv = jwk.get("crv")?.as_str()?;
    if kty != "EC" || crv != "P-256" {
        return None;
    }

    let x_bytes = URL_SAFE_NO_PAD.decode(jwk.get("x")?.as_str()?).ok()?;
    let y_bytes = URL_SAFE_NO_PAD.decode(jwk.get("y")?.as_str()?).ok()?;

    // P-256 coordinates are 32 bytes each
    if x_bytes.len() != 32 || y_bytes.len() != 32 {
        return None;
    }

    // Uncompressed SEC1 point: 0x04 || x || y
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x_bytes);
    point.extend_from_slice(&y_bytes);
    Some(point)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_jwk_to_p256_public_key_valid() {
        let x = URL_SAFE_NO_PAD.encode([1u8; 32]);
        let y = URL_SAFE_NO_PAD.encode([2u8; 32]);
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
            "kid": "test-key"
        });

        let key = jwk_to_p256_public_key(&jwk).unwrap();
        assert_eq!(key.len(), 65);
        assert_eq!(key[0], 0x04);
        assert_eq!(&key[1..33], &[1u8; 32]);
        assert_eq!(&key[33..65], &[2u8; 32]);
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

    #[test]
    fn test_jwk_to_p256_public_key_missing_x() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "y": URL_SAFE_NO_PAD.encode([2u8; 32]),
        });
        assert!(jwk_to_p256_public_key(&jwk).is_none());
    }

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
}
