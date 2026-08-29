// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9449 DPoP (Demonstrating Proof of Possession) implementation.
//!
//! DPoP provides sender-constrained tokens by binding tokens to a client's
//! cryptographic key pair. This prevents token theft and replay attacks.
//!
//! Key components:
//! - DPoP Proof JWT: A signed JWT proving possession of a private key
//! - JWK Thumbprint: SHA-256 hash of the public key (RFC 7638)
//! - Token Binding: Access tokens include `cnf` claim with JWK thumbprint

use aws_lc_rs::digest::{self, SHA256};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::crypto::alg::JwsAlgorithm;
use crate::crypto::jwk::Jwk;
use crate::crypto::jwt::{HeaderAlg, Jws, JwsError};
use crate::db::{self, store::DocumentStore};

/// Nonce validity in seconds (5 minutes).
const NONCE_VALIDITY_SECONDS: i64 = 300;

/// Supported DPoP signing algorithms (asymmetric only per RFC 9449).
///
/// See [`JwsAlgorithm::FAPI_ALLOWED`] for the FAPI 2.0 citation excluding RS256.
pub const SUPPORTED_ALGORITHMS: &[JwsAlgorithm] = &JwsAlgorithm::FAPI_ALLOWED;

/// DPoP JWT header.
///
/// Built from a [`JoseHeader`](crate::crypto::jwt::JoseHeader) that has
/// already been through [`Jws::parse`], so `jwk` carries no private key
/// material (RFC 9449 Section 4.3 item 7) and `alg` is one of
/// [`SUPPORTED_ALGORITHMS`]. `typ` is not carried: it is checked against
/// `dpop+jwt` during the parse and nothing downstream reads it.
#[derive(Debug, Clone)]
pub(crate) struct DpopHeader {
    /// Algorithm used for signing.
    pub(crate) alg: JwsAlgorithm,
    /// JSON Web Key (embedded public key).
    pub(crate) jwk: Jwk,
}

/// DPoP JWT claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopClaims {
    /// Unique identifier for the proof (prevents replay).
    pub jti: String,
    /// HTTP method of the request (e.g., "POST").
    pub htm: String,
    /// HTTP URI of the request (without query/fragment).
    pub htu: String,
    /// Issued at timestamp (seconds since epoch).
    pub iat: i64,
    /// Server-provided nonce (if required).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Access token hash (for protected resource requests).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
    /// Credential source identifier (custom claim, RFC 9449 §4.2 allows additional claims).
    /// When present, the server adds AI-specific session tags to issued tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

// CnfClaim is defined in claims.rs (used for both DPoP and mTLS binding).
pub use super::claims::CnfClaim;

/// DPoP validation error.
#[derive(Debug, Clone)]
pub enum DpopError {
    /// Missing DPoP header.
    MissingProof,
    /// Invalid proof format.
    InvalidFormat(String),
    /// Invalid signature.
    InvalidSignature,
    /// Unsupported algorithm.
    UnsupportedAlgorithm(String),
    /// Proof has expired.
    Expired,
    /// JTI replay detected.
    ReplayDetected,
    /// HTTP method mismatch.
    MethodMismatch,
    /// HTTP URI mismatch.
    UriMismatch,
    /// Missing or invalid nonce.
    InvalidNonce,
    /// Access token hash mismatch.
    TokenHashMismatch,
    /// Server requires nonce.
    UseNonce(String),
    /// Backend database failure during JTI persistence or nonce
    /// generation/validation. Distinct from `InvalidFormat`: this is a
    /// server-side fault (maps to `server_error` / HTTP 500), not a
    /// client-side proof defect (issue #427). Without this variant the
    /// catch-all in `validate_dpop_common` swallowed `ClaimError::Database`
    /// as `InvalidFormat`, which surfaced as HTTP 400 `invalid_dpop_proof`
    /// and prevented clients from retrying transient DB failures.
    Database(String),
}

impl std::fmt::Display for DpopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingProof => write!(f, "missing DPoP proof"),
            Self::InvalidFormat(msg) => write!(f, "invalid DPoP format: {msg}"),
            Self::InvalidSignature => write!(f, "invalid DPoP signature"),
            Self::UnsupportedAlgorithm(alg) => write!(f, "unsupported DPoP algorithm: {alg}"),
            Self::Expired => write!(f, "DPoP proof expired"),
            Self::ReplayDetected => write!(f, "DPoP proof replay detected"),
            Self::MethodMismatch => write!(f, "DPoP htm claim mismatch"),
            Self::UriMismatch => write!(f, "DPoP htu claim mismatch"),
            Self::InvalidNonce => write!(f, "invalid or missing DPoP nonce"),
            Self::TokenHashMismatch => write!(f, "DPoP ath claim mismatch"),
            Self::UseNonce(nonce) => write!(f, "use_dpop_nonce: {nonce}"),
            Self::Database(msg) => write!(f, "DPoP backend failure: {msg}"),
        }
    }
}

impl std::error::Error for DpopError {}

/// Witness that a DPoP proof (RFC 9449) has been fully validated AND its
/// `jti` has been atomically committed to the replay-prevention table.
///
/// Construction is private to this module — the only path to an instance is
/// a successful return from [`validate_dpop_proof`] or [`validate_dpop_at_resource`],
/// both of which call [`validate_dpop_common`], which performs signature
/// verification, claim validation (`htm`/`htu`/`exp`/`nonce`), and an atomic
/// insert into the DPoP JTI table. Callers that hold a `ValidatedDpopProof`
/// can rely on it as compile-time evidence that the proof was not a replay
/// and is bound to the carried `jkt`.
///
/// The replay half of that evidence is the [`db::DpopJtiClaim`] the witness
/// owns, not a comment: the claim is only constructible by the atomic insert
/// that won, and it is moved in here rather than dropped at the end of
/// validation.
///
/// The carried `jkt`/`jti`/`source` are the validation metadata downstream
/// consumers need (e.g., binding the access token via `cnf.jkt`, recording
/// `source` in audit logs). Reading those fields is fine; the sealing only
/// prevents *fabrication* of a witness without going through validation.
///
/// Intentionally not `Clone` — the witness represents a single one-shot
/// validation. The `#[must_use]` ensures it is bound at the call site.
#[must_use = "the DPoP proof was validated and its JTI atomically committed; \
              bind this witness so it can be threaded into downstream consumers"]
#[derive(Debug)]
pub struct ValidatedDpopProof {
    /// JWK thumbprint of the sender's key. Used to bind access tokens
    /// via `cnf.jkt` (RFC 9449 §6).
    pub(crate) jkt: String,
    /// Unique identifier from the proof.
    pub(crate) jti: String,
    /// Credential source identifier from the DPoP proof (custom claim).
    pub(crate) source: Option<String>,
    /// The replay guarantee itself: the witness [`db::check_and_store_dpop_jti`]
    /// returns when its atomic insert wins. Holding it is what makes "this
    /// `jti` was committed by this request" a property of the value rather
    /// than a claim in prose.
    ///
    /// It doubles as the construction seal. `DpopJtiClaim`'s own field is
    /// private to `db::dpop`, so no code outside that module can produce
    /// one — and therefore no code outside it can struct-literal a
    /// `ValidatedDpopProof`. Stronger than `#[non_exhaustive]`, which
    /// would still allow in-crate construction.
    _jti_claim: db::DpopJtiClaim,
}

impl ValidatedDpopProof {
    /// Test-only constructor. Production code must obtain a witness via
    /// [`validate_dpop_proof`] / [`validate_dpop_at_resource`].
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn for_testing(jkt: String, jti: String, source: Option<String>) -> Self {
        Self {
            jkt,
            jti,
            source,
            _jti_claim: db::DpopJtiClaim::for_testing(),
        }
    }
}

/// Compute the access token hash (`ath`) for DPoP (RFC 9449 Section 4.2).
///
/// The hash is the base64url-encoded SHA-256 hash of the ASCII access token.
/// This is used at protected resource endpoints (e.g., userinfo) to verify
/// that the DPoP proof was created for the specific access token being used.
pub fn compute_access_token_hash(access_token: &str) -> String {
    let hash = digest::digest(&SHA256, access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(hash.as_ref())
}

/// Parse a DPoP proof JWT header (without signature verification or claims parsing).
///
/// Used internally by `parse_and_verify_dpop_proof` to obtain the JWK and
/// algorithm before combined signature verification and claims extraction.
///
/// Three of the checks RFC 9449 Section 4.3 requires are discharged by
/// [`Jws::parse`] and the types it yields rather than here: item 2 (a
/// well-formed JWT), item 7 (no private key in the `jwk`), and the RFC 7515
/// Section 4.1.11 `crit` refusal. What remains is what is specific to DPoP —
/// the `typ`, the presence of a `jwk`, and the local algorithm policy.
fn parse_dpop_header(proof: &str) -> Result<DpopHeader, DpopError> {
    let jws = Jws::parse(proof).map_err(|e| match e {
        JwsError::Critical => DpopError::InvalidFormat(
            "DPoP proof header carries an unsupported 'crit' extension".to_string(),
        ),
        JwsError::PrivateKey => DpopError::InvalidFormat(
            "JWK in DPoP proof header must not contain private key material".to_string(),
        ),
        JwsError::Malformed(reason) => DpopError::InvalidFormat(reason.to_string()),
    })?;

    let jwk = jws.header().jwk.clone().ok_or_else(|| {
        DpopError::InvalidFormat("DPoP proof header must carry 'jwk'".to_string())
    })?;

    // RFC 9449 Section 4.3 item 4.
    let typ = jws.header().typ.clone().unwrap_or_default();
    if typ != "dpop+jwt" {
        return Err(DpopError::InvalidFormat(format!(
            "typ must be 'dpop+jwt', got '{typ}'"
        )));
    }

    // RFC 9449 Section 4.3 item 5: the `alg` must be "a registered asymmetric
    // digital signature algorithm ..., is not none, is supported by the
    // application, and is acceptable per local policy". `HeaderAlg::Other`
    // covers the first two; `SUPPORTED_ALGORITHMS` is the local policy.
    let HeaderAlg::Known(alg) = jws.header().alg else {
        return Err(DpopError::UnsupportedAlgorithm(
            jws.header().alg.as_str().to_string(),
        ));
    };
    if !SUPPORTED_ALGORITHMS.contains(&alg) {
        return Err(DpopError::UnsupportedAlgorithm(alg.as_str().to_string()));
    }

    Ok(DpopHeader { alg, jwk })
}

/// Parse and verify a DPoP proof in a single pass.
///
/// 1. Decodes the header to extract the JWK and algorithm.
/// 2. Builds a decoding key from the JWK.
/// 3. Uses `jsonwebtoken::decode()` for combined signature verification
///    and claims extraction (avoiding a redundant second parse).
///
/// Returns the parsed header and verified claims.
fn parse_and_verify_dpop_proof(proof: &str) -> Result<(DpopHeader, DpopClaims), DpopError> {
    let header = parse_dpop_header(proof)?;

    // Build decoding key from JWK
    let decoding_key = build_decoding_key(&header.jwk, header.alg)?;

    // Map the typed algorithm to jsonwebtoken's Algorithm enum. RS256 is
    // unreachable — `parse_dpop_header` admits only `SUPPORTED_ALGORITHMS`,
    // which is `FAPI_ALLOWED` — but stays an arm so adding an algorithm to
    // `JwsAlgorithm` fails to compile here rather than silently mapping.
    let algorithm = match header.alg {
        JwsAlgorithm::Es256 => jsonwebtoken::Algorithm::ES256,
        JwsAlgorithm::Ps256 => jsonwebtoken::Algorithm::PS256,
        JwsAlgorithm::EdDsa => jsonwebtoken::Algorithm::EdDSA,
        JwsAlgorithm::Rs256 => {
            return Err(DpopError::UnsupportedAlgorithm(
                header.alg.as_str().to_string(),
            ));
        }
    };

    // Build validation settings
    let mut validation = jsonwebtoken::Validation::new(algorithm);
    validation.required_spec_claims.clear(); // DPoP has custom claims
    validation.validate_exp = false; // We validate iat manually
    validation.validate_aud = false; // No audience in DPoP

    // Verify signature and extract claims in a single pass
    let token_data = jsonwebtoken::decode::<DpopClaims>(proof, &decoding_key, &validation)
        .map_err(|_| DpopError::InvalidSignature)?;

    Ok((header, token_data.claims))
}

/// Parameters for [`validate_dpop_claims`].
///
/// Bundled per the project's 5-positional-parameter limit — `now` pushed the
/// prior 6-parameter list over the line, and is a natural grouping point
/// since it is the one field every caller stamps identically.
#[derive(Clone, Copy)]
pub struct DpopClaimsValidation<'a> {
    /// Current time (seconds since epoch), stamped once by the caller at the
    /// entry point (`Timestamp::now().as_second()` in production; a fixed
    /// value in tests for deterministic boundary checks).
    pub now: i64,
    pub expected_method: &'a str,
    pub accepted_uris: &'a [String],
    pub max_age_seconds: i64,
    pub expected_nonce: Option<&'a str>,
    pub expected_ath: Option<&'a str>,
}

/// Validate DPoP proof claims (without signature verification).
pub fn validate_dpop_claims(
    claims: &DpopClaims,
    params: &DpopClaimsValidation<'_>,
) -> Result<(), DpopError> {
    let DpopClaimsValidation {
        now,
        expected_method,
        accepted_uris,
        max_age_seconds,
        expected_nonce,
        expected_ath,
    } = *params;

    // Check method
    if claims.htm.to_uppercase() != expected_method.to_uppercase() {
        return Err(DpopError::MethodMismatch);
    }

    // Check URI against all accepted URIs (canonical + mTLS alias)
    let claims_uri = normalize_uri(&claims.htu);
    let uri_matches = accepted_uris
        .iter()
        .any(|uri| normalize_uri(uri) == claims_uri);
    if !uri_matches {
        return Err(DpopError::UriMismatch);
    }

    // Check timestamp (not too old, not in future)
    let age = now.saturating_sub(claims.iat);
    if age < -60 {
        // Allow 60 seconds clock skew into future
        return Err(DpopError::Expired);
    }
    if age > max_age_seconds {
        return Err(DpopError::Expired);
    }

    // RFC 9449 Section 5.1: Nonce validation.
    // When `expected_nonce` is Some, validate inline with constant-time comparison.
    // When `expected_nonce` is None (callers use the database instead), skip
    // the inline check here. Callers handle missing nonce before calling this
    // function and validate provided nonces via the database afterward.
    if let Some(expected) = expected_nonce {
        match &claims.nonce {
            Some(proof_nonce) => {
                let is_valid: bool = proof_nonce.as_bytes().ct_eq(expected.as_bytes()).into();
                if !is_valid {
                    return Err(DpopError::InvalidNonce);
                }
            }
            None => return Err(DpopError::InvalidNonce),
        }
    }

    // Check access token hash if provided (constant-time comparison for defense-in-depth)
    if let Some(expected_ath) = expected_ath {
        match &claims.ath {
            Some(proof_ath) => {
                let is_valid: bool = proof_ath.as_bytes().ct_eq(expected_ath.as_bytes()).into();
                if !is_valid {
                    return Err(DpopError::TokenHashMismatch);
                }
            }
            _ => return Err(DpopError::TokenHashMismatch),
        }
    }

    Ok(())
}

/// Normalize a URI for comparison against the DPoP `htu` claim.
///
/// RFC 9449 Section 4.2 defines `htu` as "The HTTP target URI (Section 7.1 of
/// [RFC9110]) of the request to which the JWT is attached, without query and
/// fragment parts", so both are dropped. Section 4.3 then asks for more than
/// that: "To reduce the likelihood of false negatives, servers SHOULD employ
/// syntax-based normalization (Section 6.2.2 of [RFC3986]) and scheme-based
/// normalization (Section 6.2.3 of [RFC3986]) before comparing the htu claim."
///
/// Parsing with the URL parser supplies both: it lowercases the scheme and
/// host, uppercases percent-encoding hex digits, resolves dot segments, elides
/// a port that is the scheme's default, and gives an empty path a single
/// slash. Without it a proof reading `https://Example.com:443/token` failed
/// against a configured `https://example.com/token` even though RFC 3986 calls
/// the two equivalent.
///
/// A URI the parser rejects keeps the old treatment — query and fragment
/// stripped, nothing else — so an unparseable claim still fails the comparison
/// rather than matching something it should not.
pub fn normalize_uri(uri: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(uri) else {
        return strip_query_and_fragment(uri);
    };

    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

/// Drop the query and fragment from a URI that could not be parsed.
#[expect(
    clippy::string_slice,
    reason = "byte offsets come from str::find on ASCII chars; always at valid char boundary"
)]
fn strip_query_and_fragment(uri: &str) -> String {
    // Find the first occurrence of either '?' or '#' to handle all orderings.
    // Safety: both `find('?')` and `find('#')` return byte offsets of ASCII
    // characters, so slicing at `end` is always at a valid char boundary.
    let end = uri
        .find('?')
        .into_iter()
        .chain(uri.find('#'))
        .min()
        .unwrap_or(uri.len());
    uri[..end].to_string()
}

/// Build a `DecodingKey` from a DPoP JWK.
fn build_decoding_key(
    jwk: &Jwk,
    alg: JwsAlgorithm,
) -> Result<jsonwebtoken::DecodingKey, DpopError> {
    match alg {
        JwsAlgorithm::Es256 => match jwk {
            Jwk::Ec(ec) => {
                // jsonwebtoken expects base64url-encoded strings
                jsonwebtoken::DecodingKey::from_ec_components(ec.x(), ec.y())
                    .map_err(|e| DpopError::InvalidFormat(format!("Invalid EC key: {e}")))
            }
            Jwk::Rsa(_) | Jwk::Okp(_) => {
                Err(DpopError::UnsupportedAlgorithm(alg.as_str().to_string()))
            }
        },
        JwsAlgorithm::Ps256 => match jwk {
            Jwk::Rsa(rsa) => {
                // jsonwebtoken expects base64url-encoded strings
                jsonwebtoken::DecodingKey::from_rsa_components(rsa.n(), rsa.e())
                    .map_err(|e| DpopError::InvalidFormat(format!("Invalid RSA key: {e}")))
            }
            Jwk::Ec(_) | Jwk::Okp(_) => {
                Err(DpopError::UnsupportedAlgorithm(alg.as_str().to_string()))
            }
        },
        JwsAlgorithm::EdDsa => match jwk {
            Jwk::Okp(okp) => {
                // jsonwebtoken expects base64url-encoded string
                jsonwebtoken::DecodingKey::from_ed_components(okp.x())
                    .map_err(|e| DpopError::InvalidFormat(format!("Invalid Ed25519 key: {e}")))
            }
            Jwk::Ec(_) | Jwk::Rsa(_) => {
                Err(DpopError::UnsupportedAlgorithm(alg.as_str().to_string()))
            }
        },
        JwsAlgorithm::Rs256 => Err(DpopError::UnsupportedAlgorithm(alg.as_str().to_string())),
    }
}

/// Shared DPoP validation logic for both token and resource endpoints.
///
/// Handles: signature verification, JTI replay check, nonce requirement,
/// claims validation, nonce validation, and thumbprint extraction.
///
/// All state (nonces and JTIs) is persisted in the database for
/// Whether a DPoP proof must carry a server-issued nonce.
///
/// The two endpoints differ, and the difference is not a preference: it is
/// which mechanism binds the proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoncePolicy {
    /// Required. RFC 9449 Section 8 has the token endpoint issue nonces so a
    /// client cannot precompute proofs ahead of time.
    Required,
    /// Optional. At a resource endpoint the `ath` claim binds the proof to a
    /// specific access token, which is what a nonce would otherwise provide.
    Optional,
}

impl NoncePolicy {
    /// Whether a proof lacking a `nonce` claim must be rejected.
    const fn requires_nonce(self) -> bool {
        matches!(self, Self::Required)
    }
}

/// multi-instance consistency.
async fn validate_dpop_common(
    proof: &str,
    expected_method: &str,
    accepted_uris: &[String],
    store: &DocumentStore,
    config_max_age: i64,
    expected_ath: Option<&str>,
    nonce_policy: NoncePolicy,
) -> Result<ValidatedDpopProof, DpopError> {
    // Parse header, verify signature, and extract claims in a single pass
    let (header, claims) = parse_and_verify_dpop_proof(proof)?;

    // Check for replay (JTI must be unique) — atomic INSERT on PRIMARY KEY.
    // The returned `DpopJtiClaim` is moved into the `ValidatedDpopProof`
    // below, so the "this JTI was committed by this request" guarantee is
    // carried by the returned value for as long as it lives.
    let jti_claim = match db::check_and_store_dpop_jti(store, &claims.jti, config_max_age).await {
        Ok(claim) => claim,
        Err(db::claim::ClaimError::AlreadyConsumed) => return Err(DpopError::ReplayDetected),
        Err(db::claim::ClaimError::InvalidInput(msg)) => return Err(DpopError::InvalidFormat(msg)),
        Err(db::claim::ClaimError::Database(msg)) => {
            return Err(DpopError::Database(format!("JTI check failed: {msg}")));
        }
    };

    if nonce_policy.requires_nonce() && claims.nonce.is_none() {
        let new_nonce = db::generate_dpop_nonce(store, NONCE_VALIDITY_SECONDS)
            .await
            .map_err(|e| DpopError::Database(format!("nonce generation failed: {e}")))?;
        return Err(DpopError::UseNonce(new_nonce));
    }

    // Validate claims (method, URI, timestamp, nonce inline, ath)
    // Pass None for expected_nonce to skip redundant self-comparison;
    // database nonce validation happens below.
    validate_dpop_claims(
        &claims,
        &DpopClaimsValidation {
            now: Timestamp::now().as_second(),
            expected_method,
            accepted_uris,
            max_age_seconds: config_max_age,
            expected_nonce: None,
            expected_ath,
        },
    )?;

    // Atomically consume the nonce via the database. A successful return
    // means a single DELETE statement decided the outcome — no TOCTOU
    // window between read and consume. The "this DPoP proof validated
    // successfully" guarantee is carried forward by the returned
    // `ValidatedDpopProof`.
    if let Some(nonce) = claims.nonce.as_deref() {
        match db::validate_and_consume_dpop_nonce(store, nonce).await {
            Ok(()) => {}
            Err(db::claim::ClaimError::AlreadyConsumed) => {
                let new_nonce = db::generate_dpop_nonce(store, NONCE_VALIDITY_SECONDS)
                    .await
                    .map_err(|e| DpopError::Database(format!("nonce generation failed: {e}")))?;
                return Err(DpopError::UseNonce(new_nonce));
            }
            Err(db::claim::ClaimError::InvalidInput(msg)) => {
                return Err(DpopError::InvalidFormat(msg));
            }
            Err(db::claim::ClaimError::Database(msg)) => {
                return Err(DpopError::Database(format!(
                    "nonce validation failed: {msg}"
                )));
            }
        }
    }

    let jkt = header.jwk.thumbprint();
    Ok(ValidatedDpopProof {
        jkt,
        jti: claims.jti,
        source: claims.source,
        _jti_claim: jti_claim,
    })
}

/// Fully validate a DPoP proof, including signature verification.
///
/// This is the main entry point for DPoP validation at the token endpoint.
/// It parses, verifies the signature, validates claims, and checks for replay.
///
/// Returns the validated proof information including the JWK thumbprint.
pub async fn validate_dpop_proof(
    proof: &str,
    expected_method: &str,
    accepted_uris: &[String],
    store: &DocumentStore,
    config_max_age: i64,
) -> Result<ValidatedDpopProof, DpopError> {
    validate_dpop_common(
        proof,
        expected_method,
        accepted_uris,
        store,
        config_max_age,
        None, // No access token hash for token endpoint
        NoncePolicy::Required,
    )
    .await
}

/// Validate a DPoP proof at a resource endpoint (e.g., userinfo).
///
/// This also validates the `ath` claim (access token hash) per RFC 9449
/// Section 7.1. Resource endpoints MUST verify that the DPoP proof binds
/// to the specific access token being used.
///
/// # Arguments
/// * `proof` - The DPoP proof JWT from the `DPoP` header
/// * `access_token` - The access token from the `Authorization: DPoP` header
/// * `method` - HTTP method of the request
/// * `uri` - Full request URI
/// * `pool` - Database pool for nonce and JTI persistence
/// * `config_max_age` - Maximum allowed proof age in seconds
pub async fn validate_dpop_at_resource(
    access_token: &str,
    proof: &str,
    method: &str,
    uri: &str,
    store: &DocumentStore,
    config_max_age: i64,
) -> Result<ValidatedDpopProof, DpopError> {
    let expected_ath = compute_access_token_hash(access_token);
    let accepted_uris = vec![uri.to_string()];
    validate_dpop_common(
        proof,
        method,
        &accepted_uris,
        store,
        config_max_age,
        Some(&expected_ath),
        NoncePolicy::Optional,
    )
    .await
}

/// Published RFC 9449 vectors, kept apart from the hand-built proofs below so
/// the external-reference checks stay easy to find.
#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod rfc9449_vectors;

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_ec_jwk_thumbprint() {
        // Test vector from RFC 7638
        let jwk: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "test_x",
            "y": "test_y",
        }))
        .expect("EC JWK parses");

        let thumbprint = jwk.thumbprint();
        assert!(!thumbprint.is_empty());
        // Thumbprint should be base64url encoded SHA-256 (43 chars)
        assert_eq!(thumbprint.len(), 43);
    }

    // RFC 9449 §4.2: the htu claim is "the HTTP target URI ... without query and
    // fragment parts", so both are removed before comparison.
    #[test]
    fn test_normalize_uri() {
        assert_eq!(
            normalize_uri("https://example.com/token?foo=bar"),
            "https://example.com/token"
        );
        assert_eq!(
            normalize_uri("https://example.com/token#frag"),
            "https://example.com/token"
        );
        assert_eq!(
            normalize_uri("https://example.com/token"),
            "https://example.com/token"
        );
    }

    // RFC 9449 §4.3: "To reduce the likelihood of false negatives, servers
    // SHOULD employ syntax-based normalization (Section 6.2.2 of [RFC3986]) and
    // scheme-based normalization (Section 6.2.3 of [RFC3986]) before comparing
    // the htu claim." Each of these pairs is equivalent under those rules, so
    // each must compare equal.
    #[test]
    fn test_normalize_uri_applies_rfc3986_normalization() {
        let canonical = normalize_uri("https://example.com/token");

        // §6.2.2.1 case normalization: scheme and host are case insensitive.
        assert_eq!(normalize_uri("HTTPS://Example.COM/token"), canonical);
        // §6.2.3 scheme-based normalization: 443 is the default port for https.
        assert_eq!(normalize_uri("https://example.com:443/token"), canonical);
        // §6.2.2.3 path segment normalization: dot segments resolve away.
        assert_eq!(normalize_uri("https://example.com/a/../token"), canonical);
        // §6.2.3: an empty path is equivalent to "/".
        assert_eq!(
            normalize_uri("https://example.com"),
            normalize_uri("https://example.com/")
        );
    }

    // RFC 9449 §4.3 step 9 compares the htu claim to the request URI; a
    // non-default port distinguishes two hosts and must not be normalized away.
    #[test]
    fn test_normalize_uri_keeps_non_default_port() {
        assert_ne!(
            normalize_uri("https://example.com:8443/token"),
            normalize_uri("https://example.com/token")
        );
    }

    // A claim the URL parser rejects keeps the older treatment, so it still
    // fails the comparison rather than normalizing into a match.
    #[test]
    fn test_normalize_uri_unparseable_input() {
        assert_eq!(normalize_uri("not a uri?x=1"), "not a uri");
        assert_ne!(
            normalize_uri("not a uri"),
            normalize_uri("https://example.com/token")
        );
    }

    #[test]
    fn test_access_token_hash() {
        let hash = compute_access_token_hash("test_token");
        assert!(!hash.is_empty());
        // SHA-256 base64url encoded should be 43 chars
        assert_eq!(hash.len(), 43);
    }

    /// `DpopError::Database` is distinct from `DpopError::InvalidFormat` so
    /// the handler layer can route it to HTTP 500 `server_error` instead of
    /// HTTP 400 `invalid_dpop_proof` (issue #427). Lock in the Display form
    /// because handlers surface it verbatim in `error_description`.
    #[test]
    fn dpop_error_database_display() {
        let err = DpopError::Database("connection refused".to_string());
        assert_eq!(err.to_string(), "DPoP backend failure: connection refused");
    }

    /// Guard against accidental collapsing of `Database` back into
    /// `InvalidFormat`: the two map to different HTTP statuses.
    #[test]
    fn dpop_error_database_distinct_from_invalid_format() {
        let db_err = DpopError::Database("x".to_string());
        let fmt_err = DpopError::InvalidFormat("x".to_string());
        assert!(matches!(db_err, DpopError::Database(_)));
        assert!(!matches!(db_err, DpopError::InvalidFormat(_)));
        assert!(matches!(fmt_err, DpopError::InvalidFormat(_)));
    }

    fn make_claims(htm: &str, htu: &str, iat: i64) -> DpopClaims {
        DpopClaims {
            jti: "test-jti".to_string(),
            htm: htm.to_string(),
            htu: htu.to_string(),
            iat,
            nonce: None,
            ath: None,
            source: None,
        }
    }

    fn now() -> i64 {
        jiff::Timestamp::now().as_second()
    }

    /// Build a validation-params struct with sensible defaults, overriding
    /// only the fields a given test cares about.
    fn validation_params(now: i64, max_age_seconds: i64) -> DpopClaimsValidation<'static> {
        DpopClaimsValidation {
            now,
            expected_method: "POST",
            accepted_uris: &[],
            max_age_seconds,
            expected_nonce: None,
            expected_ath: None,
        }
    }

    #[test]
    fn test_validate_dpop_claims_method_mismatch() {
        let claims = make_claims("GET", "https://example.com/token", now());
        let uris = ["https://example.com/token".to_string()];
        let result = validate_dpop_claims(
            &claims,
            &DpopClaimsValidation {
                accepted_uris: &uris,
                ..validation_params(now(), 60)
            },
        );
        assert!(matches!(result, Err(DpopError::MethodMismatch)));
    }

    #[test]
    fn test_validate_dpop_claims_uri_mismatch() {
        let claims = make_claims("POST", "https://other.com/token", now());
        let uris = ["https://example.com/token".to_string()];
        let result = validate_dpop_claims(
            &claims,
            &DpopClaimsValidation {
                accepted_uris: &uris,
                ..validation_params(now(), 60)
            },
        );
        assert!(matches!(result, Err(DpopError::UriMismatch)));
    }

    #[test]
    fn test_validate_dpop_claims_expired() {
        // iat older than max_age_seconds
        let claims = make_claims("POST", "https://example.com/token", now() - 120);
        let uris = ["https://example.com/token".to_string()];
        let result = validate_dpop_claims(
            &claims,
            &DpopClaimsValidation {
                accepted_uris: &uris,
                ..validation_params(now(), 60)
            },
        );
        assert!(matches!(result, Err(DpopError::Expired)));
    }

    #[test]
    fn test_validate_dpop_claims_future_iat() {
        // iat more than 60 seconds in the future (age < -60)
        let claims = make_claims("POST", "https://example.com/token", now() + 120);
        let uris = ["https://example.com/token".to_string()];
        let result = validate_dpop_claims(
            &claims,
            &DpopClaimsValidation {
                accepted_uris: &uris,
                ..validation_params(now(), 300)
            },
        );
        assert!(matches!(result, Err(DpopError::Expired)));
    }

    #[test]
    fn test_validate_dpop_claims_wrong_ath() {
        let mut claims = make_claims("POST", "https://example.com/token", now());
        claims.ath = Some("wrong_hash_value_here_xxxxxxxxxxxxxxxxxxxxxxx".to_string());
        let correct_ath = compute_access_token_hash("my-access-token");
        let uris = ["https://example.com/token".to_string()];
        let result = validate_dpop_claims(
            &claims,
            &DpopClaimsValidation {
                accepted_uris: &uris,
                expected_ath: Some(&correct_ath),
                ..validation_params(now(), 60)
            },
        );
        assert!(matches!(result, Err(DpopError::TokenHashMismatch)));
    }

    #[test]
    fn test_validate_dpop_claims_valid_with_ath() {
        let access_token = "my-access-token";
        let ath = compute_access_token_hash(access_token);
        let mut claims = make_claims("POST", "https://example.com/token", now());
        claims.ath = Some(ath.clone());
        let uris = ["https://example.com/token".to_string()];
        let result = validate_dpop_claims(
            &claims,
            &DpopClaimsValidation {
                accepted_uris: &uris,
                expected_ath: Some(&ath),
                ..validation_params(now(), 60)
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_dpop_claims_valid_no_ath() {
        let claims = make_claims("POST", "https://example.com/token", now());
        let uris = ["https://example.com/token".to_string()];
        let result = validate_dpop_claims(
            &claims,
            &DpopClaimsValidation {
                accepted_uris: &uris,
                ..validation_params(now(), 60)
            },
        );
        assert!(result.is_ok());
    }

    // ========================================================================
    // Deterministic boundary tests (issue #661) — fixed `now`/`iat` pairs
    // instead of real-clock waits, exercising the exact skew and max-age
    // edges.
    // ========================================================================

    /// `iat = now + 60` is exactly at the future-skew allowance and must be
    /// accepted (`age == -60`, not `< -60`).
    #[test]
    fn test_validate_dpop_claims_skew_boundary_accepted() {
        let fixed_now = 1_700_000_000;
        let claims = make_claims("POST", "https://example.com/token", fixed_now + 60);
        let uris = ["https://example.com/token".to_string()];
        let result = validate_dpop_claims(
            &claims,
            &DpopClaimsValidation {
                accepted_uris: &uris,
                ..validation_params(fixed_now, 300)
            },
        );
        assert!(
            result.is_ok(),
            "iat = now + 60 must be accepted: {result:?}"
        );
    }

    /// `iat = now + 61` is one second past the future-skew allowance and
    /// must be rejected (`age == -61 < -60`).
    #[test]
    fn test_validate_dpop_claims_skew_boundary_rejected() {
        let fixed_now = 1_700_000_000;
        let claims = make_claims("POST", "https://example.com/token", fixed_now + 61);
        let uris = ["https://example.com/token".to_string()];
        let result = validate_dpop_claims(
            &claims,
            &DpopClaimsValidation {
                accepted_uris: &uris,
                ..validation_params(fixed_now, 300)
            },
        );
        assert!(matches!(result, Err(DpopError::Expired)));
    }

    /// `age == max_age_seconds` is exactly at the proof-age boundary and
    /// must be accepted (`age > max_age_seconds` is strict).
    #[test]
    fn test_validate_dpop_claims_max_age_boundary_accepted() {
        let fixed_now = 1_700_000_000;
        let max_age_seconds = 60;
        let claims = make_claims(
            "POST",
            "https://example.com/token",
            fixed_now - max_age_seconds,
        );
        let uris = ["https://example.com/token".to_string()];
        let result = validate_dpop_claims(
            &claims,
            &DpopClaimsValidation {
                accepted_uris: &uris,
                ..validation_params(fixed_now, max_age_seconds)
            },
        );
        assert!(
            result.is_ok(),
            "age == max_age_seconds must be accepted: {result:?}"
        );
    }

    /// `age == max_age_seconds + 1` is one second past the proof-age
    /// boundary and must be rejected.
    #[test]
    fn test_validate_dpop_claims_max_age_boundary_rejected() {
        let fixed_now = 1_700_000_000;
        let max_age_seconds = 60;
        let claims = make_claims(
            "POST",
            "https://example.com/token",
            fixed_now - (max_age_seconds + 1),
        );
        let uris = ["https://example.com/token".to_string()];
        let result = validate_dpop_claims(
            &claims,
            &DpopClaimsValidation {
                accepted_uris: &uris,
                ..validation_params(fixed_now, max_age_seconds)
            },
        );
        assert!(matches!(result, Err(DpopError::Expired)));
    }

    // ========================================================================
    // parse_dpop_header — RFC 9449 Section 4.3 private key rejection
    //
    // The JWK embedded in a DPoP proof header MUST NOT contain private key
    // material. Our structs intentionally omit these fields, so we check the
    // raw JSON before deserializing.
    // ========================================================================

    /// Build a minimal JWT string whose header is the given JSON value.
    ///
    /// The payload and signature segments are dummy values — only the header
    /// is inspected by `parse_dpop_header`.
    fn make_dpop_jwt_with_header(header_json: &serde_json::Value) -> String {
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header_json).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"{}");
        let sig_b64 = URL_SAFE_NO_PAD.encode(b"sig");
        format!("{header_b64}.{payload_b64}.{sig_b64}")
    }

    // RFC 7515 §4.1.11: "If any of the listed extension Header Parameters are
    // not understood and supported by the recipient, then the JWS is invalid."
    // Vouch implements no crit extension. Before this check existed, a proof
    // with this header was accepted at /oauth/token and a DPoP-bound access
    // token was issued for it (issue #1094).
    #[test]
    fn test_parse_dpop_header_rejects_crit() {
        let header_json = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
            },
            "crit": ["exp"],
            "exp": 1_363_284_000
        });
        let jwt = make_dpop_jwt_with_header(&header_json);

        let result = parse_dpop_header(&jwt);

        assert!(
            matches!(result, Err(DpopError::InvalidFormat(_))),
            "a crit-bearing DPoP header must be rejected, got: {result:?}"
        );
    }

    // RFC 9449 Section 4.3 item 4: "The typ JOSE Header Parameter has the
    // value dpop+jwt." RFC 8725 Section 3.11 is the reason it matters — an
    // explicit typ is what stops another kind of signed JWT being replayed
    // here as a proof.
    #[test]
    fn test_parse_dpop_header_rejects_wrong_typ() {
        for typ in ["at+jwt", "JWT", "oauth-authz-req+jwt", ""] {
            let jwt = make_dpop_jwt_with_header(&serde_json::json!({
                "typ": typ,
                "alg": "ES256",
                "jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
                }
            }));

            let result = parse_dpop_header(&jwt);

            assert!(
                matches!(result, Err(DpopError::InvalidFormat(_))),
                "typ '{typ}' must be rejected, got: {result:?}"
            );
        }
    }

    #[test]
    fn test_parse_dpop_header_rejects_jwk_with_private_key_d() {
        // A DPoP proof whose JWK contains the EC private key field "d" must
        // be rejected per RFC 9449 Section 4.3.
        let header_json = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                "d": "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
            }
        });
        let jwt = make_dpop_jwt_with_header(&header_json);

        let result = parse_dpop_header(&jwt);

        assert!(
            matches!(result, Err(DpopError::InvalidFormat(_))),
            "JWK with private 'd' field must be rejected with InvalidFormat, got: {result:?}"
        );
        if let Err(DpopError::InvalidFormat(msg)) = result {
            assert!(
                msg.contains("private key"),
                "Error message should mention private key material, got: {msg}"
            );
        }
    }

    #[test]
    fn test_parse_dpop_header_rejects_rsa_jwk_with_private_fields() {
        // RSA private key components (p, q, dp, dq, qi) must also be rejected.
        let header_json = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "PS256",
            "jwk": {
                "kty": "RSA",
                "n": "somersakeymodulus",
                "e": "AQAB",
                "p": "private_p_value"
            }
        });
        let jwt = make_dpop_jwt_with_header(&header_json);

        let result = parse_dpop_header(&jwt);

        assert!(
            matches!(result, Err(DpopError::InvalidFormat(_))),
            "JWK with RSA private 'p' field must be rejected with InvalidFormat, got: {result:?}"
        );
    }

    // =========================================================================
    // CnfClaim serialization — RFC 8705 x5t#S256 rename
    // =========================================================================

    /// `x5t_s256` must serialize to the JSON key `"x5t#S256"` per RFC 8705 Section 3.1.
    /// The serde rename is critical — wrong key name breaks certificate binding.
    #[test]
    fn test_cnf_claim_x5t_s256_serialization() {
        let cnf = CnfClaim {
            jkt: None,
            x5t_s256: Some("thumbprint123".to_string()),
        };
        let json = serde_json::to_string(&cnf).unwrap();
        assert!(
            json.contains("\"x5t#S256\""),
            "must serialize to x5t#S256 key, got: {json}"
        );
        assert!(
            !json.contains("\"jkt\""),
            "None jkt must be omitted from JSON, got: {json}"
        );
        assert!(
            !json.contains("x5t_s256"),
            "raw field name must not appear in JSON, got: {json}"
        );
    }

    /// CnfClaim with both jkt and x5t_s256 serializes both fields correctly.
    #[test]
    fn test_cnf_claim_both_fields() {
        let cnf = CnfClaim {
            jkt: Some("jwk-thumbprint".to_string()),
            x5t_s256: Some("cert-thumbprint".to_string()),
        };
        let json = serde_json::to_string(&cnf).unwrap();
        assert!(
            json.contains("\"jkt\""),
            "jkt field must be present when Some, got: {json}"
        );
        assert!(
            json.contains("\"x5t#S256\""),
            "x5t#S256 field must be present when Some, got: {json}"
        );
        assert!(
            json.contains("\"jwk-thumbprint\""),
            "jkt value must be present, got: {json}"
        );
        assert!(
            json.contains("\"cert-thumbprint\""),
            "x5t_s256 value must be present, got: {json}"
        );
    }

    /// CnfClaim with only x5t_s256 (jkt is None) must not include jkt in output.
    #[test]
    fn test_cnf_claim_only_x5t() {
        let cnf = CnfClaim {
            jkt: None,
            x5t_s256: Some("only-cert-thumbprint".to_string()),
        };
        let value = serde_json::to_value(&cnf).unwrap();
        assert!(
            value.get("jkt").is_none(),
            "jkt must be absent when None, got: {value}"
        );
        assert_eq!(
            value.get("x5t#S256").and_then(|v| v.as_str()),
            Some("only-cert-thumbprint"),
            "x5t#S256 must contain thumbprint value"
        );
    }

    /// CnfClaim with all None fields produces an empty JSON object.
    #[test]
    fn test_cnf_claim_all_none_is_empty_object() {
        let cnf = CnfClaim {
            jkt: None,
            x5t_s256: None,
        };
        let json = serde_json::to_string(&cnf).unwrap();
        assert_eq!(
            json, "{}",
            "all-None CnfClaim must serialize to empty object"
        );
    }

    // RFC 7518 §3.6: "Implementations MUST NOT accept Unsecured JWSs by
    // default." A DPoP proof is presented by the client on every
    // sender-constrained request; an accepted `alg: none` proof would let any
    // holder of a stolen access token mint a matching proof.
    #[test]
    fn test_parse_dpop_header_rejects_alg_none() {
        let header_json = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "none",
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
            }
        });
        let jwt = make_dpop_jwt_with_header(&header_json);

        let result = parse_dpop_header(&jwt);

        assert!(
            matches!(result, Err(DpopError::UnsupportedAlgorithm(ref alg)) if alg == "none"),
            "alg=none must be rejected as an unsupported algorithm, got: {result:?}"
        );
    }

    // RFC 7518 §3.6: an Unsecured JWS "MUST use the empty octet sequence as
    // its JWS Signature value", and "Recipients MUST verify that the JWS
    // Signature value is the empty octet sequence". Vouch never reaches that
    // check: the proof is rejected on its algorithm whether the signature
    // segment is empty or forged.
    #[test]
    fn test_parse_dpop_header_rejects_unsecured_jws_with_empty_signature() {
        let header_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "typ": "dpop+jwt",
                "alg": "none",
                "jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
                }
            }))
            .unwrap(),
        );
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"{}");
        // Empty signature segment: the empty octet sequence.
        let unsecured = format!("{header_b64}.{payload_b64}.");

        let result = parse_dpop_header(&unsecured);

        assert!(
            matches!(result, Err(DpopError::UnsupportedAlgorithm(_))),
            "an Unsecured JWS with an empty signature must still be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_parse_dpop_header_accepts_public_ec_jwk() {
        // A public EC JWK (no 'd' field) in the header must be accepted.
        let header_json = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
            }
        });
        let jwt = make_dpop_jwt_with_header(&header_json);

        let result = parse_dpop_header(&jwt);

        // The header parses successfully — signature verification is not
        // attempted here since we call parse_dpop_header directly.
        assert!(
            result.is_ok(),
            "Public EC JWK without private key fields must be accepted, got: {result:?}"
        );
    }

    // =========================================================================
    // CnfClaim deserialization roundtrip — x5t#S256
    // =========================================================================

    /// Serialize then deserialize a CnfClaim with x5t_s256 and verify the
    /// JSON field name and value survive the roundtrip intact.
    #[test]
    fn test_cnf_claim_x5t_s256_deserialization_roundtrip() {
        let original = CnfClaim {
            jkt: None,
            x5t_s256: Some("abc123thumbprint-xxxxxxxxxxxxxxxxxxxxxxxxx".to_string()),
        };

        // Serialize
        let json = serde_json::to_string(&original).expect("serialization");

        // Verify the wire name is correct
        assert!(
            json.contains("\"x5t#S256\""),
            "must use x5t#S256 as JSON key, got: {json}"
        );

        // Deserialize back
        let restored: CnfClaim = serde_json::from_str(&json).expect("deserialization");

        assert_eq!(
            restored.x5t_s256.as_deref(),
            Some("abc123thumbprint-xxxxxxxxxxxxxxxxxxxxxxxxx"),
            "x5t_s256 value must survive roundtrip"
        );
        assert!(
            restored.jkt.is_none(),
            "jkt must remain None after roundtrip"
        );
    }

    /// Deserializing a JSON object with `x5t#S256` must populate `x5t_s256`.
    #[test]
    fn test_cnf_claim_x5t_s256_from_json() {
        let json = r#"{"x5t#S256":"my-cert-thumbprint"}"#;
        let cnf: CnfClaim = serde_json::from_str(json).expect("deserialize");
        assert_eq!(
            cnf.x5t_s256.as_deref(),
            Some("my-cert-thumbprint"),
            "x5t_s256 must be populated from x5t#S256 JSON key"
        );
        assert!(cnf.jkt.is_none(), "jkt must be None when absent from JSON");
    }
}
