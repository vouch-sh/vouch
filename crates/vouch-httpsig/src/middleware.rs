// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Axum middleware for RFC 9421 HTTP Message Signature verification.
//!
//! Requires the `axum` feature flag.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use vouch_httpsig::middleware::{KeyResolver, require_signature};
//!
//! struct MyResolver { /* ... */ }
//!
//! impl KeyResolver for MyResolver {
//!     async fn resolve(&self, keyid: &str) -> Option<Arc<dyn VerifyingAlgorithm>> {
//!         // look up key by ID (can be async, e.g. DB query)
//!         todo!()
//!     }
//! }
//!
//! let resolver = Arc::new(MyResolver { /* ... */ });
//!
//! Router::new()
//!     .route("/api/resource", get(handler))
//!     .layer(axum::middleware::from_fn_with_state(
//!         resolver,
//!         require_signature::<MyResolver>,
//!     ))
//! ```

use std::sync::Arc;

use axum::{
    extract::{MatchedPath, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::algorithm::VerifyingAlgorithm;
use crate::component::ComponentIdentifier;
use crate::error::HttpSigError;
use crate::sig_policy::requires_signature;
use crate::signature_params::SignatureParams;
use crate::verify::{DigestEnforced, extract_signature_labels, verify_request_signature};
use std::sync::LazyLock;

/// Minimum components a signature must cover for the middleware to accept it.
///
/// Ensures signatures protect the request method and target, preventing
/// replay attacks where an attacker moves a signature to a different endpoint.
static REQUIRED_COVERAGE: LazyLock<[ComponentIdentifier; 2]> =
    LazyLock::new(|| [ComponentIdentifier::method(), ComponentIdentifier::path()]);

/// Maximum signed request body buffered for Content-Digest verification.
///
/// Signed `/v1/*` payloads are small JSON documents; 1 MiB is a generous cap
/// that bounds memory use while never rejecting a legitimate request.
const MAX_SIGNED_BODY: usize = 1024 * 1024;

/// Generic error response to avoid leaking verification details to attackers.
const SIG_VERIFY_FAILED: &str = "signature verification failed";

/// The signature label used in `Accept-Signature` advertisements.
const ACCEPT_SIG_LABEL: &str = "sig1";

/// Build an RFC 9421 §5.1 `Accept-Signature` header value for a rejected request.
///
/// The value is a label-keyed SFV Dictionary:
/// `sig1=("@method" "@authority" "@path" "@query" "authorization");alg="ecdsa-p256-sha256"`
///
/// This is an **advisory superset** of [`REQUIRED_COVERAGE`] — it advertises the
/// full set of components the vouch CLI signs, so a conformant third-party client
/// that follows this guidance will produce a signature that satisfies all server
/// checks (including body integrity).  Advertising more than the strict minimum is
/// intentional: the set here matches what the CLI signs, not what verification
/// strictly requires.
///
/// `content-digest` is added only when the rejected request carried a non-empty
/// body (`!body.is_empty()`), matching the `enforce_body_digest` exemption.
///
/// Returns `None` when `HeaderValue::from_str` fails (should never occur for
/// well-formed ASCII, but the deny-lint forbids unwrap).
fn build_accept_signature(has_body: bool) -> Option<http::HeaderValue> {
    let mut components = vec![
        ComponentIdentifier::method(),
        ComponentIdentifier::authority(),
        ComponentIdentifier::path(),
        ComponentIdentifier::query(),
        ComponentIdentifier::field("authorization"),
    ];
    if has_body {
        components.push(ComponentIdentifier::field("content-digest"));
    }

    // Components-only params: no created/keyid so serialize() emits no trailing `;`.
    let params = SignatureParams {
        components,
        alg: Some(
            crate::algorithm::SignatureAlgorithm::EcdsaP256Sha256
                .as_str()
                .to_string(),
        ),
        keyid: None,
        created: None,
        expires: None,
        nonce: None,
        tag: None,
    };

    // RFC 9421 §5.1: Accept-Signature is an SFV Dictionary, not a bare inner list.
    // Prefix "sig1=" to form a valid Dictionary member.
    let value = format!("{ACCEPT_SIG_LABEL}={}", params.serialize());
    http::HeaderValue::from_str(&value).ok()
}

/// Verified HTTP signature data stored as a request extension.
///
/// Handlers can retrieve this via `req.extensions().get::<VerifiedSignature>()`.
///
/// Constructing one requires a [`DigestEnforced`] proof, which is only
/// reachable by moving through signature verification, coverage checking, and
/// body-digest enforcement in that order. A handler that reads this extension
/// therefore knows every step ran — the guarantee comes from the type, not
/// from statement order in the middleware.
#[derive(Debug, Clone)]
pub struct VerifiedSignature {
    /// The label of the verified signature (e.g., `"sig1"`).
    pub label: String,
    /// The parsed and fully checked signature parameters.
    params: SignatureParams,
}

impl VerifiedSignature {
    /// Build from a completed verification chain.
    #[must_use]
    pub fn new(label: String, proof: DigestEnforced) -> Self {
        Self {
            label,
            params: proof.into_params(),
        }
    }

    /// The verified signature parameters.
    #[must_use]
    pub fn params(&self) -> &SignatureParams {
        &self.params
    }
}

/// Async key resolver trait for looking up verification keys by `keyid`.
///
/// Implementations should map the `keyid` parameter from the `Signature-Input`
/// header to the appropriate [`VerifyingAlgorithm`] for that key.
///
/// The resolver is async to support key lookups that require I/O
/// (e.g., database queries, remote key stores).
///
/// Request headers are provided for resolvers that need additional context
/// (e.g., extracting `client_id` from an `Authorization` header to narrow
/// the key lookup scope).
pub trait KeyResolver: Send + Sync + 'static {
    /// Look up a verifying key by its key ID.
    ///
    /// `headers` are the request headers, available for resolvers that need
    /// request context (e.g., to identify the client from an auth token).
    /// Simple resolvers can ignore this parameter.
    ///
    /// Returns `None` if the key is not recognized.
    fn resolve(
        &self,
        keyid: &str,
        headers: &http::HeaderMap,
    ) -> impl std::future::Future<Output = Option<Arc<dyn VerifyingAlgorithm>>> + Send + '_;

    /// Generate a nonce to include in the response `Signature-Nonce` header.
    ///
    /// The client should include this nonce in the next request's signature
    /// via the `nonce` parameter for replay protection.
    ///
    /// Returns `None` by default (no nonce issued). Override to enable
    /// server-issued nonce support.
    fn generate_nonce(&self) -> impl std::future::Future<Output = Option<String>> + Send + '_ {
        async { None }
    }

    /// Validate (and atomically consume) a client-supplied signature nonce.
    ///
    /// Called only when a verified signature carries a `nonce` parameter —
    /// nonce enforcement is opportunistic (enforce-when-present): a client's
    /// first request has no nonce yet, so requests without one pass through
    /// and rely on the timestamp window alone. Validation runs after
    /// signature, coverage, and body-digest checks so only a fully valid
    /// request (or a byte-perfect replay of one) can consume a nonce —
    /// first presentation wins, the replay is rejected.
    ///
    /// The default accepts without checking, for resolvers that do not
    /// issue nonces (their clients never send the parameter).
    fn validate_nonce(
        &self,
        _nonce: &str,
    ) -> impl std::future::Future<Output = NonceValidation> + Send + '_ {
        async { NonceValidation::Valid }
    }
}

/// Outcome of validating a client-supplied signature nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceValidation {
    /// Nonce accepted (or the resolver does not enforce nonces).
    Valid,
    /// Nonce unknown, expired, or already consumed — the request is
    /// rejected; the response carries a fresh `Signature-Nonce` so the
    /// client can recover on its next request.
    Invalid,
    /// Backend failure while checking — server fault (5xx), never
    /// reported as a client authentication failure.
    Error,
}

/// Default maximum signature age in seconds (5 minutes).
pub const DEFAULT_MAX_AGE: i64 = 300;

/// Axum middleware that requires a valid RFC 9421 HTTP signature.
///
/// Reads [`MatchedPath`] to determine whether the route requires a signature
/// (via [`requires_signature`]).  Public `/v1` routes (e.g. `/v1/auth/status`,
/// `/v1/credentials/ssh/ca`) pass through immediately.  All other `/v1` routes
/// are default-deny.
///
/// When `MatchedPath` is absent (no route matched, or `nest_service`), the
/// middleware falls back to `req.uri().path()` and then applies `requires_signature`
/// — so the worst case is over-enforcement (default-deny), never silently disabled
/// enforcement.
///
/// For requests that do require a signature this middleware:
/// 1. Extracts signature labels from `Signature-Input`
/// 2. Resolves the verifying key via the `keyid` parameter
/// 3. Verifies the signature against the reconstructed base
/// 4. Enforces RFC 9530 `Content-Digest` integrity for request bodies
/// 5. Stores [`VerifiedSignature`] in request extensions
/// 6. Emits `Accept-Signature` (RFC 9421 §5.1) on unsigned / under-covered 401s
///    so clients know exactly what to sign next time
///
/// Validate and consume a verified signature's nonce, if it carries one.
///
/// Returns `Some(response)` when the request must be rejected (unknown or
/// already-consumed nonce → 401 with a fresh `Signature-Nonce`; backend
/// failure → 500), or `None` when there is no nonce or it was accepted.
async fn enforce_nonce<R: KeyResolver>(
    resolver: &R,
    proof: &DigestEnforced,
    label: &str,
    keyid: &str,
) -> Option<Response> {
    let nonce = proof.params().nonce.as_deref()?;
    match resolver.validate_nonce(nonce).await {
        NonceValidation::Valid => None,
        NonceValidation::Invalid => {
            tracing::debug!(
                label = %label,
                keyid = %keyid,
                "HTTP signature nonce invalid or already consumed"
            );
            let mut resp = (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response();
            // Recovery hint: a stale or consumed nonce is fixed by signing the
            // next request with a fresh one (mirrors DPoP's use_dpop_nonce
            // flow). No Accept-Signature — this is not a coverage problem.
            if let Some(fresh) = resolver.generate_nonce().await
                && let Ok(value) = http::HeaderValue::from_str(&fresh)
            {
                resp.headers_mut().insert("signature-nonce", value);
            }
            Some(resp)
        }
        NonceValidation::Error => {
            tracing::error!(
                label = %label,
                keyid = %keyid,
                "HTTP signature nonce validation backend failure"
            );
            Some((StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response())
        }
    }
}

/// Used on endpoints where every request must be signed, e.g. the `/v1/*`
/// CLI↔server channel under FAPI 2.0 Message Signing. Returns 401 with a
/// generic message on any verification failure.
pub async fn require_signature<R: KeyResolver>(
    State(resolver): State<Arc<R>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let max_age = DEFAULT_MAX_AGE;

    // Determine the effective path for policy evaluation.
    // Prefer MatchedPath (the route template, e.g. "/v1/keys/{id}") because it is
    // the same form used in PUBLIC_V1_PATHS.  When absent (fallback/nest_service),
    // use the concrete URI path — this funnels into default-deny, never passthrough.
    let effective_path = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| req.uri().path().to_string(), |p| p.as_str().to_string());

    // Bypass for routes that do not require a signature (out of scope or explicitly
    // public).  This makes the constant in sig_policy.rs the runtime source of truth.
    if !requires_signature(&effective_path) {
        return next.run(req).await;
    }

    // Trace-level logging of incoming request metadata
    tracing::trace!(
        method = %req.method(),
        path = %req.uri().path(),
        query = ?req.uri().query(),
        has_signature = req.headers().contains_key("signature-input"),
        "httpsig middleware"
    );

    // Whether the incoming request carried a body influences Accept-Signature.
    // POST/PUT/PATCH are conventionally body-bearing; also probe Content-Length /
    // Transfer-Encoding so HTTP/2 clients that omit Content-Length receive an
    // accurate Accept-Signature hint and avoid the advertise<enforce inversion.
    // Over-advertising content-digest for an empty POST is harmless because
    // enforce_body_digest short-circuits on empty bodies.
    let has_body = matches!(
        req.method(),
        &http::Method::POST | &http::Method::PUT | &http::Method::PATCH
    ) || req
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|len| len > 0)
        || req.headers().contains_key(http::header::TRANSFER_ENCODING);

    // A missing Signature-Input header means the request is unsigned: reject
    // and advertise what the server expects (RFC 9421 §5.1).
    let sig_input = match req.headers().get("signature-input") {
        Some(v) => match v.to_str() {
            Ok(s) => s.to_string(),
            Err(e) => {
                // Non-UTF-8 Signature-Input is equivalent to absent; same remedy.
                tracing::debug!(error = %e, "invalid Signature-Input header encoding");
                let mut resp = (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response();
                if let Some(accept_sig) = build_accept_signature(has_body) {
                    resp.headers_mut().insert("accept-signature", accept_sig);
                }
                return resp;
            }
        },
        None => {
            tracing::debug!(
                path = %req.uri().path(),
                "rejecting unsigned request: signature required"
            );
            let mut resp = (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response();
            if let Some(accept_sig) = build_accept_signature(has_body) {
                resp.headers_mut().insert("accept-signature", accept_sig);
            }
            return resp;
        }
    };

    let labels = match extract_signature_labels(req.headers()) {
        Ok(labels) => labels,
        Err(e) => {
            tracing::debug!(error = %e, "failed to extract signature labels");
            return (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response();
        }
    };

    // Verify the first label. RFC 9421 allows multiple signatures;
    // if multi-signature support is needed, iterate all labels.
    let Some(label) = labels.into_iter().next() else {
        tracing::debug!("no signature labels found");
        return (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response();
    };

    let Some(keyid) = extract_keyid_from_header(&sig_input, &label) else {
        tracing::debug!(label = %label, "missing keyid in Signature-Input");
        return (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response();
    };

    let Some(verifier) = resolver.resolve(&keyid, req.headers()).await else {
        tracing::debug!(keyid = %keyid, "unknown key ID in HTTP signature");
        return (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response();
    };

    match verify_request_signature(&req, &label, verifier.as_ref(), Some(max_age)) {
        Ok(verified) => {
            // Reject signatures that don't cover minimum required components;
            // advertise the expected set so the client can fix and retry.
            let covered = match verified.require_coverage(&*REQUIRED_COVERAGE) {
                Ok(covered) => covered,
                Err(e) => {
                    tracing::debug!(
                        label = %label,
                        keyid = %keyid,
                        error = %e,
                        "HTTP signature insufficient coverage"
                    );
                    let mut resp = (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response();
                    if let Some(accept_sig) = build_accept_signature(has_body) {
                        resp.headers_mut().insert("accept-signature", accept_sig);
                    }
                    return resp;
                }
            };

            tracing::debug!(
                label = %label,
                keyid = %keyid,
                alg = ?covered.params().alg,
                "HTTP signature verified"
            );
            // Enforce RFC 9530 body integrity for signed requests that carry a
            // body, then rebuild the request for the downstream handler.
            let (mut parts, body) = req.into_parts();
            let bytes = match axum::body::to_bytes(body, MAX_SIGNED_BODY).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::debug!(error = %e, "failed to buffer signed request body");
                    return (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response();
                }
            };
            let enforced = match covered.enforce_body_digest(&parts.headers, &bytes) {
                Ok(enforced) => enforced,
                Err(e) => {
                    tracing::debug!(
                        label = %label,
                        keyid = %keyid,
                        error = %e,
                        "signed request body integrity check failed"
                    );
                    let mut resp = (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response();
                    // A coverage failure (signature verified but content-digest
                    // not covered) gets the same Accept-Signature remediation
                    // hint as the base-component coverage failure above.
                    if matches!(e, HttpSigError::MissingDigest)
                        && let Some(accept_sig) = build_accept_signature(has_body)
                    {
                        resp.headers_mut().insert("accept-signature", accept_sig);
                    }
                    return resp;
                }
            };
            // Validate and consume the server-issued nonce when the signature
            // carries one (enforce-when-present; see KeyResolver::validate_nonce).
            // Taking `&DigestEnforced` is what keeps this after the digest check:
            // the proof cannot exist until the full chain has run.
            if let Some(resp) = enforce_nonce(resolver.as_ref(), &enforced, &label, &keyid).await {
                return resp;
            }
            parts
                .extensions
                .insert(VerifiedSignature::new(label.clone(), enforced));
            let req = Request::from_parts(parts, axum::body::Body::from(bytes));
            let mut response = next.run(req).await;

            // Issue a fresh nonce for the client's next request.
            // Accept-Signature is NOT emitted on success — it is a remediation
            // hint only, and emitting it on success leaks which keyid/path combos
            // are valid.
            if let Some(nonce) = resolver.generate_nonce().await
                && let Ok(value) = http::HeaderValue::from_str(&nonce)
            {
                response.headers_mut().insert("signature-nonce", value);
            }

            response
        }
        Err(e) => {
            tracing::debug!(
                label = %label,
                keyid = %keyid,
                error = %e,
                "HTTP signature verification failed"
            );
            // Bad-keyid / tampered / expired: no Accept-Signature to avoid
            // leaking which keyids are valid.
            (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response()
        }
    }
}

/// Extract the `keyid` parameter from a Signature-Input header value for a given label.
fn extract_keyid_from_header(header_value: &str, label: &str) -> Option<String> {
    let dict = crate::sfv::parse::parse_dictionary(header_value).ok()?;
    let member = dict.get(label)?;
    match member {
        crate::sfv::types::SfvDictMember::InnerList(list) => {
            let params = crate::SignatureParams::from_inner_list(list).ok()?;
            params.keyid
        }
        _ => None,
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::algorithm::ecdsa_p256::EcdsaP256Signer;
    use crate::sign::SignatureBuilder;
    use axum::{Router, routing::get};

    /// In-memory key resolver for testing.
    struct InMemoryKeyResolver {
        keys: std::collections::HashMap<String, Arc<dyn VerifyingAlgorithm>>,
        /// When `Some`, the resolver enforces nonces: a validated nonce is
        /// removed from the set (single-use), and `generate_nonce` mints a
        /// fresh entry.
        nonces: Option<std::sync::Mutex<std::collections::HashSet<String>>>,
        /// Force `validate_nonce` to report a backend error.
        nonce_backend_error: bool,
    }

    impl InMemoryKeyResolver {
        fn new() -> Self {
            Self {
                keys: std::collections::HashMap::new(),
                nonces: None,
                nonce_backend_error: false,
            }
        }

        fn insert(&mut self, key_id: String, verifier: Arc<dyn VerifyingAlgorithm>) {
            self.keys.insert(key_id, verifier);
        }

        /// Enable nonce enforcement and pre-seed a set of issuable nonces.
        fn with_nonces(mut self, seed: &[&str]) -> Self {
            self.nonces = Some(std::sync::Mutex::new(
                seed.iter().map(|s| (*s).to_string()).collect(),
            ));
            self
        }
    }

    impl KeyResolver for InMemoryKeyResolver {
        fn resolve(
            &self,
            keyid: &str,
            _headers: &http::HeaderMap,
        ) -> impl std::future::Future<Output = Option<Arc<dyn VerifyingAlgorithm>>> + Send + '_
        {
            let result = self.keys.get(keyid).cloned();
            async move { result }
        }

        fn generate_nonce(&self) -> impl std::future::Future<Output = Option<String>> + Send + '_ {
            let issued = self.nonces.as_ref().map(|set| {
                let nonce = format!("nonce-{}", set.lock().map_or(0, |s| s.len()));
                if let Ok(mut s) = set.lock() {
                    s.insert(nonce.clone());
                }
                nonce
            });
            async move { issued }
        }

        fn validate_nonce(
            &self,
            nonce: &str,
        ) -> impl std::future::Future<Output = NonceValidation> + Send + '_ {
            let outcome = if self.nonce_backend_error {
                NonceValidation::Error
            } else {
                match &self.nonces {
                    // No enforcement: accept unconditionally (default behavior).
                    None => NonceValidation::Valid,
                    Some(set) => {
                        let consumed = set.lock().is_ok_and(|mut s| s.remove(nonce));
                        if consumed {
                            NonceValidation::Valid
                        } else {
                            NonceValidation::Invalid
                        }
                    }
                }
            };
            async move { outcome }
        }
    }

    async fn ok_handler() -> &'static str {
        "ok"
    }

    fn build_test_router(resolver: Arc<InMemoryKeyResolver>) -> Router {
        // Route must be under /v1/ so requires_signature returns true and the
        // middleware actually enforces signatures.  /test would be out of scope
        // and silently bypass all enforcement after the policy bypass was added.
        Router::new()
            .route("/v1/test", get(ok_handler).post(ok_handler))
            .layer(axum::middleware::from_fn_with_state(
                resolver,
                require_signature::<InMemoryKeyResolver>,
            ))
    }

    #[tokio::test]
    async fn test_rejects_unsigned_request() {
        // require_signature must reject a request that carries no
        // Signature-Input header.
        let resolver = Arc::new(InMemoryKeyResolver::new());
        let router = build_test_router(resolver);

        let req = Request::builder()
            .uri("/v1/test")
            .body(axum::body::Body::empty())
            .unwrap();

        let response =
            <Router as tower::ServiceExt<Request<axum::body::Body>>>::oneshot(router, req)
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_rejects_unknown_keyid() {
        let resolver = Arc::new(InMemoryKeyResolver::new());
        let router = build_test_router(resolver);

        // Build a signed request with a key the resolver doesn't know
        let signer = EcdsaP256Signer::generate("unknown-key").unwrap();
        let mut req = Request::builder()
            .method("GET")
            .uri("http://example.com/v1/test")
            .body(axum::body::Body::empty())
            .unwrap();

        SignatureBuilder::new("sig1")
            .method()
            .path()
            .created_now()
            .sign_request(&mut req, &signer)
            .unwrap();

        // Rewrite the URI to just the path (axum expects path-only)
        let (mut parts, body) = req.into_parts();
        parts.uri = "/v1/test".parse().unwrap();
        let req = Request::from_parts(parts, body);

        let response =
            <Router as tower::ServiceExt<Request<axum::body::Body>>>::oneshot(router, req)
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_verifies_valid_signature() {
        let signer = EcdsaP256Signer::generate("test-key").unwrap();
        let verifier = signer.verifier();

        let mut resolver = InMemoryKeyResolver::new();
        resolver.insert("test-key".to_string(), Arc::new(verifier));
        let resolver = Arc::new(resolver);

        let router = build_test_router(resolver);

        let mut req = Request::builder()
            .method("GET")
            .uri("http://example.com/v1/test")
            .body(axum::body::Body::empty())
            .unwrap();

        SignatureBuilder::new("sig1")
            .method()
            .path()
            .created_now()
            .sign_request(&mut req, &signer)
            .unwrap();

        let (mut parts, body) = req.into_parts();
        parts.uri = "/v1/test".parse().unwrap();
        let req = Request::from_parts(parts, body);

        let response =
            <Router as tower::ServiceExt<Request<axum::body::Body>>>::oneshot(router, req)
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_rejects_tampered_signature() {
        let signer = EcdsaP256Signer::generate("test-key").unwrap();
        let verifier = signer.verifier();

        let mut resolver = InMemoryKeyResolver::new();
        resolver.insert("test-key".to_string(), Arc::new(verifier));
        let resolver = Arc::new(resolver);

        let router = build_test_router(resolver);

        let mut req = Request::builder()
            .method("GET")
            .uri("http://example.com/v1/test")
            .body(axum::body::Body::empty())
            .unwrap();

        SignatureBuilder::new("sig1")
            .method()
            .path()
            .created_now()
            .sign_request(&mut req, &signer)
            .unwrap();

        // Tamper with the Signature header
        let (mut parts, body) = req.into_parts();
        parts.uri = "/v1/test".parse().unwrap();
        parts
            .headers
            .insert("signature", "sig1=:dGFtcGVyZWQ=:".parse().unwrap());
        let req = Request::from_parts(parts, body);

        let response =
            <Router as tower::ServiceExt<Request<axum::body::Body>>>::oneshot(router, req)
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_signed_post_with_valid_digest_succeeds() {
        let signer = EcdsaP256Signer::generate("test-key").unwrap();
        let mut resolver = InMemoryKeyResolver::new();
        resolver.insert("test-key".to_string(), Arc::new(signer.verifier()));
        let router = build_test_router(Arc::new(resolver));

        let body = b"{\"hello\":\"world\"}".to_vec();
        let mut req = Request::builder()
            .method("POST")
            .uri("http://example.com/v1/test")
            .body(axum::body::Body::from(body.clone()))
            .unwrap();
        crate::digest::set_content_digest(
            req.headers_mut(),
            &body,
            crate::digest::DigestAlgorithm::Sha256,
        )
        .unwrap();

        SignatureBuilder::new("sig1")
            .method()
            .path()
            .field("content-digest")
            .created_now()
            .sign_request(&mut req, &signer)
            .unwrap();

        let (mut parts, body) = req.into_parts();
        parts.uri = "/v1/test".parse().unwrap();
        let req = Request::from_parts(parts, body);

        let response =
            <Router as tower::ServiceExt<Request<axum::body::Body>>>::oneshot(router, req)
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_signed_post_without_digest_is_rejected() {
        let signer = EcdsaP256Signer::generate("test-key").unwrap();
        let mut resolver = InMemoryKeyResolver::new();
        resolver.insert("test-key".to_string(), Arc::new(signer.verifier()));
        let router = build_test_router(Arc::new(resolver));

        // A signed POST whose signature does not cover the body via Content-Digest.
        let mut req = Request::builder()
            .method("POST")
            .uri("http://example.com/v1/test")
            .body(axum::body::Body::from(b"{\"hello\":\"world\"}".to_vec()))
            .unwrap();

        SignatureBuilder::new("sig1")
            .method()
            .path()
            .created_now()
            .sign_request(&mut req, &signer)
            .unwrap();

        let (mut parts, body) = req.into_parts();
        parts.uri = "/v1/test".parse().unwrap();
        let req = Request::from_parts(parts, body);

        let response =
            <Router as tower::ServiceExt<Request<axum::body::Body>>>::oneshot(router, req)
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        // A verified-but-under-covered signature (missing content-digest) must
        // still carry the Accept-Signature remediation hint, like base-component
        // coverage failures (#571).
        let accept_sig = response.headers().get("accept-signature").unwrap();
        assert!(
            accept_sig.to_str().unwrap().contains("content-digest"),
            "Accept-Signature for a body request must advertise content-digest, got {accept_sig:?}"
        );
    }

    #[tokio::test]
    async fn test_signed_post_with_tampered_body_omits_accept_signature() {
        // A signature that DOES cover content-digest, but whose body was altered
        // after signing, fails with DigestMismatch (not MissingDigest). That is a
        // tamper/corruption, not a coverage gap: the client already signed the
        // right components, so no Accept-Signature remediation hint applies (#571).
        let signer = EcdsaP256Signer::generate("test-key").unwrap();
        let mut resolver = InMemoryKeyResolver::new();
        resolver.insert("test-key".to_string(), Arc::new(signer.verifier()));
        let router = build_test_router(Arc::new(resolver));

        let original = b"{\"hello\":\"world\"}".to_vec();
        let mut req = Request::builder()
            .method("POST")
            .uri("http://example.com/v1/test")
            .body(axum::body::Body::from(original.clone()))
            .unwrap();
        // Digest + signature both bind the ORIGINAL body.
        crate::digest::set_content_digest(
            req.headers_mut(),
            &original,
            crate::digest::DigestAlgorithm::Sha256,
        )
        .unwrap();
        SignatureBuilder::new("sig1")
            .method()
            .path()
            .field("content-digest")
            .created_now()
            .sign_request(&mut req, &signer)
            .unwrap();

        // Swap in a different body while keeping the original digest header and
        // signature: the signature still verifies (it covers the unchanged header
        // value), but the body no longer matches the digest -> DigestMismatch.
        let (mut parts, _original_body) = req.into_parts();
        parts.uri = "/v1/test".parse().unwrap();
        let req = Request::from_parts(
            parts,
            axum::body::Body::from(b"{\"hello\":\"evil\"}".to_vec()),
        );

        let response =
            <Router as tower::ServiceExt<Request<axum::body::Body>>>::oneshot(router, req)
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            response.headers().get("accept-signature").is_none(),
            "DigestMismatch (tampered body) must NOT advertise Accept-Signature"
        );
    }

    /// Build a signed GET request against `/v1/test`, optionally with a nonce.
    fn signed_get(signer: &EcdsaP256Signer, nonce: Option<&str>) -> Request<axum::body::Body> {
        let mut req = Request::builder()
            .method("GET")
            .uri("http://example.com/v1/test")
            .body(axum::body::Body::empty())
            .unwrap();

        let mut builder = SignatureBuilder::new("sig1").method().path().created_now();
        if let Some(n) = nonce {
            builder = builder.nonce(n);
        }
        builder.sign_request(&mut req, signer).unwrap();

        let (mut parts, body) = req.into_parts();
        parts.uri = "/v1/test".parse().unwrap();
        Request::from_parts(parts, body)
    }

    fn resolver_with_key_and_nonces(
        signer: &EcdsaP256Signer,
        seed: &[&str],
    ) -> Arc<InMemoryKeyResolver> {
        let mut resolver = InMemoryKeyResolver::new().with_nonces(seed);
        resolver.insert("test-key".to_string(), Arc::new(signer.verifier()));
        Arc::new(resolver)
    }

    /// Enforce-when-present: a nonce-enforcing resolver still accepts a
    /// signed request that carries no nonce (the client's first request).
    #[tokio::test]
    async fn test_nonce_absent_is_accepted() {
        let signer = EcdsaP256Signer::generate("test-key").unwrap();
        let resolver = resolver_with_key_and_nonces(&signer, &[]);
        let router = build_test_router(resolver);

        let response = <Router as tower::ServiceExt<Request<axum::body::Body>>>::oneshot(
            router,
            signed_get(&signer, None),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// A known nonce is accepted once, then a byte-identical replay is
    /// rejected (single-use), and the rejection carries a fresh nonce.
    #[tokio::test]
    async fn test_nonce_valid_then_replay_rejected() {
        let signer = EcdsaP256Signer::generate("test-key").unwrap();
        let resolver = resolver_with_key_and_nonces(&signer, &["known-nonce"]);
        let router = build_test_router(resolver);

        let req = signed_get(&signer, Some("known-nonce"));
        // Capture the signed headers so the replay is byte-identical.
        let (parts, _) = req.into_parts();
        let replay = Request::from_parts(parts.clone(), axum::body::Body::empty());
        let first = Request::from_parts(parts, axum::body::Body::empty());

        let response = <Router as tower::ServiceExt<Request<axum::body::Body>>>::oneshot(
            router.clone(),
            first,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response =
            <Router as tower::ServiceExt<Request<axum::body::Body>>>::oneshot(router, replay)
                .await
                .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "replaying a consumed nonce must be rejected"
        );
        assert!(
            response.headers().get("signature-nonce").is_some(),
            "a rejected nonce must offer a fresh one for recovery"
        );
    }

    /// A nonce the server never issued is rejected.
    #[tokio::test]
    async fn test_nonce_unknown_rejected() {
        let signer = EcdsaP256Signer::generate("test-key").unwrap();
        let resolver = resolver_with_key_and_nonces(&signer, &["known-nonce"]);
        let router = build_test_router(resolver);

        let response = <Router as tower::ServiceExt<Request<axum::body::Body>>>::oneshot(
            router,
            signed_get(&signer, Some("never-issued")),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// A backend failure while checking a nonce is a 500, never a 401.
    #[tokio::test]
    async fn test_nonce_backend_error_is_500() {
        let signer = EcdsaP256Signer::generate("test-key").unwrap();
        let mut resolver = InMemoryKeyResolver::new().with_nonces(&["known-nonce"]);
        resolver.nonce_backend_error = true;
        resolver.insert("test-key".to_string(), Arc::new(signer.verifier()));
        let router = build_test_router(Arc::new(resolver));

        let response = <Router as tower::ServiceExt<Request<axum::body::Body>>>::oneshot(
            router,
            signed_get(&signer, Some("known-nonce")),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
