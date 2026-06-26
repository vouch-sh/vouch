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
use crate::digest::verify_content_digest;
use crate::error::HttpSigError;
use crate::sig_policy::requires_signature;
use crate::signature_params::SignatureParams;
use crate::verify::{extract_signature_labels, validate_coverage, verify_request_signature};

/// Minimum components a signature must cover for the middleware to accept it.
///
/// Ensures signatures protect the request method and target, preventing
/// replay attacks where an attacker moves a signature to a different endpoint.
const REQUIRED_COVERAGE: &[&str] = &["@method", "@path"];

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
        alg: Some("ecdsa-p256-sha256".to_string()),
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
#[derive(Debug, Clone)]
pub struct VerifiedSignature {
    /// The label of the verified signature (e.g., `"sig1"`).
    pub label: String,
    /// The parsed and verified signature parameters.
    pub params: SignatureParams,
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
        Ok(params) => {
            // Reject signatures that don't cover minimum required components;
            // advertise the expected set so the client can fix and retry.
            if let Err(e) = validate_coverage(&params, REQUIRED_COVERAGE) {
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

            tracing::debug!(
                label = %label,
                keyid = %keyid,
                alg = ?params.alg,
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
            if let Err(e) = enforce_body_digest(&params, &parts.headers, &bytes) {
                tracing::debug!(
                    label = %label,
                    keyid = %keyid,
                    error = %e,
                    "signed request body integrity check failed"
                );
                let mut resp = (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response();
                // A coverage failure (signature verified but content-digest not
                // covered) gets the same Accept-Signature remediation hint as the
                // base-component coverage failure above.
                if matches!(e, HttpSigError::MissingDigest)
                    && let Some(accept_sig) = build_accept_signature(has_body)
                {
                    resp.headers_mut().insert("accept-signature", accept_sig);
                }
                return resp;
            }
            parts.extensions.insert(VerifiedSignature {
                label: label.clone(),
                params,
            });
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

/// Enforce RFC 9530 Content-Digest integrity for a signed request body.
///
/// A signed request that carries a non-empty body MUST cover `content-digest`
/// in its signature and present a matching `Content-Digest` header. Coverage is
/// required because an unsigned digest header could be swapped alongside the
/// body. Empty bodies (GET and bodyless POST requests) are exempt.
///
/// # Errors
///
/// Returns [`HttpSigError::MissingDigest`] when the body is not bound by a
/// covered, present `Content-Digest`, or [`HttpSigError::DigestMismatch`] when
/// the digest does not match the body.
fn enforce_body_digest(
    params: &SignatureParams,
    headers: &http::HeaderMap,
    body: &[u8],
) -> Result<(), HttpSigError> {
    if body.is_empty() {
        return Ok(());
    }

    validate_coverage(params, &["content-digest"]).map_err(|_| HttpSigError::MissingDigest)?;

    let header = headers
        .get("content-digest")
        .ok_or(HttpSigError::MissingDigest)?
        .to_str()
        .map_err(|e| HttpSigError::SfvParse(format!("Content-Digest: {e}")))?;

    verify_content_digest(header, body)
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
    }

    impl InMemoryKeyResolver {
        fn new() -> Self {
            Self {
                keys: std::collections::HashMap::new(),
            }
        }

        fn insert(&mut self, key_id: String, verifier: Arc<dyn VerifyingAlgorithm>) {
            self.keys.insert(key_id, verifier);
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

    fn params_covering(components: Vec<crate::ComponentIdentifier>) -> SignatureParams {
        SignatureParams {
            components,
            alg: None,
            keyid: None,
            created: None,
            expires: None,
            nonce: None,
            tag: None,
        }
    }

    fn digest_header(body: &[u8]) -> http::HeaderValue {
        crate::digest::content_digest(body, crate::digest::DigestAlgorithm::Sha256)
            .parse()
            .unwrap()
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

    #[test]
    fn test_enforce_body_digest_empty_body_is_exempt() {
        let params = params_covering(vec![]);
        let headers = http::HeaderMap::new();
        enforce_body_digest(&params, &headers, b"").unwrap();
    }

    #[test]
    fn test_enforce_body_digest_valid() {
        let body = b"{\"x\":1}";
        let params = params_covering(vec![
            crate::ComponentIdentifier::method(),
            crate::ComponentIdentifier::field("content-digest"),
        ]);
        let mut headers = http::HeaderMap::new();
        headers.insert("content-digest", digest_header(body));
        enforce_body_digest(&params, &headers, body).unwrap();
    }

    #[test]
    fn test_enforce_body_digest_missing_header() {
        let body = b"body";
        let params = params_covering(vec![crate::ComponentIdentifier::field("content-digest")]);
        let headers = http::HeaderMap::new();
        assert!(matches!(
            enforce_body_digest(&params, &headers, body),
            Err(HttpSigError::MissingDigest)
        ));
    }

    #[test]
    fn test_enforce_body_digest_not_covered() {
        let body = b"body";
        let params = params_covering(vec![crate::ComponentIdentifier::method()]);
        let mut headers = http::HeaderMap::new();
        headers.insert("content-digest", digest_header(body));
        assert!(matches!(
            enforce_body_digest(&params, &headers, body),
            Err(HttpSigError::MissingDigest)
        ));
    }

    #[test]
    fn test_enforce_body_digest_mismatch() {
        let params = params_covering(vec![crate::ComponentIdentifier::field("content-digest")]);
        let mut headers = http::HeaderMap::new();
        headers.insert("content-digest", digest_header(b"other body"));
        assert!(matches!(
            enforce_body_digest(&params, &headers, b"body"),
            Err(HttpSigError::DigestMismatch(_))
        ));
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
}
