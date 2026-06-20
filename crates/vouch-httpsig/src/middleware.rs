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
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::algorithm::VerifyingAlgorithm;
use crate::digest::verify_content_digest;
use crate::error::HttpSigError;
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
/// Every request must carry a `Signature-Input` header; an unsigned request is
/// rejected with 401. For a signed request this middleware:
/// 1. Extracts signature labels
/// 2. Resolves the verifying key via the `keyid` parameter
/// 3. Verifies the signature against the reconstructed base
/// 4. Enforces RFC 9530 `Content-Digest` integrity for request bodies
/// 5. Stores [`VerifiedSignature`] in request extensions
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
    // Trace-level logging of incoming request metadata
    tracing::trace!(
        method = %req.method(),
        path = %req.uri().path(),
        query = ?req.uri().query(),
        has_signature = req.headers().contains_key("signature-input"),
        "httpsig middleware"
    );

    // A missing Signature-Input header means the request is unsigned: reject.
    let sig_input = match req.headers().get("signature-input") {
        Some(v) => match v.to_str() {
            Ok(s) => s.to_string(),
            Err(e) => {
                tracing::debug!(error = %e, "invalid Signature-Input header encoding");
                return (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response();
            }
        },
        None => {
            tracing::debug!(
                path = %req.uri().path(),
                "rejecting unsigned request: signature required"
            );
            return (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response();
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
            // Reject signatures that don't cover minimum required components
            if let Err(e) = validate_coverage(&params, REQUIRED_COVERAGE) {
                tracing::debug!(
                    label = %label,
                    keyid = %keyid,
                    error = %e,
                    "HTTP signature insufficient coverage"
                );
                return (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response();
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
                return (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response();
            }
            parts.extensions.insert(VerifiedSignature {
                label: label.clone(),
                params,
            });
            let req = Request::from_parts(parts, axum::body::Body::from(bytes));
            let mut response = next.run(req).await;

            // Issue a fresh nonce for the client's next request
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
        Router::new()
            .route("/test", get(ok_handler).post(ok_handler))
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
            .uri("/test")
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
            .uri("http://example.com/test")
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
        parts.uri = "/test".parse().unwrap();
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
            .uri("http://example.com/test")
            .body(axum::body::Body::empty())
            .unwrap();

        SignatureBuilder::new("sig1")
            .method()
            .path()
            .created_now()
            .sign_request(&mut req, &signer)
            .unwrap();

        let (mut parts, body) = req.into_parts();
        parts.uri = "/test".parse().unwrap();
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
            .uri("http://example.com/test")
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
        parts.uri = "/test".parse().unwrap();
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
            .uri("http://example.com/test")
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
        parts.uri = "/test".parse().unwrap();
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
            .uri("http://example.com/test")
            .body(axum::body::Body::from(b"{\"hello\":\"world\"}".to_vec()))
            .unwrap();

        SignatureBuilder::new("sig1")
            .method()
            .path()
            .created_now()
            .sign_request(&mut req, &signer)
            .unwrap();

        let (mut parts, body) = req.into_parts();
        parts.uri = "/test".parse().unwrap();
        let req = Request::from_parts(parts, body);

        let response =
            <Router as tower::ServiceExt<Request<axum::body::Body>>>::oneshot(router, req)
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
