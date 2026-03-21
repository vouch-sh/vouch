// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Axum middleware for RFC 9421 HTTP Message Signature verification.
//!
//! Requires the `axum` feature flag.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use vouch_httpsig::middleware::{KeyResolver, verify_signature};
//!
//! let resolver: Arc<dyn KeyResolver> = /* your implementation */;
//!
//! Router::new()
//!     .route("/api/resource", get(handler))
//!     .layer(axum::middleware::from_fn_with_state(
//!         resolver,
//!         verify_signature,
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
use crate::signature_params::SignatureParams;
use crate::verify::{extract_signature_labels, verify_request_signature};

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

/// Key resolver trait for looking up verification keys by `keyid`.
///
/// Implementations should map the `keyid` parameter from the `Signature-Input`
/// header to the appropriate [`VerifyingAlgorithm`] for that key.
pub trait KeyResolver: Send + Sync {
    /// Look up a verifying key by its key ID.
    ///
    /// Returns `None` if the key is not recognized.
    fn resolve(&self, keyid: &str) -> Option<Arc<dyn VerifyingAlgorithm>>;
}

/// Default maximum signature age in seconds (5 minutes).
pub const DEFAULT_MAX_AGE: i64 = 300;

/// Axum middleware that verifies RFC 9421 HTTP signatures.
///
/// If a `Signature-Input` header is present, this middleware:
/// 1. Extracts signature labels
/// 2. Resolves the verifying key via the `keyid` parameter
/// 3. Verifies the signature against the reconstructed base
/// 4. Stores [`VerifiedSignature`] in request extensions
///
/// If no signature headers are present, the request passes through —
/// handlers must check for the `VerifiedSignature` extension if a signature
/// is required for their endpoint.
///
/// Returns 401 with a generic message if signature verification fails.
pub async fn verify_signature(
    State(resolver): State<Arc<dyn KeyResolver>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    verify_signature_with_max_age(resolver, req, next, DEFAULT_MAX_AGE).await
}

/// Axum middleware that verifies RFC 9421 HTTP signatures with a custom max age.
pub async fn verify_signature_with_max_age(
    resolver: Arc<dyn KeyResolver>,
    mut req: Request<axum::body::Body>,
    next: Next,
    max_age: i64,
) -> Response {
    if !req.headers().contains_key("signature-input") {
        return next.run(req).await;
    }

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

    let sig_input = match req.headers().get("signature-input") {
        Some(v) => match v.to_str() {
            Ok(s) => s.to_string(),
            Err(e) => {
                tracing::debug!(error = %e, "invalid Signature-Input header encoding");
                return (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response();
            }
        },
        None => return (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response(),
    };

    let Some(keyid) = extract_keyid_from_header(&sig_input, &label) else {
        tracing::debug!(label = %label, "missing keyid in Signature-Input");
        return (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response();
    };

    let Some(verifier) = resolver.resolve(&keyid) else {
        tracing::debug!(keyid = %keyid, "unknown key ID in HTTP signature");
        return (StatusCode::UNAUTHORIZED, SIG_VERIFY_FAILED).into_response();
    };

    match verify_request_signature(&req, &label, verifier.as_ref(), Some(max_age)) {
        Ok(params) => {
            tracing::debug!(
                label = %label,
                keyid = %keyid,
                alg = ?params.alg,
                "HTTP signature verified"
            );
            req.extensions_mut().insert(VerifiedSignature {
                label: label.clone(),
                params,
            });
            next.run(req).await
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
