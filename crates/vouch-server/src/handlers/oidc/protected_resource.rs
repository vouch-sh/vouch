// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OAuth 2.0 Protected Resource Metadata endpoint (RFC 9728).
//!
//! Serves the metadata document at:
//!
//! * `/.well-known/oauth-protected-resource` (root) — metadata for
//!   the Vouch deployment as a whole; `resource == base_url`.
//! * `/.well-known/oauth-protected-resource/{*path}` (per-resource) —
//!   metadata for a specific protected endpoint; `resource == base_url + "/" + path`.
//!
//! RFC 9728 §4 requires the `resource` value in the body to be
//! byte-identical to the resource identifier the client used. The
//! service layer enforces this by re-using the caller's raw sub-path
//! against an allowlist; unknown sub-paths return 404.

use crate::AppState;
use crate::services::ServiceError;
use crate::services::oidc::protected_resource as svc;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;

/// `Cache-Control` header applied to metadata responses.
///
/// Matches the value used by the AS discovery endpoint
/// ([`super::discovery`]); 1 hour balances client freshness against
/// load on the metadata endpoint, which changes only during key
/// rotation or configuration reload.
const RFC9728_CACHE_CONTROL: (axum::http::header::HeaderName, &str) =
    (axum::http::header::CACHE_CONTROL, "public, max-age=3600");

/// GET `/.well-known/oauth-protected-resource`
///
/// Returns the top-level Protected Resource Metadata document
/// (RFC 9728 §§2, 3.1). The `resource` field is the server's
/// `base_url`.
pub async fn protected_resource_metadata_root(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, StatusCode> {
    build_response(&state, None).await
}

/// GET `/.well-known/oauth-protected-resource/{*path}`
///
/// Per RFC 9728 §3.1, protected-resource metadata may be served at a
/// URL whose path is formed by inserting the well-known suffix
/// between the host and the resource's path. This handler honors
/// the variant for endpoints that are actually served (see
/// [`svc::PROTECTED_RESOURCE_PREFIXES`]); unknown sub-paths return
/// 404 to preserve the §4 identity rule — we never echo a
/// `resource` value we do not recognize.
pub async fn protected_resource_metadata_subpath(
    State(state): State<Arc<AppState>>,
    Path(sub_path): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    build_response(&state, Some(sub_path)).await
}

async fn build_response(
    state: &Arc<AppState>,
    sub_path: Option<String>,
) -> Result<impl IntoResponse + use<>, StatusCode> {
    let metadata = svc::build_protected_resource_metadata(state, sub_path.as_deref())
        .await
        .map_err(|e| match e {
            ServiceError::NotFound(_) => StatusCode::NOT_FOUND,
            other => {
                tracing::error!("Failed to build protected resource metadata: {other}");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;

    Ok(([RFC9728_CACHE_CONTROL], Json(metadata)))
}
