// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Same-origin enforcement for cookie-authenticated browser mutations.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use http::StatusCode;
use std::sync::Arc;

use crate::AppState;
use crate::error::ServiceError;
use crate::infra::i18n::Tr;

/// Reject state-changing requests whose `Origin` header is absent or not
/// this server's own origin (RFC 9700 CSRF defense).
///
/// Layered over the browser UI route group, where every handler
/// authenticates with the session cookie — an ambient credential a
/// cross-site form can replay. Safe methods pass untouched: they mutate
/// nothing, and pages must render from bookmarks and links, which carry no
/// `Origin`. The check runs before any extractor, so a forged request is
/// refused without spending the auth path's database lookups.
///
/// `/saml/acs` is registered after this layer in `build_ui_routes`: the IdP
/// delivers the SAML POST binding cross-origin by design.
pub(crate) async fn same_origin(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, ServiceError> {
    if request.method().is_safe() {
        return Ok(next.run(request).await);
    }

    let origin = request
        .headers()
        .get("Origin")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            ServiceError::api(
                StatusCode::FORBIDDEN,
                "missing_origin",
                Tr::new("login-error-missing-origin").to_string(),
            )
        })?;

    let config = state.config();
    let expected: &str = &config.base_url;
    if origin != expected {
        tracing::warn!("Origin mismatch: got '{origin}', expected '{expected}'");
        return Err(ServiceError::api(
            StatusCode::FORBIDDEN,
            "invalid_origin",
            Tr::new("login-error-origin-mismatch").to_string(),
        ));
    }

    Ok(next.run(request).await)
}
