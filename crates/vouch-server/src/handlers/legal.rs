// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Legal and policy pages — vouch.sh redirects plus RFC 9116 security.txt.

use crate::AppState;
use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Redirect};
use std::sync::Arc;

/// Privacy policy page.
/// GET /privacy → 301 to vouch.sh
pub(crate) async fn privacy_page() -> Redirect {
    Redirect::permanent("https://vouch.sh/privacy/")
}

/// Terms of service page.
/// GET /terms → 301 to vouch.sh
pub(crate) async fn terms_page() -> Redirect {
    Redirect::permanent("https://vouch.sh/terms/")
}

/// Vulnerability disclosure contact (RFC 9116).
/// GET /.well-known/security.txt
///
/// `Canonical` is built from the configured `base_url`, never the request
/// `Host` header — the header is attacker-controlled behind the L4
/// passthrough listener. `Expires` rolls 30 days ahead of each request so
/// a long-lived deployment can never serve a stale value.
pub(crate) async fn security_txt(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let config = state.config.load();
    let now = jiff::Timestamp::now();
    let expires = now
        .checked_add(jiff::Span::new().hours(720))
        .and_then(|ts| ts.round(jiff::Unit::Second))
        .unwrap_or(now);
    let base_url = &config.base_url;
    let body = format!(
        "Contact: mailto:{}\r\nExpires: {expires}\r\nCanonical: {base_url}/.well-known/security.txt\r\n",
        config.security_contact
    );
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body)
}
