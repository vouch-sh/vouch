// SPDX-License-Identifier: BUSL-1.1
//! Legal pages handler — redirects to vouch.sh.

use axum::response::Redirect;

/// Privacy policy page.
/// GET /privacy → 301 to vouch.sh
pub async fn privacy_page() -> Redirect {
    Redirect::permanent("https://vouch.sh/privacy/")
}

/// Terms of service page.
/// GET /terms → 301 to vouch.sh
pub async fn terms_page() -> Redirect {
    Redirect::permanent("https://vouch.sh/terms/")
}
