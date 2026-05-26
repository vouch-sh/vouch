// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Legal pages handler — redirects to vouch.sh.

use axum::response::Redirect;

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
