// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SVG icon constants for identity provider branding.

// Note: SVG fill colors use `fill=` with hex values. We use concat! to avoid
// the Rust lexer interpreting `#XXXXXX` as prefix identifiers in raw strings.

/// Google logo (multi-color, 24x24 viewBox).
pub(crate) const GOOGLE: &str = concat!(
    r#"<svg aria-hidden="true" class="w-5 h-5" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">"#,
    r##"<path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>"##,
    r##"<path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>"##,
    r##"<path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>"##,
    r##"<path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>"##,
    "</svg>",
);

/// Okta logo (blue).
pub(crate) const OKTA: &str = concat!(
    r#"<svg aria-hidden="true" class="w-5 h-5" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">"#,
    r##"<path d="M12 0C5.389 0 0 5.389 0 12s5.389 12 12 12 12-5.389 12-12S18.611 0 12 0zm0 18c-3.314 0-6-2.686-6-6s2.686-6 6-6 6 2.686 6 6-2.686 6-6 6z" fill="#007DC1"/>"##,
    "</svg>",
);

/// Microsoft logo (four-color square, for Entra ID).
pub(crate) const MICROSOFT: &str = concat!(
    r#"<svg aria-hidden="true" class="w-5 h-5" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">"#,
    r##"<rect x="1" y="1" width="10" height="10" fill="#F25022"/>"##,
    r##"<rect x="13" y="1" width="10" height="10" fill="#7FBA00"/>"##,
    r##"<rect x="1" y="13" width="10" height="10" fill="#00A4EF"/>"##,
    r##"<rect x="13" y="13" width="10" height="10" fill="#FFB900"/>"##,
    "</svg>",
);

/// Keycloak logo (simplified key icon).
pub(crate) const KEYCLOAK: &str = concat!(
    r#"<svg aria-hidden="true" class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">"#,
    r#"<path stroke-linecap="round" stroke-linejoin="round" d="M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z"/>"#,
    "</svg>",
);

/// Auth0 logo (shield).
pub(crate) const AUTH0: &str = concat!(
    r#"<svg aria-hidden="true" class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">"#,
    r#"<path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z"/>"#,
    "</svg>",
);

/// Generic SSO icon (lock/shield for unknown providers).
pub(crate) const GENERIC: &str = concat!(
    r#"<svg aria-hidden="true" class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">"#,
    r#"<path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z"/>"#,
    "</svg>",
);
