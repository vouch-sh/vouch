// SPDX-License-Identifier: BUSL-1.1
//! HTTP request handlers.

pub mod admin;
pub mod applications;
pub mod auth;
pub mod browser_login;
pub mod credentials;
pub mod device;
pub mod enroll;
pub mod enroll_keys;
pub mod errors;
pub(crate) mod extractors;
pub mod github;
pub mod home;
pub mod install;
pub mod integrations;
pub mod keys;
pub mod legal;
pub mod oidc;
pub mod registration;
pub mod scim;
pub mod session;

// Re-export commonly used utilities from focused modules
pub(crate) use crate::crypto::{generate_challenge, generate_random_bytes, hash_token};
pub(crate) use errors::json_error;
pub(crate) use registration::validate_registration_attestation;
pub(crate) use session::{
    clear_session_cookie, create_session_cookie, extract_session_from_cookie,
};

/// Macro to implement `IntoResponse` for Askama templates.
///
/// This reduces boilerplate when implementing `IntoResponse` for HTML templates.
/// The macro generates an implementation that renders the template and returns
/// either the HTML content or a 500 error if rendering fails.
///
/// # Example
///
/// ```ignore
/// use crate::impl_template_response;
///
/// #[derive(Template)]
/// #[template(path = "example.html")]
/// pub struct ExampleTemplate {
///     pub name: String,
/// }
///
/// impl_template_response!(ExampleTemplate);
/// ```
#[macro_export]
macro_rules! impl_template_response {
    ($($template:ty),* $(,)?) => {
        $(
            impl axum::response::IntoResponse for $template {
                fn into_response(self) -> axum::response::Response {
                    use askama::Template;
                    match self.render() {
                        Ok(html) => axum::response::Html(html).into_response(),
                        Err(e) => {
                            tracing::error!("Template render error: {}", e);
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
                        }
                    }
                }
            }
        )*
    };
}
