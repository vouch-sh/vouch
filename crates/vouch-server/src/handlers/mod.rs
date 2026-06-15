// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HTTP request handlers.

pub(crate) mod admin;
pub(crate) mod applications;
pub(crate) mod auth;
pub(crate) mod browser_login;
pub(crate) mod certification;
pub(crate) mod credentials;
pub(crate) mod device;
pub(crate) mod enroll;
pub(crate) mod enroll_keys;
pub(crate) mod extractors;
pub(crate) use extractors::{ValidPath, ValidUuid};
pub(crate) mod github;
pub(crate) mod home;
pub(crate) mod install;
pub(crate) mod integrations;
pub(crate) mod keys;
pub(crate) mod legal;
pub(crate) mod oidc;
pub(crate) mod registration;
pub(crate) mod saml;
pub(crate) mod scim;
pub(crate) mod session;

// Re-export commonly used utilities from focused modules
pub(crate) use crate::crypto::{generate_challenge, generate_random_bytes, hash_token};
pub(crate) use registration::validate_registration_attestation;
pub(crate) use session::{
    clear_session_cookie, create_session_cookie, extract_session_from_cookie,
};

/// Common helpers available to every Askama template.
///
/// Implemented automatically by [`impl_template_response!`] so templates can
/// render `{{ self.version() }}`, `{{ self.lang() }}`, and `{{ self.tr("id") }}`.
///
/// Translation methods delegate to the shared `en-US`
/// [`default_context`](crate::infra::i18n::default_context); see that module for
/// why rendering is single-context until a second language ships.
pub(crate) trait HasVersion {
    /// Server version, for footer/version links.
    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// BCP-47 tag for `<html lang="...">`.
    fn lang(&self) -> &'static str {
        crate::infra::i18n::default_context().lang()
    }

    /// Text direction for `<html dir="...">`.
    fn dir(&self) -> &'static str {
        crate::infra::i18n::default_context().dir()
    }

    /// Translate a message with no arguments.
    fn tr(&self, id: &str) -> String {
        crate::infra::i18n::default_context().t(id)
    }

    /// Translate a message with a single Fluent placeable.
    fn tr1(&self, id: &str, name: &str, value: &str) -> String {
        crate::infra::i18n::default_context().t1(id, name, value)
    }
}

/// Macro to implement `IntoResponse` for Askama templates.
///
/// This reduces boilerplate when implementing `IntoResponse` for HTML templates.
/// The macro generates an implementation that renders the template and returns
/// either the HTML content or a 500 error if rendering fails.
///
/// It also implements [`HasVersion`] so templates can access the server version
/// via `{{ self.version() }}`.
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

            impl $crate::handlers::HasVersion for $template {}
        )*
    };
}
