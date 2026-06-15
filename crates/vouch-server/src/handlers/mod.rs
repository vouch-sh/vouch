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

/// Implement [`axum::response::IntoResponse`] and the page-level template
/// shims for an Askama template.
///
/// The shims (`version`, `lang`, `dir`, `tr`, `tr1`) delegate to a required
/// `page: PageContext` field on the template, so template `.html` files render
/// `{{ self.tr("id") }}`, `{{ self.version() }}`, etc. against the
/// request-scoped translation context the handler constructed.
///
/// # Example
///
/// ```ignore
/// use crate::{impl_template_response, infra::i18n::PageContext};
///
/// #[derive(Template)]
/// #[template(path = "example.html")]
/// pub struct ExampleTemplate {
///     pub page: PageContext,
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

            #[allow(
                dead_code,
                reason = "page-context shims; not every template references every helper"
            )]
            impl $template {
                fn version(&self) -> &'static str { self.page.version() }
                fn lang(&self) -> &str { self.page.lang() }
                fn dir(&self) -> &'static str { self.page.dir() }
                fn tr(&self, id: &str) -> String { self.page.tr(id) }
                fn tr1(&self, id: &str, name: &str, value: &str) -> String {
                    self.page.tr1(id, name, value)
                }
            }
        )*
    };
}
