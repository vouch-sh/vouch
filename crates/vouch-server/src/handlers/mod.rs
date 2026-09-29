// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HTTP request handlers.

pub(crate) mod admin;
pub(crate) mod api;
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
pub(crate) use crate::crypto::{generate_challenge, hash_token};
pub(crate) use registration::validate_registration_attestation;
pub(crate) use session::{
    clear_session_cookie, create_session_cookie, extract_session_from_cookie,
};

/// Evidence that a browser request's `clientDataJSON` names the expected
/// ceremony type and this server's origin.
///
/// Both browser completion types hold one as a field. A struct literal must
/// name every field, so a completion type built without this check does not
/// compile — the same guarantee `TokenIssuanceProof`'s fields give the token
/// endpoint. The only constructor is [`ClientDataProof::verify`], and it
/// cannot be reached with an origin or type that did not match.
///
/// The comparisons themselves need the server's configured `base_url`, so
/// unlike a field length they cannot be pushed into the request type.
pub(crate) struct ClientDataProof {
    _private: (),
}

/// Why a `clientDataJSON` was rejected. Each caller maps this to its own
/// error code, which differ between the login and enrollment endpoints.
pub(crate) enum ClientDataError {
    /// The bytes are not UTF-8.
    NotUtf8,
    /// The bytes are UTF-8 but not the expected JSON object.
    Malformed(serde_json::Error),
    /// `type` named a different ceremony.
    WrongType,
    /// `origin` named a different server.
    WrongOrigin(String),
}

/// The members of `clientDataJSON` a server compares (WebAuthn Level 2 §7.1
/// step 9 and §7.2 step 11-13).
#[derive(serde::Deserialize)]
struct CollectedClientData {
    origin: String,
    #[serde(rename = "type")]
    typ: String,
}

impl ClientDataProof {
    /// Parse `client_data_json` and compare its ceremony type and origin.
    ///
    /// # Errors
    ///
    /// Returns the [`ClientDataError`] variant naming which comparison failed.
    pub(crate) fn verify(
        client_data_json: &[u8],
        expected_type: &str,
        expected_origin: &str,
    ) -> Result<Self, ClientDataError> {
        let text = std::str::from_utf8(client_data_json).map_err(|_| ClientDataError::NotUtf8)?;
        let client_data: CollectedClientData =
            serde_json::from_str(text).map_err(ClientDataError::Malformed)?;

        if client_data.typ != expected_type {
            return Err(ClientDataError::WrongType);
        }
        if client_data.origin != expected_origin {
            return Err(ClientDataError::WrongOrigin(client_data.origin));
        }

        Ok(Self { _private: () })
    }
}

/// Implement [`axum::response::IntoResponse`] for an Askama template — render
/// to HTML on success, log + 500 on error.
///
/// Doesn't touch the template's i18n shims; use it alone when you need a
/// custom `IntoResponse` (e.g. a non-200 status) and pair with
/// [`impl_template_helpers!`].
#[macro_export]
macro_rules! impl_template_into_response {
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

/// Generate the page-level helper methods every Askama template can call as
/// `self.<name>()`. Askama can only reach `self.field` and `self.method()` in
/// `{{ … }}` expressions — it can't touch module constants or free functions —
/// so these inherent shims exist to bridge that.
///
/// Currently includes:
/// - **`version`** — `env!("CARGO_PKG_VERSION")` for the footer.
/// - **`lang`**, **`dir`**, **`tr`**, **`tr1`** — i18n helpers that forward to
///   the request-scoped task-local installed by
///   [`crate::infra::i18n::i18n_layer`].
/// - **`tr_attr`**, **`tr_attr1`** — read Fluent message attributes
///   (`id .attr = value`), used for paired button label + `.title` tooltip.
#[macro_export]
macro_rules! impl_template_helpers {
    ($($template:ty),* $(,)?) => {
        $(
            #[allow(
                dead_code,
                reason = "page-level helpers; not every template references every method"
            )]
            impl $template {
                fn version(&self) -> &'static str { env!("CARGO_PKG_VERSION") }
                fn lang(&self) -> String { $crate::infra::i18n::lang() }
                fn dir(&self) -> &'static str { $crate::infra::i18n::dir() }
                // Single translation entry point. Returns a [`Tr`] builder
                // that Askama Display-renders in `{{ … }}`, so call sites
                // chain `.arg(name, value)` and `.attr(attr)` as needed:
                //
                //   {{ self.tr("home-tagline").arg("org", org_name.as_str()) }}
                //   {{ self.tr("admin-members-demote").attr("title") }}
                //   {{ self.tr("count").arg("n", member.key_count) }}
                //
                // Numeric values engage CLDR plural rules automatically.
                fn tr<'a>(&self, id: &'a str) -> $crate::infra::i18n::Tr<'a> {
                    $crate::infra::i18n::Tr::new(id)
                }
            }
        )*
    };
}

/// Wire both [`impl_template_into_response!`] (default 200/HTML) and
/// [`impl_template_helpers!`] for one or more Askama templates.
///
/// # Example
///
/// ```ignore
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
        $crate::impl_template_into_response!($($template),*);
        $crate::impl_template_helpers!($($template),*);
    };
}
