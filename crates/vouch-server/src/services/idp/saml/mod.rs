// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SAML 2.0 Service Provider.
//!
//! Submodules:
//! - `c14n` -- Exclusive XML Canonicalization (exc-c14n)
//! - `metadata` -- IdP metadata parsing and SP metadata generation

pub(crate) mod authn_request;
pub(crate) mod c14n;
pub(crate) mod metadata;
pub(crate) mod response;
pub(crate) mod signature;

pub(crate) use metadata::IdpMetadata;

/// SAML 2.0 Service Provider.
///
/// Holds parsed IdP metadata (signing certs, SSO URLs) and SP configuration
/// (entity ID, ACS URL, attribute mapping) needed to initiate auth requests
/// and validate responses.
#[derive(Debug, Clone)]
pub struct SamlProvider {
    /// Operator-chosen slug (e.g., "corp-saml"). Used as lookup key in
    /// `AppState::idps` and stored in the OIDC state row at auth-initiate time.
    pub id: String,
    /// Parsed IdP metadata (entity ID, SSO URLs, signing certs).
    pub idp_metadata: IdpMetadata,
    /// SP entity ID (audience restriction value in assertions).
    pub sp_entity_id: String,
    /// Assertion Consumer Service URL (`{base_url}/saml/acs`).
    pub acs_url: String,
    /// SAML attribute name for email (None = use NameID).
    pub email_attribute: Option<String>,
    /// SAML attribute name for domain (None = extract from email).
    pub domain_attribute: Option<String>,
}

impl SamlProvider {
    /// IdP entity ID (used for brand detection).
    #[must_use]
    pub fn entity_id(&self) -> &str {
        &self.idp_metadata.entity_id
    }

    /// CSP `form-action` origins for SAML SSO URLs.
    ///
    /// Returns the origins of `sso_post_url` and `sso_redirect_url` (whichever
    /// are configured), deduplicated. Used to widen `form-action` so the
    /// auto-submitting POST form (HTTP-POST binding) and 303 redirect
    /// (HTTP-Redirect binding) are not blocked by Chromium-based browsers.
    #[must_use]
    pub fn form_action_origins(&self) -> Vec<crate::infra::csp::CspOrigin> {
        let mut origins: Vec<crate::infra::csp::CspOrigin> = Vec::new();
        let mut push = |raw: &str| {
            if let Some(origin) = crate::infra::csp::CspOrigin::parse(raw)
                && !origins.iter().any(|existing| existing == &origin)
            {
                origins.push(origin);
            }
        };
        if let Some(url) = self.idp_metadata.sso_post_url.as_deref() {
            push(url);
        }
        if let Some(url) = self.idp_metadata.sso_redirect_url.as_deref() {
            push(url);
        }
        origins
    }
}
