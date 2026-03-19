// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SAML 2.0 Service Provider.
//!
//! Submodules:
//! - `c14n` -- Exclusive XML Canonicalization (exc-c14n)
//! - `metadata` -- IdP metadata parsing and SP metadata generation

pub mod c14n;
pub mod metadata;

pub use metadata::IdpMetadata;

/// SAML 2.0 Service Provider.
///
/// Holds parsed IdP metadata (signing certs, SSO URLs) and SP configuration
/// (entity ID, ACS URL, attribute mapping) needed to initiate auth requests
/// and validate responses.
#[derive(Debug)]
pub struct SamlProvider {
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
}
