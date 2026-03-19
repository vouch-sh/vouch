// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Upstream identity provider abstraction.
//!
//! Supports OIDC and SAML (stub) upstream identity providers with
//! protocol-agnostic auth initiation and provider-specific UI branding.

pub mod icons;
pub mod oidc;
pub mod saml;

/// Known identity provider for UI branding.
#[derive(Debug)]
pub enum IdpBrand {
    Google,
    Okta,
    Entra,
    Keycloak,
    Auth0,
    Generic,
}

impl IdpBrand {
    /// Detect provider from OIDC issuer URL.
    #[must_use]
    pub fn from_issuer(issuer: &str) -> Self {
        if issuer.contains("accounts.google.com") {
            Self::Google
        } else if issuer.contains(".okta.com") {
            Self::Okta
        } else if issuer.contains("login.microsoftonline.com") {
            Self::Entra
        } else if issuer.contains("keycloak") {
            Self::Keycloak
        } else if issuer.contains("auth0.com") {
            Self::Auth0
        } else {
            Self::Generic
        }
    }

    /// Detect provider from SAML entity ID.
    ///
    /// Auth0 SAML entity IDs typically contain `auth0.com` in the path but
    /// not necessarily the hostname. We check both for consistency with
    /// `from_issuer()`.
    #[must_use]
    pub fn from_entity_id(entity_id: &str) -> Self {
        if entity_id.contains(".okta.com") {
            Self::Okta
        } else if entity_id.contains("sts.windows.net")
            || entity_id.contains("login.microsoftonline.com")
        {
            Self::Entra
        } else if entity_id.contains("accounts.google.com") {
            Self::Google
        } else if entity_id.contains("keycloak") {
            Self::Keycloak
        } else if entity_id.contains("auth0.com") {
            Self::Auth0
        } else {
            Self::Generic
        }
    }

    /// Display name for button text ("Sign in with {name}").
    #[must_use]
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Google => "Google",
            Self::Okta => "Okta",
            Self::Entra => "Microsoft",
            Self::Keycloak => "Keycloak",
            Self::Auth0 => "Auth0",
            Self::Generic => "SSO",
        }
    }

    /// Inline SVG icon markup.
    #[must_use]
    pub fn svg_icon(&self) -> &'static str {
        match self {
            Self::Google => icons::GOOGLE,
            Self::Okta => icons::OKTA,
            Self::Entra => icons::MICROSOFT,
            Self::Keycloak => icons::KEYCLOAK,
            Self::Auth0 => icons::AUTH0,
            Self::Generic => icons::GENERIC,
        }
    }
}

/// Result of upstream identity verification (used by OIDC, future SAML).
///
/// This is the protocol-agnostic output: the caller doesn't need to know
/// whether the identity came from an OIDC ID token or a SAML assertion.
#[derive(Debug)]
pub struct IdentityResult {
    /// Verified email address.
    pub email: String,
    /// Email domain (e.g., "acme.com").
    pub domain: Option<String>,
}

/// How to send the user to the upstream IdP.
#[derive(Debug)]
pub enum AuthAction {
    /// HTTP 303 redirect (OIDC, SAML Redirect binding).
    Redirect { url: String },
    /// Auto-submitting HTML form (SAML POST binding).
    PostForm {
        action_url: String,
        saml_request: String,
        relay_state: String,
    },
}

/// Protocol-agnostic result of initiating upstream auth.
#[derive(Debug)]
pub struct AuthRequest {
    /// How to send the user to the IdP.
    pub action: AuthAction,
    /// Opaque state token (stored as `state` in oidc_state table).
    /// OIDC: random base64url token. SAML: RelayState token.
    pub state_key: String,
    /// Protocol-specific request identifier (stored as `nonce` in DB).
    /// OIDC: nonce for ID token binding. SAML: AuthnRequest ID.
    pub nonce: String,
}

/// Configured upstream identity provider.
#[derive(Debug)]
pub enum UpstreamIdp {
    Oidc(Box<oidc::OidcProvider>),
    Saml(saml::SamlProvider),
}

impl UpstreamIdp {
    /// Initiate authentication with the upstream IdP.
    ///
    /// Generates state and nonce internally, builds the appropriate auth
    /// action (redirect URL for OIDC, POST form for SAML), and returns
    /// the full `AuthRequest` to store state and redirect/render.
    ///
    /// # Note
    /// `initiate_auth` takes the full `ServerConfig` for simplicity in Phase 1.
    /// Only `oidc_client_id` and `base_url` are used. This coupling can be
    /// narrowed in Phase 2 if needed.
    ///
    /// # Invariant
    /// When `Self::Oidc` is active, `config.oidc_client_id` must be `Some`.
    /// Startup validates `oidc_configured()` before constructing `UpstreamIdp::Oidc`,
    /// so the error path below should be unreachable in practice.
    ///
    /// # Errors
    ///
    /// Returns an error if random byte generation fails, or if required OIDC
    /// config fields are missing (should be unreachable -- see invariant above).
    /// Returns an error for the SAML variant (not yet implemented in Phase 1).
    pub fn initiate_auth(
        &self,
        config: &crate::config::ServerConfig,
    ) -> Result<AuthRequest, anyhow::Error> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let state_bytes = crate::crypto::generate_random_bytes(32)?;
        let nonce_bytes = crate::crypto::generate_random_bytes(32)?;
        let state_key = URL_SAFE_NO_PAD.encode(state_bytes);
        let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);

        match self {
            Self::Oidc(p) => {
                let client_id = config
                    .oidc_client_id
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("OIDC client_id not configured"))?;
                let redirect_uri = format!("{}/oauth/callback", config.base_url);
                let mut url = p.authorization_endpoint.clone();
                url.query_pairs_mut()
                    .append_pair("client_id", client_id)
                    .append_pair("redirect_uri", &redirect_uri)
                    .append_pair("response_type", "code")
                    .append_pair("scope", "openid email")
                    .append_pair("state", &state_key)
                    .append_pair("nonce", &nonce)
                    .append_pair("prompt", "login");
                Ok(AuthRequest {
                    action: AuthAction::Redirect {
                        url: url.to_string(),
                    },
                    state_key,
                    nonce,
                })
            }
            Self::Saml(_) => {
                anyhow::bail!("SAML initiate_auth not yet implemented (Phase 2)")
            }
        }
    }

    /// Detect the IdP brand for UI display.
    #[must_use]
    pub fn brand(&self) -> IdpBrand {
        match self {
            Self::Oidc(p) => IdpBrand::from_issuer(&p.issuer),
            Self::Saml(s) => IdpBrand::from_entity_id(&s.entity_id),
        }
    }
}

/// Extract the email domain from an ID token.
///
/// For Google issuers, only the Workspace `hd` claim is used so consumer
/// accounts do not get grouped into a shared public-email organization.
/// For non-Google issuers, falls back to extracting the domain from email.
#[must_use]
pub fn extract_email_domain<'a>(
    issuer: &str,
    hd: Option<&'a str>,
    email: &'a str,
) -> Option<&'a str> {
    if matches!(IdpBrand::from_issuer(issuer), IdpBrand::Google) {
        hd
    } else {
        hd.or_else(|| email.split('@').nth(1))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::test_utils::test_config;

    // =========================================================================
    // IdpBrand::from_issuer tests
    // =========================================================================

    #[test]
    fn detect_google() {
        let brand = IdpBrand::from_issuer("https://accounts.google.com");
        assert_eq!(brand.display_name(), "Google");
    }

    #[test]
    fn detect_okta() {
        let brand = IdpBrand::from_issuer("https://dev-123.okta.com");
        assert_eq!(brand.display_name(), "Okta");
    }

    #[test]
    fn detect_entra() {
        let brand = IdpBrand::from_issuer("https://login.microsoftonline.com/tenant/v2.0");
        assert_eq!(brand.display_name(), "Microsoft");
    }

    #[test]
    fn detect_keycloak() {
        let brand = IdpBrand::from_issuer("https://keycloak.example.com/realms/myrealm");
        assert_eq!(brand.display_name(), "Keycloak");
    }

    #[test]
    fn detect_auth0() {
        let brand = IdpBrand::from_issuer("https://myapp.auth0.com");
        assert_eq!(brand.display_name(), "Auth0");
    }

    #[test]
    fn detect_generic() {
        let brand = IdpBrand::from_issuer("https://idp.example.com");
        assert_eq!(brand.display_name(), "SSO");
    }

    // =========================================================================
    // IdpBrand::from_entity_id tests
    // =========================================================================

    #[test]
    fn from_entity_id_okta() {
        let brand = IdpBrand::from_entity_id("https://dev-123.okta.com/app/example/sso/saml");
        assert_eq!(brand.display_name(), "Okta");
    }

    #[test]
    fn from_entity_id_entra_sts() {
        let brand = IdpBrand::from_entity_id("https://sts.windows.net/tenant-id/");
        assert_eq!(brand.display_name(), "Microsoft");
    }

    #[test]
    fn from_entity_id_entra_login() {
        let brand = IdpBrand::from_entity_id("https://login.microsoftonline.com/tenant-id/v2.0");
        assert_eq!(brand.display_name(), "Microsoft");
    }

    #[test]
    fn from_entity_id_google() {
        let brand = IdpBrand::from_entity_id("https://accounts.google.com");
        assert_eq!(brand.display_name(), "Google");
    }

    #[test]
    fn from_entity_id_auth0() {
        let brand = IdpBrand::from_entity_id("https://myapp.auth0.com/samlp/client-id");
        assert_eq!(brand.display_name(), "Auth0");
    }

    #[test]
    fn from_entity_id_keycloak() {
        let brand = IdpBrand::from_entity_id("https://keycloak.example.com/realms/myrealm");
        assert_eq!(brand.display_name(), "Keycloak");
    }

    #[test]
    fn from_entity_id_generic() {
        let brand = IdpBrand::from_entity_id("https://idp.example.com/saml/metadata");
        assert_eq!(brand.display_name(), "SSO");
    }

    // =========================================================================
    // UpstreamIdp::initiate_auth tests
    // =========================================================================

    fn make_oidc_provider(auth_endpoint: &str) -> oidc::OidcProvider {
        oidc::OidcProvider {
            issuer: "https://accounts.google.com".to_string(),
            authorization_endpoint: url::Url::parse(auth_endpoint).unwrap(),
            token_endpoint: url::Url::parse("https://oauth2.googleapis.com/token").unwrap(),
            jwks_uri: url::Url::parse("https://www.googleapis.com/oauth2/v3/certs").unwrap(),
        }
    }

    #[test]
    fn initiate_auth_oidc_returns_redirect() {
        let provider = make_oidc_provider("https://accounts.google.com/o/oauth2/v2/auth");
        let idp = UpstreamIdp::Oidc(Box::new(provider));
        let config = test_config();

        let auth = idp.initiate_auth(&config).unwrap();

        let AuthAction::Redirect { url } = auth.action else {
            panic!("Expected AuthAction::Redirect");
        };
        assert!(
            url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"),
            "URL should start with auth endpoint: {url}"
        );
        assert!(
            url.contains("client_id=test-client-id"),
            "Missing client_id: {url}"
        );
        assert!(url.contains("redirect_uri="), "Missing redirect_uri: {url}");
        assert!(
            url.contains("response_type=code"),
            "Missing response_type: {url}"
        );
        assert!(url.contains("scope=openid"), "Missing scope: {url}");
        assert!(url.contains("prompt=login"), "Missing prompt: {url}");
        assert!(
            url.contains(&format!("state={}", auth.state_key)),
            "URL should contain state: {url}"
        );
        assert!(
            url.contains(&format!("nonce={}", auth.nonce)),
            "URL should contain nonce: {url}"
        );
    }

    #[test]
    fn initiate_auth_oidc_handles_existing_query_params() {
        // Covers SO-1: endpoints with pre-existing query parameters
        let provider = make_oidc_provider("https://example.com/auth?existing=param");
        let idp = UpstreamIdp::Oidc(Box::new(provider));
        let config = test_config();

        let auth = idp.initiate_auth(&config).unwrap();

        let AuthAction::Redirect { url } = auth.action else {
            panic!("Expected AuthAction::Redirect");
        };
        assert!(
            url.contains("existing=param"),
            "Should preserve existing params: {url}"
        );
        assert!(
            url.contains("client_id=test-client-id"),
            "Should append new params: {url}"
        );
    }

    #[test]
    fn initiate_auth_generates_unique_state_and_nonce() {
        let provider = make_oidc_provider("https://accounts.google.com/o/oauth2/v2/auth");
        let idp = UpstreamIdp::Oidc(Box::new(provider));
        let config = test_config();

        let auth1 = idp.initiate_auth(&config).unwrap();
        let auth2 = idp.initiate_auth(&config).unwrap();

        assert_ne!(
            auth1.state_key, auth2.state_key,
            "State keys should be unique"
        );
        assert_ne!(auth1.nonce, auth2.nonce, "Nonces should be unique");
    }

    #[test]
    fn initiate_auth_saml_returns_error() {
        let saml_provider = saml::SamlProvider {
            entity_id: "https://idp.example.com/saml".to_string(),
        };
        let idp = UpstreamIdp::Saml(saml_provider);
        let config = test_config();

        let result = idp.initiate_auth(&config);
        assert!(
            result.is_err(),
            "SAML initiate_auth should return error in Phase 1"
        );
    }

    // =========================================================================
    // SVG icon tests
    // =========================================================================

    #[test]
    fn svg_icons_are_distinct() {
        let brands = [
            IdpBrand::Google,
            IdpBrand::Okta,
            IdpBrand::Entra,
            IdpBrand::Keycloak,
            IdpBrand::Auth0,
            IdpBrand::Generic,
        ];
        for (i, a) in brands.iter().enumerate() {
            for (j, b) in brands.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        a.svg_icon(),
                        b.svg_icon(),
                        "{:?} and {:?} should have different icons",
                        a,
                        b,
                    );
                }
            }
        }
    }

    // =========================================================================
    // extract_email_domain tests
    // =========================================================================

    #[test]
    fn extract_domain_from_hd() {
        assert_eq!(
            extract_email_domain(
                "https://accounts.google.com",
                Some("acme.com"),
                "user@acme.com"
            ),
            Some("acme.com"),
        );
    }

    #[test]
    fn extract_domain_from_email() {
        assert_eq!(
            extract_email_domain("https://idp.example.com", None, "user@example.org"),
            Some("example.org"),
        );
    }

    #[test]
    fn extract_domain_hd_takes_precedence() {
        assert_eq!(
            extract_email_domain(
                "https://idp.example.com",
                Some("corp.com"),
                "user@gmail.com"
            ),
            Some("corp.com"),
        );
    }

    #[test]
    fn extract_domain_no_at_sign() {
        assert_eq!(
            extract_email_domain("https://idp.example.com", None, "invalid"),
            None
        );
    }

    #[test]
    fn extract_domain_google_consumer_without_hd() {
        assert_eq!(
            extract_email_domain("https://accounts.google.com", None, "user@gmail.com"),
            None,
        );
    }
}
