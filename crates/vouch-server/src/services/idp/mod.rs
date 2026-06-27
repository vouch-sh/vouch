// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Upstream identity provider abstraction.
//!
//! Supports OIDC and SAML upstream identity providers with protocol-agnostic
//! auth initiation and provider-specific UI branding. Multiple providers of
//! either kind can be configured simultaneously and are stored as a single
//! ordered list in `AppState::idps`.

pub(crate) mod icons;
pub(crate) mod oidc;
pub(crate) mod saml;

pub(crate) use oidc::ConfiguredOidcProvider;
pub(crate) use saml::SamlProvider;

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
pub(crate) struct IdentityResult {
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
    /// PKCE code_verifier (RFC 7636). Only set for OIDC flows.
    /// Empty for SAML. Stored in DB and sent during token exchange.
    pub code_verifier: String,
}

/// Identity provider kind discriminator (used in config and audit logging).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdpKind {
    Oidc,
    Saml,
}

impl IdpKind {
    /// Serialize as lowercase string (matches env-var / S3 config values).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Saml => "saml",
        }
    }
}

/// A fully configured upstream identity provider, ready to initiate auth.
///
/// Stored as `Vec<ConfiguredIdp>` in `AppState::idps` in the order operators
/// listed them in `VOUCH_IDPS` (or the S3 `idps` array). Order controls the
/// login page button order; `id` is the lookup key at callback time.
#[derive(Debug, Clone)]
pub enum ConfiguredIdp {
    Oidc(ConfiguredOidcProvider),
    Saml(SamlProvider),
}

impl ConfiguredIdp {
    /// Operator-chosen slug (e.g., "google", "entra", "corp-saml").
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Oidc(p) => &p.id,
            Self::Saml(p) => &p.id,
        }
    }

    /// Protocol kind for this provider.
    #[must_use]
    pub fn kind(&self) -> IdpKind {
        match self {
            Self::Oidc(_) => IdpKind::Oidc,
            Self::Saml(_) => IdpKind::Saml,
        }
    }

    /// Brand for UI display (icon + display name).
    #[must_use]
    pub fn brand(&self) -> IdpBrand {
        match self {
            Self::Oidc(p) => IdpBrand::from_issuer(&p.provider.issuer),
            Self::Saml(p) => IdpBrand::from_entity_id(p.entity_id()),
        }
    }

    /// CSP `form-action` origins this IdP needs the browser to be allowed to
    /// redirect or POST to during sign-in handoff. Always returns at least
    /// one origin in practice (empty `Vec` only if all URLs are malformed).
    #[must_use]
    pub fn form_action_origins(&self) -> Vec<crate::infra::csp::CspOrigin> {
        match self {
            Self::Oidc(p) => p.provider.form_action_origin().into_iter().collect(),
            Self::Saml(p) => p.form_action_origins(),
        }
    }

    /// Initiate authentication with this provider.
    ///
    /// # Errors
    ///
    /// Returns an error if random byte generation fails (OIDC), if the SAML
    /// AuthnRequest cannot be built, or if the SAML SSO URL has a disallowed
    /// scheme.
    pub fn initiate_auth(&self, base_url: &str) -> Result<AuthRequest, anyhow::Error> {
        match self {
            Self::Oidc(p) => p.initiate_auth(base_url),
            Self::Saml(p) => initiate_saml_auth(p),
        }
    }
}

/// Initiate a SAML AuthnRequest for the given provider.
fn initiate_saml_auth(saml: &SamlProvider) -> Result<AuthRequest, anyhow::Error> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let authn = saml::authn_request::build_authn_request(saml)
        .map_err(|e| anyhow::anyhow!("Failed to build SAML AuthnRequest: {e}"))?;
    let state_key = URL_SAFE_NO_PAD.encode(crate::crypto::generate_random_bytes(32)?);
    let parsed_sso = url::Url::parse(&authn.sso_url)
        .map_err(|e| anyhow::anyhow!("Invalid SAML SSO URL: {e}"))?;
    let scheme = parsed_sso.scheme();
    if scheme != "https" && scheme != "http" {
        anyhow::bail!(
            "SAML SSO URL has disallowed scheme '{scheme}': {}",
            authn.sso_url
        );
    }
    if authn.is_post_binding {
        Ok(AuthRequest {
            action: AuthAction::PostForm {
                action_url: authn.sso_url,
                saml_request: authn.encoded_request,
                relay_state: state_key.clone(),
            },
            state_key,
            nonce: authn.request_id,
            code_verifier: String::new(),
        })
    } else {
        let mut url = url::Url::parse(&authn.sso_url)
            .map_err(|e| anyhow::anyhow!("Invalid SAML SSO URL: {e}"))?;
        url.query_pairs_mut()
            .append_pair("SAMLRequest", &authn.encoded_request)
            .append_pair("RelayState", &state_key);
        Ok(AuthRequest {
            action: AuthAction::Redirect {
                url: url.to_string(),
            },
            state_key,
            nonce: authn.request_id,
            code_verifier: String::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "test code: panic on assertion failure is acceptable"
    )]

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
    // ConfiguredIdp::initiate_auth tests
    // =========================================================================

    fn make_oidc_provider(auth_endpoint: &str) -> oidc::OidcProvider {
        oidc::OidcProvider {
            issuer: "https://accounts.google.com".to_string(),
            authorization_endpoint: url::Url::parse(auth_endpoint).unwrap(),
            token_endpoint: url::Url::parse("https://oauth2.googleapis.com/token").unwrap(),
            jwks_uri: url::Url::parse("https://www.googleapis.com/oauth2/v3/certs").unwrap(),
        }
    }

    fn make_configured_oidc_provider(auth_endpoint: &str) -> oidc::ConfiguredOidcProvider {
        use secrecy::SecretString;
        oidc::ConfiguredOidcProvider {
            id: "google".to_string(),
            client_id: "test-client-id".to_string(),
            client_secret: SecretString::from("test-client-secret"),
            provider: make_oidc_provider(auth_endpoint),
        }
    }

    #[test]
    fn initiate_auth_oidc_returns_redirect() {
        let provider =
            make_configured_oidc_provider("https://accounts.google.com/o/oauth2/v2/auth");
        let config = test_config();

        let auth = provider.initiate_auth(&config.base_url).unwrap();

        assert!(
            matches!(auth.action, AuthAction::Redirect { .. }),
            "Expected AuthAction::Redirect"
        );
        let AuthAction::Redirect { url } = auth.action else {
            return;
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
        let provider = make_configured_oidc_provider("https://example.com/auth?existing=param");
        let config = test_config();

        let auth = provider.initiate_auth(&config.base_url).unwrap();

        assert!(
            matches!(auth.action, AuthAction::Redirect { .. }),
            "Expected AuthAction::Redirect"
        );
        let AuthAction::Redirect { url } = auth.action else {
            return;
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
        let provider =
            make_configured_oidc_provider("https://accounts.google.com/o/oauth2/v2/auth");
        let config = test_config();

        let auth1 = provider.initiate_auth(&config.base_url).unwrap();
        let auth2 = provider.initiate_auth(&config.base_url).unwrap();

        assert_ne!(
            auth1.state_key, auth2.state_key,
            "State keys should be unique"
        );
        assert_ne!(auth1.nonce, auth2.nonce, "Nonces should be unique");
    }

    fn make_saml_provider_with_endpoints(
        sso_post_url: Option<&str>,
        sso_redirect_url: Option<&str>,
    ) -> saml::SamlProvider {
        saml::SamlProvider {
            id: "corp-saml".to_string(),
            idp_metadata: saml::IdpMetadata {
                entity_id: "https://idp.example.com/saml".to_string(),
                sso_post_url: sso_post_url.map(str::to_string),
                sso_redirect_url: sso_redirect_url.map(str::to_string),
                signing_certificates: vec![],
            },
            sp_entity_id: "https://vouch.example.com".to_string(),
            acs_url: "https://vouch.example.com/saml/acs".to_string(),
            email_attribute: None,
            domain_attribute: None,
        }
    }

    #[test]
    fn initiate_auth_saml_post_binding_returns_post_form() {
        let saml_provider =
            make_saml_provider_with_endpoints(Some("https://idp.example.com/sso"), None);
        let idp = ConfiguredIdp::Saml(saml_provider);
        let config = test_config();

        let result = idp.initiate_auth(&config.base_url).unwrap();
        assert!(
            matches!(result.action, AuthAction::PostForm { .. }),
            "SAML with POST binding should return PostForm action"
        );
        assert!(!result.state_key.is_empty(), "state_key must not be empty");
        assert!(!result.nonce.is_empty(), "nonce must not be empty");
    }

    #[test]
    fn initiate_auth_saml_redirect_binding_returns_redirect() {
        let saml_provider =
            make_saml_provider_with_endpoints(None, Some("https://idp.example.com/sso/redirect"));
        let idp = ConfiguredIdp::Saml(saml_provider);
        let config = test_config();

        let result = idp.initiate_auth(&config.base_url).unwrap();
        assert!(
            matches!(result.action, AuthAction::Redirect { .. }),
            "Expected AuthAction::Redirect for SAML redirect binding"
        );
        let AuthAction::Redirect { url } = result.action else {
            return;
        };
        assert!(
            url.contains("SAMLRequest="),
            "Redirect URL must contain SAMLRequest: {url}"
        );
        assert!(
            url.contains("RelayState="),
            "Redirect URL must contain RelayState: {url}"
        );
    }

    // =========================================================================
    // PKCE tests (RFC 7636)
    // =========================================================================

    #[test]
    fn initiate_auth_oidc_includes_pkce_params() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let provider =
            make_configured_oidc_provider("https://accounts.google.com/o/oauth2/v2/auth");
        let config = test_config();

        let auth = provider.initiate_auth(&config.base_url).unwrap();

        assert!(
            matches!(auth.action, AuthAction::Redirect { .. }),
            "Expected AuthAction::Redirect"
        );
        let AuthAction::Redirect { url } = auth.action else {
            return;
        };
        assert!(
            url.contains("code_challenge="),
            "Missing code_challenge: {url}"
        );
        assert!(
            url.contains("code_challenge_method=S256"),
            "Missing code_challenge_method=S256: {url}"
        );
        assert!(
            !auth.code_verifier.is_empty(),
            "code_verifier must not be empty for OIDC"
        );

        // Verify code_challenge = BASE64URL(SHA256(code_verifier))
        let expected_digest =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, auth.code_verifier.as_bytes());
        let expected_challenge = URL_SAFE_NO_PAD.encode(expected_digest.as_ref());
        assert!(
            url.contains(&format!("code_challenge={expected_challenge}")),
            "code_challenge does not match SHA256(code_verifier): {url}"
        );
    }

    #[test]
    fn initiate_auth_saml_code_verifier_is_empty() {
        let saml_provider =
            make_saml_provider_with_endpoints(Some("https://idp.example.com/sso"), None);
        let idp = ConfiguredIdp::Saml(saml_provider);
        let config = test_config();

        let auth = idp.initiate_auth(&config.base_url).unwrap();
        assert!(
            auth.code_verifier.is_empty(),
            "SAML should have empty code_verifier"
        );
    }

    // =========================================================================
    // SSO URL scheme validation tests
    // =========================================================================

    #[test]
    fn initiate_auth_saml_javascript_scheme_rejected() {
        let saml_provider = make_saml_provider_with_endpoints(Some("javascript:alert(1)"), None);
        let idp = ConfiguredIdp::Saml(saml_provider);
        let config = test_config();

        let err = idp.initiate_auth(&config.base_url).unwrap_err();
        assert!(
            err.to_string().contains("disallowed scheme"),
            "Expected disallowed scheme error, got: {err}"
        );
    }

    #[test]
    fn initiate_auth_saml_data_scheme_rejected() {
        let saml_provider =
            make_saml_provider_with_endpoints(Some("data:text/html,<h1>hi</h1>"), None);
        let idp = ConfiguredIdp::Saml(saml_provider);
        let config = test_config();

        let err = idp.initiate_auth(&config.base_url).unwrap_err();
        assert!(
            err.to_string().contains("disallowed scheme"),
            "Expected disallowed scheme error, got: {err}"
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
    // form_action_origins tests
    // =========================================================================

    fn make_saml_provider(
        sso_post_url: Option<&str>,
        sso_redirect_url: Option<&str>,
    ) -> saml::SamlProvider {
        make_saml_provider_with_endpoints(sso_post_url, sso_redirect_url)
    }

    #[test]
    fn form_action_origins_oidc_single() {
        let provider = make_oidc_provider("https://accounts.google.com/o/oauth2/v2/auth");
        let origin = provider.form_action_origin().unwrap();
        assert_eq!(origin.as_str(), "https://accounts.google.com");
    }

    #[test]
    fn form_action_origins_oidc_custom_port() {
        let provider = make_oidc_provider(
            "https://idp.example.com:8443/realms/x/protocol/openid-connect/auth",
        );
        let origin = provider.form_action_origin().unwrap();
        assert_eq!(origin.as_str(), "https://idp.example.com:8443");
    }

    #[test]
    fn form_action_origins_saml_post_only() {
        let provider = make_saml_provider(Some("https://idp.example.com/sso/post"), None);
        let origins = provider.form_action_origins();
        assert_eq!(origins.len(), 1);
        assert_eq!(origins[0].as_str(), "https://idp.example.com");
    }

    #[test]
    fn form_action_origins_saml_redirect_only() {
        let provider = make_saml_provider(None, Some("https://idp.example.com/sso/redirect"));
        let origins = provider.form_action_origins();
        assert_eq!(origins.len(), 1);
        assert_eq!(origins[0].as_str(), "https://idp.example.com");
    }

    #[test]
    fn form_action_origins_saml_dedup_same_host() {
        let provider = make_saml_provider(
            Some("https://idp.example.com/sso/post"),
            Some("https://idp.example.com/sso/redirect"),
        );
        let origins = provider.form_action_origins();
        assert_eq!(origins.len(), 1, "duplicate origins should be collapsed");
        assert_eq!(origins[0].as_str(), "https://idp.example.com");
    }

    #[test]
    fn form_action_origins_saml_two_distinct_hosts() {
        let provider = make_saml_provider(
            Some("https://idp-a.example.com/sso/post"),
            Some("https://idp-b.example.com/sso/redirect"),
        );
        let origins = provider.form_action_origins();
        let serialized: Vec<&str> = origins
            .iter()
            .map(crate::infra::csp::CspOrigin::as_str)
            .collect();
        assert_eq!(origins.len(), 2);
        assert!(serialized.contains(&"https://idp-a.example.com"));
        assert!(serialized.contains(&"https://idp-b.example.com"));
    }
}
