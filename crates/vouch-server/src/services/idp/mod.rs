// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Upstream identity provider abstraction.
//!
//! Supports OIDC and SAML (stub) upstream identity providers with
//! protocol-agnostic auth initiation and provider-specific UI branding.

pub(crate) mod icons;
pub(crate) mod oidc;
pub(crate) mod saml;

pub(crate) use oidc::ConfiguredOidcProvider;

/// Known identity provider for UI branding.
#[derive(Debug)]
pub(crate) enum IdpBrand {
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
    pub(crate) fn from_issuer(issuer: &str) -> Self {
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
    pub(crate) fn from_entity_id(entity_id: &str) -> Self {
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
    pub(crate) fn display_name(&self) -> &'static str {
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
    pub(crate) fn svg_icon(&self) -> &'static str {
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
pub(crate) enum AuthAction {
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
pub(crate) struct AuthRequest {
    /// How to send the user to the IdP.
    pub(crate) action: AuthAction,
    /// Opaque state token (stored as `state` in oidc_state table).
    /// OIDC: random base64url token. SAML: RelayState token.
    pub(crate) state_key: String,
    /// Protocol-specific request identifier (stored as `nonce` in DB).
    /// OIDC: nonce for ID token binding. SAML: AuthnRequest ID.
    pub(crate) nonce: String,
    /// PKCE code_verifier (RFC 7636). Only set for OIDC flows.
    /// Empty for SAML. Stored in DB and sent during token exchange.
    pub(crate) code_verifier: String,
}

/// Configured upstream identity provider.
///
/// OIDC providers are stored separately in `AppState::oidc_providers` as
/// `ConfiguredOidcProvider` values. This enum only covers SAML, which is
/// still the single-provider case.
#[derive(Debug)]
pub(crate) enum UpstreamIdp {
    Saml(saml::SamlProvider),
}

impl UpstreamIdp {
    /// Initiate authentication with the upstream SAML IdP.
    ///
    /// Generates state and nonce internally, builds the appropriate auth
    /// action (redirect URL or POST form for SAML POST binding), and returns
    /// the full `AuthRequest` to store state and redirect/render.
    ///
    /// # Errors
    ///
    /// Returns an error if random byte generation fails or if the SSO URL
    /// has a disallowed scheme.
    pub(crate) fn initiate_auth(
        &self,
        config: &crate::config::ServerConfig,
    ) -> Result<AuthRequest, anyhow::Error> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let _ = config; // config retained in signature for future use
        match self {
            Self::Saml(saml) => {
                let authn = saml::authn_request::build_authn_request(saml)
                    .map_err(|e| anyhow::anyhow!("Failed to build SAML AuthnRequest: {e}"))?;
                // state_key = RelayState token (browser-carried through IdP)
                // nonce = AuthnRequest ID (for InResponseTo validation)
                let state_key = URL_SAFE_NO_PAD.encode(crate::crypto::generate_random_bytes(32)?);
                // Validate SSO URL scheme (reject javascript:, data:, etc.)
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
                    // Redirect binding: append SAMLRequest and RelayState to URL
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
        }
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

    /// Extract the email domain from an ID token.
    ///
    /// For Google issuers, only the Workspace `hd` claim is used so consumer
    /// accounts do not get grouped into a shared public-email organization.
    /// For non-Google issuers, falls back to extracting the domain from email.
    fn extract_email_domain<'a>(
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

    #[test]
    fn initiate_auth_saml_post_binding_returns_post_form() {
        let saml_provider = saml::SamlProvider {
            idp_metadata: saml::IdpMetadata {
                entity_id: "https://idp.example.com/saml".to_string(),
                sso_post_url: Some("https://idp.example.com/sso".to_string()),
                sso_redirect_url: None,
                signing_certificates: vec![],
            },
            sp_entity_id: "https://vouch.example.com".to_string(),
            acs_url: "https://vouch.example.com/saml/acs".to_string(),
            email_attribute: None,
            domain_attribute: None,
        };
        let idp = UpstreamIdp::Saml(saml_provider);
        let config = test_config();

        let result = idp.initiate_auth(&config).unwrap();
        assert!(
            matches!(result.action, AuthAction::PostForm { .. }),
            "SAML with POST binding should return PostForm action"
        );
        assert!(!result.state_key.is_empty(), "state_key must not be empty");
        assert!(!result.nonce.is_empty(), "nonce must not be empty");
    }

    #[test]
    fn initiate_auth_saml_redirect_binding_returns_redirect() {
        let saml_provider = saml::SamlProvider {
            idp_metadata: saml::IdpMetadata {
                entity_id: "https://idp.example.com/saml".to_string(),
                sso_post_url: None,
                sso_redirect_url: Some("https://idp.example.com/sso/redirect".to_string()),
                signing_certificates: vec![],
            },
            sp_entity_id: "https://vouch.example.com".to_string(),
            acs_url: "https://vouch.example.com/saml/acs".to_string(),
            email_attribute: None,
            domain_attribute: None,
        };
        let idp = UpstreamIdp::Saml(saml_provider);
        let config = test_config();

        let result = idp.initiate_auth(&config).unwrap();
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
        let saml_provider = saml::SamlProvider {
            idp_metadata: saml::IdpMetadata {
                entity_id: "https://idp.example.com/saml".to_string(),
                sso_post_url: Some("https://idp.example.com/sso".to_string()),
                sso_redirect_url: None,
                signing_certificates: vec![],
            },
            sp_entity_id: "https://vouch.example.com".to_string(),
            acs_url: "https://vouch.example.com/saml/acs".to_string(),
            email_attribute: None,
            domain_attribute: None,
        };
        let idp = UpstreamIdp::Saml(saml_provider);
        let config = test_config();

        let auth = idp.initiate_auth(&config).unwrap();
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
        let saml_provider = saml::SamlProvider {
            idp_metadata: saml::IdpMetadata {
                entity_id: "https://idp.example.com/saml".to_string(),
                sso_post_url: Some("javascript:alert(1)".to_string()),
                sso_redirect_url: None,
                signing_certificates: vec![],
            },
            sp_entity_id: "https://vouch.example.com".to_string(),
            acs_url: "https://vouch.example.com/saml/acs".to_string(),
            email_attribute: None,
            domain_attribute: None,
        };
        let idp = UpstreamIdp::Saml(saml_provider);
        let config = test_config();

        let err = idp.initiate_auth(&config).unwrap_err();
        assert!(
            err.to_string().contains("disallowed scheme"),
            "Expected disallowed scheme error, got: {err}"
        );
    }

    #[test]
    fn initiate_auth_saml_data_scheme_rejected() {
        let saml_provider = saml::SamlProvider {
            idp_metadata: saml::IdpMetadata {
                entity_id: "https://idp.example.com/saml".to_string(),
                sso_post_url: Some("data:text/html,<h1>hi</h1>".to_string()),
                sso_redirect_url: None,
                signing_certificates: vec![],
            },
            sp_entity_id: "https://vouch.example.com".to_string(),
            acs_url: "https://vouch.example.com/saml/acs".to_string(),
            email_attribute: None,
            domain_attribute: None,
        };
        let idp = UpstreamIdp::Saml(saml_provider);
        let config = test_config();

        let err = idp.initiate_auth(&config).unwrap_err();
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

    // =========================================================================
    // form_action_origins tests
    // =========================================================================

    fn make_saml_provider(
        sso_post_url: Option<&str>,
        sso_redirect_url: Option<&str>,
    ) -> saml::SamlProvider {
        saml::SamlProvider {
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
