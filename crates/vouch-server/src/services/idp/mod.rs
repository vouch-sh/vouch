// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Upstream identity provider abstraction.
//!
//! Supports OIDC discovery and provider-specific UI branding.
//! Structured to support adding SAML in the future.

pub mod icons;
pub mod oidc;

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

/// Configured upstream identity provider.
#[derive(Debug)]
pub enum UpstreamIdp {
    Oidc(oidc::OidcProvider),
    // Saml(SamlProvider),  // Phase 2
}

impl UpstreamIdp {
    /// Build the full authorization URL for redirecting the user.
    ///
    /// Uses `url::Url::query_pairs_mut()` to safely handle endpoints
    /// that may already contain query parameters (RFC 6749 Section 3.1).
    #[must_use]
    pub fn authorization_url(
        &self,
        client_id: &str,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
    ) -> String {
        match self {
            Self::Oidc(p) => {
                let mut url = p.authorization_endpoint.clone();
                url.query_pairs_mut()
                    .append_pair("client_id", client_id)
                    .append_pair("redirect_uri", redirect_uri)
                    .append_pair("response_type", "code")
                    .append_pair("scope", "openid email")
                    .append_pair("state", state)
                    .append_pair("nonce", nonce)
                    .append_pair("prompt", "login");
                url.to_string()
            }
        }
    }

    /// Get the token endpoint URL.
    #[must_use]
    pub fn token_endpoint(&self) -> &url::Url {
        match self {
            Self::Oidc(p) => &p.token_endpoint,
        }
    }

    /// Detect the IdP brand for UI display.
    #[must_use]
    pub fn brand(&self) -> IdpBrand {
        match self {
            Self::Oidc(p) => IdpBrand::from_issuer(&p.issuer),
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
    #![allow(clippy::unwrap_used)]

    use super::*;

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

    #[test]
    fn authorization_url_encodes_params() {
        let provider = oidc::OidcProvider {
            issuer: "https://accounts.google.com".to_string(),
            authorization_endpoint: url::Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
                .unwrap(),
            token_endpoint: url::Url::parse("https://oauth2.googleapis.com/token").unwrap(),
            jwks_uri: url::Url::parse("https://www.googleapis.com/oauth2/v3/certs").unwrap(),
        };
        let idp = UpstreamIdp::Oidc(provider);

        let url = idp.authorization_url(
            "my-client",
            "https://example.com/callback",
            "state123",
            "nonce456",
        );

        assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        assert!(url.contains("client_id=my-client"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("scope=openid+email"));
        assert!(url.contains("state=state123"));
        assert!(url.contains("nonce=nonce456"));
        assert!(url.contains("prompt=login"));
    }

    #[test]
    fn authorization_url_handles_existing_query_params() {
        let provider = oidc::OidcProvider {
            issuer: "https://example.com".to_string(),
            authorization_endpoint: url::Url::parse("https://example.com/auth?existing=param")
                .unwrap(),
            token_endpoint: url::Url::parse("https://example.com/token").unwrap(),
            jwks_uri: url::Url::parse("https://example.com/jwks").unwrap(),
        };
        let idp = UpstreamIdp::Oidc(provider);

        let url = idp.authorization_url("c", "r", "s", "n");

        // Should preserve existing params and append new ones
        assert!(url.contains("existing=param"));
        assert!(url.contains("client_id=c"));
    }

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
