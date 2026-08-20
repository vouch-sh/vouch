// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OAuth client and related document types.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::db::document_type::{DocumentType, IndexEntry};

// ============================================================================
// Enums
// ============================================================================

/// OAuth 2.0 access scope for a client application.
///
/// Controls who can authenticate with the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum AccessScope {
    #[serde(rename = "organization")]
    Organization,
    #[default]
    #[serde(rename = "personal")]
    Personal,
    #[serde(rename = "public")]
    Public,
}

/// Parse errors for OAuth document enums.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OAuthDocumentParseError {
    #[error("Unknown access scope: {0}")]
    AccessScope(String),
    #[error("Unknown OAuth client type: {0}")]
    ClientType(String),
    #[error("Unknown token endpoint auth method: {0}")]
    TokenEndpointAuthMethod(String),
    #[error("Unknown JWS algorithm: {0}")]
    JwsAlgorithm(String),
}

impl AccessScope {
    /// Returns the canonical string representation used in the wire format.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Organization => "organization",
            Self::Personal => "personal",
            Self::Public => "public",
        }
    }

    /// Returns a capitalized display name for UI rendering.
    #[must_use]
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Organization => "Organization",
            Self::Personal => "Personal",
            Self::Public => "Public",
        }
    }

    /// Returns a human-readable description of the scope's behavior.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::Organization => "Only users in your organization can authenticate",
            Self::Personal => "Only you can authenticate",
            Self::Public => "Any Vouch user can authenticate",
        }
    }
}

impl std::str::FromStr for AccessScope {
    type Err = OAuthDocumentParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("organization") {
            Ok(Self::Organization)
        } else if s.eq_ignore_ascii_case("personal") {
            Ok(Self::Personal)
        } else if s.eq_ignore_ascii_case("public") {
            Ok(Self::Public)
        } else {
            Err(OAuthDocumentParseError::AccessScope(s.to_string()))
        }
    }
}

impl std::fmt::Display for AccessScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// OAuth 2.0 client application type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OAuthClientType {
    #[serde(rename = "web")]
    Web,
    #[serde(rename = "native")]
    Native,
    #[serde(rename = "spa")]
    Spa,
    #[serde(rename = "service")]
    Service,
}

impl OAuthClientType {
    /// Returns the canonical string representation used in the wire format.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Native => "native",
            Self::Spa => "spa",
            Self::Service => "service",
        }
    }

    /// Returns `true` if this client type requires a client secret.
    #[must_use]
    pub fn requires_secret(&self) -> bool {
        matches!(self, Self::Web | Self::Service)
    }

    /// Returns `true` if this client type requires PKCE.
    #[must_use]
    pub fn requires_pkce(&self) -> bool {
        matches!(self, Self::Native | Self::Spa)
    }
}

impl std::str::FromStr for OAuthClientType {
    type Err = OAuthDocumentParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("web") {
            Ok(Self::Web)
        } else if s.eq_ignore_ascii_case("native") {
            Ok(Self::Native)
        } else if s.eq_ignore_ascii_case("spa") {
            Ok(Self::Spa)
        } else if s.eq_ignore_ascii_case("service") {
            Ok(Self::Service)
        } else {
            Err(OAuthDocumentParseError::ClientType(s.to_string()))
        }
    }
}

impl std::fmt::Display for OAuthClientType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Token endpoint authentication method (RFC 7591).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TokenEndpointAuthMethod {
    #[default]
    #[serde(rename = "client_secret_basic")]
    ClientSecretBasic,
    #[serde(rename = "client_secret_post")]
    ClientSecretPost,
    #[serde(rename = "private_key_jwt")]
    PrivateKeyJwt,
    #[serde(rename = "none")]
    None,
    /// RFC 8705 Section 2.1.1: mTLS with PKI certificate.
    #[serde(rename = "tls_client_auth")]
    TlsClientAuth,
    /// RFC 8705 Section 2.2.2: mTLS with self-signed certificate.
    #[serde(rename = "self_signed_tls_client_auth")]
    SelfSignedTlsClientAuth,
}

impl TokenEndpointAuthMethod {
    /// Returns the canonical string representation used in the wire format.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::PrivateKeyJwt => "private_key_jwt",
            Self::None => "none",
            Self::TlsClientAuth => "tls_client_auth",
            Self::SelfSignedTlsClientAuth => "self_signed_tls_client_auth",
        }
    }
}

impl std::str::FromStr for TokenEndpointAuthMethod {
    type Err = OAuthDocumentParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("client_secret_basic") {
            Ok(Self::ClientSecretBasic)
        } else if s.eq_ignore_ascii_case("client_secret_post") {
            Ok(Self::ClientSecretPost)
        } else if s.eq_ignore_ascii_case("private_key_jwt") {
            Ok(Self::PrivateKeyJwt)
        } else if s.eq_ignore_ascii_case("none") {
            Ok(Self::None)
        } else if s.eq_ignore_ascii_case("tls_client_auth") {
            Ok(Self::TlsClientAuth)
        } else if s.eq_ignore_ascii_case("self_signed_tls_client_auth") {
            Ok(Self::SelfSignedTlsClientAuth)
        } else {
            Err(OAuthDocumentParseError::TokenEndpointAuthMethod(
                s.to_string(),
            ))
        }
    }
}

impl std::fmt::Display for TokenEndpointAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// JWS signing algorithm for OAuth 2.0 / OIDC.
///
/// Only asymmetric algorithms are supported. Symmetric (HS*)
/// and `none` are rejected at registration time via serde deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum JwsAlgorithm {
    /// ECDSA using P-256 and SHA-256.
    #[default]
    #[serde(rename = "ES256")]
    Es256,
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    #[serde(rename = "RS256")]
    Rs256,
    /// RSASSA-PSS using SHA-256.
    #[serde(rename = "PS256")]
    Ps256,
    /// Edwards-curve Digital Signature Algorithm.
    #[serde(rename = "EdDSA")]
    EdDsa,
}

impl JwsAlgorithm {
    /// Returns the canonical string representation used in the wire format.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Rs256 => "RS256",
            Self::Ps256 => "PS256",
            Self::EdDsa => "EdDSA",
        }
    }
}

impl std::str::FromStr for JwsAlgorithm {
    type Err = OAuthDocumentParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ES256" => Ok(Self::Es256),
            "RS256" => Ok(Self::Rs256),
            "PS256" => Ok(Self::Ps256),
            "EdDSA" => Ok(Self::EdDsa),
            _ => Err(OAuthDocumentParseError::JwsAlgorithm(s.to_string())),
        }
    }
}

impl std::fmt::Display for JwsAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// OAuth 2.0 authorization response mode.
///
/// Default is `Query` (plain query parameters). JARM modes wrap the
/// response in a signed JWT delivered as a single `response` parameter.
/// `FormPost` delivers parameters via an HTML form auto-submit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ResponseMode {
    /// Standard query-string response (RFC 6749 Section 4.1.2).
    #[default]
    #[serde(rename = "query")]
    Query,
    /// JARM: response parameters in a signed JWT via query string.
    /// Accepts both `"jwt"` and `"query.jwt"` on the wire.
    #[serde(rename = "jwt", alias = "query.jwt")]
    Jwt,
    /// OAuth 2.0 Form Post Response Mode.
    /// Delivers response parameters via an HTML form auto-submit.
    #[serde(rename = "form_post")]
    FormPost,
}

impl ResponseMode {
    /// Every accepted `response_mode` string, in the order shown to clients.
    ///
    /// [`parse`](Self::parse) and [`supported_values`](Self::supported_values)
    /// both read this table, so an accepted value cannot be missing from the
    /// error message that lists them and a listed value cannot be
    /// unparseable. Keeping them as separate literals is how the message came
    /// to omit `form_post` while the parser accepted it.
    ///
    /// `jwt` and `query.jwt` are aliases for the same mode (JARM), so this is
    /// a table of accepted strings rather than of variants.
    const ACCEPTED: &'static [(&'static str, Self)] = &[
        ("query", Self::Query),
        ("form_post", Self::FormPost),
        ("jwt", Self::Jwt),
        ("query.jwt", Self::Jwt),
    ];

    /// Parse a raw `response_mode` string, returning `None` for
    /// unrecognized values so the caller can produce an error.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ACCEPTED
            .iter()
            .find(|(value, _)| *value == s)
            .map(|(_, mode)| *mode)
    }

    /// Comma-separated list of accepted values, for error messages.
    #[must_use]
    pub fn supported_values() -> String {
        Self::ACCEPTED
            .iter()
            .map(|(value, _)| *value)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// FAPI 2.0 compliance profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum FapiProfile {
    #[default]
    #[serde(rename = "none")]
    None,
    #[serde(rename = "fapi2_security")]
    Fapi2Security,
}

impl FapiProfile {
    /// Returns the canonical string representation used in the wire format.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Fapi2Security => "fapi2_security",
        }
    }
}

/// How the client was registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum RegistrationSource {
    #[default]
    #[serde(rename = "manual")]
    Manual,
    #[serde(rename = "dynamic")]
    Dynamic,
}

impl RegistrationSource {
    /// Returns the canonical string representation used in the wire format.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Dynamic => "dynamic",
        }
    }
}

// ============================================================================
// Document Types
// ============================================================================

/// An OAuth 2.0 client application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClientDoc {
    pub user_id: Option<String>,
    pub client_id: String,
    pub name: String,
    pub description: Option<String>,
    pub application_type: OAuthClientType,
    pub redirect_uris: Vec<String>,
    pub active: bool,
    pub access_scope: AccessScope,
    pub org_id: Option<String>,
    pub resource_uris: Vec<String>,
    /// Inline JWKS JSON (RFC 7523).
    pub jwks: Option<serde_json::Value>,
    pub jwks_uri: Option<String>,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// RFC 9101 request object signing algorithm.
    pub request_object_signing_alg: Option<JwsAlgorithm>,
    /// RFC 9101 require signed request objects.
    pub require_signed_request_object: Option<bool>,
    pub fapi_profile: FapiProfile,
    /// RFC 9449 DPoP-bound access tokens.
    pub dpop_bound_access_tokens: bool,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    /// RFC 7591 software identifier.
    pub software_id: Option<String>,
    pub software_version: Option<String>,
    pub registration_source: Option<RegistrationSource>,
    /// RFC 7592 registration access token hash.
    pub registration_access_token_hash: Option<String>,
    /// RFC 7591 cosmetic metadata (JSON).
    pub registration_metadata: Option<serde_json::Value>,
    /// OIDC Core Section 3.1.3.7: ID token signing algorithm.
    /// New registrations default to "RS256" per OIDC Core spec, but the serde
    /// default is "ES256" for backward compatibility with existing client records
    /// that were created before RS256 support was added.
    #[serde(default)]
    pub id_token_signed_response_alg: JwsAlgorithm,
    /// RFC 8705 Section 2.1.1: subject DN for tls_client_auth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_client_auth_subject_dn: Option<String>,
    /// RFC 8705 Section 2.1.1: SAN DNS name for tls_client_auth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_client_auth_san_dns: Option<String>,
    /// RFC 8705 Section 2.1.1: SAN URI for tls_client_auth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_client_auth_san_uri: Option<String>,
    /// RFC 8705 Section 2.1.1: SAN IP for tls_client_auth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_client_auth_san_ip: Option<String>,
    /// RFC 8705 Section 2.1.1: SAN email for tls_client_auth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_client_auth_san_email: Option<String>,
    /// RFC 8705 Section 3: certificate-bound access tokens.
    #[serde(default)]
    pub tls_client_certificate_bound_access_tokens: bool,
    /// JARM (oauth-v2-jarm) Section 2.3.2: signing algorithm for
    /// authorization responses. `None` = server default (RS256 or ES256).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_signed_response_alg: Option<JwsAlgorithm>,
    /// RFC 9701 Section 6.1: Introspection response signing algorithm.
    ///
    /// When set, introspection returns a signed JWT instead of plain JSON.
    /// Only `Es256` is supported (the server's primary signing key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introspection_signed_response_alg: Option<JwsAlgorithm>,
    /// OIDC Core Section 5.3.4: UserInfo response signing algorithm.
    ///
    /// When set, the userinfo endpoint returns a signed JWT (content-type: application/jwt)
    /// instead of plain JSON (content-type: application/json).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_signed_response_alg: Option<JwsAlgorithm>,
    /// OIDC Core Section 6.2: Pre-registered request_uri allowlist.
    ///
    /// When `Some`, only the listed HTTPS URLs are accepted as `request_uri` values.
    /// When `None`, any HTTPS `request_uri` is accepted (no allowlist enforced).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_uris: Option<Vec<String>>,
    /// RP-Initiated Logout 1.0 Section 2: Registered post-logout redirect URIs.
    ///
    /// When `Some`, only the listed URIs are accepted as `post_logout_redirect_uri`
    /// values in the end-session request. Absent field (legacy records) deserializes
    /// to `None` — no migration needed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uris: Option<Vec<String>>,
}

impl DocumentType for OAuthClientDoc {
    const DOC_TYPE: &'static str = "oauth_client";

    fn index_entries(&self) -> Vec<IndexEntry> {
        let mut entries = vec![IndexEntry {
            field: "client_id",
            value: self.client_id.clone(),
        }];
        if let Some(ref user_id) = self.user_id {
            entries.push(IndexEntry {
                field: "user_id",
                value: user_id.clone(),
            });
        }
        if let Some(ref org_id) = self.org_id {
            entries.push(IndexEntry {
                field: "org_id",
                value: org_id.clone(),
            });
        }
        if let Some(ref software_id) = self.software_id {
            entries.push(IndexEntry {
                field: "software_id",
                value: software_id.clone(),
            });
        }
        if let Some(ref rat_hash) = self.registration_access_token_hash {
            entries.push(IndexEntry {
                field: "registration_access_token_hash",
                value: rat_hash.clone(),
            });
        }
        entries
    }
}

/// An OAuth client secret (hashed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClientSecretDoc {
    pub oauth_client_id: String,
    pub secret_hash: String,
    pub description: Option<String>,
    pub expires_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
}

impl DocumentType for OAuthClientSecretDoc {
    const DOC_TYPE: &'static str = "oauth_client_secret";

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![
            IndexEntry {
                field: "oauth_client_id",
                value: self.oauth_client_id.clone(),
            },
            IndexEntry {
                field: "secret_hash",
                value: self.secret_hash.clone(),
            },
        ]
    }

    fn expires_at(&self) -> Option<Timestamp> {
        self.expires_at
    }
}

/// A token exchange record (RFC 8693).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TokenExchangeDoc {
    pub(crate) subject_user_id: String,
    pub(crate) subject_token_hash: String,
    pub(crate) actor_user_id: Option<String>,
    pub(crate) issued_token_hash: String,
    pub(crate) requested_audience: Option<String>,
    pub(crate) granted_scope: Option<String>,
    pub(crate) expires_at: Timestamp,
}

impl DocumentType for TokenExchangeDoc {
    const DOC_TYPE: &'static str = "token_exchange";

    fn index_entries(&self) -> Vec<IndexEntry> {
        let mut entries = vec![IndexEntry {
            field: "subject_user_id",
            value: self.subject_user_id.clone(),
        }];
        if let Some(ref actor) = self.actor_user_id {
            entries.push(IndexEntry {
                field: "actor_user_id",
                value: actor.clone(),
            });
        }
        entries
    }

    fn expires_at(&self) -> Option<Timestamp> {
        Some(self.expires_at)
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::{
        AccessScope, JwsAlgorithm, OAuthClientType, OAuthDocumentParseError,
        TokenEndpointAuthMethod,
    };
    use std::str::FromStr;

    #[test]
    fn test_access_scope_from_str_case_insensitive() {
        assert_eq!(
            AccessScope::from_str("ORGANIZATION"),
            Ok(AccessScope::Organization)
        );
        assert_eq!(AccessScope::from_str("Personal"), Ok(AccessScope::Personal));
        assert_eq!(AccessScope::from_str("public"), Ok(AccessScope::Public));
    }

    #[test]
    fn test_oauth_client_type_from_str_case_insensitive() {
        assert_eq!(OAuthClientType::from_str("WEB"), Ok(OAuthClientType::Web));
        assert_eq!(
            OAuthClientType::from_str("Native"),
            Ok(OAuthClientType::Native)
        );
        assert_eq!(OAuthClientType::from_str("spa"), Ok(OAuthClientType::Spa));
        assert_eq!(
            OAuthClientType::from_str("Service"),
            Ok(OAuthClientType::Service)
        );
    }

    #[test]
    fn test_token_endpoint_auth_method_from_str_typed_error() {
        let result = TokenEndpointAuthMethod::from_str("mtls");
        assert!(result.is_err(), "must reject mtls");
        let err = result.unwrap_err();
        assert_eq!(
            err,
            OAuthDocumentParseError::TokenEndpointAuthMethod("mtls".to_string())
        );
        assert_eq!(err.to_string(), "Unknown token endpoint auth method: mtls");
    }

    #[test]
    fn test_jws_algorithm_round_trip() {
        for (s, variant) in &[
            ("ES256", JwsAlgorithm::Es256),
            ("RS256", JwsAlgorithm::Rs256),
            ("PS256", JwsAlgorithm::Ps256),
            ("EdDSA", JwsAlgorithm::EdDsa),
        ] {
            assert_eq!(
                JwsAlgorithm::from_str(s).unwrap(),
                *variant,
                "from_str({s})"
            );
            assert_eq!(variant.as_str(), *s, "as_str({s})");
            assert_eq!(variant.to_string(), *s, "Display({s})");
        }
    }

    #[test]
    fn test_jws_algorithm_default_is_es256() {
        assert_eq!(JwsAlgorithm::default(), JwsAlgorithm::Es256);
    }

    #[test]
    fn test_jws_algorithm_from_str_unknown() {
        let result = JwsAlgorithm::from_str("HS256");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            OAuthDocumentParseError::JwsAlgorithm("HS256".to_string())
        );
    }

    #[test]
    fn test_id_token_signed_response_alg_serde_default() {
        // Existing client records without id_token_signed_response_alg should
        // default to "ES256" for backward compatibility (not "RS256").
        let json = r#"{
            "user_id": null,
            "client_id": "test-client",
            "name": "Test",
            "description": null,
            "application_type": "web",
            "redirect_uris": [],
            "active": true,
            "access_scope": "public",
            "org_id": null,
            "resource_uris": [],
            "jwks": null,
            "jwks_uri": null,
            "token_endpoint_auth_method": "none",
            "request_object_signing_alg": null,
            "require_signed_request_object": null,
            "fapi_profile": "none",
            "dpop_bound_access_tokens": false,
            "grant_types": null,
            "response_types": null,
            "software_id": null,
            "software_version": null,
            "registration_source": null,
            "registration_access_token_hash": null,
            "registration_metadata": null
        }"#;

        let doc: super::OAuthClientDoc = serde_json::from_str(json)
            .expect("Should deserialize OAuthClientDoc without id_token_signed_response_alg");
        assert_eq!(
            doc.id_token_signed_response_alg,
            JwsAlgorithm::Es256,
            "Missing field should default to ES256 for backward compatibility"
        );
    }

    /// Every value the error message advertises must actually parse, and every
    /// accepted value must be advertised. This is the invariant that broke
    /// when the message and the parser were separate literals: the message
    /// omitted `form_post` while the parser accepted it.
    #[test]
    fn every_advertised_response_mode_parses() {
        use super::ResponseMode;
        let advertised = ResponseMode::supported_values();
        assert!(!advertised.is_empty(), "message must list something");
        for value in advertised.split(", ") {
            assert!(
                ResponseMode::parse(value).is_some(),
                "advertised response_mode {value:?} does not parse"
            );
        }
        for (value, _) in ResponseMode::ACCEPTED {
            assert!(
                advertised.contains(value),
                "accepted response_mode {value:?} is missing from the advertised list"
            );
        }
        assert!(
            ResponseMode::parse("fragment").is_none(),
            "unsupported values must still be rejected"
        );
    }
}
