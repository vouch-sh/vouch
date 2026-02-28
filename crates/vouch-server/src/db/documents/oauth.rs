// SPDX-License-Identifier: BUSL-1.1
//! OAuth client and related document types.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

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
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "organization" => Ok(Self::Organization),
            "personal" => Ok(Self::Personal),
            "public" => Ok(Self::Public),
            _ => Err(format!("Unknown access scope: {s}")),
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
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "web" => Ok(Self::Web),
            "native" => Ok(Self::Native),
            "spa" => Ok(Self::Spa),
            "service" => Ok(Self::Service),
            _ => Err(format!("Unknown OAuth client type: {s}")),
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
        }
    }
}

impl std::str::FromStr for TokenEndpointAuthMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "client_secret_basic" => Ok(Self::ClientSecretBasic),
            "client_secret_post" => Ok(Self::ClientSecretPost),
            "private_key_jwt" => Ok(Self::PrivateKeyJwt),
            "none" => Ok(Self::None),
            _ => Err(format!("Unknown token endpoint auth method: {s}")),
        }
    }
}

impl std::fmt::Display for TokenEndpointAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
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
    pub jwks: Option<String>,
    pub jwks_uri: Option<String>,
    pub jwks_uri_cached_at: Option<Timestamp>,
    pub jwks_uri_cache: Option<String>,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// RFC 9101 request object signing algorithm.
    pub request_object_signing_alg: Option<String>,
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
    pub registration_metadata: Option<String>,
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
pub struct TokenExchangeDoc {
    pub subject_user_id: String,
    pub subject_token_hash: String,
    pub actor_user_id: Option<String>,
    pub issued_token_hash: String,
    pub requested_audience: Option<String>,
    pub granted_scope: Option<String>,
    pub expires_at: Timestamp,
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

/// A delegation policy for token exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationPolicyDoc {
    pub name: String,
    pub grantor_pattern: String,
    pub grantee_pattern: String,
    pub allowed_scopes: Option<String>,
    pub max_ttl_seconds: Option<i32>,
    pub enabled: bool,
}

impl DocumentType for DelegationPolicyDoc {
    const DOC_TYPE: &'static str = "delegation_policy";

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![IndexEntry {
            field: "enabled",
            value: self.enabled.to_string(),
        }]
    }
}
