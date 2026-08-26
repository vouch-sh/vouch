// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OAuth Client Application database operations.

use super::audit::{AuditEventFilter, AuditEventKind, AuditStore};
use super::document_type::{Document, DocumentType};
use super::documents::audit::OAuthUsageData;
use super::documents::jwt_assertion_jti::JwtAssertionJtiDoc;
use super::documents::oauth::{
    AccessScope, FapiProfile, JwsAlgorithm, OAuthClientDoc, OAuthClientSecretDoc, OAuthClientType,
    RegistrationSource, TokenEndpointAuthMethod,
};
use super::store::DocumentStore;
use crate::error::ServiceError;
use anyhow::Result;
use axum::http::StatusCode;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// Maximum number of active (non-revoked, non-expired) secrets per OAuth client.
///
/// Enforced inside `create_oauth_client_secret` via an OCC-guarded transaction
/// that version-bumps the owning `OAuthClientDoc`.  Both the guard and the secret
/// insert happen atomically, so concurrent adds collide on the client row and the
/// loser re-reads the updated count before deciding whether to insert or reject.
pub const MAX_ACTIVE_SECRETS: usize = 2;

// ============================================================================
// OAuth Client
// ============================================================================

/// OAuth client application record.
#[derive(Debug)]
pub struct OAuthClient {
    pub id: String,
    pub user_id: Option<String>,
    pub client_id: String,
    pub name: String,
    pub description: Option<String>,
    pub application_type: OAuthClientType,
    pub redirect_uris: Vec<String>,
    pub active: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub last_used_at: Option<Timestamp>,
    pub access_scope: AccessScope,
    pub org_id: Option<String>,
    pub resource_uris: Vec<String>,
    /// RFC 7591 §2 key material, in whichever of the two forms was registered.
    pub keys: Option<ClientKeys>,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    pub request_object_signing_alg: Option<JwsAlgorithm>,
    pub require_signed_request_object: Option<bool>,
    pub fapi_profile: FapiProfile,
    pub dpop_bound_access_tokens: bool,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub software_id: Option<String>,
    pub software_version: Option<String>,
    pub registration_source: Option<RegistrationSource>,
    pub registration_access_token_hash: Option<String>,
    pub registration_metadata: Option<serde_json::Value>,
    pub id_token_signed_response_alg: JwsAlgorithm,
    /// RFC 8705: mTLS subject DN for tls_client_auth.
    pub tls_client_auth_subject_dn: Option<String>,
    /// RFC 8705: mTLS SAN DNS name.
    pub tls_client_auth_san_dns: Option<String>,
    /// RFC 8705: mTLS SAN URI.
    pub tls_client_auth_san_uri: Option<String>,
    /// RFC 8705: mTLS SAN IP.
    pub tls_client_auth_san_ip: Option<String>,
    /// RFC 8705: mTLS SAN email.
    pub tls_client_auth_san_email: Option<String>,
    /// RFC 8705: certificate-bound access tokens.
    pub tls_client_certificate_bound_access_tokens: bool,
    /// JARM: signing algorithm for authorization responses.
    pub authorization_signed_response_alg: Option<JwsAlgorithm>,
    /// RFC 9701: Introspection response signing algorithm.
    ///
    /// When `Some`, the introspection endpoint returns a signed JWT instead of plain JSON.
    pub introspection_signed_response_alg: Option<JwsAlgorithm>,
    /// OIDC Core Section 5.3.4: UserInfo response signing algorithm.
    pub userinfo_signed_response_alg: Option<JwsAlgorithm>,
    /// OIDC Core Section 6.2: Pre-registered request_uri allowlist.
    ///
    /// When `Some`, only the listed HTTPS URLs are accepted as `request_uri` values.
    /// When `None`, any HTTPS `request_uri` is accepted.
    pub request_uris: Option<Vec<String>>,
    /// RP-Initiated Logout 1.0 Section 2: Registered post-logout redirect URIs.
    pub post_logout_redirect_uris: Option<Vec<String>>,
}

/// Old↔new stored-row mapping: rows persisted while secretless client
/// types still fell back to the RFC 7591 §2 default `client_secret_basic`
/// are read as the public-client method `none`. No writer produces
/// `spa`/`native` + `client_secret_basic` deliberately — manual
/// registration derives the method from the application type, and dynamic
/// registration infers `spa`/`native` only when the requested method is
/// `none` (`determine_client_type`).
///
/// RFC 7591 §2 (<https://www.rfc-editor.org/rfc/rfc7591#section-2>):
/// > "none": The client is a public client as defined in OAuth 2.0,
/// > Section 2.1, and does not have a client secret.
fn normalize_stored_auth_method(
    application_type: OAuthClientType,
    stored: TokenEndpointAuthMethod,
) -> TokenEndpointAuthMethod {
    if !application_type.requires_secret() && stored == TokenEndpointAuthMethod::ClientSecretBasic {
        TokenEndpointAuthMethod::None
    } else {
        stored
    }
}

impl From<Document<OAuthClientDoc>> for OAuthClient {
    fn from(doc: Document<OAuthClientDoc>) -> Self {
        Self {
            id: doc.id.clone(),
            user_id: doc.data.user_id,
            client_id: doc.data.client_id,
            name: doc.data.name,
            description: doc.data.description,
            application_type: doc.data.application_type,
            redirect_uris: doc.data.redirect_uris,
            active: doc.data.active,
            created_at: doc.created_at,
            updated_at: doc.updated_at,
            last_used_at: doc.last_used_at,
            access_scope: doc.data.access_scope,
            org_id: doc.data.org_id,
            resource_uris: doc.data.resource_uris,
            keys: stored_client_keys(&doc.id, doc.data.jwks, doc.data.jwks_uri),
            token_endpoint_auth_method: normalize_stored_auth_method(
                doc.data.application_type,
                doc.data.token_endpoint_auth_method,
            ),
            request_object_signing_alg: doc.data.request_object_signing_alg,
            require_signed_request_object: doc.data.require_signed_request_object,
            fapi_profile: doc.data.fapi_profile,
            dpop_bound_access_tokens: doc.data.dpop_bound_access_tokens,
            grant_types: doc.data.grant_types,
            response_types: doc.data.response_types,
            software_id: doc.data.software_id,
            software_version: doc.data.software_version,
            registration_source: doc.data.registration_source,
            registration_access_token_hash: doc.data.registration_access_token_hash,
            registration_metadata: doc.data.registration_metadata,
            id_token_signed_response_alg: doc.data.id_token_signed_response_alg,
            tls_client_auth_subject_dn: doc.data.tls_client_auth_subject_dn,
            tls_client_auth_san_dns: doc.data.tls_client_auth_san_dns,
            tls_client_auth_san_uri: doc.data.tls_client_auth_san_uri,
            tls_client_auth_san_ip: doc.data.tls_client_auth_san_ip,
            tls_client_auth_san_email: doc.data.tls_client_auth_san_email,
            tls_client_certificate_bound_access_tokens: doc
                .data
                .tls_client_certificate_bound_access_tokens,
            authorization_signed_response_alg: doc.data.authorization_signed_response_alg,
            introspection_signed_response_alg: doc.data.introspection_signed_response_alg,
            userinfo_signed_response_alg: doc.data.userinfo_signed_response_alg,
            request_uris: doc.data.request_uris,
            post_logout_redirect_uris: doc.data.post_logout_redirect_uris,
        }
    }
}

impl OAuthClient {
    #[must_use]
    /// Whether `uri` may be redirected to for this client.
    ///
    /// OIDC Core §3.1.2.1 requires the requested URI to "exactly match one of
    /// the Redirection URI values for the Client pre-registered at the OpenID
    /// Provider, with the matching performed as described in Section 6.2.1 of
    /// [RFC3986] (Simple String Comparison)", which is the default here.
    ///
    /// Two departures:
    ///
    /// - A fragment is refused outright. RFC 6749 §3.1.2 says the redirection
    ///   endpoint URI "MUST NOT include a fragment component", so one can
    ///   never be a legitimate target even if it reached storage.
    /// - For loopback IP literals the port is ignored, because RFC 8252 §7.3
    ///   says "The authorization server MUST allow any port to be specified at
    ///   the time of the request for loopback IP redirect URIs, to accommodate
    ///   clients that obtain an available ephemeral port from the operating
    ///   system at the time of the request." Scheme, host, and path must still
    ///   match exactly, and every non-loopback URI keeps simple string
    ///   comparison.
    pub fn is_valid_redirect_uri(&self, uri: &str) -> bool {
        let Ok(requested) = url::Url::parse(uri) else {
            return false;
        };
        if requested.fragment().is_some() {
            return false;
        }
        self.redirect_uris.iter().any(|registered| {
            registered == uri || loopback_matches_ignoring_port(registered, &requested)
        })
    }

    #[must_use]
    pub fn is_valid_resource_uri(&self, uri: &str) -> bool {
        if self.resource_uris.is_empty() {
            return true;
        }
        self.resource_uris.iter().any(|u| u == uri)
    }

    #[must_use]
    pub fn is_fapi(&self) -> bool {
        self.fapi_profile != FapiProfile::None
    }

    /// Return `true` when `uri` is in the client's registered
    /// `post_logout_redirect_uris` (exact match, case-sensitive).
    ///
    /// Returns `false` when the list is absent or does not contain `uri`.
    #[must_use]
    pub fn is_valid_post_logout_redirect_uri(&self, uri: &str) -> bool {
        self.post_logout_redirect_uris
            .as_deref()
            .is_some_and(|uris| uris.iter().any(|u| u == uri))
    }
}

// ============================================================================
// Post-logout redirect URI validation helpers (shared between handlers and
// services so the per-URI rule and the cap live in exactly one place)
// ============================================================================

/// Maximum number of post-logout redirect URIs an application may register.
///
/// Enforced both at RFC 7591 dynamic registration time (services layer) and at
/// self-service application creation time (handlers layer).
pub const MAX_POST_LOGOUT_REDIRECT_URIS: usize = 10;

/// Whether a registered loopback IP redirect URI matches a requested one that
/// differs only in port — the RFC 8252 §7.3 any-port rule.
///
/// Everything but the port must match exactly, and both sides must be `http`
/// on a loopback IP literal, so this can never relax matching for a URI the
/// rule does not cover.
fn loopback_matches_ignoring_port(registered: &str, requested: &url::Url) -> bool {
    let Ok(registered) = url::Url::parse(registered) else {
        return false;
    };
    registered.scheme() == "http"
        && requested.scheme() == "http"
        && registered.host_str().is_some_and(is_loopback_ip_literal)
        && registered.host_str() == requested.host_str()
        && registered.path() == requested.path()
        && registered.query() == requested.query()
}

/// The hosts an `http://` redirect URI may use.
///
/// OIDC Registration §2 and OIDC Core §3.1.2.1 both name exactly this set:
/// "loopback URLs use "localhost" or the IP loopback literals "127.0.0.1" or
/// "[::1]" as the hostname".
///
/// Deliberately not [`vouch_common::is_loopback_host`], which also accepts
/// `host.docker.internal` and all of `127.0.0.0/8`. That helper exists for the
/// dev-mode RP-ID and origin checks; `host.docker.internal` resolves off-device,
/// which would break the assumption RFC 8252 §8.3 rests on — "This is
/// acceptable for loopback interface redirect URIs as the HTTP request never
/// leaves the device."
#[must_use]
pub fn is_loopback_redirect_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

/// The IP literals RFC 8252 §7.3 calls "loopback IP redirect URIs", which are
/// the ones its any-port rule covers. `localhost` is a name, not an IP literal,
/// so it is matched on its exact registered port like every other URI.
fn is_loopback_ip_literal(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "[::1]")
}

/// Why a redirect URI was rejected at registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectUriError {
    /// RFC 6749 §3.1.2: "The redirection endpoint URI MUST be an absolute URI".
    NotAbsolute,
    /// RFC 6749 §3.1.2: "The endpoint URI MUST NOT include a fragment component."
    HasFragment,
    /// `http` is permitted only for the loopback hosts above.
    HttpNonLoopback,
    /// OIDC Registration §2: "Native Clients MUST only register "redirect_uris"
    /// using custom URI schemes or loopback URLs using the "http" scheme".
    /// Everything else registers `https` (or loopback `http`).
    CustomSchemeNotNative,
}

impl std::fmt::Display for RedirectUriError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::NotAbsolute => "must be an absolute URI",
            Self::HasFragment => "must not contain a fragment component",
            Self::HttpNonLoopback => "http:// is allowed only for localhost, 127.0.0.1, or [::1]",
            Self::CustomSchemeNotNative => "a custom URI scheme is allowed only for native clients",
        };
        f.write_str(msg)
    }
}

/// Validate one `redirect_uri` for registration, for a client of this type.
///
/// The single rule for every write path — dynamic client registration and both
/// self-service paths — so a URI one path accepts cannot be a URI another
/// rejects.
///
/// # Errors
///
/// Returns the specific [`RedirectUriError`] rather than a boolean, so each
/// rejection reason can be reported to the client and tested on its own.
pub fn validate_redirect_uri(
    uri: &str,
    application_type: OAuthClientType,
) -> Result<(), RedirectUriError> {
    let parsed = url::Url::parse(uri).map_err(|_| RedirectUriError::NotAbsolute)?;
    if parsed.fragment().is_some() {
        return Err(RedirectUriError::HasFragment);
    }
    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            if is_loopback_redirect_host(parsed.host_str().unwrap_or_default()) {
                Ok(())
            } else {
                Err(RedirectUriError::HttpNonLoopback)
            }
        }
        // OIDC Core §3.1.2.1: "The Redirection URI MAY use an alternate scheme,
        // such as one that is intended to identify a callback into a native
        // application." RFC 8252 §7.1's reverse-domain format is a MUST on the
        // app, not on us, so the scheme's shape is not checked here.
        _ => match application_type {
            OAuthClientType::Native => Ok(()),
            OAuthClientType::Web | OAuthClientType::Spa | OAuthClientType::Service => {
                Err(RedirectUriError::CustomSchemeNotNative)
            }
        },
    }
}

/// Read a stored client's key material.
///
/// A row carrying both is a state RFC 7591 §2 forbids and no write path can
/// produce. It fails closed rather than inventing a precedence: a client with
/// no usable key material fails authentication instead of authenticating on a
/// guess about which field was meant.
fn stored_client_keys(
    client: &str,
    jwks: Option<serde_json::Value>,
    jwks_uri: Option<String>,
) -> Option<ClientKeys> {
    ClientKeys::from_stored(jwks, jwks_uri).unwrap_or_else(|_| {
        tracing::error!(
            client,
            "stored client has both jwks and jwks_uri; treating it as having neither"
        );
        None
    })
}

/// A client's key material.
///
/// RFC 7591 §2 states the rule twice, once under each parameter: "The
/// "jwks_uri" and "jwks" parameters MUST NOT both be present in the same
/// request or response."
///
/// Holding them as one value is what makes that hold. While they were two
/// options, "both present" was representable, so dynamic client registration
/// carried a guard to reject it, the self-service path did not, and the
/// resolver needed a precedence rule ("inline JWKS takes priority") for a
/// state the specification says cannot occur.
#[derive(Debug, Clone, PartialEq)]
pub enum ClientKeys {
    /// RFC 7591 §2 `jwks`: the key set inline, "intended to be used by clients
    /// that cannot use the "jwks_uri" parameter".
    ///
    /// Held parsed. RFC 7517 §4 says of members this crate does not model
    /// ("x5t", "key_ops", extensions): "Additional members can be present in
    /// the JWK; if not understood by implementations encountering them, they
    /// MUST be ignored." They are dropped here rather than carried, and RFC
    /// 7591 §3.2.1 requires the registration response to "return all
    /// registered metadata about this client" — so what a client gets back is
    /// what was registered, which is this.
    Inline(JwkSet),
    /// RFC 7591 §2 `jwks_uri`, whose use "is preferred over the "jwks"
    /// parameter, as it allows for easier key rotation".
    Uri(String),
}

/// Why a client's key material could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientKeysError {
    /// Both key parameters arrived together, which RFC 7591 §2 forbids.
    Conflict,
    /// The inline `jwks` is not a JWK Set this server can read.
    InvalidJwks,
}

impl std::fmt::Display for ClientKeysError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Conflict => "jwks and jwks_uri are mutually exclusive",
            Self::InvalidJwks => "jwks contains a key with an invalid field type",
        })
    }
}

impl ClientKeys {
    /// Build from the two stored columns, rejecting the state the type exists
    /// to forbid.
    ///
    /// # Errors
    ///
    /// [`ClientKeysConflict`] when both are present.
    pub fn from_stored(
        jwks: Option<serde_json::Value>,
        jwks_uri: Option<String>,
    ) -> Result<Option<Self>, ClientKeysError> {
        match (jwks, jwks_uri) {
            (Some(_), Some(_)) => Err(ClientKeysError::Conflict),
            (Some(jwks), None) => parse_jwks_set(&jwks)
                .map(|set| Some(Self::Inline(set)))
                .map_err(|_| ClientKeysError::InvalidJwks),
            (None, Some(uri)) => Ok(Some(Self::Uri(uri))),
            (None, None) => Ok(None),
        }
    }

    /// The inline key set, when that is the form.
    #[must_use]
    pub fn inline(&self) -> Option<&JwkSet> {
        match self {
            Self::Inline(jwks) => Some(jwks),
            Self::Uri(_) => None,
        }
    }

    /// The key set URI, when that is the form.
    #[must_use]
    pub fn uri(&self) -> Option<&str> {
        match self {
            Self::Uri(uri) => Some(uri),
            Self::Inline(_) => None,
        }
    }
}

/// Split back into the two stored columns.
///
/// The document keeps the shape it has always had, so a rolling deploy reads
/// and writes the same rows in both directions; exclusivity is carried by the
/// only type the code uses.
#[must_use]
pub fn client_keys_to_stored(
    keys: Option<&ClientKeys>,
) -> (Option<serde_json::Value>, Option<String>) {
    match keys {
        // `JwkSet` round-trips: every optional member skips rather than
        // emitting null, so the stored column holds the same document the
        // parse accepted.
        Some(ClientKeys::Inline(jwks)) => (serde_json::to_value(jwks).ok(), None),
        Some(ClientKeys::Uri(uri)) => (None, Some(uri.clone())),
        None => (None, None),
    }
}

/// Return `true` when `uri` is a syntactically valid post-logout redirect URI.
///
/// Valid URIs must:
/// - Parse as an absolute URL.
/// - Use `https://` for non-loopback hosts.
/// - Use `http://` only for loopback addresses (`localhost`, `127.0.0.1`, `[::1]`).
/// - Carry no fragment component (would conflict with the echoed `state` parameter).
#[must_use]
pub fn is_valid_post_logout_redirect_uri_str(uri: &str) -> bool {
    let Ok(parsed) = url::Url::parse(uri) else {
        return false;
    };
    if parsed.fragment().is_some() {
        return false;
    }
    match parsed.scheme() {
        "https" => true,
        "http" => is_loopback_redirect_host(parsed.host_str().unwrap_or_default()),
        _ => false,
    }
}

// ============================================================================
// FAPI 2.0 JWKS algorithm-usability check (shared between the admin
// application API and RFC 7591/7592 dynamic client registration, so the rule
// lives in exactly one place)
// ============================================================================

/// A JSON Web Key Set (RFC 7517 Section 5).
///
/// The typed representation shared by write-time acceptance checks (this
/// module: `jwks_has_fapi_allowed_key`, `jwks_has_x5c`) and the runtime RFC
/// 7523 client-assertion verifier (`services/oidc/jwt_bearer/jwks.rs`), so a
/// member of the wrong JSON type (e.g. `"alg": true`) is rejected the same
/// way in both places instead of silently read as absent by a separate,
/// more lenient parser. Two other JWKS consumers still parse leniently from
/// raw `serde_json::Value` and are unaffected by this type: the mTLS `x5c`
/// matcher (`services/oidc/mtls.rs::verify_self_signed_tls_client_auth`) and
/// the RFC 9421 signature key resolver (`infra/httpsig.rs`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwkSet {
    /// The keys in the set.
    pub keys: Vec<JwkEntry>,
}

/// JWK "kty" (Key Type) value (RFC 7517 §4.1).
///
/// The IANA "JSON Web Key Types" registry this parameter draws from is open
/// to extension: RFC 7518 §7.4 (<https://www.rfc-editor.org/rfc/rfc7518>)
/// — "This specification establishes the IANA 'JSON Web Key Types' registry
/// for values of the JWK 'kty' (key type) parameter" — registers only `EC`,
/// `RSA`, and `oct`. `OKP` was added later, by RFC 8037 §5
/// (<https://www.rfc-editor.org/rfc/rfc8037>) — "'kty' Parameter Value:
/// 'OKP'" — and more recently `AKP` by RFC 9964. An unrecognized value must
/// therefore still parse (`Other`), just as an unrecognized value already
/// does for the members this crate doesn't model (`x5t`, etc.) — it isn't
/// selectable by any of the three known variants, so it stays unusable the
/// same way `oct` or any other unmatched `kty` already is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyType {
    Ec,
    Rsa,
    Okp,
    /// Any value outside the three this crate matches against. Carries the
    /// original string for diagnostics; never selected by a signing-key or
    /// FAPI-allowed-algorithm check.
    Other(String),
}

impl Serialize for KeyType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(match self {
            Self::Ec => "EC",
            Self::Rsa => "RSA",
            Self::Okp => "OKP",
            Self::Other(s) => s,
        })
    }
}

impl<'de> Deserialize<'de> for KeyType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Exact-case match: RFC 7517 §4.1 (quoted above `parse_jwks_set`'s
        // "kty" test) — "The 'kty' value is a case-sensitive string" — so
        // e.g. "ec" is a *different*, unrecognized value, not `Ec`.
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "EC" => Self::Ec,
            "RSA" => Self::Rsa,
            "OKP" => Self::Okp,
            _ => Self::Other(s),
        })
    }
}

/// A single JWK entry in a JWKS.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwkEntry {
    /// Key type (RFC 7517 §4.1).
    pub kty: KeyType,
    /// Key ID (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Algorithm (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Key use (optional, e.g., "sig").
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,

    // EC key components
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,

    // RSA key components
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,

    /// X.509 certificate chain (RFC 7517 §4.7) — the certificate carrier for
    /// `self_signed_tls_client_auth` (RFC 8705 §2.2.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
}

/// Parse a raw JWKS JSON value into the typed [`JwkSet`].
///
/// Deserialization is strict: a member of the wrong JSON type (e.g. a
/// boolean `alg`) fails the whole parse rather than being read as absent.
/// Write paths (application create/update, RFC 7591/7592 registration) use
/// this to reject a malformed submission outright. Callers evaluating a
/// JWKS that may be pre-existing stored data (which could predate this
/// check) should treat a parse failure as "no usable key" rather than a
/// hard error — see `jwks_has_fapi_allowed_key`'s callers.
///
/// # Errors
/// Returns the `serde_json` deserialization error on a shape mismatch.
pub fn parse_jwks_set(value: &serde_json::Value) -> Result<JwkSet, serde_json::Error> {
    serde_json::from_value(value.clone())
}

/// Returns `true` when `jwks` contains at least one key the FAPI 2.0
/// client-assertion validator (`FapiProfile::client_assertion_algorithms`, which
/// yields `JwsAlgorithm::FAPI_ALLOWED` for `FapiProfile::Fapi2Security`) could
/// actually use: a key whose `use` (if present) is `sig`, and that either
/// declares no `alg` but has a `kty` the runtime matcher can select for
/// ES256/PS256/EdDSA (`EC`/`RSA`/`OKP`), or declares `alg` as ES256, PS256, or
/// EdDSA outright.
///
/// A key search skips a JWK whose declared `alg` differs from the assertion's
/// header, or whose `use` is present and not `sig`
/// (`services/oidc/jwt_bearer/jwks.rs`). So a JWKS made only of `alg: RS256`
/// keys would leave a FAPI client with no algorithm it is both allowed to use
/// and has a matching key for, and a JWKS made only of `use: "enc"` keys would
/// leave it with no key the search selects at all — both permanently
/// unauthenticatable. The `kty` check on both branches closes the same bug
/// class for an incompatible or missing `kty`: the runtime matcher only ever
/// selects `EC` for ES256, `RSA` for PS256, and `OKP` for EdDSA, so a key
/// whose `kty` is anything else (e.g. `oct`, or `RSA` declaring `alg: ES256`)
/// is unmatchable regardless of `alg`.
///
/// Used at every point a FAPI 2.0 client's JWKS is accepted or replaced:
/// application creation and update (`handlers/applications/validate.rs`) and
/// RFC 7591/7592 dynamic client registration (`services/oidc/registration.rs`).
#[must_use]
pub fn jwks_has_fapi_allowed_key(jwks: &JwkSet) -> bool {
    jwks.keys.iter().any(|key| {
        let use_is_sig = key.use_.as_deref().is_none_or(|u| u == "sig");
        if !use_is_sig {
            return false;
        }
        let Some(alg) = key.alg.as_deref() else {
            // An exhaustive match, not `matches!`: `matches!` isn't
            // exhaustiveness-checked, so a `KeyType` variant added later
            // without updating this arm would silently keep compiling here
            // (unlike the exhaustive match in
            // `jwt_bearer::jwks::build_decoding_key_from_jwk`, which would
            // fail to compile until updated) instead of forcing the same
            // explicit decision at both consumers.
            return match key.kty {
                KeyType::Ec | KeyType::Rsa | KeyType::Okp => true,
                KeyType::Other(_) => false,
            };
        };
        let Ok(parsed) = alg.parse::<JwsAlgorithm>() else {
            return false;
        };
        if !JwsAlgorithm::FAPI_ALLOWED.contains(&parsed) {
            return false;
        }
        // Same kty-per-alg selection rule as the runtime matcher
        // (`jwt_bearer::jwks::find_matching_key` /
        // `build_decoding_key_from_jwk`): a key whose `kty` can't carry its
        // declared `alg` is unmatchable, so declaring an allowed `alg` alone
        // must not count. Exhaustive for the same reason as the no-`alg`
        // branch above.
        let expected_kty = match parsed {
            JwsAlgorithm::Es256 => KeyType::Ec,
            JwsAlgorithm::Ps256 => KeyType::Rsa,
            JwsAlgorithm::EdDsa => KeyType::Okp,
            // Not FAPI-allowed; already rejected by the contains() gate.
            JwsAlgorithm::Rs256 => return false,
        };
        key.kty == expected_kty
    })
}

/// Returns `true` when `jwks` contains at least one key with a non-empty
/// `x5c` member — `self_signed_tls_client_auth`'s certificate carrier (RFC
/// 8705 §2.2.2 describes this representation; it is not itself a MUST). A
/// JWKS with no `x5c` anywhere passes a bare presence check but leaves the
/// client permanently unable to complete mTLS authentication:
/// `verify_self_signed_tls_client_auth` (`services/oidc/mtls.rs`) only
/// matches keys carrying an `x5c` entry and returns
/// `CertificateNotRegistered` if none do — the same "accepted at
/// registration, unusable forever after" class `jwks_has_fapi_allowed_key`
/// closes for `private_key_jwt`.
///
/// Used wherever a `self_signed_tls_client_auth` client's inline JWKS is
/// accepted or replaced: application creation and update
/// (`handlers/applications/validate.rs`) and RFC 7591/7592 dynamic client
/// registration (`services/oidc/registration.rs`). Not applicable to a
/// `jwks_uri`, which can't be inspected synchronously.
#[must_use]
pub fn jwks_has_x5c(jwks: &JwkSet) -> bool {
    jwks.keys
        .iter()
        .any(|key| key.x5c.as_ref().is_some_and(|c| !c.is_empty()))
}

/// Parameters for creating a new OAuth client application.
pub struct CreateOAuthClientParams<'a> {
    pub user_id: Option<&'a str>,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub application_type: OAuthClientType,
    pub redirect_uris: &'a [String],
    pub access_scope: AccessScope,
    pub org_id: Option<&'a str>,
    pub resource_uris: &'a [String],
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// RFC 7591 §2 key material, in whichever of the two forms was supplied.
    pub keys: Option<&'a ClientKeys>,
    pub fapi_profile: Option<FapiProfile>,
    pub dpop_bound_access_tokens: Option<bool>,
    pub grant_types: Option<&'a [String]>,
    pub response_types: Option<&'a [String]>,
    pub software_id: Option<&'a str>,
    pub software_version: Option<&'a str>,
    pub registration_source: RegistrationSource,
    pub registration_access_token_hash: Option<&'a str>,
    pub registration_metadata: Option<&'a serde_json::Value>,
    pub id_token_signed_response_alg: JwsAlgorithm,
    /// RFC 8705 mTLS fields.
    pub tls_client_auth_subject_dn: Option<&'a str>,
    pub tls_client_auth_san_dns: Option<&'a str>,
    pub tls_client_auth_san_uri: Option<&'a str>,
    pub tls_client_auth_san_ip: Option<&'a str>,
    pub tls_client_auth_san_email: Option<&'a str>,
    pub tls_client_certificate_bound_access_tokens: Option<bool>,
    /// JARM: signing algorithm for authorization responses.
    pub authorization_signed_response_alg: Option<JwsAlgorithm>,
    /// RFC 9701: Introspection response signing algorithm.
    pub introspection_signed_response_alg: Option<JwsAlgorithm>,
    /// RFC 9101: Request object signing algorithm.
    pub request_object_signing_alg: Option<JwsAlgorithm>,
    /// RFC 9101: Whether signed request objects are required.
    pub require_signed_request_object: Option<bool>,
    /// OIDC Core Section 5.3.4: UserInfo response signing algorithm.
    pub userinfo_signed_response_alg: Option<JwsAlgorithm>,
    /// OIDC Core Section 6.2: Pre-registered request_uri allowlist.
    pub request_uris: Option<Vec<String>>,
    /// RP-Initiated Logout 1.0: Registered post-logout redirect URIs.
    pub post_logout_redirect_uris: Option<Vec<String>>,
}

/// Create a new OAuth client application.
pub async fn create_oauth_client(
    store: &DocumentStore,
    params: &CreateOAuthClientParams<'_>,
) -> Result<(OAuthClient, String)> {
    let client_id = uuid::Uuid::now_v7().to_string();
    let (stored_jwks, stored_jwks_uri) = client_keys_to_stored(params.keys);

    let doc = OAuthClientDoc {
        user_id: params.user_id.map(String::from),
        client_id: client_id.clone(),
        name: params.name.to_string(),
        description: params.description.map(String::from),
        application_type: params.application_type,
        redirect_uris: params.redirect_uris.to_vec(),
        active: true,
        access_scope: params.access_scope,
        org_id: params.org_id.map(String::from),
        resource_uris: params.resource_uris.to_vec(),
        jwks: stored_jwks,
        jwks_uri: stored_jwks_uri,
        token_endpoint_auth_method: params.token_endpoint_auth_method,
        request_object_signing_alg: params.request_object_signing_alg,
        require_signed_request_object: params.require_signed_request_object,
        fapi_profile: params.fapi_profile.unwrap_or_default(),
        dpop_bound_access_tokens: params.dpop_bound_access_tokens.unwrap_or(false),
        grant_types: params.grant_types.map(<[String]>::to_vec),
        response_types: params.response_types.map(<[String]>::to_vec),
        software_id: params.software_id.map(String::from),
        software_version: params.software_version.map(String::from),
        registration_source: Some(params.registration_source),
        registration_access_token_hash: params.registration_access_token_hash.map(String::from),
        registration_metadata: params.registration_metadata.cloned(),
        id_token_signed_response_alg: params.id_token_signed_response_alg,
        tls_client_auth_subject_dn: params.tls_client_auth_subject_dn.map(String::from),
        tls_client_auth_san_dns: params.tls_client_auth_san_dns.map(String::from),
        tls_client_auth_san_uri: params.tls_client_auth_san_uri.map(String::from),
        tls_client_auth_san_ip: params.tls_client_auth_san_ip.map(String::from),
        tls_client_auth_san_email: params.tls_client_auth_san_email.map(String::from),
        tls_client_certificate_bound_access_tokens: params
            .tls_client_certificate_bound_access_tokens
            .unwrap_or(false),
        authorization_signed_response_alg: params.authorization_signed_response_alg,
        introspection_signed_response_alg: params.introspection_signed_response_alg,
        userinfo_signed_response_alg: params.userinfo_signed_response_alg,
        request_uris: params.request_uris.clone(),
        post_logout_redirect_uris: params.post_logout_redirect_uris.clone(),
    };

    let result = store.insert(&doc).await?;
    let oauth_client = OAuthClient::from(result);

    Ok((oauth_client, client_id))
}

/// Get an OAuth client by internal ID.
pub async fn get_oauth_client_by_id(
    store: &DocumentStore,
    id: &str,
) -> Result<Option<OAuthClient>> {
    let doc = store.get::<OAuthClientDoc>(id).await?;
    Ok(doc.map(OAuthClient::from))
}

/// Get an OAuth client by public client_id.
pub async fn get_oauth_client_by_client_id(
    store: &DocumentStore,
    client_id: &str,
) -> Result<Option<OAuthClient>> {
    let doc = store
        .find_one::<OAuthClientDoc>("client_id", client_id)
        .await?;
    Ok(doc.map(OAuthClient::from))
}

/// Get all OAuth clients for a user.
pub async fn get_oauth_clients_for_user(
    store: &DocumentStore,
    user_id: &str,
) -> Result<Vec<OAuthClient>> {
    let docs = store.find_all::<OAuthClientDoc>("user_id", user_id).await?;
    Ok(docs.into_iter().map(OAuthClient::from).collect())
}

/// Parameters for updating an OAuth client.
pub struct UpdateOAuthClientParams<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub redirect_uris: &'a [String],
    pub access_scope: Option<AccessScope>,
    pub org_id: Option<&'a str>,
    pub resource_uris: &'a [String],
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// RFC 7591 §2 key material, in whichever of the two forms was supplied.
    pub keys: Option<&'a ClientKeys>,
    pub fapi_profile: FapiProfile,
    pub dpop_bound_access_tokens: bool,
    /// RP-Initiated Logout 1.0: Registered post-logout redirect URIs.
    /// `None` preserves the existing value; `Some(vec![])` clears the list.
    pub post_logout_redirect_uris: Option<Vec<String>>,
}

/// Update an OAuth client.
///
/// Uses [`DocumentStore::modify`] for read-modify-write with automatic
/// version-conflict retry.
pub async fn update_oauth_client(
    store: &DocumentStore,
    params: &UpdateOAuthClientParams<'_>,
) -> Result<()> {
    // Same delete-before-modify ordering as `update_oauth_client_registration`
    // (RFC 7592), and the same reasoning: check whether jwks_uri is changing
    // before modifying the parent doc so the stale cache is gone before a
    // reader could see the new URI paired with old-host keys. Bounded race: a
    // concurrent JWKS refresh completing between this delete and the modify's
    // internal re-fetch can repopulate the cache with old-URI keys; worst-case
    // window is one TTL (~1h), self-corrected by the next cache miss.
    let jwks_uri_changing = store
        .get::<OAuthClientDoc>(params.id)
        .await?
        .is_some_and(|doc| doc.data.jwks_uri.as_deref() != params.keys.and_then(ClientKeys::uri));

    if jwks_uri_changing {
        super::jwks_cache::delete_jwks_cache(store, params.id).await?;
    }

    store
        .modify::<OAuthClientDoc, _>(params.id, |data| {
            data.name = params.name.to_string();
            data.description = params.description.map(String::from);
            data.redirect_uris = params.redirect_uris.to_vec();
            data.resource_uris = params.resource_uris.to_vec();
            data.token_endpoint_auth_method = params.token_endpoint_auth_method;
            let (jwks, jwks_uri) = client_keys_to_stored(params.keys);
            data.jwks = jwks;
            data.jwks_uri = jwks_uri;
            data.fapi_profile = params.fapi_profile;
            data.dpop_bound_access_tokens = params.dpop_bound_access_tokens;
            if let Some(ref uris) = params.post_logout_redirect_uris {
                data.post_logout_redirect_uris = if uris.is_empty() {
                    None
                } else {
                    Some(uris.clone())
                };
            }

            if let Some(scope) = params.access_scope {
                data.access_scope = scope;
                data.org_id = params.org_id.map(String::from);
            }
        })
        .await?;
    Ok(())
}

/// Delete an OAuth client permanently.
///
/// Cascade deletes secrets and the client within a single transaction
/// so no orphaned secrets remain on partial failure. Each delete is
/// idempotent, so the transaction is safe to retry on a transient
/// serialization failure.
pub async fn delete_oauth_client(store: &DocumentStore, id: &str) -> Result<u64> {
    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await?;

        // Delete secrets
        tx.delete_by_index::<OAuthClientSecretDoc>("oauth_client_id", id)
            .await?;

        // Delete the client's JWKS cache in the same transaction so it can never
        // outlive the client
        tx.delete(&super::jwks_cache::cache_id(id)).await?;

        // Delete the client
        tx.delete(id).await?;

        tx.commit().await?;
        Ok(1)
    })
}

/// Update last used timestamp for an OAuth client.
///
/// Performs a lightweight column-level UPDATE (no encrypt/decrypt).
pub async fn update_oauth_client_last_used(store: &DocumentStore, id: &str) -> Result<()> {
    store.update_last_used_at(id).await
}

// ============================================================================
// OAuth Client Secrets
// ============================================================================

/// OAuth client secret record.
#[derive(Debug)]
pub struct OAuthClientSecret {
    pub id: String,
    pub oauth_client_id: String,
    pub secret_hash: String,
    pub description: Option<String>,
    pub created_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
}

impl From<Document<OAuthClientSecretDoc>> for OAuthClientSecret {
    fn from(doc: Document<OAuthClientSecretDoc>) -> Self {
        Self {
            id: doc.id,
            oauth_client_id: doc.data.oauth_client_id,
            secret_hash: doc.data.secret_hash,
            description: doc.data.description,
            created_at: doc.created_at,
            expires_at: doc.data.expires_at,
            revoked_at: doc.data.revoked_at,
        }
    }
}

impl OAuthClientSecret {
    /// Check if this secret is valid (not revoked/expired).
    #[must_use]
    pub fn is_valid(&self, now: &Timestamp) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }
        if let Some(expires) = self.expires_at
            && expires <= *now
        {
            return false;
        }
        true
    }
}

/// Create a new client secret, enforcing the ≤`MAX_ACTIVE_SECRETS` cap.
///
/// The entire operation runs inside a single transaction wrapped in
/// `with_dsql_retry!`.  The transaction:
///
/// 1. Loads the `OAuthClientDoc` and records its `version` — this is the
///    deliberate serialization point for all secret-set mutations on this client.
/// 2. Counts currently-valid (non-revoked, non-expired) secrets.
/// 3. If the count is already at the cap, returns a terminal 409 error that
///    is **not** retried (business logic, not a transient conflict).
/// 4. Inserts the new secret inside the transaction.
/// 5. Bumps the client doc version via `compare_and_update`.  If another writer
///    committed a secret-set mutation between our read and our commit, the version
///    won't match and `compare_and_update` returns `Ok(false)` — we surface this
///    as `ServiceError::OccConflict` so `with_dsql_retry!` re-runs the whole
///    block (re-counting, possibly rejecting at the cap on the second attempt).
///
/// This approach is correct on Aurora DSQL where the reverted #547 fix was not:
/// the reverted fix relied on snapshot isolation to reject a second concurrent
/// insert, but two adds write *distinct* rows and neither `SELECT FOR UPDATE` nor
/// `SERIALIZABLE` caught them.  Here, both writers also update the **same** client
/// row via `compare_and_update`, causing a write-write conflict (DSQL OC000) that
/// the loser retries at the application level.
///
/// Note: because this function version-bumps the `OAuthClientDoc`, concurrent
/// client metadata updates (e.g. `update_oauth_client`) may incur OCC retries
/// while a secret add is in flight, and vice versa.
///
/// # Errors
///
/// - `ServiceError::NotFound` — client does not exist.
/// - `ServiceError::Api(409 "max_secrets_reached")` — cap already reached (terminal).
/// - `ServiceError::Api(409 "conflict")` — OCC retry budget exhausted; caller may retry.
/// - `ServiceError::Internal` — unexpected database or serialization error.
pub async fn create_oauth_client_secret(
    store: &DocumentStore,
    oauth_client_id: &str,
    secret_hash: &str,
    description: Option<&str>,
    expires_at: Option<Timestamp>,
) -> Result<OAuthClientSecret, ServiceError> {
    // Capture parameters as owned values so the async block (re-run on retry) can
    // borrow them without lifetime conflicts.
    let oauth_client_id = oauth_client_id.to_string();
    let secret_hash = secret_hash.to_string();
    let description = description.map(String::from);

    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await.map_err(|e| {
            ServiceError::from_db_contention(
                e,
                "Failed to begin transaction for create_oauth_client_secret",
            )
        })?;

        // Load the client doc.  Its version is the serialization point — a
        // concurrent secret-set mutation that commits between our read and our
        // compare_and_update will change the version and trigger a retry.
        let client_doc = tx
            .get::<OAuthClientDoc>(&oauth_client_id)
            .await
            .map_err(|e| {
                ServiceError::from_db_contention(
                    e,
                    "Failed to load OAuthClientDoc for secret create",
                )
            })?
            .ok_or(ServiceError::NotFound("OAuth client"))?;

        // Count currently-active secrets by filtering (not SQL COUNT) because
        // soft-deleted rows are retained and a COUNT(*) would include them.
        let now = Timestamp::now();
        let all_secrets = tx
            .find_all::<OAuthClientSecretDoc>("oauth_client_id", &oauth_client_id)
            .await
            .map_err(|e| {
                ServiceError::from_db_contention(e, "Failed to list secrets for secret create")
            })?;

        // Filter directly on the doc fields to avoid a needless From conversion.
        // Mirrors the `is_valid` predicate: not revoked, not expired.
        let active_count = all_secrets
            .iter()
            .filter(|s| {
                if s.data.revoked_at.is_some() {
                    return false;
                }
                if let Some(exp) = s.data.expires_at
                    && exp <= now
                {
                    return false;
                }
                true
            })
            .count();

        if active_count >= MAX_ACTIVE_SECRETS {
            // Terminal business error — do not retry.
            return Err(ServiceError::api(
                axum::http::StatusCode::CONFLICT,
                "max_secrets_reached",
                "Maximum of 2 active secrets allowed",
            ));
        }

        // Insert the new secret inside the transaction.
        let new_secret_doc = OAuthClientSecretDoc {
            oauth_client_id: oauth_client_id.clone(),
            secret_hash: secret_hash.clone(),
            description: description.clone(),
            expires_at,
            revoked_at: None,
        };
        let inserted = tx
            .insert(&new_secret_doc)
            .await
            .map_err(|e| ServiceError::from_db_contention(e, "Failed to insert secret"))?;

        // Version-bump the client doc.  This is the OCC serialization point:
        // any concurrent secret-set mutation on this client will have bumped the
        // version, causing compare_and_update to return Ok(false).
        let ok = tx
            .compare_and_update::<OAuthClientDoc>(
                &oauth_client_id,
                client_doc.version,
                &client_doc.data,
            )
            .await
            .map_err(|e| {
                ServiceError::from_db_contention(
                    e,
                    "Failed to version-bump client for secret create",
                )
            })?;

        if !ok {
            // OCC conflict — another writer beat us to the client row.  Signal
            // with_dsql_retry! to re-run the entire block.
            return Err(ServiceError::OccConflict);
        }

        tx.commit().await.map_err(|e| {
            ServiceError::from_db_contention(e, "Failed to commit create_oauth_client_secret")
        })?;

        Ok(OAuthClientSecret::from(inserted))
    })
    // `with_dsql_retry!` exhausts OccConflict after MAX_DSQL_RETRIES attempts.
    // Surface as 409 "conflict" (not 500) — mirrors the delete_key precedent.
    .map_err(|e| match e {
        ServiceError::OccConflict => ServiceError::api(
            axum::http::StatusCode::CONFLICT,
            "conflict",
            "Secret creation conflicted with a concurrent operation. Please retry.",
        ),
        other => other,
    })
}

/// Get all secrets for an OAuth client.
pub async fn get_oauth_client_secrets(
    store: &DocumentStore,
    oauth_client_id: &str,
) -> Result<Vec<OAuthClientSecret>> {
    let docs = store
        .find_all::<OAuthClientSecretDoc>("oauth_client_id", oauth_client_id)
        .await?;
    Ok(docs.into_iter().map(OAuthClientSecret::from).collect())
}

/// Get a secret by its hash.
pub async fn get_oauth_secret_by_hash(
    store: &DocumentStore,
    secret_hash: &str,
) -> Result<Option<OAuthClientSecret>> {
    let doc = store
        .find_one::<OAuthClientSecretDoc>("secret_hash", secret_hash)
        .await?;
    Ok(doc.map(OAuthClientSecret::from))
}

/// Revoke all secrets for an OAuth client.
pub async fn revoke_all_oauth_client_secrets(
    store: &DocumentStore,
    oauth_client_id: &str,
) -> Result<u64> {
    let now = Timestamp::now();
    let count = store
        .update_by_index::<OAuthClientSecretDoc, _>("oauth_client_id", oauth_client_id, |data| {
            if data.revoked_at.is_none() {
                data.revoked_at = Some(now);
            }
        })
        .await?;
    Ok(count)
}

/// Get a secret by its internal ID.
pub async fn get_oauth_client_secret_by_id(
    store: &DocumentStore,
    id: &str,
) -> Result<Option<OAuthClientSecret>> {
    let doc = store.get::<OAuthClientSecretDoc>(id).await?;
    Ok(doc.map(OAuthClientSecret::from))
}

/// Revoke a single secret (soft-delete), enforcing the ≥1 active floor.
///
/// The entire operation runs inside a single transaction wrapped in
/// `with_dsql_retry!`.  The transaction:
///
/// 1. Verifies the secret exists and belongs to the given client.
/// 2. Short-circuits with a terminal "not found" if the secret is already revoked.
/// 3. Loads the `OAuthClientDoc` to record its `version` (the serialization point
///    for all secret-set mutations on this client).
/// 4. Counts the *other* active secrets — those that would remain after this
///    revoke, excluding the target row itself (filter, not SQL COUNT — soft-deleted
///    rows are retained).  If none remain, returns a terminal 409 `last_secret`.
///    Excluding the target matters when it is expired-but-unrevoked: revoking it
///    must still be allowed while a different valid secret exists.
/// 5. Soft-deletes the secret (`revoked_at`) inside the transaction.
/// 6. Bumps the client version via `compare_and_update`.  If another concurrent
///    revoke committed between our read and our commit, the version won't match
///    and we surface `ServiceError::OccConflict` so the macro retries.  The
///    retried attempt re-counts and returns `last_secret` if appropriate.
///
/// Note: because this function version-bumps the `OAuthClientDoc`, concurrent
/// client metadata updates (e.g. `update_oauth_client`) may incur OCC retries
/// while a secret revocation is in flight, and vice versa.
///
/// # Errors
///
/// - `ServiceError::NotFound("Secret")` — secret does not exist, does not belong
///   to the given client, or is already revoked.
/// - `ServiceError::NotFound("OAuth client")` — the owning client does not exist.
/// - `ServiceError::Api(409 "last_secret")` — would leave zero active secrets (terminal).
/// - `ServiceError::Api(409 "conflict")` — OCC retry budget exhausted; caller may retry.
/// - `ServiceError::Internal` — unexpected database or serialization error.
pub async fn revoke_oauth_client_secret(
    store: &DocumentStore,
    secret_id: &str,
    oauth_client_id: &str,
) -> Result<(), ServiceError> {
    let secret_id = secret_id.to_string();
    let oauth_client_id = oauth_client_id.to_string();

    crate::with_dsql_retry!(async {
        let mut tx = store.begin().await.map_err(|e| {
            ServiceError::from_db_contention(
                e,
                "Failed to begin transaction for revoke_oauth_client_secret",
            )
        })?;

        // Verify the secret exists and belongs to this client.
        let secret_doc = tx
            .get::<OAuthClientSecretDoc>(&secret_id)
            .await
            .map_err(|e| ServiceError::from_db_contention(e, "Failed to load secret for revoke"))?
            .ok_or(ServiceError::NotFound("Secret"))?;

        if secret_doc.data.oauth_client_id != oauth_client_id {
            return Err(ServiceError::NotFound("Secret"));
        }

        // Already revoked — idempotent short-circuit; caller should treat as not-found.
        if secret_doc.data.revoked_at.is_some() {
            return Err(ServiceError::NotFound("Secret"));
        }

        // Load the client doc — its version is the serialization point for all
        // secret-set mutations on this client.
        let client_doc = tx
            .get::<OAuthClientDoc>(&oauth_client_id)
            .await
            .map_err(|e| {
                ServiceError::from_db_contention(e, "Failed to load OAuthClientDoc for revoke")
            })?
            .ok_or(ServiceError::NotFound("OAuth client"))?;

        // Count active secrets (filter, not SQL COUNT — soft-deleted rows are retained).
        let now = Timestamp::now();
        let all_secrets = tx
            .find_all::<OAuthClientSecretDoc>("oauth_client_id", &oauth_client_id)
            .await
            .map_err(|e| {
                ServiceError::from_db_contention(e, "Failed to list secrets for revoke")
            })?;

        // Count the *other* active secrets — exclude the target row itself, so a
        // revoke that leaves a valid secret behind is allowed even when the target
        // is expired-but-unrevoked.  Mirrors the handler's pre-flight check.
        let other_active_count = all_secrets
            .iter()
            .filter(|s| {
                if s.id == secret_id {
                    return false;
                }
                if s.data.revoked_at.is_some() {
                    return false;
                }
                if let Some(exp) = s.data.expires_at
                    && exp <= now
                {
                    return false;
                }
                true
            })
            .count();

        // Floor guard: at least one *other* active secret must remain.
        if other_active_count == 0 {
            return Err(ServiceError::api(
                StatusCode::CONFLICT,
                "last_secret",
                "Cannot delete the last active secret",
            ));
        }

        // Soft-delete: set revoked_at on the target secret.
        let mut updated_data = secret_doc.data.clone();
        updated_data.revoked_at = Some(now);
        tx.update(&secret_id, &updated_data)
            .await
            .map_err(|e| ServiceError::from_db_contention(e, "Failed to soft-delete secret"))?;

        // Version-bump the client doc.  This is the OCC serialization point.
        let ok = tx
            .compare_and_update::<OAuthClientDoc>(
                &oauth_client_id,
                client_doc.version,
                &client_doc.data,
            )
            .await
            .map_err(|e| {
                ServiceError::from_db_contention(e, "Failed to version-bump client for revoke")
            })?;

        if !ok {
            return Err(ServiceError::OccConflict);
        }

        tx.commit().await.map_err(|e| {
            ServiceError::from_db_contention(e, "Failed to commit revoke_oauth_client_secret")
        })
    })
    // `with_dsql_retry!` exhausts OccConflict after MAX_DSQL_RETRIES attempts.
    // Surface as 409 "conflict" (not 500) — mirrors the delete_key precedent.
    .map_err(|e| match e {
        ServiceError::OccConflict => ServiceError::api(
            axum::http::StatusCode::CONFLICT,
            "conflict",
            "Secret revocation conflicted with a concurrent operation. Please retry.",
        ),
        other => other,
    })
}

// ============================================================================
// OAuth Usage Events (now via AuditStore)
// ============================================================================

/// OAuth usage event types — the registry kinds whose audit payload is
/// [`OAuthUsageData`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthEventType {
    TokenIssued,
    TokenRevoked,
    ClientRegistered,
    ClientUpdated,
    ClientDeleted,
    SecretAdded,
    SecretRevoked,
}

impl OAuthEventType {
    /// Event variants included in per-client usage stats.
    pub const USAGE_EVENTS: [Self; 3] = [
        Self::TokenIssued,
        Self::TokenRevoked,
        Self::ClientRegistered,
    ];

    /// The registry kind this OAuth event maps to (drives the stored
    /// `event_type` string and retention).
    #[must_use]
    pub fn kind(&self) -> AuditEventKind {
        match self {
            Self::TokenIssued => AuditEventKind::OauthTokenIssued,
            Self::TokenRevoked => AuditEventKind::OauthTokenRevoked,
            Self::ClientRegistered => AuditEventKind::OauthClientRegistered,
            Self::ClientUpdated => AuditEventKind::OauthClientUpdated,
            Self::ClientDeleted => AuditEventKind::OauthClientDeleted,
            Self::SecretAdded => AuditEventKind::OauthSecretAdded,
            Self::SecretRevoked => AuditEventKind::OauthSecretRevoked,
        }
    }
}

/// Parameters for [`record_oauth_event`].
pub struct RecordOAuthEventParams<'a> {
    pub oauth_client_id: &'a str,
    pub event_type: OAuthEventType,
    pub user_id: Option<&'a str>,
    pub ip_address: Option<std::net::IpAddr>,
    pub user_agent: Option<&'a str>,
    pub details: Option<&'a str>,
}

/// Resolve the org domain to stamp on an OAuth event's `email_domain`.
///
/// OAuth usage events have no email of their own. Prefer the acting user's
/// org (the token subject, when present); fall back to the client's own
/// `org_id` (set for org-scoped applications, e.g. client-credentials
/// grants with no human user). Lookup failures are swallowed — a transient
/// DB error here must not fail the OAuth operation that already succeeded.
async fn resolve_oauth_event_org_domain(
    store: &DocumentStore,
    params: &RecordOAuthEventParams<'_>,
) -> Option<String> {
    if let Some(user_id) = params.user_id
        && let Ok(Some(user)) = super::get_user_by_id(store, user_id).await
        && let Some(org_id) = user.org_id
        && let Ok(Some(domain)) = super::get_organization_domain(store, &org_id).await
    {
        return Some(domain);
    }
    if let Ok(Some(client)) = get_oauth_client_by_id(store, params.oauth_client_id).await
        && let Some(org_id) = client.org_id
        && let Ok(Some(domain)) = super::get_organization_domain(store, &org_id).await
    {
        return Some(domain);
    }
    None
}

/// Record an OAuth usage event via the audit store.
///
/// Best-effort: audit writes must never fail the OAuth operation that
/// already succeeded, so failures are logged and swallowed here instead of
/// at every call site.
pub async fn record_oauth_event(
    audit: &AuditStore,
    store: &DocumentStore,
    params: &RecordOAuthEventParams<'_>,
) {
    let (country_code, asn, org_name) = crate::geo::audit_fields(params.ip_address);
    let data = OAuthUsageData {
        oauth_client_id: params.oauth_client_id.to_string(),
        details: params.details.map(String::from),
        client_ip: params.ip_address.map(|ip| ip.to_string()),
        user_agent: params.user_agent.map(String::from),
        country_code,
        asn,
        org_name,
    };
    let org_domain = resolve_oauth_event_org_domain(store, params).await;
    let result = audit
        .insert_event_with_domain(
            params.event_type.kind(),
            params.user_id,
            org_domain.as_deref(),
            &data,
        )
        .await;
    if let Err(e) = result {
        tracing::warn!(
            error = %e,
            event_type = params.event_type.kind().as_str(),
            "failed to record OAuth event"
        );
    }
}

/// OAuth usage statistics.
#[derive(Debug)]
pub struct OAuthUsageStats {
    pub event_type: String,
    pub count: i64,
}

/// Get usage statistics for an OAuth client.
///
/// Queries audit events and counts occurrences per event type,
/// filtering to events matching the given `oauth_client_id`.
pub async fn get_oauth_usage_stats(
    audit: &AuditStore,
    oauth_client_id: &str,
    since: Option<&str>,
) -> Result<Vec<OAuthUsageStats>> {
    let mut stats: std::collections::HashMap<String, i64> = std::collections::HashMap::new();

    for event_type in OAuthEventType::USAGE_EVENTS {
        let audit_event_type = event_type.kind().as_str();
        let filter = AuditEventFilter {
            event_types: Some(vec![audit_event_type.to_string()]),
            since: since.map(String::from),
            ..AuditEventFilter::default()
        };
        let events = audit.query_events(&filter).await?;
        for event in &events {
            let Ok(data) = serde_json::from_str::<OAuthUsageData>(&event.data) else {
                continue;
            };
            if data.oauth_client_id == oauth_client_id {
                let entry: &mut i64 = stats.entry(audit_event_type.to_string()).or_default();
                *entry = entry.saturating_add(1);
            }
        }
    }

    Ok(stats
        .into_iter()
        .map(|(event_type, count)| OAuthUsageStats { event_type, count })
        .collect())
}

/// Test-only helpers for modifying OAuth clients.
#[cfg(test)]
pub(super) mod test_helpers {
    use super::*;

    /// Set an OAuth client's `active` flag. Used to simulate deactivated clients.
    pub async fn set_oauth_client_active(
        store: &DocumentStore,
        id: &str,
        active: bool,
    ) -> Result<()> {
        if let Some(doc) = store.get::<OAuthClientDoc>(id).await? {
            let mut data = doc.data;
            data.active = active;
            store.update(id, &data).await?;
        }
        Ok(())
    }

    /// Set the `userinfo_signed_response_alg` directly on an OAuth client.
    ///
    /// Bypasses registration validation to allow injection of normally-rejected values.
    pub async fn set_oauth_client_userinfo_alg(
        store: &DocumentStore,
        id: &str,
        alg: Option<JwsAlgorithm>,
    ) -> Result<()> {
        if let Some(doc) = store.get::<OAuthClientDoc>(id).await? {
            let mut data = doc.data;
            data.userinfo_signed_response_alg = alg;
            store.update(id, &data).await?;
        }
        Ok(())
    }
}

/// Parameters for updating a client via RFC 7592 PUT.
pub struct UpdateClientRegistrationParams<'a> {
    pub redirect_uris: &'a [String],
    pub grant_types: Option<&'a [String]>,
    pub response_types: Option<&'a [String]>,
    /// RFC 7591 §2 key material, in whichever of the two forms was supplied.
    pub keys: Option<&'a ClientKeys>,
    pub registration_access_token_hash: &'a str,
    pub registration_metadata: Option<&'a serde_json::Value>,
    pub userinfo_signed_response_alg: Option<JwsAlgorithm>,
    pub request_uris: Option<&'a [String]>,
    /// RP-Initiated Logout 1.0: Registered post-logout redirect URIs.
    pub post_logout_redirect_uris: Option<Vec<String>>,
}

/// Update a dynamically registered OAuth client (RFC 7592 Section 2.2).
///
/// Updates mutable registration fields. Immutable fields (client_id,
/// token_endpoint_auth_method, fapi_profile) are preserved.
pub async fn update_oauth_client_registration(
    store: &DocumentStore,
    id: &str,
    params: &UpdateClientRegistrationParams<'_>,
) -> Result<OAuthClient> {
    // Check whether jwks_uri is changing BEFORE modifying the parent doc so we
    // can delete the stale cache first. A reader that races between the cache
    // delete and the parent update will re-fetch (safe). A reader that sees the
    // new URI with the old cache (reverse order) would validate the wrong keys
    // — hence delete-then-update ordering.
    // Bounded race: a concurrent JWKS refresh that completes between this delete
    // and the modify's internal re-fetch can repopulate the cache with old-URI
    // keys. Worst-case window is one TTL (~1h); next cache miss self-corrects.
    let jwks_uri_changing = store
        .get::<OAuthClientDoc>(id)
        .await?
        .is_some_and(|doc| doc.data.jwks_uri.as_deref() != params.keys.and_then(ClientKeys::uri));

    if jwks_uri_changing {
        super::jwks_cache::delete_jwks_cache(store, id).await?;
    }

    store
        .modify::<OAuthClientDoc, _>(id, |data| {
            data.redirect_uris = params.redirect_uris.to_vec();
            if let Some(gt) = params.grant_types {
                data.grant_types = Some(gt.to_vec());
            }
            if let Some(rt) = params.response_types {
                data.response_types = Some(rt.to_vec());
            }
            // RFC 7592: PUT is a full replacement — clear fields not present.
            let (jwks, jwks_uri) = client_keys_to_stored(params.keys);
            data.jwks = jwks;
            data.jwks_uri = jwks_uri;
            data.registration_access_token_hash =
                Some(params.registration_access_token_hash.to_string());
            data.registration_metadata = params.registration_metadata.cloned();
            // RFC 7592: PUT is a full replacement — clear fields not present.
            data.userinfo_signed_response_alg = params.userinfo_signed_response_alg;
            data.request_uris = params.request_uris.map(|u| u.to_vec());
            data.post_logout_redirect_uris = params.post_logout_redirect_uris.clone();
        })
        .await?;

    let updated = store
        .get::<OAuthClientDoc>(id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Client not found after update"))?;

    Ok(OAuthClient::from(updated))
}

// ============================================================================
// JWT Assertion JTI Operations (RFC 7523)
// ============================================================================

/// Maximum JTI length.
const MAX_JTI_LENGTH: usize = 256;

/// Derive a deterministic document ID from (jti, client_id).
///
/// Two concurrent inserts for the same JTI+client_id produce the same
/// document ID, so the second INSERT fails on the `documents` PRIMARY KEY
/// constraint. This eliminates the TOCTOU race without requiring elevated
/// transaction isolation or advisory locks.
fn deterministic_jti_id(jti: &str, client_id: &str) -> String {
    use aws_lc_rs::digest::{self, SHA256};

    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(b"jwt_assertion_jti\0");
    ctx.update(client_id.as_bytes());
    ctx.update(b"\0");
    ctx.update(jti.as_bytes());
    hex::encode(ctx.finish().as_ref())
}

/// Witness that the atomic JTI insert in [`store_jwt_assertion_jti`]
/// succeeded for a specific `(jti, client_id)` pair.
///
/// Construction is private to this module — the only way to obtain a
/// `JwtAssertionJtiClaim` is to call `store_jwt_assertion_jti` and receive
/// `Ok(_)`, which means the atomic INSERT serialized this caller as the
/// first/only one to claim the JTI. Callers that hold this witness can
/// rely on it as compile-time evidence that the RFC 7523 single-use
/// requirement was enforced for the corresponding assertion.
///
/// Intentionally not `Clone` or `Copy` — the witness represents a one-shot
/// claim. The `#[must_use]` ensures the value is bound at the call site
/// even when the caller does not yet thread it into a downstream consumer.
#[derive(Debug)]
#[must_use = "the JTI was atomically claimed; bind this witness so future code can require it"]
pub struct JwtAssertionJtiClaim {
    _private: (),
}

/// Store a JWT assertion JTI for replay prevention.
///
/// On success, returns a [`JwtAssertionJtiClaim`] witness — the atomic
/// INSERT with the PRIMARY KEY derived from `(jti, client_id)` serialized
/// this caller as the first to claim the JTI. Concurrent replayers receive
/// [`ClaimError::AlreadyConsumed`] regardless of transaction isolation
/// level or database backend.
pub async fn store_jwt_assertion_jti(
    store: &DocumentStore,
    jti: &str,
    client_id: &str,
    expires_at: Timestamp,
) -> std::result::Result<JwtAssertionJtiClaim, super::claim::ClaimError> {
    use super::claim::ClaimError;

    if jti.len() > MAX_JTI_LENGTH {
        return Err(ClaimError::InvalidInput(format!(
            "JTI exceeds maximum length ({MAX_JTI_LENGTH})"
        )));
    }
    // Checked here rather than downcast from the store's index guard:
    // the Err arm below stringifies the error, which destroys the type.
    if jti.contains('\0') {
        return Err(ClaimError::InvalidInput(
            "JTI must not contain a NUL (0x00) character".to_string(),
        ));
    }

    let id = deterministic_jti_id(jti, client_id);
    let doc = JwtAssertionJtiDoc {
        jti: jti.to_string(),
        client_id: client_id.to_string(),
        expires_at,
    };

    match store.insert_with_id(&id, &doc).await {
        Ok(_) => Ok(JwtAssertionJtiClaim { _private: () }),
        Err(e) => {
            if super::pool::is_unique_violation(&e) {
                Err(ClaimError::AlreadyConsumed)
            } else {
                Err(ClaimError::Database(e.to_string()))
            }
        }
    }
}

/// Delete expired JWT assertion JTI entries.
pub async fn delete_expired_jwt_assertion_jtis(store: &DocumentStore) -> Result<u64> {
    store.delete_expired(JwtAssertionJtiDoc::DOC_TYPE).await
}

// ============================================================================
// Client Credential Validation
// ============================================================================

/// Validate client credentials (client_id + client_secret).
///
/// The presented secret is hashed by the caller (SHA-256, via `hash_token`)
/// and looked up by hash. There is no application-level `ct_eq` call
/// because the comparison happens inside the SQL engine on an indexed
/// column — the timing of "row found" vs "row not found" is not
/// distinguishable from the HTTP client's perspective, and we never see
/// the raw stored secret in application code. Do NOT replace this with
/// a fetch-then-compare pattern; that would reintroduce a timing channel.
pub async fn validate_oauth_client_credentials(
    store: &DocumentStore,
    client_id: &str,
    secret_hash: &str,
) -> Result<Option<OAuthClient>> {
    let Some(client) = get_oauth_client_by_client_id(store, client_id).await? else {
        return Ok(None);
    };

    if !client.active {
        return Ok(None);
    }

    let Some(secret) = get_oauth_secret_by_hash(store, secret_hash).await? else {
        return Ok(None);
    };

    if secret.oauth_client_id != client.id {
        return Ok(None);
    }

    let now = Timestamp::now();
    if !secret.is_valid(&now) {
        return Ok(None);
    }

    update_oauth_client_last_used(store, &client.id).await?;

    Ok(Some(client))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_post_logout_redirect_uri_str() {
        // https is always allowed.
        assert!(is_valid_post_logout_redirect_uri_str(
            "https://rp.example.com/out"
        ));
        // Loopback http is allowed for all three loopback forms. The `url` crate
        // serializes IPv6 hosts WITH brackets in host_str(), so "[::1]" matches.
        assert!(is_valid_post_logout_redirect_uri_str(
            "http://localhost/out"
        ));
        assert!(is_valid_post_logout_redirect_uri_str(
            "http://127.0.0.1:8080/out"
        ));
        assert!(is_valid_post_logout_redirect_uri_str(
            "http://[::1]:8080/out"
        ));
        // Non-loopback http is rejected.
        assert!(!is_valid_post_logout_redirect_uri_str(
            "http://rp.example.com/out"
        ));
        // Fragments are rejected (would clash with the echoed `state`).
        assert!(!is_valid_post_logout_redirect_uri_str(
            "https://rp.example.com/out#x"
        ));
        // Garbage / relative URIs are rejected.
        assert!(!is_valid_post_logout_redirect_uri_str("not-a-url"));
    }

    // RFC 7517 §4.1 (<https://www.rfc-editor.org/rfc/rfc7517#section-4.1>):
    // "The 'kty' value is a case-sensitive string. This member MUST be
    // present in a JWK." No other member the struct models is required, and
    // members it doesn't model (mTLS `x5t`, future extensions) must pass
    // through rather than being rejected — `JwkEntry` has no
    // `#[serde(deny_unknown_fields)]`, so the write-path shape gate only
    // ever rejects a *known* member of the wrong JSON type, never an
    // unrecognized one. `x5c` is itself a known, typed member (needed by
    // `jwks_has_x5c`): a type-invalid `x5c` (e.g. a string instead of an
    // array) now fails the parse the same way a type-invalid `alg` does —
    // see `test_parse_jwks_set_rejects_type_invalid_x5c` below.
    #[test]
    fn test_parse_jwks_set_ignores_unknown_members_but_requires_kty() {
        let with_x5c_and_future_member = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "x5c": ["ZmFrZS1jZXJ0"],
                "x5t#S256": "ZmFrZS10aHVtYnByaW50",
                "some_future_extension": {"nested": true}
            }]
        });
        let set = parse_jwks_set(&with_x5c_and_future_member)
            .expect("unknown/future JWK members must not fail the parse");
        assert_eq!(set.keys.len(), 1);
        assert_eq!(
            set.keys.first().and_then(|k| k.x5c.as_ref()),
            Some(&vec!["ZmFrZS1jZXJ0".to_string()]),
            "x5c is a known, typed member and must populate the struct"
        );

        let missing_kty = serde_json::json!({"keys": [{"alg": "ES256"}]});
        assert!(
            parse_jwks_set(&missing_kty).is_err(),
            "kty is the only REQUIRED JWK member and must fail its absence"
        );
    }

    #[test]
    fn test_key_type_accepts_an_unrecognized_kty_registered_later_by_another_rfc() {
        // "AKP" is a real, currently-registered IANA "kty" value (RFC 9964,
        // "ML-DSA for JOSE and COSE") — chosen over a made-up string to
        // prove the open-registry design against a genuine later addition,
        // not just an arbitrary one this crate will never see.
        let jwks = serde_json::json!({"keys": [{"kty": "AKP"}]});
        let set = parse_jwks_set(&jwks).expect("an unrecognized kty must still parse");
        assert_eq!(
            set.keys.first().map(|k| &k.kty),
            Some(&KeyType::Other("AKP".to_string()))
        );
    }

    #[test]
    fn test_key_type_is_case_sensitive() {
        // RFC 7517 §4.1 (quoted above): "The 'kty' value is a case-sensitive
        // string" — "ec" is a different, unrecognized value, not `Ec`.
        let jwks = serde_json::json!({"keys": [{"kty": "ec"}]});
        let set = parse_jwks_set(&jwks).expect("valid JSON shape must still parse");
        assert_eq!(
            set.keys.first().map(|k| &k.kty),
            Some(&KeyType::Other("ec".to_string()))
        );
    }

    #[test]
    fn test_parse_jwks_set_rejects_type_invalid_x5c() {
        let string_x5c = serde_json::json!({"keys": [{"kty": "RSA", "x5c": "not-an-array"}]});
        assert!(parse_jwks_set(&string_x5c).is_err());

        let non_string_entry = serde_json::json!({"keys": [{"kty": "RSA", "x5c": [123]}]});
        assert!(parse_jwks_set(&non_string_entry).is_err());
    }

    #[test]
    fn test_jwks_has_x5c() {
        let with_x5c = parse_jwks_set(&serde_json::json!({
            "keys": [{"kty": "RSA", "x5c": ["ZmFrZS1jZXJ0"]}]
        }))
        .expect("valid fixture");
        assert!(jwks_has_x5c(&with_x5c));

        let empty_x5c = parse_jwks_set(&serde_json::json!({
            "keys": [{"kty": "RSA", "x5c": []}]
        }))
        .expect("valid fixture");
        assert!(
            !jwks_has_x5c(&empty_x5c),
            "an empty x5c array carries no certificate"
        );

        let no_x5c = parse_jwks_set(&serde_json::json!({
            "keys": [{"kty": "RSA", "n": "n", "e": "AQAB"}]
        }))
        .expect("valid fixture");
        assert!(!jwks_has_x5c(&no_x5c));

        let mixed = parse_jwks_set(&serde_json::json!({
            "keys": [
                {"kty": "RSA", "n": "n", "e": "AQAB"},
                {"kty": "RSA", "x5c": ["ZmFrZS1jZXJ0"]}
            ]
        }))
        .expect("valid fixture");
        assert!(jwks_has_x5c(&mixed), "one x5c-bearing key is enough");
    }

    #[test]
    fn test_access_scope_from_str() {
        let result: Result<AccessScope, _> = "organization".parse();
        assert_eq!(result, Ok(AccessScope::Organization));

        let result: Result<AccessScope, _> = "personal".parse();
        assert_eq!(result, Ok(AccessScope::Personal));

        let result: Result<AccessScope, _> = "public".parse();
        assert_eq!(result, Ok(AccessScope::Public));

        let result: Result<AccessScope, _> = "invalid".parse();
        assert!(result.is_err());

        let result: Result<AccessScope, _> = "".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_access_scope_from_str_case_insensitive() {
        let result: Result<AccessScope, _> = "ORGANIZATION".parse();
        assert_eq!(result, Ok(AccessScope::Organization));

        let result: Result<AccessScope, _> = "Personal".parse();
        assert_eq!(result, Ok(AccessScope::Personal));

        let result: Result<AccessScope, _> = "PUBLIC".parse();
        assert_eq!(result, Ok(AccessScope::Public));
    }

    #[test]
    fn test_access_scope_as_str() {
        assert_eq!(AccessScope::Organization.as_str(), "organization");
        assert_eq!(AccessScope::Personal.as_str(), "personal");
        assert_eq!(AccessScope::Public.as_str(), "public");
    }

    #[test]
    fn test_access_scope_default() {
        assert_eq!(AccessScope::default(), AccessScope::Personal);
    }

    #[test]
    fn test_access_scope_display_name() {
        assert_eq!(AccessScope::Organization.display_name(), "Organization");
        assert_eq!(AccessScope::Personal.display_name(), "Personal");
        assert_eq!(AccessScope::Public.display_name(), "Public");
    }

    #[test]
    fn test_access_scope_description() {
        assert!(
            AccessScope::Organization
                .description()
                .contains("organization")
        );
        assert!(AccessScope::Personal.description().contains("you"));
        assert!(AccessScope::Public.description().contains("Any"));
    }

    #[test]
    fn test_access_scope_display_roundtrip() {
        for scope in [
            AccessScope::Organization,
            AccessScope::Personal,
            AccessScope::Public,
        ] {
            let display_str = scope.to_string();
            let parsed: Result<AccessScope, _> = display_str.parse();
            assert_eq!(parsed, Ok(scope));
        }
    }

    #[test]
    fn test_token_endpoint_auth_method_from_str_basic() {
        let result: Result<TokenEndpointAuthMethod, _> = "client_secret_basic".parse();
        assert!(result.is_ok());
        assert_eq!(result, Ok(TokenEndpointAuthMethod::ClientSecretBasic));
    }

    #[test]
    fn test_token_endpoint_auth_method_from_str_post() {
        let result: Result<TokenEndpointAuthMethod, _> = "client_secret_post".parse();
        assert!(result.is_ok());
        assert_eq!(result, Ok(TokenEndpointAuthMethod::ClientSecretPost));
    }

    #[test]
    fn test_token_endpoint_auth_method_from_str_jwt() {
        let result: Result<TokenEndpointAuthMethod, _> = "private_key_jwt".parse();
        assert!(result.is_ok());
        assert_eq!(result, Ok(TokenEndpointAuthMethod::PrivateKeyJwt));
    }

    #[test]
    fn test_token_endpoint_auth_method_from_str_none() {
        let result: Result<TokenEndpointAuthMethod, _> = "none".parse();
        assert!(result.is_ok());
        assert_eq!(result, Ok(TokenEndpointAuthMethod::None));
    }

    #[test]
    fn test_token_endpoint_auth_method_rejects_unknown() {
        let result: Result<TokenEndpointAuthMethod, _> = "magic_auth".parse();
        assert!(result.is_err());

        let result2: Result<TokenEndpointAuthMethod, _> = "".parse();
        assert!(result2.is_err());
    }

    #[test]
    fn test_token_endpoint_auth_method_display_roundtrip() {
        let variants = [
            TokenEndpointAuthMethod::ClientSecretBasic,
            TokenEndpointAuthMethod::ClientSecretPost,
            TokenEndpointAuthMethod::PrivateKeyJwt,
            TokenEndpointAuthMethod::None,
        ];
        for variant in variants {
            let display_str = variant.to_string();
            let parsed: Result<TokenEndpointAuthMethod, _> = display_str.parse();
            assert_eq!(parsed, Ok(variant));
        }
    }

    #[test]
    fn test_fapi_profile_as_str() {
        assert_eq!(FapiProfile::None.as_str(), "none");
        assert_eq!(FapiProfile::Fapi2Security.as_str(), "fapi2_security");
    }

    #[test]
    fn test_fapi_profile_default() {
        assert_eq!(FapiProfile::default(), FapiProfile::None);
    }

    #[test]
    fn test_fapi_profile_serde_roundtrip() {
        let json =
            serde_json::to_string(&FapiProfile::Fapi2Security).expect("FapiProfile serialization");
        assert_eq!(json, r#""fapi2_security""#);

        let parsed: FapiProfile = serde_json::from_str(&json).expect("FapiProfile deserialization");
        assert_eq!(parsed, FapiProfile::Fapi2Security);

        let none_json =
            serde_json::to_string(&FapiProfile::None).expect("FapiProfile::None serialization");
        assert_eq!(none_json, r#""none""#);
    }

    #[test]
    fn test_fapi_profile_client_assertion_algorithms_per_variant() {
        assert_eq!(
            FapiProfile::None.client_assertion_algorithms(),
            &JwsAlgorithm::CLIENT_ASSERTION_ALLOWED
        );
        assert_eq!(
            FapiProfile::Fapi2Security.client_assertion_algorithms(),
            &JwsAlgorithm::FAPI_ALLOWED
        );
    }

    #[test]
    fn test_client_assertion_algorithms_union_contains_every_profile_set() {
        let union = FapiProfile::client_assertion_algorithms_union();
        for profile in FapiProfile::ALL {
            for alg in profile.client_assertion_algorithms() {
                assert!(
                    union.contains(alg),
                    "{profile:?}'s allowed algorithm {alg} must be in the union"
                );
            }
        }
    }

    #[test]
    fn test_client_assertion_algorithms_union_matches_client_assertion_allowed() {
        // Non-FAPI already permits every algorithm any profile permits (RS256
        // plus the FAPI-allowed three), so today the union equals it exactly.
        // This pins that fact rather than assuming it: adding a profile with an
        // algorithm outside CLIENT_ASSERTION_ALLOWED would fail this test, not
        // silently widen or narrow what discovery advertises.
        let mut union: Vec<&str> = FapiProfile::client_assertion_algorithms_union()
            .iter()
            .map(JwsAlgorithm::as_str)
            .collect();
        union.sort_unstable();

        let mut allowed: Vec<&str> = JwsAlgorithm::CLIENT_ASSERTION_ALLOWED
            .iter()
            .map(JwsAlgorithm::as_str)
            .collect();
        allowed.sort_unstable();

        assert_eq!(union, allowed);
    }

    // ========================================================================
    // Test Helpers
    // ========================================================================

    use std::sync::Arc;

    use crate::crypto::document_crypto::PlaintextDocumentCrypto;
    use crate::db::Pool;

    async fn test_store() -> DocumentStore {
        let pool = Pool::connect("sqlite::memory:", &crate::db::pool::PoolConfig::default())
            .await
            .expect("Failed to create test database");

        match &pool {
            Pool::Sqlite(p) => sqlx::migrate!("./migrations/sqlite")
                .run(p)
                .await
                .expect("Failed to run migrations"),
            Pool::Postgres(p) => sqlx::migrate!("./migrations/postgres")
                .run(p)
                .await
                .expect("Failed to run migrations"),
        }

        let crypto: Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
            Arc::new(PlaintextDocumentCrypto);
        DocumentStore::new(pool, crypto)
    }

    async fn create_client_and_secret(
        store: &DocumentStore,
    ) -> (OAuthClient, OAuthClientSecret, String) {
        let (client, _client_id) = create_oauth_client(
            store,
            &CreateOAuthClientParams {
                user_id: Some("test-user"),
                name: "Test App",
                description: None,
                application_type: OAuthClientType::Web,
                redirect_uris: &["https://example.com/callback".to_string()],
                access_scope: AccessScope::Public,
                org_id: None,
                resource_uris: &[],
                token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
                keys: None,
                fapi_profile: None,
                dpop_bound_access_tokens: None,
                grant_types: None,
                response_types: None,
                software_id: None,
                software_version: None,
                registration_source: RegistrationSource::Manual,
                registration_access_token_hash: None,
                registration_metadata: None,
                id_token_signed_response_alg: JwsAlgorithm::Rs256,
                tls_client_auth_subject_dn: None,
                tls_client_auth_san_dns: None,
                tls_client_auth_san_uri: None,
                tls_client_auth_san_ip: None,
                tls_client_auth_san_email: None,
                tls_client_certificate_bound_access_tokens: None,
                authorization_signed_response_alg: None,
                introspection_signed_response_alg: None,
                request_object_signing_alg: None,
                require_signed_request_object: None,
                userinfo_signed_response_alg: None,
                request_uris: None,
                post_logout_redirect_uris: None,
            },
        )
        .await
        .expect("create client");

        let secret_hash = "hash_abc123";
        let secret =
            create_oauth_client_secret(store, &client.id, secret_hash, Some("test secret"), None)
                .await
                .expect("create secret");

        (client, secret, secret_hash.to_string())
    }

    // ========================================================================
    // Secret Retrieval Tests
    // ========================================================================

    #[tokio::test]
    async fn test_get_secret_by_id() {
        let store = test_store().await;
        let (_client, secret, _hash) = create_client_and_secret(&store).await;

        let fetched = get_oauth_client_secret_by_id(&store, &secret.id)
            .await
            .expect("db query");

        assert!(fetched.is_some());
        let fetched = fetched.unwrap();
        assert_eq!(fetched.id, secret.id);
        assert_eq!(fetched.oauth_client_id, secret.oauth_client_id);
        assert_eq!(fetched.description.as_deref(), Some("test secret"));
    }

    #[tokio::test]
    async fn test_get_secret_by_id_not_found() {
        let store = test_store().await;

        let fetched = get_oauth_client_secret_by_id(&store, "nonexistent-id")
            .await
            .expect("db query");

        assert!(fetched.is_none());
    }

    // ========================================================================
    // Secret Revocation Tests
    // ========================================================================

    #[tokio::test]
    async fn test_revoke_secret_sets_revoked_at() {
        let store = test_store().await;
        let (client, secret, _hash) = create_client_and_secret(&store).await;

        assert!(secret.revoked_at.is_none());

        // Need a second active secret so the floor guard passes.
        let _second = create_oauth_client_secret(
            &store,
            &client.id,
            "hash_second_for_revoke_test",
            None,
            None,
        )
        .await
        .expect("create second secret");

        revoke_oauth_client_secret(&store, &secret.id, &client.id)
            .await
            .expect("revoke");

        let fetched = get_oauth_client_secret_by_id(&store, &secret.id)
            .await
            .expect("db query")
            .expect("secret exists");

        assert!(fetched.revoked_at.is_some());
    }

    // ========================================================================
    // is_valid Tests
    // ========================================================================

    #[tokio::test]
    async fn test_secret_is_valid_active() {
        let store = test_store().await;
        let (_client, secret, _hash) = create_client_and_secret(&store).await;

        let now = Timestamp::now();
        assert!(secret.is_valid(&now));
    }

    #[tokio::test]
    async fn test_secret_is_valid_revoked() {
        let store = test_store().await;
        let (client, secret, _hash) = create_client_and_secret(&store).await;

        // Need a second active secret so the floor guard passes.
        let _second = create_oauth_client_secret(
            &store,
            &client.id,
            "hash_second_for_valid_test",
            None,
            None,
        )
        .await
        .expect("create second secret");

        revoke_oauth_client_secret(&store, &secret.id, &client.id)
            .await
            .expect("revoke");

        let fetched = get_oauth_client_secret_by_id(&store, &secret.id)
            .await
            .expect("db query")
            .expect("secret exists");

        let now = Timestamp::now();
        assert!(!fetched.is_valid(&now));
    }

    #[tokio::test]
    async fn test_secret_is_valid_expired() {
        let store = test_store().await;
        let (client, _secret, _hash) = create_client_and_secret(&store).await;

        let past = Timestamp::now()
            .checked_sub(jiff::SignedDuration::from_hours(1))
            .expect("valid timestamp");

        let expired_secret = create_oauth_client_secret(
            &store,
            &client.id,
            "hash_expired",
            Some("expired"),
            Some(past),
        )
        .await
        .expect("create expired secret");

        let now = Timestamp::now();
        assert!(!expired_secret.is_valid(&now));
    }

    // ========================================================================
    // Multiple Secrets Tests
    // ========================================================================

    #[tokio::test]
    async fn test_multiple_secrets_for_client() {
        let store = test_store().await;
        let (client, _secret1, _hash1) = create_client_and_secret(&store).await;

        let _secret2 = create_oauth_client_secret(
            &store,
            &client.id,
            "hash_second",
            Some("second secret"),
            None,
        )
        .await
        .expect("create second secret");

        let secrets = get_oauth_client_secrets(&store, &client.id)
            .await
            .expect("list secrets");

        assert_eq!(secrets.len(), 2);
    }

    // ========================================================================
    // Credential Validation Tests
    // ========================================================================

    #[tokio::test]
    async fn test_validate_credentials_with_either_secret() {
        let store = test_store().await;
        let (client, _secret1, hash1) = create_client_and_secret(&store).await;

        let hash2 = "hash_second_secret";
        let _secret2 = create_oauth_client_secret(&store, &client.id, hash2, Some("second"), None)
            .await
            .expect("create second secret");

        let result1 = validate_oauth_client_credentials(&store, &client.client_id, &hash1)
            .await
            .expect("validate with first");
        assert!(result1.is_some());

        let result2 = validate_oauth_client_credentials(&store, &client.client_id, hash2)
            .await
            .expect("validate with second");
        assert!(result2.is_some());
    }

    #[tokio::test]
    async fn test_validate_credentials_revoked_fails() {
        let store = test_store().await;
        let (client, secret, hash) = create_client_and_secret(&store).await;

        // Need a second active secret so the floor guard passes.
        let _second = create_oauth_client_secret(
            &store,
            &client.id,
            "hash_second_revoke_validate",
            None,
            None,
        )
        .await
        .expect("create second secret");

        revoke_oauth_client_secret(&store, &secret.id, &client.id)
            .await
            .expect("revoke");

        let result = validate_oauth_client_credentials(&store, &client.client_id, &hash)
            .await
            .expect("validate");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_retention_sweep_covers_usage_event_variants() {
        let store = test_store().await;
        let audit = AuditStore::new(store.pool().clone(), store.crypto().clone());
        let usage_variants = OAuthEventType::USAGE_EVENTS;

        for event_type in usage_variants {
            record_oauth_event(
                &audit,
                &store,
                &RecordOAuthEventParams {
                    oauth_client_id: "oauth-client-1",
                    event_type,
                    user_id: Some("user-1"),
                    ip_address: None,
                    user_agent: None,
                    details: Some("coverage test"),
                },
            )
            .await;
        }

        let before = jiff::Timestamp::now()
            .checked_add(jiff::SignedDuration::from_mins(5))
            .expect("valid timestamp arithmetic");

        // Usage events must be swept by the OAuth-events cutoff — this fails
        // if a usage variant's registry kind lost its OAuthEvents class.
        let deleted = audit
            .delete_expired_events(None, Some(before))
            .await
            .expect("delete old oauth usage events");
        assert_eq!(
            deleted,
            usage_variants.len() as u64,
            "oauth usage cleanup must cover all usage event variants"
        );

        for event_type in usage_variants {
            let persisted = audit
                .query_events(&AuditEventFilter {
                    event_types: Some(vec![event_type.kind().as_str().to_string()]),
                    ..AuditEventFilter::default()
                })
                .await
                .expect("query oauth audit events");
            assert!(
                persisted.is_empty(),
                "event type {} should be deleted by retention cleanup",
                event_type.kind().as_str()
            );
        }
    }
}
