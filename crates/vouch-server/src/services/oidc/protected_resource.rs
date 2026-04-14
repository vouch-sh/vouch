// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OAuth 2.0 Protected Resource Metadata (RFC 9728).
//!
//! This module builds the metadata document served at
//! `/.well-known/oauth-protected-resource` (and the path-insertion
//! variants described by RFC 9728 §3.1). The document advertises the
//! protected resource's capabilities — which authorization servers are
//! trusted, which bearer methods and DPoP algorithms are accepted,
//! whether mTLS or DPoP token binding is required, and so on — so that
//! clients can discover the resource's policy at runtime.
//!
//! In Vouch, the authorization server and the protected resource are
//! the same deployment. Accordingly:
//!
//! * `authorization_servers` always contains exactly the current
//!   `base_url` (i.e. Vouch itself).
//! * `jwks_uri` points at Vouch's existing JWKS endpoint. It is used
//!   by clients to verify the `signed_metadata` JWT below.
//! * `dpop_bound_access_tokens_required` is `true`: every access
//!   token Vouch issues is DPoP-bound (`cnf.jkt`), and the resource
//!   token extractor (`handlers::session::extract_resource_token`)
//!   rejects unbound tokens.
//!
//! ## Signed metadata (RFC 9728 §3.3)
//!
//! Every response includes a `signed_metadata` parameter — a JWS
//! compact-serialized JWT with `typ=oauth-protected-resource+jwt`,
//! `iss = base_url`, and claims that mirror the enclosing JSON
//! (minus `signed_metadata` itself, which RFC 9728 §3.3 forbids
//! recursing). Clients that consume `signed_metadata` MUST treat its
//! signed claims as authoritative when they differ from the
//! surrounding JSON; Vouch guarantees they do not differ.
//!
//! Including `signed_metadata` even though Vouch is AS == RS behind
//! mandatory TLS is a defense-in-depth choice rather than a
//! cryptographic necessity:
//!
//! 1. **TLS terminator drift**: the metadata document may be served
//!    through a CDN, reverse proxy, or service mesh that terminates
//!    TLS upstream of the Vouch process. A signed copy lets a client
//!    detect tampering even when it cannot itself validate the
//!    upstream chain.
//! 2. **Cache poisoning**: `Cache-Control: public, max-age=3600`
//!    invites intermediary caches; signed claims survive a
//!    compromised cache.
//! 3. **MCP-style clients**: the Model Context Protocol bootstraps
//!    via RFC 9728 and treats `signed_metadata` as the canonical
//!    description, falling back to the unsigned JSON only when
//!    absent. Emitting both ensures both classes of consumer behave
//!    identically.
//! 4. **Future-proofing**: when Vouch eventually splits the AS and
//!    RS deployments (e.g. moves credential issuance behind a
//!    separate service), `signed_metadata` already establishes the
//!    issuer-of-record convention without a wire-format change.
//!
//! ## Allowlist of sub-paths
//!
//! RFC 9728 §4 mandates that the `resource` value returned in the
//! metadata MUST be byte-identical to the resource identifier the
//! client used. Vouch accepts the path-insertion form
//! (`/.well-known/oauth-protected-resource/{*path}`) only for
//! endpoints that are in fact OAuth 2.0 protected resources, listed
//! in [`PROTECTED_RESOURCE_PREFIXES`]. Unknown sub-paths return 404.

use crate::AppState;
use crate::db::JwsAlgorithm;
use crate::services::ServiceError;
use crate::services::oidc::OAuthScope;
use serde::Serialize;
use std::sync::Arc;

/// Well-known URL suffix for the Protected Resource Metadata document
/// (RFC 9728 §3.1).
pub const WELL_KNOWN_SUFFIX: &str = "/.well-known/oauth-protected-resource";

/// JWT `typ` header for signed Protected Resource Metadata.
///
/// RFC 9728 does not prescribe a specific `typ`, but using a media
/// type distinct from the generic `JWT` makes it easier for clients to
/// refuse the token in contexts where they expect, say, an ID token.
pub const SIGNED_METADATA_TYP: &str = "oauth-protected-resource+jwt";

/// Allowlist of protected-resource sub-paths (without a leading `/`).
///
/// The path-insertion form of the well-known URL
/// (`/.well-known/oauth-protected-resource/{*path}`) is only honored
/// when the tail matches one of these prefixes. This enforces the
/// identity rule of RFC 9728 §4 ("the resource value returned MUST be
/// identical to the resource identifier used by the client") because
/// we never echo back a resource URL that isn't actually served.
///
/// The list is intentionally prefix-based: a client that asks about
/// `v1/credentials/aws/token` also matches the `v1/credentials/aws`
/// prefix if one were registered. Matches are exact or
/// prefix-with-trailing-slash to avoid accidental overlaps
/// (e.g. `v1/credentialsX` must not match `v1/credentials`).
pub const PROTECTED_RESOURCE_PREFIXES: &[&str] = &[
    "oauth/userinfo",
    "oauth/introspect",
    "oauth/register",
    "v1/credentials/ssh",
    "v1/credentials/aws/token",
    "v1/credentials/kubernetes/token",
    "v1/credentials/github/token",
    "v1/keys",
    "api/v1/org",
    "scim/v2",
];

/// Protected Resource Metadata document (RFC 9728 §2).
///
/// All fields defined by RFC 9728 are present. Fields that are
/// `Option`-typed are omitted from the JSON response when unset
/// (`skip_serializing_if`), per RFC 9728 §3.2 which treats absent
/// fields and `null` values as equivalent but discourages emitting
/// explicit `null`s.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ProtectedResourceMetadata {
    /// RFC 9728 §2: REQUIRED. Resource identifier URL. Per §4, the
    /// returned value MUST be byte-identical to the resource
    /// identifier used by the client to retrieve this metadata.
    pub resource: String,

    /// RFC 9728 §2: OPTIONAL (RECOMMENDED in practice). Authorization
    /// servers that can issue access tokens accepted by this
    /// resource. Vouch is its own authorization server, so this is
    /// always a single-element list containing `base_url`.
    pub authorization_servers: Vec<String>,

    /// RFC 9728 §2: OPTIONAL. URL of the resource's JWKS, used by
    /// clients to verify `signed_metadata` below and any future
    /// signed resource responses. Points at Vouch's existing JWKS
    /// (`{base_url}/oauth/jwks`), which also serves the AS keys
    /// because Vouch is AS == RS.
    pub jwks_uri: String,

    /// RFC 9728 §2: OPTIONAL (RECOMMENDED). OAuth 2.0 scopes accepted
    /// at this resource. Sourced from
    /// [`OAuthScope::all`] so the list stays in sync with the
    /// authorization server's `scopes_supported`.
    pub scopes_supported: Vec<String>,

    /// RFC 9728 §2: OPTIONAL. Supported methods for sending bearer
    /// tokens. Enum values are `"header"`, `"body"`, `"query"`
    /// (location, not scheme).
    ///
    /// Vouch advertises both `"header"` (the `Authorization:` header,
    /// covering both `Bearer` and `DPoP` schemes — used by every
    /// resource endpoint) and `"body"` (POST `application/x-www-form-
    /// urlencoded` `access_token=…` accepted at `/oauth/userinfo`
    /// per RFC 6750 §2.2). `"query"` is intentionally excluded:
    /// query-string tokens are forbidden by FAPI 2.0 §5.3.2.1 and
    /// none of Vouch's resource endpoints accept them.
    pub bearer_methods_supported: Vec<String>,

    /// RFC 9728 §2: OPTIONAL. JWS algorithms Vouch can use to sign
    /// responses from this resource, including
    /// `signed_metadata`. ES256 is always present; RS256 is added
    /// when an RSA signing key is configured.
    pub resource_signing_alg_values_supported: Vec<JwsAlgorithm>,

    /// RFC 9728 §2: OPTIONAL. Human-readable name of the resource.
    /// Sourced from `ServerConfig.resource_name`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,

    /// RFC 9728 §2: OPTIONAL. URL of human-readable developer
    /// documentation. Sourced from
    /// `ServerConfig.resource_documentation`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_documentation: Option<String>,

    /// RFC 9728 §2: OPTIONAL. URL of the resource's data-use policy.
    /// Sourced from `ServerConfig.resource_policy_uri`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_policy_uri: Option<String>,

    /// RFC 9728 §2: OPTIONAL. URL of the resource's terms of
    /// service. Sourced from `ServerConfig.resource_tos_uri`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_tos_uri: Option<String>,

    /// RFC 9728 §2 + RFC 8705 §3: OPTIONAL. `true` when tokens
    /// accepted at this resource may be bound to a mTLS client
    /// certificate. Mirrors the AS discovery document's
    /// `tls_client_certificate_bound_access_tokens` field so AS and
    /// RS advertise a consistent view.
    pub tls_client_certificate_bound_access_tokens: bool,

    /// RFC 9728 §2 + RFC 9396 §11.3: OPTIONAL. List of supported
    /// authorization-details type values. Vouch currently accepts
    /// any opaque type (same posture as the AS), so this is `None`
    /// and the field is omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details_types_supported: Option<Vec<String>>,

    /// RFC 9728 §2 + RFC 9449 §5.1: OPTIONAL. JWS algorithms accepted
    /// in DPoP proofs at this resource. RS256 is deliberately absent
    /// (FAPI 2.0 §5.2.2 excludes it).
    pub dpop_signing_alg_values_supported: Vec<JwsAlgorithm>,

    /// RFC 9728 §2 + RFC 9449: OPTIONAL. `true` means every access
    /// token accepted at this resource must be DPoP-bound
    /// (`cnf.jkt`). Vouch enforces this in
    /// [`crate::handlers::session::extract_resource_token`].
    pub dpop_bound_access_tokens_required: bool,

    /// RFC 9728 §3.3: OPTIONAL. JWS-signed JWT containing the same
    /// claims as the surrounding JSON (minus `signed_metadata`
    /// itself), with `iss = base_url`, `iat` set to now, and
    /// `typ = oauth-protected-resource+jwt`. Signed by Vouch's OIDC
    /// key; clients verify with the keys published at `jwks_uri`.
    pub signed_metadata: String,
}

/// Result of classifying a caller-supplied sub-path.
#[derive(Debug, PartialEq, Eq)]
pub enum SubPathClassification {
    /// Caller requested the root metadata document (no sub-path).
    Root,
    /// Caller requested a specific protected resource. The inner
    /// string is the canonical sub-path (without leading `/`) that
    /// matched the allowlist.
    Known(String),
    /// Sub-path did not match the allowlist; handler should return
    /// 404 per RFC 9728 §4.
    Unknown,
}

/// Classify a caller-supplied sub-path against the allowlist.
///
/// The input is the raw captured tail from axum's `{*path}`
/// matcher — it does not include a leading `/`. An empty string is
/// treated as [`SubPathClassification::Root`].
#[must_use]
pub fn classify_sub_path(raw_tail: &str) -> SubPathClassification {
    // Trim at most one leading slash to be forgiving if callers
    // pass a pre-normalized path; axum itself strips it.
    let tail = raw_tail.strip_prefix('/').unwrap_or(raw_tail);
    if tail.is_empty() {
        return SubPathClassification::Root;
    }
    for prefix in PROTECTED_RESOURCE_PREFIXES {
        if tail == *prefix {
            return SubPathClassification::Known((*prefix).to_string());
        }
        // Allow paths deeper than the registered prefix (e.g.
        // `oauth/register/{client_id}` under the `oauth/register`
        // prefix). We require a `/` boundary to avoid
        // `oauth/registerX` matching `oauth/register`.
        let mut bounded = String::with_capacity(prefix.len() + 1);
        bounded.push_str(prefix);
        bounded.push('/');
        if tail.starts_with(&bounded) {
            return SubPathClassification::Known(tail.to_string());
        }
    }
    SubPathClassification::Unknown
}

/// Build the Protected Resource Metadata document.
///
/// `resource_sub_path` is the caller-supplied sub-path (without a
/// leading `/`). `None` requests the root metadata document at
/// `{base_url}/.well-known/oauth-protected-resource`; the `resource`
/// field is then `base_url`. A `Some(path)` whose classification is
/// [`SubPathClassification::Known`] builds a per-endpoint metadata
/// document whose `resource` is `base_url + "/" + path`. Unknown
/// sub-paths return [`ServiceError::NotFound`].
///
/// # Errors
/// * [`ServiceError::NotFound`] when `resource_sub_path` does not
///   match the allowlist (RFC 9728 §4 identity rule).
/// * [`ServiceError::Internal`] when the `signed_metadata` JWT
///   cannot be produced (signing-key failure).
pub async fn build_protected_resource_metadata(
    state: &Arc<AppState>,
    resource_sub_path: Option<&str>,
) -> Result<ProtectedResourceMetadata, ServiceError> {
    // Snapshot config once to avoid races with hot-reload.
    let config = state.config();

    let classification = match resource_sub_path {
        None => SubPathClassification::Root,
        Some(p) => classify_sub_path(p),
    };

    let (resource, sub_path_for_claims) = match classification {
        SubPathClassification::Root => (config.base_url.clone(), None),
        SubPathClassification::Known(canonical) => {
            // Concatenate base_url + "/" + tail literally (no URL
            // normalization) so the echoed value is byte-identical
            // to what the client asked for, per RFC 9728 §4.
            let trimmed_base = config.base_url.trim_end_matches('/');
            let full = format!("{trimmed_base}/{canonical}");
            (full, Some(canonical))
        }
        SubPathClassification::Unknown => {
            return Err(ServiceError::NotFound("protected resource"));
        }
    };

    let resource_signing_alg_values_supported = if state.oidc_rsa_key.is_some() {
        vec![JwsAlgorithm::Rs256, JwsAlgorithm::Es256]
    } else {
        vec![JwsAlgorithm::Es256]
    };

    let scopes_supported: Vec<String> = OAuthScope::all()
        .iter()
        .map(|s| s.as_str().to_string())
        .collect();

    let dpop_signing_alg_values_supported = vec![
        // RS256 excluded per FAPI 2.0 §5.2.2 (matches discovery.rs).
        JwsAlgorithm::Es256,
        JwsAlgorithm::Ps256,
        JwsAlgorithm::EdDsa,
    ];

    // Build the metadata first with an empty `signed_metadata`; sign
    // a copy of the claims; then populate `signed_metadata`. The
    // signed claims contain the same fields as the outer JSON
    // (minus `signed_metadata` itself) so consumers that trust the
    // JWS see an identical view.
    let mut metadata = ProtectedResourceMetadata {
        resource: resource.clone(),
        authorization_servers: vec![config.base_url.clone()],
        jwks_uri: format!("{}/oauth/jwks", config.base_url.trim_end_matches('/')),
        scopes_supported,
        bearer_methods_supported: vec!["header".to_string(), "body".to_string()],
        resource_signing_alg_values_supported,
        resource_name: config.resource_name.clone(),
        resource_documentation: config.resource_documentation.clone(),
        resource_policy_uri: config.resource_policy_uri.clone(),
        resource_tos_uri: config.resource_tos_uri.clone(),
        tls_client_certificate_bound_access_tokens: config.tls_cert.is_some(),
        authorization_details_types_supported: None,
        dpop_signing_alg_values_supported,
        dpop_bound_access_tokens_required: true,
        signed_metadata: String::new(),
    };

    let jwt = build_signed_metadata(state, &metadata, &config.base_url).await?;
    metadata.signed_metadata = jwt;

    // Keep `sub_path_for_claims` alive for tracing; silences unused warn
    // if the variable ends up dead in optimized builds.
    let _ = sub_path_for_claims;

    Ok(metadata)
}

/// Sign the metadata claims as a JWS compact JWT (RFC 9728 §3.3).
///
/// The JWT payload is the metadata serialized as a JSON object with
/// `signed_metadata` removed (forbidden by §3.3) and two additional
/// claims:
///
/// * `iss` — `base_url` (REQUIRED by §3.3).
/// * `iat` — current Unix timestamp (RECOMMENDED for freshness /
///   cache validation).
///
/// The header's `typ` is [`SIGNED_METADATA_TYP`].
async fn build_signed_metadata(
    state: &Arc<AppState>,
    metadata: &ProtectedResourceMetadata,
    base_url: &str,
) -> Result<String, ServiceError> {
    // Serialize metadata to a JSON value, then strip `signed_metadata`
    // and add iss/iat. Using `serde_json::Value` rather than a
    // dedicated struct keeps the signed claim set trivially in sync
    // with the outer JSON.
    let mut claims = serde_json::to_value(metadata).map_err(|e| {
        ServiceError::Internal(format!(
            "Failed to serialize protected resource metadata: {e}"
        ))
    })?;

    if let Some(obj) = claims.as_object_mut() {
        obj.remove("signed_metadata");
        obj.insert(
            "iss".to_string(),
            serde_json::Value::String(base_url.to_string()),
        );
        // RFC 9728 §3.3 leaves timestamps optional but recommends
        // `iat` for consumers performing freshness checks.
        let now = jiff::Timestamp::now().as_second();
        obj.insert("iat".to_string(), serde_json::Value::Number(now.into()));
    } else {
        return Err(ServiceError::Internal(
            "Protected resource metadata did not serialize as a JSON object".to_string(),
        ));
    }

    state
        .oidc_key
        .sign_jwt_with_typ(&claims, Some(SIGNED_METADATA_TYP))
        .await
        .map_err(|e| {
            tracing::error!("Failed to sign protected resource metadata: {e}");
            ServiceError::Internal("Failed to sign protected resource metadata".to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_sub_path_empty_is_root() {
        assert_eq!(classify_sub_path(""), SubPathClassification::Root);
    }

    #[test]
    fn classify_sub_path_exact_allowlist() {
        assert_eq!(
            classify_sub_path("oauth/userinfo"),
            SubPathClassification::Known("oauth/userinfo".to_string())
        );
        assert_eq!(
            classify_sub_path("v1/credentials/ssh"),
            SubPathClassification::Known("v1/credentials/ssh".to_string())
        );
    }

    #[test]
    fn classify_sub_path_leading_slash_tolerated() {
        assert_eq!(
            classify_sub_path("/oauth/userinfo"),
            SubPathClassification::Known("oauth/userinfo".to_string())
        );
    }

    #[test]
    fn classify_sub_path_deeper_matches_prefix() {
        assert_eq!(
            classify_sub_path("oauth/register/abc-123"),
            SubPathClassification::Known("oauth/register/abc-123".to_string())
        );
        assert_eq!(
            classify_sub_path("scim/v2/Users/42"),
            SubPathClassification::Known("scim/v2/Users/42".to_string())
        );
    }

    #[test]
    fn classify_sub_path_unknown_rejected() {
        assert_eq!(
            classify_sub_path("does/not/exist"),
            SubPathClassification::Unknown
        );
    }

    #[test]
    fn classify_sub_path_does_not_overlap_boundary() {
        // Must not match `oauth/register` prefix.
        assert_eq!(
            classify_sub_path("oauth/registerX"),
            SubPathClassification::Unknown
        );
    }
}
