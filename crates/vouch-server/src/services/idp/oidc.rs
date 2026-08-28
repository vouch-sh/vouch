// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OIDC discovery client for upstream identity providers.
//!
//! Fetches and caches the OpenID Connect discovery document (RFC 8414)
//! at startup to discover authorization, token, and JWKS endpoints.

use secrecy::SecretString;
use serde::Deserialize;
use url::Url;

use super::IdentityResult;

/// A fully configured OIDC provider: discovery endpoints + client credentials.
///
/// Built at startup by calling `fetch_discovery` for each OIDC provider and
/// storing the result together with credentials in `AppState::idps`.
#[derive(Debug, Clone)]
pub struct ConfiguredOidcProvider {
    /// Operator-chosen slug (e.g., "google", "entra").
    pub id: String,
    /// Client ID for this provider.
    pub client_id: String,
    /// Client secret for this provider.
    pub client_secret: SecretString,
    /// Discovered OIDC endpoints.
    pub provider: OidcProvider,
}

impl ConfiguredOidcProvider {
    /// Initiate an OIDC authorization code flow for this provider.
    ///
    /// Returns an `AuthRequest` with the redirect URL, state key, nonce, and
    /// PKCE code_verifier (RFC 7636). The caller must store the state key in
    /// the database before redirecting the user.
    ///
    /// # Errors
    ///
    /// Returns an error if random byte generation fails.
    pub(crate) fn initiate_auth(
        &self,
        base_url: &str,
    ) -> Result<super::AuthRequest, anyhow::Error> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let state_bytes = crate::crypto::generate_random_bytes(32)?;
        let nonce_bytes = crate::crypto::generate_random_bytes(32)?;
        let state_key = URL_SAFE_NO_PAD.encode(state_bytes);
        let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);

        let verifier_bytes = crate::crypto::generate_random_bytes(32)?;
        let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
        let challenge_digest =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, code_verifier.as_bytes());
        let code_challenge = URL_SAFE_NO_PAD.encode(challenge_digest.as_ref());

        let redirect_uri = format!("{base_url}/oauth/callback");
        let mut url = self.provider.authorization_endpoint.clone();
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", "openid email")
            .append_pair("state", &state_key)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &code_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("prompt", "login");

        Ok(super::AuthRequest {
            action: super::AuthAction::Redirect {
                url: url.to_string(),
            },
            state_key,
            nonce,
            code_verifier,
        })
    }
}

/// Cached OIDC discovery endpoints (RFC 8414).
#[derive(Debug, Clone)]
pub struct OidcProvider {
    /// The issuer identifier (must match the configured issuer).
    pub issuer: String,
    /// The authorization endpoint URL.
    pub authorization_endpoint: Url,
    /// The token endpoint URL.
    pub token_endpoint: Url,
    /// The JWKS endpoint URL (for ID token signature verification).
    pub jwks_uri: Url,
}

impl OidcProvider {
    /// CSP `form-action` origin for the authorization endpoint.
    ///
    /// Returns `None` if the endpoint URL has no host or a non-http(s) scheme;
    /// in practice this never happens because `fetch_discovery` rejects such
    /// inputs, but the type expresses the invariant.
    #[must_use]
    pub fn form_action_origin(&self) -> Option<crate::infra::csp::CspOrigin> {
        crate::infra::csp::CspOrigin::from_url(&self.authorization_endpoint)
    }
}

#[derive(Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

/// Raw OIDC ID token claims (deserialization target, not exposed).
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    /// Token issuer — used for Entra cross-tenant validation.
    iss: String,
    /// Subject — the IdP's stable identifier for this user. Required by
    /// OIDC Core Section 2; a token without it fails deserialization and
    /// therefore verification (fail-closed). Account matching keys on
    /// `(iss, sub)`, never on the email string alone.
    sub: String,
    email: String,
    #[serde(default)]
    email_verified: bool,
    nonce: Option<String>,
    /// Google Workspace hosted domain claim.
    hd: Option<String>,
    /// Entra ID tenant ID claim (present in tokens from Microsoft).
    tid: Option<String>,
    /// Entra "Email Domain Owner Verified" optional claim. Entra does not emit
    /// the OIDC standard `email_verified` claim; instead, operators must add
    /// `xms_edov` under the app registration's Token configuration. `true`
    /// means the email's domain is admin-verified in the user's tenant.
    /// Required because vouch only accepts `/organizations/v2.0` or
    /// single-tenant Entra issuers (the `/common/` endpoint cannot emit
    /// optional claims and is rejected at discovery).
    /// See: <https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference>
    xms_edov: Option<bool>,
}

/// Check whether an issuer URL is an Entra `/organizations/` endpoint.
///
/// Returns `true` for both
/// `https://login.microsoftonline.com/organizations/v2.0` (Entra) and
/// `https://login.microsoftonline.com/organizations` variants.
///
/// Parses the URL and matches on `host_str()` to avoid substring spoofing
/// (e.g., `login.microsoftonline.com.evil.com`).
fn is_entra_organizations_issuer(issuer: &str) -> bool {
    let Ok(url) = Url::parse(issuer) else {
        return false;
    };
    url.host_str() == Some("login.microsoftonline.com")
        && (url.path().starts_with("/organizations/") || url.path() == "/organizations")
}

/// Check whether an issuer URL is an Entra `/common/` endpoint.
///
/// Parses the URL and matches on `host_str()` to avoid substring spoofing
/// (e.g., `login.microsoftonline.com.evil.com`).
fn is_entra_common_issuer(issuer: &str) -> bool {
    let Ok(url) = Url::parse(issuer) else {
        return false;
    };
    url.host_str() == Some("login.microsoftonline.com")
        && (url.path().starts_with("/common/") || url.path() == "/common")
}

/// Check whether an issuer URL points at any Microsoft Entra endpoint.
///
/// Parses the URL and matches on `host_str()` so lookalike domains
/// (`login.microsoftonline.com.evil.com`) are rejected. Used by
/// `verify_id_token` to gate Entra-specific behavior — `xms_edov`
/// honoring, tenant validation against `tid`, and the Entra-specific
/// error message that walks operators through the `xms_edov` claim
/// configuration (issue #425).
fn is_entra_host(issuer: &str) -> bool {
    Url::parse(issuer)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .as_deref()
        == Some("login.microsoftonline.com")
}

/// Check whether an issuer URL points at Google's OIDC endpoint.
///
/// Same rationale as [`is_entra_host`] — substring matching accepts
/// lookalike hosts (issue #425). Discovery validation gates `provider.issuer`,
/// but the verification path uses this for feature detection (using `hd` vs.
/// extracting domain from `email`); the consistency-with-discovery-helpers
/// invariant in this file matters for future-developer copy-paste safety.
fn is_google_host(issuer: &str) -> bool {
    Url::parse(issuer)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .as_deref()
        == Some("accounts.google.com")
}

/// Check whether an issuer URL is the Entra per-tenant template returned by
/// `/organizations/` discovery (literal `{tenantid}` placeholder).
///
/// This is the form stored in `OidcProvider::issuer` after `fetch_discovery`
/// for multi-tenant Entra endpoints — Microsoft returns the literal string
/// `https://login.microsoftonline.com/{tenantid}/v2.0` as the discovery
/// document's `issuer`, not a concrete tenant URL.
///
/// Parses the URL and matches on `host_str()` to avoid substring spoofing
/// (e.g., `login.microsoftonline.com.evil.com`). The `url` crate
/// percent-encodes `{` and `}` in paths, so we match the encoded form.
fn is_entra_tenant_template_issuer(issuer: &str) -> bool {
    let Ok(url) = Url::parse(issuer) else {
        return false;
    };
    if url.host_str() != Some("login.microsoftonline.com") {
        return false;
    }
    let path = url.path();
    path == "/%7Btenantid%7D" || path.starts_with("/%7Btenantid%7D/")
}

/// Validate that the discovered issuer matches the configured issuer,
/// with special handling for Entra `/organizations/v2.0` which returns
/// a per-tenant issuer template `{tenantid}`.
///
/// For Entra `/organizations/`, the discovered issuer is of the form
/// `https://login.microsoftonline.com/{tenant-uuid}/v2.0`
/// while the configured issuer is
/// `https://login.microsoftonline.com/organizations/v2.0`.
/// We accept the mismatch iff the discovered issuer matches the
/// Entra per-tenant pattern and the configured issuer is `/organizations/`.
fn validate_discovered_issuer(configured: &str, discovered: &str) -> anyhow::Result<()> {
    let configured = configured.trim_end_matches('/');
    let discovered = discovered.trim_end_matches('/');

    if discovered == configured {
        return Ok(());
    }

    // Entra `/organizations/` discovery returns either the literal placeholder
    // `https://login.microsoftonline.com/{tenantid}/v2.0` (per Microsoft docs)
    // or a concrete per-tenant URL. Accept either form when configured is an
    // `/organizations/` URL. `/common/` is rejected earlier in fetch_discovery.
    if is_entra_organizations_issuer(configured)
        && (is_entra_tenant_template_issuer(discovered)
            || extract_entra_tenant_from_issuer(discovered).is_some())
    {
        return Ok(());
    }

    anyhow::bail!(
        "Issuer mismatch: configured '{configured}' but discovery \
         document reports '{discovered}'"
    )
}

/// Fetch discovery from `{issuer}/.well-known/openid-configuration`.
///
/// # Errors
///
/// Returns error if fetch fails, JSON is invalid, required fields missing,
/// endpoints aren't valid URLs, or discovered issuer doesn't match configured.
pub(crate) async fn fetch_discovery(
    http_client: &reqwest::Client,
    issuer_url: &str,
) -> Result<OidcProvider, anyhow::Error> {
    let issuer = issuer_url.trim_end_matches('/');

    // Reject non-HTTPS issuers (except localhost for development)
    if let Ok(parsed) = Url::parse(issuer)
        && parsed.scheme() != "https"
        && !is_localhost(&parsed)
    {
        anyhow::bail!(
            "OIDC issuer must use HTTPS (got {issuer}). \
             HTTP is only allowed for localhost development."
        );
    }

    // Reject Entra `/common/` outright. Apps that include personal Microsoft
    // accounts cannot configure optional claims (per Microsoft docs), so the
    // `xms_edov` email-verification signal vouch requires can never be emitted.
    // Operators wanting any-tenant sign-in must use `/organizations/v2.0`.
    if is_entra_common_issuer(issuer) {
        anyhow::bail!(
            "Entra `/common/` issuer is not supported: app registrations that \
             include personal Microsoft accounts cannot emit the `xms_edov` \
             email-verification claim required by vouch. Use \
             `https://login.microsoftonline.com/organizations/v2.0` for any \
             work/school tenant, or \
             `https://login.microsoftonline.com/<tenant-id>/v2.0` to restrict \
             to a single tenant."
        );
    }

    let discovery_url = format!("{issuer}/.well-known/openid-configuration");

    let response = http_client.get(&discovery_url).send().await.map_err(|e| {
        anyhow::anyhow!("Failed to fetch discovery document from {discovery_url}: {e}")
    })?;

    if !response.status().is_success() {
        anyhow::bail!(
            "Discovery endpoint returned HTTP {}: {discovery_url}",
            response.status()
        );
    }

    let doc: DiscoveryDocument = response
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to parse discovery document: {e}"))?;

    // RFC 8414 Section 3.3: validate discovered issuer against configured issuer.
    // Entra /organizations/ endpoint returns a per-tenant issuer; validate_discovered_issuer
    // accepts that template expansion.
    validate_discovered_issuer(issuer, &doc.issuer)?;

    let authorization_endpoint = Url::parse(&doc.authorization_endpoint).map_err(|e| {
        anyhow::anyhow!(
            "Invalid authorization_endpoint '{}': {e}",
            doc.authorization_endpoint
        )
    })?;

    let token_endpoint = Url::parse(&doc.token_endpoint)
        .map_err(|e| anyhow::anyhow!("Invalid token_endpoint '{}': {e}", doc.token_endpoint))?;

    let jwks_uri = Url::parse(&doc.jwks_uri)
        .map_err(|e| anyhow::anyhow!("Invalid jwks_uri '{}': {e}", doc.jwks_uri))?;

    Ok(OidcProvider {
        issuer: doc.issuer,
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
    })
}

/// Verify an ID token from the upstream IdP and return a protocol-agnostic
/// [`IdentityResult`].
///
/// Fetches the JWKS from the provider's `jwks_uri`, verifies the JWT
/// signature, validates `iss`/`aud`/`exp`/`nonce` claims, checks
/// `email_verified`, and extracts the hosted domain (`hd`) claim.
///
/// # Errors
///
/// Returns error if JWKS fetch fails, no matching key is found,
/// signature is invalid, claims validation fails, nonce mismatches,
/// or the email is not verified.
pub(crate) async fn verify_id_token(
    http_client: &reqwest::Client,
    provider: &OidcProvider,
    id_token: &str,
    expected_client_id: &str,
    expected_nonce: &str,
) -> Result<IdentityResult, anyhow::Error> {
    // RFC 7515 Section 4.1.11: "If any of the listed extension Header
    // Parameters are not understood and supported by the recipient, then the
    // JWS is invalid." Vouch supports no `crit` extension, so a `crit`-bearing
    // ID token never yields a header at all.
    let jws = crate::crypto::jwt::Jws::parse(id_token).map_err(|e| match e {
        crate::crypto::jwt::JwsError::Critical => {
            anyhow::anyhow!("ID token header carries an unsupported 'crit' extension")
        }
        crate::crypto::jwt::JwsError::Malformed(reason) => {
            anyhow::anyhow!("Invalid ID token: {reason}")
        }
    })?;

    // The signing algorithm, from the header already decoded above.
    let alg: jsonwebtoken::Algorithm = jws
        .header()
        .alg
        .parse()
        .map_err(|_| anyhow::anyhow!("Unsupported ID token algorithm: {}", jws.header().alg))?;

    // Fetch JWKS from the upstream IdP
    let jwks_response = http_client
        .get(provider.jwks_uri.as_str())
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch JWKS from {}: {e}", provider.jwks_uri))?;

    if !jwks_response.status().is_success() {
        anyhow::bail!(
            "JWKS endpoint returned HTTP {}: {}",
            jwks_response.status(),
            provider.jwks_uri,
        );
    }

    let jwks: jsonwebtoken::jwk::JwkSet = jwks_response
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to parse JWKS: {e}"))?;

    // Find matching key by kid, then by algorithm
    let decoding_key = find_decoding_key(&jwks, jws.header().kid.as_deref(), alg)?;

    // Entra `/organizations/v2.0` discovery stores the literal `{tenantid}`
    // placeholder in `provider.issuer`; real tokens carry a concrete tenant
    // UUID. In that case skip the jsonwebtoken `iss` check and validate the
    // shape of `claims.iss` after decoding. Single-tenant Entra and other
    // IdPs use the standard check.
    let entra_template_issuer = is_entra_tenant_template_issuer(&provider.issuer);

    let mut validation = jsonwebtoken::Validation::new(alg);
    if !entra_template_issuer {
        validation.set_issuer(&[&provider.issuer]);
    }
    validation.set_audience(&[expected_client_id]);

    let token_data = jsonwebtoken::decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|e| anyhow::anyhow!("ID token verification failed: {e}"))?;

    let claims = token_data.claims;

    if entra_template_issuer && extract_entra_tenant_from_issuer(&claims.iss).is_none() {
        anyhow::bail!(
            "Entra token issuer '{}' is not a valid per-tenant issuer. \
             Expected https://login.microsoftonline.com/<uuid>/v2.0",
            claims.iss
        );
    }

    // OIDC Core Section 3.1.3.7: Verify nonce matches the value sent
    // in the authentication request to prevent replay attacks.
    // Empty nonce is only valid for device-code flow where no nonce is sent.
    if !expected_nonce.is_empty() {
        match &claims.nonce {
            Some(nonce) if nonce == expected_nonce => {}
            Some(nonce) => {
                anyhow::bail!(
                    "ID token nonce mismatch: expected '{expected_nonce}', \
                     got '{nonce}'"
                );
            }
            None => {
                anyhow::bail!("ID token missing nonce claim (expected '{expected_nonce}')");
            }
        }
    }

    // Verify email is asserted-verified by the IdP. Standard OIDC providers
    // emit `email_verified`; Entra never does and instead uses the optional
    // `xms_edov` (Email Domain Owner Verified) claim. `xms_edov` is honored
    // only for Entra issuers — it's an Entra-specific signal.
    let is_entra_issuer = is_entra_host(&provider.issuer);
    let email_is_verified =
        claims.email_verified || (is_entra_issuer && claims.xms_edov == Some(true));
    if !email_is_verified {
        if is_entra_issuer {
            anyhow::bail!(
                "Email address is not verified by the identity provider. \
                 Microsoft Entra does not emit `email_verified`; configure the \
                 `xms_edov` optional claim on your app registration (Azure \
                 portal → App registrations → your app → Token configuration → \
                 Add optional claim → ID → xms_edov) and re-attempt enrollment. \
                 Note: the app's supported account types must exclude personal \
                 Microsoft accounts — `/common/v2.0` is not supported."
            );
        }
        anyhow::bail!("Email address is not verified by the identity provider");
    }

    // Entra-specific tenant validation.
    // For Entra issuers, cross-check the `tid` claim against the tenant UUID
    // in the token's `iss` claim to prevent cross-tenant token injection. When
    // `/organizations/` is configured, provider.issuer holds the `{tenantid}`
    // template; claims.iss holds the real per-tenant UUID from the validated
    // token.
    if is_entra_issuer {
        let tid = claims.tid.as_deref().unwrap_or("");

        if let Some(expected_tid) = extract_entra_tenant_from_issuer(&claims.iss)
            && !tid.eq_ignore_ascii_case(expected_tid)
        {
            anyhow::bail!(
                "Entra tid claim '{tid}' does not match issuer tenant '{expected_tid}'. \
                 Possible cross-tenant token injection."
            );
        }

        tracing::info!(tid = %tid, iss = %claims.iss, "Entra tenant validated");
    }

    // Domain extraction:
    // - Google with `hd` claim: use it (Workspace hosted domain).
    // - Google without `hd`: None (consumer account, don't group).
    // - All other providers (including Entra): extract domain from the email
    //   address. Personal Microsoft accounts cannot reach this point because
    //   `/common/` is rejected at discovery and `/organizations/` excludes MSA.
    //
    // Normalize to ASCII lowercase so that org lookups match regardless of
    // the case the IdP returned. Org domains are stored lowercase.
    // `Email::domain_of` splits on the last `@` — the same semantics the
    // audit and org-domain layers use — where `split('@').nth(1)` picked
    // the wrong "domain" for a quoted local part containing `@`.
    let is_google = is_google_host(&provider.issuer);
    let domain = if is_google {
        claims.hd.as_deref().map(str::to_ascii_lowercase)
    } else {
        crate::email::Email::domain_of(&claims.email)
    };

    // Bind to `claims.iss` (the validated token issuer), not
    // `provider.issuer`: for Entra `/organizations/` the configured issuer
    // is the literal `{tenantid}` template, while `claims.iss` names the
    // concrete tenant — the identity must be pinned to the real tenant.
    Ok(IdentityResult {
        upstream: Some(crate::db::UpstreamLogin {
            issuer: claims.iss,
            durable_subject: Some(claims.sub),
        }),
        email: claims.email,
        domain,
    })
}

/// Extract the tenant UUID from an Entra issuer URL.
///
/// Returns the path segment after `login.microsoftonline.com/` that is
/// a UUID-shaped string. Returns `None` for `/organizations/` and `/common/`
/// endpoints (no static tenant to cross-check against).
fn extract_entra_tenant_from_issuer(issuer: &str) -> Option<&str> {
    // Issuer pattern: https://login.microsoftonline.com/{tenant-uuid}/v2.0
    // We extract the segment between the first `/` after the hostname and the next `/`.
    let after_host = issuer.strip_prefix("https://login.microsoftonline.com/")?;
    let segment = after_host.split('/').next()?;
    // Skip well-known non-UUID segments (organizations, common, consumers, etc.)
    if matches!(segment, "organizations" | "common" | "consumers" | "") {
        return None;
    }
    // Accept as tenant UUID: must look like a UUID (contains hyphens, length 36)
    if segment.len() == 36 && segment.chars().filter(|c| *c == '-').count() == 4 {
        return Some(segment);
    }
    None
}

/// Find a `DecodingKey` from a JWKS matching the given `kid` and algorithm.
///
/// A JWKS may contain key types this crate cannot use — `jsonwebtoken` keeps
/// them as `AlgorithmParameters::Other` rather than rejecting the whole set —
/// so the algorithm and last-resort searches skip entries that fail to convert.
fn find_decoding_key(
    jwks: &jsonwebtoken::jwk::JwkSet,
    kid: Option<&str>,
    alg: jsonwebtoken::Algorithm,
) -> Result<jsonwebtoken::DecodingKey, anyhow::Error> {
    let expected_key_alg = jsonwebtoken::jwk::KeyAlgorithm::from(alg);

    // Try matching by kid first
    if let Some(kid) = kid {
        for jwk in &jwks.keys {
            if jwk.common.key_id.as_deref() == Some(kid) {
                return jsonwebtoken::DecodingKey::from_jwk(jwk)
                    .map_err(|e| anyhow::anyhow!("Failed to build key from JWK (kid={kid}): {e}"));
            }
        }
        anyhow::bail!("No key with kid '{kid}' found in upstream JWKS");
    }

    // Fall back to matching by algorithm
    for jwk in &jwks.keys {
        if jwk.common.key_algorithm != Some(expected_key_alg) {
            continue;
        }
        match jsonwebtoken::DecodingKey::from_jwk(jwk) {
            Ok(key) => return Ok(key),
            Err(e) => tracing::warn!(error = %e, "Skipping unusable {expected_key_alg} JWK"),
        }
    }

    // Last resort: the first key we can actually use (no kid/algorithm matched)
    tracing::warn!("No JWK matched by kid or algorithm, falling back to first usable key in JWKS");
    for jwk in &jwks.keys {
        match jsonwebtoken::DecodingKey::from_jwk(jwk) {
            Ok(key) => return Ok(key),
            Err(e) => tracing::warn!(error = %e, "Skipping unusable JWK"),
        }
    }

    anyhow::bail!("Upstream JWKS contains no key usable for {alg:?}")
}

/// Check if a URL points to localhost.
fn is_localhost(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests;
