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
    email: String,
    #[serde(default)]
    email_verified: bool,
    nonce: Option<String>,
    /// Google Workspace hosted domain claim.
    hd: Option<String>,
    /// Entra ID tenant ID claim (present in tokens from Microsoft).
    tid: Option<String>,
}

/// MSA (Microsoft consumer accounts) meta-tenant ID.
///
/// Tokens from this tenant are personal Microsoft accounts (outlook.com,
/// hotmail.com, live.com, or external emails bound to an MSA), not work/school
/// accounts. They are allowed to sign in but receive no auto-created
/// organization — domain extraction returns `None` for them, matching the
/// behavior of Google consumer accounts that lack the `hd` claim.
const ENTRA_MSA_TENANT_ID: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";

/// Check whether an issuer URL is an Entra `/organizations/` endpoint.
///
/// Returns `true` for both
/// `https://login.microsoftonline.com/organizations/v2.0` (Entra) and
/// `https://login.microsoftonline.com/organizations` variants.
fn is_entra_organizations_issuer(issuer: &str) -> bool {
    issuer.contains("login.microsoftonline.com")
        && (issuer.contains("/organizations/") || issuer.ends_with("/organizations"))
}

/// Check whether an issuer URL is an Entra `/common/` endpoint.
fn is_entra_common_issuer(issuer: &str) -> bool {
    issuer.contains("login.microsoftonline.com")
        && (issuer.contains("/common/") || issuer.ends_with("/common"))
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

    // Entra /organizations/ and /common/ endpoints return a per-tenant issuer.
    // Accept it iff:
    //   - configured issuer is an /organizations/ or /common/ URL
    //   - discovered issuer is login.microsoftonline.com/<uuid>/v2.0
    if (is_entra_organizations_issuer(configured) || is_entra_common_issuer(configured))
        && discovered.starts_with("https://login.microsoftonline.com/")
        && discovered.ends_with("/v2.0")
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

    // Note at startup if /common/ endpoint is configured. /common/ accepts
    // both work/school and personal Microsoft accounts; personal accounts are
    // allowed to sign in but have no auto-created organization (their domain
    // is reported as `None`, matching Google consumer accounts without `hd`).
    // Use /organizations/v2.0 if you want to restrict to AAD work/school
    // tenants only.
    if is_entra_common_issuer(issuer) {
        tracing::info!(
            "Entra /common/ endpoint configured. Personal Microsoft accounts \
             (tid={}) can sign in; they will not be grouped into an organization.",
            ENTRA_MSA_TENANT_ID
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
    // Decode the JWT header to determine algorithm and key ID
    let header = jsonwebtoken::decode_header(id_token)
        .map_err(|e| anyhow::anyhow!("Invalid ID token header: {e}"))?;

    let alg = header.alg;

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
    let decoding_key = find_decoding_key(&jwks, header.kid.as_deref(), alg)?;

    // Validate the token: signature, exp, iss, aud
    let mut validation = jsonwebtoken::Validation::new(alg);
    // Entra /organizations/ and /common/ discovery returns the literal template
    // `{tenantid}` as the issuer in OidcProvider::issuer. Real tokens contain a
    // per-tenant UUID. Leave validation.iss = None (skip library check) and validate
    // the issuer manually in the Entra-specific blocks below.
    if !is_entra_organizations_issuer(&provider.issuer) && !is_entra_common_issuer(&provider.issuer)
    {
        validation.set_issuer(&[&provider.issuer]);
    }
    validation.set_audience(&[expected_client_id]);

    let token_data = jsonwebtoken::decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|e| anyhow::anyhow!("ID token verification failed: {e}"))?;

    let claims = token_data.claims;

    // For Entra /organizations/ and /common/, the library issuer check was skipped.
    // Manually verify the token's iss is a valid Entra per-tenant issuer URL — not an
    // arbitrary host. This rejects tokens where `iss` is something other than
    // `https://login.microsoftonline.com/<uuid>/v2.0`.
    if (is_entra_organizations_issuer(&provider.issuer) || is_entra_common_issuer(&provider.issuer))
        && (!claims.iss.starts_with("https://login.microsoftonline.com/")
            || extract_entra_tenant_from_issuer(&claims.iss).is_none())
    {
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

    if !claims.email_verified {
        anyhow::bail!("Email address is not verified by the identity provider");
    }

    // Entra-specific tenant validation.
    // For Entra issuers (`login.microsoftonline.com`), check the `tid` claim:
    //   - Cross-check tid against the tenant UUID in the token's `iss` claim
    //     to prevent cross-tenant token injection. When /organizations/ or /common/
    //     is configured, provider.issuer holds the template; claims.iss holds the
    //     real per-tenant UUID from the validated token.
    //   - The MSA meta-tenant is allowed (personal Microsoft accounts), but its
    //     tokens get domain=None below so no organization is auto-created.
    let is_entra = provider.issuer.contains("login.microsoftonline.com");
    let entra_tid = if is_entra {
        let tid = claims.tid.as_deref().unwrap_or("");

        // Cross-check tid against the tenant UUID in the token's iss claim.
        // Use claims.iss (the real per-tenant issuer from the signed token) rather
        // than provider.issuer (which may be the /organizations/ template string).
        if let Some(expected_tid) = extract_entra_tenant_from_issuer(&claims.iss)
            && !tid.eq_ignore_ascii_case(expected_tid)
        {
            anyhow::bail!(
                "Entra tid claim '{tid}' does not match issuer tenant '{expected_tid}'. \
                 Possible cross-tenant token injection."
            );
        }

        tracing::info!(tid = %tid, iss = %claims.iss, "Entra tenant validated");
        Some(tid.to_string())
    } else {
        None
    };

    // Domain extraction:
    // - Google with `hd` claim: use it (Workspace hosted domain).
    // - Google without `hd`: None (consumer account, don't group).
    // - Entra MSA meta-tenant: None (personal account, don't group).
    // - All other providers: extract domain from the email address.
    //
    // Normalize to ASCII lowercase so that org lookups match regardless of
    // the case the IdP returned. Org domains are stored lowercase.
    let is_google = provider.issuer.contains("accounts.google.com");
    let is_entra_msa = entra_tid.as_deref() == Some(ENTRA_MSA_TENANT_ID);
    let domain = if is_google {
        claims.hd.as_deref().map(str::to_ascii_lowercase)
    } else if is_entra_msa {
        None
    } else {
        claims.email.split('@').nth(1).map(str::to_ascii_lowercase)
    };

    Ok(IdentityResult {
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
fn find_decoding_key(
    jwks: &jsonwebtoken::jwk::JwkSet,
    kid: Option<&str>,
    alg: jsonwebtoken::Algorithm,
) -> Result<jsonwebtoken::DecodingKey, anyhow::Error> {
    let expected_key_alg = algorithm_to_key_algorithm(alg);

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
    if let Some(expected) = expected_key_alg {
        for jwk in &jwks.keys {
            if jwk.common.key_algorithm == Some(expected) {
                return jsonwebtoken::DecodingKey::from_jwk(jwk)
                    .map_err(|e| anyhow::anyhow!("Failed to build key from JWK: {e}"));
            }
        }
    }

    // Last resort: try the first key (no kid/algorithm matched)
    tracing::warn!("No JWK matched by kid or algorithm, falling back to first key in JWKS");
    jwks.keys.first().map_or_else(
        || Err(anyhow::anyhow!("Upstream JWKS is empty")),
        |jwk| {
            jsonwebtoken::DecodingKey::from_jwk(jwk)
                .map_err(|e| anyhow::anyhow!("Failed to build key from JWK: {e}"))
        },
    )
}

/// Convert a `jsonwebtoken::Algorithm` to its `jwk::KeyAlgorithm` equivalent.
fn algorithm_to_key_algorithm(
    alg: jsonwebtoken::Algorithm,
) -> Option<jsonwebtoken::jwk::KeyAlgorithm> {
    use jsonwebtoken::Algorithm;
    use jsonwebtoken::jwk::KeyAlgorithm;
    match alg {
        Algorithm::ES256 => Some(KeyAlgorithm::ES256),
        Algorithm::ES384 => Some(KeyAlgorithm::ES384),
        Algorithm::RS256 => Some(KeyAlgorithm::RS256),
        Algorithm::RS384 => Some(KeyAlgorithm::RS384),
        Algorithm::RS512 => Some(KeyAlgorithm::RS512),
        Algorithm::PS256 => Some(KeyAlgorithm::PS256),
        Algorithm::PS384 => Some(KeyAlgorithm::PS384),
        Algorithm::PS512 => Some(KeyAlgorithm::PS512),
        Algorithm::EdDSA => Some(KeyAlgorithm::EdDSA),
        _ => None,
    }
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
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        reason = "test code: panic on assertion failure is acceptable"
    )]

    use super::*;

    // ── Test helpers for verify_id_token ────────────────────────────────────

    /// Build an `OidcProvider` that points all endpoints at the given mock server.
    fn make_test_provider(base_url: &str) -> OidcProvider {
        OidcProvider {
            issuer: base_url.to_string(),
            authorization_endpoint: Url::parse(&format!("{base_url}/authorize")).unwrap(),
            token_endpoint: Url::parse(&format!("{base_url}/token")).unwrap(),
            jwks_uri: Url::parse(&format!("{base_url}/jwks")).unwrap(),
        }
    }

    /// Build a JWKS JSON payload from an EC P-256 signing key.
    ///
    /// Constructs a `{"keys": [...]}` object compatible with the
    /// `jsonwebtoken::jwk::JwkSet` deserializer. The EC key coordinates
    /// (x, y) and kid are taken directly from the signing key so that
    /// the JWKS matches the signature on JWTs the same key produces.
    fn make_ec_jwks_json(signing_key: &crate::services::oidc::OidcSigningKey) -> String {
        let jwk = signing_key
            .public_key_jwk()
            .expect("public_key_jwk should succeed");

        serde_json::json!({
            "keys": [{
                "kty": jwk.kty,
                "crv": jwk.crv,
                "alg": jwk.alg,
                "kid": jwk.kid,
                "use": jwk.key_use,
                "x": jwk.x,
                "y": jwk.y,
            }]
        })
        .to_string()
    }

    /// Sign a JWT with the given custom claims using ES256.
    ///
    /// Claims must include the standard registered claims `iss`, `aud`, `exp`,
    /// and `iat`; the caller also sets `email`, `email_verified`, `nonce`, and
    /// `hd` as required by `verify_id_token`.
    async fn sign_test_jwt(
        key: &crate::services::oidc::OidcSigningKey,
        claims: serde_json::Value,
    ) -> String {
        key.sign_jwt(&claims)
            .await
            .expect("sign_jwt should succeed")
    }

    /// Mount a JWKS endpoint on the mock server and return the signing key.
    async fn mount_jwks(
        server: &wiremock::MockServer,
        key: &crate::services::oidc::OidcSigningKey,
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let jwks_json = make_ec_jwks_json(key);
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_string(jwks_json))
            .mount(server)
            .await;
    }

    /// Build a minimal valid claims object for verify_id_token.
    ///
    /// `iss` is set to `issuer`, `aud` to `client_id`, `exp` far in the
    /// future, `email_verified` to `true`, and nonce/hd are left to the
    /// caller.
    fn base_claims(issuer: &str, client_id: &str) -> serde_json::Value {
        serde_json::json!({
            "iss": issuer,
            "aud": client_id,
            "sub": "user-123",
            "exp": 9_999_999_999_i64,
            "iat": 1_000_000_000_i64,
            "email": "alice@example.com",
            "email_verified": true,
        })
    }

    fn parse_discovery_json(json: &str) -> DiscoveryDocument {
        serde_json::from_str(json).expect("valid JSON")
    }

    #[test]
    fn parse_google_discovery() {
        let json = r#"{
            "issuer": "https://accounts.google.com",
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"
        }"#;
        let doc = parse_discovery_json(json);
        assert_eq!(doc.issuer, "https://accounts.google.com");
        assert_eq!(
            doc.authorization_endpoint,
            "https://accounts.google.com/o/oauth2/v2/auth"
        );
        assert_eq!(doc.token_endpoint, "https://oauth2.googleapis.com/token");
        assert_eq!(doc.jwks_uri, "https://www.googleapis.com/oauth2/v3/certs");
    }

    #[test]
    fn parse_okta_discovery() {
        let json = r#"{
            "issuer": "https://dev-123456.okta.com",
            "authorization_endpoint": "https://dev-123456.okta.com/oauth2/v1/authorize",
            "token_endpoint": "https://dev-123456.okta.com/oauth2/v1/token",
            "jwks_uri": "https://dev-123456.okta.com/oauth2/v1/keys"
        }"#;
        let doc = parse_discovery_json(json);
        assert_eq!(doc.issuer, "https://dev-123456.okta.com");
    }

    #[test]
    fn parse_azure_ad_discovery() {
        let json = r#"{
            "issuer": "https://login.microsoftonline.com/tenant-id/v2.0",
            "authorization_endpoint": "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/authorize",
            "token_endpoint": "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token",
            "jwks_uri": "https://login.microsoftonline.com/tenant-id/discovery/v2.0/keys"
        }"#;
        let doc = parse_discovery_json(json);
        assert_eq!(
            doc.issuer,
            "https://login.microsoftonline.com/tenant-id/v2.0"
        );
    }

    #[test]
    fn reject_missing_required_fields() {
        // Missing token_endpoint and jwks_uri
        let json = r#"{"issuer": "https://example.com", "authorization_endpoint": "https://example.com/auth"}"#;
        let result: Result<DiscoveryDocument, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn reject_http_issuer() {
        let url = Url::parse("http://evil.example.com").unwrap();
        assert!(!is_localhost(&url));
    }

    #[test]
    fn allow_http_localhost() {
        let url = Url::parse("http://localhost:8080").unwrap();
        assert!(is_localhost(&url));
    }

    #[test]
    fn allow_http_ipv6_localhost() {
        let url = Url::parse("http://[::1]:8080").unwrap();
        assert!(is_localhost(&url));
    }

    #[test]
    fn issuer_mismatch_detection() {
        let configured = "https://accounts.google.com";
        let discovered = "https://evil.example.com";
        assert_ne!(
            configured.trim_end_matches('/'),
            discovered.trim_end_matches('/')
        );
    }

    // ── Entra /organizations/ issuer template tests ────────────────────────

    #[test]
    fn validate_discovered_issuer_exact_match() {
        assert!(
            validate_discovered_issuer(
                "https://accounts.google.com",
                "https://accounts.google.com"
            )
            .is_ok()
        );
    }

    #[test]
    fn validate_discovered_issuer_mismatch_rejected() {
        assert!(
            validate_discovered_issuer("https://accounts.google.com", "https://evil.example.com")
                .is_err()
        );
    }

    #[test]
    fn validate_discovered_issuer_entra_organizations_accepts_tenant_issuer() {
        // /organizations/ configured; discovered issuer is per-tenant
        assert!(
            validate_discovered_issuer(
                "https://login.microsoftonline.com/organizations/v2.0",
                "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
            )
            .is_ok()
        );
    }

    #[test]
    fn validate_discovered_issuer_entra_specific_tenant_rejects_different_tenant() {
        // A tenant-specific configured issuer must match exactly
        assert!(
            validate_discovered_issuer(
                "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
                "https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/v2.0"
            )
            .is_err()
        );
    }

    // ── extract_entra_tenant_from_issuer tests ─────────────────────────────

    #[test]
    fn extract_tenant_from_specific_issuer() {
        let issuer = "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0";
        assert_eq!(
            extract_entra_tenant_from_issuer(issuer),
            Some("11111111-2222-3333-4444-555555555555")
        );
    }

    #[test]
    fn extract_tenant_returns_none_for_organizations() {
        let issuer = "https://login.microsoftonline.com/organizations/v2.0";
        assert_eq!(extract_entra_tenant_from_issuer(issuer), None);
    }

    #[test]
    fn extract_tenant_returns_none_for_common() {
        let issuer = "https://login.microsoftonline.com/common/v2.0";
        assert_eq!(extract_entra_tenant_from_issuer(issuer), None);
    }

    #[test]
    fn extract_tenant_returns_none_for_google() {
        assert_eq!(
            extract_entra_tenant_from_issuer("https://accounts.google.com"),
            None
        );
    }

    // ── is_entra_common_issuer tests ───────────────────────────────────────

    #[test]
    fn is_entra_common_issuer_detects_common() {
        assert!(is_entra_common_issuer(
            "https://login.microsoftonline.com/common/v2.0"
        ));
        assert!(is_entra_common_issuer(
            "https://login.microsoftonline.com/common"
        ));
    }

    #[test]
    fn is_entra_common_issuer_does_not_match_organizations() {
        assert!(!is_entra_common_issuer(
            "https://login.microsoftonline.com/organizations/v2.0"
        ));
    }

    #[test]
    fn is_entra_common_issuer_does_not_match_google() {
        assert!(!is_entra_common_issuer("https://accounts.google.com"));
    }

    // ── wiremock integration tests for fetch_discovery ──────────────────

    fn discovery_json(issuer: &str) -> String {
        serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
        })
        .to_string()
    }

    #[tokio::test]
    async fn fetch_discovery_happy_path() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let issuer = server.uri();

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_string(discovery_json(&issuer)))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let provider = fetch_discovery(&client, &issuer).await.unwrap();

        assert_eq!(provider.issuer, issuer);
        assert_eq!(
            provider.authorization_endpoint.as_str(),
            format!("{issuer}/authorize"),
        );
        assert_eq!(provider.token_endpoint.as_str(), format!("{issuer}/token"),);
        assert_eq!(provider.jwks_uri.as_str(), format!("{issuer}/jwks"),);
    }

    #[tokio::test]
    async fn fetch_discovery_preserves_canonical_issuer_from_document() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let configured_issuer = server.uri();
        let canonical_issuer = format!("{configured_issuer}/");

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(discovery_json(&canonical_issuer)),
            )
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let provider = fetch_discovery(&client, &configured_issuer).await.unwrap();

        assert_eq!(provider.issuer, canonical_issuer);
    }

    #[tokio::test]
    async fn fetch_discovery_issuer_mismatch() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let issuer = server.uri();

        // Discovery doc reports a different issuer
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(discovery_json("https://evil.example.com")),
            )
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let err = fetch_discovery(&client, &issuer).await.unwrap_err();

        assert!(
            err.to_string().contains("Issuer mismatch"),
            "expected issuer mismatch error, got: {err}",
        );
    }

    #[tokio::test]
    async fn fetch_discovery_non_200() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let err = fetch_discovery(&client, &server.uri()).await.unwrap_err();

        assert!(
            err.to_string().contains("HTTP 404"),
            "expected HTTP 404 error, got: {err}",
        );
    }

    #[tokio::test]
    async fn fetch_discovery_invalid_json() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let err = fetch_discovery(&client, &server.uri()).await.unwrap_err();

        assert!(
            err.to_string().contains("parse discovery"),
            "expected parse error, got: {err}",
        );
    }

    #[tokio::test]
    async fn fetch_discovery_rejects_http_non_localhost() {
        let client = reqwest::Client::new();
        let err = fetch_discovery(&client, "http://evil.example.com")
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("HTTPS"),
            "expected HTTPS error, got: {err}",
        );
    }

    // ── verify_id_token tests ───────────────────────────────────────────────

    /// Happy path: valid ES256 JWT with all required claims returns correct
    /// `IdentityResult`.
    #[tokio::test]
    async fn verify_id_token_happy_path() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let issuer = server.uri();
        let client_id = "test-client";
        let nonce = "test-nonce-abc";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        let mut claims = base_claims(&issuer, client_id);
        claims["nonce"] = serde_json::json!(nonce);
        claims["hd"] = serde_json::json!("example.com");

        let token = sign_test_jwt(&key, claims).await;
        let provider = make_test_provider(&issuer);
        let client = reqwest::Client::new();

        let result = verify_id_token(&client, &provider, &token, client_id, nonce)
            .await
            .unwrap();

        assert_eq!(result.email, "alice@example.com");
        assert_eq!(result.domain, Some("example.com".to_string()));
    }

    /// Nonce mismatch: JWT has a nonce that differs from expected → error
    /// message must contain "nonce mismatch".
    #[tokio::test]
    async fn verify_id_token_nonce_mismatch() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let issuer = server.uri();
        let client_id = "test-client";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        let mut claims = base_claims(&issuer, client_id);
        claims["nonce"] = serde_json::json!("actual-nonce");

        let token = sign_test_jwt(&key, claims).await;
        let provider = make_test_provider(&issuer);
        let client = reqwest::Client::new();

        let err = verify_id_token(&client, &provider, &token, client_id, "expected-nonce")
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("nonce mismatch"),
            "expected 'nonce mismatch' in error, got: {err}",
        );
    }

    /// Missing nonce: JWT has no nonce claim but caller expects one → error
    /// message must contain "missing nonce".
    #[tokio::test]
    async fn verify_id_token_missing_nonce() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let issuer = server.uri();
        let client_id = "test-client";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        // No nonce claim in the token
        let claims = base_claims(&issuer, client_id);
        let token = sign_test_jwt(&key, claims).await;
        let provider = make_test_provider(&issuer);
        let client = reqwest::Client::new();

        let err = verify_id_token(&client, &provider, &token, client_id, "expected-nonce")
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("missing nonce"),
            "expected 'missing nonce' in error, got: {err}",
        );
    }

    /// Empty nonce bypass: device-code flow sends expected_nonce="" and the
    /// token has no nonce claim → should succeed (nonce check is skipped).
    #[tokio::test]
    async fn verify_id_token_empty_nonce_bypass() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let issuer = server.uri();
        let client_id = "test-client";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        // No nonce in token; empty expected_nonce signals device-code flow
        let claims = base_claims(&issuer, client_id);
        let token = sign_test_jwt(&key, claims).await;
        let provider = make_test_provider(&issuer);
        let client = reqwest::Client::new();

        let result = verify_id_token(&client, &provider, &token, client_id, "")
            .await
            .unwrap();

        assert_eq!(result.email, "alice@example.com");
    }

    /// Email not verified: JWT has email_verified=false → error message must
    /// contain "not verified".
    #[tokio::test]
    async fn verify_id_token_email_not_verified() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let issuer = server.uri();
        let client_id = "test-client";
        let nonce = "test-nonce";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        let mut claims = base_claims(&issuer, client_id);
        claims["email_verified"] = serde_json::json!(false);
        claims["nonce"] = serde_json::json!(nonce);

        let token = sign_test_jwt(&key, claims).await;
        let provider = make_test_provider(&issuer);
        let client = reqwest::Client::new();

        let err = verify_id_token(&client, &provider, &token, client_id, nonce)
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("not verified"),
            "expected 'not verified' in error, got: {err}",
        );
    }

    /// Domain from hd claim: when `hd` is present, `IdentityResult.domain`
    /// reflects that value.
    #[tokio::test]
    async fn verify_id_token_domain_from_hd_claim() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        // Google Workspace: hd claim is used for domain
        let google_issuer = "https://accounts.google.com";
        let client_id = "test-client";
        let nonce = "test-nonce";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        let mut claims = base_claims(google_issuer, client_id);
        claims["nonce"] = serde_json::json!(nonce);
        claims["hd"] = serde_json::json!("acme.com");

        let token = sign_test_jwt(&key, claims).await;
        let mut provider = make_test_provider(google_issuer);
        provider.jwks_uri = url::Url::parse(&format!("{}/jwks", server.uri())).unwrap();
        let client = reqwest::Client::new();

        let result = verify_id_token(&client, &provider, &token, client_id, nonce)
            .await
            .unwrap();

        assert_eq!(
            result.domain,
            Some("acme.com".to_string()),
            "Google Workspace domain should come from hd claim"
        );
    }

    /// No hd claim: when `hd` is absent, `IdentityResult.domain` is `None`.
    #[tokio::test]
    async fn verify_id_token_no_hd_claim_non_google_falls_back_to_email() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let issuer = server.uri(); // non-Google issuer
        let client_id = "test-client";
        let nonce = "test-nonce";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        let mut claims = base_claims(&issuer, client_id);
        claims["nonce"] = serde_json::json!(nonce);
        // Intentionally no "hd" claim

        let token = sign_test_jwt(&key, claims).await;
        let provider = make_test_provider(&issuer);
        let client = reqwest::Client::new();

        let result = verify_id_token(&client, &provider, &token, client_id, nonce)
            .await
            .unwrap();

        // Non-Google issuers fall back to email domain when hd is absent
        assert_eq!(
            result.domain.as_deref(),
            Some("example.com"),
            "non-Google issuer should fall back to email domain"
        );
    }

    /// Regression: mixed-case `hd` claim must be lowercased so org lookups
    /// (which match against the lowercase-stored primary/additional domain)
    /// find the right org. Removing the `.to_ascii_lowercase()` call would
    /// silently break login for IdPs that return uppercase domain parts.
    #[tokio::test]
    async fn verify_id_token_lowercases_mixed_case_hd_claim() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let google_issuer = "https://accounts.google.com";
        let client_id = "test-client";
        let nonce = "test-nonce";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        let mut claims = base_claims(google_issuer, client_id);
        claims["nonce"] = serde_json::json!(nonce);
        claims["hd"] = serde_json::json!("ACME.COM");

        let token = sign_test_jwt(&key, claims).await;
        let mut provider = make_test_provider(google_issuer);
        provider.jwks_uri = url::Url::parse(&format!("{}/jwks", server.uri())).unwrap();
        let client = reqwest::Client::new();

        let result = verify_id_token(&client, &provider, &token, client_id, nonce)
            .await
            .unwrap();

        assert_eq!(
            result.domain.as_deref(),
            Some("acme.com"),
            "uppercase hd claim must be normalized to lowercase",
        );
    }

    /// Regression: when falling back to the email domain for non-Google
    /// issuers, the extracted domain must be lowercased.
    #[tokio::test]
    async fn verify_id_token_lowercases_email_domain_fallback() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let issuer = server.uri();
        let client_id = "test-client";
        let nonce = "test-nonce";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        let mut claims = base_claims(&issuer, client_id);
        claims["nonce"] = serde_json::json!(nonce);
        claims["email"] = serde_json::json!("Alice@CORP.Example.COM");

        let token = sign_test_jwt(&key, claims).await;
        let provider = make_test_provider(&issuer);
        let client = reqwest::Client::new();

        let result = verify_id_token(&client, &provider, &token, client_id, nonce)
            .await
            .unwrap();

        assert_eq!(
            result.domain.as_deref(),
            Some("corp.example.com"),
            "email-fallback domain must be normalized to lowercase",
        );
    }

    #[tokio::test]
    async fn verify_id_token_google_consumer_no_hd_returns_none() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        // Use Google issuer — consumer accounts have no hd claim
        let google_issuer = "https://accounts.google.com";
        let client_id = "test-client";
        let nonce = "test-nonce";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        let mut claims = base_claims(google_issuer, client_id);
        claims["nonce"] = serde_json::json!(nonce);
        // No "hd" claim — Google consumer account

        let token = sign_test_jwt(&key, claims).await;
        let mut provider = make_test_provider(google_issuer);
        // Point jwks_uri to our mock server
        provider.jwks_uri = url::Url::parse(&format!("{}/jwks", server.uri())).unwrap();
        let client = reqwest::Client::new();

        let result = verify_id_token(&client, &provider, &token, client_id, nonce)
            .await
            .unwrap();

        // Google consumer accounts: no hd → domain should be None
        assert!(
            result.domain.is_none(),
            "Google consumer should have domain=None, got: {:?}",
            result.domain
        );
    }

    // ── Entra tid claim validation ─────────────────────────────────────────

    /// Token from the MSA meta-tenant (personal Microsoft account) succeeds
    /// but `IdentityResult.domain` is `None` — matching Google consumer-account
    /// behavior, so no organization is auto-created from the email domain.
    #[tokio::test]
    async fn verify_id_token_entra_msa_account_allowed_no_domain() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        // /common/ template: provider holds template, token holds real per-tenant
        // issuer with the MSA meta-tenant UUID.
        let provider_issuer = "https://login.microsoftonline.com/common/v2.0".to_string();
        let token_iss = format!("https://login.microsoftonline.com/{ENTRA_MSA_TENANT_ID}/v2.0");
        let client_id = "test-client";
        let nonce = "test-nonce";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        let mut claims = base_claims(&token_iss, client_id);
        claims["nonce"] = serde_json::json!(nonce);
        claims["tid"] = serde_json::json!(ENTRA_MSA_TENANT_ID);
        // Personal account using an external email — still gets domain=None
        // because the tid identifies it as MSA, not because of the email domain.
        claims["email"] = serde_json::json!("personal-user@outlook.com");

        let token = sign_test_jwt(&key, claims).await;
        let mut provider = make_test_provider(&provider_issuer);
        provider.issuer = provider_issuer.clone();
        provider.jwks_uri = url::Url::parse(&format!("{}/jwks", server.uri())).unwrap();
        let client = reqwest::Client::new();

        let result = verify_id_token(&client, &provider, &token, client_id, nonce)
            .await
            .unwrap();

        assert_eq!(result.email, "personal-user@outlook.com");
        assert!(
            result.domain.is_none(),
            "MSA personal account must have domain=None, got: {:?}",
            result.domain
        );
    }

    /// Token tid must match the tenant UUID in the issuer URL.
    #[tokio::test]
    async fn verify_id_token_entra_tid_mismatch_rejected() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let issuer_tenant = "11111111-2222-3333-4444-555555555555";
        let other_tenant = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let entra_issuer = format!("https://login.microsoftonline.com/{issuer_tenant}/v2.0");
        let client_id = "test-client";
        let nonce = "test-nonce";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        let mut claims = base_claims(&entra_issuer, client_id);
        claims["nonce"] = serde_json::json!(nonce);
        // tid from a different tenant — cross-tenant injection attempt
        claims["tid"] = serde_json::json!(other_tenant);

        let token = sign_test_jwt(&key, claims).await;
        let mut provider = make_test_provider(&entra_issuer);
        provider.issuer = entra_issuer.clone();
        provider.jwks_uri = url::Url::parse(&format!("{}/jwks", server.uri())).unwrap();
        let client = reqwest::Client::new();

        let err = verify_id_token(&client, &provider, &token, client_id, nonce)
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("cross-tenant token injection"),
            "expected cross-tenant rejection, got: {err}"
        );
    }

    /// Token with matching tid succeeds (tenant-specific issuer in provider).
    #[tokio::test]
    async fn verify_id_token_entra_tid_matches_issuer_succeeds() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let tenant_id = "11111111-2222-3333-4444-555555555555";
        let entra_issuer = format!("https://login.microsoftonline.com/{tenant_id}/v2.0");
        let client_id = "test-client";
        let nonce = "test-nonce";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        let mut claims = base_claims(&entra_issuer, client_id);
        claims["nonce"] = serde_json::json!(nonce);
        claims["tid"] = serde_json::json!(tenant_id);

        let token = sign_test_jwt(&key, claims).await;
        let mut provider = make_test_provider(&entra_issuer);
        provider.issuer = entra_issuer.clone();
        provider.jwks_uri = url::Url::parse(&format!("{}/jwks", server.uri())).unwrap();
        let client = reqwest::Client::new();

        let result = verify_id_token(&client, &provider, &token, client_id, nonce)
            .await
            .unwrap();

        assert_eq!(result.email, "alice@example.com");
    }

    // ── /organizations/ provider.issuer with real per-tenant token iss ─────

    /// When provider.issuer is the /organizations/ template, the library issuer
    /// check is disabled. A token with a real per-tenant iss and matching tid
    /// must succeed.
    #[tokio::test]
    async fn verify_id_token_entra_organizations_provider_with_tenant_token_succeeds() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let tenant_id = "11111111-2222-3333-4444-555555555555";
        // This is what OidcProvider::issuer holds after fetch_discovery from /organizations/
        let organizations_issuer =
            "https://login.microsoftonline.com/organizations/v2.0".to_string();
        // Real tokens have the per-tenant UUID in their iss claim
        let token_iss = format!("https://login.microsoftonline.com/{tenant_id}/v2.0");
        let client_id = "test-client";
        let nonce = "test-nonce";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        // Token claims use the per-tenant issuer (as Entra actually issues them)
        let mut claims = base_claims(&token_iss, client_id);
        claims["nonce"] = serde_json::json!(nonce);
        claims["tid"] = serde_json::json!(tenant_id);

        let token = sign_test_jwt(&key, claims).await;

        // provider.issuer is the /organizations/ template (as stored after discovery)
        let mut provider = make_test_provider(&organizations_issuer);
        provider.issuer = organizations_issuer.clone();
        provider.jwks_uri = url::Url::parse(&format!("{}/jwks", server.uri())).unwrap();
        let client = reqwest::Client::new();

        let result = verify_id_token(&client, &provider, &token, client_id, nonce)
            .await
            .unwrap();

        assert_eq!(result.email, "alice@example.com");
    }

    /// When provider.issuer is /organizations/, a token whose tid does not match
    /// the per-tenant UUID in its own iss claim must be rejected.
    #[tokio::test]
    async fn verify_id_token_entra_organizations_tid_mismatch_rejected() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let token_tenant = "11111111-2222-3333-4444-555555555555";
        let other_tenant = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let organizations_issuer =
            "https://login.microsoftonline.com/organizations/v2.0".to_string();
        let token_iss = format!("https://login.microsoftonline.com/{token_tenant}/v2.0");
        let client_id = "test-client";
        let nonce = "test-nonce";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        let mut claims = base_claims(&token_iss, client_id);
        claims["nonce"] = serde_json::json!(nonce);
        // tid from a different tenant — cross-tenant injection attempt
        claims["tid"] = serde_json::json!(other_tenant);

        let token = sign_test_jwt(&key, claims).await;

        let mut provider = make_test_provider(&organizations_issuer);
        provider.issuer = organizations_issuer.clone();
        provider.jwks_uri = url::Url::parse(&format!("{}/jwks", server.uri())).unwrap();
        let client = reqwest::Client::new();

        let err = verify_id_token(&client, &provider, &token, client_id, nonce)
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("cross-tenant token injection"),
            "expected cross-tenant rejection, got: {err}"
        );
    }

    // ── Fix 3: validate_discovered_issuer handles /common/ ─────────────────

    #[test]
    fn validate_discovered_issuer_entra_common_accepts_tenant_issuer() {
        // Fix 3: /common/ configured; discovered issuer is per-tenant (same as /organizations/)
        assert!(
            validate_discovered_issuer(
                "https://login.microsoftonline.com/common/v2.0",
                "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
            )
            .is_ok()
        );
    }

    #[test]
    fn validate_discovered_issuer_entra_common_rejects_non_tenant_issuer() {
        // /common/ configured but discovered issuer is a completely different host
        assert!(
            validate_discovered_issuer(
                "https://login.microsoftonline.com/common/v2.0",
                "https://evil.example.com/token"
            )
            .is_err()
        );
    }
}
