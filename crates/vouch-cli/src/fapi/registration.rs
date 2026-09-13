// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 7591 Dynamic Client Registration for FAPI 2.0 clients.
//!
//! The CLI can register itself as a FAPI 2.0 confidential client either:
//! - Before enrollment (open registration — no auth token required), or
//! - After enrollment (with a Bearer token from the device code flow).
//!
//! The server accepts `POST /oauth/register` without authentication when
//! open registration is enabled (FAPI 2.0 open registration mode).

use crate::{tr, tr_args};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::key::ClientKey;
use vouch_common::protocol;

/// RFC 7591 client registration request body.
///
/// Only the fields needed for a FAPI 2.0 CLI client are included here.
/// Per RFC 7591 Section 2, the server ignores fields it does not understand.
#[derive(Debug, Serialize)]
struct RegistrationRequest {
    /// Authentication method — always `private_key_jwt` for FAPI 2.0.
    token_endpoint_auth_method: &'static str,
    /// Grant types this client will use.
    grant_types: Vec<&'static str>,
    /// Response types — `code` for authorization code flow.
    response_types: Vec<&'static str>,
    /// Whether access tokens must be DPoP-bound — true for FAPI 2.0.
    dpop_bound_access_tokens: bool,
    /// Client's public key set (inline JWKS).
    jwks: serde_json::Value,
    /// Human-readable client name.
    client_name: String,
    /// Unique identifier for the Vouch CLI software.
    software_id: &'static str,
    /// Version of the Vouch CLI.
    software_version: String,
}

/// RFC 7591 client registration response.
///
/// Contains the server-assigned `client_id` and the RFC 7592
/// `registration_access_token` for future management operations.
#[derive(Deserialize)]
struct RegistrationResponse {
    /// Server-assigned client identifier.
    client_id: String,
    /// Token for managing the registration (RFC 7592).
    #[serde(default)]
    registration_access_token: Option<secrecy::SecretString>,
    /// URI for reading/updating/deleting the registration (RFC 7592).
    #[serde(default)]
    registration_client_uri: Option<String>,
}

// Custom Debug that redacts registration_access_token to prevent accidental
// log exposure of the RFC 7592 management credential.
impl std::fmt::Debug for RegistrationResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationResponse")
            .field("client_id", &self.client_id)
            .field("registration_access_token", &"[REDACTED]")
            .field("registration_client_uri", &self.registration_client_uri)
            .finish()
    }
}

/// Grant types the FAPI CLI client declares during RFC 7591 registration.
///
/// The CLI authenticates as this single registered client for every grant it
/// exercises, so the server's RFC 6749 §5.2 `unauthorized_client` gate —
/// `OAuthClient::is_authorized_for_grant` (`vouch-server/src/db/oauth.rs`),
/// which reads the stored `grant_types` at request time — requires each one
/// to be listed here:
/// - [`protocol::GRANT_TYPE_DEVICE_CODE`] — `vouch login` device authorization.
/// - [`protocol::GRANT_TYPE_FIDO2_ASSERTION`] — `vouch login` step-up to
///   hardware verification.
/// - [`protocol::GRANT_TYPE_TOKEN_EXCHANGE`] — Workload Identity Federation
///   credential commands (`vouch credential openai|anthropic`) mint a
///   Vouch-issued ID-token assertion via RFC 8693 token exchange.
///
/// Omitting a grant the CLI uses makes the server reject that grant's requests
/// with HTTP 401 `unauthorized_client`; commit `45b8de2d` added the
/// token-exchange gate that first exposed the missing `token-exchange` entry.
const REGISTERED_GRANT_TYPES: &[&str] = &[
    protocol::GRANT_TYPE_DEVICE_CODE,
    protocol::GRANT_TYPE_FIDO2_ASSERTION,
    protocol::GRANT_TYPE_TOKEN_EXCHANGE,
];

/// A version stamp of the CLI's declared [`REGISTERED_GRANT_TYPES`].
///
/// Persisted in config at the last successful registration (POST) or
/// registration update (PUT). A stored stamp that differs from the running
/// CLI's — for example, after an upgrade that added
/// [`protocol::GRANT_TYPE_TOKEN_EXCHANGE`] to [`REGISTERED_GRANT_TYPES`] —
/// marks the server-stored `grant_types` stale. `ensure_client_registered`
/// (`commands::login`) and `register_fapi_client_open` (`commands::enroll`)
/// then repair the existing client via RFC 7592 PUT ([`update_fapi_client`])
/// before reusing the cached `client_id`, so already-enrolled clients converge
/// to the new grant list without minting a fresh `client_id`.
pub fn registered_grant_types_version() -> String {
    REGISTERED_GRANT_TYPES.join(",")
}

/// Whether the stored registration's `grant_types` are stale relative to the
/// running CLI's [`REGISTERED_GRANT_TYPES`].
///
/// `None` — a config that predates the version stamp, or one cleared by
/// `Config::clear_fapi` — is always stale. That makes the first
/// `vouch login` / `vouch enroll` after an upgrade repair every
/// already-enrolled client whose registration predates the stamp, which is
/// exactly the population the upgrade left behind: their `device_code` grant
/// still works, so no error path forces a re-register, and only a staleness
/// check that treats `None` as stale reaches the PUT repair.
pub fn grant_types_stale(stored_version: Option<&str>) -> bool {
    let current = registered_grant_types_version();
    stored_version != Some(current.as_str())
}

/// Build the RFC 7591 registration request body the CLI sends for both the
/// initial `POST /oauth/register` ([`register_fapi_client`]) and the
/// full-replacement RFC 7592 `PUT` update ([`update_fapi_client`]).
///
/// The body always carries the inline JWKS and the full
/// [`REGISTERED_GRANT_TYPES`] list: RFC 7592 §2.2 makes `PUT` a full
/// replacement ("omitted fields MUST be treated as null or empty values"), so
/// omitting `jwks` would strip the client's only key material — and the
/// server rejects a `private_key_jwt` / FAPI 2.0 update without it — and
/// omitting any grant the CLI uses leaves the server's `unauthorized_client`
/// gate rejecting that grant's requests.
fn build_registration_request(key: &ClientKey) -> Result<RegistrationRequest> {
    let public_jwk = key
        .public_jwk()
        .context(tr!("err-failed-export-public-key-registration"))?;

    // Build JWKS with a single key (RFC 7517)
    let jwks = serde_json::json!({
        "keys": [public_jwk]
    });

    // Build a descriptive client name: vouch-cli/<hostname>
    let hostname = gethostname::gethostname()
        .to_str()
        .unwrap_or("unknown")
        .to_string();

    Ok(RegistrationRequest {
        token_endpoint_auth_method: "private_key_jwt",
        grant_types: REGISTERED_GRANT_TYPES.to_vec(),
        response_types: vec![],
        dpop_bound_access_tokens: true,
        jwks,
        client_name: format!("vouch-cli/{hostname}"),
        software_id: "vouch-cli",
        software_version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Register this CLI installation as a FAPI 2.0 client.
///
/// Calls `POST /oauth/register` with the generated ES256 public key.
/// When `token` is `Some`, the request includes an `Authorization: Bearer`
/// header (post-enrollment registration). When `token` is `None`, the
/// request is sent without authentication (open registration, pre-enrollment).
///
/// This is intended to be called once during enrollment. If registration
/// fails, the caller should warn the user but NOT fail the enrollment
/// (registration is an enhancement, not a requirement for basic operation).
///
/// # Arguments
///
/// * `http_client` - The raw reqwest client for making the HTTP request.
/// * `base_url` - The server base URL (e.g., `https://us.vouch.sh`).
/// * `token` - Optional Bearer token. Pass `None` for open registration.
/// * `key` - The generated ES256 client key.
///
/// # Errors
///
/// Returns an error if the registration request fails or the response
/// cannot be parsed.
pub async fn register_fapi_client(
    http_client: &reqwest::Client,
    base_url: &str,
    token: Option<&str>,
    key: &ClientKey,
) -> Result<RegistrationResult> {
    let request = build_registration_request(key)?;

    let url = format!("{base_url}/oauth/register");

    // Build request — add Bearer auth only when a token is provided
    let mut builder = http_client.post(&url).json(&request);
    if let Some(t) = token {
        builder = builder.bearer_auth(t);
    }

    let response = builder
        .send()
        .await
        .context(tr!("err-failed-send-registration-request"))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!(tr_args!(
            "err-client-registration-failed-http",
            status = status.to_string(),
            body = body
        ));
    }

    let reg_response: RegistrationResponse = response
        .json()
        .await
        .context(tr!("err-failed-parse-registration-response"))?;

    tracing::info!(
        "Registered as FAPI 2.0 client: client_id={}",
        reg_response.client_id
    );

    Ok(RegistrationResult {
        client_id: reg_response.client_id,
        registration_access_token: reg_response.registration_access_token,
        registration_client_uri: reg_response.registration_client_uri,
        dpop_key_id: key.kid().to_string(),
    })
}

/// Check whether a dynamic client registration is still active (RFC 7592).
///
/// Calls `GET {registration_client_uri}` with the registration access
/// token as a Bearer credential. Returns:
/// - `Ok(true)` if the server confirms the client is active (HTTP 200).
/// - `Ok(false)` if the server rejects the request (401, 404, etc.).
/// - `Err` on transport/network errors (server unreachable).
///
/// Callers should re-register on `Ok(false)` and gracefully degrade on
/// `Err` (the subsequent login will fail with a clearer message anyway).
pub async fn is_client_registered(
    http_client: &reqwest::Client,
    registration_client_uri: &str,
    registration_access_token: &str,
) -> Result<bool, reqwest::Error> {
    let response = http_client
        .get(registration_client_uri)
        .bearer_auth(registration_access_token)
        .send()
        .await?;

    Ok(response.status().is_success())
}

/// Update an existing FAPI 2.0 client's registration via RFC 7592 `PUT`.
///
/// The CLI registers a single FAPI 2.0 client at enrollment and reuses its
/// `client_id` thereafter. The server persists the registered `grant_types`
/// and re-reads them at every token request (RFC 6749 §5.2
/// `unauthorized_client` gate), so when [`REGISTERED_GRANT_TYPES`] changes —
/// e.g. an upgrade adds [`protocol::GRANT_TYPE_TOKEN_EXCHANGE`] — an
/// already-enrolled client's stored grants must be updated, or the new
/// grant's requests fail with HTTP 401 `unauthorized_client` (the bug fixed
/// in commit `d3ad2063`'s follow-up: that commit only reached the POST
/// create-new-client path, and `vouch login`/`vouch enroll` short-circuit on
/// a cached `client_id`, so already-enrolled clients never re-POSTed).
///
/// This sends the *full* [`RegistrationRequest`] — the same body
/// [`register_fapi_client`] POSTs — as a full-replacement `PUT` to the
/// client's `registration_client_uri`, authenticating with the
/// `registration_access_token`. A bare `{"grant_types": [...]}` body would
/// drop `jwks`, which the server rejects for a `private_key_jwt` / FAPI 2.0
/// client, so the full body is required.
///
/// The server rotates `registration_access_token` on every successful `PUT`
/// (RFC 7592 §2.2); the returned [`RegistrationResult`] carries the new token
/// so the caller can persist it.
///
/// # Arguments
///
/// * `http_client` - The raw reqwest client for making the HTTP request.
/// * `registration_client_uri` - The RFC 7592 management URI (returned at
///   registration, stored in config).
/// * `registration_access_token` - The current RFC 7592 management bearer
///   token (rotated by the server on every successful PUT).
/// * `key` - The current ES256 client key (must match the stored
///   `dpop_key_id`; callers gate this before calling).
///
/// # Errors
///
/// Returns an error if the request fails to send, the server returns a
/// non-success status, or the response body cannot be parsed.
pub async fn update_fapi_client(
    http_client: &reqwest::Client,
    registration_client_uri: &str,
    registration_access_token: &str,
    key: &ClientKey,
) -> Result<RegistrationResult> {
    let request = build_registration_request(key)?;

    let response = http_client
        .put(registration_client_uri)
        .bearer_auth(registration_access_token)
        .json(&request)
        .send()
        .await
        .context(tr!("err-failed-send-registration-request"))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!(tr_args!(
            "err-client-registration-failed-http",
            status = status.to_string(),
            body = body
        ));
    }

    let reg_response: RegistrationResponse = response
        .json()
        .await
        .context(tr!("err-failed-parse-registration-response"))?;

    tracing::info!(
        "Updated FAPI 2.0 client registration via RFC 7592 PUT: client_id={}",
        reg_response.client_id
    );

    Ok(RegistrationResult {
        client_id: reg_response.client_id,
        registration_access_token: reg_response.registration_access_token,
        registration_client_uri: reg_response.registration_client_uri,
        dpop_key_id: key.kid().to_string(),
    })
}

/// Registration result containing the fields to save.
pub struct RegistrationResult {
    /// Server-assigned client identifier.
    pub client_id: String,
    /// Token for managing the registration (RFC 7592).
    pub registration_access_token: Option<secrecy::SecretString>,
    /// URI for reading/updating/deleting the registration (RFC 7592).
    pub registration_client_uri: Option<String>,
    /// Key ID of the DPoP key used for registration.
    pub dpop_key_id: String,
}

// Custom Debug that redacts registration_access_token to prevent accidental
// log exposure of the RFC 7592 management credential.
impl std::fmt::Debug for RegistrationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationResult")
            .field("client_id", &self.client_id)
            .field("registration_access_token", &"[REDACTED]")
            .field("registration_client_uri", &self.registration_client_uri)
            .field("dpop_key_id", &self.dpop_key_id)
            .finish()
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    /// The CLI authenticates as a single registered FAPI client for every
    /// grant it exercises, so the server's RFC 6749 §5.2 `unauthorized_client`
    /// gate — `OAuthClient::is_authorized_for_grant`, which reads the stored
    /// `grant_types` at request time — requires each one to be listed in
    /// [`REGISTERED_GRANT_TYPES`]. Omitting one makes the server reject that
    /// grant's requests with HTTP 401 `unauthorized_client`. Commit `45b8de2d`
    /// added the token-exchange gate that first exposed a missing
    /// `token-exchange` entry, breaking the WIF credential commands
    /// (`vouch credential openai|anthropic`). This pins the full contract so
    /// the omission cannot silently recur.
    #[test]
    fn registered_grant_types_declare_every_grant_the_cli_uses() {
        assert!(
            REGISTERED_GRANT_TYPES.contains(&protocol::GRANT_TYPE_DEVICE_CODE),
            "device_code grant is used by `vouch login`"
        );
        assert!(
            REGISTERED_GRANT_TYPES.contains(&protocol::GRANT_TYPE_FIDO2_ASSERTION),
            "fido2-assertion grant is used by `vouch login` step-up"
        );
        assert!(
            REGISTERED_GRANT_TYPES.contains(&protocol::GRANT_TYPE_TOKEN_EXCHANGE),
            "token-exchange grant is used by WIF credential commands \
             (`vouch credential openai|anthropic`)"
        );
    }

    /// `registered_grant_types_version` is a stable digest of
    /// [`REGISTERED_GRANT_TYPES`] used as a config stamp to detect that an
    /// already-enrolled client's server-stored `grant_types` predate the
    /// running CLI's declared grants. The stamp must change whenever a grant
    /// is added to or removed from [`REGISTERED_GRANT_TYPES`]; otherwise the
    /// upgrade-path repair (RFC 7592 PUT) would never trigger and
    /// already-enrolled clients would stay broken.
    #[test]
    fn grant_types_version_tracks_registered_grant_types() {
        let current = registered_grant_types_version();
        assert!(!current.is_empty(), "version stamp must be non-empty");
        // The stamp derives from REGISTERED_GRANT_TYPES (not a hand-maintained
        // string), so every declared grant appears verbatim.
        for grant in REGISTERED_GRANT_TYPES {
            assert!(
                current.contains(*grant),
                "version stamp {current:?} must list grant {grant:?}"
            );
        }
    }

    /// Already-enrolled clients whose config predates the version stamp
    /// (`None`) are stale and must be repaired on the next
    /// `vouch login` / `vouch enroll`. This is the upgrade scenario the bug
    /// report describes: a client enrolled before the stamp existed keeps
    /// working for `device_code` (its `grant_types` still list that grant),
    /// so no error path forces a re-register; only a staleness check that
    /// treats `None` as stale can reach the PUT repair.
    #[test]
    fn grant_types_stale_when_version_is_none() {
        assert!(
            grant_types_stale(None),
            "a config with no stored version must be considered stale so \
             already-enrolled clients are repaired after an upgrade"
        );
    }

    /// A stored stamp matching the running CLI's version means the
    /// server-stored grants are current — no repair needed, so the login
    /// fast path (the `recently_verified` cache) stays intact and
    /// steady-state logins cost zero HTTP round-trips.
    #[test]
    fn grant_types_not_stale_when_version_matches() {
        let current = registered_grant_types_version();
        assert!(
            !grant_types_stale(Some(current.as_str())),
            "a config stamped with the current version must not be repaired"
        );
    }

    /// A stored stamp that differs from the running CLI's — e.g. an upgrade
    /// added `token-exchange` to [`REGISTERED_GRANT_TYPES`] — must be
    /// detected as stale so the PUT repair fires. This simulates the
    /// pre-`d3ad2063` grant list (`device_code` + `fido2_assertion`, no
    /// `token-exchange`) stamped on an already-enrolled client, then upgrades
    /// the running CLI to the current const.
    #[test]
    fn grant_types_stale_when_version_differs_after_upgrade() {
        // The pre-fix grant list, as the server stored it before commit
        // d3ad2063 added token-exchange to REGISTERED_GRANT_TYPES.
        let pre_fix_version = [
            protocol::GRANT_TYPE_DEVICE_CODE,
            protocol::GRANT_TYPE_FIDO2_ASSERTION,
        ]
        .join(",");
        assert_ne!(
            pre_fix_version,
            registered_grant_types_version(),
            "pre-fix grant list must differ from the current const; otherwise \
             the version stamp cannot detect the upgrade"
        );
        assert!(
            grant_types_stale(Some(pre_fix_version.as_str())),
            "an upgrade that adds a grant must mark the stored registration stale"
        );
    }

    /// The full-replacement RFC 7592 PUT body (shared with the initial POST
    /// via [`build_registration_request`]) must carry the inline JWKS and
    /// the full [`REGISTERED_GRANT_TYPES`]; the server rejects a
    /// `private_key_jwt` / FAPI 2.0 update that drops `jwks` (it would strip
    /// the client's only key material), and the `unauthorized_client` gate
    /// rejects any grant the update omitted.
    #[test]
    fn registration_request_carries_jwks_and_full_grant_types() {
        let key = ClientKey::generate().expect("generate ES256 key for test");
        let request = build_registration_request(&key).expect("build registration request");

        assert_eq!(request.token_endpoint_auth_method, "private_key_jwt");
        assert_eq!(
            request.grant_types,
            REGISTERED_GRANT_TYPES.to_vec(),
            "POST/PUT body must declare every grant the CLI uses so the \
             server stores the full list"
        );
        assert!(request.response_types.is_empty());
        assert!(request.dpop_bound_access_tokens);
        assert_eq!(request.software_id, "vouch-cli");

        // Inline JWKS with exactly one P-256 key: the full-replacement PUT
        // must re-send it, or the server clears it and rejects the
        // private_key_jwt update (no key material left to authenticate with).
        let keys = request
            .jwks
            .get("keys")
            .and_then(serde_json::Value::as_array)
            .expect("jwks.keys must be a non-empty array");
        assert_eq!(keys.len(), 1, "exactly one signing key in the JWKS");
        let signing_key = keys.first().expect("jwks.keys non-empty");
        assert_eq!(
            signing_key.get("crv").and_then(serde_json::Value::as_str),
            Some("P-256"),
            "FAPI 2.0 CLI signs with ES256 / P-256"
        );
    }
}
