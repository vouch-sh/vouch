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
    registration_access_token: Option<String>,
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

    let request = RegistrationRequest {
        token_endpoint_auth_method: "private_key_jwt",
        grant_types: vec![
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:ietf:params:oauth:grant-type:fido2-assertion",
        ],
        response_types: vec![],
        dpop_bound_access_tokens: true,
        jwks,
        client_name: format!("vouch-cli/{hostname}"),
        software_id: "vouch-cli",
        software_version: env!("CARGO_PKG_VERSION").to_string(),
    };

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

/// Registration result containing the fields to save.
pub struct RegistrationResult {
    /// Server-assigned client identifier.
    pub client_id: String,
    /// Token for managing the registration (RFC 7592).
    pub registration_access_token: Option<String>,
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
