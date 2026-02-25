// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Login command - authenticate with your `YubiKey` via FAPI 2.0.
//!
//! The flow is structured so that all async I/O (server calls) happens on the
//! tokio runtime while all FIDO2 device operations run on a plain OS thread
//! via [`crate::fido2::spawn_fido2`]. See the module-level docs in
//! [`crate::fido2`] for why this separation is required.
//!
//! ## FAPI 2.0 flow
//!
//! 1. Ensure a FAPI client is registered (load or register on demand).
//! 2. POST `/oauth/fido2/challenge` → `{ challenge, rp_id, state }`.
//! 3. CTAP2 `get_assertion` on a plain OS thread (touch YubiKey, PIN).
//! 4. POST `/oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:fido2-assertion`,
//!    `client_assertion` (private_key_jwt), `DPoP` proof, and the base64url-encoded
//!    assertion payload in the `assertion` form field.
//! 5. Store the resulting DPoP-bound access token via [`crate::session::store_and_finalize`].

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::ExposeSecret;
use serde::Serialize;
use vouch_cli::fapi::{ClientAssertionBuilder, ClientKey, DpopProofBuilder, FapiInteraction};
use vouch_common::Fido2ChallengeResponse;

use crate::client::VouchClient;
use crate::config::Config;
use crate::fido2::{self, YubiKey};
use crate::session;

/// Run the login command.
///
/// Uses the FAPI 2.0 FIDO2 assertion grant flow. Requires a FAPI client key.
/// If no client key exists, one is generated and registered automatically.
///
/// The execution order is intentional:
/// 1. Contact the server first (async) — fail fast if unreachable.
/// 2. All FIDO2 device work on a plain OS thread (wait, PIN, authenticate).
/// 3. Complete authentication with the server (async).
pub async fn run(server: &str, timeout_secs: u64) -> Result<()> {
    println!("Logging in...\n");

    let client = VouchClient::unauthenticated(server)?;

    // Load or generate the FAPI client key (required for FAPI 2.0 flow)
    let fapi_key = load_or_create_fapi_key()?;

    run_fapi_login(&client, server, timeout_secs, &fapi_key).await
}

// ============================================================================
// FAPI 2.0 login path
// ============================================================================

/// FAPI 2.0 assertion grant request form fields.
///
/// Sent as `application/x-www-form-urlencoded` to `POST /oauth/token`.
#[derive(Debug, Serialize)]
struct Fido2AssertionTokenRequest {
    grant_type: &'static str,
    client_assertion_type: &'static str,
    client_assertion: String,
    assertion: String,
    scope: &'static str,
}

/// JSON payload encoded into the `assertion` form field.
///
/// Base64url-encoded JSON blob sent in the token request.
#[derive(Debug, Serialize)]
struct AssertionPayload {
    state: String,
    credential_id: String,
    authenticator_data: String,
    signature: String,
    client_data_json: String,
    user_handle: String,
}

/// Response from the FAPI 2.0 token endpoint.
#[derive(Debug, serde::Deserialize)]
struct Fapi2TokenResponse {
    access_token: secrecy::SecretString,
    expires_in: u64,
    #[serde(default)]
    email: Option<String>,
    /// `expires_at` may be included by some server versions.
    #[serde(default)]
    expires_at: Option<String>,
}

/// Run FAPI 2.0 login using the FIDO2 assertion grant.
async fn run_fapi_login(
    client: &VouchClient,
    server: &str,
    timeout_secs: u64,
    fapi_key: &ClientKey,
) -> Result<()> {
    print!("Contacting server ({server})... ");

    // Step 1: Ensure the client is registered.
    let client_id = ensure_client_registered(client, fapi_key).await?;

    // Step 2: Obtain a FIDO2 challenge from the server.
    let token_endpoint_url = format!("{server}/oauth/token");
    let challenge_url = format!("{server}/oauth/fido2/challenge");

    let dpop_proof = DpopProofBuilder::new("POST", &challenge_url)
        .build(fapi_key)
        .context("failed to build DPoP proof for challenge request")?;

    let interaction = FapiInteraction::new();
    let fapi_headers = interaction.headers();

    let response = client
        .raw_client()
        .post(&challenge_url)
        .header("DPoP", dpop_proof)
        .header(fapi_headers[0].0, fapi_headers[0].1)
        .header(fapi_headers[1].0, fapi_headers[1].1)
        .json(&serde_json::json!({}))
        .send()
        .await
        .context("failed to request FIDO2 challenge")?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("challenge request failed (HTTP {status}): {body}");
    }

    let challenge_resp: Fido2ChallengeResponse = response
        .json()
        .await
        .context("failed to parse challenge response")?;

    println!("ok");

    // Step 3: FIDO2 assertion on a plain OS thread.
    let rp_id = challenge_resp.rp_id.clone();
    let challenge_b64 = challenge_resp.challenge.clone();

    // Decode the base64url challenge into raw bytes for the FIDO2 library.
    let challenge_bytes = URL_SAFE_NO_PAD
        .decode(&challenge_b64)
        .context("challenge is not valid base64url")?;

    let assertion_result = fido2::spawn_fido2(move || {
        let key = YubiKey::wait_for_device(timeout_secs)?;
        let pin = fido2::ensure_pin_configured(&key)?;
        println!("\nTouch your YubiKey...");
        key.authenticate(&rp_id, &challenge_bytes, pin.expose_secret())
    })
    .await?;

    // Step 4: Encode the assertion as a base64url JSON blob.
    let payload = AssertionPayload {
        state: challenge_resp.state,
        credential_id: URL_SAFE_NO_PAD.encode(assertion_result.credential_id.as_bytes()),
        authenticator_data: URL_SAFE_NO_PAD.encode(assertion_result.authenticator_data.as_bytes()),
        signature: URL_SAFE_NO_PAD.encode(assertion_result.signature.as_bytes()),
        client_data_json: URL_SAFE_NO_PAD.encode(assertion_result.client_data_json.as_bytes()),
        user_handle: URL_SAFE_NO_PAD.encode(assertion_result.user_handle.as_bytes()),
    };

    let payload_json =
        serde_json::to_vec(&payload).context("failed to serialize assertion payload")?;
    let assertion_b64 = URL_SAFE_NO_PAD.encode(&payload_json);

    // Step 5: Build client_assertion (private_key_jwt) and DPoP proof.
    let client_assertion =
        ClientAssertionBuilder::new(&client_id, &token_endpoint_url).build(fapi_key)?;

    let dpop_proof = DpopProofBuilder::new("POST", &token_endpoint_url)
        .build(fapi_key)
        .context("failed to build DPoP proof for token request")?;

    let token_request = Fido2AssertionTokenRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:fido2-assertion",
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: client_assertion.assertion,
        assertion: assertion_b64,
        scope: "openid email",
    };

    // FIDO2 touch just completed — we have hardware proof of user presence.
    let interaction = FapiInteraction::with_presence(true);
    let fapi_headers = interaction.headers();

    let form_body =
        serde_urlencoded::to_string(&token_request).context("failed to encode token request")?;

    let token_resp = client
        .raw_client()
        .post(&token_endpoint_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("DPoP", dpop_proof)
        .header(fapi_headers[0].0, fapi_headers[0].1)
        .header(fapi_headers[1].0, fapi_headers[1].1)
        .body(form_body)
        .send()
        .await
        .context("failed to send token request")?;

    let token_status = token_resp.status();

    // Capture DPoP-Nonce for potential retry (RFC 9449 nonce flow).
    let dpop_nonce = token_resp
        .headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    if !token_status.is_success() {
        let body = token_resp.text().await.unwrap_or_default();

        // RFC 9449: if use_dpop_nonce is returned, retry once with the nonce.
        if let Ok(oauth_err) = serde_json::from_str::<vouch_common::OAuthError>(&body)
            && oauth_err.error == "use_dpop_nonce"
            && let Some(nonce) = dpop_nonce
        {
            return run_fapi_login_with_nonce(
                client,
                server,
                fapi_key,
                &client_id,
                &token_request,
                &nonce,
            )
            .await;
        }

        anyhow::bail!("token request failed (HTTP {token_status}): {body}");
    }

    let fapi_token: Fapi2TokenResponse = token_resp
        .json()
        .await
        .context("failed to parse token response")?;

    // Derive expiry: prefer server-provided `expires_at`, else compute from `expires_in`.
    let (expires_at_str, expires_at_ts) =
        resolve_expiry(fapi_token.expires_at.as_deref(), fapi_token.expires_in);

    let email = fapi_token.email.as_deref().unwrap_or("").to_string();

    let agent_stored = session::store_and_finalize(
        server,
        fapi_token.access_token.expose_secret(),
        &email,
        &expires_at_str,
        Some(expires_at_ts),
    )
    .await?;

    finalize_login_output(&email, &expires_at_str, agent_stored);

    Ok(())
}

/// Retry the token request with a server-provided DPoP nonce (RFC 9449).
async fn run_fapi_login_with_nonce(
    client: &VouchClient,
    server: &str,
    fapi_key: &ClientKey,
    client_id: &str,
    request: &Fido2AssertionTokenRequest,
    nonce: &str,
) -> Result<()> {
    let token_endpoint_url = format!("{server}/oauth/token");

    // Rebuild client_assertion and DPoP proof with the nonce.
    let client_assertion =
        ClientAssertionBuilder::new(client_id, &token_endpoint_url).build(fapi_key)?;

    let dpop_proof = DpopProofBuilder::new("POST", &token_endpoint_url)
        .nonce(nonce)
        .build(fapi_key)
        .context("failed to build DPoP proof with nonce")?;

    let retry_request = Fido2AssertionTokenRequest {
        grant_type: request.grant_type,
        client_assertion_type: request.client_assertion_type,
        client_assertion: client_assertion.assertion,
        assertion: request.assertion.clone(),
        scope: request.scope,
    };

    // Still within the same FIDO2 session — user presence confirmed by prior touch.
    let interaction = FapiInteraction::with_presence(true);
    let fapi_headers = interaction.headers();

    let form_body =
        serde_urlencoded::to_string(&retry_request).context("failed to encode token request")?;

    let token_resp = client
        .raw_client()
        .post(&token_endpoint_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("DPoP", dpop_proof)
        .header(fapi_headers[0].0, fapi_headers[0].1)
        .header(fapi_headers[1].0, fapi_headers[1].1)
        .body(form_body)
        .send()
        .await
        .context("failed to send token request (nonce retry)")?;

    let token_status = token_resp.status();
    if !token_status.is_success() {
        let body = token_resp.text().await.unwrap_or_default();
        anyhow::bail!("token request failed (HTTP {token_status}): {body}");
    }

    let fapi_token: Fapi2TokenResponse = token_resp
        .json()
        .await
        .context("failed to parse token response")?;

    let (expires_at_str, expires_at_ts) =
        resolve_expiry(fapi_token.expires_at.as_deref(), fapi_token.expires_in);

    let email = fapi_token.email.as_deref().unwrap_or("").to_string();

    let agent_stored = session::store_and_finalize(
        server,
        fapi_token.access_token.expose_secret(),
        &email,
        &expires_at_str,
        Some(expires_at_ts),
    )
    .await?;

    finalize_login_output(&email, &expires_at_str, agent_stored);

    Ok(())
}

/// Ensure the FAPI client is registered, registering on demand if needed.
///
/// Reads `client_id` from config. If absent, calls open registration
/// (no auth token required — the server allows unauthenticated registration).
///
/// Returns the `client_id` on success.
async fn ensure_client_registered(client: &VouchClient, fapi_key: &ClientKey) -> Result<String> {
    // Fast path: already registered.
    if let Ok(config) = Config::load()
        && let Some(id) = config.client_id()
    {
        return Ok(id.to_string());
    }

    // Slow path: register now (open registration — no auth token needed).
    tracing::debug!("No client_id found, registering FAPI client");

    let result = vouch_cli::fapi::registration::register_fapi_client(
        client.raw_client(),
        client.base_url(),
        None,
        fapi_key,
    )
    .await
    .context("failed to register FAPI client")?;

    // Persist the registration to config.
    Config::modify(|config| {
        config.set_client_id(&result.client_id);
        if let Some(ref rat) = result.registration_access_token {
            config.set_registration_access_token(rat);
        }
        if let Some(ref uri) = result.registration_client_uri {
            config.set_registration_client_uri(uri);
        }
        config.set_dpop_key_id(&result.dpop_key_id);
    })
    .context("failed to save FAPI registration to config")?;

    Ok(result.client_id)
}

// ============================================================================
// Helpers
// ============================================================================

/// Load the FAPI client key, checking sources in order:
///
/// 1. OS keychain (preferred — encrypted at rest)
/// 2. `~/.vouch/client_key.json` (legacy/fallback — migrated to keychain if possible)
/// 3. Generate new key → save to keychain (or file if keychain unavailable)
///
/// If the key is found on disk but not in the keychain, it is migrated to the
/// keychain and the file is removed. If the keychain is unavailable (CI, headless),
/// file storage is used as a fallback.
fn load_or_create_fapi_key() -> Result<ClientKey> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    let key_path = home.join(".vouch").join("client_key.json");

    // 1. Try the OS keychain first.
    match vouch_cli::fapi::key_store::load_from_keychain() {
        Ok(Some(key_file)) => {
            let key = ClientKey::from_key_file(&key_file)
                .context("failed to load client key from keychain")?;
            tracing::debug!("FAPI client key loaded from keychain: kid={}", key.kid());
            return Ok(key);
        }
        Ok(None) => {
            tracing::debug!("No client key in keychain, checking disk");
        }
        Err(e) => {
            tracing::debug!("Keychain unavailable ({e}), falling back to disk");
        }
    }

    // 2. Try loading from disk (legacy location).
    if key_path.exists() {
        let key = ClientKey::load(&key_path).context("failed to load FAPI client key from disk")?;
        tracing::debug!("FAPI client key loaded from disk: kid={}", key.kid());

        // Migrate to keychain if possible, then remove the file.
        if let Ok(key_file) = key.to_key_file()
            && vouch_cli::fapi::key_store::save_to_keychain(&key_file).is_ok()
        {
            tracing::debug!("Migrated client key to keychain");
            if let Err(e) = std::fs::remove_file(&key_path) {
                tracing::debug!("Could not remove old key file: {e}");
            }
        }

        return Ok(key);
    }

    // 3. Generate a new key.
    let key = ClientKey::generate().context("failed to generate FAPI client key")?;
    tracing::debug!("Generated new FAPI client key: kid={}", key.kid());

    // Save to keychain first, fall back to disk.
    if let Ok(key_file) = key.to_key_file()
        && vouch_cli::fapi::key_store::save_to_keychain(&key_file).is_ok()
    {
        tracing::debug!("Saved new client key to keychain");
        return Ok(key);
    }

    // Keychain unavailable — save to disk.
    key.save(&key_path)
        .context("failed to save FAPI client key to disk")?;
    tracing::debug!("Saved new client key to disk (keychain unavailable)");

    Ok(key)
}

/// Compute `(expires_at_string, expires_at_timestamp)` from the token response.
///
/// Uses the server-provided `expires_at` string when available; otherwise
/// computes it from `expires_in` seconds.
fn resolve_expiry(expires_at: Option<&str>, expires_in: u64) -> (String, jiff::Timestamp) {
    if let Some(s) = expires_at
        && let Ok(ts) = s.parse::<jiff::Timestamp>()
    {
        return (s.to_string(), ts);
    }

    let ts = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(
            // Subtract 30 s to avoid serving an already-expired token.
            i64::try_from(expires_in)
                .unwrap_or(28800)
                .saturating_sub(30),
        ))
        .unwrap_or_else(|_| jiff::Timestamp::now());

    (ts.to_string(), ts)
}

/// Print the post-login success message.
fn finalize_login_output(email: &str, expires_at: &str, agent_stored: bool) {
    if !email.is_empty() {
        println!("Login successful as {email}!");
    } else {
        println!("Login successful!");
    }
    println!("Session expires: {}", format_expiry(expires_at));

    if agent_stored {
        println!("\nYour identity is now available. Check with: vouch status");
    } else {
        println!("\nNote: Agent not running. Start it with: vouch-agent --foreground");
        println!("Your identity is stored locally. Check with: vouch status");
    }
}

/// Format an ISO 8601 expiry timestamp as a human-readable relative time.
///
/// Example: "in 8h (2026-01-27 12:25 UTC)"
fn format_expiry(expires_at: &str) -> String {
    let Ok(ts) = expires_at.parse::<jiff::Timestamp>() else {
        return expires_at.to_string();
    };

    let secs = ts.duration_since(jiff::Timestamp::now()).as_secs().max(0);
    let remaining = jiff::SignedDuration::from_mins(secs / 60);
    let local = ts.to_zoned(jiff::tz::TimeZone::system());
    let datetime = local.strftime("%Y-%m-%d %H:%M %Z");

    format!("in {remaining:#} ({datetime})")
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn test_format_expiry_invalid_timestamp_returns_as_is() {
        let result = format_expiry("not-a-timestamp");
        assert_eq!(result, "not-a-timestamp");
    }

    #[test]
    fn test_format_expiry_valid_future_timestamp() {
        let future = jiff::Timestamp::now()
            .checked_add(jiff::SignedDuration::from_hours(2))
            .unwrap();
        let s = future.to_string();
        let result = format_expiry(&s);
        assert!(result.starts_with("in"), "should start with 'in': {result}");
    }

    #[test]
    fn test_resolve_expiry_uses_provided_expires_at() {
        let future = jiff::Timestamp::now()
            .checked_add(jiff::SignedDuration::from_hours(1))
            .unwrap();
        let s = future.to_string();
        let (str_result, ts_result) = resolve_expiry(Some(&s), 3600);
        assert_eq!(str_result, s);
        // Timestamps should be close (within 1 second due to string round-trip)
        let diff = ts_result.duration_since(future).as_secs().unsigned_abs();
        assert!(diff <= 1, "timestamp round-trip should be within 1s");
    }

    #[test]
    fn test_resolve_expiry_falls_back_to_expires_in() {
        let (str_result, ts_result) = resolve_expiry(None, 3600);
        // Should be a valid timestamp close to now + 3600 - 30 = 3570 s
        let ts: jiff::Timestamp = str_result.parse().unwrap();
        let diff = ts.duration_since(jiff::Timestamp::now()).as_secs();
        // Allow generous window for test execution time
        assert!(
            diff > 3500 && diff <= 3570,
            "expected ~3570s in future, got {diff}"
        );
        let diff2 = ts_result.duration_since(jiff::Timestamp::now()).as_secs();
        assert!(diff2 > 3500 && diff2 <= 3570);
    }

    #[test]
    fn test_resolve_expiry_invalid_expires_at_falls_back() {
        let (str_result, _) = resolve_expiry(Some("not-a-timestamp"), 3600);
        // Should fall back and produce a valid timestamp string
        let ts: jiff::Timestamp = str_result
            .parse()
            .expect("should fall back to valid timestamp");
        let diff = ts.duration_since(jiff::Timestamp::now()).as_secs();
        assert!(diff > 3500 && diff <= 3570);
    }
}
