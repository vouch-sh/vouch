// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Enroll command - RFC 8628 Device Authorization Grant with FAPI 2.0 support.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use std::io::{IsTerminal, Write, stdout};
use vouch_common::{
    DeviceCodeRequest, DeviceCodeResponse, DeviceTokenRequest, OAuthError, RegisterCompleteRequest,
    RegisterCompleteResponse, RegisterStartRequest, RegisterStartResponse,
};

use crate::client::VouchClient;
use crate::config::Config;
use crate::fido2::{self, YubiKey};
use crate::session;

/// Response from device token endpoint.
#[derive(serde::Deserialize)]
struct DeviceTokenResponse {
    access_token: SecretString,
    expires_in: u64,
    email: String,
}

impl std::fmt::Debug for DeviceTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .field("email", &self.email)
            .finish()
    }
}

/// Run the enroll command.
pub async fn run(server: &str) -> Result<()> {
    let client = VouchClient::unauthenticated(server)?;

    println!("Starting enrollment...\n");

    // Step 1: Generate or load the FAPI client key (for DPoP proofs).
    let fapi_key = vouch_cli::fapi::key_store::load_or_create_client_key().ok();

    // Step 2: Register as a FAPI 2.0 client BEFORE the device code flow
    // (open registration — no auth token required).
    //
    // This ensures we have a client_id before the device authorization
    // request so the token will be bound to our registered client from
    // the start. Registration is non-fatal: enrollment continues even
    // if this step fails.
    let pre_registered_client_id = if let Some(ref key) = fapi_key {
        register_fapi_client_open(client.raw_client(), server, key).await
    } else {
        None
    };

    // Step 3: Request device code (RFC 8628 Section 3.1).
    // Include the client_id if we registered successfully.
    let device_request = DeviceCodeRequest {
        client_id: pre_registered_client_id.clone(),
        scope: None,
    };

    let device_response: DeviceCodeResponse = client
        .post_form("/oauth/device", &device_request)
        .await
        .context("Failed to start enrollment")?;

    // Step 4: Open browser and display instructions.
    let verification_url = &device_response.verification_uri;

    // Try to open the browser automatically
    match open::that(verification_url) {
        Ok(()) => {
            println!("Opening browser to complete enrollment...");
            println!();
            println!("  URL:  {verification_url}");
            println!("  Code: {}", device_response.user_code);
            println!();
            println!(
                "If the browser didn't open, visit the URL above \
                 and enter the code."
            );
        }
        Err(e) => {
            tracing::debug!("Failed to open browser: {e}");
            println!("To complete enrollment:");
            println!();
            println!("  1. Open this URL in your browser:");
            println!("     {verification_url}");
            println!();
            println!("  2. Enter this code:");
            println!("     {}", device_response.user_code);
        }
    }
    println!();
    println!("Waiting for browser authorization...");

    // Step 5: Poll for token (with optional DPoP proofs).
    let token_response = poll_for_token(&client, &device_response, fapi_key.as_ref()).await?;

    // Step 6: Compute expiration timestamp from expires_in.
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(
            i64::try_from(token_response.expires_in).unwrap_or(28800) - 30,
        ))
        .unwrap_or_else(|_| jiff::Timestamp::now());
    let expires_at_str = expires_at.to_string();

    // Step 7: Store session, cookie, and auto-provision SSH.
    // Enrollment uses device authorization grant (no FAPI key / no DPoP).
    let agent_stored = session::store_and_finalize(
        server,
        token_response.access_token.expose_secret(),
        &token_response.email,
        &expires_at_str,
        Some(expires_at),
        None,
    )
    .await?;

    println!("\nEnrollment successful!");
    println!("Enrolled as: {}", token_response.email);

    // Step 8: Auto-register the inserted YubiKey if not already known.
    // The enrollment token is a full OAuth access token that can call
    // the /v1/keys/register/* endpoints (same as `vouch register`).
    if let Err(e) = register_current_key(server, token_response.access_token.clone()).await {
        tracing::debug!("Auto-registration skipped: {e}");
    }

    if agent_stored {
        println!("\nYour identity is now available. Check with: vouch status");
    } else {
        println!("\nNote: Agent not running. Start it with: vouch-agent --foreground");
    }

    println!();
    println!("Set up integrations:");
    println!("  vouch setup ssh      # SSH certificates");
    println!("  vouch setup aws      # AWS credentials");
    println!("  vouch setup github   # GitHub tokens");
    println!();
    println!("Or add a backup key:");
    println!("  vouch login && vouch register --name \"Backup Key\"");

    Ok(())
}


/// Attempt open (unauthenticated) FAPI client registration.
///
/// This is called before the device code flow so the resulting token will
/// be bound to the registered client from the start. The server accepts
/// `POST /oauth/register` without a Bearer token when open registration
/// is enabled.
///
/// Returns `Some(client_id)` on success, `None` on any failure (non-fatal).
async fn register_fapi_client_open(
    http_client: &reqwest::Client,
    base_url: &str,
    key: &vouch_cli::fapi::ClientKey,
) -> Option<String> {
    // If we already have a client_id in config for this server, skip.
    if let Ok(mut config) = Config::load() {
        config.set_server_url(base_url);
        if let Some(id) = config.client_id() {
            tracing::debug!("FAPI client already registered: client_id={id}");
            return Some(id.to_string());
        }
    }

    // Open registration — no auth token.
    match vouch_cli::fapi::registration::register_fapi_client(http_client, base_url, None, key)
        .await
    {
        Ok(result) => {
            let client_id = result.client_id.clone();

            // Save registration results to config.
            let url = base_url.to_string();
            if let Err(e) = Config::modify(|config| {
                config.set_server_url(&url);
                config.set_client_id(&result.client_id);
                if let Some(ref rat) = result.registration_access_token {
                    config.set_registration_access_token(rat);
                }
                if let Some(ref uri) = result.registration_client_uri {
                    config.set_registration_client_uri(uri);
                }
                config.set_dpop_key_id(&result.dpop_key_id);
            }) {
                tracing::warn!("Failed to save FAPI registration to config: {e}");
            }

            Some(client_id)
        }
        Err(e) => {
            tracing::debug!("Pre-enrollment FAPI registration failed (non-fatal): {e}");
            None
        }
    }
}

/// Poll the token endpoint until authorization is complete or timeout.
///
/// If a FAPI key is provided, includes DPoP proofs on token requests
/// and handles DPoP nonce retry from the server.
async fn poll_for_token(
    client: &VouchClient,
    device_response: &DeviceCodeResponse,
    fapi_key: Option<&vouch_cli::fapi::ClientKey>,
) -> Result<DeviceTokenResponse> {
    let request = DeviceTokenRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        device_code: device_response.device_code.clone(),
    };

    let interval = std::time::Duration::from_secs(device_response.interval);
    let timeout = std::time::Duration::from_secs(device_response.expires_in);
    let start = std::time::Instant::now();

    let mut dots = 0;
    // Track server-provided DPoP nonce for RFC 9449 nonce binding
    let mut dpop_nonce: Option<String> = None;

    loop {
        // Check timeout
        if start.elapsed() > timeout {
            anyhow::bail!(
                "Enrollment timed out. Please try again.\n\
                 Make sure to complete the sign-in in your \
                 browser window and enter the code shown above."
            );
        }

        // Wait before polling
        tokio::time::sleep(interval).await;

        // Show progress (only on interactive terminals)
        if stdout().is_terminal() {
            dots = (dots + 1) % 4;
            print!("\rWaiting for browser authorization{}", ".".repeat(dots));
            print!("{}", " ".repeat(3 - dots));
            stdout().flush().ok();
        }

        // Poll for token (with optional DPoP proof)
        match poll_once(client, &request, fapi_key, dpop_nonce.as_deref()).await {
            Ok(response) => {
                println!(); // Clear the progress line
                return Ok(response);
            }
            Err(PollError::Pending) => {
                // Keep waiting
            }
            Err(PollError::SlowDown) => {
                // Increase interval and continue
                tokio::time::sleep(interval).await;
            }
            Err(PollError::DpopNonce(nonce)) => {
                // Server requires a DPoP nonce — retry immediately
                tracing::debug!("Server requires DPoP nonce, retrying");
                dpop_nonce = Some(nonce);
            }
            Err(PollError::Denied) => {
                println!();
                return Err(crate::exit_code::CliError::PermissionDenied(
                    "authorization was denied".to_string(),
                )
                .into());
            }
            Err(PollError::Expired) => {
                println!();
                anyhow::bail!("The code has expired. Please try again.");
            }
            Err(PollError::Other(msg)) => {
                println!();
                anyhow::bail!("Enrollment failed: {msg}");
            }
        }
    }
}

/// Result of a single poll attempt.
enum PollError {
    Pending,
    SlowDown,
    Denied,
    Expired,
    /// Server returned `use_dpop_nonce` — retry with the provided nonce.
    DpopNonce(String),
    Other(String),
}

/// Make a single poll request to the token endpoint.
///
/// Includes DPoP proof and FAPI headers if a client key is available.
async fn poll_once(
    client: &VouchClient,
    request: &DeviceTokenRequest,
    fapi_key: Option<&vouch_cli::fapi::ClientKey>,
    dpop_nonce: Option<&str>,
) -> Result<DeviceTokenResponse, PollError> {
    let url = format!("{}/oauth/token", client.base_url());

    // Build the request with form encoding
    let mut builder = client.raw_client().post(&url).form(request);

    // Add DPoP proof if we have a FAPI key
    if let Some(key) = fapi_key {
        let mut dpop_builder = vouch_cli::fapi::DpopProofBuilder::new("POST", &url);
        if let Some(nonce) = dpop_nonce {
            dpop_builder = dpop_builder.nonce(nonce);
        }
        match dpop_builder.build(key) {
            Ok(proof) => {
                builder = builder.header("DPoP", proof);
            }
            Err(e) => {
                tracing::debug!("Failed to build DPoP proof: {e}");
                // Continue without DPoP — server will issue
                // a non-DPoP-bound token
            }
        }
    }

    // Add FAPI interaction headers only when FAPI key is present
    // (consistent with VouchClient::build_fapi_request)
    if fapi_key.is_some() {
        let interaction = vouch_cli::fapi::FapiInteraction::new();
        let fapi_headers = interaction.headers();
        for (name, value) in &fapi_headers {
            builder = builder.header(*name, *value);
        }
    }

    let response = builder
        .send()
        .await
        .map_err(|e| PollError::Other(e.to_string()))?;

    let status = response.status();

    // Capture DPoP-Nonce header for use_dpop_nonce flow (RFC 9449)
    let response_dpop_nonce = response
        .headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    if status.is_success() {
        let token_response: DeviceTokenResponse = response
            .json()
            .await
            .map_err(|e| PollError::Other(e.to_string()))?;
        return Ok(token_response);
    }

    // Parse error response
    let error_text = response.text().await.unwrap_or_default();

    if let Ok(oauth_error) = serde_json::from_str::<OAuthError>(&error_text) {
        match oauth_error.error.as_str() {
            "authorization_pending" => {
                return Err(PollError::Pending);
            }
            "slow_down" => return Err(PollError::SlowDown),
            "access_denied" => return Err(PollError::Denied),
            "expired_token" => return Err(PollError::Expired),
            "use_dpop_nonce" => {
                // RFC 9449: Server requires a DPoP nonce
                if let Some(nonce) = response_dpop_nonce {
                    return Err(PollError::DpopNonce(nonce));
                }
                // No nonce header — treat as a generic error
                return Err(PollError::Other(
                    "Server requires DPoP nonce but did not \
                     provide one"
                        .to_string(),
                ));
            }
            _ => {
                let msg = oauth_error.error_description.unwrap_or(oauth_error.error);
                return Err(PollError::Other(msg));
            }
        }
    }

    Err(PollError::Other(format!("HTTP {status}: {error_text}")))
}

/// Register the currently-inserted YubiKey using the enrollment token.
///
/// Called after enrollment succeeds. If the YubiKey is already registered
/// (credential ID is in the exclude list), this is a no-op. If no YubiKey
/// is inserted, or registration fails, the error is returned but should
/// not block the enrollment flow.
async fn register_current_key(server: &str, token: SecretString) -> Result<()> {
    let client = VouchClient::with_token(server, token)?;

    let start_resp: RegisterStartResponse = client
        .post_authenticated(
            "/v1/keys/register/start",
            &RegisterStartRequest {
                name: "YubiKey".to_string(),
            },
        )
        .await
        .context("failed to start key registration")?;

    println!("\nRegistering your YubiKey with the server...");

    let rp_id = start_resp.rp_id.clone();
    let rp_name = start_resp.rp_name.clone();
    let challenge = start_resp.challenge.clone();
    let user_id = start_resp.user_id;
    let user_name = start_resp.user_name.clone();

    // Short timeout — the key should already be inserted from
    // the enrollment flow. Don't block the user for long.
    let result = fido2::spawn_fido2(move || {
        let key = YubiKey::wait_for_device(10)?;
        let pin = fido2::ensure_pin_configured(&key)?;
        println!("Touch your YubiKey...");
        key.register(
            &rp_id,
            &rp_name,
            &challenge,
            user_id.as_bytes(),
            &user_name,
            pin.expose_secret(),
        )
    })
    .await?;

    let complete_resp: RegisterCompleteResponse = client
        .post_authenticated(
            "/v1/keys/register/complete",
            &RegisterCompleteRequest {
                state: start_resp.state,
                credential_id: result.credential_id,
                public_key: result.public_key,
                attestation_object: result.attestation_object,
                client_data_json: result.client_data_json,
            },
        )
        .await
        .context("failed to complete key registration")?;

    println!(
        "YubiKey registered! (device ID: {})",
        complete_resp.device_id
    );

    Ok(())
}
