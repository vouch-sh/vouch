// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Registration command - register an additional `YubiKey` with the server.
//!
//! This command requires the user to be already authenticated (via `vouch login`).
//! For first-time enrollment, use `vouch enroll` instead.

use anyhow::{Context, Result};
use secrecy::ExposeSecret;
use vouch_common::{
    RegisterCompleteRequest, RegisterCompleteResponse, RegisterStartRequest, RegisterStartResponse,
};

use crate::client::VouchClient;
use crate::config::Config;
use crate::fido2::{self, YubiKey};

/// Run the register command.
pub async fn run(server: &str, name: Option<&str>, timeout_secs: u64) -> Result<()> {
    // Require authentication
    let config = Config::load()?;
    let token = config.token().context(
        "Not authenticated.\n\n\
         To register your first key: vouch enroll\n\
         To add additional keys: vouch login, then vouch register",
    )?;

    let name = name.unwrap_or("YubiKey");
    println!("Registering additional YubiKey '{name}'...\n");

    // Step 1: Wait for YubiKey to be inserted
    let key = YubiKey::wait_for_device(timeout_secs)?;

    // Step 2: Start registration with server (authenticated)
    print!("Contacting server... ");
    let client = VouchClient::new(server)?;
    let start_resp: RegisterStartResponse = client
        .raw_client()
        .post(format!("{}/v1/auth/register/start", client.base_url()))
        .header("Authorization", format!("Bearer {}", token.expose_secret()))
        .json(&RegisterStartRequest {
            name: name.to_string(),
        })
        .send()
        .await
        .context("failed to connect to server")?
        .error_for_status()
        .map_err(|e| {
            if e.status() == Some(reqwest::StatusCode::UNAUTHORIZED) {
                anyhow::anyhow!(
                    "Session expired.\n\n\
                     Please run 'vouch login' first, then try again."
                )
            } else if e.status() == Some(reqwest::StatusCode::CONFLICT) {
                anyhow::anyhow!("This security key is already registered.")
            } else {
                anyhow::anyhow!("Server error: {}", e)
            }
        })?
        .json()
        .await
        .context("failed to parse server response")?;
    println!("ok");

    // Show info about existing keys
    if !start_resp.exclude_credential_ids.is_empty() {
        println!(
            "\nNote: You have {} existing key(s) registered.",
            start_resp.exclude_credential_ids.len()
        );
    }

    // Step 3: Ensure PIN is configured and get it
    let pin = fido2::ensure_pin_configured(&key)?;

    // Step 4: Perform FIDO2 registration on device
    println!("\nTouch your YubiKey...");
    let result = key.register(
        &start_resp.rp_id,
        &start_resp.rp_name,
        &start_resp.challenge,
        start_resp.user_id.as_bytes(),
        &start_resp.user_name,
        pin.expose_secret(),
    )?;

    // Step 5: Complete registration with server (authenticated)
    print!("Completing registration... ");
    let complete_resp: RegisterCompleteResponse = client
        .raw_client()
        .post(format!("{}/v1/auth/register/complete", client.base_url()))
        .header("Authorization", format!("Bearer {}", token.expose_secret()))
        .json(&RegisterCompleteRequest {
            state: start_resp.state,
            credential_id: result.credential_id,
            public_key: result.public_key,
            attestation_object: result.attestation_object,
            client_data_json: result.client_data_json,
        })
        .send()
        .await
        .context("failed to connect to server")?
        .error_for_status()
        .map_err(|e| {
            if e.status() == Some(reqwest::StatusCode::CONFLICT) {
                anyhow::anyhow!("This security key is already registered.")
            } else {
                anyhow::anyhow!("Server error: {}", e)
            }
        })?
        .json()
        .await
        .context("failed to parse server response")?;
    println!("ok\n");

    println!("Registration successful!");
    println!("Device ID: {}", complete_resp.device_id);
    println!("\nYou can manage your keys with: vouch keys");

    Ok(())
}
