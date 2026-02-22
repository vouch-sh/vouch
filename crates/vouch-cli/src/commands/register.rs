// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Registration command - register an additional `YubiKey` with the server.
//!
//! This command requires the user to be already authenticated (via `vouch login`).
//! For first-time enrollment, use `vouch enroll` instead.
//!
//! Like [`super::login`], the flow is structured so that async server calls and
//! synchronous FIDO2 device operations run on separate threads. See the
//! module-level docs in [`crate::fido2`] for why this separation is required.

use anyhow::{Context, Result};
use secrecy::ExposeSecret;
use vouch_common::{
    RegisterCompleteRequest, RegisterCompleteResponse, RegisterStartRequest, RegisterStartResponse,
};

use crate::client::VouchClient;
use crate::fido2::{self, YubiKey};

/// Run the register command.
///
/// The execution order is intentional:
/// 1. Contact the server first (async, authenticated) — fail fast if
///    unreachable or unauthenticated
/// 2. All FIDO2 device work on a plain OS thread (wait, PIN, register)
/// 3. Complete registration with the server (async)
pub async fn run(server: &str, name: Option<&str>, timeout_secs: u64) -> Result<()> {
    let name = name.unwrap_or("YubiKey");
    println!("Registering additional YubiKey '{name}'...\n");

    // Step 1: Start registration with server (async, authenticated).
    // This fails fast if the server is unreachable or the user is not
    // authenticated, before they insert their key.
    print!("Contacting server... ");
    let client = VouchClient::new(server).await.context(
        "Not authenticated.\n\n\
         To register your first key: vouch enroll\n\
         To add additional keys: vouch login, then vouch register",
    )?;
    let start_resp: RegisterStartResponse = client
        .post_authenticated(
            "/v1/auth/register/start",
            &RegisterStartRequest {
                name: name.to_string(),
            },
        )
        .await
        .context("failed to start registration")?;
    println!("ok");

    // Show info about existing keys
    if !start_resp.exclude_credential_ids.is_empty() {
        println!(
            "\nNote: You have {} existing key(s) registered.",
            start_resp.exclude_credential_ids.len()
        );
    }

    // Step 2: All FIDO2 operations on a plain OS thread.
    //
    // SAFETY INVARIANT: FIDO2 calls use `with_suppressed_stdout` which mutates
    // the process-global stdout fd. They must not run on a tokio runtime thread.
    // `spawn_fido2` creates a dedicated `std::thread` with no tokio context.
    let rp_id = start_resp.rp_id.clone();
    let rp_name = start_resp.rp_name.clone();
    let challenge = start_resp.challenge.clone();
    let user_id = start_resp.user_id;
    let user_name = start_resp.user_name.clone();
    let result = fido2::spawn_fido2(move || {
        let key = YubiKey::wait_for_device(timeout_secs)?;
        let pin = fido2::ensure_pin_configured(&key)?;
        println!("\nTouch your YubiKey...");
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

    // Step 3: Complete registration with server (async, authenticated)
    print!("Completing registration... ");
    let complete_resp: RegisterCompleteResponse = client
        .post_authenticated(
            "/v1/auth/register/complete",
            &RegisterCompleteRequest {
                state: start_resp.state,
                credential_id: result.credential_id,
                public_key: result.public_key,
                attestation_object: result.attestation_object,
                client_data_json: result.client_data_json,
            },
        )
        .await
        .context("failed to complete registration")?;
    println!("ok\n");

    println!("Registration successful!");
    println!("Device ID: {}", complete_resp.device_id);
    println!("\nYou can manage your keys with: vouch keys");

    Ok(())
}
