//! Registration command - register a new `YubiKey` with the server.

use anyhow::{Context, Result};
use vouch_common::{
    RegisterCompleteRequest, RegisterCompleteResponse, RegisterStartRequest, RegisterStartResponse,
};

use crate::client::VouchClient;
use crate::fido2::{self, YubiKey};

/// Run the register command.
pub async fn run(server: &str, name: Option<&str>, email: &str) -> Result<()> {
    let name = name.unwrap_or("YubiKey");
    println!("Registering YubiKey '{name}' for {email}...\n");

    // Step 1: Wait for YubiKey to be inserted
    let key = YubiKey::wait_for_device()?;

    // Step 2: Start registration with server
    print!("Contacting server... ");
    let client = VouchClient::new(server)?;
    let start_resp: RegisterStartResponse = client
        .post(
            "/v1/auth/register/start",
            &RegisterStartRequest {
                name: name.to_string(),
                email: email.to_string(),
            },
        )
        .await
        .context("failed to start registration")?;
    println!("ok");

    // Step 3: Prompt for PIN
    println!();
    let pin = fido2::prompt_pin()?;

    // Step 4: Perform FIDO2 registration on device
    println!("\nTouch your YubiKey...");
    let result = key.register(
        &start_resp.rp_id,
        &start_resp.rp_name,
        &start_resp.challenge,
        start_resp.user_id.as_bytes(),
        &start_resp.user_name,
        &pin,
    )?;

    // Step 5: Complete registration with server
    print!("Completing registration... ");
    let complete_resp: RegisterCompleteResponse = client
        .post(
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
    println!("\nYou can now log in with: vouch login --email {email}");

    Ok(())
}
