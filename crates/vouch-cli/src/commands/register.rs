//! Register a new authenticator (YubiKey or Touch ID)

use anyhow::{Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};

use crate::client::VouchClient;

#[derive(Serialize)]
struct StartRegistrationRequest {
    name: Option<String>,
}

#[derive(Deserialize)]
struct StartRegistrationResponse {
    /// URL to open in browser for WebAuthn ceremony
    registration_url: String,
    /// One-time code to complete registration
    code: String,
}

#[derive(Serialize)]
struct CompleteRegistrationRequest {
    code: String,
}

#[derive(Deserialize)]
struct CompleteRegistrationResponse {
    device_id: String,
    device_name: String,
}

pub async fn run(client: &VouchClient, name: Option<String>) -> Result<()> {
    println!("{}", "Registering new authenticator...".bold());
    println!();

    // Start registration flow
    let req = StartRegistrationRequest { name };
    let resp: StartRegistrationResponse = client
        .post("/v1/auth/register/start", &req, None)
        .await
        .context("failed to start registration")?;

    println!("Opening browser for device registration...");
    println!();
    println!("If the browser doesn't open, visit:");
    println!("  {}", resp.registration_url.cyan());
    println!();
    println!("Verification code: {}", resp.code.yellow().bold());
    println!();

    // Open browser
    if let Err(e) = open::that(&resp.registration_url) {
        tracing::warn!("failed to open browser: {}", e);
    }

    // Wait for user to complete registration
    println!("Waiting for registration to complete...");
    println!("(Touch your YubiKey or use Touch ID when prompted in the browser)");
    println!();

    // Poll for completion
    let mut attempts = 0;
    let max_attempts = 60; // 2 minutes timeout

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        attempts += 1;

        if attempts > max_attempts {
            anyhow::bail!("registration timed out - please try again");
        }

        let complete_req = CompleteRegistrationRequest {
            code: resp.code.clone(),
        };

        match client
            .post::<_, CompleteRegistrationResponse>(
                "/v1/auth/register/complete",
                &complete_req,
                None,
            )
            .await
        {
            Ok(result) => {
                println!("{}", "✓ Authenticator registered successfully!".green().bold());
                println!();
                println!("  Device ID:   {}", result.device_id);
                println!("  Device name: {}", result.device_name);
                println!();
                println!("Run {} to start a session.", "vouch login".cyan());
                return Ok(());
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("pending") || err_str.contains("not_complete") {
                    // Still waiting, continue polling
                    continue;
                }
                // Real error
                return Err(e);
            }
        }
    }
}
