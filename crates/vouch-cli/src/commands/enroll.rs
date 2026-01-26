//! Enroll command - RFC 8628 Device Authorization Grant.

use anyhow::{Context, Result};
use std::io::{Write, stdout};
use vouch_common::{
    DeviceCodeRequest, DeviceCodeResponse, DeviceTokenRequest, DeviceTokenResponse, OAuthError,
};

use crate::client::VouchClient;
use crate::config::Config;

/// Run the enroll command.
pub async fn run(server: &str) -> Result<()> {
    let client = VouchClient::new(server)?;

    println!("Starting enrollment...\n");

    // Step 1: Request device code
    let device_response: DeviceCodeResponse = client
        .post("/oauth/device/code", &DeviceCodeRequest::default())
        .await
        .context("Failed to start enrollment")?;

    // Step 2: Open browser and display instructions
    let verification_url = &device_response.verification_uri;

    // Try to open the browser automatically
    match open::that(verification_url) {
        Ok(()) => {
            println!("Opening browser to complete enrollment...");
            println!();
            println!("  URL:  {verification_url}");
            println!("  Code: {}", device_response.user_code);
            println!();
            println!("If the browser didn't open, visit the URL above and enter the code.");
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

    // Step 3: Poll for token
    let token_response = poll_for_token(&client, &device_response).await?;

    // Step 4: Save token
    let mut config = Config::load()?;
    config.save_token(&token_response.access_token)?;

    println!("\nEnrollment successful!");
    println!("Enrolled as: {}", token_response.email);
    println!();
    println!("To add additional keys:");
    println!("  1. vouch login");
    println!("  2. vouch register --name \"Backup Key\"");

    Ok(())
}

/// Poll the token endpoint until authorization is complete or timeout.
async fn poll_for_token(
    client: &VouchClient,
    device_response: &DeviceCodeResponse,
) -> Result<DeviceTokenResponse> {
    let request = DeviceTokenRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        device_code: device_response.device_code.clone(),
    };

    let interval = std::time::Duration::from_secs(device_response.interval);
    let timeout = std::time::Duration::from_secs(device_response.expires_in);
    let start = std::time::Instant::now();

    let mut dots = 0;

    loop {
        // Check timeout
        if start.elapsed() > timeout {
            anyhow::bail!("Enrollment timed out. Please try again.");
        }

        // Wait before polling
        tokio::time::sleep(interval).await;

        // Show progress
        dots = (dots + 1) % 4;
        print!("\rWaiting for browser authorization{}", ".".repeat(dots));
        print!("{}", " ".repeat(3 - dots));
        stdout().flush().ok();

        // Poll for token
        match poll_once(client, &request).await {
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
            Err(PollError::Denied) => {
                println!();
                anyhow::bail!("Authorization was denied.");
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
    Other(String),
}

/// Make a single poll request.
async fn poll_once(
    client: &VouchClient,
    request: &DeviceTokenRequest,
) -> Result<DeviceTokenResponse, PollError> {
    let url = format!("{}/oauth/token", client.base_url());

    let response = client
        .raw_client()
        .post(&url)
        .json(request)
        .send()
        .await
        .map_err(|e| PollError::Other(e.to_string()))?;

    let status = response.status();

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
            "authorization_pending" => return Err(PollError::Pending),
            "slow_down" => return Err(PollError::SlowDown),
            "access_denied" => return Err(PollError::Denied),
            "expired_token" => return Err(PollError::Expired),
            _ => {
                let msg = oauth_error.error_description.unwrap_or(oauth_error.error);
                return Err(PollError::Other(msg));
            }
        }
    }

    Err(PollError::Other(format!("HTTP {status}: {error_text}")))
}
