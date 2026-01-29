// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Enroll command - RFC 8628 Device Authorization Grant.

use anyhow::{Context, Result};
use std::io::{Write, stdout};
#[cfg(unix)]
use vouch_agent::{AgentClient, AgentError};
use vouch_common::{
    DeviceCodeRequest, DeviceCodeResponse, DeviceTokenRequest, DeviceTokenResponse, OAuthError,
    SessionCookie, write_cookie,
};

use crate::client::VouchClient;
use crate::commands::credential;
use crate::config::Config;

/// Run the enroll command.
pub async fn run(server: &str) -> Result<()> {
    let client = VouchClient::new(server)?;

    println!("Starting enrollment...\n");

    // Step 1: Request device code (RFC 8628 Section 3.1 requires form encoding)
    let device_response: DeviceCodeResponse = client
        .post_form("/oauth/device/code", &DeviceCodeRequest::default())
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

    // Step 4: Save server URL and token
    let mut config = Config::load()?;
    config.save_server_url(server)?;
    config.save_token(&token_response.access_token)?;

    // Step 5: Compute expiration timestamp from expires_in
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(
            i64::try_from(token_response.expires_in).unwrap_or(28800) - 30,
        ))
        .unwrap_or_else(|_| jiff::Timestamp::now());
    let expires_at_str = expires_at.to_string();

    // Step 6: Store session in agent (if running)
    #[cfg(unix)]
    let agent_stored = store_session_in_agent(
        &token_response.access_token,
        &token_response.email,
        &expires_at_str,
        server,
    )
    .await;
    #[cfg(not(unix))]
    let agent_stored = false;

    // Step 7: Write cookie file for CLI tools
    if let Err(e) = write_session_cookie(server, &token_response.access_token, expires_at) {
        tracing::debug!("Failed to write cookie file: {e}");
    }

    println!("\nEnrollment successful!");
    println!("Enrolled as: {}", token_response.email);

    // Step 8: Auto-provision SSH certificate
    credential::ssh::auto_provision(server, &expires_at_str).await;

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

/// Store session in the agent (if running).
#[cfg(unix)]
async fn store_session_in_agent(token: &str, email: &str, expires_at: &str, server: &str) -> bool {
    match AgentClient::connect().await {
        Ok(mut agent) => {
            match agent
                .store_session(token, email, expires_at, Some(server))
                .await
            {
                Ok(()) => true,
                Err(e) => {
                    tracing::debug!("Failed to store session in agent: {e}");
                    false
                }
            }
        }
        Err(AgentError::NotRunning) => {
            tracing::debug!("Agent not running, session stored in config only");
            false
        }
        Err(e) => {
            tracing::debug!("Failed to connect to agent: {e}");
            false
        }
    }
}

/// Write the session cookie file for CLI tools.
fn write_session_cookie(server: &str, token: &str, expires_at: jiff::Timestamp) -> Result<()> {
    let url = url::Url::parse(server).context("failed to parse server URL")?;
    let domain = url
        .host_str()
        .context("server URL has no host")?
        .to_string();

    let cookie = SessionCookie::new(&domain, token, expires_at.as_second());
    write_cookie(&cookie)?;

    tracing::debug!("Cookie written to ~/.vouch/cookie.txt");
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

    // RFC 8628 Section 3.4: Token endpoint requires application/x-www-form-urlencoded
    let response = client
        .raw_client()
        .post(&url)
        .form(request)
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
