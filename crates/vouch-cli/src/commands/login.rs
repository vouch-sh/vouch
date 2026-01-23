//! Authenticate and start a session

use anyhow::{Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};

use crate::client::VouchClient;
use crate::config::Config;

#[derive(Deserialize)]
struct StartLoginResponse {
    /// URL to open in browser for WebAuthn ceremony
    login_url: String,
    /// One-time code to complete login
    code: String,
}

#[derive(Serialize)]
struct CompleteLoginRequest {
    code: String,
}

#[derive(Deserialize)]
struct CompleteLoginResponse {
    token: String,
    user_email: String,
    expires_at: String,
}

pub async fn run(client: &VouchClient, config: &Config) -> Result<()> {
    println!("{}", "Starting authentication...".bold());
    println!();

    // Start login flow
    let resp: StartLoginResponse = client
        .get("/v1/auth/login/start", None)
        .await
        .context("failed to start login")?;

    println!("Opening browser for authentication...");
    println!();
    println!("If the browser doesn't open, visit:");
    println!("  {}", resp.login_url.cyan());
    println!();
    println!("Verification code: {}", resp.code.yellow().bold());
    println!();

    // Open browser
    if let Err(e) = open::that(&resp.login_url) {
        tracing::warn!("failed to open browser: {}", e);
    }

    // Wait for user to complete login
    println!("Waiting for authentication...");
    println!("(Touch your YubiKey or use Touch ID when prompted)");
    println!();

    // Poll for completion
    let mut attempts = 0;
    let max_attempts = 60; // 2 minutes timeout

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        attempts += 1;

        if attempts > max_attempts {
            anyhow::bail!("login timed out - please try again");
        }

        let complete_req = CompleteLoginRequest {
            code: resp.code.clone(),
        };

        match client
            .post::<_, CompleteLoginResponse>("/v1/auth/login/complete", &complete_req, None)
            .await
        {
            Ok(result) => {
                // Save session
                let mut config = config.clone();
                config.set_session(result.token, result.user_email.clone())?;

                println!("{}", "✓ Authenticated successfully!".green().bold());
                println!();
                println!("  User:    {}", result.user_email);
                println!("  Expires: {}", result.expires_at);
                println!();
                println!(
                    "Run {} to get credentials.",
                    "vouch get github".cyan()
                );
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
