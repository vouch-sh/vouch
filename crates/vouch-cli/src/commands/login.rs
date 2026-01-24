//! Login command - authenticate with your `YubiKey`.

use anyhow::{Context, Result};
use vouch_agent::{AgentClient, AgentError};
use vouch_common::{
    LoginCompleteRequest, LoginCompleteResponse, LoginStartRequest, LoginStartResponse,
    SessionCookie, write_cookie,
};

use crate::client::VouchClient;
use crate::config::Config;
use crate::fido2::{self, YubiKey};

/// Run the login command.
pub async fn run(server: &str, email: &str) -> Result<()> {
    println!("Logging in as {email}...\n");

    // Step 1: Wait for YubiKey to be inserted
    let key = YubiKey::wait_for_device()?;

    // Step 2: Start authentication with server
    print!("Contacting server... ");
    let client = VouchClient::new(server)?;
    let start_resp: LoginStartResponse = client
        .post(
            "/v1/auth/login/start",
            &LoginStartRequest {
                email: email.to_string(),
            },
        )
        .await
        .context("failed to start login")?;
    println!("ok");

    if start_resp.credential_ids.is_empty() {
        anyhow::bail!("no credentials found for {email} - have you registered?");
    }

    // Step 3: Prompt for PIN
    println!();
    let pin = fido2::prompt_pin()?;

    // Step 4: Perform FIDO2 authentication on device
    println!("\nTouch your YubiKey...");
    let result = key.authenticate(
        &start_resp.rp_id,
        &start_resp.challenge,
        &start_resp.credential_ids,
        &pin,
    )?;

    // Step 5: Complete authentication with server
    print!("Completing login... ");
    let complete_resp: LoginCompleteResponse = client
        .post(
            "/v1/auth/login/complete",
            &LoginCompleteRequest {
                state: start_resp.state,
                credential_id: result.credential_id,
                authenticator_data: result.authenticator_data,
                signature: result.signature,
                client_data_json: result.client_data_json,
                user_handle: result.user_handle,
            },
        )
        .await
        .context("failed to complete login")?;
    println!("ok\n");

    // Step 6: Store session in agent (if running) and config
    let agent_stored = store_session_in_agent(email, &complete_resp).await;

    // Also save to config as fallback
    let mut config = Config::load()?;
    config.save_token(&complete_resp.token)?;

    // Step 7: Write cookie file for CLI tools
    if let Err(e) = write_session_cookie(server, &complete_resp) {
        tracing::debug!("Failed to write cookie file: {e}");
    }

    println!("Login successful!");
    println!("Session expires: {}", complete_resp.expires_at);

    if agent_stored {
        println!("\nYour identity is now available. Check with: vouch status");
    } else {
        println!("\nNote: Agent not running. Start it with: vouch-agent --foreground");
        println!("Your identity is stored locally. Check with: vouch status");
    }

    Ok(())
}

/// Store session in the agent (if running).
async fn store_session_in_agent(email: &str, response: &LoginCompleteResponse) -> bool {
    match AgentClient::connect().await {
        Ok(mut agent) => {
            match agent
                .store_session(&response.token, email, &response.expires_at)
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
fn write_session_cookie(server: &str, response: &LoginCompleteResponse) -> Result<()> {
    // Extract domain from server URL
    let url = url::Url::parse(server).context("failed to parse server URL")?;
    let domain = url
        .host_str()
        .context("server URL has no host")?
        .to_string();

    // Parse expiration time
    let expires_at: jiff::Timestamp = response
        .expires_at
        .parse()
        .context("failed to parse expiration time")?;
    let expires_unix = expires_at.as_second();

    // Create and write cookie
    let cookie = SessionCookie::new(&domain, &response.token, expires_unix);
    write_cookie(&cookie)?;

    tracing::debug!("Cookie written to ~/.vouch/cookie.txt");
    Ok(())
}
