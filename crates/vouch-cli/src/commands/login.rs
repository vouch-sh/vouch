// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Login command - authenticate with your `YubiKey`.

use anyhow::{Context, Result};
use secrecy::ExposeSecret;
#[cfg(unix)]
use vouch_agent::{AgentClient, AgentError};
use vouch_common::{
    ClientContext, LoginCompleteRequest, LoginCompleteResponse, LoginStartRequest,
    LoginStartResponse, SessionCookie, write_cookie,
};

use crate::client::VouchClient;
use crate::commands::credential;
use crate::config::Config;
use crate::fido2::{self, YubiKey};

/// Run the login command.
/// Uses discoverable credentials - the YubiKey identifies the user.
pub async fn run(server: &str, timeout_secs: u64) -> Result<()> {
    println!("Logging in...\n");

    // Step 1: Wait for YubiKey to be inserted
    let key = YubiKey::wait_for_device(timeout_secs)?;

    // Step 2: Start authentication with server (no email needed)
    print!("Contacting server ({server})... ");
    let client = VouchClient::unauthenticated(server)?;
    let start_resp: LoginStartResponse = client
        .post("/v1/auth/login/start", &LoginStartRequest {})
        .await
        .context("failed to start login")?;
    println!("ok");

    // Step 3: Ensure PIN is configured and get it
    let pin = fido2::ensure_pin_configured(&key)?;

    // Step 4: Perform FIDO2 authentication using discoverable credential
    println!("\nTouch your YubiKey...");
    let result = key.authenticate(
        &start_resp.rp_id,
        &start_resp.challenge,
        pin.expose_secret(),
    )?;

    // Step 5: Complete authentication with server
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
                client_context: Some(ClientContext::current()),
            },
        )
        .await
        .context("failed to complete login")?;

    // Step 6: Store session in config, agent, and cookie file
    // Config save is fast local I/O, do it first
    let mut config = Config::load()?;
    config.set_server_url(server);
    config.set_token(&complete_resp.token);
    config.save()?;

    // Agent IPC and cookie write are independent — run concurrently
    let (agent_stored, _) = tokio::join!(
        async {
            #[cfg(unix)]
            {
                store_session_in_agent(&complete_resp.email, &complete_resp, server).await
            }
            #[cfg(not(unix))]
            {
                false
            }
        },
        async {
            if let Err(e) = write_session_cookie(server, &complete_resp) {
                tracing::debug!("Failed to write cookie file: {e}");
            }
        },
    );

    println!("Login successful as {}!", complete_resp.email);
    println!(
        "Session expires: {}",
        format_expiry(&complete_resp.expires_at)
    );

    // Step 8: Auto-provision SSH certificate
    credential::ssh::auto_provision(server, &complete_resp.expires_at).await;

    if agent_stored {
        println!("\nYour identity is now available. Check with: vouch status");
    } else {
        println!("\nNote: Agent not running. Start it with: vouch-agent --foreground");
        println!("Your identity is stored locally. Check with: vouch status");
    }

    Ok(())
}

/// Store session in the agent (if running).
#[cfg(unix)]
async fn store_session_in_agent(
    email: &str,
    response: &LoginCompleteResponse,
    server: &str,
) -> bool {
    match AgentClient::connect().await {
        Ok(mut agent) => {
            match agent
                .store_session(&response.token, email, &response.expires_at, Some(server))
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

/// Format an ISO 8601 expiry timestamp as a human-readable relative time.
///
/// Example: "in 8h (2026-01-27 12:25 UTC)"
fn format_expiry(expires_at: &str) -> String {
    let Ok(ts) = expires_at.parse::<jiff::Timestamp>() else {
        return expires_at.to_string();
    };

    let secs = ts.duration_since(jiff::Timestamp::now()).as_secs().max(0);
    let remaining = jiff::SignedDuration::from_mins(secs / 60);
    let datetime = ts.strftime("%Y-%m-%d %H:%M UTC");

    format!("in {remaining:#} ({datetime})")
}
