// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Login command - authenticate with your `YubiKey`.
//!
//! The flow is structured so that all async I/O (server calls) happens on the
//! tokio runtime while all FIDO2 device operations run on a plain OS thread
//! via [`crate::fido2::spawn_fido2`]. See the module-level docs in
//! [`crate::fido2`] for why this separation is required.

use anyhow::{Context, Result};
use secrecy::ExposeSecret;
use vouch_common::{
    ClientContext, LoginCompleteRequest, LoginCompleteResponse, LoginStartRequest,
    LoginStartResponse,
};

use crate::client::VouchClient;
use crate::commands::credential;
use crate::config::Config;
use crate::fido2::{self, YubiKey};
use crate::session;

/// Run the login command.
///
/// Uses discoverable credentials - the YubiKey identifies the user.
///
/// The execution order is intentional:
/// 1. Contact the server first (async) — fail fast if unreachable
/// 2. All FIDO2 device work on a plain OS thread (wait, PIN, authenticate)
/// 3. Complete authentication with the server (async)
pub async fn run(server: &str, timeout_secs: u64) -> Result<()> {
    println!("Logging in...\n");

    // Step 1: Start authentication with server (async, no YubiKey needed yet).
    // This fails fast if the server is unreachable, before the user inserts
    // their key.
    print!("Contacting server ({server})... ");
    let client = VouchClient::unauthenticated(server)?;
    let start_resp: LoginStartResponse = client
        .post("/v1/auth/login/start", &LoginStartRequest {})
        .await
        .context("failed to start login")?;
    println!("ok");

    // Step 2: All FIDO2 operations on a plain OS thread.
    //
    // SAFETY INVARIANT: FIDO2 calls use `with_suppressed_stdout` which mutates
    // the process-global stdout fd. They must not run on a tokio runtime thread.
    // `spawn_fido2` creates a dedicated `std::thread` with no tokio context.
    let rp_id = start_resp.rp_id.clone();
    let challenge = start_resp.challenge.clone();
    let result = fido2::spawn_fido2(move || {
        let key = YubiKey::wait_for_device(timeout_secs)?;
        let pin = fido2::ensure_pin_configured(&key)?;
        println!("\nTouch your YubiKey...");
        key.authenticate(&rp_id, &challenge, pin.expose_secret())
    })
    .await?;

    // Step 3: Complete authentication with server (async)
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

    // Step 4: Store session in config, agent, and cookie file
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
                session::store_session_in_agent(
                    &complete_resp.token,
                    &complete_resp.email,
                    &complete_resp.expires_at,
                    server,
                )
                .await
            }
            #[cfg(not(unix))]
            {
                false
            }
        },
        async {
            // Parse expiration time for cookie
            if let Ok(expires_at) = complete_resp.expires_at.parse::<jiff::Timestamp>() {
                if let Err(e) =
                    session::write_session_cookie_file(server, &complete_resp.token, expires_at)
                {
                    tracing::debug!("Failed to write cookie file: {e}");
                }
            } else {
                tracing::debug!(
                    "Failed to parse expiration time: {}",
                    complete_resp.expires_at
                );
            }
        },
    );

    println!("Login successful as {}!", complete_resp.email);
    println!(
        "Session expires: {}",
        format_expiry(&complete_resp.expires_at)
    );

    // Step 5: Auto-provision SSH certificate
    credential::ssh::auto_provision(server, &complete_resp.expires_at).await;

    if agent_stored {
        println!("\nYour identity is now available. Check with: vouch status");
    } else {
        println!("\nNote: Agent not running. Start it with: vouch-agent --foreground");
        println!("Your identity is stored locally. Check with: vouch status");
    }

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
    let local = ts.to_zoned(jiff::tz::TimeZone::system());
    let datetime = local.strftime("%Y-%m-%d %H:%M %Z");

    format!("in {remaining:#} ({datetime})")
}
