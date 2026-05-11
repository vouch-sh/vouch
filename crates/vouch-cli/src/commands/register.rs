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
use vouch_common::{
    RegisterCompleteRequest, RegisterCompleteResponse, RegisterStartRequest, RegisterStartResponse,
};

use crate::client::VouchClient;
use crate::fido2::{self, FidoDevice, YubiKey};

/// On macOS, Google Chrome claims YubiKeys at the USB device level the moment
/// they enumerate (so its WebAuthn can respond instantly), which blocks every
/// other process from doing CTAP-HID. Detect that case so we can route the
/// user through the server's browser-based enrollment page instead — Chrome
/// can use the device for its own WebAuthn while it holds it, even though
/// nothing else can.
#[cfg(target_os = "macos")]
fn is_chrome_running() -> bool {
    std::process::Command::new("pgrep")
        .args(["-f", "Google Chrome.app/Contents/MacOS/Google Chrome"])
        .output()
        .is_ok_and(|out| out.status.success())
}

#[cfg(not(target_os = "macos"))]
fn is_chrome_running() -> bool {
    false
}

fn browser_register_fallback(server: &str) -> Result<()> {
    let url = format!("{}/enroll/keys", server.trim_end_matches('/'));
    println!(
        "Google Chrome is using your YubiKey, so we can't register it from\n\
         the command line. Opening your browser to finish registration there\n\
         instead. (Tip: quit Chrome and re-run if you'd prefer the CLI.)\n"
    );
    match open::that(&url) {
        Ok(()) => {
            println!("Opening browser to complete registration...");
            println!();
            println!("  URL: {url}");
            println!();
            println!(
                "If the browser didn't open, visit the URL above. You may be\n\
                 prompted to sign in again. After registration, run `vouch keys`\n\
                 to verify."
            );
        }
        Err(e) => {
            tracing::debug!("Failed to open browser: {e}");
            println!("To complete registration:");
            println!();
            println!("  1. Open this URL in your browser:");
            println!("     {url}");
            println!();
            println!("  2. Sign in (if prompted) and complete the WebAuthn ceremony.");
            println!();
            println!("After registration, run `vouch keys` to verify.");
        }
    }
    Ok(())
}

/// Run the register command.
///
/// The execution order is intentional:
/// 1. Contact the server first (async, authenticated) — fail fast if
///    unreachable or unauthenticated
/// 2. All FIDO2 device work on a plain OS thread (wait, PIN, register)
/// 3. Complete registration with the server (async)
pub(crate) async fn run(server: &str, name: Option<&str>, timeout_secs: u64) -> Result<()> {
    let name = name.unwrap_or("YubiKey");
    println!("Registering additional YubiKey '{name}'...\n");

    // Pre-flight: if Chrome is running on macOS, the CTAP-HID flow will fail
    // due to Chrome's USB device claim. Route through the browser instead.
    if is_chrome_running() {
        return browser_register_fallback(server);
    }

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
            "/v1/keys/register/start",
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
    let exclude_credentials = start_resp.exclude_credential_ids.clone();
    let result = fido2::spawn_fido2(move || {
        let key = YubiKey::wait_for_device(timeout_secs)?;
        key.register(
            &rp_id,
            &rp_name,
            &challenge,
            user_id.as_bytes(),
            &user_name,
            &exclude_credentials,
        )
    })
    .await?;

    // Step 3: Complete registration with server (async, authenticated)
    print!("Completing registration... ");
    let complete_resp: RegisterCompleteResponse = client
        .post_authenticated(
            "/v1/keys/register/complete",
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
