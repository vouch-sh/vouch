// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Registration command - register an additional `YubiKey` with the server.
//!
//! This command requires the user to be already authenticated (via `vouch login`).
//! For first-time enrollment, use `vouch enroll` instead.
//!
//! Like [`super::login`], the flow is structured so that async server calls and
//! synchronous FIDO2 device operations run on separate threads. See the
//! module-level docs in [`crate::fido2`] for why this separation is required.

use anyhow::{Context, Result, bail};
use vouch_common::{
    MAX_KEY_NAME_CHARS, RegisterCompleteRequest, RegisterCompleteResponse, RegisterStartRequest,
    RegisterStartResponse,
};

use crate::client::VouchClient;
use crate::exit_code::CliError;
use crate::fido2::{self, FidoDevice, YubiKey};
use vouch_cli::{tr, tr_println};

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
    tr_println!("register-chrome-blocking");
    println!();
    match open::that(&url) {
        Ok(()) => tr_println!("register-browser-block", url = url.as_str()),
        Err(e) => {
            tracing::debug!("Failed to open browser: {e}");
            tr_println!("register-manual-block", url = url.as_str());
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
    // Validate the key name (mirroring `keys::rename`) before contacting the
    // server or asking the user to insert their hardware key, so input the
    // server would refuse does not waste a round-trip or a YubiKey prompt.
    let name = name.trim();
    if name.is_empty() {
        bail!(tr!("register-err-name-empty"));
    }
    if name.chars().count() > MAX_KEY_NAME_CHARS {
        bail!(tr!("register-err-name-long"));
    }
    tr_println!("register-starting", name = name);
    println!();

    // Pre-flight: if Chrome is running on macOS, the CTAP-HID flow will fail
    // due to Chrome's USB device claim. Route through the browser instead.
    if is_chrome_running() {
        return browser_register_fallback(server);
    }

    // Step 1: Start registration with server (async, authenticated).
    // This fails fast if the server is unreachable or the user is not
    // authenticated, before they insert their key.
    print!("{} ", tr!("register-contacting-server"));
    // Only swap in the enroll/login guidance for a genuine missing-session
    // error — bad URLs, HTTP client setup failures, or config corruption
    // bubble up with their real cause instead of being mis-attributed to
    // authentication.
    let client = VouchClient::new(server).await.map_err(|err| {
        if err
            .downcast_ref::<CliError>()
            .is_some_and(|e| matches!(e, CliError::NotAuthenticated { .. }))
        {
            anyhow::anyhow!(tr!("register-not-authenticated"))
        } else {
            err
        }
    })?;
    let start_resp: RegisterStartResponse = client
        .post_authenticated(
            "/v1/keys/register/start",
            &RegisterStartRequest {
                name: name.to_string(),
            },
        )
        .await
        .context(tr!("err-failed-start-registration"))?;
    tr_println!("register-contact-ok");

    // Show info about existing keys
    if !start_resp.exclude_credential_ids.is_empty() {
        println!();
        tr_println!(
            "register-existing-keys",
            count = start_resp.exclude_credential_ids.len(),
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
    print!("{} ", tr!("register-completing"));
    let complete_resp: RegisterCompleteResponse = client
        .post_authenticated(
            "/v1/keys/register/complete",
            &RegisterCompleteRequest {
                state: start_resp.state.into(),
                credential_id: result.credential_id,
                public_key: result.public_key,
                attestation_object: result.attestation_object,
                client_data_json: result.client_data_json,
            },
        )
        .await
        .context(tr!("err-failed-complete-registration"))?;
    tr_println!("register-completed-ok");

    println!();
    tr_println!(
        "register-success-block",
        device_id = complete_resp.device_id.to_string(),
    );

    Ok(())
}
