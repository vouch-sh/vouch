// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Unix (macOS/Linux) FIDO2 backend using `ctap-hid-fido2`.
//!
//! Talks directly to the YubiKey via HID. PIN entry happens in the CLI
//! (via `rpassword`) before the CTAP2 call.

use anyhow::{Context, Result, bail};
use ctap_hid_fido2::FidoKeyHid;
use ctap_hid_fido2::FidoKeyHidFactory;
use ctap_hid_fido2::LibCfg;
use ctap_hid_fido2::fidokey::get_assertion::GetAssertionArgsBuilder;
use ctap_hid_fido2::fidokey::get_info::InfoOption;
use ctap_hid_fido2::fidokey::make_credential::{Attestation, MakeCredentialArgsBuilder};
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::verifier;
use secrecy::{ExposeSecret, SecretString};

use vouch_common::encoding::Raw;
use vouch_common::fido2_types::CredentialId;

use super::{AuthenticationResult, ClientData, FidoDevice, RegistrationResult};

// ---------------------------------------------------------------------------
// Suppress spurious stdout from ctap-hid-fido2
//
// The ctap-hid-fido2 crate uses unconditional `println!` for unknown CBOR
// members (e.g. FIPS certification extensions on YubiKey 5 FIPS). Since there
// is no config flag to disable this, we temporarily redirect fd 1 to /dev/null.
// ---------------------------------------------------------------------------

/// Guard that redirects stdout to /dev/null on creation and restores it on drop.
///
/// # Safety
///
/// Uses `libc::dup`/`dup2` to redirect file descriptor 1. This is safe as long as
/// no other thread is concurrently modifying stdout's fd. All FIDO2 calls are
/// single-threaded (synchronous HID communication).
struct SuppressStdout {
    saved_fd: std::os::unix::io::RawFd,
}

#[expect(
    unsafe_code,
    reason = "POSIX dup/dup2 for stdout suppression; safety documented inline"
)]
impl SuppressStdout {
    fn new() -> Option<Self> {
        use std::os::unix::io::AsRawFd;

        let stdout_fd = std::io::stdout().as_raw_fd();
        // SAFETY: `libc::dup` duplicates a valid file descriptor (stdout = fd 1).
        // This is safe because fd 1 is always open in a running process and `dup`
        // only reads the fd table. All FIDO2 calls are synchronous and single-threaded,
        // so no other thread is concurrently modifying stdout.
        let saved_fd = unsafe { libc::dup(stdout_fd) };
        if saved_fd < 0 {
            return None;
        }
        if let Ok(devnull) = std::fs::OpenOptions::new().write(true).open("/dev/null") {
            // SAFETY: `libc::dup2` atomically replaces stdout (fd 1) with /dev/null.
            // Both `devnull.as_raw_fd()` and `stdout_fd` are valid open descriptors.
            // The original stdout is preserved in `saved_fd` and restored on drop.
            unsafe { libc::dup2(devnull.as_raw_fd(), stdout_fd) };
            Some(Self { saved_fd })
        } else {
            // SAFETY: `saved_fd` is a valid fd returned by `dup` above. We close it
            // because we failed to open /dev/null and won't be using the guard.
            unsafe { libc::close(saved_fd) };
            None
        }
    }
}

#[expect(
    unsafe_code,
    reason = "POSIX dup2 to restore stdout on drop; safety documented inline"
)]
impl Drop for SuppressStdout {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        let stdout_fd = std::io::stdout().as_raw_fd();
        // SAFETY: Restoring stdout by dup2'ing the saved fd back onto fd 1, then
        // closing the saved copy. `self.saved_fd` was obtained from `dup(stdout_fd)`
        // in `new()` and is still valid (only used here). `stdout_fd` (fd 1) is valid
        // in any running process. Single-threaded FIDO2 context ensures no concurrent
        // fd modifications.
        unsafe {
            libc::dup2(self.saved_fd, stdout_fd);
            libc::close(self.saved_fd);
        }
    }
}

/// Run a closure with stdout suppressed (to hide ctap-hid-fido2 println noise).
///
/// # Safety invariant
///
/// Must not be called from within an async context (tokio runtime), as fd-level
/// stdout redirection would affect all concurrent tasks. FIDO2 operations are
/// synchronous HID communication and must run on a plain OS thread.
///
/// The `debug_assert!` below enforces this invariant. If it fires, the fix is to
/// wrap the calling code in [`super::spawn_fido2`] — do **not** remove the assertion.
fn with_suppressed_stdout<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    debug_assert!(
        tokio::runtime::Handle::try_current().is_err(),
        "FIDO2 operations must not be called from async contexts"
    );
    let _guard = SuppressStdout::new();
    f()
}

/// Wrapper around a FIDO2 device (`YubiKey`) on Unix.
pub struct YubiKey {
    device: FidoKeyHid,
}

/// Build a CBOR-encoded attestation object from parsed attestation fields.
///
/// The attestation object structure (per WebAuthn spec):
/// - fmt: attestation format string
/// - authData: authenticator data bytes
/// - attStmt: attestation statement map
fn build_attestation_object(attestation: &Attestation) -> Result<Vec<u8>> {
    use ciborium::Value;

    // Build attStmt map
    let mut att_stmt = Vec::new();
    att_stmt.push((
        Value::Text("alg".into()),
        Value::Integer(attestation.attstmt_alg.into()),
    ));
    att_stmt.push((
        Value::Text("sig".into()),
        Value::Bytes(attestation.attstmt_sig.clone()),
    ));

    if !attestation.attstmt_x5c.is_empty() {
        let x5c: Vec<Value> = attestation
            .attstmt_x5c
            .iter()
            .map(|cert| Value::Bytes(cert.clone()))
            .collect();
        att_stmt.push((Value::Text("x5c".into()), Value::Array(x5c)));
    }

    // Build attestation object map
    let attestation_obj = Value::Map(vec![
        (
            Value::Text("fmt".into()),
            Value::Text(attestation.fmt.clone()),
        ),
        (
            Value::Text("authData".into()),
            Value::Bytes(attestation.auth_data.clone()),
        ),
        (Value::Text("attStmt".into()), Value::Map(att_stmt)),
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&attestation_obj, &mut buf)
        .context("failed to encode attestation object")?;
    Ok(buf)
}

impl YubiKey {
    /// Wait for a `YubiKey` to be inserted, polling until one is found or timeout.
    ///
    /// Prompts the user to insert their device and polls every 500ms.
    /// A `timeout_secs` of 0 means wait indefinitely.
    pub fn wait_for_device(timeout_secs: u64) -> Result<Self> {
        use crate::{tr, tr_args, tr_println};
        use std::io::{Write, stdout};
        use std::thread;
        use std::time::{Duration, Instant};

        let cfg = LibCfg::init();

        // Try once first
        if let Ok(device) = FidoKeyHidFactory::create(&cfg) {
            return Ok(Self { device });
        }

        // Prompt user and wait
        print!("{} ", tr!("fido2-insert-prompt"));
        stdout().flush().ok();

        let start = Instant::now();
        let timeout = if timeout_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(timeout_secs))
        };

        loop {
            thread::sleep(Duration::from_millis(500));

            if let Ok(device) = FidoKeyHidFactory::create(&cfg) {
                tr_println!("fido2-detected");
                let key = Self { device };
                key.wait_until_ready()?;
                return Ok(key);
            }

            if let Some(t) = timeout
                && start.elapsed() >= t
            {
                println!();
                bail!(tr_args!("fido2-err-insert-prompt", timeout = timeout_secs));
            }
        }
    }

    /// Poll the device until it responds to commands.
    ///
    /// After USB insertion, the YubiKey needs time to initialize its CTAP HID
    /// channel. This method retries a lightweight query until the device is ready
    /// rather than using a fixed delay.
    fn wait_until_ready(&self) -> Result<()> {
        use crate::tr;
        use std::thread;
        use std::time::Duration;

        for _ in 0..10 {
            match with_suppressed_stdout(|| self.device.enable_info_option(&InfoOption::ClientPin))
            {
                Ok(_) => return Ok(()),
                Err(_) => thread::sleep(Duration::from_millis(200)),
            }
        }
        bail!(tr!("fido2-err-not-ready"))
    }

    /// Check if a PIN is configured on this `YubiKey`.
    ///
    /// Returns:
    /// - `Ok(true)` if a PIN is set
    /// - `Ok(false)` if no PIN is set (user needs to create one)
    /// - `Err` if PIN is not supported or device communication failed
    pub(crate) fn is_pin_set(&self) -> Result<bool> {
        use crate::tr;

        match with_suppressed_stdout(|| self.device.enable_info_option(&InfoOption::ClientPin))
            .with_context(|| tr!("fido2-err-pin-query"))?
        {
            Some(true) => Ok(true),
            Some(false) => Ok(false),
            None => bail!(tr!("fido2-err-pin-unsupported")),
        }
    }

    /// Set a new PIN on a `YubiKey` that doesn't have one configured.
    ///
    /// # Errors
    /// Returns an error if a PIN is already set.
    pub(crate) fn set_new_pin(&self, pin: &str) -> Result<()> {
        use crate::{tr, tr_args};

        self.device.set_new_pin(pin).map_err(|e| {
            let err_str = e.to_string();
            if err_str.contains("0x37") || err_str.contains("PIN_POLICY") {
                anyhow::anyhow!(tr!("fido2-pin-policy-block"))
            } else if err_str.contains("already set") || err_str.contains("clientPin is true") {
                anyhow::anyhow!(tr!("fido2-err-pin-already-set"))
            } else {
                anyhow::anyhow!(tr_args!(
                    "fido2-err-pin-set-failed",
                    reason = format!("{e:#}")
                ))
            }
        })
    }

    /// Perform FIDO2 registration (`make_credential`) with an explicit PIN.
    ///
    /// Internal method called from the `FidoDevice` trait impl after PIN
    /// collection.
    ///
    /// `exclude_credentials` is a list of credential IDs already registered
    /// for this user. If the `YubiKey` holds any of them, it returns
    /// `CTAP2_ERR_CREDENTIAL_EXCLUDED` (0x19) instead of creating a duplicate.
    #[expect(
        clippy::too_many_arguments,
        reason = "FIDO2 makeCredential parameters per CTAP2 spec"
    )]
    fn register_with_pin(
        &self,
        rp_id: &str,
        _rp_name: &str,
        challenge: &[u8],
        user_id: &[u8],
        user_name: &str,
        pin: &str,
        exclude_credentials: &[CredentialId<Raw>],
    ) -> Result<RegistrationResult> {
        // Build client data JSON (WebAuthn spec)
        let client_data = ClientData::new_create(challenge, rp_id);
        let client_data_json = client_data.to_json()?;

        // Create user entity
        let user =
            PublicKeyCredentialUserEntity::new(Some(user_id), Some(user_name), Some(user_name));

        // Build make_credential arguments
        // Use .resident_key() to create a discoverable credential (passkey)
        // IMPORTANT: ctap-hid-fido2 expects raw bytes and hashes them internally.
        // We pass the full client_data_json so the library computes:
        // clientDataHash = SHA256(client_data_json)
        let mut builder = MakeCredentialArgsBuilder::new(rp_id, &client_data_json)
            .user_entity(&user)
            .pin(pin)
            .resident_key();

        for cred_id in exclude_credentials {
            builder = builder.exclude_authenticator(cred_id.as_bytes());
        }

        let args = builder.build();

        // Execute make_credential
        let attestation = with_suppressed_stdout(|| self.device.make_credential_with_args(&args))
            .map_err(|e| translate_fido2_error(e, "FIDO2 registration"))?;

        // Verify the attestation locally
        let verify_result = verifier::verify_attestation(rp_id, &client_data_json, &attestation);
        if !verify_result.is_success {
            bail!(crate::tr!("fido2-err-attestation"));
        }

        Ok(RegistrationResult {
            credential_id: verify_result.credential_id.into(),
            public_key: verify_result.credential_public_key.der.into(),
            attestation_object: build_attestation_object(&attestation)?.into(),
            client_data_json: client_data_json.into(),
        })
    }

    /// Perform FIDO2 authentication with an explicit PIN.
    ///
    /// Internal method called from the `FidoDevice` trait impl after PIN
    /// collection. Uses the YubiKey's resident/discoverable credential to
    /// identify the user without needing to provide credential IDs upfront.
    fn authenticate_with_pin(
        &self,
        rp_id: &str,
        challenge: &[u8],
        pin: &str,
    ) -> Result<AuthenticationResult> {
        // Build client data JSON (WebAuthn spec)
        let client_data = ClientData::new_get(challenge, rp_id);
        let client_data_json = client_data.to_json()?;

        // IMPORTANT: ctap-hid-fido2 expects raw bytes and hashes them internally.
        // We pass the full client_data_json so the library computes:
        // clientDataHash = SHA256(client_data_json)
        // This matches what WebAuthn/browsers do.
        let args = GetAssertionArgsBuilder::new(rp_id, &client_data_json)
            .pin(pin)
            .build();

        // Execute get_assertion
        let assertions = with_suppressed_stdout(|| self.device.get_assertion_with_args(&args))
            .map_err(|e| {
                // Check if it's a "no credentials" error vs a PIN error
                let err_str = e.to_string();
                if err_str.contains("0x2E") || err_str.contains("NO_CREDENTIALS") {
                    anyhow::anyhow!(crate::tr!("fido2-err-no-credentials"))
                } else {
                    translate_fido2_error(e, "FIDO2 authentication")
                }
            })?;

        let assertion = assertions
            .into_iter()
            .next()
            .with_context(|| crate::tr!("fido2-err-no-assertion"))?;

        // Discoverable credentials must return a user handle
        if assertion.user.id.is_empty() {
            bail!(crate::tr!("fido2-err-not-passkey"));
        }

        Ok(AuthenticationResult {
            credential_id: assertion.credential_id.into(),
            authenticator_data: assertion.auth_data.into(),
            signature: assertion.signature.into(),
            client_data_json: client_data_json.into(),
            user_handle: assertion.user.id.into(),
        })
    }
}

impl FidoDevice for YubiKey {
    fn register(
        &self,
        rp_id: &str,
        rp_name: &str,
        challenge: &[u8],
        user_id: &[u8],
        user_name: &str,
        exclude_credentials: &[CredentialId<Raw>],
    ) -> Result<RegistrationResult> {
        let pin = ensure_pin_configured(self)?;
        println!("\nTouch your YubiKey...");
        self.register_with_pin(
            rp_id,
            rp_name,
            challenge,
            user_id,
            user_name,
            pin.expose_secret(),
            exclude_credentials,
        )
    }

    fn authenticate(&self, rp_id: &str, challenge: &[u8]) -> Result<AuthenticationResult> {
        let pin = ensure_pin_configured(self)?;
        println!("\nTouch your YubiKey...");
        self.authenticate_with_pin(rp_id, challenge, pin.expose_secret())
    }
}

/// Prompt for `YubiKey` PIN securely (no echo).
///
/// Returns the PIN wrapped in `SecretString` for memory protection.
fn prompt_pin() -> Result<SecretString> {
    use crate::tr;
    eprint!("{} ", tr!("fido2-pin-prompt"));
    let pin = rpassword::read_password().with_context(|| tr!("fido2-err-read-pin"))?;
    Ok(SecretString::from(pin))
}

/// Translate FIDO2/CTAP2 errors into user-friendly messages.
///
/// The ctap-hid-fido2 library returns error messages containing CTAP2 error codes.
/// This function provides more helpful guidance for common PIN-related errors.
fn translate_fido2_error(err: anyhow::Error, operation: &str) -> anyhow::Error {
    use crate::{tr, tr_args};

    let err_str = err.to_string();

    // CTAP2_ERR_CREDENTIAL_EXCLUDED: authenticator already holds a
    // credential from the exclude list for this RP.
    if err_str.contains("0x19") || err_str.contains("CREDENTIAL_EXCLUDED") {
        return anyhow::anyhow!(tr!("fido2-err-credential-excluded"));
    }

    if err_str.contains("0x31") || err_str.contains("PIN_INVALID") {
        return anyhow::anyhow!(tr!("fido2-err-pin-invalid"));
    }

    if err_str.contains("0x32") || err_str.contains("PIN_BLOCKED") {
        return anyhow::anyhow!(tr!("fido2-err-pin-blocked"));
    }

    if err_str.contains("0x33") || err_str.contains("PIN_AUTH_INVALID") {
        return anyhow::anyhow!(tr!("fido2-err-pin-auth-invalid"));
    }

    if err_str.contains("0x34") || err_str.contains("PIN_AUTH_BLOCKED") {
        return anyhow::anyhow!(tr!("fido2-err-pin-auth-blocked"));
    }

    if err_str.contains("0x35") || err_str.contains("PIN_NOT_SET") {
        return anyhow::anyhow!(tr!("fido2-err-pin-not-set"));
    }

    if err_str.contains("0x36") || err_str.contains("PIN_REQUIRED") {
        return anyhow::anyhow!(tr!("fido2-err-pin-required"));
    }

    if err_str.contains("0x37") || err_str.contains("PIN_POLICY") {
        return anyhow::anyhow!(tr!("fido2-err-pin-policy"));
    }

    if err_str.contains("0x38") || err_str.contains("PIN_TOKEN_EXPIRED") {
        return anyhow::anyhow!(tr!("fido2-err-pin-token-expired"));
    }

    // Generic fallback with the operation context
    anyhow::anyhow!(tr_args!(
        "fido2-err-generic",
        operation = operation,
        reason = format!("{err:#}")
    ))
}

/// Prompt for a new PIN with confirmation.
///
/// Validates PIN requirements:
/// - Minimum 8 characters (Vouch security requirement)
/// - Maximum 63 characters (FIDO2 limit)
///
/// Returns the PIN wrapped in `SecretString` for memory protection.
fn prompt_new_pin() -> Result<SecretString> {
    use crate::{tr, tr_eprintln};
    use std::io::{Write, stderr};

    loop {
        eprint!("{} ", tr!("fido2-pin-prompt-new"));
        stderr().flush().ok();
        let pin = rpassword::read_password().with_context(|| tr!("fido2-err-read-pin"))?;

        // Validate PIN length
        if pin.len() < 8 {
            tr_eprintln!("fido2-pin-err-too-short");
            continue;
        }
        if pin.len() > 63 {
            tr_eprintln!("fido2-pin-err-too-long");
            continue;
        }

        // Confirm PIN
        eprint!("{} ", tr!("fido2-pin-prompt-confirm"));
        stderr().flush().ok();
        let confirm =
            rpassword::read_password().with_context(|| tr!("fido2-err-read-pin-confirmation"))?;

        if pin != confirm {
            eprintln!("{}\n", tr!("fido2-pin-err-mismatch"));
            continue;
        }

        return Ok(SecretString::from(pin));
    }
}

/// Check if a PIN is set on the YubiKey, and if not, guide the user through setup.
///
/// Returns the PIN wrapped in `SecretString` (either existing or newly set).
pub(crate) fn ensure_pin_configured(key: &YubiKey) -> Result<SecretString> {
    use crate::{tr, tr_println};

    if key.is_pin_set()? {
        // PIN is already set, just prompt for it
        return prompt_pin();
    }

    // No PIN set - guide user through setup
    println!();
    tr_println!("fido2-setup-pin-intro");
    println!();

    let pin = prompt_new_pin()?;

    print!("{} ", tr!("fido2-setting-pin"));
    key.set_new_pin(pin.expose_secret())?;
    tr_println!("fido2-setting-pin-done");
    println!();

    Ok(pin)
}
