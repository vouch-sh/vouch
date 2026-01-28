// SPDX-License-Identifier: Apache-2.0 OR MIT
//! FIDO2 device communication using ctap-hid-fido2.
//!
//! This module provides a trait-based abstraction over FIDO2 devices, enabling
//! integration testing without requiring physical hardware.
//!
//! # Testability
//!
//! The [`FidoDevice`] trait allows injecting mock implementations for testing.
//! The [`MockFidoDevice`] (behind `test-utils` feature) provides a software
//! implementation that generates real Ed25519 signatures.
//!
//! # Type Safety
//!
//! This module provides both untyped (`Vec<u8>`) result types for compatibility
//! and typed result types using `vouch_common::fido2_types` for compile-time safety.

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ctap_hid_fido2::FidoKeyHid;
use ctap_hid_fido2::FidoKeyHidFactory;
use ctap_hid_fido2::LibCfg;
use ctap_hid_fido2::fidokey::get_assertion::GetAssertionArgsBuilder;
use ctap_hid_fido2::fidokey::get_info::InfoOption;
use ctap_hid_fido2::fidokey::make_credential::{Attestation, MakeCredentialArgsBuilder};
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::verifier;

// Type-safe FIDO2 types (Phase 3)
use vouch_common::encoding::Raw;

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
#[cfg(unix)]
struct SuppressStdout {
    saved_fd: std::os::unix::io::RawFd,
}

#[cfg(unix)]
#[allow(unsafe_code)]
impl SuppressStdout {
    fn new() -> Option<Self> {
        use std::os::unix::io::AsRawFd;

        let stdout_fd = std::io::stdout().as_raw_fd();
        let saved_fd = unsafe { libc::dup(stdout_fd) };
        if saved_fd < 0 {
            return None;
        }
        if let Ok(devnull) = std::fs::OpenOptions::new().write(true).open("/dev/null") {
            unsafe { libc::dup2(devnull.as_raw_fd(), stdout_fd) };
            Some(Self { saved_fd })
        } else {
            unsafe { libc::close(saved_fd) };
            None
        }
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
impl Drop for SuppressStdout {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        let stdout_fd = std::io::stdout().as_raw_fd();
        unsafe {
            libc::dup2(self.saved_fd, stdout_fd);
            libc::close(self.saved_fd);
        }
    }
}

/// Run a closure with stdout suppressed (to hide ctap-hid-fido2 println noise).
#[cfg(unix)]
fn with_suppressed_stdout<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let _guard = SuppressStdout::new();
    f()
}

#[cfg(not(unix))]
fn with_suppressed_stdout<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}
use vouch_common::fido2_types::{
    AttestationObject, AuthData, ClientDataJson, CoseKey, CredentialId, Signature, UserHandle,
};

/// Result of FIDO2 registration (`make_credential`).
pub struct RegistrationResult {
    /// Credential ID assigned by the authenticator.
    pub credential_id: CredentialId<Raw>,
    /// COSE-encoded public key.
    pub public_key: CoseKey<Raw>,
    /// Raw attestation object.
    pub attestation_object: AttestationObject<Raw>,
    /// Client data JSON.
    pub client_data_json: ClientDataJson<Raw>,
}

/// Result of FIDO2 authentication (`get_assertion`).
pub struct AuthenticationResult {
    /// Credential ID used for this assertion.
    pub credential_id: CredentialId<Raw>,
    /// Authenticator data.
    pub authenticator_data: AuthData<Raw>,
    /// Signature over client data hash and authenticator data.
    pub signature: Signature<Raw>,
    /// Client data JSON.
    pub client_data_json: ClientDataJson<Raw>,
    /// User handle (required for discoverable credentials).
    pub user_handle: UserHandle<Raw>,
}

/// Wrapper around a FIDO2 device (`YubiKey`).
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
    /// Discover and connect to a `YubiKey`.
    ///
    /// Returns immediately if a device is found, or an error if not.
    #[allow(dead_code)]
    pub fn discover() -> Result<Self> {
        let cfg = LibCfg::init();
        let device = FidoKeyHidFactory::create(&cfg)
            .context("no YubiKey found - please insert your YubiKey")?;

        Ok(Self { device })
    }

    /// Wait for a `YubiKey` to be inserted, polling until one is found.
    ///
    /// Prompts the user to insert their device and polls every 500ms.
    pub fn wait_for_device() -> Result<Self> {
        use std::io::{Write, stdout};
        use std::thread;
        use std::time::Duration;

        let cfg = LibCfg::init();

        // Try once first
        if let Ok(device) = FidoKeyHidFactory::create(&cfg) {
            return Ok(Self { device });
        }

        // Prompt user and wait
        print!("Please insert your YubiKey... ");
        stdout().flush().ok();

        loop {
            thread::sleep(Duration::from_millis(500));

            if let Ok(device) = FidoKeyHidFactory::create(&cfg) {
                println!("detected!");
                let key = Self { device };
                key.wait_until_ready()?;
                return Ok(key);
            }
        }
    }

    /// Poll the device until it responds to commands.
    ///
    /// After USB insertion, the YubiKey needs time to initialize its CTAP HID
    /// channel. This method retries a lightweight query until the device is ready
    /// rather than using a fixed delay.
    fn wait_until_ready(&self) -> Result<()> {
        use std::thread;
        use std::time::Duration;

        for _ in 0..10 {
            match with_suppressed_stdout(|| self.device.enable_info_option(&InfoOption::ClientPin))
            {
                Ok(_) => return Ok(()),
                Err(_) => thread::sleep(Duration::from_millis(200)),
            }
        }
        bail!("YubiKey not ready after insertion - try removing and reinserting it")
    }

    /// Check if a PIN is configured on this `YubiKey`.
    ///
    /// Returns:
    /// - `Ok(true)` if a PIN is set
    /// - `Ok(false)` if no PIN is set (user needs to create one)
    /// - `Err` if PIN is not supported or device communication failed
    pub fn is_pin_set(&self) -> Result<bool> {
        match with_suppressed_stdout(|| self.device.enable_info_option(&InfoOption::ClientPin))
            .context("failed to query PIN status")?
        {
            Some(true) => Ok(true),
            Some(false) => Ok(false),
            None => bail!("This device does not support PIN authentication"),
        }
    }

    /// Get the number of PIN retry attempts remaining.
    ///
    /// Returns the count of attempts before the PIN is blocked.
    #[allow(dead_code)]
    pub fn pin_retries(&self) -> Result<i32> {
        self.device
            .get_pin_retries()
            .context("failed to get PIN retry count")
    }

    /// Set a new PIN on a `YubiKey` that doesn't have one configured.
    ///
    /// # Errors
    /// Returns an error if a PIN is already set (use `change_pin` instead).
    pub fn set_new_pin(&self, pin: &str) -> Result<()> {
        self.device.set_new_pin(pin).map_err(|e| {
            let err_str = e.to_string();
            if err_str.contains("0x37") || err_str.contains("PIN_POLICY") {
                anyhow::anyhow!(
                    "PIN does not meet requirements.\n\
                     PIN must be at least 8 characters."
                )
            } else if err_str.contains("already set") || err_str.contains("clientPin is true") {
                anyhow::anyhow!("A PIN is already set on this YubiKey.")
            } else {
                anyhow::anyhow!("Failed to set PIN: {e}")
            }
        })
    }

    /// Change the PIN on a `YubiKey`.
    #[allow(dead_code)]
    pub fn change_pin(&self, current_pin: &str, new_pin: &str) -> Result<()> {
        self.device
            .change_pin(current_pin, new_pin)
            .context("failed to change PIN")
    }

    /// Perform FIDO2 registration (`make_credential`).
    ///
    /// This creates a new credential on the `YubiKey`.
    #[allow(clippy::too_many_arguments)]
    pub fn register(
        &self,
        rp_id: &str,
        _rp_name: &str,
        challenge: &[u8],
        user_id: &[u8],
        user_name: &str,
        pin: &str,
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
        let args = MakeCredentialArgsBuilder::new(rp_id, &client_data_json)
            .user_entity(&user)
            .pin(pin)
            .resident_key()
            .build();

        // Execute make_credential
        let attestation = with_suppressed_stdout(|| self.device.make_credential_with_args(&args))
            .map_err(|e| translate_fido2_error(e, "FIDO2 registration"))?;

        // Verify the attestation locally
        let verify_result = verifier::verify_attestation(rp_id, &client_data_json, &attestation);
        if !verify_result.is_success {
            bail!("attestation verification failed");
        }

        Ok(RegistrationResult {
            credential_id: verify_result.credential_id.into(),
            public_key: verify_result.credential_public_key.der.into(),
            attestation_object: build_attestation_object(&attestation)?.into(),
            client_data_json: client_data_json.into(),
        })
    }

    /// Perform FIDO2 authentication using discoverable credentials.
    ///
    /// This uses the YubiKey's resident/discoverable credential to identify
    /// the user without needing to provide credential IDs upfront.
    pub fn authenticate(
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
                    anyhow::anyhow!(
                        "No credentials found for this service.\n\
                         Have you enrolled with `vouch enroll`?"
                    )
                } else {
                    translate_fido2_error(e, "FIDO2 authentication")
                }
            })?;

        let assertion = assertions
            .into_iter()
            .next()
            .context("no assertion returned")?;

        // Discoverable credentials must return a user handle
        if assertion.user.id.is_empty() {
            bail!("Credential is not discoverable. Please re-register with `vouch register`");
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

/// Prompt for `YubiKey` PIN securely (no echo).
pub fn prompt_pin() -> Result<String> {
    eprint!("YubiKey PIN: ");
    rpassword::read_password().context("failed to read PIN")
}

/// Translate FIDO2/CTAP2 errors into user-friendly messages.
///
/// The ctap-hid-fido2 library returns error messages containing CTAP2 error codes.
/// This function provides more helpful guidance for common PIN-related errors.
fn translate_fido2_error(err: anyhow::Error, operation: &str) -> anyhow::Error {
    let err_str = err.to_string();

    // Check for specific CTAP2 PIN errors in the error string
    if err_str.contains("0x31") || err_str.contains("PIN_INVALID") {
        return anyhow::anyhow!(
            "Incorrect PIN. Please try again.\n\
             Hint: Too many wrong attempts will lock your YubiKey."
        );
    }

    if err_str.contains("0x32") || err_str.contains("PIN_BLOCKED") {
        return anyhow::anyhow!(
            "Your YubiKey PIN is blocked due to too many incorrect attempts.\n\
             You must reset the FIDO2 application to continue:\n\
             \n\
             WARNING: This will delete all FIDO2 credentials on this YubiKey!\n\
             Run: ykman fido reset"
        );
    }

    if err_str.contains("0x33") || err_str.contains("PIN_AUTH_INVALID") {
        return anyhow::anyhow!("PIN authentication failed. Please try again.");
    }

    if err_str.contains("0x34") || err_str.contains("PIN_AUTH_BLOCKED") {
        return anyhow::anyhow!(
            "PIN authentication is temporarily blocked.\n\
             Please unplug your YubiKey and plug it back in, then try again."
        );
    }

    if err_str.contains("0x35") || err_str.contains("PIN_NOT_SET") {
        return anyhow::anyhow!(
            "Your YubiKey does not have a PIN set.\n\
             Run `vouch login` to set up a PIN."
        );
    }

    if err_str.contains("0x36") || err_str.contains("PIN_REQUIRED") {
        return anyhow::anyhow!("A PIN is required for this operation.");
    }

    if err_str.contains("0x37") || err_str.contains("PIN_POLICY") {
        return anyhow::anyhow!(
            "PIN does not meet policy requirements.\n\
             PIN must be at least 8 characters."
        );
    }

    if err_str.contains("0x38") || err_str.contains("PIN_TOKEN_EXPIRED") {
        return anyhow::anyhow!("PIN authentication expired. Please try again.");
    }

    // Generic fallback with the operation context
    anyhow::anyhow!("{operation} failed: {err}")
}

/// Prompt for a new PIN with confirmation.
///
/// Validates PIN requirements:
/// - Minimum 8 characters (Vouch security requirement)
/// - Maximum 63 characters (FIDO2 limit)
pub fn prompt_new_pin() -> Result<String> {
    use std::io::{Write, stderr};

    loop {
        eprint!("New PIN (minimum 8 characters): ");
        stderr().flush().ok();
        let pin = rpassword::read_password().context("failed to read PIN")?;

        // Validate PIN length
        if pin.len() < 8 {
            eprintln!("PIN must be at least 8 characters.");
            continue;
        }
        if pin.len() > 63 {
            eprintln!("PIN must be at most 63 characters.");
            continue;
        }

        // Confirm PIN
        eprint!("Confirm PIN: ");
        stderr().flush().ok();
        let confirm = rpassword::read_password().context("failed to read PIN confirmation")?;

        if pin != confirm {
            eprintln!("PINs do not match. Please try again.\n");
            continue;
        }

        return Ok(pin);
    }
}

/// Check if a PIN is set on the YubiKey, and if not, guide the user through setup.
///
/// Returns the PIN (either existing or newly set).
pub fn ensure_pin_configured(key: &YubiKey) -> Result<String> {
    if key.is_pin_set()? {
        // PIN is already set, just prompt for it
        return prompt_pin();
    }

    // No PIN set - guide user through setup
    println!();
    println!("Your YubiKey does not have a PIN configured.");
    println!("A PIN is required for FIDO2 authentication to prove you are present.");
    println!();
    println!("Let's set one up now.");
    println!();

    let pin = prompt_new_pin()?;

    print!("Setting PIN... ");
    key.set_new_pin(&pin)?;
    println!("done!");
    println!();

    Ok(pin)
}

/// Client data structure for `WebAuthn`.
#[derive(serde::Serialize)]
struct ClientData {
    #[serde(rename = "type")]
    typ: &'static str,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin")]
    cross_origin: bool,
}

impl ClientData {
    fn new_create(challenge: &[u8], rp_id: &str) -> Self {
        Self {
            typ: "webauthn.create",
            challenge: URL_SAFE_NO_PAD.encode(challenge),
            origin: format!("https://{rp_id}"),
            cross_origin: false,
        }
    }

    fn new_get(challenge: &[u8], rp_id: &str) -> Self {
        Self {
            typ: "webauthn.get",
            challenge: URL_SAFE_NO_PAD.encode(challenge),
            origin: format!("https://{rp_id}"),
            cross_origin: false,
        }
    }

    fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("failed to serialize client data")
    }
}

/// Trait for abstracting FIDO2 device operations.
///
/// This trait enables testing FIDO2 flows without physical hardware.
#[allow(dead_code)]
pub trait FidoDevice: Send {
    /// Perform FIDO2 registration (makeCredential).
    ///
    /// Creates a new credential on the device.
    fn register(
        &self,
        rp_id: &str,
        rp_name: &str,
        challenge: &[u8],
        user_id: &[u8],
        user_name: &str,
        pin: &str,
    ) -> Result<RegistrationResult>;

    /// Perform FIDO2 authentication (getAssertion) using discoverable credentials.
    ///
    /// Returns an assertion signed by the device.
    fn authenticate(
        &self,
        rp_id: &str,
        challenge: &[u8],
        pin: &str,
    ) -> Result<AuthenticationResult>;
}

impl FidoDevice for YubiKey {
    fn register(
        &self,
        rp_id: &str,
        rp_name: &str,
        challenge: &[u8],
        user_id: &[u8],
        user_name: &str,
        pin: &str,
    ) -> Result<RegistrationResult> {
        YubiKey::register(self, rp_id, rp_name, challenge, user_id, user_name, pin)
    }

    fn authenticate(
        &self,
        rp_id: &str,
        challenge: &[u8],
        pin: &str,
    ) -> Result<AuthenticationResult> {
        YubiKey::authenticate(self, rp_id, challenge, pin)
    }
}

/// Mock FIDO2 device for integration testing.
///
/// This implementation uses Ed25519 keys to generate real cryptographic
/// signatures that can be verified by the server's COSE verifier.
#[cfg(any(test, feature = "test-utils"))]
#[allow(dead_code)]
fn sha256(data: &[u8]) -> Vec<u8> {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data)
        .as_ref()
        .to_vec()
}

#[cfg(any(test, feature = "test-utils"))]
#[allow(dead_code)]
pub struct MockFidoDevice {
    /// The signing key (Ed25519 private key).
    signing_key: ed25519_dalek::SigningKey,
    /// The credential ID (randomly generated).
    credential_id: Vec<u8>,
    /// The user ID associated with this credential.
    user_id: Vec<u8>,
    /// Counter for replay protection.
    counter: std::sync::atomic::AtomicU32,
}

#[cfg(any(test, feature = "test-utils"))]
#[allow(dead_code)]
impl MockFidoDevice {
    /// Create a new mock FIDO2 device with random keys.
    #[must_use]
    pub fn new() -> Self {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let mut credential_id = vec![0u8; 32];
        // Generate random credential ID
        for (i, byte) in credential_id.iter_mut().enumerate() {
            *byte = (i as u8)
                .wrapping_mul(17)
                .wrapping_add(signing_key.to_bytes().get(i % 32).copied().unwrap_or(0));
        }

        Self {
            signing_key,
            credential_id,
            user_id: Vec::new(),
            counter: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Create a mock device with a specific seed for reproducible tests.
    #[must_use]
    pub fn with_seed(seed: &[u8; 32]) -> Self {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(seed);
        let credential_id = sha256(seed);

        Self {
            signing_key,
            credential_id,
            user_id: Vec::new(),
            counter: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Get the public key in COSE format (for server storage).
    #[must_use]
    pub fn public_key_cose(&self) -> Vec<u8> {
        use ed25519_dalek::VerifyingKey;

        let verifying_key: VerifyingKey = self.signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_bytes();

        // Build COSE key for Ed25519 (OKP with EdDSA)
        // COSE Key structure:
        // 1 (kty): 1 (OKP)
        // 3 (alg): -8 (EdDSA)
        // -1 (crv): 6 (Ed25519)
        // -2 (x): public key bytes
        build_cose_okp_key(&public_key_bytes)
    }

    /// Get the credential ID.
    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// Get the current counter value.
    #[must_use]
    pub fn counter(&self) -> u32 {
        self.counter.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Build authenticator data for the given RP ID.
    fn build_authenticator_data(&self, rp_id: &str, flags: u8) -> Vec<u8> {
        let counter = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let rp_id_hash = sha256(rp_id.as_bytes());
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&rp_id_hash); // 32 bytes
        auth_data.push(flags); // 1 byte
        auth_data.extend_from_slice(&counter.to_be_bytes()); // 4 bytes
        auth_data
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Default for MockFidoDevice {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl std::fmt::Debug for MockFidoDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockFidoDevice")
            .field("credential_id", &hex::encode(&self.credential_id))
            .field("counter", &self.counter())
            .finish_non_exhaustive()
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl FidoDevice for MockFidoDevice {
    fn register(
        &self,
        rp_id: &str,
        _rp_name: &str,
        challenge: &[u8],
        _user_id: &[u8],
        _user_name: &str,
        _pin: &str,
    ) -> Result<RegistrationResult> {
        // Build client data JSON
        let client_data = ClientData::new_create(challenge, rp_id);
        let client_data_json = client_data.to_json()?;

        // Build authenticator data with attested credential data
        // Flags: UP (0x01) + UV (0x04) + AT (0x40) = 0x45
        let flags = 0x45u8;
        let rp_id_hash = sha256(rp_id.as_bytes());
        let counter = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let public_key_cose = self.public_key_cose();

        // Build attested credential data
        // AAGUID (16 bytes) + credential ID length (2 bytes) + credential ID + public key
        let aaguid = [0u8; 16]; // Zeros for mock device
        #[allow(clippy::cast_possible_truncation)]
        let cred_id_len = (self.credential_id.len() as u16).to_be_bytes();

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash); // 32 bytes
        auth_data.push(flags); // 1 byte
        auth_data.extend_from_slice(&counter.to_be_bytes()); // 4 bytes
        auth_data.extend_from_slice(&aaguid); // 16 bytes
        auth_data.extend_from_slice(&cred_id_len); // 2 bytes
        auth_data.extend_from_slice(&self.credential_id);
        auth_data.extend_from_slice(&public_key_cose);

        // Build attestation object
        // For testing, use "none" attestation format
        let attestation_object = build_none_attestation_object(&auth_data)?;

        Ok(RegistrationResult {
            credential_id: self.credential_id.clone().into(),
            public_key: public_key_cose.into(),
            attestation_object: attestation_object.into(),
            client_data_json: client_data_json.into(),
        })
    }

    fn authenticate(
        &self,
        rp_id: &str,
        challenge: &[u8],
        _pin: &str,
    ) -> Result<AuthenticationResult> {
        use ed25519_dalek::Signer as _;

        // Build client data JSON
        let client_data = ClientData::new_get(challenge, rp_id);
        let client_data_json = client_data.to_json()?;
        let client_data_hash = sha256(&client_data_json);

        // Build authenticator data
        // Flags: UP (0x01) + UV (0x04) = 0x05
        let auth_data = self.build_authenticator_data(rp_id, 0x05);

        // Build signed data: authenticator_data || SHA-256(client_data_json)
        let mut signed_data = Vec::with_capacity(auth_data.len() + 32);
        signed_data.extend_from_slice(&auth_data);
        signed_data.extend_from_slice(&client_data_hash);

        // Sign with Ed25519
        let signature = self.signing_key.sign(&signed_data);

        Ok(AuthenticationResult {
            credential_id: self.credential_id.clone().into(),
            authenticator_data: auth_data.into(),
            signature: signature.to_bytes().to_vec().into(),
            client_data_json: client_data_json.into(),
            user_handle: self.user_id.clone().into(),
        })
    }
}

/// Build a COSE OKP (Octet Key Pair) key for Ed25519.
#[cfg(any(test, feature = "test-utils"))]
#[allow(dead_code)]
fn build_cose_okp_key(public_key: &[u8; 32]) -> Vec<u8> {
    use ciborium::Value;

    let cose_key = Value::Map(vec![
        // kty: 1 (OKP)
        (Value::Integer(1.into()), Value::Integer(1.into())),
        // alg: -8 (EdDSA)
        (Value::Integer(3.into()), Value::Integer((-8).into())),
        // crv: 6 (Ed25519)
        (Value::Integer((-1).into()), Value::Integer(6.into())),
        // x: public key
        (
            Value::Integer((-2).into()),
            Value::Bytes(public_key.to_vec()),
        ),
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&cose_key, &mut buf).unwrap_or_default();
    buf
}

/// Build a "none" attestation object for testing.
#[cfg(any(test, feature = "test-utils"))]
#[allow(dead_code)]
fn build_none_attestation_object(auth_data: &[u8]) -> Result<Vec<u8>> {
    use ciborium::Value;

    let attestation_obj = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (
            Value::Text("authData".into()),
            Value::Bytes(auth_data.to_vec()),
        ),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&attestation_obj, &mut buf)
        .context("failed to encode attestation object")?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_device_registration() {
        let device = MockFidoDevice::new();
        let challenge = [1u8; 32];

        let result = device.register(
            "example.com",
            "Example",
            &challenge,
            b"user123",
            "test@example.com",
            "1234",
        );

        assert!(result.is_ok());
        let reg = result.ok();
        assert!(reg.is_some());
        let reg = reg.unwrap_or_else(|| RegistrationResult {
            credential_id: vec![].into(),
            public_key: vec![].into(),
            attestation_object: vec![].into(),
            client_data_json: vec![].into(),
        });
        assert!(!reg.credential_id.is_empty());
        assert!(!reg.public_key.is_empty());
        assert!(!reg.attestation_object.is_empty());
    }

    #[test]
    fn test_mock_device_authentication() {
        let device = MockFidoDevice::new();
        let challenge = [2u8; 32];

        let result = device.authenticate("example.com", &challenge, "1234");

        assert!(result.is_ok());
        let auth = result.ok();
        assert!(auth.is_some());
        let auth = auth.unwrap_or_else(|| AuthenticationResult {
            credential_id: vec![].into(),
            authenticator_data: vec![].into(),
            signature: vec![].into(),
            client_data_json: vec![].into(),
            user_handle: vec![].into(),
        });
        assert!(!auth.credential_id.is_empty());
        assert_eq!(auth.authenticator_data.len(), 37); // 32 + 1 + 4
        assert_eq!(auth.signature.len(), 64); // Ed25519 signature
    }

    #[test]
    fn test_mock_device_counter_increments() {
        let device = MockFidoDevice::new();
        let challenge = [3u8; 32];

        // Counter starts at 0
        assert_eq!(device.counter(), 0);

        // First authentication increments to 1
        let _ = device.authenticate("example.com", &challenge, "1234");
        // Counter was read as 0 and incremented to 1 during auth
        assert_eq!(device.counter(), 1);

        // Second authentication increments to 2
        let _ = device.authenticate("example.com", &challenge, "1234");
        assert_eq!(device.counter(), 2);
    }
}
