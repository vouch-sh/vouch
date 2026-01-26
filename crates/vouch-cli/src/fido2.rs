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

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ctap_hid_fido2::FidoKeyHid;
use ctap_hid_fido2::FidoKeyHidFactory;
use ctap_hid_fido2::LibCfg;
use ctap_hid_fido2::fidokey::get_assertion::GetAssertionArgsBuilder;
use ctap_hid_fido2::fidokey::make_credential::{Attestation, MakeCredentialArgsBuilder};
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::verifier;

/// Result of FIDO2 registration (`make_credential`).
pub struct RegistrationResult {
    /// Credential ID assigned by the authenticator.
    pub credential_id: Vec<u8>,
    /// DER-encoded public key.
    pub public_key: Vec<u8>,
    /// Raw authenticator data from the attestation.
    pub attestation_object: Vec<u8>,
    /// Client data JSON.
    pub client_data_json: Vec<u8>,
}

/// Result of FIDO2 authentication (`get_assertion`).
pub struct AuthenticationResult {
    /// Credential ID used for this assertion.
    pub credential_id: Vec<u8>,
    /// Authenticator data.
    pub authenticator_data: Vec<u8>,
    /// Signature over client data hash and authenticator data.
    pub signature: Vec<u8>,
    /// Client data JSON.
    pub client_data_json: Vec<u8>,
    /// User handle (required for discoverable credentials).
    pub user_handle: Vec<u8>,
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
                return Ok(Self { device });
            }
        }
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
        let client_data_hash = sha256(&client_data_json);

        // Create user entity
        let user =
            PublicKeyCredentialUserEntity::new(Some(user_id), Some(user_name), Some(user_name));

        // Build make_credential arguments
        // Use .resident_key() to create a discoverable credential (passkey)
        let args = MakeCredentialArgsBuilder::new(rp_id, &client_data_hash)
            .user_entity(&user)
            .pin(pin)
            .resident_key()
            .build();

        // Execute make_credential
        let attestation = self
            .device
            .make_credential_with_args(&args)
            .context("FIDO2 registration failed - check your PIN and touch the YubiKey")?;

        // Verify the attestation locally
        let verify_result = verifier::verify_attestation(rp_id, &client_data_hash, &attestation);
        if !verify_result.is_success {
            bail!("attestation verification failed");
        }

        Ok(RegistrationResult {
            credential_id: verify_result.credential_id,
            public_key: verify_result.credential_public_key.der,
            attestation_object: build_attestation_object(&attestation)?,
            client_data_json,
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
        let client_data_hash = sha256(&client_data_json);

        // Build get_assertion arguments without credential_id (discoverable flow)
        let args = GetAssertionArgsBuilder::new(rp_id, &client_data_hash)
            .pin(pin)
            .build();

        // Execute get_assertion
        let assertions = self
            .device
            .get_assertion_with_args(&args)
            .context("No credentials found for this service. Have you registered?")?;

        let assertion = assertions
            .into_iter()
            .next()
            .context("no assertion returned")?;

        // Discoverable credentials must return a user handle
        if assertion.user.id.is_empty() {
            bail!("Credential is not discoverable. Please re-register with `vouch register`");
        }

        Ok(AuthenticationResult {
            credential_id: assertion.credential_id,
            authenticator_data: assertion.auth_data,
            signature: assertion.signature,
            client_data_json,
            user_handle: assertion.user.id,
        })
    }
}

/// Prompt for `YubiKey` PIN securely (no echo).
pub fn prompt_pin() -> Result<String> {
    eprint!("YubiKey PIN: ");
    rpassword::read_password().context("failed to read PIN")
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

/// Compute SHA-256 hash.
fn sha256(data: &[u8]) -> Vec<u8> {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data)
        .as_ref()
        .to_vec()
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
            credential_id: self.credential_id.clone(),
            public_key: public_key_cose,
            attestation_object,
            client_data_json,
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
            credential_id: self.credential_id.clone(),
            authenticator_data: auth_data,
            signature: signature.to_bytes().to_vec(),
            client_data_json,
            user_handle: self.user_id.clone(),
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
            credential_id: vec![],
            public_key: vec![],
            attestation_object: vec![],
            client_data_json: vec![],
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
            credential_id: vec![],
            authenticator_data: vec![],
            signature: vec![],
            client_data_json: vec![],
            user_handle: vec![],
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
