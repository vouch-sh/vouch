// SPDX-License-Identifier: Apache-2.0 OR MIT
//! FIDO2 device communication.
//!
//! This module provides a trait-based abstraction over FIDO2 devices, enabling
//! integration testing without requiring physical hardware.
//!
//! # Backends
//!
//! On macOS and Linux, the [`unix`] backend uses `ctap-hid-fido2` to talk
//! directly to the YubiKey via HID. On Windows, the [`windows`] backend uses
//! the native WebAuthn API (`webauthn.dll`) — Microsoft blocks non-elevated
//! processes from accessing FIDO2 HID devices, so direct CTAP2 is not viable.
//!
//! # Threading requirements
//!
//! FIDO2 operations **must not** run on tokio runtime threads. The Unix
//! backend uses `libc::dup2` to redirect fd 1 to `/dev/null` (a process-global
//! mutation that would corrupt output from concurrent async tasks).
//!
//! Use [`spawn_fido2`] to run FIDO2 work on a plain OS thread from async code.
//! `tokio::task::spawn_blocking` is **not** sufficient because its threads
//! still have a tokio `Handle` attached, which would trip the `debug_assert!`
//! in the Unix backend's stdout suppression.
//!
//! # Testability
//!
//! The [`FidoDevice`] trait allows injecting mock implementations for testing.
//! The [`MockFidoDevice`] (behind `test-utils` feature) provides a software
//! implementation that generates real Ed25519 signatures.
//!
//! # Type Safety
//!
//! This module provides typed result types using `vouch_common::fido2_types`
//! for compile-time safety.

use crate::tr;
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use vouch_common::encoding::Raw;
use vouch_common::fido2_types::{
    AttestationObject, AuthData, ClientDataJson, CoseKey, CredentialId, Signature, UserHandle,
};

#[cfg(not(target_os = "windows"))]
mod unix;
#[cfg(not(target_os = "windows"))]
pub use unix::YubiKey;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::YubiKey;

/// Run a FIDO2 closure on a plain OS thread, returning the result to async code.
///
/// FIDO2 operations on Unix mutate the process-global stdout file descriptor.
/// Running them on a tokio runtime thread would corrupt output for all
/// concurrent tasks. This helper spawns a dedicated `std::thread` with no
/// tokio context attached, sidestepping the problem.
///
/// `tokio::task::spawn_blocking` is **not** sufficient: its threads still
/// carry a tokio `Handle`, so `Handle::try_current()` returns `Ok` and the
/// `debug_assert!` in `with_suppressed_stdout` fires.
///
/// # Cancellation (Windows only)
///
/// On Windows, this races the FIDO2 thread against `tokio::signal::ctrl_c`.
/// On Ctrl-C it calls `WebAuthNCancelCurrentOperation`, which makes the
/// in-flight WebAuthn call return `NTE_USER_CANCELLED` so the YubiKey is
/// left in a clean state before the process exits. On Unix we don't catch
/// Ctrl-C — the default SIGINT behavior (process termination) is fine since
/// `ctap-hid-fido2` doesn't have the same statefulness concern.
///
/// # Usage
///
/// All `YubiKey` operations (wait, PIN, authenticate/register) must happen
/// inside a single `spawn_fido2` call because the Unix `YubiKey` is `!Send`.
///
/// ```ignore
/// let result = spawn_fido2(move || {
///     let key = YubiKey::wait_for_device(30)?;
///     key.authenticate(&rp_id, &challenge)
/// }).await?;
/// ```
pub async fn spawn_fido2<F, R>(f: F) -> Result<R>
where
    F: FnOnce() -> Result<R> + Send + 'static,
    R: Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        // Receiver dropping (caller cancelled) is fine; nothing to do.
        let _sent = tx.send(f());
    });

    #[cfg(target_os = "windows")]
    {
        tokio::select! {
            result = rx => result.context(tr!("err-fido2-thread-panicked"))?,
            _ = tokio::signal::ctrl_c() => {
                windows::cancel_current_operation();
                anyhow::bail!(tr!("err-operation-cancelled-by-user"))
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        rx.await.context(tr!("err-fido2-thread-panicked"))?
    }
}

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

/// Trait for abstracting FIDO2 device operations.
///
/// This trait enables testing FIDO2 flows without physical hardware.
///
/// PIN handling is an implementation detail of the backend: the Unix CTAP2
/// backend prompts for the PIN internally; the Windows backend delegates to
/// the OS WebAuthn modal which collects the PIN itself; mock backends ignore
/// PINs entirely. Callers must not pass a PIN through the trait.
#[allow(
    dead_code,
    reason = "trait used by tests and feature-gated test-utils consumers; lint fires inconsistently across compilation targets"
)]
pub trait FidoDevice: Send {
    /// Perform FIDO2 registration (makeCredential).
    ///
    /// Creates a new credential on the device.
    /// `exclude_credentials` prevents duplicate registration when the device
    /// already holds one of the listed credentials.
    fn register(
        &self,
        rp_id: &str,
        rp_name: &str,
        challenge: &[u8],
        user_id: &[u8],
        user_name: &str,
        exclude_credentials: &[CredentialId<Raw>],
    ) -> Result<RegistrationResult>;

    /// Perform FIDO2 authentication (getAssertion) using discoverable credentials.
    ///
    /// Returns an assertion signed by the device.
    fn authenticate(&self, rp_id: &str, challenge: &[u8]) -> Result<AuthenticationResult>;
}

/// Client data structure for `WebAuthn`.
///
/// Shared between Unix and Windows backends and the mock device. Both
/// CTAP-level (Unix) and WebAuthn-level (Windows) APIs accept this JSON;
/// the API hashes it with SHA-256 to produce the client data hash that
/// gets signed by the authenticator.
#[derive(serde::Serialize)]
pub(crate) struct ClientData {
    #[serde(rename = "type")]
    typ: &'static str,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin")]
    cross_origin: bool,
}

impl ClientData {
    pub(crate) fn new_create(challenge: &[u8], rp_id: &str) -> Self {
        Self {
            typ: "webauthn.create",
            challenge: URL_SAFE_NO_PAD.encode(challenge),
            origin: format!("https://{rp_id}"),
            cross_origin: false,
        }
    }

    pub(crate) fn new_get(challenge: &[u8], rp_id: &str) -> Self {
        Self {
            typ: "webauthn.get",
            challenge: URL_SAFE_NO_PAD.encode(challenge),
            origin: format!("https://{rp_id}"),
            cross_origin: false,
        }
    }

    pub(crate) fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context(tr!("err-failed-serialize-client-data"))
    }
}

// ---------------------------------------------------------------------------
// MockFidoDevice — software FIDO2 device for testing.
// ---------------------------------------------------------------------------

/// Mock FIDO2 device for integration testing.
///
/// This implementation uses Ed25519 keys to generate real cryptographic
/// signatures that can be verified by the server's COSE verifier.
#[cfg(any(test, feature = "test-utils"))]
#[allow(
    dead_code,
    reason = "test/test-utils helper; lint fires inconsistently across compilation targets"
)]
fn sha256(data: &[u8]) -> Vec<u8> {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data)
        .as_ref()
        .to_vec()
}

#[cfg(feature = "test-utils")]
#[allow(
    dead_code,
    reason = "fields populated for feature-gated test-utils consumers; lint fires inconsistently"
)]
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

#[cfg(feature = "test-utils")]
#[allow(
    dead_code,
    reason = "constructors and helpers invoked by feature-gated test consumers; lint fires inconsistently"
)]
impl MockFidoDevice {
    /// Create a new mock FIDO2 device with random keys.
    ///
    /// # Panics
    ///
    /// Panics if the system RNG fails. Test-utils only.
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "test-utils mock; RNG failure is unrecoverable, panic is the right fail-fast"
    )]
    pub fn new() -> Self {
        use ed25519_dalek::SigningKey;

        let mut seed = [0u8; 32];
        aws_lc_rs::rand::fill(&mut seed).expect("system RNG failure");
        let signing_key = SigningKey::from_bytes(&seed);

        let mut credential_id = vec![0u8; 32];
        aws_lc_rs::rand::fill(&mut credential_id).expect("system RNG failure");

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

#[cfg(feature = "test-utils")]
impl Default for MockFidoDevice {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "test-utils")]
impl std::fmt::Debug for MockFidoDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockFidoDevice")
            .field("credential_id", &hex::encode(&self.credential_id))
            .field("counter", &self.counter())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "test-utils")]
impl FidoDevice for MockFidoDevice {
    fn register(
        &self,
        rp_id: &str,
        _rp_name: &str,
        challenge: &[u8],
        _user_id: &[u8],
        _user_name: &str,
        _exclude_credentials: &[CredentialId<Raw>],
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
        #[expect(
            clippy::cast_possible_truncation,
            reason = "credential_id length is bounded to ≤u16::MAX by FIDO2 attestation format"
        )]
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

    fn authenticate(&self, rp_id: &str, challenge: &[u8]) -> Result<AuthenticationResult> {
        use ed25519_dalek::Signer as _;

        // Build client data JSON
        let client_data = ClientData::new_get(challenge, rp_id);
        let client_data_json = client_data.to_json()?;
        let client_data_hash = sha256(&client_data_json);

        // Build authenticator data
        // Flags: UP (0x01) + UV (0x04) = 0x05
        let auth_data = self.build_authenticator_data(rp_id, 0x05);

        // Build signed data: authenticator_data || SHA-256(client_data_json)
        let mut signed_data = Vec::with_capacity(auth_data.len().saturating_add(32));
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
#[allow(
    dead_code,
    clippy::expect_used,
    reason = "test/test-utils helper; .expect on infallible CBOR construction; lint fires inconsistently"
)]
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
    ciborium::into_writer(&cose_key, &mut buf).expect("CBOR encoding of COSE key must succeed");
    buf
}

/// Build a "none" attestation object for testing.
#[cfg(any(test, feature = "test-utils"))]
#[allow(
    dead_code,
    reason = "test/test-utils helper; lint fires inconsistently across compilation targets"
)]
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
        .context(tr!("err-failed-encode-attestation-object"))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_spawn_fido2_runs_outside_tokio() {
        // Verify the closure runs on a thread with no tokio runtime context
        let has_runtime = spawn_fido2(|| Ok(tokio::runtime::Handle::try_current().is_ok())).await;
        assert!(matches!(has_runtime, Ok(false)));
    }

    #[tokio::test]
    async fn test_spawn_fido2_propagates_result() {
        let value = spawn_fido2(|| Ok(42u64)).await;
        assert!(matches!(value, Ok(42)));
    }

    #[tokio::test]
    async fn test_spawn_fido2_propagates_error() {
        let result = spawn_fido2(|| Err::<(), _>(anyhow::anyhow!("test error"))).await;
        assert!(result.is_err());
        let err_msg = result.err().map(|e| e.to_string());
        assert!(err_msg.as_deref().is_some_and(|s| s.contains("test error")));
    }

    #[cfg(feature = "test-utils")]
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
            &[],
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

    #[cfg(feature = "test-utils")]
    #[test]
    fn test_mock_device_authentication() {
        let device = MockFidoDevice::new();
        let challenge = [2u8; 32];

        let result = device.authenticate("example.com", &challenge);

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

    #[cfg(feature = "test-utils")]
    #[test]
    fn test_mock_device_counter_increments() {
        let device = MockFidoDevice::new();
        let challenge = [3u8; 32];

        // Counter starts at 0
        assert_eq!(device.counter(), 0);

        // First authentication increments to 1
        let _auth = device.authenticate("example.com", &challenge);
        // Counter was read as 0 and incremented to 1 during auth
        assert_eq!(device.counter(), 1);

        // Second authentication increments to 2
        let _auth = device.authenticate("example.com", &challenge);
        assert_eq!(device.counter(), 2);
    }
}
