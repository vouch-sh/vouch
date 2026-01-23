//! FIDO2 device communication using ctap-hid-fido2.

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ctap_hid_fido2::FidoKeyHid;
use ctap_hid_fido2::FidoKeyHidFactory;
use ctap_hid_fido2::LibCfg;
use ctap_hid_fido2::fidokey::get_assertion::GetAssertionArgsBuilder;
use ctap_hid_fido2::fidokey::make_credential::MakeCredentialArgsBuilder;
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::verifier;
use sha2::{Digest, Sha256};

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
    /// User handle (may be empty for non-resident keys).
    pub user_handle: Option<Vec<u8>>,
}

/// Wrapper around a FIDO2 device (`YubiKey`).
pub struct YubiKey {
    device: FidoKeyHid,
}

impl YubiKey {
    /// Discover and connect to a `YubiKey`.
    ///
    /// Returns immediately if a device is found, or an error if not.
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
        let args = MakeCredentialArgsBuilder::new(rp_id, &client_data_hash)
            .user_entity(&user)
            .pin(pin)
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
            attestation_object: attestation.auth_data,
            client_data_json,
        })
    }

    /// Perform FIDO2 authentication (`get_assertion`).
    ///
    /// This proves possession of a previously registered credential.
    pub fn authenticate(
        &self,
        rp_id: &str,
        challenge: &[u8],
        credential_ids: &[Vec<u8>],
        pin: &str,
    ) -> Result<AuthenticationResult> {
        if credential_ids.is_empty() {
            bail!("no credentials provided for authentication");
        }

        // Build client data JSON (WebAuthn spec)
        let client_data = ClientData::new_get(challenge, rp_id);
        let client_data_json = client_data.to_json()?;
        let client_data_hash = sha256(&client_data_json);

        // Use the first credential ID for now
        // The ctap-hid-fido2 library wants a single credential ID
        let credential_id = credential_ids
            .first()
            .context("no credential IDs provided")?;

        // Build get_assertion arguments
        let args = GetAssertionArgsBuilder::new(rp_id, &client_data_hash)
            .pin(pin)
            .credential_id(credential_id)
            .build();

        // Execute get_assertion
        let assertions = self
            .device
            .get_assertion_with_args(&args)
            .context("FIDO2 authentication failed - check your PIN and touch the YubiKey")?;

        let assertion = assertions
            .into_iter()
            .next()
            .context("no assertion returned")?;

        // Get user handle if user ID is not empty
        let user_handle = if assertion.user.id.is_empty() {
            None
        } else {
            Some(assertion.user.id)
        };

        Ok(AuthenticationResult {
            credential_id: assertion.credential_id,
            authenticator_data: assertion.auth_data,
            signature: assertion.signature,
            client_data_json,
            user_handle,
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
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}
