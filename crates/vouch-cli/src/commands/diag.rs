// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Diagnostic command for testing YubiKey registration and authentication flow.
//!
//! This bypasses the server and webauthn-rs entirely to test if the YubiKey
//! and signature verification work correctly together.

// This is a diagnostic/debug command that intentionally does low-level byte manipulation
// and uses direct indexing for parsing binary data structures. The lints below are
// suppressed because this is debugging code, not production code.
#![expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::needless_borrows_for_generic_args,
    reason = "debugging command for diagnostics output, not production code paths"
)]

use anyhow::{Context, Result, bail};
use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Args;
use ctap_hid_fido2::FidoKeyHid;
use ctap_hid_fido2::FidoKeyHidFactory;
use ctap_hid_fido2::LibCfg;
use ctap_hid_fido2::fidokey::get_assertion::GetAssertionArgsBuilder;
use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Assertion;
use ctap_hid_fido2::fidokey::make_credential::{Attestation, MakeCredentialArgsBuilder};
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::verifier;
use ctap_hid_fido2::verifier::AttestationVerifyResult;
use std::path::PathBuf;
use vouch_cli::{tr, tr_args};
use vouch_common::fixtures::{
    AuthenticationFixture, Fido2Fixture, FixtureMetadata, RegistrationFixture,
};

/// Test relying party ID used for the local diagnostic flow.
const RP_ID: &str = "diag.test.local";

/// Print a progress line. When JSON mode is active, use stderr so stdout
/// stays clean JSON.
macro_rules! out {
    ($json:expr, $($arg:tt)*) => {
        if $json {
            eprintln!($($arg)*);
        } else {
            println!($($arg)*);
        }
    };
}
/// Like [`out!`] but without a trailing newline.
macro_rules! out_print {
    ($json:expr, $($arg:tt)*) => {
        if $json {
            eprint!($($arg)*);
        } else {
            print!($($arg)*);
        }
    };
}

/// Arguments for the diag command.
#[derive(Args)]
pub(crate) struct DiagArgs {
    /// Export fixture data to a JSON file for use in tests.
    #[arg(long, value_name = "FILE")]
    pub export_fixture: Option<PathBuf>,
    /// Output results as JSON.
    #[arg(long)]
    pub json: bool,
}

/// JSON representation of diagnostic results.
#[derive(serde::Serialize)]
struct DiagJson {
    registration_success: bool,
    authentication_success: bool,
    library_verification: bool,
    aws_lc_verification: bool,
    credential_id: String,
    public_key_hex: String,
    aaguid: Option<String>,
    device_model: Option<String>,
}

/// Everything captured during the registration phase.
struct Registration {
    challenge: [u8; 32],
    client_data_json: Vec<u8>,
    attestation: Attestation,
    verify_result: AttestationVerifyResult,
    /// Raw COSE key bytes from the attested credential data.
    cose_key: Vec<u8>,
    /// P-256 public key x coordinate (32 bytes).
    x: Vec<u8>,
    /// P-256 public key y coordinate (32 bytes).
    y: Vec<u8>,
}

/// Everything captured during the authentication phase.
struct Authentication {
    challenge: [u8; 32],
    client_data_json: Vec<u8>,
    assertion: Assertion,
}

/// Outcome of the signature verification phase.
struct Verification {
    lib_result: bool,
    aws_lc_result: bool,
    /// Signed message: authenticator_data || SHA256(raw_challenge).
    message: Vec<u8>,
    /// SEC1 uncompressed public key point (0x04 || x || y).
    point: Vec<u8>,
}

/// Run diagnostic test of YubiKey registration + authentication + verification.
pub(crate) fn run(args: DiagArgs) -> Result<()> {
    let json = args.json;

    out!(json, "{}", tr!("diag-intro-block"));
    out!(json, "");

    let (device, pin) = wait_for_device_and_pin(json)?;

    let reg = run_registration(json, &device, &pin)?;
    let auth = run_authentication(json, &device, &pin, &reg.verify_result.credential_id)?;
    let verification = verify_signatures(json, &reg, &auth);

    print_report(json, &reg, &auth, &verification);

    // JSON output
    if json {
        let diag_json = build_diag_json(&reg, &verification);
        println!("{}", serde_json::to_string_pretty(&diag_json)?);
    }

    // Export fixture if requested
    if let Some(ref path) = args.export_fixture {
        export_fixture(json, path, &reg, &auth)?;
    }

    Ok(())
}

/// Wait for a YubiKey to be inserted and prompt for its PIN.
fn wait_for_device_and_pin(json: bool) -> Result<(FidoKeyHid, String)> {
    out_print!(json, "{} ", tr!("diag-insert-prompt"));
    if json {
        std::io::Write::flush(&mut std::io::stderr()).ok();
    } else {
        std::io::Write::flush(&mut std::io::stdout()).ok();
    }

    let cfg = LibCfg::init();
    let device = loop {
        if let Ok(dev) = FidoKeyHidFactory::create(&cfg) {
            out!(json, "{}", tr!("diag-detected"));
            break dev;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    };

    out!(json, "");
    eprint!("{} ", tr!("diag-pin-prompt"));
    let pin = rpassword::read_password().context("failed to read PIN")?;
    // Note: In diag mode, we keep this as a plain String for simplicity since
    // this is a debugging tool that immediately uses and discards the PIN.
    // In production code (fido2.rs), we use SecretString.

    Ok((device, pin))
}

/// Register a new (non-resident) credential, verify the attestation, and
/// extract the P-256 public key coordinates from the COSE key.
fn run_registration(json: bool, device: &FidoKeyHid, pin: &str) -> Result<Registration> {
    let user_id = b"diag-test-user";
    let user_name = "diag@test.local";

    // Generate challenge for registration
    let challenge: [u8; 32] = rand::random();

    // Build client data for registration
    let client_data = serde_json::json!({
        "type": "webauthn.create",
        "challenge": URL_SAFE_NO_PAD.encode(&challenge),
        "origin": format!("https://{}", RP_ID),
        "crossOrigin": false
    });
    let client_data_json = serde_json::to_vec(&client_data)?;
    let client_data_hash = digest(&SHA256, &client_data_json);

    out!(json, "");
    out!(json, "{}", tr!("diag-registration-header"));
    out!(json, "RP ID: {}", RP_ID);
    out!(json, "Challenge: {}", hex::encode(&challenge));
    out!(
        json,
        "Client data hash: {}",
        hex::encode(client_data_hash.as_ref())
    );

    // Create user entity
    let user = PublicKeyCredentialUserEntity::new(Some(user_id), Some(user_name), Some(user_name));

    // Build make_credential arguments WITHOUT resident key (server-side credential)
    // IMPORTANT: The library expects RAW challenge bytes, not a pre-hashed clientDataHash!
    // The library handles clientDataJSON construction and hashing internally.
    let make_cred_args = MakeCredentialArgsBuilder::new(RP_ID, &challenge)
        .user_entity(&user)
        .pin(pin)
        // NOT using .resident_key() - credential ID stored server-side
        .build();

    out!(json, "");
    out!(json, "{}", tr!("diag-touch-register"));
    let attestation = device
        .make_credential_with_args(&make_cred_args)
        .with_context(|| tr!("diag-err-registration"))?;

    // Verify attestation locally - pass raw challenge, library hashes internally
    let verify_result = verifier::verify_attestation(RP_ID, &challenge, &attestation);
    if !verify_result.is_success {
        bail!(tr!("diag-err-attestation"));
    }

    out!(json, "{}", tr!("diag-registration-success"));
    out!(
        json,
        "Credential ID: {} ({} bytes)",
        hex::encode(&verify_result.credential_id),
        verify_result.credential_id.len()
    );

    // Extract public key from ctap-hid-fido2's verification result
    // The .der field contains the SubjectPublicKeyInfo (SPKI) format
    let public_key_der = &verify_result.credential_public_key.der;
    out!(
        json,
        "Public key DER: {} ({} bytes)",
        hex::encode(public_key_der),
        public_key_der.len()
    );

    // Extract x and y from the COSE key in auth_data
    // auth_data structure: rp_id_hash(32) + flags(1) + counter(4) + aaguid(16) + cred_id_len(2) + cred_id(N) + cose_key
    let auth_data = &attestation.auth_data;
    out!(
        json,
        "Auth data: {} ({} bytes)",
        hex::encode(auth_data),
        auth_data.len()
    );

    let flags = auth_data[32];
    out!(json, "Flags: {:#04x}", flags);

    if flags & 0x40 == 0 {
        bail!(tr!("diag-err-no-attested-data"));
    }

    let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let cose_key_start = 55_usize.saturating_add(cred_id_len);
    let cose_key = auth_data[cose_key_start..].to_vec();

    out!(
        json,
        "COSE key bytes: {} ({} bytes)",
        hex::encode(&cose_key),
        cose_key.len()
    );

    // Parse COSE key to extract x and y
    let cose_val: ciborium::Value =
        ciborium::from_reader(cose_key.as_slice()).with_context(|| tr!("diag-err-cose-parse"))?;

    let cose_map = cose_val
        .as_map()
        .with_context(|| tr!("diag-err-cose-not-map"))?;

    let mut x: Option<Vec<u8>> = None;
    let mut y: Option<Vec<u8>> = None;
    let mut kty: Option<i64> = None;
    let mut alg: Option<i64> = None;

    for (k, v) in cose_map {
        if let Some(key_int) = k.as_integer() {
            let key_i64: i64 = key_int.try_into().unwrap_or(0);
            match key_i64 {
                1 => kty = v.as_integer().and_then(|i| i.try_into().ok()),
                3 => alg = v.as_integer().and_then(|i| i.try_into().ok()),
                -2 => x = v.as_bytes().cloned(),
                -3 => y = v.as_bytes().cloned(),
                _ => {}
            }
        }
    }

    out!(json, "\nCOSE key parsed:");
    out!(json, "  kty: {:?} (should be 2 for EC2)", kty);
    out!(json, "  alg: {:?} (should be -7 for ES256)", alg);

    let x = x.with_context(|| tr!("diag-err-missing-x"))?;
    let y = y.with_context(|| tr!("diag-err-missing-y"))?;

    out!(json, "  x ({} bytes): {}", x.len(), hex::encode(&x));
    out!(json, "  y ({} bytes): {}", y.len(), hex::encode(&y));

    if x.len() != 32 || y.len() != 32 {
        bail!(tr_args!(
            "diag-err-coord-length",
            x_len = x.len(),
            y_len = y.len(),
        ));
    }

    Ok(Registration {
        challenge,
        client_data_json,
        attestation,
        verify_result,
        cose_key,
        x,
        y,
    })
}

/// Authenticate with the registered credential and check the assertion's
/// rpid_hash against the expected value.
fn run_authentication(
    json: bool,
    device: &FidoKeyHid,
    pin: &str,
    credential_id: &[u8],
) -> Result<Authentication> {
    out!(json, "");
    out!(json, "{}", tr!("diag-authentication-header"));

    let challenge: [u8; 32] = rand::random();

    // Build client data for authentication
    let client_data = serde_json::json!({
        "type": "webauthn.get",
        "challenge": URL_SAFE_NO_PAD.encode(&challenge),
        "origin": format!("https://{}", RP_ID),
        "crossOrigin": false
    });
    let client_data_json = serde_json::to_vec(&client_data)?;
    let client_data_hash = digest(&SHA256, &client_data_json);

    out!(json, "Challenge: {}", hex::encode(&challenge));
    out!(
        json,
        "Client data hash: {}",
        hex::encode(client_data_hash.as_ref())
    );

    // Build get_assertion arguments with explicit credential ID (non-discoverable flow)
    // IMPORTANT: Pass raw challenge, not pre-hashed clientDataHash!
    let get_assertion_args = GetAssertionArgsBuilder::new(RP_ID, &challenge)
        .pin(pin)
        .add_credential_id(credential_id) // Explicitly specify which credential
        .build();

    out!(json, "");
    out!(json, "{}", tr!("diag-touch-authenticate"));
    let assertions = device
        .get_assertion_with_args(&get_assertion_args)
        .with_context(|| tr!("diag-err-authentication"))?;

    let assertion = assertions
        .into_iter()
        .next()
        .with_context(|| tr!("diag-err-no-assertion"))?;

    out!(json, "{}", tr!("diag-authentication-success"));
    out!(
        json,
        "Credential ID: {} ({} bytes)",
        hex::encode(&assertion.credential_id),
        assertion.credential_id.len()
    );
    out!(
        json,
        "Authenticator data: {} ({} bytes)",
        hex::encode(&assertion.auth_data),
        assertion.auth_data.len()
    );
    out!(
        json,
        "Signature: {} ({} bytes)",
        hex::encode(&assertion.signature),
        assertion.signature.len()
    );

    // Debug: Check the rpid_hash from the assertion
    out!(json, "");
    out!(json, "{}", tr!("diag-rpid-header"));
    let expected_rpid_hash = digest(&SHA256, RP_ID.as_bytes());
    out!(
        json,
        "Expected rpid_hash: {}",
        hex::encode(expected_rpid_hash.as_ref())
    );
    out!(
        json,
        "Assertion rpid_hash: {}",
        hex::encode(&assertion.rpid_hash)
    );
    if expected_rpid_hash.as_ref() == assertion.rpid_hash.as_slice() {
        out!(json, "{}", tr!("diag-rpid-match"));
    } else {
        out!(json, "{}", tr!("diag-rpid-mismatch"));
    }

    Ok(Authentication {
        challenge,
        client_data_json,
        assertion,
    })
}

/// Verify the assertion signature two ways — via the ctap-hid-fido2 library
/// and directly with aws-lc-rs — and dump the DER signature's r/s values.
#[expect(
    clippy::too_many_lines,
    reason = "diagnostic dump of every signature-verification path"
)]
fn verify_signatures(json: bool, reg: &Registration, auth: &Authentication) -> Verification {
    let assertion = &auth.assertion;

    // First, use the library's verify_assertion function
    out!(json, "");
    out!(json, "{}", tr!("diag-lib-verification-header"));

    // The library's verify_assertion expects raw challenge bytes (not clientDataJSON or hash)
    // It constructs clientDataJSON internally and hashes it
    let lib_result = verifier::verify_assertion(
        RP_ID,
        &reg.verify_result.credential_public_key,
        &auth.challenge, // raw challenge bytes, library handles the rest
        assertion,
    );

    if lib_result {
        out!(json, "{}", tr!("diag-lib-verification-passed"));
    } else {
        out!(json, "{}", tr!("diag-lib-verification-failed"));

        // Debug: Show what the library would compute
        // The library hashes the RAW challenge directly, not a clientDataJSON
        let lib_client_data_hash = digest(&SHA256, &auth.challenge);
        out!(json, "\nDebug - Library computes:");
        out!(
            json,
            "  SHA256(raw_challenge) = {}",
            hex::encode(lib_client_data_hash.as_ref())
        );

        // Show the exact message the library would use
        let mut lib_message = Vec::new();
        lib_message.extend_from_slice(&assertion.auth_data);
        lib_message.extend_from_slice(lib_client_data_hash.as_ref());
        out!(json, "\n  Library would verify message:");
        out!(
            json,
            "    auth_data ({} bytes) + SHA256(challenge) ({} bytes) = {} bytes",
            assertion.auth_data.len(),
            lib_client_data_hash.as_ref().len(),
            lib_message.len()
        );
        out!(json, "    message = {}", hex::encode(&lib_message));
    }

    // Now verify the signature ourselves
    out!(json, "");
    out!(json, "{}", tr!("diag-aws-lc-header"));

    // Build the message: authenticator_data || SHA256(raw_challenge)
    // The library uses SHA256(challenge) directly, not SHA256(clientDataJSON)
    let challenge_hash = digest(&SHA256, &auth.challenge);
    let mut message = Vec::with_capacity(assertion.auth_data.len().saturating_add(32));
    message.extend_from_slice(&assertion.auth_data);
    message.extend_from_slice(challenge_hash.as_ref());

    out!(
        json,
        "Message: {} ({} bytes)",
        hex::encode(&message),
        message.len()
    );

    // Build SEC1 uncompressed point: 0x04 || x || y
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&reg.x);
    point.extend_from_slice(&reg.y);

    out!(
        json,
        "Public key point: {} ({} bytes)",
        hex::encode(&point),
        point.len()
    );

    // Also show the library's public key for comparison
    let library_key = &reg.verify_result.credential_public_key.der;
    out!(
        json,
        "Library public key: {} ({} bytes)",
        hex::encode(library_key),
        library_key.len()
    );

    // Explicit byte-by-byte comparison
    if point == *library_key {
        out!(json, "{}", tr!("diag-keys-identical"));
    } else {
        out!(json, "{}", tr!("diag-keys-differ"));
        out!(json, "  Our point len: {}", point.len());
        out!(json, "  Library len: {}", library_key.len());
        for (i, (a, b)) in point.iter().zip(library_key.iter()).enumerate() {
            if a != b {
                out!(
                    json,
                    "  First diff at byte {}: ours=0x{:02x}, lib=0x{:02x}",
                    i,
                    a,
                    b
                );
                break;
            }
        }
        if point.len() != library_key.len() {
            out!(json, "  Length mismatch!");
        }
    }

    // Verify with aws-lc-rs using our extracted point
    let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &point);

    let aws_lc_result = public_key.verify(&message, &assertion.signature).is_ok();
    out!(json, "");
    if aws_lc_result {
        out!(
            json,
            "{}",
            tr_args!("diag-aws-lc-passed", kind = "our point")
        );
    } else {
        out!(
            json,
            "{}",
            tr_args!("diag-aws-lc-failed", kind = "our point")
        );
    }

    // Also verify using the library's extracted public key directly
    let public_key_lib = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, library_key);

    match public_key_lib.verify(&message, &assertion.signature) {
        Ok(()) => {
            out!(
                json,
                "{}",
                tr_args!("diag-aws-lc-passed", kind = "library key")
            );
        }
        Err(e) => {
            out!(
                json,
                "{}",
                tr_args!(
                    "diag-aws-lc-failed-reason",
                    kind = "library key",
                    reason = format!("{e:?}"),
                ),
            );
        }
    }

    // Additional debug: Parse the DER signature to see r and s values
    out!(json, "");
    out!(json, "{}", tr!("diag-sig-header"));
    let sig = &assertion.signature;
    if sig.len() >= 2 && sig[0] == 0x30 {
        let seq_len = sig[1] as usize;
        out!(json, "DER SEQUENCE length: {}", seq_len);
        if sig.len() >= 4 && sig[2] == 0x02 {
            let r_len = sig[3] as usize;
            let r_start = 4_usize;
            let r_end = r_start.saturating_add(r_len);
            if sig.len() >= r_end {
                out!(
                    json,
                    "r ({} bytes): {}",
                    r_len,
                    hex::encode(&sig[r_start..r_end])
                );
                if sig.len() > r_end.saturating_add(1) && sig[r_end] == 0x02 {
                    let s_len = sig[r_end.saturating_add(1)] as usize;
                    let s_start = r_end.saturating_add(2);
                    let s_end = s_start.saturating_add(s_len);
                    if sig.len() >= s_end {
                        out!(
                            json,
                            "s ({} bytes): {}",
                            s_len,
                            hex::encode(&sig[s_start..s_end])
                        );
                    }
                }
            }
        }
    }

    Verification {
        lib_result,
        aws_lc_result,
        message,
        point,
    }
}

/// Print the credential-ID consistency check, summary, and manual OpenSSL
/// verification commands.
fn print_report(
    json: bool,
    reg: &Registration,
    auth: &Authentication,
    verification: &Verification,
) {
    // Check if credential IDs match between registration and authentication
    out!(json, "");
    out!(json, "{}", tr!("diag-cred-id-header"));
    out!(
        json,
        "Registration cred_id: {}",
        hex::encode(&reg.verify_result.credential_id)
    );
    out!(
        json,
        "Assertion cred_id:    {}",
        hex::encode(&auth.assertion.credential_id)
    );
    if reg.verify_result.credential_id == auth.assertion.credential_id {
        out!(json, "{}", tr!("diag-cred-id-match"));
    } else {
        out!(json, "{}", tr!("diag-cred-id-mismatch"));
    }

    out!(json, "");
    out!(json, "{}", tr!("diag-summary-header"));
    if verification.lib_result {
        out!(json, "{}", tr!("diag-summary-lib-ok"));
    } else {
        out!(json, "{}", tr!("diag-summary-lib-fail"));
    }

    // Output data for manual OpenSSL verification
    out!(json, "");
    out!(json, "{}", tr!("diag-openssl-header"));
    out!(json, "");
    out!(json, "# Create public key PEM file");
    out!(json, "echo '-----BEGIN PUBLIC KEY-----' > /tmp/pubkey.pem");

    // Build SubjectPublicKeyInfo DER format
    // SEQUENCE { SEQUENCE { OID ecPublicKey, OID secp256r1 }, BIT STRING point }
    let mut spki = Vec::new();
    // Fixed header for P-256 public key
    spki.extend_from_slice(&[
        0x30, 0x59, // SEQUENCE, 89 bytes
        0x30, 0x13, // SEQUENCE, 19 bytes
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, // OID 1.2.840.10045.2.1 (ecPublicKey)
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
        0x07, // OID 1.2.840.10045.3.1.7 (secp256r1)
        0x03, 0x42, 0x00, // BIT STRING, 66 bytes, 0 unused bits
    ]);
    spki.extend_from_slice(&verification.point);

    use base64::engine::general_purpose::STANDARD;
    let spki_b64 = STANDARD.encode(&spki);
    // Split into 64-char lines
    for chunk in spki_b64.as_bytes().chunks(64) {
        out!(
            json,
            "echo '{}' >> /tmp/pubkey.pem",
            std::str::from_utf8(chunk).unwrap()
        );
    }
    out!(json, "echo '-----END PUBLIC KEY-----' >> /tmp/pubkey.pem");
    out!(json, "");

    out!(
        json,
        "# Create message file (auth_data || client_data_hash)"
    );
    out!(
        json,
        "echo -n '{}' | xxd -r -p > /tmp/message.bin",
        hex::encode(&verification.message)
    );
    out!(json, "");

    out!(json, "# Create signature file (DER format)");
    out!(
        json,
        "echo -n '{}' | xxd -r -p > /tmp/signature.der",
        hex::encode(&auth.assertion.signature)
    );
    out!(json, "");

    out!(json, "# Verify with OpenSSL");
    out!(
        json,
        "openssl dgst -sha256 -verify /tmp/pubkey.pem -signature /tmp/signature.der /tmp/message.bin"
    );

    // Note: This test now uses non-resident credentials (no cleanup needed)
    out!(json, "");
    out!(json, "{}", tr!("diag-no-cleanup"));
}

/// Extract the AAGUID (hex) from registration auth_data, if attested
/// credential data is present.
fn extract_aaguid(reg: &Registration) -> Option<String> {
    // AAGUID lives at bytes 37-52 when the AT flag (0x40) is set
    let auth_data = &reg.attestation.auth_data;
    if auth_data.len() >= 53 && auth_data[32] & 0x40 != 0 {
        Some(hex::encode(&auth_data[37..53]))
    } else {
        None
    }
}

/// Build the JSON result summary.
fn build_diag_json(reg: &Registration, verification: &Verification) -> DiagJson {
    let aaguid = extract_aaguid(reg);
    let device_model = aaguid
        .as_ref()
        .and_then(|aaguid_hex| vouch_common::lookup_device_model(aaguid_hex).map(String::from));
    DiagJson {
        // Both phases bail on failure, so reaching the report means success.
        registration_success: true,
        authentication_success: true,
        library_verification: verification.lib_result,
        aws_lc_verification: verification.aws_lc_result,
        credential_id: hex::encode(&reg.verify_result.credential_id),
        public_key_hex: hex::encode(&reg.verify_result.credential_public_key.der),
        aaguid,
        device_model,
    }
}

/// Save the captured registration/authentication data as a test fixture.
fn export_fixture(
    json: bool,
    path: &std::path::Path,
    reg: &Registration,
    auth: &Authentication,
) -> Result<()> {
    out!(json, "");
    out!(json, "{}", tr!("diag-export-header"));

    let aaguid = extract_aaguid(reg);
    let device_model = aaguid
        .as_ref()
        .and_then(|aaguid_hex| vouch_common::lookup_device_model(aaguid_hex).map(String::from));

    let fixture = Fido2Fixture {
        metadata: FixtureMetadata {
            description: "YubiKey diagnostic test fixture".to_string(),
            device_model,
            aaguid,
            created_at: jiff::Zoned::now().to_string(),
            rp_id: RP_ID.to_string(),
        },
        registration: RegistrationFixture {
            challenge_hex: hex::encode(&reg.challenge),
            client_data_json: String::from_utf8_lossy(&reg.client_data_json).to_string(),
            credential_id_hex: hex::encode(&reg.verify_result.credential_id),
            public_key_cose_hex: hex::encode(&reg.cose_key),
            auth_data_hex: hex::encode(&reg.attestation.auth_data),
            attestation_object_hex: None, // Not capturing full attestation object
            x_hex: hex::encode(&reg.x),
            y_hex: hex::encode(&reg.y),
        },
        authentication: AuthenticationFixture {
            challenge_hex: hex::encode(&auth.challenge),
            client_data_json: String::from_utf8_lossy(&auth.client_data_json).to_string(),
            auth_data_hex: hex::encode(&auth.assertion.auth_data),
            signature_hex: hex::encode(&auth.assertion.signature),
            user_handle_hex: None, // Non-resident credential doesn't have user_handle
        },
    };

    fixture
        .save_to_file(path)
        .map_err(|e| anyhow::anyhow!(tr_args!("diag-err-fixture-save", reason = e)))?;
    out!(
        json,
        "{}",
        tr_args!("diag-fixture-saved", path = path.display())
    );

    Ok(())
}

// Re-use rand for challenge generation
mod rand {
    pub(super) fn random<T: Default + AsMut<[u8]>>() -> T {
        let mut val = T::default();
        aws_lc_rs::rand::fill(val.as_mut()).expect("RNG failure");
        val
    }
}
