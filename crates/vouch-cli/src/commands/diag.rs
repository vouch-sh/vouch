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
    clippy::unwrap_in_result,
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
use ctap_hid_fido2::FidoKeyHidFactory;
use ctap_hid_fido2::LibCfg;
use ctap_hid_fido2::fidokey::get_assertion::GetAssertionArgsBuilder;
use ctap_hid_fido2::fidokey::make_credential::MakeCredentialArgsBuilder;
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::verifier;
use std::path::PathBuf;
use vouch_common::fixtures::{
    AuthenticationFixture, Fido2Fixture, FixtureMetadata, RegistrationFixture,
};

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

/// Run diagnostic test of YubiKey registration + authentication + verification.
pub(crate) fn run(args: DiagArgs) -> Result<()> {
    let json = args.json;

    // When json mode is active, use stderr for progress output so stdout is clean JSON.
    // This macro dispatches to println! or eprintln! based on the json flag.
    macro_rules! out {
        ($($arg:tt)*) => {
            if json {
                eprintln!($($arg)*);
            } else {
                println!($($arg)*);
            }
        };
    }
    macro_rules! out_print {
        ($($arg:tt)*) => {
            if json {
                eprint!($($arg)*);
            } else {
                print!($($arg)*);
            }
        };
    }

    out!("=== YubiKey Diagnostic Test ===\n");
    out!("This test will:");
    out!("1. Register a new credential on your YubiKey");
    out!("2. Authenticate with that credential");
    out!("3. Verify the signature using aws-lc-rs\n");

    // Wait for YubiKey
    out_print!("Please insert your YubiKey... ");
    if json {
        std::io::Write::flush(&mut std::io::stderr()).ok();
    } else {
        std::io::Write::flush(&mut std::io::stdout()).ok();
    }

    let cfg = LibCfg::init();
    let device = loop {
        if let Ok(dev) = FidoKeyHidFactory::create(&cfg) {
            out!("detected!");
            break dev;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    };

    // Get PIN
    out!("");
    eprint!("YubiKey PIN: ");
    let pin_raw = rpassword::read_password().context("failed to read PIN")?;
    // Note: In diag mode, we keep this as a plain String for simplicity since
    // this is a debugging tool that immediately uses and discards the PIN.
    // In production code (fido2.rs), we use SecretString.
    let pin = pin_raw;

    // Test parameters
    let rp_id = "diag.test.local";
    let user_id = b"diag-test-user";
    let user_name = "diag@test.local";

    // Generate challenge for registration
    let reg_challenge: [u8; 32] = rand::random();

    // Build client data for registration
    let reg_client_data = serde_json::json!({
        "type": "webauthn.create",
        "challenge": URL_SAFE_NO_PAD.encode(&reg_challenge),
        "origin": format!("https://{}", rp_id),
        "crossOrigin": false
    });
    let reg_client_data_json = serde_json::to_vec(&reg_client_data)?;
    let reg_client_data_hash = digest(&SHA256, &reg_client_data_json);

    out!("\n=== REGISTRATION ===");
    out!("RP ID: {}", rp_id);
    out!("Challenge: {}", hex::encode(&reg_challenge));
    out!(
        "Client data hash: {}",
        hex::encode(reg_client_data_hash.as_ref())
    );

    // Create user entity
    let user = PublicKeyCredentialUserEntity::new(Some(user_id), Some(user_name), Some(user_name));

    // Build make_credential arguments WITHOUT resident key (server-side credential)
    // IMPORTANT: The library expects RAW challenge bytes, not a pre-hashed clientDataHash!
    // The library handles clientDataJSON construction and hashing internally.
    let make_cred_args = MakeCredentialArgsBuilder::new(rp_id, &reg_challenge)
        .user_entity(&user)
        .pin(&pin)
        // NOT using .resident_key() - credential ID stored server-side
        .build();

    out!("\nTouch your YubiKey to register...");
    let attestation = device
        .make_credential_with_args(&make_cred_args)
        .context("Registration failed - check PIN and touch YubiKey")?;

    // Verify attestation locally - pass raw challenge, library hashes internally
    let verify_result = verifier::verify_attestation(rp_id, &reg_challenge, &attestation);
    let registration_success = verify_result.is_success;
    if !registration_success {
        bail!("Attestation verification failed!");
    }

    out!("Registration successful!");
    out!(
        "Credential ID: {} ({} bytes)",
        hex::encode(&verify_result.credential_id),
        verify_result.credential_id.len()
    );

    // Extract public key from ctap-hid-fido2's verification result
    // The .der field contains the SubjectPublicKeyInfo (SPKI) format
    let public_key_der = &verify_result.credential_public_key.der;
    out!(
        "Public key DER: {} ({} bytes)",
        hex::encode(public_key_der),
        public_key_der.len()
    );

    // Extract x and y from the COSE key in auth_data
    // auth_data structure: rp_id_hash(32) + flags(1) + counter(4) + aaguid(16) + cred_id_len(2) + cred_id(N) + cose_key
    let auth_data = &attestation.auth_data;
    out!(
        "Auth data: {} ({} bytes)",
        hex::encode(auth_data),
        auth_data.len()
    );

    let flags = auth_data[32];
    out!("Flags: {:#04x}", flags);

    if flags & 0x40 == 0 {
        bail!("No attested credential data in auth_data!");
    }

    let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let cose_key_start = 55_usize.saturating_add(cred_id_len);
    let cose_key_bytes = &auth_data[cose_key_start..];

    out!(
        "COSE key bytes: {} ({} bytes)",
        hex::encode(cose_key_bytes),
        cose_key_bytes.len()
    );

    // Parse COSE key to extract x and y
    let cose_val: ciborium::Value =
        ciborium::from_reader(cose_key_bytes).context("Failed to parse COSE key")?;

    let cose_map = cose_val.as_map().context("COSE key is not a map")?;

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

    out!("\nCOSE key parsed:");
    out!("  kty: {:?} (should be 2 for EC2)", kty);
    out!("  alg: {:?} (should be -7 for ES256)", alg);

    let x = x.context("Missing x coordinate")?;
    let y = y.context("Missing y coordinate")?;

    out!("  x ({} bytes): {}", x.len(), hex::encode(&x));
    out!("  y ({} bytes): {}", y.len(), hex::encode(&y));

    if x.len() != 32 || y.len() != 32 {
        bail!("Invalid coordinate lengths: x={}, y={}", x.len(), y.len());
    }

    // Now do authentication
    out!("\n=== AUTHENTICATION ===");

    let auth_challenge: [u8; 32] = rand::random();

    // Build client data for authentication
    let auth_client_data = serde_json::json!({
        "type": "webauthn.get",
        "challenge": URL_SAFE_NO_PAD.encode(&auth_challenge),
        "origin": format!("https://{}", rp_id),
        "crossOrigin": false
    });
    let auth_client_data_json = serde_json::to_vec(&auth_client_data)?;
    let auth_client_data_hash = digest(&SHA256, &auth_client_data_json);

    out!("Challenge: {}", hex::encode(&auth_challenge));
    out!(
        "Client data hash: {}",
        hex::encode(auth_client_data_hash.as_ref())
    );

    // Build get_assertion arguments with explicit credential ID (non-discoverable flow)
    // IMPORTANT: Pass raw challenge, not pre-hashed clientDataHash!
    let get_assertion_args = GetAssertionArgsBuilder::new(rp_id, &auth_challenge)
        .pin(&pin)
        .add_credential_id(&verify_result.credential_id) // Explicitly specify which credential
        .build();

    out!("\nTouch your YubiKey to authenticate...");
    let assertions = device
        .get_assertion_with_args(&get_assertion_args)
        .context("Authentication failed")?;

    let assertion = assertions
        .into_iter()
        .next()
        .context("No assertion returned")?;

    let authentication_success = true; // If we got here, authentication succeeded
    out!("Authentication successful!");
    out!(
        "Credential ID: {} ({} bytes)",
        hex::encode(&assertion.credential_id),
        assertion.credential_id.len()
    );
    out!(
        "Authenticator data: {} ({} bytes)",
        hex::encode(&assertion.auth_data),
        assertion.auth_data.len()
    );
    out!(
        "Signature: {} ({} bytes)",
        hex::encode(&assertion.signature),
        assertion.signature.len()
    );

    // Debug: Check the rpid_hash from the assertion
    out!("\n=== RPID VERIFICATION ===");
    let expected_rpid_hash = digest(&SHA256, rp_id.as_bytes());
    out!(
        "Expected rpid_hash: {}",
        hex::encode(expected_rpid_hash.as_ref())
    );
    out!("Assertion rpid_hash: {}", hex::encode(&assertion.rpid_hash));
    if expected_rpid_hash.as_ref() == assertion.rpid_hash.as_slice() {
        out!("OK RPID hash matches");
    } else {
        out!("FAIL RPID hash MISMATCH!");
    }

    // First, use the library's verify_assertion function
    out!("\n=== LIBRARY VERIFICATION ===");

    // The library's verify_assertion expects raw challenge bytes (not clientDataJSON or hash)
    // It constructs clientDataJSON internally and hashes it
    let lib_result = verifier::verify_assertion(
        rp_id,
        &verify_result.credential_public_key,
        &auth_challenge, // raw challenge bytes, library handles the rest
        &assertion,
    );

    if lib_result {
        out!("OK ctap-hid-fido2 library verification: PASSED");
    } else {
        out!("FAIL ctap-hid-fido2 library verification: FAILED");

        // Debug: Show what the library would compute
        // The library hashes the RAW challenge directly, not a clientDataJSON
        let lib_client_data_hash = digest(&SHA256, &auth_challenge);
        out!("\nDebug - Library computes:");
        out!(
            "  SHA256(raw_challenge) = {}",
            hex::encode(lib_client_data_hash.as_ref())
        );

        // Show the exact message the library would use
        let mut lib_message = Vec::new();
        lib_message.extend_from_slice(&assertion.auth_data);
        lib_message.extend_from_slice(lib_client_data_hash.as_ref());
        out!("\n  Library would verify message:");
        out!(
            "    auth_data ({} bytes) + SHA256(challenge) ({} bytes) = {} bytes",
            assertion.auth_data.len(),
            lib_client_data_hash.as_ref().len(),
            lib_message.len()
        );
        out!("    message = {}", hex::encode(&lib_message));
    }

    // Now verify the signature ourselves
    out!("\n=== AWS-LC-RS VERIFICATION ===");

    // Build the message: authenticator_data || SHA256(raw_challenge)
    // The library uses SHA256(challenge) directly, not SHA256(clientDataJSON)
    let challenge_hash = digest(&SHA256, &auth_challenge);
    let mut message = Vec::with_capacity(assertion.auth_data.len().saturating_add(32));
    message.extend_from_slice(&assertion.auth_data);
    message.extend_from_slice(challenge_hash.as_ref());

    out!(
        "Message: {} ({} bytes)",
        hex::encode(&message),
        message.len()
    );

    // Build SEC1 uncompressed point: 0x04 || x || y
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);

    out!(
        "Public key point: {} ({} bytes)",
        hex::encode(&point),
        point.len()
    );

    // Also show the library's public key for comparison
    out!(
        "Library public key: {} ({} bytes)",
        hex::encode(&verify_result.credential_public_key.der),
        verify_result.credential_public_key.der.len()
    );

    // Explicit byte-by-byte comparison
    if point == verify_result.credential_public_key.der {
        out!("OK Public keys are IDENTICAL (byte-by-byte)");
    } else {
        out!("FAIL Public keys DIFFER!");
        out!("  Our point len: {}", point.len());
        out!(
            "  Library len: {}",
            verify_result.credential_public_key.der.len()
        );
        for (i, (a, b)) in point
            .iter()
            .zip(verify_result.credential_public_key.der.iter())
            .enumerate()
        {
            if a != b {
                out!(
                    "  First diff at byte {}: ours=0x{:02x}, lib=0x{:02x}",
                    i,
                    a,
                    b
                );
                break;
            }
        }
        if point.len() != verify_result.credential_public_key.der.len() {
            out!("  Length mismatch!");
        }
    }

    // Verify with aws-lc-rs using our extracted point
    let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &point);

    let aws_lc_result = public_key.verify(&message, &assertion.signature).is_ok();
    if aws_lc_result {
        out!("\nOK aws-lc-rs verification (our point): PASSED");
    } else {
        out!("\nFAIL aws-lc-rs verification (our point): FAILED");
    }

    // Also verify using the library's extracted public key directly
    let public_key_lib = UnparsedPublicKey::new(
        &ECDSA_P256_SHA256_ASN1,
        &verify_result.credential_public_key.der,
    );

    match public_key_lib.verify(&message, &assertion.signature) {
        Ok(()) => {
            out!("OK aws-lc-rs verification (library key): PASSED");
        }
        Err(e) => {
            out!(
                "FAIL aws-lc-rs verification (library key): FAILED - {:?}",
                e
            );
        }
    }

    // Additional debug: Parse the DER signature to see r and s values
    out!("\n=== SIGNATURE ANALYSIS ===");
    let sig = &assertion.signature;
    if sig.len() >= 2 && sig[0] == 0x30 {
        let seq_len = sig[1] as usize;
        out!("DER SEQUENCE length: {}", seq_len);
        if sig.len() >= 4 && sig[2] == 0x02 {
            let r_len = sig[3] as usize;
            let r_start = 4_usize;
            let r_end = r_start.saturating_add(r_len);
            if sig.len() >= r_end {
                out!("r ({} bytes): {}", r_len, hex::encode(&sig[r_start..r_end]));
                if sig.len() > r_end.saturating_add(1) && sig[r_end] == 0x02 {
                    let s_len = sig[r_end.saturating_add(1)] as usize;
                    let s_start = r_end.saturating_add(2);
                    let s_end = s_start.saturating_add(s_len);
                    if sig.len() >= s_end {
                        out!("s ({} bytes): {}", s_len, hex::encode(&sig[s_start..s_end]));
                    }
                }
            }
        }
    }

    // Check if credential IDs match between registration and authentication
    out!("\n=== CREDENTIAL ID CHECK ===");
    out!(
        "Registration cred_id: {}",
        hex::encode(&verify_result.credential_id)
    );
    out!(
        "Assertion cred_id:    {}",
        hex::encode(&assertion.credential_id)
    );
    if verify_result.credential_id == assertion.credential_id {
        out!("OK Credential IDs match");
    } else {
        out!("FAIL Credential ID MISMATCH - authenticator used different credential!");
    }

    out!("\n=== SUMMARY ===");
    if lib_result {
        out!("The ctap-hid-fido2 library CAN verify the signature.");
        out!("This suggests the issue is with how we're calling aws-lc-rs.");
    } else {
        out!("Even the ctap-hid-fido2 library CANNOT verify the signature.");
        out!("This suggests a fundamental issue with the YubiKey or authentication flow.");
        out!("\nPossible causes:");
        out!("1. YubiKey firmware bug (especially FIPS models)");
        out!("2. Credential corruption on the YubiKey");
        out!("3. Different key pair being used for signing vs registration");
    }

    // Output data for manual OpenSSL verification
    out!("\n=== OPENSSL VERIFICATION DATA ===");
    out!("To verify with OpenSSL, run these commands:");
    out!("");
    out!("# Create public key PEM file");
    out!("echo '-----BEGIN PUBLIC KEY-----' > /tmp/pubkey.pem");

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
    spki.extend_from_slice(&point);

    use base64::engine::general_purpose::STANDARD;
    let spki_b64 = STANDARD.encode(&spki);
    // Split into 64-char lines
    for chunk in spki_b64.as_bytes().chunks(64) {
        out!(
            "echo '{}' >> /tmp/pubkey.pem",
            std::str::from_utf8(chunk).unwrap()
        );
    }
    out!("echo '-----END PUBLIC KEY-----' >> /tmp/pubkey.pem");
    out!("");

    out!("# Create message file (auth_data || client_data_hash)");
    out!(
        "echo -n '{}' | xxd -r -p > /tmp/message.bin",
        hex::encode(&message)
    );
    out!("");

    out!("# Create signature file (DER format)");
    out!(
        "echo -n '{}' | xxd -r -p > /tmp/signature.der",
        hex::encode(&assertion.signature)
    );
    out!("");

    out!("# Verify with OpenSSL");
    out!(
        "openssl dgst -sha256 -verify /tmp/pubkey.pem -signature /tmp/signature.der /tmp/message.bin"
    );

    // Note: This test now uses non-resident credentials (no cleanup needed)
    out!("\nNote: Non-resident credential used - no cleanup needed on YubiKey.");

    // Extract AAGUID from auth_data (bytes 37-52 when AT flag is set)
    let aaguid = if flags & 0x40 != 0 && auth_data.len() >= 53 {
        Some(hex::encode(&auth_data[37..53]))
    } else {
        None
    };

    // Try to look up device model from AAGUID
    let device_model = aaguid
        .as_ref()
        .and_then(|aaguid_hex| vouch_common::lookup_device_model(aaguid_hex).map(String::from));

    // JSON output
    if json {
        let diag_json = DiagJson {
            registration_success,
            authentication_success,
            library_verification: lib_result,
            aws_lc_verification: aws_lc_result,
            credential_id: hex::encode(&verify_result.credential_id),
            public_key_hex: hex::encode(public_key_der),
            aaguid: aaguid.clone(),
            device_model: device_model.clone(),
        };
        println!("{}", serde_json::to_string_pretty(&diag_json)?);
    }

    // Export fixture if requested
    if let Some(ref path) = args.export_fixture {
        out!("\n=== EXPORTING FIXTURE ===");

        let fixture = Fido2Fixture {
            metadata: FixtureMetadata {
                description: "YubiKey diagnostic test fixture".to_string(),
                device_model,
                aaguid,
                created_at: jiff::Zoned::now().to_string(),
                rp_id: rp_id.to_string(),
            },
            registration: RegistrationFixture {
                challenge_hex: hex::encode(&reg_challenge),
                client_data_json: String::from_utf8_lossy(&reg_client_data_json).to_string(),
                credential_id_hex: hex::encode(&verify_result.credential_id),
                public_key_cose_hex: hex::encode(cose_key_bytes),
                auth_data_hex: hex::encode(auth_data),
                attestation_object_hex: None, // Not capturing full attestation object
                x_hex: hex::encode(&x),
                y_hex: hex::encode(&y),
            },
            authentication: AuthenticationFixture {
                challenge_hex: hex::encode(&auth_challenge),
                client_data_json: String::from_utf8_lossy(&auth_client_data_json).to_string(),
                auth_data_hex: hex::encode(&assertion.auth_data),
                signature_hex: hex::encode(&assertion.signature),
                user_handle_hex: None, // Non-resident credential doesn't have user_handle
            },
        };

        fixture
            .save_to_file(path)
            .map_err(|e| anyhow::anyhow!("Failed to save fixture: {}", e))?;
        out!("Fixture saved to: {}", path.display());
    }

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
