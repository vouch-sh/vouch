// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Golden file tests using real FIDO2 fixture data.
//!
//! These tests verify that our verification code works correctly with real
//! YubiKey data captured using `vouch diag --export-fixture`.
//!
//! To generate a new fixture:
//! ```bash
//! cargo run -p vouch-cli -- diag --export-fixture ./crates/vouch-tests/fixtures/yubikey.json
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::Path;
use vouch_cli::FidoDevice;
use vouch_common::fixtures::Fido2Fixture;

/// Load a fixture from the fixtures directory.
fn load_fixture(name: &str) -> Option<Fido2Fixture> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name);
    if path.exists() {
        Fido2Fixture::load_from_file(&path).ok()
    } else {
        None
    }
}

/// Test that we can load and parse a fixture file.
#[test]
fn test_fixture_loading() {
    // This test always passes - it just validates the fixture format
    // If a fixture exists, it should be parseable
    if let Some(fixture) = load_fixture("yubikey.json") {
        assert!(!fixture.metadata.rp_id.is_empty());
        assert!(!fixture.registration.credential_id_hex.is_empty());
        assert!(!fixture.authentication.signature_hex.is_empty());
    }
}

/// Test that fixture helper methods work correctly.
#[test]
fn test_fixture_helpers() {
    if let Some(fixture) = load_fixture("yubikey.json") {
        // Test decoding methods
        let cred_id = fixture.credential_id();
        assert!(cred_id.is_ok(), "credential_id should decode");

        let public_key = fixture.public_key_cose();
        assert!(public_key.is_ok(), "public_key_cose should decode");

        let auth_data = fixture.auth_authenticator_data();
        assert!(auth_data.is_ok(), "auth_authenticator_data should decode");

        let signature = fixture.auth_signature();
        assert!(signature.is_ok(), "auth_signature should decode");

        let sec1 = fixture.public_key_sec1();
        assert!(sec1.is_ok(), "public_key_sec1 should decode");

        // SEC1 format should be 65 bytes (0x04 + 32 bytes x + 32 bytes y)
        if let Ok(sec1_bytes) = sec1 {
            assert_eq!(sec1_bytes.len(), 65, "SEC1 point should be 65 bytes");
            assert_eq!(sec1_bytes[0], 0x04, "SEC1 point should start with 0x04");
        }
    }
}

/// Test signature verification with real YubiKey data.
///
/// This test is skipped if no fixture file exists.
#[test]
fn test_signature_verification_with_fixture() {
    let Some(fixture) = load_fixture("yubikey.json") else {
        println!("Skipping test: no yubikey.json fixture found");
        println!(
            "Generate one with: cargo run -p vouch-cli -- diag --export-fixture ./crates/vouch-tests/fixtures/yubikey.json"
        );
        return;
    };

    // Decode fixture data
    let auth_data = fixture.auth_authenticator_data().unwrap();
    let signature = fixture.auth_signature().unwrap();
    let public_key_sec1 = fixture.public_key_sec1().unwrap();
    let challenge = fixture.authentication_challenge().unwrap();

    // Build the message: authenticator_data || SHA256(challenge)
    // Note: The diag command uses SHA256(raw_challenge), not SHA256(clientDataJSON)
    let challenge_hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &challenge);
    let mut message = Vec::with_capacity(auth_data.len() + 32);
    message.extend_from_slice(&auth_data);
    message.extend_from_slice(challenge_hash.as_ref());

    // Verify with aws-lc-rs
    let public_key = aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        &public_key_sec1,
    );

    let result = public_key.verify(&message, &signature);
    assert!(
        result.is_ok(),
        "Signature verification should pass for real YubiKey data: {:?}",
        result.err()
    );
}

/// Test COSE key parsing with real YubiKey data.
#[test]
fn test_cose_key_parsing_with_fixture() {
    let Some(fixture) = load_fixture("yubikey.json") else {
        println!("Skipping test: no yubikey.json fixture found");
        return;
    };

    let cose_key = fixture.public_key_cose().unwrap();

    // Parse with ciborium
    let cose_val: ciborium::Value = ciborium::from_reader(&cose_key[..]).unwrap();

    // Should be a map
    let cose_map = cose_val.as_map().expect("COSE key should be a map");

    // Extract key fields
    let mut kty: Option<i64> = None;
    let mut alg: Option<i64> = None;
    let mut crv: Option<i64> = None;

    for (k, v) in cose_map {
        if let Some(key_int) = k.as_integer() {
            let key_i64: i64 = key_int.try_into().unwrap_or(0);
            match key_i64 {
                1 => kty = v.as_integer().and_then(|i| i.try_into().ok()),
                3 => alg = v.as_integer().and_then(|i| i.try_into().ok()),
                -1 => crv = v.as_integer().and_then(|i| i.try_into().ok()),
                _ => {}
            }
        }
    }

    // Verify key type is EC2 (2)
    assert_eq!(kty, Some(2), "Key type should be EC2 (2)");

    // Algorithm should be ES256 (-7) for P-256
    assert_eq!(alg, Some(-7), "Algorithm should be ES256 (-7)");

    // Curve should be P-256 (1)
    assert_eq!(crv, Some(1), "Curve should be P-256 (1)");
}

/// Test contract validation with real YubiKey data.
#[test]
fn test_contract_validation_with_fixture() {
    let Some(fixture) = load_fixture("yubikey.json") else {
        println!("Skipping test: no yubikey.json fixture found");
        return;
    };

    use vouch_tests::contracts::*;

    // Validate COSE key
    let cose_key = fixture.public_key_cose().unwrap();
    let result = validate_cose_key(&cose_key);
    assert!(
        result.is_ok(),
        "COSE key validation should pass: {:?}",
        result.err()
    );

    // Validate registration authenticator data
    let reg_auth_data = hex::decode(&fixture.registration.auth_data_hex).unwrap();
    let result = validate_authenticator_data(&reg_auth_data);
    assert!(
        result.is_ok(),
        "Registration auth data validation should pass: {:?}",
        result.err()
    );

    // Validate authentication authenticator data
    let auth_auth_data = fixture.auth_authenticator_data().unwrap();
    let result = validate_authenticator_data(&auth_auth_data);
    assert!(
        result.is_ok(),
        "Authentication auth data validation should pass: {:?}",
        result.err()
    );

    // Validate credential ID
    let cred_id = fixture.credential_id().unwrap();
    let result = validate_credential_id(&cred_id);
    assert!(
        result.is_ok(),
        "Credential ID validation should pass: {:?}",
        result.err()
    );

    // Validate signature
    let signature = fixture.auth_signature().unwrap();
    let result = validate_signature(&signature);
    assert!(
        result.is_ok(),
        "Signature validation should pass: {:?}",
        result.err()
    );

    // Validate client data JSON
    let client_data = fixture.authentication.client_data_json.as_bytes();
    let result = validate_client_data_json(client_data);
    assert!(
        result.is_ok(),
        "Client data JSON validation should pass: {:?}",
        result.err()
    );
}

/// Test that typed encoding works with fixture data.
#[test]
fn test_typed_encoding_with_fixture() {
    let Some(fixture) = load_fixture("yubikey.json") else {
        println!("Skipping test: no yubikey.json fixture found");
        return;
    };

    use vouch_common::encoding::Raw;
    use vouch_common::fido2_types::*;

    // Convert fixture data to typed encodings
    let cred_id: CredentialId<Raw> = fixture.credential_id().unwrap().into();
    let cose_key: CoseKey<Raw> = fixture.public_key_cose().unwrap().into();
    let auth_data: AuthData<Raw> = fixture.auth_authenticator_data().unwrap().into();
    let signature: Signature<Raw> = fixture.auth_signature().unwrap().into();

    // Verify the typed values match the original data
    assert_eq!(
        cred_id.as_bytes(),
        hex::decode(&fixture.registration.credential_id_hex)
            .unwrap()
            .as_slice()
    );
    assert_eq!(
        cose_key.as_bytes(),
        hex::decode(&fixture.registration.public_key_cose_hex)
            .unwrap()
            .as_slice()
    );
    assert_eq!(
        auth_data.as_bytes(),
        hex::decode(&fixture.authentication.auth_data_hex)
            .unwrap()
            .as_slice()
    );
    assert_eq!(
        signature.as_bytes(),
        hex::decode(&fixture.authentication.signature_hex)
            .unwrap()
            .as_slice()
    );

    // Test JSON round-trip with typed values
    let json = serde_json::to_string(&cred_id).unwrap();
    let decoded: CredentialId<Raw> = serde_json::from_str(&json).unwrap();
    assert_eq!(cred_id, decoded);
}

// ============================================================================
// Tests using MockFidoDevice data (always run, no hardware needed)
// ============================================================================

/// Test that MockFidoDevice generates valid fixture-compatible data.
#[test]
fn test_mock_device_fixture_compatibility() {
    use vouch_cli::MockFidoDevice;

    let device = MockFidoDevice::new();
    let challenge = [42u8; 32];
    let user_id = [1u8; 16];

    let reg = device
        .register(
            "test.local",
            "Test RP",
            &challenge,
            &user_id,
            "test@example.com",
            "123456",
        )
        .unwrap();
    let auth = device
        .authenticate("test.local", &challenge, "123456")
        .unwrap();

    // Create a fixture from MockFidoDevice data
    let fixture = Fido2Fixture {
        metadata: vouch_common::fixtures::FixtureMetadata {
            description: "MockFidoDevice test fixture".to_string(),
            device_model: Some("Mock Device".to_string()),
            aaguid: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            rp_id: "test.local".to_string(),
        },
        registration: vouch_common::fixtures::RegistrationFixture {
            challenge_hex: hex::encode(challenge),
            client_data_json: String::from_utf8_lossy(&reg.client_data_json).to_string(),
            credential_id_hex: hex::encode(&reg.credential_id),
            public_key_cose_hex: hex::encode(&reg.public_key),
            auth_data_hex: hex::encode(&reg.attestation_object), // Using attestation_object as stand-in
            attestation_object_hex: Some(hex::encode(&reg.attestation_object)),
            x_hex: String::new(), // Would need to extract from COSE key
            y_hex: String::new(),
        },
        authentication: vouch_common::fixtures::AuthenticationFixture {
            challenge_hex: hex::encode(challenge),
            client_data_json: String::from_utf8_lossy(&auth.client_data_json).to_string(),
            auth_data_hex: hex::encode(&auth.authenticator_data),
            signature_hex: hex::encode(&auth.signature),
            user_handle_hex: Some(hex::encode(&auth.user_handle)),
        },
    };

    // Serialize and deserialize
    let json = serde_json::to_string_pretty(&fixture).unwrap();
    let decoded: Fido2Fixture = serde_json::from_str(&json).unwrap();

    assert_eq!(fixture.metadata.rp_id, decoded.metadata.rp_id);
    assert_eq!(
        fixture.registration.credential_id_hex,
        decoded.registration.credential_id_hex
    );
    assert_eq!(
        fixture.authentication.signature_hex,
        decoded.authentication.signature_hex
    );
}
