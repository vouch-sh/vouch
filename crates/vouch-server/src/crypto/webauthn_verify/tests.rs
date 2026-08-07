// SPDX-License-Identifier: Apache-2.0 OR MIT
#![expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use super::*;
use aws_lc_rs::digest::{self, SHA256};

// =========================================================================
// Test Helpers
// =========================================================================

/// Create minimal valid authenticator data
fn make_auth_data(rp_id: &str, flags: u8, counter: u32) -> Vec<u8> {
    let rp_id_hash = digest::digest(&SHA256, rp_id.as_bytes());
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(rp_id_hash.as_ref()); // 32 bytes
    auth_data.push(flags);
    auth_data.extend_from_slice(&counter.to_be_bytes()); // 4 bytes
    auth_data
}

/// Create valid client data JSON
fn make_client_data_json(type_: &str, challenge: &str, origin: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "type": type_,
        "challenge": challenge,
        "origin": origin
    }))
    .unwrap()
}

/// Create a minimal valid EdDSA COSE key
fn make_eddsa_cose_key(x: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let key = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(1.into()), // kty = OKP
            ciborium::Value::Integer(1.into()),
        ),
        (
            ciborium::Value::Integer(3.into()), // alg = EdDSA (-8)
            ciborium::Value::Integer((-8).into()),
        ),
        (
            ciborium::Value::Integer((-1).into()), // crv = Ed25519 (6)
            ciborium::Value::Integer(6.into()),
        ),
        (
            ciborium::Value::Integer((-2).into()), // x (public key)
            ciborium::Value::Bytes(x.to_vec()),
        ),
    ]);
    ciborium::into_writer(&key, &mut buf).unwrap();
    buf
}

/// Build a registration-style auth_data: rpIdHash(32) + flags(1) +
/// counter(4) + aaguid(16) + credIdLen(2) + credId + cose_key.
fn make_registration_auth_data(
    rp_id: &str,
    aaguid: [u8; 16],
    credential_id: &[u8],
    cose_key: &[u8],
) -> Vec<u8> {
    let mut auth_data = make_auth_data(rp_id, 0x45, 0); // UP + UV + AT
    auth_data.extend_from_slice(&aaguid);
    let cred_id_len = u16::try_from(credential_id.len()).unwrap();
    auth_data.extend_from_slice(&cred_id_len.to_be_bytes());
    auth_data.extend_from_slice(credential_id);
    auth_data.extend_from_slice(cose_key);
    auth_data
}

/// Wrap auth_data into a CBOR attestation object with fmt = "none".
fn make_attestation_object_none(auth_data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let value = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("fmt".to_string()),
            ciborium::Value::Text("none".to_string()),
        ),
        (
            ciborium::Value::Text("attStmt".to_string()),
            ciborium::Value::Map(vec![]),
        ),
        (
            ciborium::Value::Text("authData".to_string()),
            ciborium::Value::Bytes(auth_data.to_vec()),
        ),
    ]);
    ciborium::into_writer(&value, &mut buf).unwrap();
    buf
}

// =========================================================================
// Basic Tests (existing)
// =========================================================================

#[test]
fn test_rp_id_hash_verification() {
    // Create minimal valid authenticator data with correct RP ID hash
    let rp_id = "example.com";
    let rp_id_hash = digest::digest(&SHA256, rp_id.as_bytes());

    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(rp_id_hash.as_ref()); // 32 bytes
    auth_data.push(0x05); // flags: UP + UV
    auth_data.extend_from_slice(&[0, 0, 0, 1]); // counter = 1

    // This should pass RP ID verification
    assert_eq!(&auth_data[0..32], rp_id_hash.as_ref());
}

#[test]
fn test_flags_parsing() {
    let flags_up_only: u8 = 0x01;
    let flags_up_uv: u8 = 0x05;

    assert!((flags_up_only & 0x01) != 0); // UP set
    assert!((flags_up_only & 0x04) == 0); // UV not set

    assert!((flags_up_uv & 0x01) != 0); // UP set
    assert!((flags_up_uv & 0x04) != 0); // UV set
}

// =========================================================================
// COSE Key Parsing Tests
// =========================================================================

#[test]
fn test_cose_key_missing_kty() {
    // Create COSE key without kty field
    let mut buf = Vec::new();
    let key = ciborium::Value::Map(vec![(
        ciborium::Value::Integer(3.into()), // alg only
        ciborium::Value::Integer((-7).into()),
    )]);
    ciborium::into_writer(&key, &mut buf).unwrap();

    let result = verify_cose_signature(&buf, &[], &[]);
    assert!(matches!(result, Err(VerifyError::InvalidCoseKey(msg)) if msg.contains("1")));
}

#[test]
fn test_cose_key_missing_alg() {
    // Create COSE key without alg field
    let mut buf = Vec::new();
    let key = ciborium::Value::Map(vec![(
        ciborium::Value::Integer(1.into()), // kty only
        ciborium::Value::Integer(2.into()),
    )]);
    ciborium::into_writer(&key, &mut buf).unwrap();

    let result = verify_cose_signature(&buf, &[], &[]);
    assert!(matches!(result, Err(VerifyError::InvalidCoseKey(msg)) if msg.contains("3")));
}

#[test]
fn test_cose_key_unsupported_algorithm() {
    // Create COSE key with unsupported algorithm (e.g., -999)
    let mut buf = Vec::new();
    let key = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer(2.into()),
        ),
        (
            ciborium::Value::Integer(3.into()),
            ciborium::Value::Integer((-999).into()),
        ),
    ]);
    ciborium::into_writer(&key, &mut buf).unwrap();

    let result = verify_cose_signature(&buf, &[], &[]);
    assert!(matches!(
        result,
        Err(VerifyError::UnsupportedAlgorithm(-999))
    ));
}

#[test]
fn test_cose_key_ec2_missing_x() {
    // EC2 key missing x coordinate
    let mut buf = Vec::new();
    let key = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(1.into()), // kty = EC2
            ciborium::Value::Integer(2.into()),
        ),
        (
            ciborium::Value::Integer(3.into()), // alg = ES256
            ciborium::Value::Integer((-7).into()),
        ),
        (
            ciborium::Value::Integer((-3).into()), // y only
            ciborium::Value::Bytes(vec![0u8; 32]),
        ),
    ]);
    ciborium::into_writer(&key, &mut buf).unwrap();

    let result = verify_cose_signature(&buf, &[], &[]);
    assert!(matches!(result, Err(VerifyError::InvalidCoseKey(msg)) if msg.contains("-2")));
}

#[test]
fn test_cose_key_ec2_missing_y() {
    // EC2 key missing y coordinate
    let mut buf = Vec::new();
    let key = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(1.into()), // kty = EC2
            ciborium::Value::Integer(2.into()),
        ),
        (
            ciborium::Value::Integer(3.into()), // alg = ES256
            ciborium::Value::Integer((-7).into()),
        ),
        (
            ciborium::Value::Integer((-2).into()), // x only
            ciborium::Value::Bytes(vec![0u8; 32]),
        ),
    ]);
    ciborium::into_writer(&key, &mut buf).unwrap();

    let result = verify_cose_signature(&buf, &[], &[]);
    assert!(matches!(result, Err(VerifyError::InvalidCoseKey(msg)) if msg.contains("-3")));
}

#[test]
fn test_cose_key_okp_missing_x() {
    // OKP key missing x (public key)
    let mut buf = Vec::new();
    let key = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(1.into()), // kty = OKP
            ciborium::Value::Integer(1.into()),
        ),
        (
            ciborium::Value::Integer(3.into()), // alg = EdDSA
            ciborium::Value::Integer((-8).into()),
        ),
    ]);
    ciborium::into_writer(&key, &mut buf).unwrap();

    let result = verify_cose_signature(&buf, &[], &[]);
    assert!(matches!(result, Err(VerifyError::InvalidCoseKey(msg)) if msg.contains("-2")));
}

#[test]
fn test_cose_key_truncated_cbor() {
    // Truncated CBOR data
    let truncated = vec![0xA3, 0x01, 0x02]; // Start of map but incomplete
    let result = verify_cose_signature(&truncated, &[], &[]);
    assert!(matches!(result, Err(VerifyError::InvalidCoseKey(_))));
}

#[test]
fn test_cose_key_not_a_map() {
    // CBOR integer instead of map
    let mut buf = Vec::new();
    ciborium::into_writer(&ciborium::Value::Integer(42.into()), &mut buf).unwrap();

    let result = verify_cose_signature(&buf, &[], &[]);
    assert!(matches!(result, Err(VerifyError::InvalidCoseKey(msg)) if msg.contains("map")));
}

#[test]
fn test_cose_key_eddsa_wrong_key_length() {
    // Ed25519 key with wrong length (not 32 bytes)
    let cose_key = make_eddsa_cose_key(&[0u8; 16]); // Should be 32 bytes

    let result = verify_cose_signature(&cose_key, &[], &[]);
    assert!(matches!(result, Err(VerifyError::InvalidCoseKey(msg)) if msg.contains("32")));
}

// =========================================================================
// Signature Verification Tests
// =========================================================================

#[test]
fn test_eddsa_signature_wrong_length() {
    // Generate a real Ed25519 keypair for testing
    use ed25519_dalek::SigningKey;

    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let verifying_key = signing_key.verifying_key();

    let cose_key = make_eddsa_cose_key(verifying_key.as_bytes());
    let message = b"test message";
    let wrong_len_sig = vec![0u8; 32]; // Should be 64 bytes

    let result = verify_cose_signature(&cose_key, message, &wrong_len_sig);
    assert!(matches!(result, Err(VerifyError::SignatureInvalid)));
}

#[test]
fn test_eddsa_signature_valid() {
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let verifying_key = signing_key.verifying_key();

    let cose_key = make_eddsa_cose_key(verifying_key.as_bytes());
    let message = b"test message for EdDSA";
    let signature = signing_key.sign(message);

    let result = verify_cose_signature(&cose_key, message, &signature.to_bytes());
    assert!(result.is_ok());
}

#[test]
fn test_eddsa_signature_tampered() {
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let verifying_key = signing_key.verifying_key();

    let cose_key = make_eddsa_cose_key(verifying_key.as_bytes());
    let message = b"test message for EdDSA";
    let mut signature = signing_key.sign(message).to_bytes();

    // Tamper with signature
    signature[0] ^= 0xFF;

    let result = verify_cose_signature(&cose_key, message, &signature);
    assert!(matches!(result, Err(VerifyError::SignatureInvalid)));
}

#[test]
fn test_eddsa_wrong_message() {
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let verifying_key = signing_key.verifying_key();

    let cose_key = make_eddsa_cose_key(verifying_key.as_bytes());
    let message = b"original message";
    let signature = signing_key.sign(message);

    // Verify with different message
    let result = verify_cose_signature(&cose_key, b"different message", &signature.to_bytes());
    assert!(matches!(result, Err(VerifyError::SignatureInvalid)));
}

// =========================================================================
// Authenticator Data Tests
// =========================================================================

#[test]
fn test_auth_data_minimum_length() {
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "example.com";

    // Too short (less than 37 bytes)
    let short_auth_data = vec![0u8; 36];
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &short_auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "https://example.com",
            stored_counter: 0,
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::InvalidAuthDataLength)));
}

#[test]
fn test_auth_data_exactly_minimum_length() {
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "example.com";
    let auth_data = make_auth_data(rp_id, 0x05, 1); // 37 bytes exactly
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "https://example.com",
            stored_counter: 0,
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(result.is_ok());
}

#[test]
fn test_auth_data_rp_id_mismatch() {
    let verifier = TestCoseVerifier::always_succeed();
    let auth_data = make_auth_data("wrong-rp.com", 0x05, 1);
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: "example.com", // Expected RP ID doesn't match auth_data
            expected_challenge: "test-challenge",
            expected_origin: "https://example.com",
            stored_counter: 0,
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::RpIdMismatch)));
}

#[test]
fn test_auth_data_user_presence_required() {
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "example.com";
    let auth_data = make_auth_data(rp_id, 0x00, 1); // No UP flag
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "https://example.com",
            stored_counter: 0,
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::UserNotPresent)));
}

#[test]
fn test_auth_data_user_verification_required() {
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "example.com";
    let auth_data = make_auth_data(rp_id, 0x01, 1); // UP but no UV
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "https://example.com",
            stored_counter: 0,
            require_user_verification: true, // Require UV
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::UserNotVerified)));
}

#[test]
fn test_auth_data_user_verification_not_required() {
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "example.com";
    let auth_data = make_auth_data(rp_id, 0x01, 1); // UP but no UV
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "https://example.com",
            stored_counter: 0,
            require_user_verification: false, // Don't require UV
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(result.is_ok());
}

// =========================================================================
// Counter Validation Tests (Replay Protection)
// =========================================================================

#[test]
fn test_counter_must_increase() {
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "example.com";
    let auth_data = make_auth_data(rp_id, 0x05, 5); // counter = 5
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    // With stored counter 4, new counter 5 should succeed
    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "https://example.com",
            stored_counter: 4, // stored counter
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(result.is_ok());
    assert_eq!(result.unwrap().counter, 5);
}

#[test]
fn test_counter_exact_match_rejected() {
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "example.com";
    let auth_data = make_auth_data(rp_id, 0x05, 5); // counter = 5
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    // Same counter = replay attack
    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "https://example.com",
            stored_counter: 5, // Same as auth_data counter
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::CounterNotIncreasing)));
}

#[test]
fn test_counter_decrease_rejected() {
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "example.com";
    let auth_data = make_auth_data(rp_id, 0x05, 3); // counter = 3
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    // Lower counter = cloned authenticator
    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "https://example.com",
            stored_counter: 5, // stored counter is higher
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::CounterNotIncreasing)));
}

#[test]
fn test_counter_zero_special_case() {
    // Some CTAP1 authenticators always return 0
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "example.com";
    let auth_data = make_auth_data(rp_id, 0x05, 0); // counter = 0
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    // Zero counter should be accepted (authenticator doesn't support counters)
    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "https://example.com",
            stored_counter: 0, // stored counter also 0
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(result.is_ok());
}

#[test]
fn test_counter_zero_to_nonzero() {
    // First use with stored=0, new counter=1
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "example.com";
    let auth_data = make_auth_data(rp_id, 0x05, 1); // counter = 1
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "https://example.com",
            stored_counter: 0, // Initial stored counter
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(result.is_ok());
}

#[test]
fn test_counter_u32_max_boundary() {
    // Test near u32::MAX boundary
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "example.com";
    let auth_data = make_auth_data(rp_id, 0x05, u32::MAX); // Maximum counter
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "https://example.com",
            stored_counter: u32::MAX - 1, // stored counter just below max
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(result.is_ok());
    assert_eq!(result.unwrap().counter, u32::MAX);
}

#[test]
fn test_counter_regression_to_zero_rejected() {
    // A credential that has reported a nonzero counter must never regress
    // to zero: that is unambiguous evidence of a cloned or forged
    // authenticator (WebAuthn L2 §6.1.1). Clone detection must run even
    // when the asserted counter is 0 — a zero value is not exempt.
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "example.com";
    let auth_data = make_auth_data(rp_id, 0x05, 0); // counter regressed to 0
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "https://example.com",
            stored_counter: 5, // stored counter was nonzero
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::CounterNotIncreasing)));
}

// =========================================================================
// Origin Relaxation Gating Tests (P2.2)
// =========================================================================

#[test]
fn test_localhost_origin_relaxation_allowed_when_enabled() {
    // With relaxation enabled (development, no TLS), a loopback origin
    // variation (localhost vs 127.0.0.1, differing ports) is tolerated.
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "localhost";
    let auth_data = make_auth_data(rp_id, 0x05, 1);
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "http://127.0.0.1:9000");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    let result = verify_assertion_inner(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "http://localhost:8080",
            stored_counter: 0,
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(result.is_ok(), "expected ok, got {result:?}");
}

#[test]
fn test_localhost_origin_relaxation_rejected_when_disabled() {
    // With relaxation disabled (production), the same loopback origin
    // variation is rejected: production must never weaken origin binding,
    // even on a misconfigured loopback rp_id.
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "localhost";
    let auth_data = make_auth_data(rp_id, 0x05, 1);
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "http://127.0.0.1:9000");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    let result = verify_assertion_inner(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "http://localhost:8080",
            stored_counter: 0,
            require_user_verification: false,
            allow_localhost_origin: false,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::InvalidOrigin)));
}

// =========================================================================
// Client Data JSON Tests
// =========================================================================

#[test]
fn test_client_data_invalid_json() {
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "example.com";
    let auth_data = make_auth_data(rp_id, 0x05, 1);
    let invalid_json = b"not valid json{";
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: invalid_json,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "https://example.com",
            stored_counter: 0,
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::InvalidClientData(_))));
}

#[test]
fn test_client_data_wrong_type() {
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "example.com";
    let auth_data = make_auth_data(rp_id, 0x05, 1);
    let client_data =
        make_client_data_json("webauthn.create", "test-challenge", "https://example.com");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    // Type should be "webauthn.get" for assertions
    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "https://example.com",
            stored_counter: 0,
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(
        matches!(result, Err(VerifyError::InvalidClientData(msg)) if msg.contains("webauthn.get"))
    );
}

#[test]
fn test_client_data_challenge_mismatch() {
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "example.com";
    let auth_data = make_auth_data(rp_id, 0x05, 1);
    let client_data =
        make_client_data_json("webauthn.get", "wrong-challenge", "https://example.com");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "expected-challenge",
            expected_origin: "https://example.com",
            stored_counter: 0,
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::ChallengeMismatch)));
}

#[test]
fn test_client_data_origin_mismatch() {
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "example.com";
    let auth_data = make_auth_data(rp_id, 0x05, 1);
    let client_data = make_client_data_json("webauthn.get", "test-challenge", "https://evil.com");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "https://example.com",
            stored_counter: 0,
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::InvalidOrigin)));
}

#[test]
fn test_client_data_localhost_variations_allowed() {
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "localhost";
    let auth_data = make_auth_data(rp_id, 0x05, 1);
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "https://127.0.0.1:8080");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    // localhost and 127.0.0.1 should be treated as equivalent
    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "https://localhost:8080",
            stored_counter: 0,
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(result.is_ok());
}

#[test]
fn test_client_data_docker_internal_to_localhost_allowed() {
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "host.docker.internal";
    let auth_data = make_auth_data(rp_id, 0x05, 1);
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "http://localhost:3000");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    // host.docker.internal and localhost are both loopback
    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "http://host.docker.internal:3000",
            stored_counter: 0,
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(result.is_ok());
}

#[test]
fn test_client_data_ipv6_loopback_to_localhost_allowed() {
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "localhost";
    let auth_data = make_auth_data(rp_id, 0x05, 1);
    let client_data = make_client_data_json("webauthn.get", "test-challenge", "http://[::1]:3000");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    // [::1] and localhost are both loopback
    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "http://localhost:3000",
            stored_counter: 0,
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(result.is_ok());
}

#[test]
fn test_client_data_loopback_vs_remote_rejected() {
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "example.com";
    let auth_data = make_auth_data(rp_id, 0x05, 1);
    // Client claims localhost origin, but expected origin is remote
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "http://localhost:3000");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "https://example.com",
            stored_counter: 0,
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::InvalidOrigin)));
}

#[test]
fn test_client_data_remote_vs_loopback_rejected() {
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "localhost";
    let auth_data = make_auth_data(rp_id, 0x05, 1);
    // Client claims remote origin, but expected origin is loopback
    let client_data = make_client_data_json("webauthn.get", "test-challenge", "https://evil.com");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "http://localhost:3000",
            stored_counter: 0,
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::InvalidOrigin)));
}

#[test]
fn test_client_data_localhost_in_path_not_matched() {
    // An origin like https://evil.com/localhost must NOT be treated as
    // loopback — only the origin's host component may match, never a
    // substring elsewhere in the URL.
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "localhost";
    let auth_data = make_auth_data(rp_id, 0x05, 1);
    let client_data = make_client_data_json(
        "webauthn.get",
        "test-challenge",
        "https://evil.com/localhost",
    );
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "http://localhost:3000",
            stored_counter: 0,
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::InvalidOrigin)));
}

// =========================================================================
// Full Assertion Verification Tests
// =========================================================================

#[test]
fn test_verify_assertion_success() {
    let verifier = TestCoseVerifier::always_succeed();
    let rp_id = "example.com";
    let auth_data = make_auth_data(rp_id, 0x05, 1);
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "https://example.com",
            stored_counter: 0,
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );

    assert!(result.is_ok());
    let verification = result.unwrap();
    assert_eq!(verification.counter, 1);
    assert!(verification.user_verified);
}

#[test]
fn test_verify_assertion_signature_invalid() {
    let verifier = TestCoseVerifier::always_fail();
    let rp_id = "example.com";
    let auth_data = make_auth_data(rp_id, 0x05, 1);
    let client_data =
        make_client_data_json("webauthn.get", "test-challenge", "https://example.com");
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);

    let result = verify_assertion_with_verifier(
        &AssertionParams {
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 64],
            public_key_cose: &cose_key,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "https://example.com",
            stored_counter: 0,
            require_user_verification: false,
            allow_localhost_origin: true,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::SignatureInvalid)));
}

// =========================================================================
// Test Verifier Tests
// =========================================================================

#[test]
fn test_test_cose_verifier_always_succeed() {
    let verifier = TestCoseVerifier::always_succeed();
    assert!(verifier.verify(&[], &[], &[]).is_ok());
}

#[test]
fn test_test_cose_verifier_always_fail() {
    let verifier = TestCoseVerifier::always_fail();
    assert!(matches!(
        verifier.verify(&[], &[], &[]),
        Err(VerifyError::SignatureInvalid)
    ));
}

#[test]
fn test_test_cose_verifier_default() {
    let verifier = TestCoseVerifier::default();
    assert!(verifier.verify(&[], &[], &[]).is_ok());
}

// =========================================================================
// Registration Attested-Credential-Data Parsing Tests
// =========================================================================

#[test]
fn test_verify_registration_empty_cose_key_returns_invalid_cose_key() {
    let rp_id = "example.com";
    let challenge = "challenge-bytes";
    let origin = "https://example.com";
    let auth_data = make_registration_auth_data(rp_id, [1; 16], b"cred-id", &[]);
    let attestation = make_attestation_object_none(&auth_data);
    let client_data = make_client_data_json("webauthn.create", challenge, origin);

    let err = verify_registration_with_verifier(
        &RegistrationParams {
            attestation_object: &attestation,
            client_data_json: &client_data,
            expected_rp_id: rp_id,
            expected_challenge: challenge,
            expected_origin: origin,
            require_user_verification: true,
            allow_localhost_origin: true,
        },
        &TestCoseVerifier::always_succeed(),
    )
    .unwrap_err();

    assert!(matches!(err, VerifyError::InvalidCoseKey(_)), "got {err:?}");
}

#[test]
fn test_verify_registration_truncated_attested_data_returns_invalid_auth_data_length() {
    let rp_id = "example.com";
    let challenge = "challenge-bytes";
    let origin = "https://example.com";
    // rpIdHash(32) + flags(1) + counter(4) + aaguid(16) + 1 byte — one byte
    // short of a complete credIdLen field.
    let mut auth_data = make_auth_data(rp_id, 0x45, 0);
    auth_data.extend_from_slice(&[0u8; 16]);
    auth_data.push(0);
    let attestation = make_attestation_object_none(&auth_data);
    let client_data = make_client_data_json("webauthn.create", challenge, origin);

    let err = verify_registration_with_verifier(
        &RegistrationParams {
            attestation_object: &attestation,
            client_data_json: &client_data,
            expected_rp_id: rp_id,
            expected_challenge: challenge,
            expected_origin: origin,
            require_user_verification: true,
            allow_localhost_origin: true,
        },
        &TestCoseVerifier::always_succeed(),
    )
    .unwrap_err();

    assert!(
        matches!(err, VerifyError::InvalidAuthDataLength),
        "got {err:?}"
    );
}

#[test]
fn test_registration_localhost_origin_relaxation_allowed_when_enabled() {
    // With relaxation enabled (development), a loopback origin variation
    // (localhost vs 127.0.0.1, differing ports) is accepted.
    let rp_id = "localhost";
    let challenge = "test-challenge";
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);
    let auth_data = make_registration_auth_data(rp_id, [1; 16], b"cred-id", &cose_key);
    let attestation = make_attestation_object_none(&auth_data);
    let client_data = make_client_data_json("webauthn.create", challenge, "http://127.0.0.1:9000");

    let result = verify_registration_with_verifier(
        &RegistrationParams {
            attestation_object: &attestation,
            client_data_json: &client_data,
            expected_rp_id: rp_id,
            expected_challenge: challenge,
            expected_origin: "http://localhost:8080",
            require_user_verification: true,
            allow_localhost_origin: true,
        },
        &TestCoseVerifier::always_succeed(),
    );
    assert!(result.is_ok(), "expected ok, got {result:?}");
}

#[test]
fn test_registration_localhost_origin_relaxation_rejected_when_disabled() {
    // With relaxation disabled (production), the same loopback origin
    // variation is rejected: production must never weaken origin binding,
    // even on a misconfigured loopback rp_id.
    let rp_id = "localhost";
    let challenge = "test-challenge";
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);
    let auth_data = make_registration_auth_data(rp_id, [1; 16], b"cred-id", &cose_key);
    let attestation = make_attestation_object_none(&auth_data);
    let client_data = make_client_data_json("webauthn.create", challenge, "http://127.0.0.1:9000");

    let result = verify_registration_with_verifier(
        &RegistrationParams {
            attestation_object: &attestation,
            client_data_json: &client_data,
            expected_rp_id: rp_id,
            expected_challenge: challenge,
            expected_origin: "http://localhost:8080",
            require_user_verification: true,
            allow_localhost_origin: false,
        },
        &TestCoseVerifier::always_succeed(),
    );
    assert!(matches!(result, Err(VerifyError::InvalidOrigin)));
}
