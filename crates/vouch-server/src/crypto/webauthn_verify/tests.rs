// SPDX-License-Identifier: Apache-2.0 OR MIT
#![expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
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

// WebAuthn L2 §7.2 step 15: the rpIdHash in authData is the SHA-256 hash of the expected RP ID.
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

// WebAuthn L2 §6.1: the UP and UV flags occupy defined bits of authenticator data.
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

// WebAuthn L2 §6.5.1: a credential public key with no kty is not a COSE_Key.
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

// WebAuthn L2 §6.5.1: a credential public key with no alg is not a COSE_Key.
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

// WebAuthn L2 §6.5.1: an unregistered alg cannot be used to verify.
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

// WebAuthn L2 §6.5.1: an EC2 key without its x coordinate is malformed.
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
            ciborium::Value::Integer((-1).into()), // crv = P-256
            ciborium::Value::Integer(1.into()),
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

// WebAuthn L2 §6.5.1: an EC2 key without its y coordinate is malformed.
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
            ciborium::Value::Integer((-1).into()), // crv = P-256
            ciborium::Value::Integer(1.into()),
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

// WebAuthn L2 §6.5.1: an OKP key without its public key is malformed.
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
        (
            ciborium::Value::Integer((-1).into()), // crv = Ed25519
            ciborium::Value::Integer(6.into()),
        ),
    ]);
    ciborium::into_writer(&key, &mut buf).unwrap();

    let result = verify_cose_signature(&buf, &[], &[]);
    assert!(matches!(result, Err(VerifyError::InvalidCoseKey(msg)) if msg.contains("-2")));
}

// WebAuthn L2 §6.5.1: truncated CBOR does not decode to a COSE_Key.
#[test]
fn test_cose_key_truncated_cbor() {
    // Truncated CBOR data
    let truncated = vec![0xA3, 0x01, 0x02]; // Start of map but incomplete
    let result = verify_cose_signature(&truncated, &[], &[]);
    assert!(matches!(result, Err(VerifyError::InvalidCoseKey(_))));
}

// WebAuthn L2 §6.5.1: a COSE_Key is a CBOR map.
#[test]
fn test_cose_key_not_a_map() {
    // CBOR integer instead of map
    let mut buf = Vec::new();
    ciborium::into_writer(&ciborium::Value::Integer(42.into()), &mut buf).unwrap();

    let result = verify_cose_signature(&buf, &[], &[]);
    assert!(matches!(result, Err(VerifyError::InvalidCoseKey(msg)) if msg.contains("map")));
}

// WebAuthn L2 §6.5.1: an Ed25519 public key is 32 bytes.
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

// WebAuthn L2 §7.2 step 20: a malformed signature does not verify.
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

// WebAuthn L2 §7.2 step 20: sig verifies over authData concatenated with the client data hash.
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

// WebAuthn L2 §7.2 step 20: an altered signature does not verify.
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

// WebAuthn L2 §7.2 step 20: a signature over different data does not verify.
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

// WebAuthn L2 §6.1: authenticator data is at least 37 bytes.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::InvalidAuthDataLength)));
}

// WebAuthn L2 §6.1: 37 bytes is a complete assertion authenticator data.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(result.is_ok());
}

// WebAuthn L2 §7.2 step 15: an rpIdHash for a different RP ID is rejected.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::RpIdMismatch)));
}

// WebAuthn L2 §7.2 step 16: the User Present bit must be set.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::UserNotPresent)));
}

// WebAuthn L2 §7.2 step 17: when user verification is required, the UV bit must be set.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::UserNotVerified)));
}

// WebAuthn L2 §7.2 step 17: when user verification is not required, a clear UV bit is accepted.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(result.is_ok());
}

// =========================================================================
// Counter Validation Tests (Replay Protection)
// =========================================================================

// WebAuthn L2 §7.2 step 21: a signCount greater than the stored value is accepted.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(result.is_ok());
    assert_eq!(result.unwrap().counter, 5);
}

// WebAuthn L2 §7.2 step 21: a signCount equal to the stored value is a cloned authenticator.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::CounterNotIncreasing)));
}

// WebAuthn L2 §7.2 step 21: a signCount below the stored value is a cloned authenticator.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::CounterNotIncreasing)));
}

// WebAuthn L2 §6.1.1: an authenticator that implements no counter reports zero throughout.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(result.is_ok());
}

// WebAuthn L2 §6.1.1: a counter may begin reporting after a zero start.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(result.is_ok());
}

// WebAuthn L2 §6.1: signCount is an unsigned 32-bit value.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(result.is_ok());
    assert_eq!(result.unwrap().counter, u32::MAX);
}

// WebAuthn L2 §7.2 step 21: a credential that has reported a nonzero counter must never regress to
// zero.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::CounterNotIncreasing)));
}

// =========================================================================
// Origin Relaxation Gating Tests
// =========================================================================

// WebAuthn L2 §7.2 step 13: loopback origin variation is tolerated only under an explicit
// development opt-in.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(result.is_ok(), "expected ok, got {result:?}");
}

// WebAuthn L2 §7.2 step 13: C.origin must match the Relying Party origin in production.
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
            origin_policy: OriginPolicy::Strict,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::InvalidOrigin)));
}

// =========================================================================
// Client Data JSON Tests
// =========================================================================

// WebAuthn L2 §7.2 step 10: clientDataJSON that is not valid JSON cannot yield C.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::InvalidClientData(_))));
}

// WebAuthn L2 §7.2 step 11: C.type must be the string webauthn.get.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(
        matches!(result, Err(VerifyError::InvalidClientData(msg)) if msg.contains("webauthn.get"))
    );
}

// WebAuthn L2 §7.2 step 12: C.challenge must equal the base64url encoding of the issued challenge.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::ChallengeMismatch)));
}

// WebAuthn L2 §7.2 step 13: C.origin must match the Relying Party origin.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::InvalidOrigin)));
}

// WebAuthn L2 §7.2 step 13: loopback spellings compare equal under the development opt-in.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(result.is_ok());
}

// WebAuthn L2 §7.2 step 13: a container loopback alias compares equal under the development opt-in.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(result.is_ok());
}

// WebAuthn L2 §7.2 step 13: the IPv6 loopback compares equal under the development opt-in.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(result.is_ok());
}

// WebAuthn L2 §7.2 step 13: relaxation never admits a remote origin.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::InvalidOrigin)));
}

// WebAuthn L2 §7.2 step 13: relaxation never admits a loopback origin for a remote RP.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::InvalidOrigin)));
}

// WebAuthn L2 §7.2 step 13: the origin comparison is on the origin, not a substring of the URL.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );
    assert!(matches!(result, Err(VerifyError::InvalidOrigin)));
}

// =========================================================================
// Full Assertion Verification Tests
// =========================================================================

// WebAuthn L2 §7.2: a complete, conformant assertion verifies.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &verifier,
    );

    assert!(result.is_ok());
    let verification = result.unwrap();
    assert_eq!(verification.counter, 1);
    assert!(verification.user_verified);
}

// WebAuthn L2 §7.2 step 20: an assertion whose signature does not verify is rejected.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
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

// WebAuthn L2 §7.1: a credential public key that is not a COSE_Key fails registration.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &TestCoseVerifier::always_succeed(),
    )
    .unwrap_err();

    assert!(matches!(err, VerifyError::InvalidCoseKey(_)), "got {err:?}");
}

// WebAuthn L2 §6.5.1: truncated attested credential data is malformed.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &TestCoseVerifier::always_succeed(),
    )
    .unwrap_err();

    assert!(
        matches!(err, VerifyError::InvalidAuthDataLength),
        "got {err:?}"
    );
}

// WebAuthn L2 §7.1 step 9: loopback origin variation is tolerated only under an explicit
// development opt-in.
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
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &TestCoseVerifier::always_succeed(),
    );
    assert!(result.is_ok(), "expected ok, got {result:?}");
}

// WebAuthn L2 §7.1 step 9: C.origin must match the Relying Party origin in production.
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
            origin_policy: OriginPolicy::Strict,
        },
        &TestCoseVerifier::always_succeed(),
    );
    assert!(matches!(result, Err(VerifyError::InvalidOrigin)));
}

// =========================================================================
// ES256 signature encoding (WebAuthn Level 2 Section 6.5.5)
// =========================================================================

/// Build an EC2/P-256/ES256 COSE key from an uncompressed SEC1 point.
fn make_es256_cose_key(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let key = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(1.into()), // kty = EC2
            ciborium::Value::Integer(2.into()),
        ),
        (
            ciborium::Value::Integer(3.into()), // alg = ES256 (-7)
            ciborium::Value::Integer((-7).into()),
        ),
        (
            ciborium::Value::Integer((-1).into()), // crv = P-256 (1)
            ciborium::Value::Integer(1.into()),
        ),
        (
            ciborium::Value::Integer((-2).into()), // x
            ciborium::Value::Bytes(x.to_vec()),
        ),
        (
            ciborium::Value::Integer((-3).into()), // y
            ciborium::Value::Bytes(y.to_vec()),
        ),
    ]);
    ciborium::into_writer(&key, &mut buf).unwrap();
    buf
}

/// Sign `message` with a deterministic P-256 key, returning the COSE key
/// alongside the signature in both encodings.
fn es256_fixture(message: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};

    let signing_key = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
    let point = signing_key.verifying_key().to_encoded_point(false);
    let cose_key = make_es256_cose_key(point.x().unwrap(), point.y().unwrap());

    let signature: Signature = signing_key.sign(message);
    (
        cose_key,
        signature.to_der().as_bytes().to_vec(),
        signature.to_bytes().to_vec(),
    )
}

/// WebAuthn Level 2 Section 6.5.5: "the sig value MUST be encoded as an
/// ASN.1 DER Ecdsa-Sig-Value". Both browsers and CTAP2 authenticators emit
/// this encoding, so it is the only one a conformant client produces.
// WebAuthn L2 §6.5.5, §7.2 step 20: an ES256 signature in the encoding WebAuthn specifies verifies.
#[test]
fn test_es256_der_signature_is_accepted() {
    let message = b"webauthn assertion signing input";
    let (cose_key, der, _raw) = es256_fixture(message);

    assert!(verify_cose_signature(&cose_key, message, &der).is_ok());
}

/// A raw r||s pair is a valid signature over the same message, but not a
/// conformant encoding. Accepting it on the strength of its 64-byte length
/// was the heuristic this replaces, so rejection is the property under test.
// WebAuthn L2 §6.5.5, §7.2 step 20: a raw (r, s) pair is not the ES256 signature encoding.
#[test]
fn test_es256_raw_rs_signature_is_rejected() {
    let message = b"webauthn assertion signing input";
    let (cose_key, _der, raw) = es256_fixture(message);

    assert_eq!(raw.len(), 64, "r||s for P-256 is 64 bytes");
    assert!(
        matches!(
            verify_cose_signature(&cose_key, message, &raw),
            Err(VerifyError::SignatureInvalid)
        ),
        "a non-conformant raw r||s signature must not verify"
    );
}

/// A DER signature over a different message must still fail, so the test
/// above is not passing merely because DER parsing succeeded.
// WebAuthn L2 §7.2 step 20: an ES256 signature over different data does not verify.
#[test]
fn test_es256_der_signature_over_wrong_message_is_rejected() {
    let (cose_key, der, _raw) = es256_fixture(b"original message");

    assert!(matches!(
        verify_cose_signature(&cose_key, b"different message", &der),
        Err(VerifyError::SignatureInvalid)
    ));
}

// =========================================================================
// COSE (kty, alg, crv) triple validation (RFC 9053 Section 2.1)
// =========================================================================

/// Build an EC2 COSE key with an explicitly chosen `alg` and `crv`, so a
/// mismatched pair can be constructed for testing.
fn make_ec2_cose_key_with(alg: i64, crv: i64, x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let key = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer(2.into()), // kty = EC2
        ),
        (
            ciborium::Value::Integer(3.into()),
            ciborium::Value::Integer(alg.into()),
        ),
        (
            ciborium::Value::Integer((-1).into()),
            ciborium::Value::Integer(crv.into()),
        ),
        (
            ciborium::Value::Integer((-2).into()),
            ciborium::Value::Bytes(x.to_vec()),
        ),
        (
            ciborium::Value::Integer((-3).into()),
            ciborium::Value::Bytes(y.to_vec()),
        ),
    ]);
    ciborium::into_writer(&key, &mut buf).unwrap();
    buf
}

/// An EC2 key declaring ES256 but carrying P-384 must be rejected for the
/// curve, not passed to a P-256 verifier that fails opaquely inside aws-lc.
///
/// RFC 9053 Section 2.1: "Implementations need to check that the key type and
/// curve are correct when creating and verifying a signature."
// WebAuthn L2 §6.5.1: the crv of an EC2 key must match the algorithm it declares.
#[test]
fn test_es256_with_p384_curve_is_rejected() {
    let message = b"webauthn assertion signing input";
    let (_, der, _) = es256_fixture(message);

    // Real P-256 coordinates, but the key claims the P-384 curve.
    let cose_key = make_ec2_cose_key_with(-7, 2, &[1u8; 32], &[2u8; 32]);

    let err = verify_cose_signature(&cose_key, message, &der).unwrap_err();
    assert!(
        matches!(err, VerifyError::InvalidCoseKey(ref m) if m.contains("crv")),
        "error must name the curve mismatch, got: {err:?}"
    );
}

/// The mismatch must be caught even when the signature itself is well-formed
/// and the coordinates are a genuine P-256 point.
// WebAuthn L2 §6.5.1: a curve mismatch is rejected before any signature arithmetic.
#[test]
fn test_es256_curve_mismatch_precedes_signature_check() {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};

    let message = b"webauthn assertion signing input";
    let signing_key = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
    let point = signing_key.verifying_key().to_encoded_point(false);
    let signature: Signature = signing_key.sign(message);

    // Same key and a signature that would verify, but crv says P-521.
    let cose_key = make_ec2_cose_key_with(-7, 3, point.x().unwrap(), point.y().unwrap());

    assert!(matches!(
        verify_cose_signature(&cose_key, message, signature.to_der().as_bytes()),
        Err(VerifyError::InvalidCoseKey(_))
    ));
}

/// An EdDSA key declaring the wrong key type must be rejected.
// WebAuthn L2 §6.5.1: EdDSA requires an OKP key type.
#[test]
fn test_eddsa_with_ec2_key_type_is_rejected() {
    // kty = EC2 (2) but alg = EdDSA (-8), which requires OKP.
    let cose_key = make_ec2_cose_key_with(-8, 6, &[1u8; 32], &[2u8; 32]);

    let err = verify_cose_signature(&cose_key, b"message", &[0u8; 64]).unwrap_err();
    assert!(
        matches!(err, VerifyError::InvalidCoseKey(ref m) if m.contains("kty")),
        "error must name the key-type mismatch, got: {err:?}"
    );
}

/// An unknown algorithm still reports `UnsupportedAlgorithm`, not a mismatch.
// WebAuthn L2 §6.5.1: an unrecognized alg is reported as unsupported.
#[test]
fn test_unknown_algorithm_reports_unsupported() {
    let cose_key = make_ec2_cose_key_with(-999, 1, &[1u8; 32], &[2u8; 32]);

    assert!(matches!(
        verify_cose_signature(&cose_key, b"message", &[0u8; 64]),
        Err(VerifyError::UnsupportedAlgorithm(-999))
    ));
}

/// The conformant triple still verifies, so the check is not simply refusing
/// everything.
// WebAuthn L2 §6.5.1: the conformant ES256/EC2/P-256 combination verifies.
#[test]
fn test_conformant_es256_p256_triple_still_verifies() {
    let message = b"webauthn assertion signing input";
    let (cose_key, der, _raw) = es256_fixture(message);

    assert!(verify_cose_signature(&cose_key, message, &der).is_ok());
}

/// An EC2 key carrying no `crv` label is malformed: RFC 9053 Section 2.1
/// requires the curve be checked, which is impossible when it is absent.
// WebAuthn L2 §6.5.1: an EC2 key must carry a crv parameter.
#[test]
fn test_ec2_key_without_curve_is_rejected() {
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
            ciborium::Value::Integer((-2).into()),
            ciborium::Value::Bytes(vec![1u8; 32]),
        ),
        (
            ciborium::Value::Integer((-3).into()),
            ciborium::Value::Bytes(vec![2u8; 32]),
        ),
    ]);
    ciborium::into_writer(&key, &mut buf).unwrap();

    let err = verify_cose_signature(&buf, b"message", &[0u8; 70]).unwrap_err();
    assert!(
        matches!(err, VerifyError::InvalidCoseKey(ref m) if m.contains("crv")),
        "a curveless EC2 key must be rejected for the missing crv, got: {err:?}"
    );
}

// =========================================================================
// WebAuthn L2 §8.2 — packed attestation statement format
// =========================================================================

/// Wrap auth_data into a CBOR attestation object with an arbitrary `fmt` and
/// attestation statement.
fn make_attestation_object(
    fmt: &str,
    att_stmt: Vec<(ciborium::Value, ciborium::Value)>,
    auth_data: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    let value = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("fmt".to_string()),
            ciborium::Value::Text(fmt.to_string()),
        ),
        (
            ciborium::Value::Text("attStmt".to_string()),
            ciborium::Value::Map(att_stmt),
        ),
        (
            ciborium::Value::Text("authData".to_string()),
            ciborium::Value::Bytes(auth_data.to_vec()),
        ),
    ]);
    ciborium::into_writer(&value, &mut buf).unwrap();
    buf
}

/// A self-attestation `attStmt`: `alg` plus `sig`, and no `x5c`.
fn self_att_stmt(alg: Option<i64>) -> Vec<(ciborium::Value, ciborium::Value)> {
    let mut entries = vec![(
        ciborium::Value::Text("sig".to_string()),
        ciborium::Value::Bytes(vec![0u8; 64]),
    )];
    if let Some(alg) = alg {
        entries.push((
            ciborium::Value::Text("alg".to_string()),
            ciborium::Value::Integer(alg.into()),
        ));
    }
    entries
}

/// Run registration over a packed self-attestation carrying `alg`, against a
/// credential public key that is EdDSA (COSE alg -8).
fn verify_self_attestation(fmt: &str, alg: Option<i64>) -> Result<(), VerifyError> {
    let rp_id = "example.com";
    let challenge = "test-challenge";
    let origin = "https://example.com";
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);
    let auth_data = make_registration_auth_data(rp_id, [1; 16], b"cred-id", &cose_key);
    let attestation = make_attestation_object(fmt, self_att_stmt(alg), &auth_data);
    let client_data = make_client_data_json("webauthn.create", challenge, origin);

    verify_registration_with_verifier(
        &RegistrationParams {
            attestation_object: &attestation,
            client_data_json: &client_data,
            expected_rp_id: rp_id,
            expected_challenge: challenge,
            expected_origin: origin,
            require_user_verification: true,
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &TestCoseVerifier::always_succeed(),
    )
    .map(|_| ())
}

/// WebAuthn L2 §8.2, verification procedure step 3: "If x5c is not present,
/// self attestation is in use." Its first sub-step is "Validate that alg
/// matches the algorithm of the credentialPublicKey in authenticatorData."
///
/// The credential key here is EdDSA (-8), so a statement declaring ES256 (-7)
/// fails that step. Nothing downstream catches it: the signature is verified
/// with the algorithm the *key* names, so without this check the declared
/// value simply goes unread.
#[test]
fn test_packed_self_attestation_rejects_alg_mismatch() {
    let err = verify_self_attestation("packed", Some(-7)).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::AttestationAlgMismatch { declared: -7, .. }
        ),
        "got {err:?}"
    );
}

/// The matching half of §8.2 step 3: `alg` equal to the credential public
/// key's algorithm passes the check and the statement verifies.
#[test]
fn test_packed_self_attestation_accepts_matching_alg() {
    assert!(verify_self_attestation("packed", Some(-8)).is_ok());
}

/// WebAuthn L2 §8.2 gives the packed syntax in CDDL, where `alg:
/// COSEAlgorithmIdentifier` is a member of both arms — the one with `x5c` and
/// the self-attestation one. Step 1 of the verification procedure is "Verify
/// that attStmt is valid CBOR conforming to the syntax defined above and
/// perform CBOR decoding on it to extract the contained fields", so a
/// statement missing `alg` does not conform.
#[test]
fn test_packed_attestation_requires_alg() {
    let err = verify_self_attestation("packed", None).unwrap_err();
    assert!(
        matches!(err, VerifyError::InvalidClientData(ref m) if m.contains("alg")),
        "got {err:?}"
    );
}

/// WebAuthn L2 §8.1: "Implementations MUST match WebAuthn attestation
/// statement format identifiers in a case-sensitive fashion."
///
/// `Packed` is not `packed`, so the packed verification procedure — and the
/// `alg` check that rejects the statement above — must not run for it.
#[test]
fn test_attestation_format_identifiers_match_case_sensitively() {
    // The identical statement, rejected under the registered identifier.
    assert!(verify_self_attestation("packed", Some(-7)).is_err());

    // Under a differently-cased identifier it is not a packed statement at
    // all, so no packed rule is applied to it.
    assert!(
        verify_self_attestation("Packed", Some(-7)).is_ok(),
        "a case variant must not be treated as the packed format"
    );
}

/// The §8.2 CDDL types every x5c element as `bytes`
/// (`x5c: [ attestnCert: bytes, * (caCert: bytes) ]`), and step 1 of the
/// verification procedure requires "that attStmt is valid CBOR conforming to
/// the syntax defined above". A packed x5c carrying a non-byte-string element
/// is malformed and must be rejected, not repaired by dropping the element —
/// webauthn-rs rejects the same input on the browser path.
#[test]
fn test_packed_rejects_x5c_with_non_byte_string_element() {
    // The genuine fixture, with junk appended to its otherwise-valid chain.
    let raw = real_packed_attestation();
    let mut value: ciborium::Value =
        ciborium::from_reader(raw.as_slice()).expect("fixture is CBOR");
    if let ciborium::Value::Map(ref mut entries) = value {
        for (k, v) in entries.iter_mut() {
            if k.as_text() == Some("attStmt")
                && let ciborium::Value::Map(ref mut stmt) = *v
            {
                for (sk, sv) in stmt.iter_mut() {
                    if sk.as_text() == Some("x5c")
                        && let ciborium::Value::Array(ref mut arr) = *sv
                    {
                        arr.push(ciborium::Value::Text("junk".to_string()));
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("CBOR serialization");

    let err = verify_registration_with_verifier(
        &RegistrationParams {
            attestation_object: &out,
            client_data_json: &fixture_client_data(),
            expected_rp_id: "localhost",
            expected_challenge: "test-challenge",
            expected_origin: "http://localhost",
            require_user_verification: true,
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &RealCoseVerifier::new(),
    )
    .expect_err("a packed x5c with a non-byte-string element must be rejected");
    assert!(
        matches!(err, VerifyError::AttestationChainInvalid(ref m) if m.contains("non-byte-string")),
        "expected a non-byte-string extraction error, got {err:?}"
    );
}

/// §8.2 step 3 keys self attestation to absence: "If x5c is not present, self
/// attestation is in use." An x5c that is present but empty is neither a
/// conforming chain nor absence, so it is rejected as malformed rather than
/// silently downgraded to the self-attestation path.
#[test]
fn test_packed_rejects_empty_x5c_array() {
    let rp_id = "example.com";
    let challenge = "test-challenge";
    let origin = "https://example.com";
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);
    let auth_data = make_registration_auth_data(rp_id, [1; 16], b"cred-id", &cose_key);
    let mut att_stmt = self_att_stmt(Some(-8));
    att_stmt.push((
        ciborium::Value::Text("x5c".to_string()),
        ciborium::Value::Array(vec![]),
    ));
    let attestation = make_attestation_object("packed", att_stmt, &auth_data);
    let client_data = make_client_data_json("webauthn.create", challenge, origin);

    let err = verify_registration_with_verifier(
        &RegistrationParams {
            attestation_object: &attestation,
            client_data_json: &client_data,
            expected_rp_id: rp_id,
            expected_challenge: challenge,
            expected_origin: origin,
            require_user_verification: true,
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &TestCoseVerifier::always_succeed(),
    )
    .expect_err("a present-but-empty x5c must not fall back to self attestation");
    assert!(
        matches!(err, VerifyError::AttestationChainInvalid(ref m) if m.contains("empty")),
        "expected an empty-x5c extraction error, got {err:?}"
    );
}

// =========================================================================
// Unverified attestation formats do not convey an AAGUID
// =========================================================================

/// Run registration over an attestation of `fmt` whose authData carries
/// `aaguid`, and return the AAGUID the verifier reports.
fn aaguid_reported_for(fmt: &str, aaguid: [u8; 16]) -> Option<String> {
    let rp_id = "example.com";
    let challenge = "test-challenge";
    let origin = "https://example.com";
    let cose_key = make_eddsa_cose_key(&[0u8; 32]);
    let auth_data = make_registration_auth_data(rp_id, aaguid, b"cred-id", &cose_key);
    let attestation = make_attestation_object(fmt, self_att_stmt(Some(-8)), &auth_data);
    let client_data = make_client_data_json("webauthn.create", challenge, origin);

    verify_registration_with_verifier(
        &RegistrationParams {
            attestation_object: &attestation,
            client_data_json: &client_data,
            expected_rp_id: rp_id,
            expected_challenge: challenge,
            expected_origin: origin,
            require_user_verification: true,
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &TestCoseVerifier::always_succeed(),
    )
    .unwrap()
    .aaguid
}

/// Formats without a verification procedure here (the `other` arm) discard the
/// authData AAGUID, so it cannot be reported as the authenticator's identity.
/// `fido-u2f` no longer reaches this arm — it has its own verifying arm now
/// (see the fido-u2f tests below) — so a platform format (`tpm`) stands in
/// here for any format the `other` arm still accepts. The registration
/// chokepoint rejects these formats afterwards; this is the defense-in-depth
/// AAGUID suppression the `other` arm provides.
#[test]
fn test_unverified_format_does_not_convey_an_aaguid() {
    let forged = [
        0x28, 0x96, 0x9c, 0x24, 0x04, 0x87, 0x4a, 0x46, 0xbe, 0x39, 0x37, 0xbc, 0x63, 0x37, 0xa2,
        0x4f,
    ];
    assert_eq!(
        aaguid_reported_for("tpm", forged),
        None,
        "an AAGUID from an attestation format with no verification procedure must be discarded"
    );
}

/// The packed path still reports its AAGUID: §8.2 step 3 verifies the
/// self-attestation signature, so the value is at least bound to the
/// credential key. Guards against the suppression above being applied too
/// broadly.
#[test]
fn test_packed_still_conveys_its_aaguid() {
    assert_eq!(
        aaguid_reported_for("packed", [1; 16]),
        Some("01010101-0101-0101-0101-010101010101".to_string())
    );
}

// =========================================================================
// WebAuthn L2 §8.3 — fido-u2f attestation statement format
//
// The `other` arm used to admit `fido-u2f` without ever reading `attStmt.sig`,
// so a captured chain (whose x5c validates against a pinned Yubico root)
// could be replayed under `fmt = "fido-u2f"` with any credential public key
// and a non-verifying signature. The chokepoint then stamped the certificate's
// AAGUID onto the authenticator row — re-opening the issue #1111 AAGUID
// forgery against the `fido-u2f` format (the browser path was safe: webauthn-rs
// verifies this signature). The arm now verifies `attStmt.sig` over
// `0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F` with the
// leaf cert's public key, mirroring `verify_fidou2f_attestation`.
// =========================================================================

/// AAGUID of the YubiKey 5C Nano FIPS (Enterprise) the fixture was captured
/// from — the value a forged registration would stamp onto the authenticator
/// row.
const FIPS_FIXTURE_AAGUID: [u8; 16] = [
    0x28, 0x96, 0x9c, 0x24, 0x04, 0x87, 0x4a, 0x46, 0xbe, 0x39, 0x37, 0xbc, 0x63, 0x37, 0xa2, 0x4f,
];

/// The genuine captured `packed` fixture, whose x5c chain validates against a
/// pinned Yubico root and whose leaf carries the FIPS AAGUID. See
/// `crypto/attestation_chain/fixtures/README.md`. Synthetic certificates cannot
/// chain to `PINNED_ROOTS`, so this is the only input that exercises the arm
/// against a chain the chokepoint would accept.
fn real_packed_attestation() -> Vec<u8> {
    use base64::Engine as _;
    let b64 = include_str!(
        "../attestation_chain/fixtures/yubikey-5c-nano-fips-enterprise.attestation.b64"
    );
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64.trim())
        .expect("fixture is valid base64url")
}

/// Pull the fixture's `authData` and `x5c` leaf certificate out as borrowed
/// views, for re-encoding under a different `fmt`.
fn fixture_auth_data_and_x5c() -> (Vec<u8>, Vec<u8>) {
    let raw = real_packed_attestation();
    let value: ciborium::Value = ciborium::from_reader(raw.as_slice()).expect("fixture is CBOR");
    let map = value.as_map().expect("attestation object is a CBOR map");
    let auth_data = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("authData"))
        .and_then(|(_, v)| v.as_bytes())
        .expect("fixture has authData")
        .to_vec();
    let x5c = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("attStmt"))
        .and_then(|(_, v)| v.as_map())
        .expect("fixture has attStmt")
        .iter()
        .find(|(k, _)| k.as_text() == Some("x5c"))
        .and_then(|(_, v)| v.as_array())
        .expect("fixture has x5c")
        .first()
        .and_then(|c| c.as_bytes())
        .expect("fixture x5c[0] is a byte string")
        .to_vec();
    (auth_data, x5c)
}

/// Encode a `fmt = "fido-u2f"` attestation object that reuses the fixture's
/// genuine `authData` and `x5c` leaf certificate, with `attStmt.sig` set to
/// `sig`. The fixture's original `alg` member is dropped: fido-u2f carries
/// only `x5c` and `sig` (WebAuthn L2 §8.3).
fn fixture_rewrapped_as_fido_u2f(sig: Vec<u8>) -> Vec<u8> {
    let (auth_data, x5c) = fixture_auth_data_and_x5c();
    let att_stmt = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("x5c".to_string()),
            ciborium::Value::Array(vec![ciborium::Value::Bytes(x5c)]),
        ),
        (
            ciborium::Value::Text("sig".to_string()),
            ciborium::Value::Bytes(sig),
        ),
    ]);
    let value = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("fmt".to_string()),
            ciborium::Value::Text("fido-u2f".to_string()),
        ),
        (ciborium::Value::Text("attStmt".to_string()), att_stmt),
        (
            ciborium::Value::Text("authData".to_string()),
            ciborium::Value::Bytes(auth_data),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("CBOR serialization");
    out
}

/// The fixture's original `packed` attStmt signature (a real DER ECDSA sig,
/// but over `authData || clientDataHash`, not the fido-u2f verification data).
fn fixture_original_packed_sig() -> Vec<u8> {
    let raw = real_packed_attestation();
    let value: ciborium::Value = ciborium::from_reader(raw.as_slice()).expect("fixture is CBOR");
    let map = value.as_map().expect("attestation object is a CBOR map");
    map.iter()
        .find(|(k, _)| k.as_text() == Some("attStmt"))
        .and_then(|(_, v)| v.as_map())
        .expect("fixture has attStmt")
        .iter()
        .find(|(k, _)| k.as_text() == Some("sig"))
        .and_then(|(_, v)| v.as_bytes())
        .expect("fixture attStmt has sig")
        .to_vec()
}

/// Client-data JSON for the fixture, whose `rpIdHash` is SHA-256 of
/// `localhost`. The challenge and origin are chosen to satisfy the verifier's
/// client-data checks under loopback relaxation; the attestation signature is
/// verified over `clientDataHash`, so the specific values do not have to match
/// the original capture.
fn fixture_client_data() -> Vec<u8> {
    make_client_data_json("webauthn.create", "test-challenge", "http://localhost")
}

/// Verify a fido-u2f registration built from the fixture, with loopback origin
/// relaxation and `rp_id = "localhost"` (the fixture's `rpIdHash`).
fn verify_fixture_fido_u2f(
    attestation: &[u8],
) -> Result<RegistrationVerificationResult, VerifyError> {
    verify_registration_with_verifier(
        &RegistrationParams {
            attestation_object: attestation,
            client_data_json: &fixture_client_data(),
            expected_rp_id: "localhost",
            expected_challenge: "test-challenge",
            expected_origin: "http://localhost",
            require_user_verification: true,
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &RealCoseVerifier::new(),
    )
}

/// WebAuthn L2 §8.3, verification procedure step 2: `attStmt.sig` must verify
/// over `0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F`
/// using the leaf certificate's public key. A fido-u2f statement with bytes
/// that are not a valid signature over that data must be rejected — the
/// issue #1111 forgery against the `fido-u2f` format. The old `other` arm
/// accepted this input; the verifying arm must not.
#[test]
fn test_fido_u2f_rejects_non_verifying_sig() {
    let forged = fixture_rewrapped_as_fido_u2f(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let err = verify_fixture_fido_u2f(&forged)
        .expect_err("a non-verifying fido-u2f sig must be rejected");
    assert!(
        matches!(err, VerifyError::SignatureInvalid),
        "expected SignatureInvalid, got {err:?}"
    );
}

/// The fixture's real `packed` signature is a well-formed DER ECDSA sig, but
/// it was computed over `authData || clientDataHash` (the packed verification
/// data), not the fido-u2f verification data. It must still fail verification
/// — proving the arm runs the fido-u2f signature check (under the old `other`
/// arm, this input was accepted, signature unread).
#[test]
fn test_fido_u2f_rejects_packed_sig_replayed_over_fido_u2f_data() {
    let forged = fixture_rewrapped_as_fido_u2f(fixture_original_packed_sig());
    let err = verify_fixture_fido_u2f(&forged)
        .expect_err("a packed sig replayed under fido-u2f must not verify over the U2F data");
    assert!(
        matches!(err, VerifyError::SignatureInvalid),
        "expected SignatureInvalid, got {err:?}"
    );
}

/// WebAuthn L2 §8.3 requires `attStmt` to be present with `x5c` and `sig`.
/// A fido-u2f statement with no `x5c` array is rejected before any signature
/// work — it cannot bind the credential to a certificate at all.
#[test]
fn test_fido_u2f_rejects_missing_x5c() {
    let (auth_data, _) = fixture_auth_data_and_x5c();
    let att_stmt = ciborium::Value::Map(vec![(
        ciborium::Value::Text("sig".to_string()),
        ciborium::Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    )]);
    let value = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("fmt".to_string()),
            ciborium::Value::Text("fido-u2f".to_string()),
        ),
        (ciborium::Value::Text("attStmt".to_string()), att_stmt),
        (
            ciborium::Value::Text("authData".to_string()),
            ciborium::Value::Bytes(auth_data),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("CBOR serialization");

    let err = verify_fixture_fido_u2f(&out).expect_err("fido-u2f without x5c must be rejected");
    assert!(
        matches!(err, VerifyError::AttestationChainInvalid(ref m) if m.contains("x5c")),
        "expected an x5c-related chain error, got {err:?}"
    );
}

/// A fido-u2f statement with `x5c` but no `sig` cannot prove the credential
/// is bound to the certificate and is rejected.
#[test]
fn test_fido_u2f_rejects_missing_sig() {
    let (auth_data, x5c) = fixture_auth_data_and_x5c();
    let att_stmt = ciborium::Value::Map(vec![(
        ciborium::Value::Text("x5c".to_string()),
        ciborium::Value::Array(vec![ciborium::Value::Bytes(x5c)]),
    )]);
    let value = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("fmt".to_string()),
            ciborium::Value::Text("fido-u2f".to_string()),
        ),
        (ciborium::Value::Text("attStmt".to_string()), att_stmt),
        (
            ciborium::Value::Text("authData".to_string()),
            ciborium::Value::Bytes(auth_data),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("CBOR serialization");

    let err = verify_fixture_fido_u2f(&out).expect_err("fido-u2f without sig must be rejected");
    assert!(
        matches!(err, VerifyError::InvalidClientData(ref m) if m.contains("sig")),
        "expected a missing-sig error, got {err:?}"
    );
}

/// WebAuthn L2 §8.3 step 2: "Check that x5c has exactly one element and let
/// attCert be that element." A fido-u2f statement that carries a chain rather
/// than the lone leaf certificate is not a conforming U2F statement and is
/// rejected here, before the signature is inspected.
#[test]
fn test_fido_u2f_rejects_multi_element_x5c() {
    let (auth_data, x5c) = fixture_auth_data_and_x5c();
    let att_stmt = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("x5c".to_string()),
            // Two copies of the leaf; not a conforming U2F statement.
            ciborium::Value::Array(vec![
                ciborium::Value::Bytes(x5c.clone()),
                ciborium::Value::Bytes(x5c),
            ]),
        ),
        (
            ciborium::Value::Text("sig".to_string()),
            ciborium::Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        ),
    ]);
    let value = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("fmt".to_string()),
            ciborium::Value::Text("fido-u2f".to_string()),
        ),
        (ciborium::Value::Text("attStmt".to_string()), att_stmt),
        (
            ciborium::Value::Text("authData".to_string()),
            ciborium::Value::Bytes(auth_data),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("CBOR serialization");

    let err =
        verify_fixture_fido_u2f(&out).expect_err("a multi-element fido-u2f x5c must be rejected");
    assert!(
        matches!(err, VerifyError::AttestationChainInvalid(ref m) if m.contains("exactly one")),
        "expected an exactly-one-element error, got {err:?}"
    );
}

/// The §8.3 CDDL types x5c as `[ attestnCert: bytes ]`, so every element must
/// be a byte string. An `x5c` of `[leaf, "junk"]` must be rejected as
/// malformed rather than filtered down to the lone leaf, which would let it
/// satisfy step 2's exactly-one-element check on an array that actually
/// carries two (issue #1167).
#[test]
fn test_fido_u2f_rejects_x5c_with_non_byte_string_element() {
    let (auth_data, x5c) = fixture_auth_data_and_x5c();
    let att_stmt = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("x5c".to_string()),
            ciborium::Value::Array(vec![
                ciborium::Value::Bytes(x5c),
                ciborium::Value::Text("junk".to_string()),
            ]),
        ),
        (
            ciborium::Value::Text("sig".to_string()),
            ciborium::Value::Bytes(fixture_original_packed_sig()),
        ),
    ]);
    let value = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("fmt".to_string()),
            ciborium::Value::Text("fido-u2f".to_string()),
        ),
        (ciborium::Value::Text("attStmt".to_string()), att_stmt),
        (
            ciborium::Value::Text("authData".to_string()),
            ciborium::Value::Bytes(auth_data),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("CBOR serialization");

    let err = verify_fixture_fido_u2f(&out)
        .expect_err("an x5c with a non-byte-string element must be rejected");
    assert!(
        matches!(err, VerifyError::AttestationChainInvalid(ref m) if m.contains("non-byte-string")),
        "expected a non-byte-string extraction error, got {err:?}"
    );
}

/// An `x5c` member that is not an array at all does not conform to the §8.3
/// CDDL and is rejected as malformed, not treated as an absent chain.
#[test]
fn test_fido_u2f_rejects_non_array_x5c() {
    let (auth_data, x5c) = fixture_auth_data_and_x5c();
    let att_stmt = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("x5c".to_string()),
            ciborium::Value::Bytes(x5c),
        ),
        (
            ciborium::Value::Text("sig".to_string()),
            ciborium::Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        ),
    ]);
    let value = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("fmt".to_string()),
            ciborium::Value::Text("fido-u2f".to_string()),
        ),
        (ciborium::Value::Text("attStmt".to_string()), att_stmt),
        (
            ciborium::Value::Text("authData".to_string()),
            ciborium::Value::Bytes(auth_data),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("CBOR serialization");

    let err = verify_fixture_fido_u2f(&out).expect_err("a non-array x5c must be rejected");
    assert!(
        matches!(err, VerifyError::AttestationChainInvalid(ref m) if m.contains("not an array")),
        "expected a not-an-array extraction error, got {err:?}"
    );
}

/// A fido-u2f attestation object with no `attStmt` at all is rejected: the
/// format has no "none" equivalent.
#[test]
fn test_fido_u2f_rejects_missing_att_stmt() {
    let (auth_data, _) = fixture_auth_data_and_x5c();
    let value = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("fmt".to_string()),
            ciborium::Value::Text("fido-u2f".to_string()),
        ),
        (
            ciborium::Value::Text("attStmt".to_string()),
            ciborium::Value::Map(vec![]),
        ),
        (
            ciborium::Value::Text("authData".to_string()),
            ciborium::Value::Bytes(auth_data),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("CBOR serialization");

    let err =
        verify_fixture_fido_u2f(&out).expect_err("fido-u2f with an empty attStmt must be rejected");
    assert!(
        matches!(err, VerifyError::AttestationChainInvalid(ref m) if m.contains("x5c")),
        "expected an x5c-related error for an empty attStmt, got {err:?}"
    );
}

/// `publicKeyU2F` is the credential public key in SEC1 uncompressed form, and
/// U2F authenticators register EC2/P-256 keys exclusively. An EdDSA (OKP)
/// credential key has no SEC1 uncompressed encoding and must be rejected
/// rather than fed to the verifier.
#[test]
fn test_fido_u2f_rejects_non_ec2_credential_key() {
    let rp_id = "localhost";
    let cose_key = make_eddsa_cose_key(&[1u8; 32]); // OKP/Ed25519, not EC2
    let auth_data = make_registration_auth_data(rp_id, FIPS_FIXTURE_AAGUID, b"cred-id", &cose_key);
    let att_stmt = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("x5c".to_string()),
            ciborium::Value::Array(vec![ciborium::Value::Bytes(fixture_auth_data_and_x5c().1)]),
        ),
        (
            ciborium::Value::Text("sig".to_string()),
            ciborium::Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        ),
    ]);
    let value = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("fmt".to_string()),
            ciborium::Value::Text("fido-u2f".to_string()),
        ),
        (ciborium::Value::Text("attStmt".to_string()), att_stmt),
        (
            ciborium::Value::Text("authData".to_string()),
            ciborium::Value::Bytes(auth_data),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("CBOR serialization");

    let err = verify_fixture_fido_u2f(&out)
        .expect_err("a non-EC2 credential key must not be accepted as a U2F publicKeyU2F");
    assert!(
        matches!(err, VerifyError::InvalidCoseKey(ref m) if m.contains("EC2")),
        "expected an EC2 key-type error, got {err:?}"
    );
}

/// An EC2 key on the wrong curve (P-384) is also not a U2F `publicKeyU2F` and
/// must be rejected for the curve, not passed to a P-256 verifier.
#[test]
fn test_fido_u2f_rejects_non_p256_credential_key() {
    let rp_id = "localhost";
    // EC2 but crv = P-384 (2).
    let cose_key = make_ec2_cose_key_with(-7, 2, &[1u8; 32], &[2u8; 32]);
    let auth_data = make_registration_auth_data(rp_id, FIPS_FIXTURE_AAGUID, b"cred-id", &cose_key);
    let att_stmt = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("x5c".to_string()),
            ciborium::Value::Array(vec![ciborium::Value::Bytes(fixture_auth_data_and_x5c().1)]),
        ),
        (
            ciborium::Value::Text("sig".to_string()),
            ciborium::Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        ),
    ]);
    let value = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("fmt".to_string()),
            ciborium::Value::Text("fido-u2f".to_string()),
        ),
        (ciborium::Value::Text("attStmt".to_string()), att_stmt),
        (
            ciborium::Value::Text("authData".to_string()),
            ciborium::Value::Bytes(auth_data),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("CBOR serialization");

    let err = verify_fixture_fido_u2f(&out)
        .expect_err("a non-P-256 credential key must not be accepted as a U2F publicKeyU2F");
    assert!(
        matches!(err, VerifyError::InvalidCoseKey(ref m) if m.contains("P-256")),
        "expected a P-256 curve error, got {err:?}"
    );
}

/// `build_fido_u2f_verification_data` must produce exactly
/// `0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F` per
/// WebAuthn L2 §8.3.
#[test]
fn test_build_fido_u2f_verification_data_layout() {
    let rp_id_hash = [0x11u8; 32];
    let client_data_hash = [0x22u8; 32];
    let credential_id = [0x33u8; 4];
    let public_key_u2f = [0x04u8; 65];

    let data = build_fido_u2f_verification_data(
        &rp_id_hash,
        &client_data_hash,
        &credential_id,
        &public_key_u2f,
    );

    assert_eq!(data.len(), 1 + 32 + 32 + 4 + 65);
    assert_eq!(data[0], 0x00);
    assert_eq!(&data[1..33], &rp_id_hash);
    assert_eq!(&data[33..65], &client_data_hash);
    assert_eq!(&data[65..69], &credential_id);
    assert_eq!(&data[69..134], &public_key_u2f);
}

/// `cose_key_to_sec1_uncompressed` converts an EC2/P-256 COSE key to the SEC1
/// uncompressed point `0x04 || x || y` (65 bytes).
#[test]
fn test_cose_key_to_sec1_uncompressed_roundtrip() {
    let (cose_key, _der, _raw) = es256_fixture(b"irrelevant - only the key is read");
    // `es256_fixture` builds a P-256 key from a fixed seed; reuse its COSE key.
    let point = cose_key_to_sec1_uncompressed(&cose_key).expect("EC2/P-256 key converts to SEC1");
    assert_eq!(point.len(), 65);
    assert_eq!(point[0], 0x04);
}

/// A non-EC2 COSE key (OKP/Ed25519) has no SEC1 uncompressed form for U2F and
/// must be rejected.
#[test]
fn test_cose_key_to_sec1_rejects_okp() {
    let cose_key = make_eddsa_cose_key(&[1u8; 32]);
    let err = cose_key_to_sec1_uncompressed(&cose_key).expect_err("OKP is not EC2");
    assert!(matches!(err, VerifyError::InvalidCoseKey(_)), "got {err:?}");
}

/// A fido-u2f registration that verifies end-to-end — a leaf certificate whose
/// private key is held, signing the U2F verification data over an
/// attacker-chosen credential key — must be accepted by the arm. The fixture's
/// captured chain pins to a Yubico root whose private key is unavailable, so
/// the positive path is exercised against a freshly generated self-signed EC
/// P-256 certificate. The chain itself is not checked here (the chokepoint owns
/// chain policy); only the signature that binds the credential to the
/// certificate is.
#[test]
fn test_fido_u2f_accepts_valid_signature() {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};

    // The U2F signing key (the leaf attestation certificate's private key).
    let u2f_signing_key = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
    let point = u2f_signing_key.verifying_key().to_encoded_point(false);
    let x = point.x().unwrap();
    let y = point.y().unwrap();
    let leaf_cert = build_ec_p256_cert(&u2f_signing_key);

    // The credential key being registered (EC2/P-256, the only shape U2F uses).
    let cose_key = make_es256_cose_key(x.as_slice(), y.as_slice());

    let rp_id = "localhost";
    let credential_id: Vec<u8> = (0..32u8).collect();
    let auth_data = make_registration_auth_data(rp_id, [0u8; 16], &credential_id, &cose_key);

    let rp_id_hash = digest::digest(&SHA256, rp_id.as_bytes());
    let client_data =
        make_client_data_json("webauthn.create", "test-challenge", "http://localhost");
    let client_data_hash = digest::digest(&SHA256, &client_data);
    let public_key_u2f = cose_key_to_sec1_uncompressed(&cose_key).unwrap();
    let verification_data = build_fido_u2f_verification_data(
        rp_id_hash.as_ref(),
        client_data_hash.as_ref(),
        &credential_id,
        &public_key_u2f,
    );
    let sig: Signature = u2f_signing_key.sign(&verification_data);
    let sig_der = sig.to_der();

    let att_stmt = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("x5c".to_string()),
            ciborium::Value::Array(vec![ciborium::Value::Bytes(leaf_cert)]),
        ),
        (
            ciborium::Value::Text("sig".to_string()),
            ciborium::Value::Bytes(sig_der.as_bytes().to_vec()),
        ),
    ]);
    let value = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("fmt".to_string()),
            ciborium::Value::Text("fido-u2f".to_string()),
        ),
        (ciborium::Value::Text("attStmt".to_string()), att_stmt),
        (
            ciborium::Value::Text("authData".to_string()),
            ciborium::Value::Bytes(auth_data),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("CBOR serialization");

    let result = verify_registration_with_verifier(
        &RegistrationParams {
            attestation_object: &out,
            client_data_json: &client_data,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "http://localhost",
            require_user_verification: true,
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &RealCoseVerifier::new(),
    )
    .expect("a fido-u2f attestation with a valid signature must be accepted");

    // The authData AAGUID is not signed by a fido-u2f statement, so it is
    // discarded; the model identity comes from the certificate via the
    // chokepoint.
    assert_eq!(result.aaguid, None);
    assert_eq!(result.credential_id, credential_id);
}

/// Tampering with a valid fido-u2f signature must flip the result from
/// accepted to rejected — the security-relevant half of the positive test
/// above.
#[test]
fn test_fido_u2f_rejects_tampered_valid_signature() {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};

    let u2f_signing_key = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
    let point = u2f_signing_key.verifying_key().to_encoded_point(false);
    let x = point.x().unwrap();
    let y = point.y().unwrap();
    let leaf_cert = build_ec_p256_cert(&u2f_signing_key);
    let cose_key = make_es256_cose_key(x.as_slice(), y.as_slice());

    let rp_id = "localhost";
    let credential_id: Vec<u8> = (0..32u8).collect();
    let auth_data = make_registration_auth_data(rp_id, [0u8; 16], &credential_id, &cose_key);

    let rp_id_hash = digest::digest(&SHA256, rp_id.as_bytes());
    let client_data =
        make_client_data_json("webauthn.create", "test-challenge", "http://localhost");
    let client_data_hash = digest::digest(&SHA256, &client_data);
    let public_key_u2f = cose_key_to_sec1_uncompressed(&cose_key).unwrap();
    let verification_data = build_fido_u2f_verification_data(
        rp_id_hash.as_ref(),
        client_data_hash.as_ref(),
        &credential_id,
        &public_key_u2f,
    );
    let sig: Signature = u2f_signing_key.sign(&verification_data);
    let mut sig_bytes = sig.to_der().as_bytes().to_vec();
    // Tamper with the signature: flip the first byte so it no longer verifies.
    sig_bytes[0] ^= 0xFF;

    let att_stmt = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("x5c".to_string()),
            ciborium::Value::Array(vec![ciborium::Value::Bytes(leaf_cert)]),
        ),
        (
            ciborium::Value::Text("sig".to_string()),
            ciborium::Value::Bytes(sig_bytes),
        ),
    ]);
    let value = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("fmt".to_string()),
            ciborium::Value::Text("fido-u2f".to_string()),
        ),
        (ciborium::Value::Text("attStmt".to_string()), att_stmt),
        (
            ciborium::Value::Text("authData".to_string()),
            ciborium::Value::Bytes(auth_data),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("CBOR serialization");

    let err = verify_registration_with_verifier(
        &RegistrationParams {
            attestation_object: &out,
            client_data_json: &client_data,
            expected_rp_id: rp_id,
            expected_challenge: "test-challenge",
            expected_origin: "http://localhost",
            require_user_verification: true,
            origin_policy: OriginPolicy::AllowLoopbackVariations,
        },
        &RealCoseVerifier::new(),
    )
    .expect_err("a tampered fido-u2f signature must be rejected");
    assert!(
        matches!(err, VerifyError::SignatureInvalid),
        "expected SignatureInvalid, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Minimal DER helpers and an EC P-256 self-signed certificate builder, for the
// fido-u2f positive tests. The certificate is not chained to a pinned root —
// the fido-u2f arm checks the signature, not the chain (the chokepoint owns
// chain policy) — so a self-signed cert with a held key is sufficient.
// ---------------------------------------------------------------------------

/// DER length-prefix `content` with `tag`.
#[expect(
    clippy::cast_possible_truncation,
    reason = "test-only DER helper; lengths here are small"
)]
fn u2f_der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    }
    out.extend_from_slice(content);
    out
}

fn u2f_der_seq(items: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for item in items {
        content.extend_from_slice(item);
    }
    u2f_der_wrap(0x30, &content)
}

fn u2f_der_int(value: &[u8]) -> Vec<u8> {
    u2f_der_wrap(0x02, value)
}

fn u2f_der_bitstring(value: &[u8]) -> Vec<u8> {
    let mut content = vec![0x00]; // no unused bits
    content.extend_from_slice(value);
    u2f_der_wrap(0x03, &content)
}

fn u2f_der_set(items: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for item in items {
        content.extend_from_slice(item);
    }
    u2f_der_wrap(0x31, &content)
}

/// Build a self-signed X.509 v3 DER certificate with an EC P-256 public key,
/// signed with ECDSA P-256 SHA-256.
fn build_ec_p256_cert(signing_key: &p256::ecdsa::SigningKey) -> Vec<u8> {
    use p256::ecdsa::signature::Signer;

    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let x = point.x().unwrap();
    let y = point.y().unwrap();

    // AlgorithmIdentifier for id-ecPublicKey with params prime256v1.
    let ec_pk_oid: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    let p256_oid: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let pk_alg_id = u2f_der_seq(&[ec_pk_oid, p256_oid]);

    // SubjectPublicKeyInfo: the BIT STRING holds 0x04 || x || y.
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(x.as_slice());
    sec1.extend_from_slice(y.as_slice());
    let spki = u2f_der_seq(&[&pk_alg_id, &u2f_der_bitstring(&sec1)]);

    // signatureAlgorithm: ecdsa-with-SHA256 (used for both the TBS signature
    // field and the certificate's signatureAlgorithm).
    let sig_alg_oid: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    let sig_alg_id = u2f_der_seq(&[sig_alg_oid]);

    // Version v3 (explicit [0] wrapping INTEGER 2).
    let version: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x02];
    let serial = u2f_der_int(&[0x01]);

    // Issuer/Subject: CN=U2F.
    // Name ::= SEQUENCE { RDNSequence }, RDNSequence ::= SEQUENCE OF SET OF SEQUENCE { OID, value }.
    let cn_oid: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
    let cn_value: &[u8] = &[0x0c, 0x03, b'U', b'2', b'F'];
    let attr = u2f_der_seq(&[cn_oid, cn_value]); // SEQUENCE { OID, UTF8String }
    let rdn = u2f_der_set(&[&attr]); // SET { attr }
    let name = u2f_der_seq(&[&rdn]); // SEQUENCE { rdn }

    // Validity (UTCTime): valid 2024-2049.
    let not_before: &[u8] = b"\x17\x0d240101000000Z";
    let not_after: &[u8] = b"\x17\x0d490101000000Z";
    let validity = u2f_der_seq(&[not_before, not_after]);

    let tbs = u2f_der_seq(&[
        version,
        &serial,
        &sig_alg_id,
        &name,
        &validity,
        &name,
        &spki,
    ]);

    let sig: p256::ecdsa::Signature = signing_key.sign(&tbs);
    let sig_der = sig.to_der();

    u2f_der_seq(&[&tbs, &sig_alg_id, &u2f_der_bitstring(sig_der.as_bytes())])
}
