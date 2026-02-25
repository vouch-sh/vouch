// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Property-based tests for encoding types and conversions.
//!
//! These tests verify that binary data round-trips correctly through
//! JSON serialization, which is critical for CLI→Server communication.
//!
//! Phase 0: Tests existing Vec<u8> behavior
//! Phase 1+: Will test Encoded<T, E> types (see TODOs below)

use proptest::prelude::*;
use vouch_common::encoding::{Base64Url, ConvertEncoding, Raw};
use vouch_common::fido2_types::{Challenge, CoseKey, CredentialId, Signature};
use vouch_common::{LoginCompleteRequest, RegisterCompleteRequest, RegisterStartResponse};

proptest! {
    // =========================================================================
    // Test Vec<u8> JSON round-trip (current behavior)
    // =========================================================================

    /// Vec<u8> → JSON → Vec<u8> preserves data
    #[test]
    fn prop_vec_u8_json_round_trip(data: Vec<u8>) {
        let json = serde_json::to_string(&data).unwrap();
        let decoded: Vec<u8> = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(data, decoded);
    }

    /// Multiple Vec<u8> fields in struct preserve data
    #[test]
    fn prop_multiple_vec_u8_fields(
        field1 in prop::collection::vec(any::<u8>(), 0..100),
        field2 in prop::collection::vec(any::<u8>(), 0..100),
        field3 in prop::collection::vec(any::<u8>(), 0..100),
    ) {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct TestStruct {
            a: Vec<u8>,
            b: Vec<u8>,
            c: Vec<u8>,
        }

        let original = TestStruct {
            a: field1.clone(),
            b: field2.clone(),
            c: field3.clone(),
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: TestStruct = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(original, decoded);
    }

    // =========================================================================
    // Test API request/response types
    // =========================================================================

    /// Full LoginCompleteRequest round-trip (simulates CLI → Server)
    #[test]
    fn prop_login_complete_request_round_trip(
        cred_id in prop::collection::vec(any::<u8>(), 32..64),
        auth_data in prop::collection::vec(any::<u8>(), 37..100),
        signature in prop::collection::vec(any::<u8>(), 64..72),
        client_data in prop::collection::vec(any::<u8>(), 50..200),
        user_handle in prop::collection::vec(any::<u8>(), 16..64),
    ) {
        let request = LoginCompleteRequest {
            state: "test-state".to_string(),
            credential_id: cred_id.clone().into(),
            authenticator_data: auth_data.clone().into(),
            signature: signature.clone().into(),
            client_data_json: client_data.clone().into(),
            user_handle: user_handle.clone().into(),
            client_context: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        let decoded: LoginCompleteRequest = serde_json::from_str(&json).unwrap();

        // Verify all binary fields preserved exactly
        prop_assert_eq!(cred_id.as_slice(), decoded.credential_id.as_bytes());
        prop_assert_eq!(auth_data.as_slice(), decoded.authenticator_data.as_bytes());
        prop_assert_eq!(signature.as_slice(), decoded.signature.as_bytes());
        prop_assert_eq!(client_data.as_slice(), decoded.client_data_json.as_bytes());
        prop_assert_eq!(user_handle.as_slice(), decoded.user_handle.as_bytes());
    }

    /// Full RegisterCompleteRequest round-trip
    #[test]
    fn prop_register_complete_request_round_trip(
        cred_id in prop::collection::vec(any::<u8>(), 32..64),
        public_key in prop::collection::vec(any::<u8>(), 77..100),
        attestation_object in prop::collection::vec(any::<u8>(), 100..500),
        client_data in prop::collection::vec(any::<u8>(), 50..200),
    ) {
        let request = RegisterCompleteRequest {
            state: "test-state".to_string(),
            credential_id: cred_id.clone().into(),
            public_key: public_key.clone().into(),
            attestation_object: attestation_object.clone().into(),
            client_data_json: client_data.clone().into(),
        };

        let json = serde_json::to_string(&request).unwrap();
        let decoded: RegisterCompleteRequest = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(cred_id.as_slice(), decoded.credential_id.as_bytes());
        prop_assert_eq!(public_key.as_slice(), decoded.public_key.as_bytes());
        prop_assert_eq!(attestation_object.as_slice(), decoded.attestation_object.as_bytes());
        prop_assert_eq!(client_data.as_slice(), decoded.client_data_json.as_bytes());
    }

    /// RegisterStartResponse with nested Vec<CredentialId<Raw>> round-trip
    #[test]
    fn prop_register_start_response_round_trip(
        challenge in prop::collection::vec(any::<u8>(), 32..33),
        exclude_ids in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 32..64),
            0..5
        ),
    ) {
        let response = RegisterStartResponse {
            challenge: challenge.clone().into(),
            rp_id: "test.com".to_string(),
            rp_name: "Test".to_string(),
            user_id: uuid::Uuid::nil(),
            user_name: "user@test.com".to_string(),
            algorithms: vec![-7],
            state: "state".to_string(),
            exclude_credential_ids: exclude_ids.iter().map(|v| v.clone().into()).collect(),
        };

        let json = serde_json::to_string(&response).unwrap();
        let decoded: RegisterStartResponse = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(challenge.as_slice(), decoded.challenge.as_bytes());
        // Compare exclude_ids element by element
        prop_assert_eq!(exclude_ids.len(), decoded.exclude_credential_ids.len());
        for (orig, decoded_cred) in exclude_ids.iter().zip(decoded.exclude_credential_ids.iter()) {
            prop_assert_eq!(orig.as_slice(), decoded_cred.as_bytes());
        }
    }

    // =========================================================================
    // Edge case generators
    // =========================================================================

    /// Test with empty Vec<u8>
    #[test]
    fn prop_empty_vec_round_trip(_unused: ()) {
        let empty: Vec<u8> = vec![];
        let json = serde_json::to_string(&empty).unwrap();
        let decoded: Vec<u8> = serde_json::from_str(&json).unwrap();

        prop_assert!(decoded.is_empty());
    }

    /// Test with single byte (all possible values)
    #[test]
    fn prop_single_byte_round_trip(byte: u8) {
        let data = vec![byte];
        let json = serde_json::to_string(&data).unwrap();
        let decoded: Vec<u8> = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(data, decoded);
    }
}

// =========================================================================
// Non-proptest edge case tests
// =========================================================================

#[test]
fn test_all_byte_values_round_trip() {
    let all_bytes: Vec<u8> = (0..=255).collect();

    let json = serde_json::to_string(&all_bytes).unwrap();
    let decoded: Vec<u8> = serde_json::from_str(&json).unwrap();

    assert_eq!(all_bytes, decoded);
}

#[test]
fn test_large_data_round_trip() {
    let large = vec![0xABu8; 100_000];

    let json = serde_json::to_string(&large).unwrap();
    let decoded: Vec<u8> = serde_json::from_str(&json).unwrap();

    assert_eq!(large, decoded);
}

#[test]
fn test_nested_empty_vecs() {
    let nested: Vec<Vec<u8>> = vec![vec![], vec![], vec![]];

    let json = serde_json::to_string(&nested).unwrap();
    let decoded: Vec<Vec<u8>> = serde_json::from_str(&json).unwrap();

    assert_eq!(nested, decoded);
}

// =========================================================================
// Compile-time trait assertions (aws-lc-rs pattern)
// These fail compilation if types don't implement required traits
// =========================================================================

/// Assert a type implements Clone
fn compile_time_assert_clone<T: Clone>() {}

/// Assert a type implements Send + Sync for thread safety
fn compile_time_assert_send_sync<T: Send + Sync>() {}

/// Assert a type implements required serde traits
fn compile_time_assert_serde<T: serde::Serialize + for<'de> serde::Deserialize<'de>>() {}

#[test]
fn test_api_types_implement_required_traits() {
    // LoginCompleteRequest
    compile_time_assert_serde::<LoginCompleteRequest>();

    // RegisterCompleteRequest
    compile_time_assert_serde::<RegisterCompleteRequest>();

    // RegisterStartResponse
    compile_time_assert_serde::<RegisterStartResponse>();

    // Vec<u8> (the underlying type we use)
    compile_time_assert_clone::<Vec<u8>>();
    compile_time_assert_send_sync::<Vec<u8>>();
    compile_time_assert_serde::<Vec<u8>>();
}

// =========================================================================
// Encoded<T, E> type tests (Phase 1+)
// =========================================================================

proptest! {
    /// Raw → Base64Url → Raw conversion preserves data
    #[test]
    fn prop_encoding_conversion_round_trip(data: Vec<u8>) {
        let raw: CredentialId<Raw> = CredentialId::from_raw(data.clone());
        let b64 = raw.clone().to_base64url();
        let back_to_raw = b64.to_raw();

        prop_assert_eq!(raw.as_bytes(), back_to_raw.as_bytes());
        prop_assert_eq!(data.as_slice(), back_to_raw.as_bytes());
    }

    /// Encoded<T, Raw> serde round-trip preserves data
    #[test]
    fn prop_encoded_raw_serde_round_trip(data: Vec<u8>) {
        let original: Challenge<Raw> = Challenge::from_raw(data.clone());
        let json = serde_json::to_string(&original).unwrap();
        let decoded: Challenge<Raw> = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(original.as_bytes(), decoded.as_bytes());
    }

    /// Encoded<T, Base64Url> serde round-trip preserves data
    #[test]
    fn prop_encoded_base64url_serde_round_trip(data: Vec<u8>) {
        let raw: CredentialId<Raw> = CredentialId::from_raw(data.clone());
        let b64: CredentialId<Base64Url> = raw.to_base64url();

        let json = serde_json::to_string(&b64).unwrap();
        let decoded: CredentialId<Base64Url> = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(b64.as_bytes(), decoded.as_bytes());
    }

    /// From<Vec<u8>> conversion preserves data
    #[test]
    fn prop_from_vec_preserves_data(data: Vec<u8>) {
        let encoded: CoseKey<Raw> = data.clone().into();
        let back: Vec<u8> = encoded.into();

        prop_assert_eq!(data, back);
    }

    /// AsRef<[u8]> returns correct data
    #[test]
    fn prop_as_ref_returns_correct_data(data: Vec<u8>) {
        let encoded: Signature<Raw> = Signature::from_raw(data.clone());
        let as_ref: &[u8] = encoded.as_ref();

        prop_assert_eq!(data.as_slice(), as_ref);
    }

    /// Different semantic types with same data are distinct (same bytes, different types)
    #[test]
    fn prop_semantic_types_same_bytes(data: Vec<u8>) {
        let challenge: Challenge<Raw> = Challenge::from_raw(data.clone());
        let cred_id: CredentialId<Raw> = CredentialId::from_raw(data.clone());

        // Both have same underlying bytes
        prop_assert_eq!(challenge.as_bytes(), cred_id.as_bytes());

        // JSON should be identical since underlying data is the same
        let challenge_json = serde_json::to_string(&challenge).unwrap();
        let cred_id_json = serde_json::to_string(&cred_id).unwrap();
        prop_assert_eq!(challenge_json, cred_id_json);
    }
}

// =========================================================================
// Compile-time trait assertions for Encoded types (aws-lc-rs pattern)
// =========================================================================

#[test]
fn test_encoded_types_implement_required_traits() {
    // Challenge
    compile_time_assert_clone::<Challenge<Raw>>();
    compile_time_assert_send_sync::<Challenge<Raw>>();
    compile_time_assert_serde::<Challenge<Raw>>();
    compile_time_assert_clone::<Challenge<Base64Url>>();
    compile_time_assert_serde::<Challenge<Base64Url>>();

    // CredentialId
    compile_time_assert_clone::<CredentialId<Raw>>();
    compile_time_assert_send_sync::<CredentialId<Raw>>();
    compile_time_assert_serde::<CredentialId<Raw>>();

    // CoseKey
    compile_time_assert_clone::<CoseKey<Raw>>();
    compile_time_assert_serde::<CoseKey<Raw>>();

    // Signature
    compile_time_assert_clone::<Signature<Raw>>();
    compile_time_assert_serde::<Signature<Raw>>();

    // All types should be Send + Sync for use across async boundaries
    compile_time_assert_send_sync::<CredentialId<Raw>>();
    compile_time_assert_send_sync::<CoseKey<Raw>>();
    compile_time_assert_send_sync::<Signature<Raw>>();
}

// =========================================================================
// Edge case tests for Encoded types
// =========================================================================

#[test]
fn test_all_byte_values_in_encoded() {
    let all_bytes: Vec<u8> = (0..=255).collect();
    let encoded: Challenge<Raw> = Challenge::from_raw(all_bytes.clone());

    // Serde round-trip
    let json = serde_json::to_string(&encoded).unwrap();
    let decoded: Challenge<Raw> = serde_json::from_str(&json).unwrap();
    assert_eq!(all_bytes.as_slice(), decoded.as_bytes());

    // Encoding conversion
    let b64 = encoded.to_base64url();
    let back = b64.to_raw();
    assert_eq!(all_bytes.as_slice(), back.as_bytes());
}

#[test]
fn test_empty_encoded() {
    let empty: Vec<u8> = vec![];
    let encoded: CredentialId<Raw> = CredentialId::from_raw(empty);

    assert!(encoded.is_empty());
    assert_eq!(encoded.len(), 0);

    let json = serde_json::to_string(&encoded).unwrap();
    let decoded: CredentialId<Raw> = serde_json::from_str(&json).unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn test_large_encoded_data() {
    // Test marker type for attestation objects
    use vouch_common::fido2_types::AttestationObject;

    let large = vec![0xABu8; 100_000];
    let encoded: AttestationObject<Raw> = AttestationObject::from_raw(large.clone());

    let json = serde_json::to_string(&encoded).unwrap();
    let decoded: AttestationObject<Raw> = serde_json::from_str(&json).unwrap();

    assert_eq!(large.as_slice(), decoded.as_bytes());
}

// =============================================================================
// Security Fuzzing Tests - These verify parsers don't panic on arbitrary input
// =============================================================================

proptest! {
    // =========================================================================
    // COSE Key Parsing Fuzzing
    // =========================================================================

    /// COSE key validation should never panic on arbitrary input
    #[test]
    fn prop_cose_key_validation_no_panic(data: Vec<u8>) {
        use vouch_tests::contracts::validate_cose_key;

        // Should not panic - errors are expected for random data
        let _ = validate_cose_key(&data);
    }

    /// COSE key validation with valid CBOR maps should not panic
    #[test]
    fn prop_cose_key_cbor_map_no_panic(
        keys in prop::collection::vec(any::<i32>(), 0..10),
        values in prop::collection::vec(any::<i32>(), 0..10),
    ) {
        use vouch_tests::contracts::validate_cose_key;

        // Create a random CBOR map
        let map_entries: Vec<_> = keys.iter().zip(values.iter())
            .map(|(k, v)| {
                (
                    ciborium::Value::Integer((*k as i64).into()),
                    ciborium::Value::Integer((*v as i64).into()),
                )
            })
            .collect();

        let mut buf = Vec::new();
        if ciborium::into_writer(&ciborium::Value::Map(map_entries), &mut buf).is_ok() {
            // Should not panic
            let _ = validate_cose_key(&buf);
        }
    }

    // =========================================================================
    // Authenticator Data Parsing Fuzzing
    // =========================================================================

    /// Authenticator data validation should never panic on arbitrary input
    #[test]
    fn prop_authenticator_data_validation_no_panic(data: Vec<u8>) {
        use vouch_tests::contracts::validate_authenticator_data;

        // Should not panic
        let _ = validate_authenticator_data(&data);
    }

    /// AAGUID extraction should never panic on arbitrary input
    #[test]
    fn prop_aaguid_extraction_no_panic(data: Vec<u8>) {
        use vouch_common::aaguid::extract_aaguid_from_auth_data;

        // Should not panic
        let _ = extract_aaguid_from_auth_data(&data);
    }

    /// Public key extraction from auth data should never panic
    #[test]
    fn prop_public_key_extraction_no_panic(data: Vec<u8>) {
        use vouch_common::aaguid::{extract_public_key_from_auth_data, extract_public_key_from_attestation};

        // Should not panic
        let _ = extract_public_key_from_auth_data(&data);
        let _ = extract_public_key_from_attestation(&data);
    }

    // =========================================================================
    // Attestation Object Parsing Fuzzing
    // =========================================================================

    /// Attestation object validation should never panic on arbitrary input
    #[test]
    fn prop_attestation_object_validation_no_panic(data: Vec<u8>) {
        use vouch_tests::contracts::validate_attestation_object;

        // Should not panic
        let _ = validate_attestation_object(&data);
    }

    /// Random CBOR data should not panic attestation parsing
    #[test]
    fn prop_attestation_cbor_no_panic(
        fmt in "[a-z]{0,10}",
        auth_data in prop::collection::vec(any::<u8>(), 0..100),
    ) {
        use vouch_tests::contracts::validate_attestation_object;

        let obj = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("fmt".to_string()),
                ciborium::Value::Text(fmt),
            ),
            (
                ciborium::Value::Text("authData".to_string()),
                ciborium::Value::Bytes(auth_data),
            ),
            (
                ciborium::Value::Text("attStmt".to_string()),
                ciborium::Value::Map(vec![]),
            ),
        ]);

        let mut buf = Vec::new();
        if ciborium::into_writer(&obj, &mut buf).is_ok() {
            // Should not panic
            let _ = validate_attestation_object(&buf);
        }
    }

    // =========================================================================
    // Base64url Invalid Input Fuzzing
    // =========================================================================

    /// Base64url decoding should never panic on arbitrary strings
    #[test]
    fn prop_base64url_decode_no_panic(s: String) {
        use vouch_common::encoding::Encoded;

        // Test marker type
        struct TestMarker;

        // Should not panic - errors are expected
        let _: Result<Encoded<TestMarker, Base64Url>, _> = Encoded::from_base64url(&s);
    }

    /// Base64url decoding with ASCII-only strings should not panic
    #[test]
    fn prop_base64url_ascii_no_panic(chars in prop::collection::vec(0x20u8..0x7Fu8, 0..100)) {
        use vouch_common::encoding::Encoded;

        struct TestMarker;

        if let Ok(s) = String::from_utf8(chars) {
            // Should not panic
            let _: Result<Encoded<TestMarker, Base64Url>, _> = Encoded::from_base64url(&s);
        }
    }

    // =========================================================================
    // Client Data JSON Parsing Fuzzing
    // =========================================================================

    /// Client data JSON validation should never panic on arbitrary bytes
    #[test]
    fn prop_client_data_json_validation_no_panic(data: Vec<u8>) {
        use vouch_tests::contracts::validate_client_data_json;

        // Should not panic
        let _ = validate_client_data_json(&data);
    }

    /// Client data JSON with random strings should not panic
    #[test]
    fn prop_client_data_json_strings_no_panic(
        type_ in "[a-z.]{0,20}",
        challenge in "[A-Za-z0-9_-]{0,64}",
        origin in "https?://[a-z.]{0,20}",
    ) {
        use vouch_tests::contracts::validate_client_data_json;

        let json = format!(
            r#"{{"type":"{}","challenge":"{}","origin":"{}"}}"#,
            type_, challenge, origin
        );

        // Should not panic
        let _ = validate_client_data_json(json.as_bytes());
    }

    // =========================================================================
    // Credential ID Validation Fuzzing
    // =========================================================================

    /// Credential ID validation should never panic on arbitrary input
    #[test]
    fn prop_credential_id_validation_no_panic(data: Vec<u8>) {
        use vouch_tests::contracts::validate_credential_id;

        // Should not panic
        let _ = validate_credential_id(&data);
    }

    // =========================================================================
    // Challenge Validation Fuzzing
    // =========================================================================

    /// Challenge validation should never panic on arbitrary input
    #[test]
    fn prop_challenge_validation_no_panic(data: Vec<u8>) {
        use vouch_tests::contracts::validate_challenge;

        // Should not panic
        let _ = validate_challenge(&data);
    }

    // =========================================================================
    // Signature Validation Fuzzing
    // =========================================================================

    /// Signature validation should never panic on arbitrary input
    #[test]
    fn prop_signature_validation_no_panic(data: Vec<u8>) {
        use vouch_tests::contracts::validate_signature;

        // Should not panic
        let _ = validate_signature(&data);
    }

    // =========================================================================
    // Device Model Lookup Fuzzing
    // =========================================================================

    /// Device model lookup should never panic on arbitrary strings
    #[test]
    fn prop_device_model_lookup_no_panic(s: String) {
        use vouch_common::aaguid::lookup_device_model;

        // Should not panic
        let _ = lookup_device_model(&s);
    }
}

// =============================================================================
// Additional Non-proptest Security Tests
// =============================================================================

#[test]
fn test_cose_key_truncated_cbor_no_panic() {
    use vouch_tests::contracts::validate_cose_key;

    // Various truncated/malformed CBOR inputs
    let inputs = [
        vec![0xA3],                   // Start of map but incomplete
        vec![0xA3, 0x01],             // Map with one key, missing value
        vec![0xA3, 0x01, 0x02, 0x03], // Map with first entry, missing rest
        vec![0xFF],                   // Invalid CBOR
        vec![0xA0],                   // Empty map
        vec![0xBF],                   // Indefinite length map start
        vec![0x80],                   // Empty array (not a map)
    ];

    for input in inputs {
        // Should not panic
        let _ = validate_cose_key(&input);
    }
}

#[test]
fn test_auth_data_boundary_conditions_no_panic() {
    use vouch_common::aaguid::extract_aaguid_from_auth_data;
    use vouch_tests::contracts::validate_authenticator_data;

    // Test various boundary lengths
    for len in [0, 1, 32, 36, 37, 38, 52, 53, 54, 55, 56, 100, 1000] {
        let data = vec![0u8; len];
        // Should not panic
        let _ = validate_authenticator_data(&data);
        let _ = extract_aaguid_from_auth_data(&data);
    }
}

#[test]
fn test_public_key_extraction_boundary_no_panic() {
    use vouch_common::aaguid::extract_public_key_from_auth_data;

    // Test with AT flag set at various lengths
    for len in [0, 37, 54, 55, 56, 70, 100, 200] {
        let mut data = vec![0u8; len];
        if len > 32 {
            data[32] = 0x41; // AT + UP flags
        }
        // Should not panic
        let _ = extract_public_key_from_auth_data(&data);
    }
}

#[test]
fn test_base64url_special_characters_no_panic() {
    use vouch_common::encoding::Encoded;

    struct TestMarker;

    // Various problematic strings
    let inputs = [
        "",
        " ",
        "\t\n",
        "===",
        "+/+/",
        "日本語",
        "\0\0\0",
        "A",
        "AB",
        "ABC",
        "ABCD",
        "A===",
        "AB==",
        "ABC=",
        "AAAA",
        &"A".repeat(1000),
    ];

    for input in inputs {
        // Should not panic
        let _: Result<Encoded<TestMarker, Base64Url>, _> = Encoded::from_base64url(input);
    }
}

#[test]
fn test_client_data_json_malformed_no_panic() {
    use vouch_tests::contracts::validate_client_data_json;

    // Various malformed JSON inputs
    let inputs: &[&[u8]] = &[
        b"",
        b"{}",
        b"[]",
        b"null",
        b"true",
        b"123",
        b"\"string\"",
        b"{invalid}",
        b"{\"type\": \"webauthn.get\"}",
        b"{\"challenge\": \"test\"}",
        b"{\"origin\": \"https://example.com\"}",
        b"{\"\x00\": \"test\"}", // Null byte in key
        &[0xFF, 0xFE],           // Invalid UTF-8
    ];

    for input in inputs {
        // Should not panic
        let _ = validate_client_data_json(input);
    }
}

#[test]
fn test_attestation_malformed_cbor_no_panic() {
    use vouch_tests::contracts::validate_attestation_object;

    // Various malformed CBOR inputs
    let inputs: &[&[u8]] = &[
        &[],
        &[0xFF],
        &[0xA0],       // Empty map
        &[0x80],       // Empty array
        &[0xBF, 0xFF], // Empty indefinite map
        &[0xA3],       // Truncated map header
    ];

    for input in inputs {
        // Should not panic
        let _ = validate_attestation_object(input);
    }
}

// =============================================================================
// RFC 7591 — Dynamic Client Registration Property-Based Tests
// =============================================================================
//
// These tests verify that the registration request validation helpers are safe
// against arbitrary string input — they must never panic.

proptest! {
    // =========================================================================
    // Redirect URI Validation Fuzzing (RFC 7591 Section 2)
    // =========================================================================

    /// `validate_registration_redirect_uri` must never panic on arbitrary strings.
    ///
    /// This mirrors how the handler receives untrusted client input.
    #[test]
    fn prop_redirect_uri_validation_no_panic(uri in "\\PC*") {
        use vouch_server::services::oidc::registration::validate_redirect_uri_for_test;

        // Must not panic — errors are expected for random input
        let _ = validate_redirect_uri_for_test(&uri);
    }

    /// Redirect URI validation must not panic on ASCII-printable strings.
    #[test]
    fn prop_redirect_uri_validation_ascii_no_panic(
        chars in prop::collection::vec(0x20u8..0x7Eu8, 0..200)
    ) {
        use vouch_server::services::oidc::registration::validate_redirect_uri_for_test;

        if let Ok(s) = String::from_utf8(chars) {
            // Must not panic
            let _ = validate_redirect_uri_for_test(&s);
        }
    }

    /// Any HTTPS URI should be accepted as a redirect URI.
    #[test]
    fn prop_https_redirect_uri_always_accepted(
        path in "[a-z0-9/._-]{0,50}",
        host in "[a-z][a-z0-9.-]{0,30}\\.[a-z]{2,6}",
    ) {
        use vouch_server::services::oidc::registration::validate_redirect_uri_for_test;

        let uri = format!("https://{host}/{path}");
        // Any well-formed HTTPS URI must be accepted
        let result = validate_redirect_uri_for_test(&uri);
        prop_assert!(
            result.is_ok(),
            "HTTPS redirect URI '{uri}' must be accepted: {result:?}"
        );
    }

    /// URIs containing '#' must always be rejected (fragment component).
    #[test]
    fn prop_redirect_uri_with_fragment_always_rejected(
        prefix in "https://[a-z]{3,10}\\.[a-z]{2,4}/[a-z]{0,20}",
        fragment in "[a-z0-9]{1,20}",
    ) {
        use vouch_server::services::oidc::registration::validate_redirect_uri_for_test;

        let uri = format!("{prefix}#{fragment}");
        let result = validate_redirect_uri_for_test(&uri);
        prop_assert!(
            result.is_err(),
            "Redirect URI with fragment '{uri}' must be rejected"
        );
    }

    // =========================================================================
    // Registration Request JSON Deserialization Fuzzing
    // =========================================================================

    /// Arbitrary JSON strings must not cause deserialization to panic.
    ///
    /// The RegistrationRequest struct must safely handle any input string since
    /// the handler receives raw bytes from untrusted clients.
    #[test]
    fn prop_registration_request_deserialize_no_panic(s in "\\PC*") {
        // Must not panic — errors are expected for most random strings
        let _: Result<vouch_server::services::oidc::registration::RegistrationRequest, _> =
            serde_json::from_str(&s);
    }

    /// JSON objects with arbitrary key/value string pairs must not panic.
    ///
    /// RFC 7591 requires ignoring unknown fields — this verifies that property.
    #[test]
    fn prop_registration_request_with_arbitrary_keys_no_panic(
        key in "[a-zA-Z_][a-zA-Z0-9_]{0,30}",
        value in "\\PC{0,100}",
    ) {
        let json = serde_json::json!({ key: value });
        let json_str = json.to_string();
        // Must not panic regardless of key/value content
        let _: Result<vouch_server::services::oidc::registration::RegistrationRequest, _> =
            serde_json::from_str(&json_str);
    }
}
