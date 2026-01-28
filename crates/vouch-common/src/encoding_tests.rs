// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Safety tests for binary encoding round-trips.
//!
//! These tests verify that Vec<u8> serialization works correctly
//! with serde_json before we introduce new encoding types.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use crate::encoding::{Base64Url, ConvertEncoding, Encoded, Raw};
    use serde::{Deserialize, Serialize};

    // Test marker type
    struct TestData;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct TestRequest {
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
    }

    // =========================================================================
    // Vec<u8> Serialization Tests (Existing)
    // =========================================================================

    #[test]
    fn test_vec_u8_json_round_trip() {
        let original = TestRequest {
            credential_id: vec![0, 1, 2, 255, 128, 64],
            public_key: vec![4, 0, 1, 2, 3], // COSE-like
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: TestRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_vec_u8_json_encoding_format() {
        // Verify serde_json uses array format for Vec<u8>
        let data = vec![1u8, 2, 3];
        let json = serde_json::to_string(&data).unwrap();
        // serde_json encodes Vec<u8> as JSON array: [1,2,3]
        assert_eq!(json, "[1,2,3]");
    }

    #[test]
    fn test_credential_id_with_special_bytes() {
        // Bytes that could cause issues: 0x00, 0xFF, UTF-8 sequences
        let problematic = vec![0x00, 0xFF, 0x7F, 0x80, 0xC0, 0xE0, 0xF0];
        let json = serde_json::to_string(&problematic).unwrap();
        let decoded: Vec<u8> = serde_json::from_str(&json).unwrap();
        assert_eq!(problematic, decoded);
    }

    #[test]
    fn test_empty_credential_id() {
        let empty: Vec<u8> = vec![];
        let json = serde_json::to_string(&empty).unwrap();
        let decoded: Vec<u8> = serde_json::from_str(&json).unwrap();
        assert_eq!(empty, decoded);
    }

    #[test]
    fn test_large_credential_id() {
        // Test with a typical credential ID size (64 bytes)
        let large = vec![0xABu8; 64];
        let json = serde_json::to_string(&large).unwrap();
        let decoded: Vec<u8> = serde_json::from_str(&json).unwrap();
        assert_eq!(large, decoded);
    }

    #[test]
    fn test_all_byte_values() {
        // Ensure all 256 byte values round-trip correctly
        let all_bytes: Vec<u8> = (0..=255).collect();
        let json = serde_json::to_string(&all_bytes).unwrap();
        let decoded: Vec<u8> = serde_json::from_str(&json).unwrap();
        assert_eq!(all_bytes, decoded);
    }

    // =========================================================================
    // TryFrom Error Case Tests
    // =========================================================================

    #[test]
    fn test_tryfrom_string_invalid_base64url() {
        // Invalid base64url string
        let result: Result<Encoded<TestData, Base64Url>, _> =
            Encoded::from_base64url("not valid base64url!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_tryfrom_string_with_padding() {
        // Base64 with padding (should fail for URL_SAFE_NO_PAD)
        let result: Result<Encoded<TestData, Base64Url>, _> = Encoded::from_base64url("AQID==");
        // URL_SAFE_NO_PAD doesn't accept padding
        assert!(result.is_err());
    }

    #[test]
    fn test_tryfrom_string_empty() {
        // Empty string is valid base64url (decodes to empty bytes)
        let result: Result<Encoded<TestData, Base64Url>, _> = Encoded::from_base64url("");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_tryfrom_string_standard_base64() {
        // Standard base64 with + and / characters (should fail for URL_SAFE)
        let result: Result<Encoded<TestData, Base64Url>, _> = Encoded::from_base64url("a+b/c=");
        assert!(result.is_err());
    }

    #[test]
    fn test_tryfrom_string_url_safe_valid() {
        // Valid URL-safe base64 (uses - and _)
        let result: Result<Encoded<TestData, Base64Url>, _> = Encoded::from_base64url("AQID");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn test_tryfrom_str_invalid() {
        // Test TryFrom<&str> error case
        let result: Result<Encoded<TestData, Base64Url>, _> = "!!!invalid!!!".try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_tryfrom_string_owned_invalid() {
        // Test TryFrom<String> error case
        let result: Result<Encoded<TestData, Base64Url>, _> = String::from("@#$%^&*").try_into();
        assert!(result.is_err());
    }

    // =========================================================================
    // Debug Output Truncation Tests
    // =========================================================================

    #[test]
    fn test_debug_output_short_data() {
        // Short data should show completely
        let encoded: Encoded<TestData, Raw> = Encoded::from_raw(vec![0xAB, 0xCD, 0xEF]);
        let debug = format!("{:?}", encoded);
        assert!(debug.contains("abcdef")); // Full hex
        assert!(debug.contains("len"));
        assert!(debug.contains("3")); // Length
        assert!(!debug.contains("...")); // No truncation
    }

    #[test]
    fn test_debug_output_long_data_truncated() {
        // Long data should be truncated
        let encoded: Encoded<TestData, Raw> = Encoded::from_raw(vec![0xAB; 100]);
        let debug = format!("{:?}", encoded);
        assert!(debug.contains("...")); // Should have truncation indicator
        assert!(debug.contains("100")); // Length should be shown
    }

    #[test]
    fn test_debug_output_exactly_16_bytes() {
        // Exactly 16 bytes - boundary condition
        let encoded: Encoded<TestData, Raw> = Encoded::from_raw(vec![0x12; 16]);
        let debug = format!("{:?}", encoded);
        // Should show full hex for 16 bytes
        assert!(!debug.contains("...")); // No truncation at boundary
        assert!(debug.contains("16")); // Length
    }

    #[test]
    fn test_debug_output_17_bytes() {
        // 17 bytes - just over boundary, should truncate
        let encoded: Encoded<TestData, Raw> = Encoded::from_raw(vec![0x12; 17]);
        let debug = format!("{:?}", encoded);
        assert!(debug.contains("...")); // Should truncate
        assert!(debug.contains("17")); // Length
    }

    #[test]
    fn test_debug_output_empty() {
        // Empty data
        let encoded: Encoded<TestData, Raw> = Encoded::from_raw(vec![]);
        let debug = format!("{:?}", encoded);
        assert!(debug.contains("0")); // Length should be 0
    }

    // =========================================================================
    // Base64Url Invalid Input Tests
    // =========================================================================

    #[test]
    fn test_base64url_non_ascii() {
        // Non-ASCII characters
        let result: Result<Encoded<TestData, Base64Url>, _> = Encoded::from_base64url("日本語");
        assert!(result.is_err());
    }

    #[test]
    fn test_base64url_control_characters() {
        // Control characters
        let result: Result<Encoded<TestData, Base64Url>, _> = Encoded::from_base64url("abc\x00def");
        assert!(result.is_err());
    }

    #[test]
    fn test_base64url_whitespace() {
        // Whitespace is not allowed in base64url
        let result: Result<Encoded<TestData, Base64Url>, _> = Encoded::from_base64url("abc def");
        assert!(result.is_err());
    }

    #[test]
    fn test_base64url_newlines() {
        // Newlines not allowed
        let result: Result<Encoded<TestData, Base64Url>, _> = Encoded::from_base64url("abc\ndef");
        assert!(result.is_err());
    }

    #[test]
    fn test_base64url_invalid_length() {
        // Invalid length (not multiple of 4 without correct padding inference)
        // Base64url with single character is invalid
        let result: Result<Encoded<TestData, Base64Url>, _> = Encoded::from_base64url("A");
        assert!(result.is_err());
    }

    #[test]
    fn test_base64url_serde_deserialize_error() {
        // Test serde deserialization error for Base64Url
        let invalid_json = r#""not!valid!base64!""#;
        let result: Result<Encoded<TestData, Base64Url>, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }

    // =========================================================================
    // Encoding Conversion Edge Cases
    // =========================================================================

    #[test]
    fn test_raw_to_base64url_empty() {
        let raw: Encoded<TestData, Raw> = Encoded::from_raw(vec![]);
        let b64 = raw.to_base64url();
        assert_eq!(b64.as_base64url(), "");
    }

    #[test]
    fn test_base64url_to_raw_preserves_data() {
        let raw: Encoded<TestData, Raw> = Encoded::from_raw(vec![1, 2, 3, 4, 5]);
        let b64 = raw.clone().to_base64url();
        let back = b64.to_raw();
        assert_eq!(raw.as_bytes(), back.as_bytes());
    }

    #[test]
    fn test_double_conversion() {
        let raw: Encoded<TestData, Raw> = Encoded::from_raw(vec![255, 128, 0]);
        let b64 = raw.clone().to_base64url();
        let raw2 = b64.to_raw();
        let b64_2 = raw2.to_base64url();
        let raw3 = b64_2.to_raw();
        assert_eq!(raw.as_bytes(), raw3.as_bytes());
    }

    // =========================================================================
    // LowerHex Formatting Tests
    // =========================================================================

    #[test]
    fn test_lowerhex_formatting() {
        let encoded: Encoded<TestData, Raw> = Encoded::from_raw(vec![0xAB, 0xCD, 0xEF]);
        let hex = format!("{:x}", encoded);
        assert_eq!(hex, "abcdef");
    }

    #[test]
    fn test_lowerhex_empty() {
        let encoded: Encoded<TestData, Raw> = Encoded::from_raw(vec![]);
        let hex = format!("{:x}", encoded);
        assert_eq!(hex, "");
    }

    #[test]
    fn test_lowerhex_single_byte() {
        let encoded: Encoded<TestData, Raw> = Encoded::from_raw(vec![0x0F]);
        let hex = format!("{:x}", encoded);
        assert_eq!(hex, "0f"); // Should be zero-padded
    }

    #[test]
    fn test_lowerhex_all_zeros() {
        let encoded: Encoded<TestData, Raw> = Encoded::from_raw(vec![0x00, 0x00, 0x00]);
        let hex = format!("{:x}", encoded);
        assert_eq!(hex, "000000");
    }

    // =========================================================================
    // Hash Implementation Tests
    // =========================================================================

    #[test]
    fn test_hash_equality() {
        use std::collections::HashMap;

        let e1: Encoded<TestData, Raw> = Encoded::from_raw(vec![1, 2, 3]);
        let e2: Encoded<TestData, Raw> = Encoded::from_raw(vec![1, 2, 3]);

        let mut map = HashMap::new();
        map.insert(e1.clone(), "value1");

        // Same data should hash to same key
        assert!(map.contains_key(&e2));
    }

    #[test]
    fn test_hash_different_data() {
        use std::collections::HashSet;

        let e1: Encoded<TestData, Raw> = Encoded::from_raw(vec![1, 2, 3]);
        let e2: Encoded<TestData, Raw> = Encoded::from_raw(vec![3, 2, 1]);

        let mut set = HashSet::new();
        set.insert(e1.clone());

        // Different data should not be in set
        assert!(!set.contains(&e2));
    }

    // =========================================================================
    // AsRef and Borrow Tests
    // =========================================================================

    #[test]
    fn test_asref_slice() {
        let encoded: Encoded<TestData, Raw> = Encoded::from_raw(vec![1, 2, 3]);
        let slice: &[u8] = encoded.as_ref();
        assert_eq!(slice, &[1, 2, 3]);
    }

    #[test]
    fn test_borrow_slice() {
        use std::borrow::Borrow;

        let encoded: Encoded<TestData, Raw> = Encoded::from_raw(vec![4, 5, 6]);
        let slice: &[u8] = encoded.borrow();
        assert_eq!(slice, &[4, 5, 6]);
    }

    #[test]
    fn test_deref_coercion() {
        let encoded: Encoded<TestData, Raw> = Encoded::from_raw(vec![1, 2, 3, 4, 5]);
        // Using slice methods via Deref
        assert_eq!(encoded.len(), 5);
        assert_eq!(encoded.first(), Some(&1));
        assert_eq!(encoded.last(), Some(&5));
    }
}
