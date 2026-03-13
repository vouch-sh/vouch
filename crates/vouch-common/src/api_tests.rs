// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Safety tests for API type serialization.
//!
//! These tests verify that API request/response types serialize
//! and deserialize correctly with the typed encoding wrappers.

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use crate::api::*;
    use uuid::Uuid;

    // =========================================================================
    // Round-Trip Tests (Existing)
    // =========================================================================

    #[test]
    fn test_register_complete_request_round_trip() {
        let request = RegisterCompleteRequest {
            state: "test-state".to_string(),
            credential_id: vec![1u8, 2, 3, 4].into(),
            public_key: vec![5u8, 6, 7, 8].into(),
            attestation_object: vec![9u8, 10, 11, 12].into(),
            client_data_json: br#"{"type":"webauthn.create"}"#.to_vec().into(),
        };
        let json = serde_json::to_string(&request).unwrap();
        let decoded: RegisterCompleteRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request.credential_id, decoded.credential_id);
        assert_eq!(request.public_key, decoded.public_key);
        assert_eq!(request.attestation_object, decoded.attestation_object);
        assert_eq!(request.client_data_json, decoded.client_data_json);
    }

    #[test]
    fn test_register_start_response_round_trip() {
        let response = RegisterStartResponse {
            challenge: vec![0u8; 32].into(),
            rp_id: "test.com".to_string(),
            rp_name: "Test".to_string(),
            user_id: Uuid::nil(),
            user_name: "test@test.com".to_string(),
            algorithms: vec![-7, -257],
            state: "state".to_string(),
            exclude_credential_ids: vec![vec![1u8, 2, 3].into()],
        };
        let json = serde_json::to_string(&response).unwrap();
        let decoded: RegisterStartResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response.challenge, decoded.challenge);
        assert_eq!(
            response.exclude_credential_ids,
            decoded.exclude_credential_ids
        );
        assert_eq!(response.rp_id, decoded.rp_id);
        assert_eq!(response.algorithms, decoded.algorithms);
    }

    #[test]
    fn test_binary_fields_with_special_bytes() {
        // Test that fields with special byte values (0x00, 0xFF, etc.) work correctly
        let request = RegisterCompleteRequest {
            state: "test".to_string(),
            credential_id: vec![0x00u8, 0xFF, 0x7F, 0x80].into(),
            public_key: vec![0xC0u8, 0xE0, 0xF0, 0xFE].into(),
            attestation_object: vec![0x00u8, 0x01, 0xFE, 0xFF].into(),
            client_data_json: vec![0x7Bu8, 0x7D].into(), // "{}"
        };
        let json = serde_json::to_string(&request).unwrap();
        let decoded: RegisterCompleteRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request.credential_id, decoded.credential_id);
        assert_eq!(request.public_key, decoded.public_key);
    }

    #[test]
    fn test_nested_vec_u8_round_trip() {
        // Test Vec<CredentialId<Raw>> (exclude_credential_ids) serialization
        let response = RegisterStartResponse {
            challenge: vec![1u8, 2, 3].into(),
            rp_id: "test.com".to_string(),
            rp_name: "Test".to_string(),
            user_id: Uuid::nil(),
            user_name: "user".to_string(),
            algorithms: vec![-7],
            state: "state".to_string(),
            exclude_credential_ids: vec![
                vec![1u8, 2, 3].into(),
                vec![4u8, 5, 6, 7, 8].into(),
                vec![0xFFu8, 0x00, 0x80].into(),
                vec![].into(), // empty is allowed
            ],
        };
        let json = serde_json::to_string(&response).unwrap();
        let decoded: RegisterStartResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(
            response.exclude_credential_ids,
            decoded.exclude_credential_ids
        );
    }

    // =========================================================================
    // Missing Field Deserialization Tests
    // =========================================================================

    #[test]
    fn test_register_complete_missing_public_key() {
        // Missing required 'public_key' field should fail
        let json = r#"{
            "state": "test-state",
            "credential_id": [1, 2, 3],
            "attestation_object": [4, 5, 6],
            "client_data_json": [7, 8, 9]
        }"#;
        let result: Result<RegisterCompleteRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("public_key"));
    }

    // =========================================================================
    // Empty Field Handling Tests
    // =========================================================================

    #[test]
    fn test_register_complete_empty_public_key() {
        // Empty public_key is syntactically valid
        let request = RegisterCompleteRequest {
            state: "test".to_string(),
            credential_id: vec![1u8, 2, 3].into(),
            public_key: vec![].into(),
            attestation_object: vec![4u8, 5, 6].into(),
            client_data_json: vec![7u8, 8, 9].into(),
        };
        let json = serde_json::to_string(&request).unwrap();
        let decoded: RegisterCompleteRequest = serde_json::from_str(&json).unwrap();
        assert!(decoded.public_key.is_empty());
    }

    #[test]
    fn test_register_start_response_empty_exclude_list() {
        // Empty exclude_credential_ids list is valid
        let response = RegisterStartResponse {
            challenge: vec![0u8; 32].into(),
            rp_id: "test.com".to_string(),
            rp_name: "Test".to_string(),
            user_id: Uuid::nil(),
            user_name: "test@test.com".to_string(),
            algorithms: vec![-7],
            state: "state".to_string(),
            exclude_credential_ids: vec![],
        };
        let json = serde_json::to_string(&response).unwrap();
        let decoded: RegisterStartResponse = serde_json::from_str(&json).unwrap();
        assert!(decoded.exclude_credential_ids.is_empty());
    }

    // =========================================================================
    // Large Field Handling Tests
    // =========================================================================

    #[test]
    fn test_register_complete_large_attestation_object() {
        // Large attestation_object should work
        let large_att = vec![0xCDu8; 50_000];
        let request = RegisterCompleteRequest {
            state: "test".to_string(),
            credential_id: vec![1u8, 2, 3].into(),
            public_key: vec![4u8, 5, 6].into(),
            attestation_object: large_att.clone().into(),
            client_data_json: vec![7u8, 8, 9].into(),
        };
        let json = serde_json::to_string(&request).unwrap();
        let decoded: RegisterCompleteRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.attestation_object.len(), 50_000);
    }

    #[test]
    fn test_register_start_response_many_exclude_ids() {
        // Many excluded credential IDs
        let many_creds: Vec<crate::CredentialId<crate::Raw>> =
            (0..100).map(|i| vec![i as u8; 64].into()).collect();

        let response = RegisterStartResponse {
            challenge: vec![0u8; 32].into(),
            rp_id: "test.com".to_string(),
            rp_name: "Test".to_string(),
            user_id: Uuid::nil(),
            user_name: "test@test.com".to_string(),
            algorithms: vec![-7],
            state: "state".to_string(),
            exclude_credential_ids: many_creds.clone(),
        };
        let json = serde_json::to_string(&response).unwrap();
        let decoded: RegisterStartResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.exclude_credential_ids.len(), 100);
    }

    // =========================================================================
    // OAuth Error Tests
    // =========================================================================

    #[test]
    fn test_oauth_error_serialization() {
        let error = OAuthError {
            error: "invalid_request".to_string(),
            error_description: Some("Missing required parameter".to_string()),
        };
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("invalid_request"));
        assert!(json.contains("Missing required parameter"));
    }

    #[test]
    fn test_oauth_error_without_description() {
        let error = OAuthError {
            error: "access_denied".to_string(),
            error_description: None,
        };
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("access_denied"));
        // error_description should be absent (skip_serializing_if)
        let decoded: OAuthError = serde_json::from_str(&json).unwrap();
        assert!(decoded.error_description.is_none());
    }

    // =========================================================================
    // Session Status Tests
    // =========================================================================

    #[test]
    fn test_session_status_unauthenticated() {
        let status = SessionStatus {
            authenticated: false,
            email: None,
            expires_in_seconds: None,
            device_name: None,
        };
        let json = serde_json::to_string(&status).unwrap();
        let decoded: SessionStatus = serde_json::from_str(&json).unwrap();
        assert!(!decoded.authenticated);
        assert!(decoded.email.is_none());
        assert!(decoded.expires_in_seconds.is_none());
        assert!(decoded.device_name.is_none());
    }

    #[test]
    fn test_session_status_authenticated() {
        let status = SessionStatus {
            authenticated: true,
            email: Some("user@example.com".to_string()),
            expires_in_seconds: Some(28800), // 8 hours
            device_name: Some("YubiKey 5 NFC".to_string()),
        };
        let json = serde_json::to_string(&status).unwrap();
        let decoded: SessionStatus = serde_json::from_str(&json).unwrap();
        assert!(decoded.authenticated);
        assert_eq!(decoded.email.as_deref(), Some("user@example.com"));
        assert_eq!(decoded.expires_in_seconds, Some(28800));
        assert_eq!(decoded.device_name.as_deref(), Some("YubiKey 5 NFC"));
    }

    // =========================================================================
    // Client Context Tests
    // =========================================================================

    #[test]
    fn test_client_context_all_fields_none() {
        let ctx = ClientContext {
            cli_version: None,
            os: None,
            os_version: None,
            arch: None,
            hostname: None,
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: ClientContext = serde_json::from_str(&json).unwrap();
        assert!(decoded.cli_version.is_none());
        assert!(decoded.os.is_none());
        assert!(decoded.os_version.is_none());
        assert!(decoded.arch.is_none());
        assert!(decoded.hostname.is_none());
    }

    #[test]
    fn test_client_context_partial_fields() {
        let ctx = ClientContext {
            cli_version: Some("1.0.0".to_string()),
            os: Some("linux".to_string()),
            os_version: None,
            arch: None,
            hostname: Some("workstation".to_string()),
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: ClientContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.cli_version.as_deref(), Some("1.0.0"));
        assert_eq!(decoded.os.as_deref(), Some("linux"));
        assert!(decoded.os_version.is_none());
        assert!(decoded.arch.is_none());
        assert_eq!(decoded.hostname.as_deref(), Some("workstation"));
    }

    // =========================================================================
    // Invalid JSON Format Tests
    // =========================================================================

    #[test]
    fn test_register_start_response_wrong_type_for_algorithms() {
        // algorithms should be an array of numbers, not strings
        let json = r#"{
            "challenge": [1, 2, 3],
            "rp_id": "test.com",
            "rp_name": "Test",
            "user_id": "00000000-0000-0000-0000-000000000000",
            "user_name": "user@test.com",
            "algorithms": ["ES256", "RS256"],
            "state": "state",
            "exclude_credential_ids": []
        }"#;
        let result: Result<RegisterStartResponse, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // =========================================================================
    // Unicode and Special Character Tests
    // =========================================================================

    #[test]
    fn test_register_start_response_unicode_names() {
        let response = RegisterStartResponse {
            challenge: vec![0u8; 32].into(),
            rp_id: "test.com".to_string(),
            rp_name: "テスト会社 🔐".to_string(), // Japanese + emoji
            user_id: Uuid::nil(),
            user_name: "用户@example.com".to_string(), // Chinese characters
            algorithms: vec![-7],
            state: "state".to_string(),
            exclude_credential_ids: vec![],
        };
        let json = serde_json::to_string(&response).unwrap();
        let decoded: RegisterStartResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.rp_name, "テスト会社 🔐");
        assert_eq!(decoded.user_name, "用户@example.com");
    }

    #[test]
    fn test_client_context_unicode_hostname() {
        let ctx = ClientContext {
            cli_version: Some("1.0.0".to_string()),
            os: Some("macos".to_string()),
            os_version: None,
            arch: None,
            hostname: Some("开发机-αβγ".to_string()), // Chinese + Greek
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: ClientContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.hostname.as_deref(), Some("开发机-αβγ"));
    }
}
