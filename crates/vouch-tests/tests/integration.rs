// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integration tests for Vouch.
//!
//! These tests run through actual production code paths by using
//! traits and dependency injection to substitute external dependencies
//! (hardware, network, filesystem) while testing real logic.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code: panicking on an assertion failure is the point"
)]
#![expect(
    clippy::print_stdout,
    reason = "the signature-verification tests print intermediate values for diagnosis"
)]

use vouch_tests::{HttpClient, IntegrationMockDevice, TestHarness, TestTransportPair};

mod flows {
    use super::*;

    /// Test that the login flow works with a valid session.
    #[tokio::test]
    async fn test_login_with_valid_session() {
        let harness = TestHarness::new().await;

        // Create a user with an authenticator and session
        let (_user, _auth_id, token) = harness
            .create_authenticated_user("test@example.com")
            .await
            .expect("Failed to create authenticated user");

        // Verify the session is valid by checking status
        let response = harness
            .get_authenticated("/v1/auth/status", &token)
            .await
            .expect("Failed to get auth status");

        assert_eq!(response.status, 200);

        // Parse response
        let status: serde_json::Value = response.json().expect("Failed to parse status response");
        assert_eq!(
            status.get("email").and_then(|v| v.as_str()),
            Some("test@example.com")
        );
    }

    /// Test that health check endpoint works.
    #[tokio::test]
    async fn test_health_check() {
        let harness = TestHarness::new().await;

        let response = harness
            .get("/health")
            .await
            .expect("Failed to get health check");

        assert_eq!(response.status, 200);
        assert_eq!(response.text().ok(), Some("ok".to_string()));
    }

    /// Test mock device generates valid assertions.
    #[tokio::test]
    async fn test_mock_device_generates_valid_assertion() {
        let device = IntegrationMockDevice::new();
        let challenge = [1u8; 32];

        // Perform authentication
        let result = device.authenticate("test.example.com", &challenge);
        assert!(result.is_ok());

        let auth = result.unwrap();

        // Verify the assertion structure
        assert!(!auth.credential_id.is_empty());
        assert_eq!(auth.authenticator_data.len(), 37); // 32 + 1 + 4
        assert_eq!(auth.signature.len(), 64); // Ed25519 signature
        assert!(!auth.client_data_json.is_empty());
    }

    /// Test mock device counter increments correctly.
    #[tokio::test]
    async fn test_mock_device_counter_increments() {
        let device = IntegrationMockDevice::new();
        let challenge = [2u8; 32];

        // Initial counter should be 0
        assert_eq!(device.counter(), 0);

        // After first authentication, counter should be 1
        device
            .authenticate("test.example.com", &challenge)
            .expect("authenticate");
        assert_eq!(device.counter(), 1);

        // After second authentication, counter should be 2
        device
            .authenticate("test.example.com", &challenge)
            .expect("authenticate");
        assert_eq!(device.counter(), 2);
    }
}

mod credentials {
    use super::*;

    /// Test that SSH CA public key endpoint works.
    #[tokio::test]
    async fn test_get_ssh_ca_public_key() {
        let harness = TestHarness::new().await;

        // The test server doesn't have SSH CA configured
        let response = harness
            .get("/v1/credentials/ssh/ca")
            .await
            .expect("Failed to get SSH CA public key");

        // Without SSH CA configured, should return an error (404 or 503)
        assert!(
            response.status == 404 || response.status == 503,
            "Expected 404 or 503, got {}",
            response.status
        );
    }

    /// Test that SSH certificate issuance requires authentication.
    #[tokio::test]
    async fn test_ssh_certificate_requires_auth() {
        let harness = TestHarness::new().await;

        #[derive(serde::Serialize)]
        struct SshCertRequest {
            public_key: String,
        }

        let request = SshCertRequest {
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test@example.com".to_string(),
        };

        // /v1/* requires a valid RFC 9421 signature; the unsigned request is
        // rejected by the signature middleware before the handler's CA check.
        let response = harness
            .post_json("/v1/credentials/ssh", &request)
            .await
            .expect("Failed to post SSH cert request");

        assert_eq!(response.status, 401);
    }

    /// Test that authenticated users can attempt to get SSH certificates.
    #[tokio::test]
    async fn test_ssh_certificate_authenticated() {
        let harness = TestHarness::new().await;

        // Create authenticated user
        let (_user, _auth_id, token) = harness
            .create_authenticated_user("dev@example.com")
            .await
            .expect("Failed to create authenticated user");

        #[derive(serde::Serialize)]
        struct SshCertRequest {
            public_key: String,
        }

        let request = SshCertRequest {
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test@example.com".to_string(),
        };

        // With auth but no SSH CA, should get an error (CA not configured)
        let response = harness
            .post_json_authenticated("/v1/credentials/ssh", &request, &token)
            .await
            .expect("Failed to post SSH cert request");

        // Should fail because SSH CA is not configured in test environment
        // Could be 404, 500, or 503 depending on how the server handles missing CA
        assert!(
            response.status == 404 || response.status == 500 || response.status == 503,
            "Expected 404, 500, or 503, got {}",
            response.status
        );
    }
}

mod agent {
    use super::*;

    /// Test that test transport pair works for bidirectional communication.
    #[tokio::test]
    async fn test_transport_pair_bidirectional() {
        let pair = TestTransportPair::default_pair();
        let mut client = pair.client;
        let mut server = pair.server;

        // Client sends to server
        let message = b"hello from client";
        client
            .write_all(message)
            .await
            .expect("Failed to write from client");

        let mut buf = vec![0u8; message.len()];
        server
            .read_exact(&mut buf)
            .await
            .expect("Failed to read on server");
        assert_eq!(&buf, message);

        // Server sends to client
        let response = b"hello from server";
        server
            .write_all(response)
            .await
            .expect("Failed to write from server");

        let mut buf = vec![0u8; response.len()];
        client
            .read_exact(&mut buf)
            .await
            .expect("Failed to read on client");
        assert_eq!(&buf, response);
    }

    /// Test that test transport handles length-prefixed messages.
    #[tokio::test]
    async fn test_transport_length_prefixed() {
        let pair = TestTransportPair::default_pair();
        let mut client = pair.client;
        let mut server = pair.server;

        // Send a length-prefixed message (like JSON-RPC)
        let message = b"{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":1}";
        let len = u32::try_from(message.len())
            .expect("message fits u32")
            .to_be_bytes();

        client
            .write_all(&len)
            .await
            .expect("Failed to write length");
        client
            .write_all(message)
            .await
            .expect("Failed to write message");

        // Read length prefix
        let mut len_buf = [0u8; 4];
        server
            .read_exact(&mut len_buf)
            .await
            .expect("Failed to read length");
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        assert_eq!(msg_len, message.len());

        // Read message
        let mut msg_buf = vec![0u8; msg_len];
        server
            .read_exact(&mut msg_buf)
            .await
            .expect("Failed to read message");
        assert_eq!(&msg_buf, message);
    }
}

// ============================================================================
// Priority 1: Authentication Security Tests
// ============================================================================

mod auth_security {
    use super::*;

    /// Test that auth status without token returns 401.
    #[tokio::test]
    async fn test_auth_status_without_token_returns_401() {
        let harness = TestHarness::new().await;

        let response = harness
            .get("/v1/auth/status")
            .await
            .expect("Failed to get auth status");

        // Without token, should return 200 but with authenticated=false
        assert_eq!(response.status, 200);
        let status: serde_json::Value = response.json().expect("Failed to parse response");
        assert_eq!(status["authenticated"], false);
    }

    /// Test that auth status with invalid token returns unauthenticated.
    #[tokio::test]
    async fn test_auth_status_with_invalid_token_returns_unauthenticated() {
        let harness = TestHarness::new().await;

        let response = harness
            .get_authenticated("/v1/auth/status", "invalid.token.here")
            .await
            .expect("Failed to get auth status");

        // Invalid token returns 200 but authenticated=false
        assert_eq!(response.status, 200);
        let status: serde_json::Value = response.json().expect("Failed to parse response");
        assert_eq!(status["authenticated"], false);
    }

    /// Test that auth status with expired token returns unauthenticated.
    #[tokio::test]
    async fn test_auth_status_with_expired_token_returns_unauthenticated() {
        let harness = TestHarness::new().await;

        // Create a user and authenticator
        let user = harness
            .create_user("expired@example.com")
            .await
            .expect("Failed to create user");
        let auth_id = harness
            .create_authenticator(&user.id)
            .await
            .expect("Failed to create auth");

        // Create an expired token
        let expired_token = harness
            .create_expired_token(&user.id, &user.email, &auth_id)
            .await;

        let response = harness
            .get_authenticated("/v1/auth/status", &expired_token)
            .await
            .expect("Failed to get auth status");

        // Expired token should return 200 but authenticated=false
        assert_eq!(response.status, 200);
        let status: serde_json::Value = response.json().expect("Failed to parse response");
        assert_eq!(status["authenticated"], false);
    }

    /// Test that protected endpoints reject missing authentication.
    #[tokio::test]
    async fn test_protected_endpoints_reject_missing_auth() {
        let harness = TestHarness::new().await;

        // Test /v1/keys endpoint
        let response = harness.get("/v1/keys").await.expect("Failed to get keys");
        assert_eq!(response.status, 401, "Keys endpoint should require auth");

        // Test /oauth/userinfo endpoint
        let response = harness
            .get("/oauth/userinfo")
            .await
            .expect("Failed to get userinfo");
        assert_eq!(
            response.status, 401,
            "Userinfo endpoint should require auth"
        );

        // Test /v1/keys/register/start endpoint (POST)
        #[derive(serde::Serialize)]
        struct RegisterRequest {
            name: String,
        }
        let response = harness
            .post_json(
                "/v1/keys/register/start",
                &RegisterRequest {
                    name: "test".to_string(),
                },
            )
            .await
            .expect("Failed to post register start");
        assert_eq!(response.status, 401, "Register start should require auth");
    }

    /// Test that SSH certificate issuance requires valid session.
    #[tokio::test]
    async fn test_ssh_cert_requires_valid_session() {
        let harness = TestHarness::new().await;

        #[derive(serde::Serialize)]
        struct SshCertRequest {
            public_key: String,
        }

        let request = SshCertRequest {
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test@example.com".to_string(),
        };

        // /v1/* requires a valid RFC 9421 signature; the unsigned request is
        // rejected by the signature middleware before the handler's CA check.
        let response = harness
            .post_json("/v1/credentials/ssh", &request)
            .await
            .expect("Failed to post SSH cert request");
        assert_eq!(response.status, 401);

        // An invalid token resolves to no client, so the signature check
        // rejects it with 401 before the handler runs.
        let response = harness
            .post_json_authenticated("/v1/credentials/ssh", &request, "invalid.token")
            .await
            .expect("Failed to post SSH cert request");
        assert_eq!(response.status, 401);
    }

    /// Test that AWS token endpoint requires valid session.
    #[tokio::test]
    async fn test_aws_token_requires_valid_session() {
        let harness = TestHarness::new().await;

        // Without auth
        let response = harness
            .get("/v1/credentials/aws/token")
            .await
            .expect("Failed to get AWS token");
        assert_eq!(response.status, 401);

        // With invalid token
        let response = harness
            .get_authenticated("/v1/credentials/aws/token", "invalid.token")
            .await
            .expect("Failed to get AWS token");
        assert_eq!(response.status, 401);
    }
}

// ============================================================================
// Priority 2: Device Authorization Flow Tests
// ============================================================================

mod device_flow {
    use super::*;

    /// Test that device code endpoint returns valid response.
    #[tokio::test]
    async fn test_device_code_returns_valid_response() {
        let harness = TestHarness::new().await;

        let response = harness
            .post_form("/oauth/device", "scope=openid")
            .await
            .expect("Failed to post device code");

        assert_eq!(response.status, 200);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");

        // Verify required fields
        assert!(resp.get("device_code").is_some(), "Should have device_code");
        assert!(resp.get("user_code").is_some(), "Should have user_code");
        assert!(
            resp.get("verification_uri").is_some(),
            "Should have verification_uri"
        );
        assert!(resp.get("expires_in").is_some(), "Should have expires_in");
    }

    /// Test that user code follows XXXX-XXXX format.
    #[tokio::test]
    async fn test_device_code_user_code_format() {
        let harness = TestHarness::new().await;

        let response = harness
            .post_form("/oauth/device", "scope=openid")
            .await
            .expect("Failed to post device code");

        assert_eq!(response.status, 200);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");
        let user_code = resp["user_code"]
            .as_str()
            .expect("user_code should be string");

        // Verify format: XXXX-XXXX
        assert!(user_code.contains('-'), "User code should contain hyphen");
        let parts: Vec<&str> = user_code.split('-').collect();
        assert_eq!(parts.len(), 2, "User code should have two parts");
        assert_eq!(parts[0].len(), 4, "First part should be 4 chars");
        assert_eq!(parts[1].len(), 4, "Second part should be 4 chars");
    }

    /// Test that polling pending authorization returns authorization_pending.
    #[tokio::test]
    async fn test_device_token_poll_authorization_pending() {
        let harness = TestHarness::new().await;

        // Create device code
        let response = harness
            .post_form("/oauth/device", "scope=openid")
            .await
            .expect("Failed to post device code");
        let resp: serde_json::Value = response.json().expect("Failed to parse response");
        let device_code = resp["device_code"].as_str().expect("device_code");

        // Poll immediately (should be pending)
        let poll_body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={}",
            device_code
        );
        let response = harness
            .post_form("/oauth/token", &poll_body)
            .await
            .expect("Failed to poll token");

        assert_eq!(response.status, 400);
        let error: serde_json::Value = response.json().expect("Failed to parse error");
        let error_code = error["error"].as_str().unwrap_or("");
        assert!(
            error_code == "authorization_pending" || error_code == "slow_down",
            "Expected authorization_pending or slow_down, got: {}",
            error_code
        );
    }

    /// Test that invalid device code returns invalid_grant.
    #[tokio::test]
    async fn test_device_token_poll_invalid_code() {
        let harness = TestHarness::new().await;

        let poll_body =
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=nonexistent";
        let response = harness
            .post_form("/oauth/token", poll_body)
            .await
            .expect("Failed to poll token");

        assert_eq!(response.status, 400);
        let error: serde_json::Value = response.json().expect("Failed to parse error");
        assert_eq!(error["error"], "invalid_grant");
    }

    /// Test that authorized device receives token.
    #[tokio::test]
    async fn test_device_token_poll_success() {
        let harness = TestHarness::new().await;

        // Create user and authenticator
        let user = harness
            .create_user("device-poll@example.com")
            .await
            .expect("Failed to create user");
        let auth_id = harness
            .create_authenticator(&user.id)
            .await
            .expect("Failed to create auth");

        // Create device code
        let response = harness
            .post_form("/oauth/device", "scope=openid")
            .await
            .expect("Failed to post device code");
        let resp: serde_json::Value = response.json().expect("Failed to parse response");
        let device_code = resp["device_code"].as_str().expect("device_code");
        let user_code = resp["user_code"].as_str().expect("user_code");

        // Authorize the device code
        harness
            .authorize_device_code(user_code, &user.id, &user.email, &auth_id)
            .await
            .expect("Failed to authorize device code");

        // Poll for token (should succeed)
        let poll_body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={}",
            device_code
        );
        let response = harness
            .post_form("/oauth/token", &poll_body)
            .await
            .expect("Failed to poll token");

        assert_eq!(response.status, 200);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");
        assert!(
            resp.get("access_token").is_some(),
            "Should have access_token"
        );
        assert_eq!(resp["token_type"], "Bearer");
    }

    /// Test that verification interval is respected.
    #[tokio::test]
    async fn test_device_code_interval_field() {
        let harness = TestHarness::new().await;

        let response = harness
            .post_form("/oauth/device", "scope=openid")
            .await
            .expect("Failed to post device code");

        assert_eq!(response.status, 200);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");

        // Interval should be present and a reasonable value
        if let Some(interval) = resp.get("interval") {
            let interval_val = interval.as_u64().unwrap_or(0);
            assert!(interval_val >= 1, "Interval should be at least 1 second");
        }
    }
}

// ============================================================================
// Priority 4: Key Registration Tests
// ============================================================================

mod register_flow {
    use super::*;

    /// Test that register start requires authentication.
    #[tokio::test]
    async fn test_register_requires_authentication() {
        let harness = TestHarness::new().await;

        #[derive(serde::Serialize)]
        struct RegisterRequest {
            name: String,
        }

        let response = harness
            .post_json(
                "/v1/keys/register/start",
                &RegisterRequest {
                    name: "New Key".to_string(),
                },
            )
            .await
            .expect("Failed to post register start");

        assert_eq!(response.status, 401);
    }

    /// Test that register start returns exclude list with existing credentials.
    #[tokio::test]
    async fn test_register_start_excludes_existing_credentials() {
        let harness = TestHarness::new().await;

        // Create authenticated user
        let (_user, _auth_id, token) = harness
            .create_authenticated_user("register@example.com")
            .await
            .expect("Failed to create authenticated user");

        #[derive(serde::Serialize)]
        struct RegisterRequest {
            name: String,
        }

        let response = harness
            .post_json_authenticated(
                "/v1/keys/register/start",
                &RegisterRequest {
                    name: "New Key".to_string(),
                },
                &token,
            )
            .await
            .expect("Failed to post register start");

        assert_eq!(response.status, 200);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");

        // Should have exclude_credential_ids
        assert!(resp.get("exclude_credential_ids").is_some());
        let exclude_ids = resp["exclude_credential_ids"].as_array().expect("array");
        // Should include at least one credential (the one from create_authenticated_user)
        assert!(
            !exclude_ids.is_empty(),
            "Should exclude existing credentials"
        );
    }

    /// Test that register complete stores authenticator.
    #[tokio::test]
    async fn test_register_returns_challenge_and_options() {
        let harness = TestHarness::new().await;

        let (_user, _auth_id, token) = harness
            .create_authenticated_user("register-options@example.com")
            .await
            .expect("Failed to create authenticated user");

        #[derive(serde::Serialize)]
        struct RegisterRequest {
            name: String,
        }

        let response = harness
            .post_json_authenticated(
                "/v1/keys/register/start",
                &RegisterRequest {
                    name: "New Key".to_string(),
                },
                &token,
            )
            .await
            .expect("Failed to post register start");

        assert_eq!(response.status, 200);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");

        // Verify all required fields
        assert!(resp.get("challenge").is_some(), "Should have challenge");
        assert!(resp.get("rp_id").is_some(), "Should have rp_id");
        assert!(resp.get("rp_name").is_some(), "Should have rp_name");
        assert!(resp.get("user_id").is_some(), "Should have user_id");
        assert!(resp.get("user_name").is_some(), "Should have user_name");
        assert!(resp.get("algorithms").is_some(), "Should have algorithms");
        assert!(resp.get("state").is_some(), "Should have state");
    }
}

// ============================================================================
// Priority 5: Key Management Tests
// ============================================================================

mod keys {
    use super::*;

    /// Test that list keys returns user's keys.
    #[tokio::test]
    async fn test_list_keys_returns_user_keys() {
        let harness = TestHarness::new().await;

        let (_user, _auth_id, token) = harness
            .create_authenticated_user("keys@example.com")
            .await
            .expect("Failed to create authenticated user");

        let response = harness
            .get_authenticated("/v1/keys", &token)
            .await
            .expect("Failed to get keys");

        assert_eq!(response.status, 200);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");
        let keys = resp["keys"].as_array().expect("keys array");
        assert!(!keys.is_empty(), "Should have at least one key");
    }

    /// Test that list keys marks current session key.
    #[tokio::test]
    async fn test_list_keys_marks_current_session() {
        let harness = TestHarness::new().await;

        let (_user, _auth_id, token) = harness
            .create_authenticated_user("keys-session@example.com")
            .await
            .expect("Failed to create authenticated user");

        let response = harness
            .get_authenticated("/v1/keys", &token)
            .await
            .expect("Failed to get keys");

        assert_eq!(response.status, 200);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");
        let keys = resp["keys"].as_array().expect("keys array");

        // At least one key should be marked as current session
        let has_current = keys
            .iter()
            .any(|k| k["is_current_session"].as_bool().unwrap_or(false));
        assert!(has_current, "Should have one key marked as current session");
    }

    /// Test that delete key requires authentication.
    #[tokio::test]
    async fn test_delete_key_requires_auth() {
        let harness = TestHarness::new().await;

        let response = HttpClient::request(
            &harness.http_client,
            "DELETE",
            &harness.url("/v1/keys/00000000-0000-7000-0000-000000000000"),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("Failed to delete key");

        assert_eq!(response.status, 401);
    }

    /// Test that deleting nonexistent key returns 404.
    #[tokio::test]
    async fn test_delete_key_not_found() {
        let harness = TestHarness::new().await;

        let (_user, _auth_id, token) = harness
            .create_authenticated_user("delete-404@example.com")
            .await
            .expect("Failed to create authenticated user");

        let response = harness
            .delete_authenticated("/v1/keys/00000000-0000-0000-0000-000000000000", &token)
            .await
            .expect("Failed to delete key");

        assert_eq!(response.status, 404);
    }

    /// Test that cannot delete another user's key.
    #[tokio::test]
    async fn test_delete_key_wrong_user() {
        let harness = TestHarness::new().await;

        // Create two users
        let (_user1, auth_id1, _token1) = harness
            .create_authenticated_user("user1@example.com")
            .await
            .expect("Failed to create user 1");

        let (_user2, _auth_id2, token2) = harness
            .create_authenticated_user("user2@example.com")
            .await
            .expect("Failed to create user 2");

        // User 2 tries to delete User 1's key
        let response = harness
            .delete_authenticated(&format!("/v1/keys/{}", auth_id1), &token2)
            .await
            .expect("Failed to delete key");

        assert_eq!(response.status, 403);
        let error: serde_json::Value = response.json().expect("Failed to parse error");
        assert_eq!(error["code"], "forbidden");
    }

    /// Test that cannot delete last key.
    #[tokio::test]
    async fn test_delete_last_key_prevented() {
        let harness = TestHarness::new().await;

        let (_user, auth_id, token) = harness
            .create_authenticated_user("last-key@example.com")
            .await
            .expect("Failed to create authenticated user");

        // Try to delete the only key
        let response = harness
            .delete_authenticated(&format!("/v1/keys/{}", auth_id), &token)
            .await
            .expect("Failed to delete key");

        assert_eq!(response.status, 400);
        let error: serde_json::Value = response.json().expect("Failed to parse error");
        assert_eq!(error["code"], "last_key");
    }

    /// Test that delete key with multiple keys succeeds.
    #[tokio::test]
    async fn test_delete_key_success_with_multiple_keys() {
        let harness = TestHarness::new().await;

        let (user, _auth_id1, token) = harness
            .create_authenticated_user("delete-success@example.com")
            .await
            .expect("Failed to create authenticated user");

        // Add a second key
        let auth_id2 = harness
            .create_authenticator(&user.id)
            .await
            .expect("Failed to create second authenticator");

        // Delete the second key (should succeed)
        let response = harness
            .delete_authenticated(&format!("/v1/keys/{}", auth_id2), &token)
            .await
            .expect("Failed to delete key");

        assert_eq!(response.status, 200);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");
        assert!(resp.get("message").is_some());
    }

    /// Test that list keys requires authentication.
    #[tokio::test]
    async fn test_list_keys_requires_auth() {
        let harness = TestHarness::new().await;

        let response = harness.get("/v1/keys").await.expect("Failed to get keys");

        assert_eq!(response.status, 401);
    }

    /// Regression test for issue #388: two concurrent DELETEs against a user
    /// with exactly two authenticators must not both succeed. The fix uses a
    /// transactional delete-then-check plus an optimistic-concurrency version
    /// bump on the User doc, so one of the two requests is guaranteed to fail
    /// (400 last_key on SQLite/DSQL, or 409 conflict if the PostgreSQL READ
    /// COMMITTED race interleaving is hit). The user must retain exactly one
    /// authenticator afterwards.
    #[tokio::test]
    async fn test_concurrent_delete_last_two_keys_prevented() {
        let harness = TestHarness::new().await;

        let (user, auth_id1, token1) = harness
            .create_authenticated_user("race-test@example.com")
            .await
            .expect("Failed to create authenticated user");

        let auth_id2 = harness
            .create_authenticator(&user.id)
            .await
            .expect("Failed to create second authenticator");
        let token2 = harness
            .create_session(&user.id, "race-test@example.com", &auth_id2)
            .await
            .expect("Failed to create second session");

        let path1 = format!("/v1/keys/{}", auth_id1);
        let path2 = format!("/v1/keys/{}", auth_id2);
        let (r1, r2) = tokio::join!(
            harness.delete_authenticated(&path1, &token1),
            harness.delete_authenticated(&path2, &token2),
        );
        let s1 = r1.expect("Failed to send delete 1").status;
        let s2 = r2.expect("Failed to send delete 2").status;

        assert!(
            s1 == 200 || s2 == 200,
            "at least one delete should succeed (got {s1} and {s2})"
        );
        assert!(
            !(s1 == 200 && s2 == 200),
            "both deletes must not succeed (got {s1} and {s2})"
        );
        // The losing request must be either 400 (last_key, caught by the
        // pre/post count check) or 409 (conflict, caught by the User-doc
        // version bump). Anything else (500, panic) is a regression.
        let loser = if s1 == 200 { s2 } else { s1 };
        assert!(
            loser == 400 || loser == 409,
            "losing delete must return 400 or 409, got {loser} (s1={s1} s2={s2})"
        );

        let remaining =
            vouch_server::db::get_authenticators_for_user(&harness.state.store, &user.id)
                .await
                .expect("Failed to query remaining authenticators");
        assert_eq!(
            remaining.len(),
            1,
            "user must retain exactly one authenticator after concurrent deletes"
        );
    }
}

// ============================================================================
// Priority 6: OIDC Provider Tests
// ============================================================================

mod oidc {
    use super::*;

    /// Test that discovery returns required fields.
    #[tokio::test]
    async fn test_discovery_returns_required_fields() {
        let harness = TestHarness::new().await;

        let response = harness
            .get("/.well-known/openid-configuration")
            .await
            .expect("Failed to get discovery");

        assert_eq!(response.status, 200);
        let disc: serde_json::Value = response.json().expect("Failed to parse response");

        // OIDC Core 1.0 required fields
        assert!(disc.get("issuer").is_some(), "Should have issuer");
        assert!(
            disc.get("authorization_endpoint").is_some(),
            "Should have authorization_endpoint"
        );
        assert!(
            disc.get("token_endpoint").is_some(),
            "Should have token_endpoint"
        );
        assert!(disc.get("jwks_uri").is_some(), "Should have jwks_uri");
        assert!(
            disc.get("response_types_supported").is_some(),
            "Should have response_types_supported"
        );
        assert!(
            disc.get("subject_types_supported").is_some(),
            "Should have subject_types_supported"
        );
        assert!(
            disc.get("id_token_signing_alg_values_supported").is_some(),
            "Should have id_token_signing_alg_values_supported"
        );
    }

    /// Test that JWKS returns keys.
    #[tokio::test]
    async fn test_jwks_returns_keys() {
        let harness = TestHarness::new().await;

        let response = harness
            .get("/oauth/jwks")
            .await
            .expect("Failed to get JWKS");

        assert_eq!(response.status, 200);
        let jwks: serde_json::Value = response.json().expect("Failed to parse response");
        assert!(jwks.get("keys").is_some(), "Should have keys array");
        let keys = jwks["keys"].as_array().expect("keys array");
        assert!(!keys.is_empty(), "Should have at least one key");
    }

    /// Test that userinfo requires bearer token.
    ///
    /// RFC 6750 Section 3.1: When the request lacks any authentication
    /// information, the WWW-Authenticate challenge SHOULD NOT include an
    /// error code.
    #[tokio::test]
    async fn test_userinfo_requires_bearer_token() {
        let harness = TestHarness::new().await;

        let response = harness
            .get("/oauth/userinfo")
            .await
            .expect("Failed to get userinfo");

        assert_eq!(response.status, 401);
        let www_auth = response
            .www_authenticate
            .as_deref()
            .expect("Should have WWW-Authenticate header");
        assert!(
            www_auth.starts_with("Bearer"),
            "No-auth response must use Bearer challenge per RFC 6750 Section 3.1, got: {www_auth}"
        );
        // RFC 9728 §5.2: the middleware appends resource_metadata to 401s
        // from protected resources. This is compatible with RFC 6750 §3.1
        // (no error code when authentication info is absent).
        assert!(
            www_auth.contains("resource_metadata="),
            "401 from a protected resource should include resource_metadata (RFC 9728 §5.2)"
        );
    }

    /// Test that userinfo returns claims with valid token.
    #[tokio::test]
    async fn test_userinfo_returns_claims() {
        let harness = TestHarness::new().await;

        let (_user, _auth_id, token) = harness
            .create_authenticated_user("userinfo@example.com")
            .await
            .expect("Failed to create authenticated user");

        let response = harness
            .get_authenticated("/oauth/userinfo", &token)
            .await
            .expect("Failed to get userinfo");

        assert_eq!(response.status, 200);
        let userinfo: serde_json::Value = response.json().expect("Failed to parse response");
        assert!(userinfo.get("sub").is_some(), "Should have sub claim");
        // OAuth access tokens include email scope, so email is present
        assert_eq!(
            userinfo["email"].as_str(),
            Some("userinfo@example.com"),
            "Email should be present when email scope is granted"
        );
        // Custom claims such as hardware_verified are excluded from standard
        // OIDC userinfo responses unless explicitly requested.
        assert!(
            userinfo.get("hardware_verified").is_none(),
            "hardware_verified should not be in standard userinfo response"
        );
    }

    /// Test that revoke token succeeds.
    #[tokio::test]
    async fn test_revoke_token_succeeds() {
        let harness = TestHarness::new().await;

        let (user, _auth_id, token) = harness
            .create_authenticated_user("revoke@example.com")
            .await
            .expect("Failed to create authenticated user");

        // RFC 7009 Section 2.1: Revocation requires client authentication
        let client = harness
            .create_oauth_client(&user.id)
            .await
            .expect("Failed to create OAuth client");
        let auth_header = client.basic_auth_header();

        let response = harness
            .post_form_with_auth("/oauth/revoke", &format!("token={}", token), &auth_header)
            .await
            .expect("Failed to revoke token");

        // RFC 7009: Always returns 200
        assert_eq!(response.status, 200);
    }

    /// Test that introspect returns active token metadata.
    #[tokio::test]
    async fn test_introspect_active_token() {
        let harness = TestHarness::new().await;

        let (user, auth_id, _token) = harness
            .create_authenticated_user("introspect@example.com")
            .await
            .expect("Failed to create authenticated user");

        // RFC 7662: Introspection requires client authentication.
        // Create the OAuth client first, then issue a session bound to it
        // so the token's client_id matches the introspecting client
        // (RFC 7662 Section 4: cross-client protection).
        let client = harness
            .create_oauth_client(&user.id)
            .await
            .expect("Failed to create OAuth client");
        let auth_header = client.basic_auth_header();

        let token = harness
            .create_session_for_client(
                &user.id,
                "introspect@example.com",
                &auth_id,
                &client.client_id,
            )
            .await
            .expect("Failed to create client-bound session");

        let response = harness
            .post_form_with_auth(
                "/oauth/introspect",
                &format!("token={}", token),
                &auth_header,
            )
            .await
            .expect("Failed to introspect token");

        assert_eq!(response.status, 200);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");
        assert_eq!(resp["active"], true);
        assert!(resp.get("exp").is_some(), "Should have exp");
        assert!(resp.get("sub").is_some(), "Should have sub");
    }
}

// ============================================================================
// Priority 7: Token Exchange Tests
// ============================================================================

mod token_exchange {
    use super::*;

    /// Test that token exchange requires valid subject token.
    #[tokio::test]
    async fn test_token_exchange_invalid_subject_token() {
        let harness = TestHarness::new().await;

        // Token exchange requires client authentication (RFC 8693)
        let (user, _auth_id, _token) = harness
            .create_authenticated_user("exchange-invalid-subj@example.com")
            .await
            .expect("Failed to create authenticated user");
        let client = harness
            .create_oauth_client(&user.id)
            .await
            .expect("Failed to create OAuth client");
        let auth_header = client.basic_auth_header();

        let body = "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=invalid&subject_token_type=urn:ietf:params:oauth:token-type:access_token";
        let response = harness
            .post_form_with_auth("/oauth/token", body, &auth_header)
            .await
            .expect("Failed to exchange token");

        assert_eq!(response.status, 400);
        let error: serde_json::Value = response.json().expect("Failed to parse error");
        assert_eq!(error["error"], "invalid_grant");
    }

    /// Test that token exchange works with valid token.
    #[tokio::test]
    async fn test_token_exchange_valid() {
        let harness = TestHarness::new().await;

        let (user, _auth_id, token) = harness
            .create_authenticated_user("exchange@example.com")
            .await
            .expect("Failed to create authenticated user");

        // Token exchange requires client authentication (RFC 8693)
        let client = harness
            .create_oauth_client(&user.id)
            .await
            .expect("Failed to create OAuth client");
        let auth_header = client.basic_auth_header();

        let body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            token
        );
        let response = harness
            .post_form_with_auth("/oauth/token", &body, &auth_header)
            .await
            .expect("Failed to exchange token");

        assert_eq!(response.status, 200);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");
        assert!(
            resp.get("access_token").is_some(),
            "Should have access_token"
        );
        assert!(
            resp.get("issued_token_type").is_some(),
            "Should have issued_token_type"
        );
        assert!(resp.get("token_type").is_some(), "Should have token_type");
        assert!(resp.get("expires_in").is_some(), "Should have expires_in");
    }

    /// Test that token exchange can reduce scope.
    #[tokio::test]
    async fn test_token_exchange_scope_downgrade() {
        let harness = TestHarness::new().await;

        let (user, _auth_id, token) = harness
            .create_authenticated_user("exchange-scope@example.com")
            .await
            .expect("Failed to create authenticated user");

        // Token exchange requires client authentication (RFC 8693)
        let client = harness
            .create_oauth_client(&user.id)
            .await
            .expect("Failed to create OAuth client");
        let auth_header = client.basic_auth_header();

        let body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token&scope=openid",
            token
        );
        let response = harness
            .post_form_with_auth("/oauth/token", &body, &auth_header)
            .await
            .expect("Failed to exchange token");

        assert_eq!(response.status, 200);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");
        // Should have requested scope or subset
        if let Some(scope) = resp.get("scope").and_then(|s| s.as_str()) {
            assert!(scope.contains("openid") || scope.is_empty());
        }
    }

    /// Test that invalid token type returns error.
    #[tokio::test]
    async fn test_token_exchange_invalid_token_type() {
        let harness = TestHarness::new().await;

        let (user, _auth_id, token) = harness
            .create_authenticated_user("exchange-bad-type@example.com")
            .await
            .expect("Failed to create authenticated user");

        // Token exchange requires client authentication (RFC 8693)
        let client = harness
            .create_oauth_client(&user.id)
            .await
            .expect("Failed to create OAuth client");
        let auth_header = client.basic_auth_header();

        let body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=invalid:token:type",
            token
        );
        let response = harness
            .post_form_with_auth("/oauth/token", &body, &auth_header)
            .await
            .expect("Failed to exchange token");

        assert_eq!(response.status, 400);
        let error: serde_json::Value = response.json().expect("Failed to parse error");
        assert_eq!(error["error"], "invalid_request");
    }
}

// ============================================================================
// Priority 8: SCIM 2.0 Tests
// ============================================================================

mod scim {
    use super::*;

    /// Test that SCIM endpoints require authentication.
    #[tokio::test]
    async fn test_scim_requires_bearer_token() {
        let harness = TestHarness::new().await;

        // Try to list users without auth
        let response = harness
            .get("/scim/v2/Users")
            .await
            .expect("Failed to get SCIM users");

        assert_eq!(response.status, 401);
    }

    /// Test that SCIM can list users with valid token.
    #[tokio::test]
    async fn test_scim_list_users() {
        let harness = TestHarness::new().await;

        let org = harness
            .create_org("scim-list.example.com")
            .await
            .expect("Failed to create org");
        let scim_token = harness
            .create_scim_token("Test SCIM Token", &org.id)
            .await
            .expect("Failed to create SCIM token");

        let response = harness
            .get_authenticated("/scim/v2/Users", &scim_token)
            .await
            .expect("Failed to get SCIM users");

        assert_eq!(response.status, 200);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");
        assert!(resp.get("schemas").is_some(), "Should have schemas");
        assert!(resp.get("Resources").is_some(), "Should have Resources");
    }

    /// Test SCIM service provider config endpoint.
    #[tokio::test]
    async fn test_scim_service_provider_config() {
        let harness = TestHarness::new().await;

        let response = harness
            .get("/scim/v2/ServiceProviderConfig")
            .await
            .expect("Failed to get SCIM config");

        assert_eq!(response.status, 200);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");
        assert!(resp.get("schemas").is_some(), "Should have schemas");
    }

    /// Test SCIM schemas endpoint.
    #[tokio::test]
    async fn test_scim_schemas() {
        let harness = TestHarness::new().await;

        let response = harness
            .get("/scim/v2/Schemas")
            .await
            .expect("Failed to get SCIM schemas");

        assert_eq!(response.status, 200);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");
        assert!(
            resp.get("schemas").is_some() || resp.as_array().is_some(),
            "Should return schemas"
        );
    }

    /// Test SCIM resource types endpoint.
    #[tokio::test]
    async fn test_scim_resource_types() {
        let harness = TestHarness::new().await;

        let response = harness
            .get("/scim/v2/ResourceTypes")
            .await
            .expect("Failed to get SCIM resource types");

        assert_eq!(response.status, 200);
    }

    /// Test SCIM create user.
    #[tokio::test]
    async fn test_scim_create_user() {
        let harness = TestHarness::new().await;

        let org = harness
            .create_org("scim-create.example.com")
            .await
            .expect("Failed to create org");
        let scim_token = harness
            .create_scim_token("Test SCIM Token", &org.id)
            .await
            .expect("Failed to create SCIM token");

        #[derive(serde::Serialize)]
        struct ScimUserCreate {
            schemas: Vec<String>,
            #[serde(rename = "userName")]
            user_name: String,
            active: bool,
        }

        let user = ScimUserCreate {
            schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:User".to_string()],
            user_name: "scim-new@scim-create.example.com".to_string(),
            active: true,
        };

        let response = harness
            .post_json_authenticated("/scim/v2/Users", &user, &scim_token)
            .await
            .expect("Failed to create SCIM user");

        assert_eq!(response.status, 201);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");
        assert!(resp.get("id").is_some(), "Should have id");
        assert_eq!(resp["userName"], "scim-new@scim-create.example.com");
    }

    /// Test SCIM get user by ID.
    #[tokio::test]
    async fn test_scim_get_user() {
        let harness = TestHarness::new().await;

        let org = harness
            .create_org("scim-get.example.com")
            .await
            .expect("Failed to create org");
        let scim_token = harness
            .create_scim_token("Test SCIM Token", &org.id)
            .await
            .expect("Failed to create SCIM token");

        // Create user via SCIM (which binds them to the org) so that the
        // org-scoped GET finds them.
        #[derive(serde::Serialize)]
        struct ScimUserCreate {
            schemas: Vec<String>,
            #[serde(rename = "userName")]
            user_name: String,
        }
        let create_resp = harness
            .post_json_authenticated(
                "/scim/v2/Users",
                &ScimUserCreate {
                    schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:User".to_string()],
                    user_name: "scim-get@scim-get.example.com".to_string(),
                },
                &scim_token,
            )
            .await
            .expect("Failed to create SCIM user");
        assert_eq!(create_resp.status, 201);
        let created: serde_json::Value = create_resp.json().expect("Failed to parse response");
        let user_id = created["id"].as_str().expect("user id");

        let response = harness
            .get_authenticated(&format!("/scim/v2/Users/{}", user_id), &scim_token)
            .await
            .expect("Failed to get SCIM user");

        assert_eq!(response.status, 200);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");
        assert_eq!(resp["id"], user_id);
    }

    /// Test SCIM get user not found.
    #[tokio::test]
    async fn test_scim_get_user_not_found() {
        let harness = TestHarness::new().await;

        let org = harness
            .create_org("scim-notfound.example.com")
            .await
            .expect("Failed to create org");
        let scim_token = harness
            .create_scim_token("Test SCIM Token", &org.id)
            .await
            .expect("Failed to create SCIM token");

        let response = harness
            .get_authenticated(
                "/scim/v2/Users/00000000-0000-0000-0000-000000000000",
                &scim_token,
            )
            .await
            .expect("Failed to get SCIM user");

        assert_eq!(response.status, 404);
    }

    /// Test SCIM delete user.
    #[tokio::test]
    async fn test_scim_delete_user() {
        let harness = TestHarness::new().await;

        let org = harness
            .create_org("scim-delete.example.com")
            .await
            .expect("Failed to create org");
        let scim_token = harness
            .create_scim_token("Test SCIM Token", &org.id)
            .await
            .expect("Failed to create SCIM token");

        // Create the user via SCIM so they are bound to the org.
        #[derive(serde::Serialize)]
        struct ScimUserCreate {
            schemas: Vec<String>,
            #[serde(rename = "userName")]
            user_name: String,
        }
        let create_resp = harness
            .post_json_authenticated(
                "/scim/v2/Users",
                &ScimUserCreate {
                    schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:User".to_string()],
                    user_name: "scim-delete@scim-delete.example.com".to_string(),
                },
                &scim_token,
            )
            .await
            .expect("Failed to create SCIM user");
        assert_eq!(create_resp.status, 201);
        let created: serde_json::Value = create_resp.json().expect("Failed to parse response");
        let user_id = created["id"].as_str().expect("user id");

        let response = harness
            .delete_authenticated(&format!("/scim/v2/Users/{}", user_id), &scim_token)
            .await
            .expect("Failed to delete SCIM user");

        // SCIM delete returns 204 No Content
        assert_eq!(response.status, 204);

        // Verify user is gone
        let response = harness
            .get_authenticated(&format!("/scim/v2/Users/{}", user_id), &scim_token)
            .await
            .expect("Failed to get SCIM user");
        assert_eq!(response.status, 404);
    }
}

// ============================================================================
// Priority 9: Session Management Tests
// ============================================================================

mod session {
    use super::*;

    /// Test that session status shows correct expiration.
    #[tokio::test]
    async fn test_session_status_shows_expiration() {
        let harness = TestHarness::new().await;

        let (_user, _auth_id, token) = harness
            .create_authenticated_user("session-exp@example.com")
            .await
            .expect("Failed to create authenticated user");

        let response = harness
            .get_authenticated("/v1/auth/status", &token)
            .await
            .expect("Failed to get auth status");

        assert_eq!(response.status, 200);
        let status: serde_json::Value = response.json().expect("Failed to parse response");
        assert_eq!(status["authenticated"], true);
        assert!(
            status.get("expires_in_seconds").is_some(),
            "Should have expiration"
        );
        let expires_in = status["expires_in_seconds"].as_u64().expect("expires_in");
        // Should be roughly 8 hours (less a few seconds)
        assert!(expires_in > 28000, "Session should have ~8 hours remaining");
    }

    /// Test that logout clears session.
    #[tokio::test]
    async fn test_logout_via_revoke_clears_session() {
        let harness = TestHarness::new().await;

        let (user, auth_id, _raw_token) = harness
            .create_authenticated_user("logout@example.com")
            .await
            .expect("Failed to create authenticated user");

        // RFC 7009 Section 2.1: Revocation requires client authentication.
        // Token must be bound to the client for ownership check.
        let client = harness
            .create_oauth_client(&user.id)
            .await
            .expect("Failed to create OAuth client");
        let token = harness
            .create_session_for_client(&user.id, &user.email, &auth_id, &client.client_id)
            .await
            .expect("Failed to create client-bound session");
        let auth_header = client.basic_auth_header();

        // Verify token works
        let response = harness
            .get_authenticated("/v1/auth/status", &token)
            .await
            .expect("Failed to get auth status");
        let status: serde_json::Value = response.json().expect("Failed to parse response");
        assert_eq!(status["authenticated"], true);

        // Revoke the token
        harness
            .post_form_with_auth("/oauth/revoke", &format!("token={}", token), &auth_header)
            .await
            .expect("Failed to revoke token");

        // Verify token no longer works
        let response = harness
            .get_authenticated("/v1/auth/status", &token)
            .await
            .expect("Failed to get auth status");
        let status: serde_json::Value = response.json().expect("Failed to parse response");
        assert_eq!(status["authenticated"], false);
    }

    /// Test that session shows device name.
    #[tokio::test]
    async fn test_session_status_shows_device_name() {
        let harness = TestHarness::new().await;

        let (_user, _auth_id, token) = harness
            .create_authenticated_user("session-device@example.com")
            .await
            .expect("Failed to create authenticated user");

        let response = harness
            .get_authenticated("/v1/auth/status", &token)
            .await
            .expect("Failed to get auth status");

        assert_eq!(response.status, 200);
        let status: serde_json::Value = response.json().expect("Failed to parse response");
        assert!(
            status.get("device_name").is_some(),
            "Should have device name"
        );
    }
}

/// ES256 (ECDSA P-256) signature verification tests.
/// These tests replicate the exact flow used by real YubiKeys.
mod es256_flow {
    use aws_lc_rs::digest::{SHA256, digest};
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    };
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ciborium::Value;
    use vouch_server::crypto::webauthn_verify::{CoseVerifier, RealCoseVerifier};

    /// Build a COSE EC2 key for ES256 (P-256) in the format used by cose_key_to_cbor.
    fn build_cose_ec2_key(x: &[u8], y: &[u8]) -> Vec<u8> {
        let map: Vec<(Value, Value)> = vec![
            (Value::Integer(1.into()), Value::Integer(2.into())), // kty = EC2
            (Value::Integer(3.into()), Value::Integer((-7_i64).into())), // alg = ES256 (-7)
            (Value::Integer((-1_i64).into()), Value::Integer(1.into())), // crv = P-256 (1)
            (Value::Integer((-2_i64).into()), Value::Bytes(x.to_vec())), // x
            (Value::Integer((-3_i64).into()), Value::Bytes(y.to_vec())), // y
        ];

        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut buf).expect("Failed to encode COSE key");
        buf
    }

    /// Build client data JSON for WebAuthn get assertion.
    fn build_client_data_json(challenge: &[u8], origin: &str) -> Vec<u8> {
        let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge);
        let json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
            challenge_b64, origin
        );
        json.into_bytes()
    }

    /// Build authenticator data for the given RP ID.
    fn build_authenticator_data(rp_id: &str, counter: u32) -> Vec<u8> {
        let rp_id_hash = digest(&SHA256, rp_id.as_bytes());
        let flags = 0x05u8; // UP (0x01) + UV (0x04)

        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(rp_id_hash.as_ref()); // 32 bytes
        auth_data.push(flags); // 1 byte
        auth_data.extend_from_slice(&counter.to_be_bytes()); // 4 bytes
        auth_data
    }

    /// Test ES256 signature verification with DER format (like CTAP2/YubiKey).
    #[test]
    fn test_es256_der_signature_verification() {
        let rng = SystemRandom::new();

        // Generate an ECDSA P-256 key pair (ASN.1/DER signatures)
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("Failed to generate key pair");
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_ref())
                .expect("Failed to parse key pair");

        // Extract the public key (uncompressed SEC1 format: 0x04 || x || y)
        let public_key = key_pair.public_key();
        let public_key_bytes = public_key.as_ref();

        // SEC1 uncompressed point is 65 bytes: 0x04 + 32 bytes x + 32 bytes y
        assert_eq!(
            public_key_bytes.len(),
            65,
            "Public key should be 65 bytes (SEC1 uncompressed)"
        );
        assert_eq!(public_key_bytes[0], 0x04, "First byte should be 0x04");

        let x = &public_key_bytes[1..33];
        let y = &public_key_bytes[33..65];

        // Build COSE key (same format as cose_key_to_cbor produces)
        let cose_key = build_cose_ec2_key(x, y);

        // Build the message to sign (authenticator_data || SHA256(client_data_json))
        let rp_id = "dev.vouch.sh";
        let challenge = [0x42u8; 32];
        let origin = format!("https://{}", rp_id);

        let auth_data = build_authenticator_data(rp_id, 1);
        let client_data_json = build_client_data_json(&challenge, &origin);
        let client_data_hash = digest(&SHA256, &client_data_json);

        let mut message = Vec::with_capacity(auth_data.len() + 32);
        message.extend_from_slice(&auth_data);
        message.extend_from_slice(client_data_hash.as_ref());

        // Sign the message (produces DER-encoded signature)
        let signature = key_pair.sign(&rng, &message).expect("Failed to sign");
        let signature_bytes = signature.as_ref();

        println!("ES256 DER test:");
        println!(
            "  public_key_bytes (SEC1): {} bytes",
            public_key_bytes.len()
        );
        println!("  x: {}", hex::encode(x));
        println!("  y: {}", hex::encode(y));
        println!(
            "  cose_key: {} bytes = {}",
            cose_key.len(),
            hex::encode(&cose_key)
        );
        println!(
            "  signature: {} bytes (should be 70-72 for DER)",
            signature_bytes.len()
        );
        println!("  message: {} bytes", message.len());

        // Verify using the server's verification code
        let verifier = RealCoseVerifier::new();
        let result = verifier.verify(&cose_key, &message, signature_bytes);

        assert!(
            result.is_ok(),
            "ES256 DER signature verification should succeed: {:?}",
            result
        );
    }

    /// A raw r||s ES256 signature must be rejected.
    ///
    /// This test previously asserted the opposite, on the premise that
    /// browsers emit the fixed format. WebAuthn Level 2 Section 6.5.5 says
    /// otherwise: "For COSEAlgorithmIdentifier -7 (ES256), and other
    /// ECDSA-based algorithms, the sig value MUST be encoded as an ASN.1 DER
    /// Ecdsa-Sig-Value, as defined in [RFC3279] section 2.2.3." The adjacent
    /// Note confirms CTAP2 authenticators use that same encoding, and
    /// browsers relay the authenticator's signature unchanged.
    #[test]
    fn test_es256_fixed_signature_is_rejected() {
        let rng = SystemRandom::new();

        // Generate an ECDSA P-256 key pair (fixed/raw signatures - r||s format)
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("Failed to generate key pair");
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes.as_ref())
                .expect("Failed to parse key pair");

        // Extract the public key
        let public_key = key_pair.public_key();
        let public_key_bytes = public_key.as_ref();

        let x = &public_key_bytes[1..33];
        let y = &public_key_bytes[33..65];

        // Build COSE key
        let cose_key = build_cose_ec2_key(x, y);

        // Build the message to sign
        let rp_id = "dev.vouch.sh";
        let challenge = [0x42u8; 32];
        let origin = format!("https://{}", rp_id);

        let auth_data = build_authenticator_data(rp_id, 1);
        let client_data_json = build_client_data_json(&challenge, &origin);
        let client_data_hash = digest(&SHA256, &client_data_json);

        let mut message = Vec::with_capacity(auth_data.len() + 32);
        message.extend_from_slice(&auth_data);
        message.extend_from_slice(client_data_hash.as_ref());

        // Sign the message (produces fixed 64-byte r||s signature)
        let signature = key_pair.sign(&rng, &message).expect("Failed to sign");
        let signature_bytes = signature.as_ref();

        assert_eq!(
            signature_bytes.len(),
            64,
            "the fixed signer produces a 64-byte r||s pair"
        );

        // Verify using the server's verification code
        let verifier = RealCoseVerifier::new();
        let result = verifier.verify(&cose_key, &message, signature_bytes);

        assert!(
            result.is_err(),
            "a raw r||s ES256 signature is not a conformant WebAuthn encoding \
             and must not verify: {:?}",
            result
        );
    }

    /// Test that simulates the exact browser enrollment + CLI login flow.
    /// Browser enrollment stores public key via webauthn-rs (cose_key_to_cbor).
    /// CLI login gets assertion from YubiKey (DER signature) and sends to server.
    #[test]
    fn test_browser_enrollment_cli_login_es256_flow() {
        let rng = SystemRandom::new();

        // === BROWSER ENROLLMENT ===
        // webauthn-rs extracts x, y from attestation and we call cose_key_to_cbor
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("Failed to generate key pair");
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_ref())
                .expect("Failed to parse key pair");

        let public_key = key_pair.public_key();
        let public_key_bytes = public_key.as_ref();
        let x = &public_key_bytes[1..33];
        let y = &public_key_bytes[33..65];

        // This is what cose_key_to_cbor produces during browser enrollment
        let stored_cose_key = build_cose_ec2_key(x, y);

        println!("=== BROWSER ENROLLMENT ===");
        println!(
            "Stored COSE key ({} bytes): {}",
            stored_cose_key.len(),
            hex::encode(&stored_cose_key)
        );

        // === CLI LOGIN ===
        // CLI constructs client_data_json and gets assertion from YubiKey
        let rp_id = "dev.vouch.sh";
        let challenge = [0xABu8; 32]; // Different challenge for login
        let origin = format!("https://{}", rp_id);

        // CLI builds client_data_json
        let client_data_json = build_client_data_json(&challenge, &origin);
        let client_data_hash = digest(&SHA256, &client_data_json);

        // YubiKey builds authenticator_data and signs
        let auth_data = build_authenticator_data(rp_id, 1);

        // YubiKey signs: authenticator_data || client_data_hash
        let mut signed_data = Vec::with_capacity(auth_data.len() + 32);
        signed_data.extend_from_slice(&auth_data);
        signed_data.extend_from_slice(client_data_hash.as_ref());

        // YubiKey produces DER signature
        let signature = key_pair.sign(&rng, &signed_data).expect("Failed to sign");

        println!("=== CLI LOGIN ===");
        println!(
            "client_data_json: {}",
            String::from_utf8_lossy(&client_data_json)
        );
        println!(
            "client_data_hash: {}",
            hex::encode(client_data_hash.as_ref())
        );
        println!(
            "auth_data ({} bytes): {}",
            auth_data.len(),
            hex::encode(&auth_data)
        );
        println!(
            "signed_data ({} bytes): {}",
            signed_data.len(),
            hex::encode(&signed_data)
        );
        println!(
            "signature ({} bytes): {}",
            signature.as_ref().len(),
            hex::encode(signature.as_ref())
        );

        // === SERVER VERIFICATION ===
        // Server receives: auth_data, client_data_json, signature
        // Server looks up stored_cose_key from database
        // Server builds signed_data and verifies

        let server_client_data_hash = digest(&SHA256, &client_data_json);
        let mut server_signed_data = Vec::with_capacity(auth_data.len() + 32);
        server_signed_data.extend_from_slice(&auth_data);
        server_signed_data.extend_from_slice(server_client_data_hash.as_ref());

        println!("=== SERVER VERIFICATION ===");
        println!(
            "server_client_data_hash: {}",
            hex::encode(server_client_data_hash.as_ref())
        );
        println!(
            "server_signed_data ({} bytes): {}",
            server_signed_data.len(),
            hex::encode(&server_signed_data)
        );

        // Verify the message matches what was signed
        assert_eq!(
            signed_data, server_signed_data,
            "Server should construct same signed_data"
        );

        let verifier = RealCoseVerifier::new();
        let result = verifier.verify(&stored_cose_key, &server_signed_data, signature.as_ref());

        assert!(
            result.is_ok(),
            "Browser enrollment + CLI login ES256 flow should succeed: {:?}",
            result
        );
    }

    /// Diagnostic test using actual data from production logs.
    /// This helps identify parsing/verification issues.
    #[test]
    fn test_parse_production_cose_key() {
        // This is the actual stored_public_key_hex from the login logs
        let stored_key_hex = "a50102032620012158203ff01435ac5cca700aff1a0bfd61776ef85b60085c47a39f26b8932a596528f022582047332d1c68fe933c56b2fcf502fe2cb74cb8d2f8a4eb0c7f61a92f6bd0893328";
        let stored_key = hex::decode(stored_key_hex).expect("Failed to decode hex");

        println!("Stored key length: {} bytes", stored_key.len());
        println!("Stored key hex: {}", stored_key_hex);

        // Parse the CBOR
        let parsed: ciborium::Value =
            ciborium::from_reader(&stored_key[..]).expect("Failed to parse CBOR");

        let map = parsed.as_map().expect("Should be a map");
        println!("Map has {} entries", map.len());

        let mut kty: Option<i128> = None;
        let mut alg: Option<i128> = None;
        let mut crv: Option<i128> = None;
        let mut x_bytes: Option<Vec<u8>> = None;
        let mut y_bytes: Option<Vec<u8>> = None;

        for (k, v) in map {
            if let ciborium::Value::Integer(key) = k {
                let key_i128: i128 = (*key).into();
                match key_i128 {
                    1 => {
                        if let ciborium::Value::Integer(val) = v {
                            kty = Some((*val).into());
                        }
                    }
                    3 => {
                        if let ciborium::Value::Integer(val) = v {
                            alg = Some((*val).into());
                        }
                    }
                    -1 => {
                        if let ciborium::Value::Integer(val) = v {
                            crv = Some((*val).into());
                        }
                    }
                    -2 => {
                        if let ciborium::Value::Bytes(bytes) = v {
                            x_bytes = Some(bytes.clone());
                        }
                    }
                    -3 => {
                        if let ciborium::Value::Bytes(bytes) = v {
                            y_bytes = Some(bytes.clone());
                        }
                    }
                    _ => {}
                }
            }
        }

        println!("kty = {:?} (expected 2 for EC2)", kty);
        println!("alg = {:?} (expected -7 for ES256)", alg);
        println!("crv = {:?} (expected 1 for P-256)", crv);
        println!(
            "x = {:?} ({:?} bytes)",
            x_bytes.as_ref().map(hex::encode),
            x_bytes.as_ref().map(|b| b.len())
        );
        println!(
            "y = {:?} ({:?} bytes)",
            y_bytes.as_ref().map(hex::encode),
            y_bytes.as_ref().map(|b| b.len())
        );

        assert_eq!(kty, Some(2), "kty should be 2 (EC2)");
        assert_eq!(alg, Some(-7), "alg should be -7 (ES256)");
        assert_eq!(crv, Some(1), "crv should be 1 (P-256)");
        assert_eq!(
            x_bytes.as_ref().map(|b| b.len()),
            Some(32),
            "x should be 32 bytes"
        );
        assert_eq!(
            y_bytes.as_ref().map(|b| b.len()),
            Some(32),
            "y should be 32 bytes"
        );

        // Now try to verify using the RealCoseVerifier (without a real signature)
        // Just to make sure the key can be parsed by the verification code
        let verifier = RealCoseVerifier::new();

        // Create a dummy message and signature - this will fail verification
        // but should NOT fail parsing
        let dummy_message = [0u8; 69];
        let dummy_signature = [0u8; 72];

        let result = verifier.verify(&stored_key, &dummy_message, &dummy_signature);
        // We expect SignatureInvalid, NOT InvalidCoseKey
        println!(
            "Verification result (expected SignatureInvalid): {:?}",
            result
        );

        // The key should parse correctly even if signature is invalid
        match result {
            Err(e) => {
                let err_str = format!("{:?}", e);
                assert!(
                    !err_str.contains("InvalidCoseKey"),
                    "Key parsing should succeed, got: {}",
                    err_str
                );
            }
            Ok(_) => panic!("Should not succeed with dummy signature"),
        }
    }

    /// Test that COSE key encoding matches expected format.
    #[test]
    fn test_cose_key_encoding_format() {
        // Build a COSE key and verify it can be parsed correctly
        let x = [0x11u8; 32];
        let y = [0x22u8; 32];

        let cose_key = build_cose_ec2_key(&x, &y);

        println!("COSE key hex: {}", hex::encode(&cose_key));

        // Parse it back
        let parsed: ciborium::Value =
            ciborium::from_reader(&cose_key[..]).expect("Failed to parse COSE key");

        let map = parsed.as_map().expect("Should be a map");

        // Extract and verify each field
        let mut found_kty = false;
        let mut found_alg = false;
        let mut found_crv = false;
        let mut found_x = false;
        let mut found_y = false;

        for (k, v) in map {
            if let ciborium::Value::Integer(key) = k {
                let key_i128: i128 = (*key).into();
                match key_i128 {
                    1 => {
                        // kty
                        if let ciborium::Value::Integer(val) = v {
                            let val_i128: i128 = (*val).into();
                            assert_eq!(val_i128, 2, "kty should be 2 (EC2)");
                            found_kty = true;
                            println!("kty = {}", val_i128);
                        }
                    }
                    3 => {
                        // alg
                        if let ciborium::Value::Integer(val) = v {
                            let val_i128: i128 = (*val).into();
                            assert_eq!(val_i128, -7, "alg should be -7 (ES256)");
                            found_alg = true;
                            println!("alg = {}", val_i128);
                        }
                    }
                    -1 => {
                        // crv
                        if let ciborium::Value::Integer(val) = v {
                            let val_i128: i128 = (*val).into();
                            assert_eq!(val_i128, 1, "crv should be 1 (P-256)");
                            found_crv = true;
                            println!("crv = {}", val_i128);
                        }
                    }
                    -2 => {
                        // x
                        if let ciborium::Value::Bytes(bytes) = v {
                            assert_eq!(bytes.len(), 32, "x should be 32 bytes");
                            assert_eq!(&bytes[..], &x[..], "x should match");
                            found_x = true;
                            println!("x = {} ({} bytes)", hex::encode(bytes), bytes.len());
                        }
                    }
                    -3 => {
                        // y
                        if let ciborium::Value::Bytes(bytes) = v {
                            assert_eq!(bytes.len(), 32, "y should be 32 bytes");
                            assert_eq!(&bytes[..], &y[..], "y should match");
                            found_y = true;
                            println!("y = {} ({} bytes)", hex::encode(bytes), bytes.len());
                        }
                    }
                    _ => {
                        println!("Unknown key: {}", key_i128);
                    }
                }
            }
        }

        assert!(found_kty, "Should have kty");
        assert!(found_alg, "Should have alg");
        assert!(found_crv, "Should have crv");
        assert!(found_x, "Should have x");
        assert!(found_y, "Should have y");
    }

    /// Diagnostic test using exact data from production failure logs (run 1).
    #[test]
    fn test_production_signature_verification_run1() {
        // Exact data from production logs (first run):
        let x_hex = "0482045c4bd8941821e8c7e18d36e9f803ceeb3193e0f8b931cac9bff63fd213";
        let y_hex = "7d544f9f06dc5e248563d76b0fbdb45f13cf0125bcd8b21db8056c7400b78962";

        let authenticator_data_hex =
            "32e5feaf4b667a32cc4dba9396c490e5fc13df5025ebac41a038f74c5b2ef1680500000004";
        let signature_hex = "304402205ef921b0eaa9b01d0d5c5459ceccf6e554daefe00dea2ae9b3c50706c6ab50fc022043db7eebd84bed56535dc45849d873da3fd3ef750e8000661d8422ca6b6b27cc";
        let client_data_hash_hex =
            "4d07963b810377553a6b035ac82d9aa5ab7652e59d8eae881eff9a3a238ec6e5";

        run_signature_verification_test(
            x_hex,
            y_hex,
            authenticator_data_hex,
            signature_hex,
            client_data_hash_hex,
            "run1",
        );
    }

    /// Diagnostic test using exact data from production failure logs (run 2 - fresh enrollment).
    #[test]
    fn test_production_signature_verification_run2() {
        // Exact data from production logs (second run with fresh enrollment):
        let x_hex = "cd6025d79845ccb0a2f125044461e6f3ad2ec01239c87ee5d96cc5fb0e3a916b";
        let y_hex = "e09f643a60fb9b9d3a93263a377333634efd89f8b12912063d616a9f3dcbc73b";

        let authenticator_data_hex =
            "32e5feaf4b667a32cc4dba9396c490e5fc13df5025ebac41a038f74c5b2ef1680500000002";
        let signature_hex = "3045022019410652447749152675b35fac57219211e57d139d145a1b6c1f1af222d9e44a022100bd7b489c2ab62dbd08470d55209b84d7c6df22702f95d45201cd4e54f1065563";
        let client_data_hash_hex =
            "82a7c974f92f99f9366cc336ae57f38a226c920d98bfa5f3d85236618be21662";

        run_signature_verification_test(
            x_hex,
            y_hex,
            authenticator_data_hex,
            signature_hex,
            client_data_hash_hex,
            "run2",
        );
    }

    fn run_signature_verification_test(
        x_hex: &str,
        y_hex: &str,
        authenticator_data_hex: &str,
        signature_hex: &str,
        client_data_hash_hex: &str,
        label: &str,
    ) {
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};

        let x = hex::decode(x_hex).expect("Failed to decode x");
        let y = hex::decode(y_hex).expect("Failed to decode y");
        let authenticator_data =
            hex::decode(authenticator_data_hex).expect("Failed to decode authenticator_data");
        let signature = hex::decode(signature_hex).expect("Failed to decode signature");
        let client_data_hash =
            hex::decode(client_data_hash_hex).expect("Failed to decode client_data_hash");

        println!("=== PRODUCTION DATA VERIFICATION ({}) ===", label);
        println!("x: {} ({} bytes)", x_hex, x.len());
        println!("y: {} ({} bytes)", y_hex, y.len());

        // Check if (x, y) is a valid point on the P-256 curve
        // P-256 curve equation: y^2 = x^3 - 3x + b (mod p)
        // where p = 2^256 - 2^224 + 2^192 + 2^96 - 1
        // and b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
        println!("\n=== CURVE POINT VALIDATION ===");
        // We can check this by trying to parse the point with aws-lc-rs
        // If it's not on the curve, parsing will fail

        // Build SEC1 uncompressed point
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        println!("point: {} ({} bytes)", hex::encode(&point), point.len());

        // Try to create an ECDSA public key - this validates the point is on the curve
        let _key_parse_result =
            aws_lc_rs::agreement::UnparsedPublicKey::new(&aws_lc_rs::agreement::ECDH_P256, &point);
        // We can't directly check if it's valid, but verification will fail if point is invalid
        println!("Point created (will validate during verify)");

        // Build message
        let mut message = Vec::with_capacity(
            authenticator_data
                .len()
                .saturating_add(client_data_hash.len()),
        );
        message.extend_from_slice(&authenticator_data);
        message.extend_from_slice(&client_data_hash);
        println!(
            "message: {} ({} bytes)",
            hex::encode(&message),
            message.len()
        );

        println!("signature: {} ({} bytes)", signature_hex, signature.len());

        // Try to verify directly with aws-lc-rs
        let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &point);
        let result = public_key.verify(&message, &signature);

        println!("\n=== DIRECT aws-lc-rs VERIFICATION ===");
        println!("Result: {:?}", result);

        // Also try with RealCoseVerifier for comparison
        let cose_key = build_cose_ec2_key(&x, &y);
        let verifier = RealCoseVerifier::new();
        let cose_result = verifier.verify(&cose_key, &message, &signature);
        println!("COSE verifier result: {:?}", cose_result);

        // Parse the DER signature to show r and s values
        println!("\n=== DER SIGNATURE STRUCTURE ===");
        if signature.len() > 2 && signature[0] == 0x30 {
            let seq_len = signature[1] as usize;
            println!("SEQUENCE length: {}", seq_len);
            if signature.len() > 4 && signature[2] == 0x02 {
                let r_len = signature[3] as usize;
                let r_start: usize = 4;
                let r_end = r_start.saturating_add(r_len);
                if signature.len() >= r_end {
                    let r = &signature[r_start..r_end];
                    println!("r ({} bytes): {}", r_len, hex::encode(r));

                    if signature.len() > r_end.saturating_add(1) && signature[r_end] == 0x02 {
                        let s_len = signature[r_end.saturating_add(1)] as usize;
                        let s_start = r_end.saturating_add(2);
                        let s_end = s_start.saturating_add(s_len);
                        if signature.len() >= s_end {
                            let s = &signature[s_start..s_end];
                            println!("s ({} bytes): {}", s_len, hex::encode(s));
                        }
                    }
                }
            }
        }
    }

    /// Old diagnostic test - keeping for reference.
    #[test]
    fn test_production_signature_verification_old() {
        // Exact data from production logs:
        // Enrollment logged these x/y coordinates from webauthn-rs:
        let x_hex = "0482045c4bd8941821e8c7e18d36e9f803ceeb3193e0f8b931cac9bff63fd213";
        let y_hex = "7d544f9f06dc5e248563d76b0fbdb45f13cf0125bcd8b21db8056c7400b78962";

        // Login logged these values:
        let authenticator_data_hex =
            "32e5feaf4b667a32cc4dba9396c490e5fc13df5025ebac41a038f74c5b2ef1680500000004";
        let signature_hex = "304402205ef921b0eaa9b01d0d5c5459ceccf6e554daefe00dea2ae9b3c50706c6ab50fc022043db7eebd84bed56535dc45849d873da3fd3ef750e8000661d8422ca6b6b27cc";
        let client_data_hash_hex =
            "4d07963b810377553a6b035ac82d9aa5ab7652e59d8eae881eff9a3a238ec6e5";

        // Decode all values
        let x = hex::decode(x_hex).expect("Failed to decode x");
        let y = hex::decode(y_hex).expect("Failed to decode y");
        let authenticator_data =
            hex::decode(authenticator_data_hex).expect("Failed to decode authenticator_data");
        let signature = hex::decode(signature_hex).expect("Failed to decode signature");
        let client_data_hash =
            hex::decode(client_data_hash_hex).expect("Failed to decode client_data_hash");

        println!("=== PRODUCTION DATA VERIFICATION ===");
        println!("x: {} ({} bytes)", x_hex, x.len());
        println!("y: {} ({} bytes)", y_hex, y.len());
        println!(
            "authenticator_data: {} ({} bytes)",
            authenticator_data_hex,
            authenticator_data.len()
        );
        println!("signature: {} ({} bytes)", signature_hex, signature.len());
        println!(
            "client_data_hash: {} ({} bytes)",
            client_data_hash_hex,
            client_data_hash.len()
        );

        // Verify sizes
        assert_eq!(x.len(), 32, "x should be 32 bytes");
        assert_eq!(y.len(), 32, "y should be 32 bytes");
        assert_eq!(
            authenticator_data.len(),
            37,
            "authenticator_data should be 37 bytes"
        );
        assert_eq!(
            client_data_hash.len(),
            32,
            "client_data_hash should be 32 bytes"
        );

        // Build COSE key (same as cose_key_to_cbor)
        let cose_key = build_cose_ec2_key(&x, &y);
        println!(
            "COSE key: {} ({} bytes)",
            hex::encode(&cose_key),
            cose_key.len()
        );

        // Build the message that should have been signed
        // WebAuthn assertion signature is over: authenticator_data || SHA256(client_data_json)
        // But we have the hash already, so: authenticator_data || client_data_hash
        let mut message = Vec::with_capacity(
            authenticator_data
                .len()
                .saturating_add(client_data_hash.len()),
        );
        message.extend_from_slice(&authenticator_data);
        message.extend_from_slice(&client_data_hash);
        println!(
            "message: {} ({} bytes)",
            hex::encode(&message),
            message.len()
        );

        // Parse the DER signature to understand its structure
        println!("\n=== DER SIGNATURE ANALYSIS ===");
        if signature.len() >= 2 && signature[0] == 0x30 {
            let total_len = signature[1] as usize;
            println!("SEQUENCE length: {}", total_len);

            if signature.len() >= 4 && signature[2] == 0x02 {
                let r_len = signature[3] as usize;
                println!("R INTEGER length: {}", r_len);
                if signature.len() >= 4 + r_len {
                    let r = &signature[4..4 + r_len];
                    println!("R value ({} bytes): {}", r.len(), hex::encode(r));

                    let s_offset = 4 + r_len;
                    if signature.len() > s_offset + 1 && signature[s_offset] == 0x02 {
                        let s_len = signature[s_offset + 1] as usize;
                        println!("S INTEGER length: {}", s_len);
                        if signature.len() >= s_offset + 2 + s_len {
                            let s = &signature[s_offset + 2..s_offset + 2 + s_len];
                            println!("S value ({} bytes): {}", s.len(), hex::encode(s));
                        }
                    }
                }
            }
        }

        // Try verification with RealCoseVerifier
        let verifier = RealCoseVerifier::new();
        let result = verifier.verify(&cose_key, &message, &signature);

        println!("\n=== VERIFICATION RESULT ===");
        println!("Result: {:?}", result);

        // Even if this fails, we want to understand why
        // This test documents the actual failure behavior
        if result.is_err() {
            println!("\nSignature verification FAILED (as expected from production).");
            println!("This indicates either:");
            println!("  1. The YubiKey used a different credential than what was enrolled");
            println!(
                "  2. The public key stored during enrollment doesn't match the YubiKey's key"
            );
            println!("  3. The message being verified differs from what the YubiKey signed");
        }

        // For now, let's NOT assert success - this test documents the failure
        // We expect this to fail based on production behavior
        // assert!(result.is_ok(), "Signature should verify: {:?}", result);
    }
}

mod encoding_verification {
    use super::*;
    /// Verify MockFidoDevice data survives JSON round-trip
    #[tokio::test]
    async fn test_mock_device_data_survives_serialization() {
        use vouch_common::encoding::Raw;
        use vouch_common::fido2_types::{
            AuthData, ClientDataJson, CredentialId, Signature, UserHandle,
        };

        #[derive(serde::Serialize, serde::Deserialize)]
        struct AssertionPayload {
            credential_id: CredentialId<Raw>,
            authenticator_data: AuthData<Raw>,
            signature: Signature<Raw>,
            client_data_json: ClientDataJson<Raw>,
            user_handle: UserHandle<Raw>,
        }

        let device = IntegrationMockDevice::new();
        let challenge = [1u8; 32];

        // Use a proper user_id for registration
        let user_id = [42u8; 16];
        let _reg = device
            .register("test.local", &challenge, &user_id, "test@example.com")
            .unwrap();
        let auth = device.authenticate("test.local", &challenge).unwrap();

        // Simulate CLI→Server serialization using typed fields
        let req = AssertionPayload {
            credential_id: auth.credential_id.clone(),
            authenticator_data: auth.authenticator_data.clone(),
            signature: auth.signature.clone(),
            client_data_json: auth.client_data_json.clone(),
            user_handle: auth.user_handle.clone(),
        };

        let json = serde_json::to_string(&req).unwrap();
        let decoded: AssertionPayload = serde_json::from_str(&json).unwrap();

        // Verify exact byte match
        assert_eq!(
            auth.credential_id.as_bytes(),
            decoded.credential_id.as_bytes()
        );
        assert_eq!(
            auth.authenticator_data.as_bytes(),
            decoded.authenticator_data.as_bytes()
        );
        assert_eq!(auth.signature.as_bytes(), decoded.signature.as_bytes());
        assert_eq!(
            auth.client_data_json.as_bytes(),
            decoded.client_data_json.as_bytes()
        );
    }

    /// Verify COSE key survives round-trip
    #[tokio::test]
    async fn test_cose_key_round_trip() {
        let device = IntegrationMockDevice::new();
        let user_id = [1u8; 16];
        let reg = device
            .register("test.local", &[0u8; 32], &user_id, "user@example.com")
            .unwrap();

        // Round-trip through JSON
        let json = serde_json::to_string(&reg.public_key).unwrap();
        let decoded: Vec<u8> = serde_json::from_str(&json).unwrap();

        // Parse as COSE to verify structure preserved
        let original_cose: ciborium::Value = ciborium::from_reader(&reg.public_key[..]).unwrap();
        let decoded_cose: ciborium::Value = ciborium::from_reader(&decoded[..]).unwrap();
        assert_eq!(original_cose, decoded_cose);
    }

    /// Verify credential_id serialization format
    #[tokio::test]
    async fn test_credential_id_serialization_format() {
        let device = IntegrationMockDevice::new();
        let cred_id = device.credential_id();

        // Verify JSON encoding produces array format [1,2,3,...]
        let json = serde_json::to_string(&cred_id).unwrap();
        assert!(json.starts_with('['), "Should be JSON array, got: {}", json);
        assert!(json.ends_with(']'), "Should be JSON array, got: {}", json);
    }

    /// Verify all special byte values survive round-trip through typed fido2 fields.
    #[tokio::test]
    async fn test_special_bytes_in_request() {
        use vouch_common::encoding::Raw;
        use vouch_common::fido2_types::{
            AuthData, ClientDataJson, CredentialId, Signature, UserHandle,
        };

        // Test with bytes that could cause issues. Sixteen of them, so the
        // value clears `CredentialIdData`'s floor and the test exercises byte
        // fidelity rather than the length bound.
        let problematic_bytes: Vec<u8> = vec![
            0x00, 0xFF, 0x7F, 0x80, 0xC0, 0xE0, 0xF0, 0xFE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08,
        ];

        // Use typed FIDO2 encoded fields to verify special bytes survive serialization
        let cred_id: CredentialId<Raw> = problematic_bytes.clone().into();
        let auth_data: AuthData<Raw> = problematic_bytes.clone().into();
        let signature: Signature<Raw> = problematic_bytes.clone().into();
        let client_data: ClientDataJson<Raw> = problematic_bytes.clone().into();
        let user_handle: UserHandle<Raw> = problematic_bytes.clone().into();

        let json_cred = serde_json::to_string(&cred_id).unwrap();
        let json_auth = serde_json::to_string(&auth_data).unwrap();
        let json_sig = serde_json::to_string(&signature).unwrap();
        let json_client = serde_json::to_string(&client_data).unwrap();
        let json_user = serde_json::to_string(&user_handle).unwrap();

        let decoded_cred: CredentialId<Raw> = serde_json::from_str(&json_cred).unwrap();
        let decoded_auth: AuthData<Raw> = serde_json::from_str(&json_auth).unwrap();
        let decoded_sig: Signature<Raw> = serde_json::from_str(&json_sig).unwrap();
        let decoded_client: ClientDataJson<Raw> = serde_json::from_str(&json_client).unwrap();
        let decoded_user: UserHandle<Raw> = serde_json::from_str(&json_user).unwrap();

        assert_eq!(problematic_bytes.as_slice(), decoded_cred.as_bytes());
        assert_eq!(problematic_bytes.as_slice(), decoded_auth.as_bytes());
        assert_eq!(problematic_bytes.as_slice(), decoded_sig.as_bytes());
        assert_eq!(problematic_bytes.as_slice(), decoded_client.as_bytes());
        assert_eq!(problematic_bytes.as_slice(), decoded_user.as_bytes());
    }

    /// Test typed API with MockFidoDevice
    #[tokio::test]
    async fn test_typed_mock_device_api() {
        use vouch_cli::{FidoDevice, MockFidoDevice};

        let device = MockFidoDevice::new();
        let challenge = [42u8; 32];
        let user_id = [1u8; 16];

        // Verify credential_id() and public_key_cose() work correctly
        assert!(!device.credential_id().is_empty());
        assert!(!device.public_key_cose().is_empty());

        // Registration now returns typed result directly
        let reg_result = device
            .register(
                "test.local",
                "Test",
                &challenge,
                &user_id,
                "user@test.com",
                &[],
            )
            .unwrap();

        // Verify typed result fields
        assert!(!reg_result.credential_id.is_empty());
        assert!(!reg_result.public_key.is_empty());
        assert!(!reg_result.attestation_object.is_empty());
        assert!(!reg_result.client_data_json.is_empty());

        // Authentication now returns typed result directly
        let auth_result = device.authenticate("test.local", &challenge).unwrap();

        // Verify typed result fields
        assert!(!auth_result.credential_id.is_empty());
        assert_eq!(auth_result.authenticator_data.len(), 37);
        assert_eq!(auth_result.signature.len(), 64);
        assert!(!auth_result.client_data_json.is_empty());
    }

    /// Test verification through the AssertionParams API
    #[tokio::test]
    async fn test_typed_verification_functions() {
        use vouch_cli::{FidoDevice, MockFidoDevice};
        use vouch_server::crypto::webauthn_verify::{
            AssertionParams, TestCoseVerifier, verify_assertion_with_verifier,
        };

        let device = MockFidoDevice::new();
        let challenge = [99u8; 32];
        let user_id = [2u8; 16];

        // Register first to get the public key
        let reg = device
            .register(
                "test.local",
                "Test",
                &challenge,
                &user_id,
                "user@test.com",
                &[],
            )
            .unwrap();

        // Authenticate
        let auth = device.authenticate("test.local", &challenge).unwrap();

        // Verify using typed API
        let verifier = TestCoseVerifier::always_succeed();

        // Results are now typed directly
        let auth_data = &auth.authenticator_data;
        let client_data = &auth.client_data_json;
        let signature = &auth.signature;
        let public_key = &reg.public_key;

        // Extract challenge from client data for verification
        let client_data_str = std::str::from_utf8(client_data.as_bytes()).unwrap();
        let client_data_json: serde_json::Value = serde_json::from_str(client_data_str).unwrap();
        let expected_challenge = client_data_json["challenge"].as_str().unwrap();

        let result = verify_assertion_with_verifier(
            &AssertionParams {
                authenticator_data: auth_data.as_bytes(),
                client_data_json: client_data.as_bytes(),
                signature: signature.as_bytes(),
                public_key_cose: public_key.as_bytes(),
                expected_rp_id: "test.local",
                expected_challenge,
                expected_origin: "https://test.local",
                stored_counter: 0,
                require_user_verification: true,
                origin_policy:
                    vouch_server::crypto::webauthn_verify::OriginPolicy::AllowLoopbackVariations,
            },
            &verifier,
        );

        assert!(
            result.is_ok(),
            "Typed verification should succeed: {:?}",
            result.err()
        );
    }
}

mod httpsig {
    use super::*;
    use vouch_cli::fapi::ClientKey;
    use vouch_cli::fapi::httpsig::ClientKeySigner;
    use vouch_httpsig::SignatureBuilder;

    /// Helper: create a user with an OAuth client that has JWKS containing
    /// the given ClientKey's public key, and a session bound to that client.
    async fn setup_user_with_httpsig_key(harness: &TestHarness, key: &ClientKey) -> String {
        use vouch_server::test_utils::{TestClientSpec, TestJwks, create_test_client};

        let user = harness.create_user("httpsig@example.com").await.unwrap();
        let auth_id = harness.create_authenticator(&user.id).await.unwrap();

        // Create OAuth client with the key's public JWK in JWKS (per-user key so
        // the wrong-key test can register one key and sign with another).
        let public_jwk = key.public_jwk().unwrap();
        let jwks = serde_json::json!({ "keys": [public_jwk] });

        let client = create_test_client(
            &harness.state.store,
            &user.id,
            TestClientSpec {
                name: "Test FAPI Client".to_string(),
                application_type: vouch_server::db::OAuthClientType::Native,
                redirect_uris: vec![],
                token_endpoint_auth_method: Some(
                    vouch_server::db::TokenEndpointAuthMethod::PrivateKeyJwt,
                ),
                jwks: TestJwks::Custom(jwks),
                dpop_bound_access_tokens: true,
                id_token_signed_response_alg: vouch_server::db::JwsAlgorithm::Es256,
                with_secret: false,
                ..Default::default()
            },
        )
        .await;

        harness
            .create_session_for_client(&user.id, "httpsig@example.com", &auth_id, &client.client_id)
            .await
            .unwrap()
    }

    /// Build RFC 9421 signature headers for a GET request.
    fn sign_get_request(url: &str, auth_header: &str, key: &ClientKey) -> Vec<(String, String)> {
        let signer = ClientKeySigner::from_client_key(key).unwrap();

        let mut req: http::Request<Vec<u8>> = http::Request::builder()
            .method("GET")
            .uri(url)
            .header("authorization", auth_header)
            .body(Vec::new())
            .unwrap();

        SignatureBuilder::new("sig1")
            .method()
            .authority()
            .path()
            .field("authorization")
            .created_now()
            .sign_request(&mut req, &signer)
            .unwrap();

        let mut headers: Vec<(String, String)> = Vec::new();
        if let Some(v) = req.headers().get("signature-input") {
            let val: &str = v.to_str().unwrap();
            headers.push(("Signature-Input".to_string(), val.to_string()));
        }
        if let Some(v) = req.headers().get("signature") {
            let val: &str = v.to_str().unwrap();
            headers.push(("Signature".to_string(), val.to_string()));
        }
        headers
    }

    #[tokio::test]
    async fn test_httpsig_verified_request_succeeds() {
        let harness = TestHarness::new().await;
        let key = ClientKey::generate().unwrap();
        let token = setup_user_with_httpsig_key(&harness, &key).await;

        let url = harness.url("/v1/auth/status");
        let auth_header = format!("Bearer {token}");
        let sig_headers = sign_get_request(&url, &auth_header, &key);

        let extra_refs: Vec<(&str, &str)> = sig_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let response = harness
            .http_client
            .request(
                "GET",
                &url,
                None,
                None,
                Some(&auth_header),
                Some(&extra_refs),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status,
            200,
            "signed request should succeed: {}",
            response.text().unwrap_or_default()
        );
    }

    #[tokio::test]
    async fn test_httpsig_jwks_cache_fallback_verifies() {
        // A client registered without inline JWKS (the jwks_uri flow) resolves
        // its signing key from the JWKS cache row instead. The cache row is only
        // ever populated by fetching jwks_uri, so the client must carry one —
        // a cache row with no URI behind it can never be revalidated.
        use vouch_server::test_utils::{TestClientSpec, TestJwks, create_test_client};

        let harness = TestHarness::new().await;
        let key = ClientKey::generate().unwrap();

        let user = harness
            .create_user("httpsig-cache@example.com")
            .await
            .unwrap();
        let auth_id = harness.create_authenticator(&user.id).await.unwrap();

        let public_jwk = key.public_jwk().unwrap();
        let jwks = serde_json::json!({ "keys": [public_jwk] });

        let client = create_test_client(
            &harness.state.store,
            &user.id,
            TestClientSpec {
                name: "Test FAPI Client".to_string(),
                application_type: vouch_server::db::OAuthClientType::Native,
                redirect_uris: vec![],
                token_endpoint_auth_method: Some(
                    vouch_server::db::TokenEndpointAuthMethod::PrivateKeyJwt,
                ),
                jwks: TestJwks::None,
                jwks_uri: Some("https://client.example/jwks.json".to_string()),
                dpop_bound_access_tokens: true,
                id_token_signed_response_alg: vouch_server::db::JwsAlgorithm::Es256,
                with_secret: false,
                ..Default::default()
            },
        )
        .await;

        vouch_server::db::upsert_jwks_cache(&harness.state.store, &client.app_id, &jwks)
            .await
            .unwrap();

        let token = harness
            .create_session_for_client(
                &user.id,
                "httpsig-cache@example.com",
                &auth_id,
                &client.client_id,
            )
            .await
            .unwrap();

        let url = harness.url("/v1/keys");
        let auth_header = format!("Bearer {token}");
        let sig_headers = sign_get_request(&url, &auth_header, &key);

        let extra_refs: Vec<(&str, &str)> = sig_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let response = harness
            .http_client
            .request(
                "GET",
                &url,
                None,
                None,
                Some(&auth_header),
                Some(&extra_refs),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status,
            200,
            "signature resolved via JWKS cache should verify: {}",
            response.text().unwrap_or_default()
        );
    }

    #[tokio::test]
    async fn test_httpsig_unsigned_request_rejected_on_v1_keys() {
        // A signature-required /v1/* endpoint rejects an unsigned request.
        let harness = TestHarness::new().await;
        let (_user, _auth_id, token) = harness
            .create_authenticated_user("unsigned-v1@example.com")
            .await
            .unwrap();

        // Send an unsigned request by hitting the low-level client directly
        // (the harness's authenticated helpers sign /v1/* requests).
        let url = harness.url("/v1/keys");
        let auth_header = format!("Bearer {token}");
        let response = harness
            .http_client
            .request("GET", &url, None, None, Some(&auth_header), None)
            .await
            .unwrap();

        assert_eq!(
            response.status, 401,
            "unsigned /v1/keys request must be rejected"
        );
    }

    #[tokio::test]
    async fn test_httpsig_unsigned_auth_status_still_succeeds() {
        // The soft /v1/auth/status probe is intentionally exempt and still
        // answers unsigned requests.
        let harness = TestHarness::new().await;
        let key = ClientKey::generate().unwrap();
        let token = setup_user_with_httpsig_key(&harness, &key).await;

        let url = harness.url("/v1/auth/status");
        let auth_header = format!("Bearer {token}");
        let response = harness
            .http_client
            .request("GET", &url, None, None, Some(&auth_header), None)
            .await
            .unwrap();

        assert_eq!(
            response.status, 200,
            "unsigned /v1/auth/status should still succeed"
        );
    }

    #[tokio::test]
    async fn test_httpsig_tampered_signature_rejected_on_v1_keys() {
        let harness = TestHarness::new().await;
        let key = ClientKey::generate().unwrap();
        let token = setup_user_with_httpsig_key(&harness, &key).await;

        let url = harness.url("/v1/keys");
        let auth_header = format!("Bearer {token}");

        // Sign with the correct key
        let mut sig_headers = sign_get_request(&url, &auth_header, &key);

        // Tamper with the signature value
        for (name, value) in &mut sig_headers {
            if name == "Signature" {
                *value = "sig1=:dGFtcGVyZWQ=:".to_string();
            }
        }

        let extra_refs: Vec<(&str, &str)> = sig_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let response = harness
            .http_client
            .request(
                "GET",
                &url,
                None,
                None,
                Some(&auth_header),
                Some(&extra_refs),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status, 401,
            "tampered signature should be rejected"
        );
    }

    #[tokio::test]
    async fn test_httpsig_wrong_key_rejected() {
        let harness = TestHarness::new().await;
        let registered_key = ClientKey::generate().unwrap();
        let wrong_key = ClientKey::generate().unwrap();
        let token = setup_user_with_httpsig_key(&harness, &registered_key).await;

        let url = harness.url("/v1/keys");
        let auth_header = format!("Bearer {token}");

        // Sign with a different key than what's registered
        let sig_headers = sign_get_request(&url, &auth_header, &wrong_key);

        let extra_refs: Vec<(&str, &str)> = sig_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let response = harness
            .http_client
            .request(
                "GET",
                &url,
                None,
                None,
                Some(&auth_header),
                Some(&extra_refs),
            )
            .await
            .unwrap();

        assert_eq!(response.status, 401, "wrong key should be rejected");
    }
}
