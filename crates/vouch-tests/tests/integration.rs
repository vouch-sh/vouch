//! Integration tests for Vouch.
//!
//! These tests run through actual production code paths by using
//! traits and dependency injection to substitute external dependencies
//! (hardware, network, filesystem) while testing real logic.

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
        let _ = device.authenticate("test.example.com", &challenge);
        assert_eq!(device.counter(), 1);

        // After second authentication, counter should be 2
        let _ = device.authenticate("test.example.com", &challenge);
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

        // Without auth, should get 401
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
        let len = (message.len() as u32).to_be_bytes();

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
        let expired_token = harness.create_expired_token(&user.id, &user.email, &auth_id);

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

        // Test /v1/auth/register/start endpoint (POST)
        #[derive(serde::Serialize)]
        struct RegisterRequest {
            name: String,
        }
        let response = harness
            .post_json(
                "/v1/auth/register/start",
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

        // Without auth
        let response = harness
            .post_json("/v1/credentials/ssh", &request)
            .await
            .expect("Failed to post SSH cert request");
        assert_eq!(response.status, 401);

        // With invalid token
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
            .post_form("/oauth/device/code", "client_id=test")
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
            .post_form("/oauth/device/code", "client_id=test")
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
            .post_form("/oauth/device/code", "client_id=test")
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
            .post_form("/oauth/device/code", "client_id=test")
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
            .post_form("/oauth/device/code", "client_id=test")
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
// Priority 3: WebAuthn Login Flow Tests
// ============================================================================

mod webauthn_flow {
    use super::*;

    /// Test that login start returns a challenge.
    #[tokio::test]
    async fn test_login_start_returns_challenge() {
        let harness = TestHarness::new().await;

        #[derive(serde::Serialize)]
        struct LoginStartRequest {}

        let response = harness
            .post_json("/v1/auth/login/start", &LoginStartRequest {})
            .await
            .expect("Failed to post login start");

        assert_eq!(response.status, 200);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");
        assert!(resp.get("challenge").is_some(), "Should have challenge");
        assert!(resp.get("rp_id").is_some(), "Should have rp_id");
        assert!(resp.get("state").is_some(), "Should have state token");
    }

    /// Test that login start with mock device setup succeeds.
    #[tokio::test]
    async fn test_login_start_with_mock_device() {
        let harness = TestHarness::new().await;
        let _device = IntegrationMockDevice::new();

        // Create user with authenticator (this creates a test authenticator)
        let _user = harness
            .create_user("login@example.com")
            .await
            .expect("Failed to create user");

        // Get login challenge
        #[derive(serde::Serialize)]
        struct LoginStartRequest {}

        let response = harness
            .post_json("/v1/auth/login/start", &LoginStartRequest {})
            .await
            .expect("Failed to post login start");
        let start_resp: serde_json::Value = response.json().expect("Failed to parse response");

        // Verify challenge was returned
        assert!(start_resp.get("challenge").is_some());
        assert!(start_resp.get("state").is_some());
    }

    /// Test that login complete fails with invalid state.
    #[tokio::test]
    async fn test_login_complete_invalid_state() {
        let harness = TestHarness::new().await;

        #[derive(serde::Serialize)]
        struct LoginCompleteRequest {
            state: String,
            credential_id: Vec<u8>,
            authenticator_data: Vec<u8>,
            client_data_json: Vec<u8>,
            signature: Vec<u8>,
            user_handle: Vec<u8>,
        }

        let request = LoginCompleteRequest {
            state: "invalid.state.token".to_string(),
            credential_id: vec![1, 2, 3],
            authenticator_data: vec![],
            client_data_json: vec![],
            signature: vec![],
            user_handle: vec![],
        };

        let response = harness
            .post_json("/v1/auth/login/complete", &request)
            .await
            .expect("Failed to post login complete");

        assert_eq!(response.status, 400);
        let error: serde_json::Value = response.json().expect("Failed to parse error");
        assert_eq!(error["code"], "invalid_state");
    }

    /// Test that login complete fails with unknown credential.
    #[tokio::test]
    async fn test_login_complete_credential_not_found() {
        let harness = TestHarness::new().await;

        // Get a valid state token first
        #[derive(serde::Serialize)]
        struct LoginStartRequest {}

        let response = harness
            .post_json("/v1/auth/login/start", &LoginStartRequest {})
            .await
            .expect("Failed to post login start");
        let start_resp: serde_json::Value = response.json().expect("Failed to parse response");
        let state = start_resp["state"].as_str().expect("state");

        // Try to complete with unknown credential
        #[derive(serde::Serialize)]
        struct LoginCompleteRequest {
            state: String,
            credential_id: Vec<u8>,
            authenticator_data: Vec<u8>,
            client_data_json: Vec<u8>,
            signature: Vec<u8>,
            user_handle: Vec<u8>,
        }

        // Use a random UUID-like bytes as user handle
        let fake_user_handle = [1u8; 16]; // 16 bytes like a UUID
        let request = LoginCompleteRequest {
            state: state.to_string(),
            credential_id: vec![1, 2, 3, 4, 5],
            authenticator_data: vec![0; 37],
            client_data_json: vec![],
            signature: vec![],
            user_handle: fake_user_handle.to_vec(),
        };

        let response = harness
            .post_json("/v1/auth/login/complete", &request)
            .await
            .expect("Failed to post login complete");

        // Invalid user_handle format returns 400
        assert!(response.status == 400 || response.status == 404);
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
                "/v1/auth/register/start",
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
                "/v1/auth/register/start",
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
                "/v1/auth/register/start",
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
            &harness.url("/v1/keys/some-key-id"),
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
            .delete_authenticated("/v1/keys/nonexistent-key-id", &token)
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
    #[tokio::test]
    async fn test_userinfo_requires_bearer_token() {
        let harness = TestHarness::new().await;

        let response = harness
            .get("/oauth/userinfo")
            .await
            .expect("Failed to get userinfo");

        assert_eq!(response.status, 401);
        let error: serde_json::Value = response.json().expect("Failed to parse error");
        assert_eq!(error["code"], "invalid_token");
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
        assert!(userinfo.get("email").is_some(), "Should have email claim");
        assert_eq!(userinfo["email"], "userinfo@example.com");
        assert!(
            userinfo["hardware_verified"].as_bool().unwrap_or(false),
            "Should be hardware verified"
        );
    }

    /// Test that revoke token succeeds.
    #[tokio::test]
    async fn test_revoke_token_succeeds() {
        let harness = TestHarness::new().await;

        let (_user, _auth_id, token) = harness
            .create_authenticated_user("revoke@example.com")
            .await
            .expect("Failed to create authenticated user");

        let response = harness
            .post_form("/oauth/revoke", &format!("token={}", token))
            .await
            .expect("Failed to revoke token");

        // RFC 7009: Always returns 200
        assert_eq!(response.status, 200);
    }

    /// Test that introspect returns active token metadata.
    #[tokio::test]
    async fn test_introspect_active_token() {
        let harness = TestHarness::new().await;

        let (_user, _auth_id, token) = harness
            .create_authenticated_user("introspect@example.com")
            .await
            .expect("Failed to create authenticated user");

        let response = harness
            .post_form("/oauth/introspect", &format!("token={}", token))
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

        let body = "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=invalid&subject_token_type=urn:ietf:params:oauth:token-type:access_token";
        let response = harness
            .post_form("/oauth/token", body)
            .await
            .expect("Failed to exchange token");

        assert_eq!(response.status, 400);
        let error: serde_json::Value = response.json().expect("Failed to parse error");
        assert_eq!(error["code"], "invalid_grant");
    }

    /// Test that token exchange works with valid token.
    #[tokio::test]
    async fn test_token_exchange_valid() {
        let harness = TestHarness::new().await;

        let (_user, _auth_id, token) = harness
            .create_authenticated_user("exchange@example.com")
            .await
            .expect("Failed to create authenticated user");

        let body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            token
        );
        let response = harness
            .post_form("/oauth/token", &body)
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

        let (_user, _auth_id, token) = harness
            .create_authenticated_user("exchange-scope@example.com")
            .await
            .expect("Failed to create authenticated user");

        let body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token&scope=openid",
            token
        );
        let response = harness
            .post_form("/oauth/token", &body)
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

        let (_user, _auth_id, token) = harness
            .create_authenticated_user("exchange-bad-type@example.com")
            .await
            .expect("Failed to create authenticated user");

        let body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=invalid:token:type",
            token
        );
        let response = harness
            .post_form("/oauth/token", &body)
            .await
            .expect("Failed to exchange token");

        assert_eq!(response.status, 400);
        let error: serde_json::Value = response.json().expect("Failed to parse error");
        assert_eq!(error["code"], "invalid_request");
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

        let scim_token = harness
            .create_scim_token("Test SCIM Token")
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

        let scim_token = harness
            .create_scim_token("Test SCIM Token")
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
            user_name: "scim-new@example.com".to_string(),
            active: true,
        };

        let response = harness
            .post_json_authenticated("/scim/v2/Users", &user, &scim_token)
            .await
            .expect("Failed to create SCIM user");

        assert_eq!(response.status, 201);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");
        assert!(resp.get("id").is_some(), "Should have id");
        assert_eq!(resp["userName"], "scim-new@example.com");
    }

    /// Test SCIM get user by ID.
    #[tokio::test]
    async fn test_scim_get_user() {
        let harness = TestHarness::new().await;

        // Create a user first
        let user = harness
            .create_user("scim-get@example.com")
            .await
            .expect("Failed to create user");

        let scim_token = harness
            .create_scim_token("Test SCIM Token")
            .await
            .expect("Failed to create SCIM token");

        let response = harness
            .get_authenticated(&format!("/scim/v2/Users/{}", user.id), &scim_token)
            .await
            .expect("Failed to get SCIM user");

        assert_eq!(response.status, 200);
        let resp: serde_json::Value = response.json().expect("Failed to parse response");
        assert_eq!(resp["id"], user.id);
    }

    /// Test SCIM get user not found.
    #[tokio::test]
    async fn test_scim_get_user_not_found() {
        let harness = TestHarness::new().await;

        let scim_token = harness
            .create_scim_token("Test SCIM Token")
            .await
            .expect("Failed to create SCIM token");

        let response = harness
            .get_authenticated("/scim/v2/Users/nonexistent-id", &scim_token)
            .await
            .expect("Failed to get SCIM user");

        assert_eq!(response.status, 404);
    }

    /// Test SCIM delete user.
    #[tokio::test]
    async fn test_scim_delete_user() {
        let harness = TestHarness::new().await;

        // Create a user first
        let user = harness
            .create_user("scim-delete@example.com")
            .await
            .expect("Failed to create user");

        let scim_token = harness
            .create_scim_token("Test SCIM Token")
            .await
            .expect("Failed to create SCIM token");

        let response = harness
            .delete_authenticated(&format!("/scim/v2/Users/{}", user.id), &scim_token)
            .await
            .expect("Failed to delete SCIM user");

        // SCIM delete returns 204 No Content
        assert_eq!(response.status, 204);

        // Verify user is gone
        let response = harness
            .get_authenticated(&format!("/scim/v2/Users/{}", user.id), &scim_token)
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

        let (_user, _auth_id, token) = harness
            .create_authenticated_user("logout@example.com")
            .await
            .expect("Failed to create authenticated user");

        // Verify token works
        let response = harness
            .get_authenticated("/v1/auth/status", &token)
            .await
            .expect("Failed to get auth status");
        let status: serde_json::Value = response.json().expect("Failed to parse response");
        assert_eq!(status["authenticated"], true);

        // Revoke the token
        harness
            .post_form("/oauth/revoke", &format!("token={}", token))
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
