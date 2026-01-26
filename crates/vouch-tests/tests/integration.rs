//! Integration tests for Vouch.
//!
//! These tests run through actual production code paths by using
//! traits and dependency injection to substitute external dependencies
//! (hardware, network, filesystem) while testing real logic.

use vouch_tests::{IntegrationMockDevice, TestHarness, TestTransportPair};

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
