// SPDX-License-Identifier: Apache-2.0 OR MIT
//! End-to-end IPC integration tests for the agent.
//!
//! These tests exercise the agent state, protocol types, and IPC message
//! serialization without requiring a running agent or Unix sockets.

use vouch_agent::protocol::{
    NOT_AUTHENTICATED, Response, SESSION_EXPIRED, StoreSessionParams, StoreSshCredentialsParams,
};
use vouch_agent::state::{AgentState, Session, SessionInfo};

use jiff::Timestamp;
use secrecy::{ExposeSecret, SecretString};

/// Helper: create a timestamp N seconds from now.
fn future_timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_second(Timestamp::now().as_second() + seconds).unwrap()
}

/// Helper: create a timestamp N seconds in the past.
fn past_timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_second(Timestamp::now().as_second() - seconds).unwrap()
}

/// Helper: create a valid session.
fn make_session(email: &str, expires_in_secs: i64) -> Session {
    Session::new(
        SecretString::from("test_jwt_token"),
        email.to_string(),
        future_timestamp(expires_in_secs),
    )
}

mod session_lifecycle {
    use super::*;

    /// Store a session and retrieve it.
    #[tokio::test]
    async fn test_store_and_get_session() {
        let state = AgentState::new();
        let session = make_session("alice@example.com", 3600);

        state.store_session(session).await;

        let retrieved = state.get_session().await;
        assert!(retrieved.is_some());
        let s = retrieved.unwrap();
        assert_eq!(s.user_email(), "alice@example.com");
        assert!(!s.is_expired());
    }

    /// Session info conversion preserves fields.
    #[tokio::test]
    async fn test_session_info_conversion() {
        let state = AgentState::new();
        let session = make_session("bob@example.com", 7200);

        state.store_session(session).await;

        let retrieved = state.get_session().await.unwrap();
        let info = SessionInfo::from(&retrieved);

        assert_eq!(info.user_email, "bob@example.com");
        assert!(info.expires_in_seconds > 0);
        assert!(info.expires_in_seconds <= 7200);
        assert!(!info.expires_at.is_empty());
        assert!(!info.authenticated_at.is_empty());
    }

    /// Clear session removes it.
    #[tokio::test]
    async fn test_clear_session() {
        let state = AgentState::new();
        let session = make_session("alice@example.com", 3600);

        state.store_session(session).await;
        assert!(state.get_session().await.is_some());

        state.clear_session().await;
        assert!(state.get_session().await.is_none());
    }

    /// Expired session not returned by get_session.
    #[tokio::test]
    async fn test_expired_session_not_returned() {
        let state = AgentState::new();
        let expired_session = Session::new(
            SecretString::from("expired_token"),
            "expired@example.com".to_string(),
            past_timestamp(100),
        );

        state.store_session(expired_session).await;

        // get_session filters expired sessions
        assert!(state.get_session().await.is_none());
    }

    /// Token is accessible when session is valid.
    #[tokio::test]
    async fn test_get_token() {
        let state = AgentState::new();
        let session = Session::new(
            SecretString::from("my_secret_jwt"),
            "user@example.com".to_string(),
            future_timestamp(3600),
        );

        state.store_session(session).await;

        let token = state.get_token().await;
        assert!(token.is_some());
        assert_eq!(token.unwrap().expose_secret(), "my_secret_jwt");
    }

    /// Token not accessible when no session.
    #[tokio::test]
    async fn test_get_token_no_session() {
        let state = AgentState::new();
        assert!(state.get_token().await.is_none());
    }

    /// Token not accessible when session is expired.
    #[tokio::test]
    async fn test_get_token_expired_session() {
        let state = AgentState::new();
        let session = Session::new(
            SecretString::from("expired_jwt"),
            "user@example.com".to_string(),
            past_timestamp(100),
        );

        state.store_session(session).await;
        assert!(state.get_token().await.is_none());
    }

    /// Expiry tracking returns correct seconds.
    #[tokio::test]
    async fn test_expires_in_seconds() {
        let state = AgentState::new();
        let session = make_session("user@example.com", 1800);

        state.store_session(session).await;

        let retrieved = state.get_session().await.unwrap();
        let secs = retrieved.expires_in_seconds();
        // Allow some tolerance for test execution time
        assert!(secs > 1700 && secs <= 1800);
    }

    /// No session means no expiry info.
    #[tokio::test]
    async fn test_expires_in_seconds_no_session() {
        let state = AgentState::new();
        assert!(state.get_session().await.is_none());
    }

    /// Replacing a session overwrites the old one.
    #[tokio::test]
    async fn test_replace_session() {
        let state = AgentState::new();

        let session1 = make_session("first@example.com", 3600);
        state.store_session(session1).await;

        let session2 = make_session("second@example.com", 7200);
        state.store_session(session2).await;

        let retrieved = state.get_session().await.unwrap();
        assert_eq!(retrieved.user_email(), "second@example.com");
    }
}

mod protocol_types {
    use super::*;

    /// StoreSessionParams serialization round-trip.
    #[test]
    fn test_store_session_params_roundtrip() {
        use secrecy::ExposeSecret;

        let params = StoreSessionParams {
            token: secrecy::SecretString::from("jwt_token"),
            user_email: "user@example.com".to_string(),
            expires_at: "2099-12-31T23:59:59Z".to_string(),
            server_url: Some("https://vouch.example.com".to_string()),
        };

        let json = serde_json::to_string(&params).unwrap();
        let deserialized: StoreSessionParams = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.token.expose_secret(), "jwt_token");
        assert_eq!(deserialized.user_email, "user@example.com");
        assert_eq!(deserialized.expires_at, "2099-12-31T23:59:59Z");
        assert_eq!(
            deserialized.server_url.as_deref(),
            Some("https://vouch.example.com")
        );
    }

    /// StoreSessionParams without server_url.
    #[test]
    fn test_store_session_params_no_server_url() {
        let params = StoreSessionParams {
            token: secrecy::SecretString::from("jwt_token"),
            user_email: "user@example.com".to_string(),
            expires_at: "2099-12-31T23:59:59Z".to_string(),
            server_url: None,
        };

        let json = serde_json::to_string(&params).unwrap();
        // server_url should be omitted when None (skip_serializing_if)
        assert!(!json.contains("server_url"));

        let deserialized: StoreSessionParams = serde_json::from_str(&json).unwrap();
        assert!(deserialized.server_url.is_none());
    }

    /// StoreSshCredentialsParams serialization.
    #[test]
    fn test_store_ssh_credentials_params_roundtrip() {
        let params = StoreSshCredentialsParams {
            key_path: "/home/user/.ssh/id_ed25519_vouch".to_string(),
            cert_path: "/home/user/.ssh/id_ed25519_vouch-cert.pub".to_string(),
            session_expires_at: Some("2099-12-31T23:59:59Z".to_string()),
            server_url: Some("https://vouch.example.com".to_string()),
        };

        let json = serde_json::to_string(&params).unwrap();
        let deserialized: StoreSshCredentialsParams = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.key_path, "/home/user/.ssh/id_ed25519_vouch");
        assert_eq!(
            deserialized.cert_path,
            "/home/user/.ssh/id_ed25519_vouch-cert.pub"
        );
        assert_eq!(
            deserialized.session_expires_at.as_deref(),
            Some("2099-12-31T23:59:59Z")
        );
    }

    /// JSON-RPC response success.
    #[test]
    fn test_response_success() {
        let response = Response::success(1, "pong").unwrap();
        assert!(response.result.is_some());
        assert!(response.error.is_none());
        assert_eq!(response.id, 1);
        assert_eq!(
            response.result.as_ref().and_then(|v| v.as_str()),
            Some("pong")
        );
    }

    /// JSON-RPC response not authenticated.
    #[test]
    fn test_response_not_authenticated() {
        let response = Response::not_authenticated(1);
        assert!(response.error.is_some());
        let error = response.error.as_ref().unwrap();
        assert_eq!(error.code, NOT_AUTHENTICATED);
    }

    /// JSON-RPC response session expired.
    #[test]
    fn test_response_session_expired() {
        let response = Response::session_expired(1);
        assert!(response.error.is_some());
        let error = response.error.as_ref().unwrap();
        assert_eq!(error.code, SESSION_EXPIRED);
    }

    /// JSON-RPC response method not found.
    #[test]
    fn test_response_method_not_found() {
        let response = Response::method_not_found(1);
        assert!(response.error.is_some());
        let error = response.error.as_ref().unwrap();
        assert_eq!(error.code, -32601);
    }

    /// JSON-RPC response invalid params.
    #[test]
    fn test_response_invalid_params() {
        let response = Response::invalid_params(1, "missing token");
        assert!(response.error.is_some());
        let error = response.error.as_ref().unwrap();
        assert_eq!(error.code, -32602);
        assert!(error.message.contains("missing token"));
    }

    /// Response serialization round-trip.
    #[test]
    fn test_response_serialization_roundtrip() {
        let response = Response::success(42, serde_json::json!({"authenticated": true})).unwrap();

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: Response = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, 42);
        assert!(deserialized.result.is_some());
        assert!(deserialized.error.is_none());
    }
}

mod wire_protocol {
    use vouch_agent::wire;

    /// Round-trip a JSON-RPC message through the wire protocol.
    #[tokio::test]
    async fn test_jsonrpc_message_roundtrip() {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ping"
        });
        let data = serde_json::to_vec(&request).unwrap();

        // Write to a buffer
        let mut buffer = Vec::new();
        wire::write_message(&mut buffer, &data).await.unwrap();

        // Read it back
        let mut cursor = std::io::Cursor::new(buffer);
        let result = wire::read_message(&mut cursor).await.unwrap();
        assert!(result.is_some());

        let received = result.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&received).unwrap();
        assert_eq!(parsed["method"], "ping");
        assert_eq!(parsed["id"], 1);
    }

    /// Multiple messages through the same channel.
    #[tokio::test]
    async fn test_multiple_messages() {
        let mut buffer = Vec::new();

        // Write two messages
        let msg1 = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}";
        let msg2 = b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"get_session\"}";

        wire::write_message(&mut buffer, msg1).await.unwrap();
        wire::write_message(&mut buffer, msg2).await.unwrap();

        // Read both back
        let mut cursor = std::io::Cursor::new(buffer);

        let result1 = wire::read_message(&mut cursor).await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&result1).contains("ping"));

        let result2 = wire::read_message(&mut cursor).await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&result2).contains("get_session"));
    }

    /// Store session request encoding matches expected format.
    #[tokio::test]
    async fn test_store_session_wire_format() {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "store_session",
            "params": {
                "token": "test_jwt",
                "user_email": "user@example.com",
                "expires_at": "2099-12-31T23:59:59Z"
            }
        });
        let data = serde_json::to_vec(&request).unwrap();

        let mut buffer = Vec::new();
        wire::write_message(&mut buffer, &data).await.unwrap();

        // Verify the 4-byte length prefix is correct
        assert!(buffer.len() > 4);
        let len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
        assert_eq!(len, data.len());
        assert_eq!(buffer.len(), 4 + len);

        // Verify the payload is valid JSON
        let payload = &buffer[4..];
        let parsed: serde_json::Value = serde_json::from_slice(payload).unwrap();
        assert_eq!(parsed["method"], "store_session");
        assert_eq!(parsed["params"]["user_email"], "user@example.com");
    }
}

mod audit_log {
    use vouch_agent::audit::AuditEvent;

    /// Audit event with data serializes correctly.
    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent::SessionStored {
            email: "user@example.com".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event\":\"session_stored\""));
        assert!(json.contains("\"email\":\"user@example.com\""));
    }

    /// All enum variants serialize to snake_case event names.
    #[test]
    fn test_all_event_types_serialize_to_snake_case() {
        let events: Vec<AuditEvent> = vec![
            AuditEvent::SessionStored {
                email: "test@example.com".to_string(),
            },
            AuditEvent::SessionCleared,
            AuditEvent::SessionExpired { email: None },
            AuditEvent::SshCertProvisioned {
                key_path: "/tmp/key".to_string(),
                cert_path: "/tmp/cert".to_string(),
            },
            AuditEvent::SshSigning,
            AuditEvent::CredentialCached {
                credential_type: "aws".to_string(),
            },
            AuditEvent::CredentialCacheCleared,
        ];

        for event in &events {
            let json = serde_json::to_string(event).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
            let event_name = parsed["event"].as_str().unwrap();
            assert!(
                !event_name.is_empty(),
                "event name should not be empty: {json}"
            );
            assert!(
                event_name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_'),
                "event name should be snake_case: {event_name}"
            );
        }
    }

    /// Audit event with no extra fields.
    #[test]
    fn test_audit_event_empty_variant() {
        let event = AuditEvent::SessionCleared;

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event\":\"session_cleared\""));
        // Only the event field, no extra data
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.as_object().unwrap().len(), 1);
    }
}
