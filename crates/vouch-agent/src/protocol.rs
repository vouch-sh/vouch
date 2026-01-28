// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JSON-RPC 2.0 protocol types for agent IPC.

use serde::{Deserialize, Serialize};

/// JSON-RPC 2.0 request.
#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    /// JSON-RPC version (always "2.0").
    pub jsonrpc: String,
    /// Request ID.
    pub id: u64,
    /// Method name.
    pub method: String,
    /// Method parameters (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

impl Request {
    /// Create a new request.
    pub fn new(id: u64, method: &str) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            method: method.to_string(),
            params: None,
        }
    }

    /// Create a new request with parameters.
    pub fn with_params<T: Serialize>(id: u64, method: &str, params: T) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            method: method.to_string(),
            params: Some(serde_json::to_value(params).unwrap_or(serde_json::Value::Null)),
        }
    }
}

/// JSON-RPC 2.0 response.
#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    /// JSON-RPC version (always "2.0").
    pub jsonrpc: String,
    /// Request ID (matches request).
    pub id: u64,
    /// Result (if successful).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Error (if failed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl Response {
    /// Create a successful response.
    pub fn success<T: Serialize>(id: u64, result: T) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(serde_json::to_value(result).unwrap_or(serde_json::Value::Null)),
            error: None,
        }
    }

    /// Create an error response.
    pub fn error(id: u64, code: i32, message: &str) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.to_string(),
                data: None,
            }),
        }
    }
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Serialize, Deserialize)]
pub struct RpcError {
    /// Error code.
    pub code: i32,
    /// Error message.
    pub message: String,
    /// Additional error data (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

// Standard JSON-RPC 2.0 error codes
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

// Application-specific error codes (starting at -32000)
pub const NOT_AUTHENTICATED: i32 = -32000;
pub const SESSION_EXPIRED: i32 = -32001;

/// Parameters for `store_session` method.
#[derive(Debug, Serialize, Deserialize)]
pub struct StoreSessionParams {
    /// JWT token.
    pub token: String,
    /// User's email.
    pub user_email: String,
    /// ISO 8601 expiration timestamp.
    pub expires_at: String,
    /// Server URL for credential refresh (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
}

/// Parameters for `store_ssh_credentials` method.
#[derive(Debug, Serialize, Deserialize)]
pub struct StoreSshCredentialsParams {
    /// Path to SSH private key.
    pub key_path: String,
    /// Path to SSH certificate.
    pub cert_path: String,
    /// Session expiration timestamp (ISO 8601).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_expires_at: Option<String>,
    /// Server URL for certificate refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_request_new() {
        let req = Request::new(1, "ping");

        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.id, 1);
        assert_eq!(req.method, "ping");
        assert!(req.params.is_none());
    }

    #[test]
    fn test_request_with_params() {
        let params = StoreSessionParams {
            token: "test_token".to_string(),
            user_email: "test@example.com".to_string(),
            expires_at: "2099-12-31T23:59:59Z".to_string(),
            server_url: None,
        };
        let req = Request::with_params(2, "store_session", &params);

        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.id, 2);
        assert_eq!(req.method, "store_session");
        assert!(req.params.is_some());
    }

    #[test]
    fn test_response_success() {
        let resp = Response::success(1, "pong");

        assert_eq!(resp.jsonrpc, "2.0");
        assert_eq!(resp.id, 1);
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
        assert_eq!(resp.result.as_ref().and_then(|v| v.as_str()), Some("pong"));
    }

    #[test]
    fn test_response_error() {
        let resp = Response::error(1, NOT_AUTHENTICATED, "Not authenticated");

        assert_eq!(resp.jsonrpc, "2.0");
        assert_eq!(resp.id, 1);
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());

        let err = resp.error.as_ref().expect("error should exist");
        assert_eq!(err.code, NOT_AUTHENTICATED);
        assert_eq!(err.message, "Not authenticated");
    }

    #[test]
    fn test_request_serialization() {
        let req = Request::new(42, "get_session");
        let json = serde_json::to_string(&req).expect("serialization should succeed");

        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"id\":42"));
        assert!(json.contains("\"method\":\"get_session\""));
    }

    #[test]
    fn test_response_deserialization() {
        let json = r#"{"jsonrpc":"2.0","id":1,"result":"pong"}"#;
        let resp: Response = serde_json::from_str(json).expect("deserialization should succeed");

        assert_eq!(resp.id, 1);
        assert_eq!(resp.result.as_ref().and_then(|v| v.as_str()), Some("pong"));
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_error_codes() {
        // Verify standard JSON-RPC error codes
        assert_eq!(PARSE_ERROR, -32700);
        assert_eq!(INVALID_REQUEST, -32600);
        assert_eq!(METHOD_NOT_FOUND, -32601);
        assert_eq!(INVALID_PARAMS, -32602);
        assert_eq!(INTERNAL_ERROR, -32603);

        // Verify application-specific error codes
        assert_eq!(NOT_AUTHENTICATED, -32000);
        assert_eq!(SESSION_EXPIRED, -32001);
    }
}
