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
}
