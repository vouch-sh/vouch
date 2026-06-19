// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JSON-RPC 2.0 protocol types for agent IPC.

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// JSON-RPC protocol version.
pub const JSONRPC_VERSION: &str = "2.0";

/// Serialize a `SecretString` by exposing the secret value.
///
/// Required because `secrecy` intentionally does not implement `Serialize`
/// for `SecretString` to prevent accidental leakage. This explicit serializer
/// is only used for IPC over a Unix socket, not for logging or external APIs.
fn serialize_secret_string<S: serde::Serializer>(
    secret: &SecretString,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(secret.expose_secret())
}

/// Supported JSON-RPC methods for agent IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    Ping,
    GetSession,
    StoreSession,
    ClearSession,
    GetToken,
    StoreSshCredentials,
    ClearSshCredentials,
    HasSshCredentials,
    CacheCredential,
    GetCachedCredential,
    ClearCredentialCache,
}

/// JSON-RPC 2.0 request.
#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    /// JSON-RPC version (always "2.0").
    pub jsonrpc: String,
    /// Request ID.
    pub id: u64,
    /// Method name.
    pub method: Method,
    /// Method parameters (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

impl Request {
    /// Create a new request.
    pub fn new(id: u64, method: Method) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            method,
            params: None,
        }
    }

    /// Create a new request with parameters.
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if params cannot be serialized.
    pub fn with_params<T: Serialize>(
        id: u64,
        method: Method,
        params: T,
    ) -> Result<Self, serde_json::Error> {
        let params = serde_json::to_value(params)?;
        Ok(Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            method,
            params: Some(params),
        })
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
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if the result cannot be serialized.
    pub fn success<T: Serialize>(id: u64, result: T) -> Result<Self, serde_json::Error> {
        let result = serde_json::to_value(result)?;
        Ok(Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: Some(result),
            error: None,
        })
    }

    /// Create an error response.
    pub fn error(id: u64, code: i32, message: &str) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.to_string(),
                data: None,
            }),
        }
    }

    /// Create a "not authenticated" error response.
    pub fn not_authenticated(id: u64) -> Self {
        Self::error(id, NOT_AUTHENTICATED, "not authenticated")
    }

    /// Create a "session expired" error response.
    pub fn session_expired(id: u64) -> Self {
        Self::error(id, SESSION_EXPIRED, "session expired")
    }

    /// Create an "invalid params" error response.
    pub fn invalid_params(id: u64, detail: &str) -> Self {
        Self::error(id, INVALID_PARAMS, &format!("invalid params: {detail}"))
    }

    /// Create a "cache miss" error response (no cached credential found).
    pub fn cache_miss(id: u64) -> Self {
        Self::error(id, CACHE_MISS, "cache miss")
    }

    /// Create a "method not found" error response.
    pub fn method_not_found(id: u64) -> Self {
        Self::error(id, METHOD_NOT_FOUND, "method not found")
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
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

// Application-specific error codes (starting at -32000)
pub const NOT_AUTHENTICATED: i32 = -32000;
pub const SESSION_EXPIRED: i32 = -32001;
pub const CACHE_MISS: i32 = -32002;

/// Parameters for `store_session` method.
#[derive(Serialize, Deserialize)]
pub struct StoreSessionParams {
    /// JWT token (redacted in Debug output via `SecretString`).
    #[serde(serialize_with = "serialize_secret_string")]
    pub token: SecretString,
    /// User's email.
    pub user_email: String,
    /// ISO 8601 expiration timestamp.
    pub expires_at: String,
    /// Server URL for credential refresh (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
}

impl std::fmt::Debug for StoreSessionParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreSessionParams")
            .field("token", &"[REDACTED]")
            .field("user_email", &self.user_email)
            .field("expires_at", &self.expires_at)
            .field("server_url", &self.server_url)
            .finish()
    }
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

/// Parameters for `cache_credential` method.
#[derive(Serialize, Deserialize)]
pub struct CacheCredentialParams {
    /// Credential type (e.g., "aws", "github").
    pub credential_type: String,
    /// Credential data (service-specific JSON fields).
    pub data: serde_json::Value,
    /// When the credential expires (ISO 8601).
    pub expires_at: String,
}

impl std::fmt::Debug for CacheCredentialParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheCredentialParams")
            .field("credential_type", &self.credential_type)
            .field("data", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Parameters for `get_cached_credential` method.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetCachedCredentialParams {
    /// Credential type to retrieve (e.g., "aws", "github").
    pub credential_type: String,
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_request_new() {
        let req = Request::new(1, Method::Ping);

        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.id, 1);
        assert_eq!(req.method, Method::Ping);
        assert!(req.params.is_none());
    }

    #[test]
    fn test_request_with_params() {
        let params = StoreSessionParams {
            token: SecretString::from("test_token"),
            user_email: "test@example.com".to_string(),
            expires_at: "2099-12-31T23:59:59Z".to_string(),
            server_url: None,
        };
        let req = Request::with_params(2, Method::StoreSession, &params).unwrap();

        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.id, 2);
        assert_eq!(req.method, Method::StoreSession);
        assert!(req.params.is_some());
    }

    #[test]
    fn test_response_success() {
        let resp = Response::success(1, "pong").unwrap();

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
        let req = Request::new(42, Method::GetSession);
        let json = serde_json::to_string(&req).expect("serialization should succeed");

        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"id\":42"));
        assert!(json.contains("\"method\":\"get_session\""));
    }

    #[test]
    fn test_method_serde_roundtrip() {
        // Verify all variants serialize to snake_case and roundtrip correctly
        let methods = [
            (Method::Ping, "\"ping\""),
            (Method::GetSession, "\"get_session\""),
            (Method::StoreSession, "\"store_session\""),
            (Method::ClearSession, "\"clear_session\""),
            (Method::GetToken, "\"get_token\""),
            (Method::StoreSshCredentials, "\"store_ssh_credentials\""),
            (Method::ClearSshCredentials, "\"clear_ssh_credentials\""),
            (Method::HasSshCredentials, "\"has_ssh_credentials\""),
            (Method::CacheCredential, "\"cache_credential\""),
            (Method::GetCachedCredential, "\"get_cached_credential\""),
            (Method::ClearCredentialCache, "\"clear_credential_cache\""),
        ];
        for (method, expected_json) in methods {
            let json = serde_json::to_string(&method).expect("serialize");
            assert_eq!(json, expected_json, "serialization mismatch for {method:?}");
            let back: Method = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, method, "roundtrip mismatch for {method:?}");
        }
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
        assert_eq!(METHOD_NOT_FOUND, -32601);
        assert_eq!(INVALID_PARAMS, -32602);
        assert_eq!(INTERNAL_ERROR, -32603);

        // Verify application-specific error codes
        assert_eq!(NOT_AUTHENTICATED, -32000);
        assert_eq!(SESSION_EXPIRED, -32001);
        assert_eq!(CACHE_MISS, -32002);
    }
}
