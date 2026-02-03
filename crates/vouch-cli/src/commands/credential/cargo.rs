// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cargo credential provider for private registries.
//!
//! This module implements Cargo's credential provider protocol (RFC 2730/3139).
//! It provides authentication tokens for private Cargo registries using Vouch.
//!
//! Protocol: Cargo communicates with credential providers via stdin/stdout JSON.
//! See: https://doc.rust-lang.org/cargo/reference/credential-provider-protocol.html
//!
//! Usage: Configure Cargo to use this provider in ~/.cargo/config.toml:
//!   [registry]
//!   global-credential-providers = ["vouch credential cargo --"]
//!
//! Or for a specific registry:
//!   [registries.my-registry]
//!   credential-provider = ["vouch", "credential", "cargo", "--"]

use anyhow::{Context, Result};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};

use crate::config::Config;

/// Protocol version supported by this credential provider.
const PROTOCOL_VERSION: u32 = 1;

// ============================================================================
// Protocol Messages (matching Cargo's credential-provider-protocol)
// ============================================================================

/// Hello message sent from credential provider to Cargo.
/// Contains the protocol versions supported by this provider.
#[derive(Debug, Serialize)]
struct CredentialHello {
    /// Supported protocol versions.
    v: Vec<u32>,
}

/// Request from Cargo to credential provider.
#[derive(Debug, Deserialize)]
struct CredentialRequest {
    /// Negotiated protocol version.
    v: u32,
    /// Registry information.
    registry: RegistryInfo,
    /// Action to perform.
    action: Action,
    /// Additional command-line arguments (after `--`).
    #[serde(default)]
    #[allow(dead_code)]
    args: Vec<String>,
}

/// Registry information from Cargo.
#[derive(Debug, Deserialize)]
struct RegistryInfo {
    /// Registry index URL.
    #[serde(rename = "index-url")]
    index_url: String,
    /// Registry name from config (if any).
    name: Option<String>,
    /// Headers from HTTP 401 response (if any).
    #[serde(default)]
    #[allow(dead_code)]
    headers: Vec<String>,
}

/// Action requested by Cargo.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum Action {
    /// Get a token for authentication.
    Get(Operation),
    /// Store/login with credentials.
    Login(LoginOptions),
    /// Remove stored credentials.
    Logout,
    /// Unknown action (forward compatibility).
    #[serde(other)]
    Unknown,
}

/// Operation details for "get" action.
#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case")]
#[allow(dead_code)]
enum Operation {
    /// Reading from registry (cargo fetch, build, etc).
    Read,
    /// Publishing a crate.
    Publish {
        name: String,
        vers: String,
        cksum: String,
    },
    /// Yanking a crate version.
    Yank { name: String, vers: String },
    /// Unyanking a crate version.
    Unyank { name: String, vers: String },
    /// Managing crate owners.
    Owners { name: String },
    /// Unknown operation (forward compatibility).
    #[serde(other)]
    Unknown,
}

/// Login options from Cargo.
#[derive(Deserialize, zeroize::ZeroizeOnDrop)]
struct LoginOptions {
    /// Token provided by user (if any).
    /// We don't use this - vouch manages its own authentication.
    #[allow(dead_code)]
    token: Option<String>,
    /// URL for browser-based login (if any).
    #[serde(rename = "login-url")]
    #[allow(dead_code)]
    login_url: Option<String>,
}

impl std::fmt::Debug for LoginOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginOptions")
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("login_url", &self.login_url)
            .finish()
    }
}

/// Response from credential provider to Cargo.
#[derive(Serialize, zeroize::ZeroizeOnDrop)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum CredentialResponse {
    /// Successful get response.
    Get {
        /// The authentication token.
        token: String,
        /// Cache control for the token.
        #[zeroize(skip)]
        cache: CacheControl,
        /// Whether the token is independent of the operation.
        #[serde(rename = "operation-independent")]
        #[zeroize(skip)]
        operation_independent: bool,
    },
    /// Successful login response.
    /// We don't use this - vouch doesn't support cargo login.
    #[allow(dead_code)]
    Login,
    /// Successful logout response.
    Logout,
}

impl std::fmt::Debug for CredentialResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get {
                cache,
                operation_independent,
                ..
            } => f
                .debug_struct("CredentialResponse::Get")
                .field("token", &"[REDACTED]")
                .field("cache", cache)
                .field("operation_independent", operation_independent)
                .finish(),
            Self::Login => f.debug_struct("CredentialResponse::Login").finish(),
            Self::Logout => f.debug_struct("CredentialResponse::Logout").finish(),
        }
    }
}

/// Cache control for tokens.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)]
enum CacheControl {
    /// Never cache the token.
    Never,
    /// Cache for the current Cargo session only.
    Session,
    /// Cache until a specific expiration time (Unix timestamp).
    Expires { expiration: i64 },
}

/// Error response from credential provider.
#[derive(Debug, Serialize)]
struct CredentialError {
    /// Error kind.
    kind: String,
    /// Human-readable error message (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

// ============================================================================
// Implementation
// ============================================================================

/// Run the Cargo credential provider.
///
/// This function implements Cargo's credential provider protocol:
/// 1. Send Hello message with supported versions
/// 2. Read CredentialRequest from stdin
/// 3. Handle the request and send response to stdout
pub async fn run() -> Result<()> {
    // Send Hello message
    let hello = CredentialHello {
        v: vec![PROTOCOL_VERSION],
    };
    send_message(&hello)?;

    // Read request from stdin
    let request_line = read_line()?;
    let request: CredentialRequest =
        serde_json::from_str(&request_line).context("failed to parse credential request")?;

    // Verify protocol version
    if request.v != PROTOCOL_VERSION {
        return send_error(
            "unsupported-version",
            Some(format!(
                "unsupported protocol version {}, expected {}",
                request.v, PROTOCOL_VERSION
            )),
        );
    }

    // Handle the action
    match request.action {
        Action::Get(_operation) => handle_get(&request.registry).await,
        Action::Login(options) => handle_login(&request.registry, options),
        Action::Logout => handle_logout(&request.registry),
        Action::Unknown => send_error("operation-not-supported", None),
    }
}

/// Handle "get" action - return authentication token.
async fn handle_get(registry: &RegistryInfo) -> Result<()> {
    // Load Vouch config
    let config = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            return send_error("not-found", Some(format!("failed to load config: {e}")));
        }
    };

    // Get the session token
    let token = match config.token() {
        Some(t) => t,
        None => {
            return send_error(
                "not-found",
                Some(format!(
                    "not authenticated for registry '{}' - run 'vouch login' first",
                    registry.name.as_deref().unwrap_or(&registry.index_url)
                )),
            );
        }
    };

    // Calculate expiration from JWT if possible, otherwise use session cache
    let token_str = token.expose_secret();
    let cache = parse_jwt_expiration(token_str).map_or(CacheControl::Session, |exp| {
        CacheControl::Expires { expiration: exp }
    });

    let response = CredentialResponse::Get {
        // Token is exposed here because Cargo requires it in the JSON output
        token: token_str.to_string(),
        cache,
        // Token works for any operation (read, publish, yank, etc.)
        operation_independent: true,
    };

    send_message(&response)
}

/// Handle "login" action - direct users to vouch login.
fn handle_login(registry: &RegistryInfo, _options: LoginOptions) -> Result<()> {
    // Vouch manages authentication via `vouch login`, not cargo login.
    // This is consistent with AWS/SSH/GCP integrations where the user
    // authenticates with Vouch once, and native tools use credential helpers.
    eprintln!();
    eprintln!(
        "To authenticate with registry '{}', run:",
        registry.name.as_deref().unwrap_or(&registry.index_url)
    );
    eprintln!();
    eprintln!("    vouch login");
    eprintln!();

    // Return url-not-supported to indicate we don't support cargo login
    send_error(
        "url-not-supported",
        Some("use 'vouch login' to authenticate".to_string()),
    )
}

/// Handle "logout" action - remove stored credentials.
fn handle_logout(registry: &RegistryInfo) -> Result<()> {
    // We don't clear Vouch's session on cargo logout, as the user might
    // want to keep using Vouch for other purposes. Just acknowledge.
    eprintln!(
        "Note: 'cargo logout' does not affect your Vouch session for registry '{}'.",
        registry.name.as_deref().unwrap_or(&registry.index_url)
    );
    eprintln!("To fully log out, run: vouch logout");

    send_message(&CredentialResponse::Logout)
}

/// Send a JSON message to stdout.
fn send_message<T: Serialize>(message: &T) -> Result<()> {
    let json = serde_json::to_string(message).context("failed to serialize message")?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{json}")?;
    out.flush()?;
    Ok(())
}

/// Send an error response to stdout.
fn send_error(kind: &str, message: Option<String>) -> Result<()> {
    let error = CredentialError {
        kind: kind.to_string(),
        message,
    };
    send_message(&error)
}

/// Read a line from stdin.
fn read_line() -> Result<String> {
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .context("failed to read from stdin")?;
    Ok(line.trim().to_string())
}

/// Parse JWT expiration time (exp claim).
/// Returns the expiration as Unix timestamp, or None if parsing fails.
fn parse_jwt_expiration(token: &str) -> Option<i64> {
    // JWT format: header.payload.signature
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    // Decode the payload (second part)
    use base64::Engine;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts.get(1)?)
        .ok()?;

    // Parse as JSON
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;

    // Get expiration
    claims.get("exp")?.as_i64()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_serialization() {
        let hello = CredentialHello { v: vec![1] };
        let json = serde_json::to_string(&hello).unwrap();
        assert_eq!(json, r#"{"v":[1]}"#);
    }

    #[test]
    fn test_get_response_serialization() {
        let response = CredentialResponse::Get {
            token: "secret".to_string(),
            cache: CacheControl::Session,
            operation_independent: true,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains(r#""kind":"get""#));
        assert!(json.contains(r#""token":"secret""#));
        assert!(json.contains(r#""cache":"session""#));
        assert!(json.contains(r#""operation-independent":true"#));
    }

    #[test]
    fn test_expires_cache_serialization() {
        let cache = CacheControl::Expires {
            expiration: 1700000000,
        };
        let json = serde_json::to_string(&cache).unwrap();
        assert_eq!(json, r#"{"expires":{"expiration":1700000000}}"#);
    }

    #[test]
    fn test_error_serialization() {
        let error = CredentialError {
            kind: "not-found".to_string(),
            message: Some("no token".to_string()),
        };
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains(r#""kind":"not-found""#));
        assert!(json.contains(r#""message":"no token""#));
    }

    #[test]
    fn test_request_deserialization() {
        let json = r#"{
            "v": 1,
            "registry": {
                "index-url": "https://index.crates.io/",
                "name": "crates-io"
            },
            "action": {
                "kind": "get",
                "operation": "read"
            },
            "args": []
        }"#;
        let request: CredentialRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.v, 1);
        assert_eq!(request.registry.index_url, "https://index.crates.io/");
        assert_eq!(request.registry.name.as_deref(), Some("crates-io"));
    }

    #[test]
    fn test_publish_operation_deserialization() {
        let json = r#"{
            "v": 1,
            "registry": {
                "index-url": "https://index.crates.io/"
            },
            "action": {
                "kind": "get",
                "operation": "publish",
                "name": "my-crate",
                "vers": "1.0.0",
                "cksum": "abc123"
            }
        }"#;
        let request: CredentialRequest = serde_json::from_str(json).unwrap();
        match request.action {
            Action::Get(Operation::Publish { name, vers, cksum }) => {
                assert_eq!(name, "my-crate");
                assert_eq!(vers, "1.0.0");
                assert_eq!(cksum, "abc123");
            }
            _ => panic!("expected Get(Publish)"),
        }
    }

    #[test]
    fn test_login_with_token_deserialization() {
        let json = r#"{
            "v": 1,
            "registry": {
                "index-url": "https://my-registry.example.com/"
            },
            "action": {
                "kind": "login",
                "token": "secret-token"
            }
        }"#;
        let request: CredentialRequest = serde_json::from_str(json).unwrap();
        match request.action {
            Action::Login(opts) => {
                assert_eq!(opts.token.as_deref(), Some("secret-token"));
            }
            _ => panic!("expected Login"),
        }
    }
}
