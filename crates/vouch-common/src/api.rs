//! API request and response types for CLI-Server communication.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// Registration
// ============================================================================

/// Request to start FIDO2 registration.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterStartRequest {
    /// Human-readable name for the authenticator (e.g., "My `YubiKey` 5").
    pub name: String,
    /// User's email address.
    pub email: String,
}

/// Response containing challenge for FIDO2 registration.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterStartResponse {
    /// Random challenge bytes (32 bytes).
    pub challenge: Vec<u8>,
    /// Relying Party ID (domain, e.g., "vouch.sh").
    pub rp_id: String,
    /// Relying Party name for display.
    pub rp_name: String,
    /// Server-assigned user ID.
    pub user_id: Uuid,
    /// User's email (used as user name in `WebAuthn`).
    pub user_name: String,
    /// Algorithms the server accepts (COSE algorithm identifiers).
    /// Typically [-7] for ES256 (ECDSA with P-256 and SHA-256).
    pub algorithms: Vec<i32>,
    /// Registration state token (opaque, returned to complete endpoint).
    pub state: String,
}

/// Request to complete FIDO2 registration with authenticator response.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterCompleteRequest {
    /// Registration state token from start response.
    pub state: String,
    /// Credential ID from authenticator.
    pub credential_id: Vec<u8>,
    /// COSE public key from authenticator.
    pub public_key: Vec<u8>,
    /// Attestation object from authenticator.
    pub attestation_object: Vec<u8>,
    /// Client data JSON (constructed by CLI).
    pub client_data_json: Vec<u8>,
}

/// Response after successful registration.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterCompleteResponse {
    /// Server-assigned device/authenticator ID.
    pub device_id: Uuid,
    /// Confirmation message.
    pub message: String,
}

// ============================================================================
// Client Context (device/environment info sent with requests)
// ============================================================================

/// Context about the client environment, sent with authentication requests.
/// This enables future anomaly detection (e.g., impossible travel, new device).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientContext {
    /// CLI version (from `CARGO_PKG_VERSION`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cli_version: Option<String>,
    /// Operating system (e.g., "macos", "linux", "windows").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// OS version (e.g., "14.2.1").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    /// CPU architecture (e.g., "aarch64", "x86_64").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// Client hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

impl ClientContext {
    /// Create a new client context with current system information.
    #[must_use]
    pub fn current() -> Self {
        Self {
            cli_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            os: Some(std::env::consts::OS.to_string()),
            os_version: None, // Filled in by CLI if available
            arch: Some(std::env::consts::ARCH.to_string()),
            hostname: gethostname::gethostname().to_str().map(String::from),
        }
    }
}

// ============================================================================
// Login / Authentication
// ============================================================================

/// Request to start FIDO2 authentication.
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginStartRequest {
    /// User's email address.
    pub email: String,
}

/// Response containing challenge for FIDO2 authentication.
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginStartResponse {
    /// Random challenge bytes (32 bytes).
    pub challenge: Vec<u8>,
    /// Relying Party ID (domain).
    pub rp_id: String,
    /// Credential IDs the user has registered.
    pub credential_ids: Vec<Vec<u8>>,
    /// Authentication state token (opaque, returned to complete endpoint).
    pub state: String,
}

/// Request to complete FIDO2 authentication with assertion.
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginCompleteRequest {
    /// Authentication state token from start response.
    pub state: String,
    /// Credential ID used for this assertion.
    pub credential_id: Vec<u8>,
    /// Authenticator data from assertion.
    pub authenticator_data: Vec<u8>,
    /// Signature from assertion.
    pub signature: Vec<u8>,
    /// Client data JSON (constructed by CLI).
    pub client_data_json: Vec<u8>,
    /// User handle returned by authenticator (may be empty for non-resident keys).
    pub user_handle: Option<Vec<u8>>,
    /// Client context (device/environment info for anomaly detection).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_context: Option<ClientContext>,
}

/// Response after successful authentication.
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginCompleteResponse {
    /// JWT session token.
    pub token: String,
    /// ISO 8601 expiration timestamp.
    pub expires_at: String,
}

// ============================================================================
// Session Status
// ============================================================================

/// Current session status.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionStatus {
    /// Whether the user is currently authenticated.
    pub authenticated: bool,
    /// User's email if authenticated.
    pub email: Option<String>,
    /// Seconds until session expires (if authenticated).
    pub expires_in_seconds: Option<u64>,
    /// Name of the authenticator used for this session.
    pub device_name: Option<String>,
}

// ============================================================================
// Device Authorization Grant (RFC 8628)
// ============================================================================

/// Request to start device authorization flow.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DeviceCodeRequest {
    /// Client identifier (optional for this implementation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Requested scope (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Response containing device and user codes.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceCodeResponse {
    /// Device verification code (used by CLI to poll for token).
    pub device_code: String,
    /// User code to enter in browser.
    pub user_code: String,
    /// URL where user should go to enter the code.
    pub verification_uri: String,
    /// Seconds until codes expire.
    pub expires_in: u64,
    /// Minimum polling interval in seconds.
    pub interval: u64,
}

/// Request to exchange device code for token.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceTokenRequest {
    /// Must be "urn:ietf:params:oauth:grant-type:device_code".
    pub grant_type: String,
    /// Device code from device authorization response.
    pub device_code: String,
}

/// Response containing access token.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceTokenResponse {
    /// JWT access token.
    pub access_token: String,
    /// Token type (always "Bearer").
    pub token_type: String,
    /// Seconds until token expires.
    pub expires_in: u64,
    /// User's email address.
    pub email: String,
}

/// OAuth 2.0 error response.
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthError {
    /// Error code.
    pub error: String,
    /// Human-readable error description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

impl OAuthError {
    /// Create an `authorization_pending` error.
    #[must_use]
    pub fn authorization_pending() -> Self {
        Self {
            error: "authorization_pending".to_string(),
            error_description: Some("The user has not yet completed authorization".to_string()),
        }
    }

    /// Create a `slow_down` error.
    #[must_use]
    pub fn slow_down() -> Self {
        Self {
            error: "slow_down".to_string(),
            error_description: Some("Polling too frequently, please slow down".to_string()),
        }
    }

    /// Create an `expired_token` error.
    #[must_use]
    pub fn expired_token() -> Self {
        Self {
            error: "expired_token".to_string(),
            error_description: Some("The device code has expired".to_string()),
        }
    }

    /// Create an `access_denied` error.
    #[must_use]
    pub fn access_denied() -> Self {
        Self {
            error: "access_denied".to_string(),
            error_description: Some("The user denied the authorization request".to_string()),
        }
    }

    /// Create an `invalid_grant` error.
    #[must_use]
    pub fn invalid_grant() -> Self {
        Self {
            error: "invalid_grant".to_string(),
            error_description: Some(
                "The device code is invalid or has already been used".to_string(),
            ),
        }
    }
}

// ============================================================================
// Browser-based WebAuthn Registration (for enrollment)
// ============================================================================

/// Request to start browser-based `WebAuthn` registration.
#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserRegisterStartRequest {
    /// OIDC state token (proves user completed OIDC flow).
    pub oidc_state: String,
}

/// Response containing `WebAuthn` options for browser registration.
#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserRegisterStartResponse {
    /// Random challenge bytes (base64url encoded for browser).
    pub challenge: String,
    /// Relying Party ID.
    pub rp_id: String,
    /// Relying Party name.
    pub rp_name: String,
    /// User ID (base64url encoded).
    pub user_id: String,
    /// User's email address.
    pub user_email: String,
    /// User's display name.
    pub user_display_name: String,
    /// Supported algorithms (-7 for ES256).
    pub algorithms: Vec<i32>,
    /// Registration state token.
    pub state: String,
}

/// Request to complete browser-based `WebAuthn` registration.
#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserRegisterCompleteRequest {
    /// Registration state token.
    pub state: String,
    /// Credential ID (base64url encoded).
    pub credential_id: String,
    /// Attestation object (base64url encoded).
    pub attestation_object: String,
    /// Client data JSON (base64url encoded).
    pub client_data_json: String,
}

// ============================================================================
// Key Management
// ============================================================================

/// Information about a registered security key.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Unique identifier for the key.
    pub id: String,
    /// Human-readable name for the key.
    pub name: String,
    /// ISO 8601 timestamp when the key was registered.
    pub created_at: String,
    /// Whether this key was used to create the current session.
    pub is_current_session: bool,
    /// Device model name (e.g., "YubiKey 5 NFC") if known from AAGUID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_model: Option<String>,
    /// AAGUID (Authenticator Attestation GUID) identifying the authenticator model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aaguid: Option<String>,
}

/// Response containing the list of registered keys.
#[derive(Debug, Serialize, Deserialize)]
pub struct ListKeysResponse {
    /// List of registered security keys.
    pub keys: Vec<KeyInfo>,
}

/// Response after deleting a key.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteKeyResponse {
    /// Confirmation message.
    pub message: String,
    /// Number of sessions that were revoked.
    pub sessions_revoked: u64,
}

// ============================================================================
// Authentication Events (Admin API)
// ============================================================================

/// Authentication event for audit/security review.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthEventInfo {
    /// Unique identifier.
    pub id: String,
    /// User ID.
    pub user_id: String,
    /// User email (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_email: Option<String>,
    /// Event type (login_success, login_failed, enrollment, logout).
    pub event_type: String,
    /// Authenticator ID used (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_id: Option<String>,
    /// Client IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    /// HTTP User-Agent header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Client hostname (from CLI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_hostname: Option<String>,
    /// Client OS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_os: Option<String>,
    /// Client architecture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_arch: Option<String>,
    /// CLI version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,
    /// Whether the event was successful.
    pub success: bool,
    /// Reason for failure (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    /// ISO 8601 timestamp when the event occurred.
    pub created_at: String,
}

/// Response containing a list of authentication events.
#[derive(Debug, Serialize, Deserialize)]
pub struct ListAuthEventsResponse {
    /// List of authentication events.
    pub events: Vec<AuthEventInfo>,
}
