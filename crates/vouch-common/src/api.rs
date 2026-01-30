// SPDX-License-Identifier: Apache-2.0 OR MIT
//! API request and response types for CLI-Server communication.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::encoding::Raw;
use crate::fido2_types::{
    AttestationObject, AuthData, Challenge, ClientDataJson, CoseKey, CredentialId, Signature,
    UserHandle,
};

// ============================================================================
// Registration
// ============================================================================

/// Request to start FIDO2 registration.
///
/// Note: Email is not included in this request. For first-time enrollment,
/// users must use the browser-based OIDC flow (`vouch enroll`). This CLI
/// registration endpoint requires authentication, and the email is derived
/// from the session token.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterStartRequest {
    /// Human-readable name for the authenticator (e.g., "My `YubiKey` 5").
    pub name: String,
}

/// Response containing challenge for FIDO2 registration.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterStartResponse {
    /// Random challenge bytes (32 bytes).
    pub challenge: Challenge<Raw>,
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
    /// Credential IDs to exclude (already registered for this user).
    /// Used to prevent duplicate registrations of the same key.
    #[serde(default)]
    pub exclude_credential_ids: Vec<CredentialId<Raw>>,
}

/// Request to complete FIDO2 registration with authenticator response.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterCompleteRequest {
    /// Registration state token from start response.
    pub state: String,
    /// Credential ID from authenticator.
    pub credential_id: CredentialId<Raw>,
    /// COSE public key from authenticator.
    pub public_key: CoseKey<Raw>,
    /// Attestation object from authenticator.
    pub attestation_object: AttestationObject<Raw>,
    /// Client data JSON (constructed by CLI).
    pub client_data_json: ClientDataJson<Raw>,
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
/// Empty for discoverable credentials - the YubiKey identifies the user.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct LoginStartRequest {}

/// Response containing challenge for FIDO2 authentication.
/// For discoverable credentials, no credential_ids are needed.
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginStartResponse {
    /// Random challenge bytes (32 bytes).
    pub challenge: Challenge<Raw>,
    /// Relying Party ID (domain).
    pub rp_id: String,
    /// Authentication state token (opaque, returned to complete endpoint).
    pub state: String,
}

/// Request to complete FIDO2 authentication with assertion.
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginCompleteRequest {
    /// Authentication state token from start response.
    pub state: String,
    /// Credential ID used for this assertion.
    pub credential_id: CredentialId<Raw>,
    /// Authenticator data from assertion.
    pub authenticator_data: AuthData<Raw>,
    /// Signature from assertion.
    pub signature: Signature<Raw>,
    /// Client data JSON (constructed by CLI).
    pub client_data_json: ClientDataJson<Raw>,
    /// User handle from discoverable credential (identifies the user).
    pub user_handle: UserHandle<Raw>,
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
    /// User's email address (identified from user_handle).
    pub email: String,
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
    /// Credential IDs to exclude (base64url encoded).
    /// Used to prevent duplicate registrations of the same key.
    #[serde(default)]
    pub exclude_credential_ids: Vec<String>,
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

/// Request to rename a security key.
#[derive(Debug, Serialize, Deserialize)]
pub struct RenameKeyRequest {
    /// New name for the key.
    pub name: String,
}

/// Response after renaming a key.
#[derive(Debug, Serialize, Deserialize)]
pub struct RenameKeyResponse {
    /// Confirmation message.
    pub message: String,
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

// ============================================================================
// SSH Credentials
// ============================================================================

/// Request to obtain an SSH certificate.
#[derive(Debug, Serialize, Deserialize)]
pub struct SshCertificateRequest {
    /// User's SSH public key (OpenSSH format, e.g., "ssh-ed25519 AAAA...").
    pub public_key: String,
}

/// Response containing the signed SSH certificate.
#[derive(Debug, Serialize, Deserialize)]
pub struct SshCertificateResponse {
    /// Signed SSH certificate (OpenSSH format).
    pub certificate: String,
    /// Certificate validity period in seconds.
    pub valid_for_seconds: u64,
    /// Principals (usernames) the certificate is valid for.
    pub principals: Vec<String>,
    /// Certificate serial number.
    pub serial: u64,
}

/// Response containing the SSH CA public key.
#[derive(Debug, Serialize, Deserialize)]
pub struct SshCaPublicKeyResponse {
    /// SSH CA public key (OpenSSH format).
    pub public_key: String,
    /// Key comment/identifier.
    pub comment: String,
}

// ============================================================================
// Cloud Provider Credentials (AWS, GCP)
// ============================================================================

/// Cloud provider token response (AWS and GCP use identical format).
/// Contains an OIDC ID token for use with cloud provider identity federation.
#[derive(Debug, Serialize, Deserialize)]
pub struct CloudTokenResponse {
    /// OIDC ID token for use with cloud provider identity federation.
    pub id_token: String,
    /// Token validity period in seconds.
    pub expires_in: u64,
}

/// Response containing an OIDC ID token for AWS STS.
pub type AwsTokenResponse = CloudTokenResponse;

/// Response containing an OIDC ID token for GCP Workload Identity Federation.
pub type GcpTokenResponse = CloudTokenResponse;

// ============================================================================
// Cloud Provider Integration Configs
// ============================================================================

/// GCP Workload Identity Federation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpIntegrationConfig {
    /// GCP project number (numeric, not project ID).
    pub project_number: String,
    /// Workload Identity Pool ID.
    pub pool_id: String,
    /// Provider ID within the Workload Identity Pool.
    pub provider_id: String,
    /// Optional service account email to impersonate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_account: Option<String>,
}

/// AWS OIDC federation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsIntegrationConfig {
    /// Default IAM role ARN to assume.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_role_arn: Option<String>,
}

/// Response for GET /v1/integrations/{provider}.
#[derive(Debug, Serialize, Deserialize)]
pub struct IntegrationConfigResponse<T> {
    /// Whether the integration is configured for this organization.
    pub configured: bool,
    /// The configuration, if configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<T>,
}

// ============================================================================
// GitHub Credentials
// ============================================================================

/// Request to obtain a GitHub installation access token.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GitHubTokenRequest {
    /// GitHub organization/user to get token for. Required if multiple GitHub
    /// accounts are connected. Can be inferred from `repositories` if provided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Optional: scope token to specific repositories (format: "owner/repo").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repositories: Option<Vec<String>>,
}

/// Response containing a GitHub installation access token.
#[derive(Debug, Serialize, Deserialize)]
pub struct GitHubTokenResponse {
    /// Installation access token (use as password with username "x-access-token").
    pub token: String,
    /// ISO 8601 expiration timestamp.
    pub expires_at: String,
    /// Seconds until expiration.
    pub expires_in: u64,
    /// Granted permissions (scope -> level).
    pub permissions: std::collections::HashMap<String, String>,
    /// Repositories the token can access (if scoped).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repositories: Option<Vec<String>>,
}

/// Response indicating GitHub integration status.
#[derive(Debug, Serialize, Deserialize)]
pub struct GitHubStatusResponse {
    /// Whether GitHub App is configured on the server.
    pub configured: bool,
    /// Whether the user's organization has connected GitHub.
    pub connected: bool,
    /// Connected GitHub accounts (may be multiple).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub github_accounts: Vec<GitHubAccountStatus>,
}

/// Status of a connected GitHub account.
#[derive(Debug, Serialize, Deserialize)]
pub struct GitHubAccountStatus {
    /// GitHub account login (organization or user name).
    pub login: String,
    /// Account type ("Organization" or "User").
    pub account_type: String,
    /// Whether the installation is suspended.
    pub suspended: bool,
    /// Repository selection mode ("all" or "selected").
    pub repository_selection: String,
    /// Repository names when repository_selection is "selected".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repositories: Option<Vec<String>>,
}
