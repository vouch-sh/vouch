// SPDX-License-Identifier: Apache-2.0 OR MIT
//! API request and response types for CLI-Server communication.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::encoding::Raw;
use crate::fido2_types::{AttestationObject, Challenge, ClientDataJson, CoseKey, CredentialId};

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

/// Response from `POST /oauth/fido2/challenge`.
///
/// Used by the CLI login flow (FAPI 2.0 FIDO2 assertion grant).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2ChallengeResponse {
    /// Base64url-encoded 32-byte challenge.
    pub challenge: String,
    /// Relying Party ID (domain, e.g., "vouch.sh").
    pub rp_id: String,
    /// HS256 state JWT to include in the assertion grant.
    pub state: String,
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
    /// RFC 8628 §3.2: Complete URI with user_code for one-click flows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_uri_complete: Option<String>,
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
#[derive(Serialize, Deserialize)]
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

// Custom Debug that redacts access_token to prevent accidental log exposure.
impl std::fmt::Debug for DeviceTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("email", &self.email)
            .finish()
    }
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
// Browser-based WebAuthn Login (RFC 6749 OAuth authorize flow)
// ============================================================================

/// Request to start browser-based `WebAuthn` login.
///
/// Used during OAuth authorization flow when user is not authenticated.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BrowserLoginStartRequest {
    /// Pending OAuth authorization ID (to maintain OAuth state across login).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_auth: Option<String>,
}

/// Response containing `WebAuthn` options for browser login.
///
/// Uses discoverable credentials (passkeys) so the authenticator identifies the user.
#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserLoginStartResponse {
    /// Random challenge bytes (base64url encoded for browser).
    pub challenge: String,
    /// Relying Party ID.
    pub rp_id: String,
    /// Authentication state token.
    pub state: String,
    /// Timeout in milliseconds for WebAuthn operation.
    pub timeout: u64,
    /// User verification requirement ("required", "preferred", "discouraged").
    pub user_verification: String,
}

/// Request to complete browser-based `WebAuthn` login.
#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserLoginCompleteRequest {
    /// Authentication state token from start response.
    pub state: String,
    /// Credential ID (base64url encoded).
    pub credential_id: String,
    /// Authenticator data (base64url encoded).
    pub authenticator_data: String,
    /// Client data JSON (base64url encoded).
    pub client_data_json: String,
    /// Signature (base64url encoded).
    pub signature: String,
    /// User handle (base64url encoded) - identifies the user from discoverable credential.
    pub user_handle: String,
    /// Pending OAuth authorization ID (to resume OAuth flow after login).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_auth: Option<String>,
}

/// Response after successful browser login.
#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserLoginCompleteResponse {
    /// Whether login was successful.
    pub success: bool,
    /// Redirect URL after successful login (e.g., back to /oauth/authorize).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
    /// Error message if login failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
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
    /// Timestamp when the key was registered.
    pub created_at: Timestamp,
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
// Cloud Provider Credentials (AWS)
// ============================================================================

/// Cloud provider token response.
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
#[derive(Serialize, Deserialize)]
pub struct GitHubTokenResponse {
    /// Installation access token (use as password with username "x-access-token").
    #[serde(serialize_with = "serialize_secret_string")]
    pub token: secrecy::SecretString,
    /// Expiration timestamp.
    pub expires_at: Timestamp,
    /// Seconds until expiration.
    pub expires_in: u64,
    /// Granted permissions (scope -> level).
    pub permissions: std::collections::HashMap<String, String>,
    /// Repositories the token can access (if scoped).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repositories: Option<Vec<String>>,
}

/// Serialize a `SecretString` by exposing its value.
///
/// This is intentionally used only for wire-protocol serialization (server → client).
/// The `secrecy` crate omits `Serialize` on purpose to prevent accidental logging;
/// this explicit serializer makes the exposure deliberate and auditable.
///
/// Use with `#[serde(serialize_with = "vouch_common::serialize_secret_string")]`.
pub fn serialize_secret_string<S>(
    secret: &secrecy::SecretString,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use secrecy::ExposeSecret;
    serializer.serialize_str(secret.expose_secret())
}

impl std::fmt::Debug for GitHubTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubTokenResponse")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("expires_in", &self.expires_in)
            .field("permissions", &self.permissions)
            .field("repositories", &self.repositories)
            .finish()
    }
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
