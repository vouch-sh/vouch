//! Credential types issued by vouch
//!
//! Credentials are short-lived tokens/certificates that vouch issues after
//! verifying human presence or delegation.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How was this credential obtained?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceType {
    /// Human physically present (touched YubiKey or Touch ID)
    HumanPresent,
    /// Delegated to an agent by a human
    HumanDelegated,
}

/// What service is this credential for?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum CredentialTarget {
    /// GitHub installation access token
    GitHub {
        /// GitHub App installation ID
        installation_id: u64,
        /// Repository scope (optional, empty = all repos)
        repositories: Vec<String>,
        /// Permissions granted
        permissions: GitHubPermissions,
    },
    /// AWS STS credentials via OIDC federation
    Aws {
        /// IAM role ARN to assume
        role_arn: String,
        /// Optional session name
        session_name: Option<String>,
    },
    /// SSH certificate signed by vouch CA
    Ssh {
        /// Principals (usernames) allowed
        principals: Vec<String>,
        /// Certificate extensions
        extensions: Vec<String>,
    },
}

/// GitHub App permissions
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHubPermissions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contents: Option<PermissionLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<PermissionLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pull_requests: Option<PermissionLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issues: Option<PermissionLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<PermissionLevel>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionLevel {
    Read,
    Write,
}

/// A credential request from CLI to server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// What credential is being requested
    pub target: CredentialTarget,
    /// Session token proving authentication
    pub session_token: String,
    /// Optional delegation token (if acting as agent)
    pub delegation_token: Option<String>,
}

/// A credential response from server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResponse {
    /// Unique ID for audit trail
    pub credential_id: Uuid,
    /// The actual credential value
    pub credential: IssuedCredential,
    /// How was this obtained
    pub presence: PresenceType,
    /// When it expires
    pub expires_at: Timestamp,
    /// Who requested it (user ID)
    pub issued_to: Uuid,
    /// If delegated, which delegation
    pub delegation_id: Option<Uuid>,
}

/// The actual credential value
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum IssuedCredential {
    /// GitHub installation access token
    GitHubToken { token: String },
    /// AWS STS credentials
    AwsCredentials {
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
    },
    /// SSH certificate (PEM encoded)
    SshCertificate { certificate: String },
}
