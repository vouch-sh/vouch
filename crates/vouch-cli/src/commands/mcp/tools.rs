// SPDX-License-Identifier: Apache-2.0 OR MIT
//! MCP tool definitions and handlers.

// rmcp macros require pub types for schema generation
#![allow(unreachable_pub)]

use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::{schemars, tool, tool_router};
use serde::{Deserialize, Serialize};

/// The Vouch MCP server.
///
/// Holds the Vouch server URL for making API calls. Session state
/// is resolved via the vouch-agent daemon IPC (same pattern as CLI).
pub(crate) struct VouchMcpServer {
    server_url: String,
}

impl VouchMcpServer {
    pub(crate) fn new(server_url: String) -> Self {
        Self { server_url }
    }
}

// -- Tool parameter and result types --

/// Parameters for `vouch_status` (none required).
#[derive(Debug, Deserialize, schemars::JsonSchema, Default)]
pub struct StatusParams {}

/// Result of `vouch_status`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct StatusResult {
    /// Whether the user has an active FIDO2 session.
    pub authenticated: bool,
    /// User email (if authenticated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Session expiration time (ISO 8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Hours remaining in the session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hours_remaining: Option<f64>,
    /// Guidance for the agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
}

/// Parameters for `vouch_credential_aws`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AwsCredentialParams {
    /// AWS IAM role ARN to assume.
    pub role: String,
}

/// Result of `vouch_credential_aws`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct AwsCredentialResult {
    /// Whether credentials are ready for use.
    pub status: String,
    /// AWS CLI profile name to use.
    pub profile: String,
    /// The role ARN that was assumed.
    pub role_arn: String,
    /// Cache TTL in seconds (credentials refreshed after this).
    pub cache_ttl_seconds: u64,
    /// Whether credentials are restricted to read-only access.
    pub read_only: bool,
    /// Session tags applied to the credentials.
    pub session_tags: SessionTags,
    /// How the agent should use these credentials.
    pub usage: String,
}

/// AI session tags applied to MCP-sourced credentials.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SessionTags {
    #[serde(rename = "AccessType")]
    pub access_type: String,
    #[serde(rename = "Source")]
    pub source: String,
}

/// Parameters for `vouch_credential_ssh`.
#[derive(Debug, Deserialize, schemars::JsonSchema, Default)]
pub struct SshCredentialParams {
    /// Path to SSH private key (default: ~/.ssh/id_ed25519_vouch).
    #[serde(default)]
    pub key: Option<String>,
}

/// Result of `vouch_credential_ssh`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SshCredentialResult {
    /// Whether the SSH certificate is ready.
    pub status: String,
    /// Path to the SSH private key.
    pub key_path: String,
    /// Path to the SSH certificate.
    pub cert_path: String,
    /// SSH principals the certificate is valid for.
    pub principals: Vec<String>,
    /// Certificate validity in seconds.
    pub valid_for_seconds: u64,
    /// How the agent should use this credential.
    pub usage: String,
}

// -- Tool router --

#[tool_router(server_handler)]
impl VouchMcpServer {
    /// Check Vouch authentication status.
    ///
    /// Returns the current session state: whether the user is authenticated,
    /// their email, and session expiration. No credentials are returned.
    #[tool(
        name = "vouch_status",
        description = "Check Vouch authentication status. Returns session state (authenticated, email, expiry). Call this first to verify the user has an active FIDO2 session before requesting credentials."
    )]
    async fn status(&self, Parameters(_params): Parameters<StatusParams>) -> Json<StatusResult> {
        Json(self.handle_status().await)
    }

    /// Get AWS credentials via credential_process.
    ///
    /// Ensures the AWS CLI profile is configured with Vouch as the
    /// credential_process. Returns the profile name and usage instructions.
    /// Credentials are restricted to ReadOnlyAccess and tagged with
    /// AccessType=AI for CloudTrail differentiation.
    #[tool(
        name = "vouch_credential_aws",
        description = "Get read-only AWS credentials for a role. Returns an AWS CLI profile name — use `aws --profile vouch <command>`. Credentials are time-limited (15min cache), read-only (ReadOnlyAccess session policy), and tagged AccessType=AI in CloudTrail. Requires active FIDO2 session."
    )]
    async fn credential_aws(
        &self,
        Parameters(params): Parameters<AwsCredentialParams>,
    ) -> Json<AwsCredentialResult> {
        Json(self.handle_aws_credential(&params.role).await)
    }

    /// Get an SSH certificate.
    ///
    /// Fetches or refreshes an SSH certificate from the Vouch server
    /// and writes it to disk. Returns file paths and usage instructions.
    #[tool(
        name = "vouch_credential_ssh",
        description = "Get an SSH certificate. Writes certificate to ~/.ssh/ and returns key/cert paths with usage instructions. Certificate is time-limited. Requires active FIDO2 session."
    )]
    async fn credential_ssh(
        &self,
        Parameters(params): Parameters<SshCredentialParams>,
    ) -> Json<SshCredentialResult> {
        Json(self.handle_ssh_credential(params.key.as_deref()).await)
    }
}

// -- Handler implementations --

impl VouchMcpServer {
    async fn handle_status(&self) -> StatusResult {
        // Try to get session from the agent daemon via IPC
        let session = async {
            let mut agent = vouch_agent::AgentClient::connect().await.ok()?;
            agent.get_session().await.ok()
        }
        .await;

        match session {
            Some(info) => {
                let hours_remaining = info.expires_in_seconds as f64 / 3600.0;
                StatusResult {
                    authenticated: true,
                    email: Some(info.user_email),
                    expires_at: Some(info.expires_at),
                    hours_remaining: Some(hours_remaining),
                    guidance: None,
                }
            }
            None => StatusResult {
                authenticated: false,
                email: None,
                expires_at: None,
                hours_remaining: None,
                guidance: Some(
                    "Not authenticated. Run `vouch login` and touch your YubiKey to start a session."
                        .to_string(),
                ),
            },
        }
    }

    async fn handle_aws_credential(&self, role_arn: &str) -> AwsCredentialResult {
        use crate::integrations::aws::config::AwsConfig;

        // Verify that a vouch-configured AWS profile exists with credential_process.
        // The user must have run `vouch setup aws --role <ARN>` beforehand.
        let profile = match AwsConfig::load() {
            Ok(config) => {
                // Find a vouch profile matching this role ARN, or any vouch profile
                let profiles = config.find_all_vouch_profiles();
                let matching = profiles.iter().find(|p| {
                    p.credential_process
                        .as_ref()
                        .is_some_and(|cp| cp.contains(role_arn))
                });
                match matching.or_else(|| profiles.first()) {
                    Some(p) => p.name.clone(),
                    None => {
                        return AwsCredentialResult {
                            status: "error: no vouch AWS profile configured".to_string(),
                            profile: String::new(),
                            role_arn: role_arn.to_string(),
                            cache_ttl_seconds: 0,
                            read_only: true,
                            session_tags: SessionTags {
                                access_type: "AI".to_string(),
                                source: "VouchMCP".to_string(),
                            },
                            usage: format!(
                                "Run `vouch setup aws --role {role_arn}` to configure the AWS profile, then retry."
                            ),
                        };
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to load AWS config: {e:#}");
                return AwsCredentialResult {
                    status: "error: cannot read ~/.aws/config".to_string(),
                    profile: String::new(),
                    role_arn: role_arn.to_string(),
                    cache_ttl_seconds: 0,
                    read_only: true,
                    session_tags: SessionTags {
                        access_type: "AI".to_string(),
                        source: "VouchMCP".to_string(),
                    },
                    usage: "Run `vouch setup aws --role <ARN>` to configure the AWS profile."
                        .to_string(),
                };
            }
        };

        // Profile exists with credential_process pointing to vouch.
        // The actual STS call happens when the agent runs `aws --profile <name>` —
        // credential_process invokes `vouch credential aws` at that point.
        AwsCredentialResult {
            status: "ready".to_string(),
            profile: profile.clone(),
            role_arn: role_arn.to_string(),
            cache_ttl_seconds: 900,
            read_only: true,
            session_tags: SessionTags {
                access_type: "AI".to_string(),
                source: "VouchMCP".to_string(),
            },
            usage: format!("aws --profile {profile} <command>"),
        }
    }

    async fn handle_ssh_credential(&self, key: Option<&str>) -> SshCredentialResult {
        use crate::commands::credential::ssh::{default_key_path, provision_ssh_certificate};
        use ssh_key::certificate::Certificate;

        // Determine key and cert paths
        let key_path = match key {
            Some(p) => std::path::PathBuf::from(p),
            None => match default_key_path() {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("MCP SSH: failed to resolve key path: {e:#}");
                    return self.ssh_error_result();
                }
            },
        };
        let cert_path = format!("{}-cert.pub", key_path.display());

        // Check if a valid certificate already exists on disk
        if let Ok(cert_data) = std::fs::read_to_string(&cert_path)
            && let Ok(cert) = Certificate::from_openssh(&cert_data)
        {
            let now_unix = jiff::Timestamp::now().as_second();
            let valid_before = i64::try_from(cert.valid_before()).unwrap_or(i64::MAX);
            if valid_before > now_unix {
                let remaining = u64::try_from(valid_before - now_unix).unwrap_or(0);
                let principals: Vec<String> = cert
                    .valid_principals()
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                let kp = key_path.display().to_string();
                return SshCredentialResult {
                    status: "ready".to_string(),
                    key_path: kp.clone(),
                    cert_path,
                    principals,
                    valid_for_seconds: remaining,
                    usage: format!("ssh -i {kp} user@host"),
                };
            }
        }

        // Certificate missing or expired — provision a new one
        let result = provision_ssh_certificate(&self.server_url, key, None).await;

        match result {
            Ok(provision) => {
                let kp = provision.key_path.display().to_string();
                let cp = provision.cert_path.display().to_string();
                SshCredentialResult {
                    status: "ready".to_string(),
                    key_path: kp.clone(),
                    cert_path: cp,
                    principals: provision.response.principals,
                    valid_for_seconds: provision.response.valid_for_seconds,
                    usage: format!("ssh -i {kp} user@host"),
                }
            }
            Err(e) => {
                tracing::warn!("MCP SSH credential request failed: {e:#}");
                self.ssh_error_result()
            }
        }
    }

    fn ssh_error_result(&self) -> SshCredentialResult {
        let home = dirs::home_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "/tmp".to_string());
        let key_path = format!("{home}/.ssh/id_ed25519_vouch");
        SshCredentialResult {
            status: "error: SSH certificate provisioning failed".to_string(),
            key_path: key_path.clone(),
            cert_path: format!("{key_path}-cert.pub"),
            principals: vec![],
            valid_for_seconds: 0,
            usage: "Run `vouch login` first, then retry. Run `vouch credential ssh` for details."
                .to_string(),
        }
    }
}
