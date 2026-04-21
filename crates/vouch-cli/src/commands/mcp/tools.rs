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

/// Parameters for `vouch_aws_exec`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AwsExecParams {
    /// AWS IAM role ARN to assume.
    pub role: String,
    /// AWS CLI command to execute (without the leading "aws").
    /// Example: "s3 ls" or "ec2 describe-instances --region us-west-2"
    pub command: String,
}

/// Result of `vouch_aws_exec`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct AwsExecResult {
    /// Whether the command executed successfully.
    pub status: String,
    /// Command stdout.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    /// Command stderr (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
    /// Process exit code.
    pub exit_code: i32,
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

    /// Execute an AWS CLI command with scoped credentials.
    ///
    /// The MCP server is the trust boundary: it fetches ReadOnlyAccess-scoped
    /// STS credentials with AI session tags, executes the AWS CLI command in a
    /// subprocess with those credentials injected as env vars, and returns the
    /// output. The agent never sees raw credentials.
    #[tool(
        name = "vouch_aws_exec",
        description = "Execute an AWS CLI command with read-only, FIDO2-backed credentials. The command runs server-side — credentials never enter the conversation. Scoped to ReadOnlyAccess and tagged AccessType=AI in CloudTrail. Requires active FIDO2 session. Example: { \"role\": \"arn:aws:iam::123:role/Dev\", \"command\": \"s3 ls\" }"
    )]
    async fn aws_exec(&self, Parameters(params): Parameters<AwsExecParams>) -> Json<AwsExecResult> {
        Json(self.handle_aws_exec(&params.role, &params.command).await)
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

    async fn handle_aws_exec(&self, role_arn: &str, command: &str) -> AwsExecResult {
        use crate::commands::credential::aws::{StsExchangeOptions, exchange_for_sts_credentials};
        use secrecy::ExposeSecret;
        use std::process::Command;

        // Resolve region from AWS config or partition default
        let region = match crate::integrations::aws::resolve_region_with_fallback(role_arn) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("MCP AWS exec: failed to resolve region: {e:#}");
                return AwsExecResult {
                    status: "error".to_string(),
                    stdout: None,
                    stderr: Some(
                        "Failed to resolve AWS region. Check your AWS config or role ARN."
                            .to_string(),
                    ),
                    exit_code: -1,
                };
            }
        };

        // Fetch scoped STS credentials with ReadOnlyAccess and MCP attribution
        let sts_result = exchange_for_sts_credentials(
            &self.server_url,
            role_arn,
            &region,
            "vouch-mcp",
            &StsExchangeOptions {
                session_policy_names: &["ReadOnlyAccess"],
                source: Some("mcp"),
                ..StsExchangeOptions::default()
            },
        )
        .await;

        let creds = match sts_result {
            Ok(result) => result.credentials,
            Err(e) => {
                tracing::warn!("MCP AWS exec: STS credential exchange failed: {e:#}");
                return AwsExecResult {
                    status: "error".to_string(),
                    stdout: None,
                    stderr: Some(
                        "Credential exchange failed. Run `vouch login` and retry.".to_string(),
                    ),
                    exit_code: -1,
                };
            }
        };

        // Parse the command string into args
        let args: Vec<&str> = command.split_whitespace().collect();
        if args.is_empty() {
            return AwsExecResult {
                status: "error".to_string(),
                stdout: None,
                stderr: Some("No command specified.".to_string()),
                exit_code: -1,
            };
        }

        // Execute `aws <command>` with scoped credentials injected as env vars.
        // Credentials never leave this process boundary.
        let output = Command::new("aws")
            .args(&args)
            .env("AWS_ACCESS_KEY_ID", &creds.access_key_id)
            .env(
                "AWS_SECRET_ACCESS_KEY",
                creds.secret_access_key.expose_secret(),
            )
            .env("AWS_SESSION_TOKEN", creds.session_token.expose_secret())
            .env("AWS_DEFAULT_REGION", &region)
            .env(
                "AWS_EXECUTION_ENV",
                format!("vouch-mcp/{}", env!("CARGO_PKG_VERSION")),
            )
            .output();

        match output {
            Ok(result) => {
                let code = result.status.code().unwrap_or(-1);
                AwsExecResult {
                    status: if result.status.success() {
                        "success".to_string()
                    } else {
                        "error".to_string()
                    },
                    stdout: Some(String::from_utf8_lossy(&result.stdout).to_string()),
                    stderr: if result.stderr.is_empty() {
                        None
                    } else {
                        Some(String::from_utf8_lossy(&result.stderr).to_string())
                    },
                    exit_code: code,
                }
            }
            Err(e) => {
                tracing::warn!("MCP AWS exec: failed to spawn aws CLI: {e:#}");
                AwsExecResult {
                    status: "error".to_string(),
                    stdout: None,
                    stderr: Some(
                        "Failed to execute `aws` CLI. Ensure it is installed and in PATH."
                            .to_string(),
                    ),
                    exit_code: -1,
                }
            }
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
