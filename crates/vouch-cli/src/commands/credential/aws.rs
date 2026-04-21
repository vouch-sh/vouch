// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS credential command.
//!
//! Obtains temporary AWS credentials using Vouch session and STS.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::client::VouchClient;
use crate::session::get_user_email;

/// AWS credential process output format.
/// See: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
pub(crate) struct CredentialProcessOutput {
    pub(crate) version: u32,
    pub(crate) access_key_id: String,
    pub(crate) secret_access_key: SecretString,
    pub(crate) session_token: SecretString,
    pub(crate) expiration: String,
}

impl CredentialProcessOutput {
    /// Serialize to the JSON format expected by AWS credential_process consumers.
    ///
    /// See: <https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html>
    ///
    /// Field names MUST be PascalCase to match the AWS SDK expectation:
    /// `Version`, `AccessKeyId`, `SecretAccessKey`, `SessionToken`, `Expiration`.
    pub(crate) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "Version": self.version,
            "AccessKeyId": self.access_key_id,
            "SecretAccessKey": self.secret_access_key.expose_secret(),
            "SessionToken": self.session_token.expose_secret(),
            "Expiration": self.expiration,
        })
    }
}

impl std::fmt::Debug for CredentialProcessOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialProcessOutput")
            .field("version", &self.version)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field("session_token", &"[REDACTED]")
            .field("expiration", &self.expiration)
            .finish()
    }
}

/// Response from Vouch OIDC token endpoint.
///
/// Shared by all credential commands that exchange a Vouch session for an
/// AWS OIDC ID token (`aws`, `codeartifact`, `docker`).
#[derive(Deserialize)]
pub(crate) struct OidcTokenResponse {
    pub(crate) id_token: SecretString,
}

impl std::fmt::Debug for OidcTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcTokenResponse")
            .field("id_token", &"[REDACTED]")
            .finish()
    }
}

/// Result of the OIDC → STS credential exchange.
///
/// Provides everything downstream AWS API calls need: an HTTP client,
/// the temporary STS credentials, and the domain suffix for endpoint
/// construction.
pub(crate) struct StsExchangeResult {
    pub(crate) http_client: reqwest::Client,
    pub(crate) credentials: crate::integrations::aws::sts::StsCredentials,
    pub(crate) domain_suffix: &'static str,
}

/// Exchange a Vouch session for AWS STS credentials.
///
/// Handles the full flow: OIDC token fetch → JWT decode for session tags →
/// Detect if running inside an AI coding agent by checking environment variables.
///
/// Returns the agent identifier (e.g., "claude-code", "cursor") if detected.
/// These env vars are set by the agent's shell environment and inherited by
/// child processes including `credential_process` invocations.
///
/// Reference implementation:
/// <https://github.com/vercel/vercel/blob/main/packages/detect-agent/src/index.ts>
///
/// Sources:
/// - `AGENT`: <https://github.com/agentsmd/agents.md/issues/136>
/// - `AI_AGENT`: <https://github.com/vercel/vercel/blob/main/packages/detect-agent/src/index.ts>
/// - `CLAUDECODE` / `CLAUDE_CODE`: <https://code.claude.com/docs/en/env-vars>
/// - `CURSOR_TRACE_ID` / `CURSOR_AGENT`: <https://cursor.com/docs/agent/tools/terminal>
/// - `GEMINI_CLI`: <https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/services/shellExecutionService.ts#L56>
/// - `CODEX_SANDBOX` / `CODEX_THREAD_ID`: <https://github.com/openai/codex/blob/main/codex-rs/core/src/spawn.rs#L25>
/// - `COPILOT_MODEL`: <https://github.com/microsoft/vscode/issues/265446>
/// - `AUGMENT_AGENT`: <https://docs.augmentcode.com/cli/reference>
/// - `ANTIGRAVITY_AGENT`: <https://github.com/vercel/vercel/blob/main/packages/detect-agent/src/index.ts>
/// - `OPENCODE_CLIENT`: <https://github.com/vercel/vercel/blob/main/packages/detect-agent/src/index.ts>
/// - `CLINE_ACTIVE`: <https://github.com/cline/cline/discussions/5366>
fn detect_agent_source() -> Option<&'static str> {
    // Emerging standard: https://github.com/agentsmd/agents.md/issues/136
    if let Ok(val) = std::env::var("AGENT") {
        return match val.as_str() {
            "amp" => Some("amp"),
            "goose" => Some("goose"),
            _ => Some("agent"),
        };
    }
    // Generic agent identifier (Vercel convention)
    if let Ok(val) = std::env::var("AI_AGENT") {
        return match val.as_str() {
            "v0" => Some("v0"),
            _ => Some("agent"),
        };
    }
    // Claude Code: https://code.claude.com/docs/en/env-vars
    if std::env::var_os("CLAUDECODE").is_some() || std::env::var_os("CLAUDE_CODE").is_some() {
        return Some("claude-code");
    }
    // Cursor: https://cursor.com/docs/agent/tools/terminal
    if std::env::var_os("CURSOR_TRACE_ID").is_some() || std::env::var_os("CURSOR_AGENT").is_some() {
        return Some("cursor");
    }
    // Gemini CLI: https://github.com/google-gemini/gemini-cli
    if std::env::var_os("GEMINI_CLI").is_some() {
        return Some("gemini");
    }
    // OpenAI Codex: https://github.com/openai/codex
    if std::env::var_os("CODEX_SANDBOX").is_some() || std::env::var_os("CODEX_THREAD_ID").is_some()
    {
        return Some("codex");
    }
    // GitHub Copilot: https://github.com/microsoft/vscode/issues/265446
    if std::env::var_os("COPILOT_MODEL").is_some() {
        return Some("copilot");
    }
    // Augment: https://docs.augmentcode.com/cli/reference
    if std::env::var_os("AUGMENT_AGENT").is_some() {
        return Some("augment");
    }
    // Antigravity
    if std::env::var_os("ANTIGRAVITY_AGENT").is_some() {
        return Some("antigravity");
    }
    // OpenCode
    if std::env::var_os("OPENCODE_CLIENT").is_some() {
        return Some("opencode");
    }
    // Cline: https://github.com/cline/cline/discussions/5366
    if std::env::var_os("CLINE_ACTIVE").is_some() {
        return Some("cline");
    }
    None
}

/// role ARN validation → `AssumeRoleWithWebIdentity`.
///
/// When `management_role` is `Some` and differs from `role_arn`, chains
/// through the management role: `AssumeRoleWithWebIdentity` into the
/// management role, then `AssumeRole` into the target.
///
/// External callers (EKS, RDS, etc.) pass `None` — the management role
/// is resolved internally from vouch config so they get chaining for
/// free. `get_aws_credentials` pre-resolves it to avoid a double config
/// load.
///
/// When running inside an AI coding agent (detected via environment
/// variables like `CLAUDECODE`, `CURSOR_AGENT`, etc.), automatically
/// attaches `ReadOnlyAccess` session policy and sets a DPoP source
/// claim for CloudTrail attribution.
pub(crate) async fn exchange_for_sts_credentials(
    server: &str,
    role_arn: &str,
    region: &str,
    session_name: &str,
    management_role: Option<&str>,
) -> Result<StsExchangeResult> {
    use crate::integrations::aws::sts::{
        WebIdentityRequest, assume_role, assume_role_with_web_identity, parse_role_arn,
    };

    // If caller didn't pre-resolve, resolve now from config
    let resolved;
    let mgmt = match management_role {
        Some(m) => Some(m),
        None => {
            resolved = crate::config::Config::load()
                .ok()
                .and_then(|c| resolve_management_role(&c).ok())
                .flatten();
            resolved.as_deref()
        }
    };

    let arn = parse_role_arn(role_arn)?;
    let domain_suffix = arn.partition.dns_suffix();

    // Detect AI agent environment and apply restrictions automatically
    let agent_source = detect_agent_source();
    let agent_policies: &[&str] = if agent_source.is_some() {
        &["ReadOnlyAccess"]
    } else {
        &[]
    };

    let mut client = VouchClient::new(server).await?;

    // Set DPoP source claim for agent attribution (tamperproof via DPoP signature).
    // Server extracts this to add AI-specific session tags to the JWT.
    if let Some(source) = agent_source {
        tracing::info!("AI agent detected ({source}), applying ReadOnlyAccess session policy");
        client.set_dpop_source(source);
    }

    let token_response: OidcTokenResponse = client
        .get_authenticated("/v1/credentials/aws/token")
        .await
        .context("failed to get OIDC token from Vouch server")?;

    let id_token = token_response.id_token.expose_secret();

    // Session tags are now embedded in the JWT via the
    // https://aws.amazon.com/tags claim (server-side). AWS extracts them
    // during AssumeRoleWithWebIdentity and logs them as principalTags in
    // CloudTrail. Tags must NOT also be passed as STS API parameters —
    // AWS rejects requests that include both.

    let http_client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to create HTTP client")?;

    let email = get_user_email(server).await;
    let session = email.as_deref().unwrap_or(session_name);

    let all_policies: &[&str] = agent_policies;

    if let Some(mgmt_role_arn) = mgmt.filter(|m| *m != role_arn) {
        // Chain: AssumeRoleWithWebIdentity into management role, then AssumeRole into target
        let mgmt_arn = parse_role_arn(mgmt_role_arn)?;
        let mgmt_domain_suffix = mgmt_arn.partition.dns_suffix();

        let mgmt_credentials = assume_role_with_web_identity(WebIdentityRequest {
            http_client: &http_client,
            role_arn: mgmt_role_arn,
            role_session_name: session,
            web_identity_token: id_token,
            region,
            domain_suffix: mgmt_domain_suffix,
            session_policy_names: all_policies,
        })
        .await
        .context("failed to assume management role")?;

        let credentials = assume_role(
            &http_client,
            role_arn,
            session,
            region,
            &mgmt_credentials,
            all_policies,
        )
        .await
        .context("failed to assume target role via chaining")?;

        return Ok(StsExchangeResult {
            http_client,
            credentials,
            domain_suffix,
        });
    }

    // Direct AssumeRoleWithWebIdentity (no chaining needed)
    let credentials = assume_role_with_web_identity(WebIdentityRequest {
        http_client: &http_client,
        role_arn,
        role_session_name: session,
        web_identity_token: id_token,
        region,
        domain_suffix,
        session_policy_names: all_policies,
    })
    .await
    .context("failed to assume AWS role")?;

    Ok(StsExchangeResult {
        http_client,
        credentials,
        domain_suffix,
    })
}

/// Resolve the management role ARN from vouch config.
///
/// Tries to match an SSO session from `~/.aws/config` to a key in
/// `aws.sso_sessions`. If no SSO session is found but there's exactly
/// one entry in `sso_sessions`, uses that directly (chaining doesn't
/// require SSO discovery).
/// Returns `None` if no chaining config is found (direct auth is used).
pub(crate) fn resolve_management_role(
    vouch_config: &crate::config::Config,
) -> Result<Option<String>> {
    let aws_cfg = match vouch_config.aws() {
        Some(cfg) if !cfg.sso_sessions.is_empty() => cfg,
        _ => return Ok(None),
    };

    // Try to match via SSO session name from ~/.aws/config
    let aws_config = crate::integrations::aws::config::AwsConfig::load()?;
    if let Some(session_cfg) = aws_config
        .find_sso_session(None)
        .and_then(|s| aws_cfg.sso_sessions.get(&s.name))
    {
        return Ok(Some(session_cfg.management_role.clone()));
    }

    // Fallback: if there's exactly one sso_sessions entry, use it
    if let [only] = aws_cfg.sso_sessions.values().collect::<Vec<_>>().as_slice() {
        return Ok(Some(only.management_role.clone()));
    }

    Ok(None)
}

/// Get cached AWS credentials, fetching fresh ones if needed.
///
/// Shared entry point for `vouch credential aws`, `vouch credential
/// codecommit`, and `vouch exec`. Resolves the management role once
/// and uses it for both the cache key and credential exchange.
pub(crate) async fn get_aws_credentials(server: &str, role_arn: &str) -> Result<serde_json::Value> {
    let vouch_config = crate::config::Config::load()?;
    let management_role = resolve_management_role(&vouch_config)?.filter(|m| m != role_arn);
    let cache_key = if let Some(ref mgmt_role) = management_role {
        format!("aws:chain:{mgmt_role}:{role_arn}")
    } else {
        format!("aws:{role_arn}")
    };

    let mgmt = management_role;
    super::cache::get_or_fetch(&cache_key, "AWS credentials", || async move {
        let output = fetch_and_assume(server, role_arn, mgmt.as_deref()).await?;
        let expires_at = output.expiration.clone();
        Ok((output.to_json(), expires_at))
    })
    .await
}

/// Run the AWS credential command.
///
/// Outputs AWS credential_process JSON to stdout.
pub(crate) async fn run(server: &str, role_arn: &str) -> Result<()> {
    let data = get_aws_credentials(server, role_arn).await?;
    let json = serde_json::to_string(&data).context("failed to serialize credentials")?;
    println!("{json}");
    Ok(())
}

/// Fetch an OIDC token and exchange it for STS credentials.
///
/// Resolves the AWS region, then calls `exchange_for_sts_credentials`
/// with the pre-resolved management role.
async fn fetch_and_assume(
    server: &str,
    role_arn: &str,
    mgmt_role: Option<&str>,
) -> Result<CredentialProcessOutput> {
    let region = crate::integrations::aws::resolve_region_with_fallback(role_arn)?;

    let result =
        exchange_for_sts_credentials(server, role_arn, &region, "vouch-session", mgmt_role).await?;
    let creds = &result.credentials;
    Ok(CredentialProcessOutput {
        version: 1,
        access_key_id: creds.access_key_id.clone(),
        secret_access_key: creds.secret_access_key.clone(),
        session_token: creds.session_token.clone(),
        expiration: creds.expiration.to_string(),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Verify the credential_process JSON output matches the format expected by
    /// AWS CLI and SDKs. Field names must be PascalCase.
    /// See: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
    #[test]
    fn test_credential_process_output_json_format() {
        let output = CredentialProcessOutput {
            version: 1,
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: SecretString::from(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            ),
            session_token: SecretString::from("FwoGZXIvYXdzEBYaDH...EXAMPLETOKEN".to_string()),
            expiration: "2024-01-14T18:00:00Z".to_string(),
        };

        let json = output.to_json();

        // AWS credential_process requires exactly these PascalCase field names
        assert_eq!(json["Version"], 1);
        assert_eq!(json["AccessKeyId"], "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(
            json["SecretAccessKey"],
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        assert_eq!(json["SessionToken"], "FwoGZXIvYXdzEBYaDH...EXAMPLETOKEN");
        assert_eq!(json["Expiration"], "2024-01-14T18:00:00Z");

        // Must have exactly 5 fields — no extra fields allowed
        assert_eq!(json.as_object().unwrap().len(), 5);
    }

    /// Verify the cached credential JSON can be round-tripped through the
    /// extraction code used by exec.rs and codecommit.rs.
    #[test]
    fn test_credential_process_output_cache_round_trip() {
        let output = CredentialProcessOutput {
            version: 1,
            access_key_id: "AKIAEXAMPLE".to_string(),
            secret_access_key: SecretString::from("secret-key".to_string()),
            session_token: SecretString::from("session-token".to_string()),
            expiration: "2024-01-14T18:00:00Z".to_string(),
        };

        let data = output.to_json();

        // These are the exact field names used by exec.rs and codecommit.rs
        // to extract credentials from cache
        assert_eq!(
            data.get("AccessKeyId").unwrap().as_str().unwrap(),
            "AKIAEXAMPLE"
        );
        assert_eq!(
            data.get("SecretAccessKey").unwrap().as_str().unwrap(),
            "secret-key"
        );
        assert_eq!(
            data.get("SessionToken").unwrap().as_str().unwrap(),
            "session-token"
        );
        assert_eq!(
            data.get("Expiration").unwrap().as_str().unwrap(),
            "2024-01-14T18:00:00Z"
        );
    }
}
