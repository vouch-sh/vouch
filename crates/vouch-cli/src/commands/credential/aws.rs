// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS credential command.
//!
//! Obtains temporary AWS credentials using Vouch session and STS.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::client::VouchClient;

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

/// Minimal OIDC ID token claims.
///
/// Only the fields needed by the credential flow are deserialized here.
#[derive(Deserialize)]
struct JwtIdTokenClaims {
    /// OIDC Core Section 2: Subject Identifier (required).
    sub: String,
}

/// Extract the `sub` claim from a JWT payload without signature verification.
///
/// The token was just received over TLS from our server, so cryptographic
/// verification is unnecessary. Returns an error if the token is malformed
/// or missing the required `sub` claim — this indicates a server bug.
fn extract_sub_from_jwt(token: &str) -> Result<String> {
    let payload = token
        .split('.')
        .nth(1)
        .context("invalid JWT: expected 3 dot-separated parts")?;
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .context("invalid JWT: payload is not valid base64url")?;
    let claims: JwtIdTokenClaims = serde_json::from_slice(&decoded)
        .context("invalid JWT: payload missing required 'sub' claim")?;
    anyhow::ensure!(!claims.sub.is_empty(), "invalid JWT: 'sub' claim is empty");
    // AWS RoleSessionName max is 64 chars.
    Ok(claims.sub.chars().take(64).collect())
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
/// Returns the agent identifier (e.g., "claude-code/2.1.120/agent", "cursor")
/// if detected. These env vars are set by the agent's shell environment and
/// inherited by child processes including `credential_process` invocations.
///
/// `AI_AGENT` (the emerging cross-vendor convention) is forwarded verbatim —
/// agents like Claude Code v2.1.120+ self-identify with a slash-separated
/// `<name>/<version>/<context>` value, which we surface unchanged so the full
/// attribution reaches the AWS `vouch:Agent` session tag.
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
pub(crate) fn detect_agent_source() -> Option<String> {
    detect_agent_source_from(|k| std::env::var(k).ok())
}

/// Build the cache key for AWS STS credentials.
///
/// The agent source is folded into the key so that agent and non-agent
/// invocations (and invocations from different agents) never share a
/// cached entry — they receive credentials with different session
/// policies and principal tags. See issue #398.
fn build_cache_key(role_arn: &str, mgmt: Option<&str>, agent: Option<&str>) -> String {
    let suffix = match agent {
        Some(src) => format!(":agent:{src}"),
        None => String::new(),
    };
    match mgmt {
        Some(mgmt_role) => format!("aws:chain:{mgmt_role}:{role_arn}{suffix}"),
        None => format!("aws:{role_arn}{suffix}"),
    }
}

/// Inner implementation of [`detect_agent_source`] parameterised over the env
/// lookup, so unit tests can exercise the matrix without mutating the real
/// process environment (which is `unsafe` under edition 2024).
fn detect_agent_source_from<F>(get: F) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    // Emerging standard: https://github.com/agentsmd/agents.md/issues/136
    if let Some(val) = get("AGENT") {
        return Some(match val.as_str() {
            "amp" => "amp".to_string(),
            "goose" => "goose".to_string(),
            _ => "agent".to_string(),
        });
    }
    // Generic agent identifier (Vercel/Claude Code convention). Forwarded
    // verbatim so callers see the agent's self-reported identity (e.g.
    // "claude-code/2.1.120/agent"). An empty value falls through to the
    // vendor-specific checks below.
    if let Some(val) = get("AI_AGENT")
        && !val.is_empty()
    {
        return Some(val);
    }
    // Claude Code: https://code.claude.com/docs/en/env-vars
    if get("CLAUDECODE").is_some() || get("CLAUDE_CODE").is_some() {
        return Some("claude-code".to_string());
    }
    // Cursor: https://cursor.com/docs/agent/tools/terminal
    if get("CURSOR_TRACE_ID").is_some() || get("CURSOR_AGENT").is_some() {
        return Some("cursor".to_string());
    }
    // Gemini CLI: https://github.com/google-gemini/gemini-cli
    if get("GEMINI_CLI").is_some() {
        return Some("gemini".to_string());
    }
    // OpenAI Codex: https://github.com/openai/codex
    if get("CODEX_SANDBOX").is_some() || get("CODEX_THREAD_ID").is_some() {
        return Some("codex".to_string());
    }
    // GitHub Copilot: https://github.com/microsoft/vscode/issues/265446
    if get("COPILOT_MODEL").is_some() {
        return Some("copilot".to_string());
    }
    // Augment: https://docs.augmentcode.com/cli/reference
    if get("AUGMENT_AGENT").is_some() {
        return Some("augment".to_string());
    }
    // Antigravity
    if get("ANTIGRAVITY_AGENT").is_some() {
        return Some("antigravity".to_string());
    }
    // OpenCode
    if get("OPENCODE_CLIENT").is_some() {
        return Some("opencode".to_string());
    }
    // Cline: https://github.com/cline/cline/discussions/5366
    if get("CLINE_ACTIVE").is_some() {
        return Some("cline".to_string());
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
    management_role: Option<&str>,
    agent_source: Option<&str>,
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

    // Apply AI-agent restrictions when the caller detected an agent context.
    // Detection must happen at the caller — and, for cached callers, before
    // the cache lookup — otherwise a cache hit would silently return
    // credentials minted in the wrong context (issue #398).
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

    let session = extract_sub_from_jwt(id_token).context("server returned invalid OIDC token")?;

    let all_policies: &[&str] = agent_policies;

    // Inline session policy for the management role hop when an agent is
    // detected: restrict to only the STS actions needed for role chaining.
    let mgmt_hop_policy = if agent_source.is_some() {
        Some(serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "sts:AssumeRole",
                    "sts:TagSession",
                    "sts:SetSourceIdentity"
                ],
                "Resource": "*"
            }]
        }))
    } else {
        None
    };

    if let Some(mgmt_role_arn) = mgmt.filter(|m| *m != role_arn) {
        // Chain: AssumeRoleWithWebIdentity into management role, then AssumeRole into target.
        // Management hop gets an inline STS-only policy; final hop gets ReadOnlyAccess.
        let mgmt_arn = parse_role_arn(mgmt_role_arn)?;
        let mgmt_domain_suffix = mgmt_arn.partition.dns_suffix();

        let mgmt_credentials = assume_role_with_web_identity(WebIdentityRequest {
            http_client: &http_client,
            role_arn: mgmt_role_arn,
            role_session_name: &session,
            web_identity_token: id_token,
            region,
            domain_suffix: mgmt_domain_suffix,
            session_policy_names: &[],
            session_policy: mgmt_hop_policy.as_ref(),
        })
        .await
        .context("failed to assume management role")?;

        let credentials = assume_role(
            &http_client,
            role_arn,
            &session,
            region,
            &mgmt_credentials,
            all_policies,
            None,
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
        role_session_name: &session,
        web_identity_token: id_token,
        region,
        domain_suffix,
        session_policy_names: all_policies,
        session_policy: None,
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

    // Detect agent context BEFORE the cache lookup. Folding the source into
    // the cache key ensures agent and non-agent invocations never share a
    // cached entry, which would otherwise hand the agent credentials minted
    // without ReadOnlyAccess / `vouch:AccessType=ai` tags (issue #398).
    let agent_source = detect_agent_source();
    let cache_key = build_cache_key(role_arn, management_role.as_deref(), agent_source.as_deref());

    let mgmt = management_role;
    let agent = agent_source;
    super::cache::get_or_fetch(&cache_key, "AWS credentials", || async move {
        let output = fetch_and_assume(server, role_arn, mgmt.as_deref(), agent.as_deref()).await?;
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
    agent_source: Option<&str>,
) -> Result<CredentialProcessOutput> {
    let region = crate::integrations::aws::resolve_region_with_fallback(role_arn)?;

    let result =
        exchange_for_sts_credentials(server, role_arn, &region, mgmt_role, agent_source).await?;
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
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
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

    #[test]
    fn test_extract_sub_from_jwt() {
        let payload = serde_json::json!({
            "sub": "user@example.com",
            "email": "user@example.com",
            "iss": "https://vouch.example.com"
        });
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let token = format!("eyJhbGciOiJFUzI1NiJ9.{encoded}.fake-sig");

        assert_eq!(extract_sub_from_jwt(&token).unwrap(), "user@example.com");
    }

    #[test]
    fn test_extract_sub_from_jwt_without_email() {
        // sub is present but email is absent — should still succeed
        let payload = serde_json::json!({"sub": "user@example.com"});
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let token = format!("eyJhbGciOiJFUzI1NiJ9.{encoded}.fake");

        assert_eq!(extract_sub_from_jwt(&token).unwrap(), "user@example.com");
    }

    #[test]
    fn test_extract_sub_from_jwt_missing_sub() {
        let payload = serde_json::json!({"email": "user@example.com"});
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let token = format!("eyJhbGciOiJFUzI1NiJ9.{encoded}.fake");

        let err = extract_sub_from_jwt(&token).unwrap_err();
        assert!(
            err.to_string().contains("sub"),
            "error should mention 'sub': {err}"
        );
    }

    #[test]
    fn test_extract_sub_from_jwt_invalid_token() {
        assert!(extract_sub_from_jwt("not-a-jwt").is_err());
        assert!(extract_sub_from_jwt("").is_err());
        assert!(extract_sub_from_jwt("a.!!!.c").is_err());
    }

    #[test]
    fn test_extract_sub_from_jwt_empty_sub() {
        let payload = serde_json::json!({"sub": ""});
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let token = format!("eyJhbGciOiJFUzI1NiJ9.{encoded}.fake");

        let err = extract_sub_from_jwt(&token).unwrap_err();
        assert!(
            err.to_string().contains("empty"),
            "error should mention 'empty': {err}"
        );
    }

    #[test]
    fn test_extract_sub_from_jwt_truncates_to_64_chars() {
        // 72-char sub — must be truncated to 64 for AWS RoleSessionName limit
        let long_sub = "a".repeat(60) + "@example.com"; // 72 chars
        let payload = serde_json::json!({"sub": long_sub});
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let token = format!("eyJhbGciOiJFUzI1NiJ9.{encoded}.fake");

        let result = extract_sub_from_jwt(&token).unwrap();
        assert_eq!(result.len(), 64);
        assert_eq!(result, long_sub.chars().take(64).collect::<String>());
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

    /// Build an env-lookup closure backed by an in-memory map. Used to drive
    /// `detect_agent_source_from` without mutating the real process env (which
    /// is `unsafe` under edition 2024 and racy across parallel tests).
    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    /// Claude Code v2.1.120+ sets `AI_AGENT=<name>/<version>/<context>`. The
    /// full string flows verbatim into the AWS `vouch:Agent` session tag so
    /// CloudTrail records the agent name, version, and invocation context.
    #[test]
    fn test_detect_agent_ai_agent_slash_format_verbatim() {
        let got = detect_agent_source_from(env(&[("AI_AGENT", "claude-code/2.1.120/agent")]));
        assert_eq!(got.as_deref(), Some("claude-code/2.1.120/agent"));
    }

    /// Bare `AI_AGENT` values (e.g. Vercel's `v0`) are also forwarded verbatim.
    #[test]
    fn test_detect_agent_ai_agent_bare_value_verbatim() {
        let got = detect_agent_source_from(env(&[("AI_AGENT", "v0")]));
        assert_eq!(got.as_deref(), Some("v0"));
    }

    /// Empty `AI_AGENT` must not suppress vendor-specific signals: it falls
    /// through so a real `CLAUDECODE=1` is still detected.
    #[test]
    fn test_detect_agent_empty_ai_agent_falls_through_to_claudecode() {
        let got = detect_agent_source_from(env(&[("AI_AGENT", ""), ("CLAUDECODE", "1")]));
        assert_eq!(got.as_deref(), Some("claude-code"));
    }

    /// Empty `AI_AGENT` with no other agent vars returns `None`.
    #[test]
    fn test_detect_agent_empty_ai_agent_alone_returns_none() {
        let got = detect_agent_source_from(env(&[("AI_AGENT", "")]));
        assert_eq!(got, None);
    }

    /// No agent env vars set → `None`.
    #[test]
    fn test_detect_agent_no_env_returns_none() {
        let got = detect_agent_source_from(env(&[]));
        assert_eq!(got, None);
    }

    /// Existing vendor-specific detection still works for agents that don't
    /// set `AI_AGENT` (older Claude Code, etc.).
    #[test]
    fn test_detect_agent_claudecode_only() {
        let got = detect_agent_source_from(env(&[("CLAUDECODE", "1")]));
        assert_eq!(got.as_deref(), Some("claude-code"));
    }

    const ROLE: &str = "arn:aws:iam::123456789012:role/target";
    const MGMT: &str = "arn:aws:iam::123456789012:role/mgmt";

    /// Direct (no chaining), no agent: backward-compatible key format.
    #[test]
    fn test_build_cache_key_direct_no_agent() {
        assert_eq!(build_cache_key(ROLE, None, None), format!("aws:{ROLE}"));
    }

    /// Chained (management role), no agent: backward-compatible key format.
    #[test]
    fn test_build_cache_key_chain_no_agent() {
        assert_eq!(
            build_cache_key(ROLE, Some(MGMT), None),
            format!("aws:chain:{MGMT}:{ROLE}")
        );
    }

    /// Agent context produces a different key than no-agent — this is the
    /// invariant that prevents issue #398's cache-confusion bypass.
    #[test]
    fn test_build_cache_key_differs_when_agent_detected() {
        let without = build_cache_key(ROLE, None, None);
        let with = build_cache_key(ROLE, None, Some("claude-code"));
        assert_ne!(without, with);
    }

    /// Different agents must not share a cached entry: each agent's identity
    /// flows into the `vouch:Agent` principal tag, so the credentials are
    /// distinguishable in IAM and CloudTrail.
    #[test]
    fn test_build_cache_key_differs_between_agents() {
        let claude = build_cache_key(ROLE, None, Some("claude-code"));
        let cursor = build_cache_key(ROLE, None, Some("cursor"));
        assert_ne!(claude, cursor);
    }

    /// Same inputs → same key. Lock the format so accidental refactors that
    /// drop fields from the key are caught.
    #[test]
    fn test_build_cache_key_stable_for_same_agent() {
        let a = build_cache_key(ROLE, Some(MGMT), Some("claude-code"));
        let b = build_cache_key(ROLE, Some(MGMT), Some("claude-code"));
        assert_eq!(a, b);
        assert_eq!(a, format!("aws:chain:{MGMT}:{ROLE}:agent:claude-code"));
    }
}
