// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS credential command.
//!
//! Obtains temporary AWS credentials using Vouch session and STS.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use vouch_cli::{tr, tr_args};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::client::VouchClient;
use crate::config::SsoSessionConfig;
use crate::integrations::aws::config::SsoSession;
use crate::integrations::aws::identity_center::create_token_with_iam;
use crate::integrations::aws::sso_portal::get_role_credentials;

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

/// Extract the domain portion of the `email` claim (e.g. `"acme.com"`) from a
/// JWT payload without signature verification.
///
/// Returns `None` when the token is malformed or carries no `email` claim (or an
/// address with no domain). Used by `vouch setup aws` to scope the generated
/// trust policy's subject to the caller's domain — read from the locally
/// resolved session token, with no additional server call.
pub(crate) fn extract_email_domain_from_jwt(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    let email = claims.get("email")?.as_str()?;
    let (_, domain) = email.rsplit_once('@')?;
    (!domain.is_empty()).then(|| domain.to_string())
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

/// Inputs to a single AWS STS credential exchange.
///
/// All fields are borrowed for the duration of the call. `management_role`,
/// when `Some`, triggers role chaining; `agent_source`, when `Some`, applies
/// AI-agent restrictions (`ReadOnlyAccess` session policy and the DPoP
/// source claim the server turns into `vouch:AccessType=ai` /
/// `vouch:Agent=<name>` principal tags). Contains no secrets.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StsRequest<'a> {
    pub(crate) server: &'a str,
    pub(crate) role_arn: &'a str,
    pub(crate) region: &'a str,
    pub(crate) management_role: Option<&'a str>,
    pub(crate) agent_source: Option<&'a str>,
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
pub(crate) async fn exchange_for_sts_credentials(req: StsRequest<'_>) -> Result<StsExchangeResult> {
    use crate::integrations::aws::sts::{
        WebIdentityRequest, assume_role, assume_role_with_web_identity, parse_role_arn,
    };

    let StsRequest {
        server,
        role_arn,
        region,
        management_role,
        agent_source,
    } = req;

    // The management role, when present, is passed explicitly by the caller
    // (chaining `--management-role`); `None` means a direct web-identity assume.
    let mgmt = management_role;

    let arn = parse_role_arn(role_arn)?;
    let domain_suffix = arn.partition.dns_suffix();

    // Apply AI-agent restrictions when the caller detected an agent context.
    // Detection must happen at the caller — and, for cached callers, before
    // the cache lookup — otherwise a cache hit would silently return
    // credentials minted in the wrong context (issue #398).
    let policies = agent_session_policies(agent_source);

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
            session_policy: policies.mgmt_hop_policy.as_ref(),
        })
        .await
        .context("failed to assume management role")?;

        let credentials = assume_role(
            &http_client,
            role_arn,
            &session,
            region,
            &mgmt_credentials,
            policies.session_policy_names,
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
        session_policy_names: policies.session_policy_names,
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

/// Session policies applied to STS calls, restricted when an AI coding
/// agent context is detected.
struct AgentSessionPolicies {
    /// Managed policy names attached to the issued credentials.
    session_policy_names: &'static [&'static str],
    /// Inline policy for the management-role hop, restricting it to only
    /// the STS actions needed for role chaining.
    mgmt_hop_policy: Option<serde_json::Value>,
}

/// Build the session policies for an exchange: unrestricted normally,
/// ReadOnlyAccess plus an STS-only management-hop policy when an AI agent
/// is detected.
fn agent_session_policies(agent_source: Option<&str>) -> AgentSessionPolicies {
    if agent_source.is_none() {
        return AgentSessionPolicies {
            session_policy_names: &[],
            mgmt_hop_policy: None,
        };
    }
    AgentSessionPolicies {
        session_policy_names: &["ReadOnlyAccess"],
        mgmt_hop_policy: Some(serde_json::json!({
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
        })),
    }
}

/// Get cached AWS credentials, fetching fresh ones if needed.
///
/// Shared entry point for `vouch credential aws`, `vouch credential
/// codecommit`, and `vouch exec`. Resolves the management role once
/// and uses it for both the cache key and credential exchange.
pub(crate) async fn get_aws_credentials(
    server: &str,
    role_arn: &str,
    management_role: Option<&str>,
) -> Result<serde_json::Value> {
    // The management role is passed explicitly (chaining `--management-role`);
    // a role that equals the target is a no-op hop and is dropped.
    let management_role = management_role
        .filter(|m| *m != role_arn)
        .map(str::to_string);

    // Detect agent context BEFORE the cache lookup. Folding the source into
    // the cache key ensures agent and non-agent invocations never share a
    // cached entry, which would otherwise hand the agent credentials minted
    // without ReadOnlyAccess / `vouch:AccessType=ai` tags (issue #398).
    let agent_source = detect_agent_source();
    let cache_key = build_cache_key(
        role_arn,
        management_role.as_deref(),
        agent_source.as_deref(),
    );

    let mgmt = management_role;
    let agent = agent_source;
    super::cache::get_or_fetch(&cache_key, "AWS credentials", || async move {
        let output = fetch_and_assume(server, role_arn, mgmt.as_deref(), agent.as_deref()).await?;
        let expires_at = output.expiration.clone();
        Ok((output.to_json(), expires_at))
    })
    .await
}

/// Run the AWS credential command (a non-interactive `credential_process` helper).
///
/// Serves all three access patterns from one command, selected by the target
/// form:
/// - `--role <arn>` (no `--account`) → STS `AssumeRoleWithWebIdentity`, chaining
///   through the management role when configured (patterns 1 & 2).
/// - `--account <id> --role <permission-set>` → IAM Identity Center portal
///   `GetRoleCredentials` (pattern 3).
///
/// Outputs AWS credential_process JSON to stdout.
pub(crate) async fn run(
    server: &str,
    role: &str,
    account: Option<&str>,
    sso_session: Option<&str>,
    management_role: Option<&str>,
) -> Result<()> {
    let data = if let Some(account_id) = account {
        // IdC portal: `role` is a permission-set name; `--sso-session` selects it.
        run_identity_center(server, account_id, role, sso_session).await?
    } else {
        // STS web-identity: `role` is a role ARN, optionally chained through
        // an explicit `--management-role`.
        get_aws_credentials(server, role, management_role).await?
    };
    let json = serde_json::to_string(&data).context("failed to serialize credentials")?;
    // Machine-readable JSON output: stays English (consumed by AWS CLI).
    println!("{json}");
    Ok(())
}

/// Pattern 3: issue credentials for a permission-set role via the IAM Identity
/// Center portal `GetRoleCredentials`.
async fn run_identity_center(
    server: &str,
    account_id: &str,
    role_name: &str,
    sso_session: Option<&str>,
) -> Result<serde_json::Value> {
    // Fail closed for coding agents: the SSO portal's `GetRoleCredentials` returns
    // the permission set's full access and accepts no inline session policy, so we
    // cannot apply the `ReadOnlyAccess` downscoping the STS `--role` path uses
    // (issue #398). Refuse rather than silently hand an agent unrestricted creds.
    if let Some(source) = detect_agent_source() {
        return Err(crate::exit_code::CliError::ConfigError(tr_args!(
            "aws-err-agent-idc-readonly-unsupported",
            source = source,
        ))
        .into());
    }

    let aws_config = crate::integrations::aws::config::AwsConfig::load()?;
    let session = crate::commands::aws::resolve_sso_session(&aws_config, sso_session)?;
    let region = session.region.clone();

    // Cache the credential_process output keyed by SSO session + target account +
    // permission set, mirroring the STS `--role` path: repeated AWS CLI refreshes
    // reuse credentials until expiry (instead of repeating web identity → RS256 →
    // CreateTokenWithIAM → GetRoleCredentials every time) and fall back to the
    // cached entry on network errors. Coding agents fail closed above and never
    // reach this cache.
    let cache_key = format!("aws:idc:{}:{account_id}:{role_name}", session.name);
    super::cache::get_or_fetch(&cache_key, "AWS credentials", || async move {
        let http_client = vouch_common::http::credential_client(&format!(
            "vouch-cli/{}",
            env!("CARGO_PKG_VERSION")
        ))
        .context("failed to create HTTP client")?;

        let bearer = resolve_bearer_token(server, &session, &region).await?;
        let creds = get_role_credentials(&http_client, &region, &bearer, account_id, role_name)
            .await
            .with_context(|| {
                format!("failed to get role credentials for account {account_id} role {role_name}")
            })?;

        let output = CredentialProcessOutput {
            version: 1,
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key,
            session_token: creds.session_token,
            expiration: creds.expiration.to_string(),
        };
        let expires_at = output.expiration.clone();
        Ok((output.to_json(), expires_at))
    })
    .await
}

/// Resolve an Identity Center bearer token for an SSO session via the
/// trusted-token-issuer (TTI) exchange.
///
/// Requires that the Vouch config has an `aws.sso_sessions.<name>` entry with
/// `identity_center_application_arn` set (written by `vouch setup aws`). If the
/// entry is missing, returns a [`crate::exit_code::CliError::ConfigError`] that
/// directs the user to run `vouch setup aws`.
///
/// Shared with `vouch setup aws --discover`, which uses it for IdC portal
/// account enumeration.
pub(crate) async fn resolve_bearer_token(
    server: &str,
    session: &SsoSession,
    region: &str,
) -> Result<SecretString> {
    let vouch_config = crate::config::Config::load()?;
    // Exact `[sso-session]`-name → key match, no fallback: a lone Vouch entry
    // under a mismatched key must not apply one org's config to another's session.
    let cfg = vouch_config
        .aws()
        .and_then(|a| a.sso_sessions.get(&session.name))
        .filter(|c| c.identity_center_application_arn.is_some())
        .ok_or_else(|| {
            crate::exit_code::CliError::ConfigError(tr!("aws-err-idc-not-configured"))
        })?;

    obtain_identity_center_token(server, cfg, region).await
}

/// Obtain an Identity Center access token via the trusted-token-issuer exchange.
///
/// 1. Assume the management role via `AssumeRoleWithWebIdentity` — the SigV4
///    caller for `CreateTokenWithIAM`. No AI-agent `ReadOnlyAccess` restriction
///    is applied here (the caller only needs `sso-oauth:CreateTokenWithIAM`,
///    which `ReadOnlyAccess` would strip); agent attribution still flows via
///    the RS256 token's session tags.
/// 2. Fetch the RS256 assertion token from Vouch (its `aud` is the Vouch server
///    URL), carrying agent attribution when running inside a coding agent.
/// 3. Exchange the assertion for an Identity Center access token.
async fn obtain_identity_center_token(
    server: &str,
    cfg: &SsoSessionConfig,
    region: &str,
) -> Result<SecretString> {
    let application_arn = cfg
        .identity_center_application_arn
        .as_deref()
        .context("identity_center_application_arn not configured")?;

    // Fail closed for coding agents: this hop assumes the management role as the
    // SigV4 caller for CreateTokenWithIAM and cannot be downscoped to
    // ReadOnlyAccess (that would strip sso-oauth:CreateTokenWithIAM). Like the
    // credential and console Identity Center paths, an agent must not reach it —
    // including via `setup aws --discover`, which has no terminal gate (#398).
    if let Some(source) = detect_agent_source() {
        return Err(crate::exit_code::CliError::ConfigError(tr_args!(
            "aws-err-agent-idc-readonly-unsupported",
            source = source,
        ))
        .into());
    }

    // Assume *this* session's management role directly via web identity — it is
    // the SigV4 caller for CreateTokenWithIAM. Set `management_role` equal to the
    // target so no chaining hop is added and the role is not re-resolved from the
    // first `~/.aws/config` session (which may belong to a different org).
    let mgmt = exchange_for_sts_credentials(StsRequest {
        server,
        role_arn: &cfg.management_role,
        region,
        management_role: Some(cfg.management_role.as_str()),
        agent_source: None,
    })
    .await
    .context("failed to assume management role for Identity Center token exchange")?;

    let client = VouchClient::new(server).await?;
    let assertion: OidcTokenResponse = client
        .get_authenticated("/v1/credentials/aws/sso/token")
        .await
        .context("failed to get Identity Center assertion token from Vouch server")?;

    create_token_with_iam(
        &mgmt.http_client,
        region,
        application_arn,
        assertion.id_token.expose_secret(),
        &mgmt.credentials,
    )
    .await
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

    let result = exchange_for_sts_credentials(StsRequest {
        server,
        role_arn,
        region: &region,
        management_role: mgmt_role,
        agent_source,
    })
    .await?;
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
