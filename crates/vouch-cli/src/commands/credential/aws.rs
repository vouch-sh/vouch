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
        WebIdentityRequest, assume_role_with_web_identity, parse_role_arn,
    };

    let StsRequest {
        server,
        role_arn,
        region,
        management_role,
        agent_source,
    } = req;

    // If caller didn't pre-resolve, resolve now from config. External callers
    // (eks, rds, etc.) pass None; `resolve_management_role_for` applies the
    // chain-if-different-role test so they get chaining for free.
    let resolved;
    let mgmt = match management_role {
        Some(m) => Some(m),
        None => {
            resolved = crate::config::Config::load()
                .ok()
                .map(|c| resolve_management_role_for(&c, role_arn, None))
                .transpose()?
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
    let policies = agent_session_policies(agent_source);

    let (chain_role, pin_role) = select_chain_and_pin(role_arn, mgmt);

    let (http_client, id_token_secret, session) =
        fetch_aws_oidc_token(server, agent_source, Some(pin_role)).await?;
    let id_token = id_token_secret.expose_secret();

    // Session tags travel inside the JWT (server-side `https://aws.amazon.com/tags`
    // claim); AWS extracts them during AssumeRoleWithWebIdentity and logs them as
    // principalTags, so they must NOT also be passed as STS API parameters.

    if let Some(mgmt_role_arn) = chain_role {
        // Chain through the management role, then assume the target role.
        let credentials = assume_role_via_management_chain(ChainInputs {
            http_client: &http_client,
            id_token,
            session: &session,
            role_arn,
            mgmt_role_arn,
            region,
            policies: &policies,
        })
        .await?;

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

/// Fetch a fresh OIDC ID token from the Vouch server and derive the STS
/// role-session name from its `sub` claim.
///
/// When `agent_source` is set, the DPoP source claim is attached so the server
/// embeds the AI-agent session tags. When `pin_role` is set, the server pins
/// the token to that role via the `https://aws.amazon.com/roles` claim and
/// STS rejects it for any other role — pass the exact ARN the subsequent
/// `AssumeRoleWithWebIdentity` call will use. Returns the HTTP client used
/// for the subsequent STS calls, the ID token, and the session name.
async fn fetch_aws_oidc_token(
    server: &str,
    agent_source: Option<&str>,
    pin_role: Option<&str>,
) -> Result<(reqwest::Client, SecretString, String)> {
    let mut client = VouchClient::new(server).await?;

    // Set DPoP source claim for agent attribution (tamperproof via DPoP signature).
    // Server extracts this to add AI-specific session tags to the JWT.
    if let Some(source) = agent_source {
        tracing::info!("AI agent detected ({source}), applying ReadOnlyAccess session policy");
        client.set_dpop_source(source);
    }

    let path = aws_token_path(pin_role)?;
    let token_response: OidcTokenResponse = client
        .get_authenticated(&path)
        .await
        .context("failed to get OIDC token from Vouch server")?;

    let http_client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to create HTTP client")?;

    let session = extract_sub_from_jwt(token_response.id_token.expose_secret())
        .context("server returned invalid OIDC token")?;

    Ok((http_client, token_response.id_token, session))
}

/// Decide role chaining and token pinning in one place, before the token is
/// fetched.
///
/// Returns `(chain_role, pin_role)`: `chain_role` is the management role to
/// hop through when it is configured and differs from the target, and
/// `pin_role` is the exact role the `AssumeRoleWithWebIdentity` call will
/// use — the management role when chaining, the target role otherwise. The
/// OIDC token must be pinned to `pin_role`; the second SigV4 `AssumeRole`
/// hop of a chain is not constrained by the roles claim.
fn select_chain_and_pin<'a>(
    role_arn: &'a str,
    mgmt: Option<&'a str>,
) -> (Option<&'a str>, &'a str) {
    let chain_role = mgmt.filter(|m| *m != role_arn);
    (chain_role, chain_role.unwrap_or(role_arn))
}

/// Build the AWS token endpoint path, appending `?role_arn=` when pinning.
///
/// The ARN is percent-encoded (it contains `:` and `/`); the HTTP message
/// signature covers `@query`, so the pin is tamperproof in transit.
fn aws_token_path(pin_role: Option<&str>) -> Result<String> {
    const TOKEN_PATH: &str = "/v1/credentials/aws/token";
    match pin_role {
        Some(role) => {
            let query = serde_urlencoded::to_string([("role_arn", role)])
                .context("failed to encode role_arn query parameter")?;
            Ok(format!("{TOKEN_PATH}?{query}"))
        }
        None => Ok(TOKEN_PATH.to_string()),
    }
}

/// Borrowed inputs to the two-hop management-role chain.
struct ChainInputs<'a> {
    http_client: &'a reqwest::Client,
    id_token: &'a str,
    session: &'a str,
    role_arn: &'a str,
    mgmt_role_arn: &'a str,
    region: &'a str,
    policies: &'a AgentSessionPolicies,
}

/// Assume the target role by chaining through a management role:
/// `AssumeRoleWithWebIdentity` into the management role (with an inline
/// STS-only policy when agent-restricted), then `AssumeRole` into the target.
async fn assume_role_via_management_chain(
    input: ChainInputs<'_>,
) -> Result<crate::integrations::aws::sts::StsCredentials> {
    use crate::integrations::aws::sts::{
        AssumeRoleRequest, WebIdentityRequest, assume_role, assume_role_with_web_identity,
        parse_role_arn,
    };

    let mgmt_arn = parse_role_arn(input.mgmt_role_arn)?;
    let mgmt_domain_suffix = mgmt_arn.partition.dns_suffix();

    let mgmt_credentials = assume_role_with_web_identity(WebIdentityRequest {
        http_client: input.http_client,
        role_arn: input.mgmt_role_arn,
        role_session_name: input.session,
        web_identity_token: input.id_token,
        region: input.region,
        domain_suffix: mgmt_domain_suffix,
        session_policy_names: &[],
        session_policy: input.policies.mgmt_hop_policy.as_ref(),
    })
    .await
    .context("failed to assume management role")?;

    assume_role(AssumeRoleRequest {
        http_client: input.http_client,
        role_arn: input.role_arn,
        role_session_name: input.session,
        region: input.region,
        source_creds: &mgmt_credentials,
        session_policy_names: input.policies.session_policy_names,
        session_policy: None,
        // Plumbed but not yet fed: populating it requires a CreateTokenWithIAM
        // call on this path, which is deferred (#623).
        identity_context: None,
    })
    .await
    .context("failed to assume target role via chaining")
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

/// Decide whether to chain through a management role for a target.
///
/// Returns `Some(management_role)` when the management role differs from the
/// target (same full-ARN comparison as the existing `mgmt.filter(|m| m != role_arn)`
/// at `exchange_for_sts_credentials`), or `None` for a direct assumption.
fn chain_if_different_role(
    org: &crate::config::AwsOrganization,
    target_role_arn: &str,
) -> Option<String> {
    (org.management_role != target_role_arn).then(|| org.management_role.clone())
}

/// Extract the AWS account ID segment from a role ARN.
///
/// Role ARNs have the form `arn:partition:iam::ACCOUNT:role/NAME`.
/// Returns `None` for any ARN that doesn't have a non-empty account field.
fn extract_account_from_arn(arn: &str) -> Option<&str> {
    arn.split(':').nth(4).filter(|s| !s.is_empty())
}

/// Resolve the management role ARN to chain through for a given target role.
///
/// - No organizations configured → `None` (direct `AssumeRoleWithWebIdentity`).
/// - One organization → use `chain_if_different_role` to decide.
/// - `via` supplied → match the org whose `management_role` equals the given full ARN
///   exactly; error if no match.
/// - Multiple orgs, no `via` → disambiguate by account ID: if the target role's
///   account matches exactly one org's management-role account, use that org.
///   Zero matches → `aws-err-no-org-covers-account`; multiple matches →
///   `aws-err-via-ambiguous`.
///
/// Returns `Err` if `via` matches no org, if no configured org covers the target
/// account, or if multiple orgs match the target account (true ambiguity).
pub(crate) fn resolve_management_role_for(
    vouch_config: &crate::config::Config,
    target_role_arn: &str,
    via: Option<&str>,
) -> Result<Option<String>> {
    let aws_cfg = match vouch_config.aws() {
        Some(cfg) if !cfg.organizations.is_empty() => cfg,
        _ => return Ok(None),
    };

    if let Some(via_role) = via {
        // Explicit --via: must match an org by its full management-role ARN.
        let org = aws_cfg
            .organizations
            .iter()
            .find(|o| o.management_role == via_role)
            .ok_or_else(|| {
                crate::exit_code::CliError::ConfigError(tr_args!(
                    "aws-err-via-not-found",
                    management_role = via_role.to_string()
                ))
            })?;
        return Ok(chain_if_different_role(org, target_role_arn));
    }

    // Single org: chain only when the management role differs from the target.
    if aws_cfg.organizations.len() == 1 {
        return Ok(aws_cfg
            .organizations
            .first()
            .and_then(|o| chain_if_different_role(o, target_role_arn)));
    }

    // Multiple orgs, no --via: disambiguate by matching the target account ID to
    // an org's management-role account. If exactly one org matches, use it.
    // Never silently pick an arbitrary org — wrong account is a silent security bug.
    let target_account = extract_account_from_arn(target_role_arn);
    if let Some(acct) = target_account {
        let matches: Vec<_> = aws_cfg
            .organizations
            .iter()
            .filter(|o| extract_account_from_arn(&o.management_role) == Some(acct))
            .collect();
        match matches.len() {
            1 => {
                return Ok(matches
                    .first()
                    .and_then(|o| chain_if_different_role(o, target_role_arn)));
            }
            0 => {
                // No org's management account matches the target account. The
                // target may be a member account reachable by chaining through a
                // configured org (--via), or an account no org covers (setup aws) —
                // config doesn't record member accounts, so the message offers both.
                return Err(crate::exit_code::CliError::ConfigError(tr_args!(
                    "aws-err-no-org-covers-account",
                    account = acct.to_string()
                ))
                .into());
            }
            _ => {
                return Err(
                    crate::exit_code::CliError::ConfigError(tr!("aws-err-via-ambiguous")).into(),
                );
            }
        }
    }
    Err(crate::exit_code::CliError::ConfigError(tr!("aws-err-via-ambiguous")).into())
}

/// Resolve the Identity Center instance config for credential issuance.
///
/// Returns the owning `AwsOrganization` alongside the `AwsIdentityCenter` so
/// callers always derive the management role from the same org as the IdC
/// instance, preventing cross-org mismatches.
///
/// - `idc_application_arn` provided → match by ARN (`None` if not found).
/// - Single org → use its IdC if present, `None` if absent.
/// - Multiple orgs, exactly one has IdC → use it (unambiguous).
/// - Multiple orgs, more than one has IdC, no hint → `Err(aws-err-idc-ambiguous)`.
/// - No org has IdC → `Ok(None)`.
pub(crate) fn resolve_identity_center<'a>(
    aws_cfg: &'a crate::config::AwsOrgsConfig,
    idc_application_arn: Option<&str>,
) -> Result<
    Option<(
        &'a crate::config::AwsOrganization,
        &'a crate::config::AwsIdentityCenter,
    )>,
> {
    if let Some(arn) = idc_application_arn {
        return Ok(aws_cfg.organizations.iter().find_map(|o| {
            o.identity_center
                .as_ref()
                .filter(|idc| idc.application_arn == arn)
                .map(|idc| (o, idc))
        }));
    }
    // Single org: use its IdC if present.
    if aws_cfg.organizations.len() == 1 {
        return Ok(aws_cfg
            .organizations
            .first()
            .and_then(|o| o.identity_center.as_ref().map(|idc| (o, idc))));
    }
    // Multiple orgs, no hint: error if more than one has IdC (ambiguous).
    // If exactly one has IdC it is unambiguous; if none have it, return None.
    let idc_count = aws_cfg
        .organizations
        .iter()
        .filter(|o| o.identity_center.is_some())
        .count();
    if idc_count > 1 {
        return Err(crate::exit_code::CliError::ConfigError(tr!("aws-err-idc-ambiguous")).into());
    }
    Ok(aws_cfg
        .organizations
        .iter()
        .find_map(|o| o.identity_center.as_ref().map(|idc| (o, idc))))
}

/// Obtain an IAM Identity Center access token via the trusted-token-issuer
/// (TTI) exchange.
///
/// Called by `credential aws --account/--permission-set`, `aws console`
/// (IdC path), and `setup aws --discover`. Blocks AI agents — permission-set
/// credentials cannot be downscoped — so caller credentials are always full
/// (no `ReadOnlyAccess` policy, no DPoP source tag).
///
/// 1. Fetch the RS256 AWS token and assume the management role via
///    `AssumeRoleWithWebIdentity` (full creds).
/// 2. Exchange the same token for an IdC access token via `CreateTokenWithIAM`.
pub(crate) async fn obtain_identity_center_token(
    http_client: &reqwest::Client,
    server: &str,
    management_role: &str,
    idc: &crate::config::AwsIdentityCenter,
) -> Result<secrecy::SecretString> {
    use crate::integrations::aws::sts::{WebIdentityRequest, assume_role_with_web_identity};
    use secrecy::ExposeSecret;

    // Block AI agents: GetRoleCredentials returns full permission-set access
    // that cannot be downscoped with inline session policies, and the
    // vouch:AccessType=ai tag does not reliably propagate through it.
    if detect_agent_source().is_some() {
        return Err(
            crate::exit_code::CliError::ConfigError(tr!("aws-err-agent-idc-unsupported")).into(),
        );
    }

    // Step 1: assume the management role with full (unrestricted) credentials.
    let region = crate::integrations::aws::resolve_region_with_fallback(management_role)?;
    let mgmt_arn = crate::integrations::aws::sts::parse_role_arn(management_role)?;
    let domain_suffix = mgmt_arn.partition.dns_suffix();

    // Deliberately unpinned (no `?role_arn=`): this one token is used both to
    // assume the management role AND as the jwt-bearer assertion for
    // CreateTokenWithIAM, and the roles-claim semantics are undefined for the
    // latter. Trust policies on IdC management roles must therefore not
    // require `sts:RoleAuthorizedByIdp`.
    let client = VouchClient::new(server).await?;
    let token_response: OidcTokenResponse = client
        .get_authenticated("/v1/credentials/aws/token")
        .await
        .context("failed to get OIDC token for management role")?;
    let id_token = token_response.id_token.expose_secret();
    let session = extract_sub_from_jwt(id_token).context("server returned invalid OIDC token")?;

    let caller_creds = assume_role_with_web_identity(WebIdentityRequest {
        http_client,
        role_arn: management_role,
        role_session_name: &session,
        web_identity_token: id_token,
        region: &region,
        domain_suffix,
        session_policy_names: &[],
        session_policy: None,
    })
    .await
    .context("failed to assume management role for IdC exchange")?;

    // Step 2: exchange the same RS256 token (the TTI assertion) for an IdC
    // access token. The identity context in the exchange is not needed on
    // this path — GetRoleCredentials mints permission-set credentials with
    // the identity context already embedded.
    let exchange = crate::integrations::aws::identity_center::create_token_with_iam(
        http_client,
        &idc.region,
        &idc.application_arn,
        id_token,
        &caller_creds,
    )
    .await?;
    Ok(exchange.access_token)
}

/// Get cached Identity Center credentials, fetching fresh ones if needed.
pub(crate) async fn get_idc_credentials(
    server: &str,
    account_id: &str,
    permission_set: &str,
    idc_application_arn: Option<&str>,
    via: Option<&str>,
) -> Result<serde_json::Value> {
    use crate::integrations::aws::sso_portal::get_role_credentials;
    use vouch_common::http::credential_client;

    // Block AI agents early (fast-fail before config load): GetRoleCredentials
    // returns full permission-set access that cannot be downscoped with inline
    // session policies, and the vouch:AccessType=ai tag does not propagate.
    if detect_agent_source().is_some() {
        return Err(
            crate::exit_code::CliError::ConfigError(tr!("aws-err-agent-idc-unsupported")).into(),
        );
    }

    let vouch_config = crate::config::Config::load()?;
    let aws_cfg = vouch_config.aws().ok_or_else(|| {
        crate::exit_code::CliError::ConfigError(tr!("aws-err-idc-not-configured"))
    })?;

    // `resolve_identity_center` returns the owning org+idc pair so the
    // management role always comes from the same org as the IdC instance.
    let (org, idc) = resolve_identity_center(aws_cfg, idc_application_arn)?.ok_or_else(|| {
        crate::exit_code::CliError::ConfigError(tr!("aws-err-idc-not-configured"))
    })?;

    // If --via is supplied it must match the owning org's management role;
    // cross-org pairings are rejected.
    if let Some(via_role) = via
        && via_role != org.management_role
    {
        return Err(crate::exit_code::CliError::ConfigError(tr_args!(
            "aws-err-via-not-found",
            management_role = via_role.to_string()
        ))
        .into());
    }
    let management_role = org.management_role.clone();

    let idc = idc.clone();
    let cache_key = format!(
        "aws:idc:{}:{}:{}",
        idc.application_arn, account_id, permission_set
    );
    let account_id = account_id.to_string();
    let permission_set = permission_set.to_string();

    super::cache::get_or_fetch(&cache_key, "IdC credentials", || async move {
        let http_client = credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to create HTTP client")?;

        let idc_token =
            obtain_identity_center_token(&http_client, server, &management_role, &idc).await?;

        let creds = get_role_credentials(
            &http_client,
            &idc.region,
            &idc_token,
            &account_id,
            &permission_set,
        )
        .await?;

        let expiration = creds.expiration.to_string();
        let output = CredentialProcessOutput {
            version: 1,
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key,
            session_token: creds.session_token,
            expiration,
        };
        let expires_at = output.expiration.clone();
        Ok((output.to_json(), expires_at))
    })
    .await
}

/// Get cached AWS credentials, fetching fresh ones if needed.
///
/// Shared entry point for `vouch credential aws --role`, `vouch credential
/// codecommit`, and `vouch exec`. Resolves the management role once
/// and uses it for both the cache key and credential exchange.
pub(crate) async fn get_aws_credentials(server: &str, role_arn: &str) -> Result<serde_json::Value> {
    let vouch_config = crate::config::Config::load()?;
    let management_role = resolve_management_role_for(&vouch_config, role_arn, None)?;

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

/// Run the AWS credential command.
///
/// Dispatches to the STS path (`--role`) or the Identity Center path
/// (`--account` + `--permission-set`) and outputs credential_process JSON.
pub(crate) async fn run(
    server: &str,
    role: Option<&str>,
    account: Option<&str>,
    permission_set: Option<&str>,
    via: Option<&str>,
    idc_application: Option<&str>,
) -> Result<()> {
    let data = if let Some(role_arn) = role {
        // STS path: direct AssumeRoleWithWebIdentity (no management role) or
        // management-role chain (chain_if_different_role returns Some).
        let vouch_config = crate::config::Config::load()?;
        let management_role = resolve_management_role_for(&vouch_config, role_arn, via)?;

        let agent_source = detect_agent_source();
        let cache_key = build_cache_key(
            role_arn,
            management_role.as_deref(),
            agent_source.as_deref(),
        );
        let mgmt = management_role;
        let agent = agent_source;
        super::cache::get_or_fetch(&cache_key, "AWS credentials", || async move {
            let output =
                fetch_and_assume(server, role_arn, mgmt.as_deref(), agent.as_deref()).await?;
            let expires_at = output.expiration.clone();
            Ok((output.to_json(), expires_at))
        })
        .await?
    } else {
        // Identity Center path
        let acct = account.context("--account is required for Identity Center path")?;
        let ps = permission_set.context("--permission-set is required for Identity Center path")?;
        get_idc_credentials(server, acct, ps, idc_application, via).await?
    };

    let json = serde_json::to_string(&data).context("failed to serialize credentials")?;
    // Machine-readable JSON output: stays English (consumed by AWS CLI).
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

/// Process-wide lock used by tests that mutate `CLAUDECODE` (or other agent-
/// detection env vars). Acquired before `set_var` and held until `remove_var`
/// so parallel test threads cannot observe each other's env mutations.
///
/// `tokio::sync::Mutex` is used so the guard can be held across `.await`
/// points without triggering `await_holding_lock`; `std::sync::Mutex` would
/// also block a tokio thread and trip the workspace lint.
#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
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

    /// Direct flow: no management role means no chaining and the pin is the
    /// target role itself.
    #[test]
    fn test_select_chain_and_pin_direct() {
        let target = "arn:aws:iam::111122223333:role/Target";
        assert_eq!(select_chain_and_pin(target, None), (None, target));
    }

    /// Chained flow: the pin must be the management role — the role actually
    /// passed to AssumeRoleWithWebIdentity.
    #[test]
    fn test_select_chain_and_pin_chained() {
        let target = "arn:aws:iam::111122223333:role/Target";
        let mgmt = "arn:aws:iam::444455556666:role/Management";
        assert_eq!(select_chain_and_pin(target, Some(mgmt)), (Some(mgmt), mgmt));
    }

    /// Management role equal to the target collapses to the direct flow,
    /// pinned to the target.
    #[test]
    fn test_select_chain_and_pin_mgmt_equals_target() {
        let target = "arn:aws:iam::111122223333:role/Target";
        assert_eq!(select_chain_and_pin(target, Some(target)), (None, target));
    }

    /// The role ARN is percent-encoded in the query string (`:` and `/`
    /// are reserved characters).
    #[test]
    fn test_aws_token_path_encodes_role_arn() {
        let path = aws_token_path(Some("arn:aws:iam::111122223333:role/Example")).unwrap();
        assert_eq!(
            path,
            "/v1/credentials/aws/token?role_arn=arn%3Aaws%3Aiam%3A%3A111122223333%3Arole%2FExample"
        );
    }

    /// No pin requested → bare path, identical to the pre-pinning request
    /// shape (backwards compatible with older servers).
    #[test]
    fn test_aws_token_path_without_pin() {
        assert_eq!(aws_token_path(None).unwrap(), "/v1/credentials/aws/token");
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

    // --- extract_account_from_arn -------------------------------------------------

    #[test]
    fn extract_account_parses_standard_role_arn() {
        assert_eq!(
            extract_account_from_arn("arn:aws:iam::123456789012:role/Admin"),
            Some("123456789012")
        );
    }

    #[test]
    fn extract_account_parses_govcloud_role_arn() {
        assert_eq!(
            extract_account_from_arn("arn:aws-us-gov:iam::999000111222:role/Ops"),
            Some("999000111222")
        );
    }

    #[test]
    fn extract_account_returns_none_for_malformed_arn() {
        assert_eq!(extract_account_from_arn("not-an-arn"), None);
    }

    // --- resolve_management_role_for ---------------------------------------------

    fn make_config(management_roles: &[&str]) -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        for mgmt in management_roles {
            cfg.append_aws_org(crate::config::AwsOrganization {
                management_role: (*mgmt).to_string(),
                identity_center: None,
            });
        }
        cfg
    }

    #[test]
    fn resolve_no_orgs_returns_none() {
        let cfg = crate::config::Config::default();
        let result = resolve_management_role_for(&cfg, "arn:aws:iam::111:role/Target", None);
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn resolve_single_org_same_arn_returns_none() {
        // Management role == target → direct assume, no chain.
        let mgmt = "arn:aws:iam::111:role/Mgmt";
        let cfg = make_config(&[mgmt]);
        let result = resolve_management_role_for(&cfg, mgmt, None);
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn resolve_single_org_different_arn_returns_management_role() {
        let mgmt = "arn:aws:iam::111:role/Mgmt";
        let target = "arn:aws:iam::222:role/Target";
        let cfg = make_config(&[mgmt]);
        let result = resolve_management_role_for(&cfg, target, None);
        assert_eq!(result.unwrap().as_deref(), Some(mgmt));
    }

    #[test]
    fn resolve_via_matches_exact_arn() {
        let mgmt1 = "arn:aws:iam::111:role/Mgmt1";
        let mgmt2 = "arn:aws:iam::222:role/Mgmt2";
        let target = "arn:aws:iam::333:role/Target";
        let cfg = make_config(&[mgmt1, mgmt2]);
        let result = resolve_management_role_for(&cfg, target, Some(mgmt2));
        assert_eq!(result.unwrap().as_deref(), Some(mgmt2));
    }

    #[test]
    fn resolve_via_not_found_returns_error() {
        let mgmt = "arn:aws:iam::111:role/Mgmt";
        let cfg = make_config(&[mgmt]);
        let result = resolve_management_role_for(
            &cfg,
            "arn:aws:iam::333:role/T",
            Some("arn:aws:iam::999:role/Unknown"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn resolve_multi_org_account_disambiguates() {
        // Two orgs in different accounts; target is in org1's account.
        let mgmt1 = "arn:aws:iam::111:role/Mgmt1";
        let mgmt2 = "arn:aws:iam::222:role/Mgmt2";
        // Target is in account 111 — matches mgmt1.
        let target = "arn:aws:iam::111:role/Target";
        let cfg = make_config(&[mgmt1, mgmt2]);
        let result = resolve_management_role_for(&cfg, target, None);
        // mgmt1 != target → chain through mgmt1.
        assert_eq!(result.unwrap().as_deref(), Some(mgmt1));
    }

    #[test]
    fn resolve_multi_org_no_match_returns_no_coverage_error() {
        // Two orgs; target account matches neither management account. The target
        // may be a member account reachable via --via, so the message names the
        // account and recommends --via (with setup aws as the fallback).
        let mgmt1 = "arn:aws:iam::111:role/Mgmt1";
        let mgmt2 = "arn:aws:iam::222:role/Mgmt2";
        let target = "arn:aws:iam::333:role/Target";
        let cfg = make_config(&[mgmt1, mgmt2]);
        let err = resolve_management_role_for(&cfg, target, None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("333"),
            "no-coverage error should name the target account 333: {msg}"
        );
        assert!(
            msg.contains("--via"),
            "no-coverage error should recommend --via for member-account targets: {msg}"
        );
    }

    #[test]
    fn resolve_multi_org_both_match_returns_ambiguous_error() {
        // Two orgs in the SAME account; target in that account → true ambiguity,
        // so the error tells the user to disambiguate with --via.
        let mgmt1 = "arn:aws:iam::111:role/Mgmt1";
        let mgmt2 = "arn:aws:iam::111:role/Mgmt2";
        let target = "arn:aws:iam::111:role/Target";
        let cfg = make_config(&[mgmt1, mgmt2]);
        let err = resolve_management_role_for(&cfg, target, None).unwrap_err();
        assert!(
            err.to_string().contains("--via"),
            "true ambiguity should tell the user to specify --via: {err}"
        );
    }

    // --- resolve_identity_center -----------------------------------------------

    /// Fixture: build a Config with IdC-aware orgs.
    /// Each entry is `(management_role_arn, Option<(app_arn, region)>)`.
    fn make_idc_config(orgs: &[(&str, Option<(&str, &str)>)]) -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        for (mgmt, idc_opt) in orgs {
            cfg.append_aws_org(crate::config::AwsOrganization {
                management_role: (*mgmt).to_string(),
                identity_center: idc_opt.map(|(arn, region)| crate::config::AwsIdentityCenter {
                    application_arn: arn.to_string(),
                    region: region.to_string(),
                }),
            });
        }
        cfg
    }

    const MGMT1: &str = "arn:aws:iam::111:role/Mgmt1";
    const MGMT2: &str = "arn:aws:iam::222:role/Mgmt2";
    const APP1: &str = "arn:aws:sso::111:application/ssoins-x/apl-a";
    const APP2: &str = "arn:aws:sso::222:application/ssoins-y/apl-b";

    #[test]
    fn idc_explicit_arn_returns_owning_org_and_idc() {
        // Two orgs both have IdC; explicit ARN picks the matching one.
        let cfg = make_idc_config(&[
            (MGMT1, Some((APP1, "us-east-1"))),
            (MGMT2, Some((APP2, "eu-west-1"))),
        ]);
        let aws_cfg = cfg.aws().unwrap();
        let (org, idc) = resolve_identity_center(aws_cfg, Some(APP2))
            .unwrap()
            .unwrap();
        assert_eq!(org.management_role, MGMT2);
        assert_eq!(idc.application_arn, APP2);
    }

    #[test]
    fn idc_explicit_arn_no_match_returns_none() {
        let cfg = make_idc_config(&[(MGMT1, Some((APP1, "us-east-1")))]);
        let aws_cfg = cfg.aws().unwrap();
        let result =
            resolve_identity_center(aws_cfg, Some("arn:aws:sso::999:application/unknown")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn idc_single_org_with_idc_returns_pair() {
        let cfg = make_idc_config(&[(MGMT1, Some((APP1, "us-east-1")))]);
        let aws_cfg = cfg.aws().unwrap();
        let (org, idc) = resolve_identity_center(aws_cfg, None).unwrap().unwrap();
        assert_eq!(org.management_role, MGMT1);
        assert_eq!(idc.application_arn, APP1);
    }

    #[test]
    fn idc_single_org_without_idc_returns_none() {
        let cfg = make_idc_config(&[(MGMT1, None)]);
        let aws_cfg = cfg.aws().unwrap();
        let result = resolve_identity_center(aws_cfg, None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn idc_multi_org_exactly_one_idc_is_unambiguous() {
        // Only the first org has IdC; second has none. Must return the first org's pair.
        let cfg = make_idc_config(&[(MGMT1, Some((APP1, "us-east-1"))), (MGMT2, None)]);
        let aws_cfg = cfg.aws().unwrap();
        let (org, idc) = resolve_identity_center(aws_cfg, None).unwrap().unwrap();
        assert_eq!(org.management_role, MGMT1);
        assert_eq!(idc.application_arn, APP1);
    }

    #[test]
    fn idc_multi_org_two_idc_no_hint_errors_with_ambiguous() {
        // Both orgs have IdC and no --idc-application given → must error.
        let cfg = make_idc_config(&[
            (MGMT1, Some((APP1, "us-east-1"))),
            (MGMT2, Some((APP2, "eu-west-1"))),
        ]);
        let aws_cfg = cfg.aws().unwrap();
        let err = resolve_identity_center(aws_cfg, None).unwrap_err();
        assert!(
            err.downcast_ref::<crate::exit_code::CliError>().is_some(),
            "expected CliError, got: {err}"
        );
    }

    #[test]
    fn idc_multi_org_zero_idc_returns_none() {
        // Neither org has IdC configured.
        let cfg = make_idc_config(&[(MGMT1, None), (MGMT2, None)]);
        let aws_cfg = cfg.aws().unwrap();
        let result = resolve_identity_center(aws_cfg, None).unwrap();
        assert!(result.is_none());
    }

    // Pairing: the returned org always owns the resolved IdC instance.

    #[test]
    fn idc_pairing_management_role_comes_from_owning_org() {
        // orgA (MGMT1) has IdC; orgB (MGMT2) does not. The pair must be
        // (MGMT1, APP1) — never (MGMT2, APP1).
        let cfg = make_idc_config(&[(MGMT1, Some((APP1, "us-east-1"))), (MGMT2, None)]);
        let aws_cfg = cfg.aws().unwrap();
        let (org, idc) = resolve_identity_center(aws_cfg, None).unwrap().unwrap();
        assert_eq!(
            org.management_role, MGMT1,
            "management role must come from the org that owns the IdC instance, not a different org"
        );
        assert_eq!(idc.application_arn, APP1);
    }

    #[test]
    fn idc_explicit_arn_picks_owning_org_when_first_org_lacks_idc() {
        // orgA (MGMT1) has no IdC; orgB (MGMT2) has APP2.
        // Selecting APP2 must return MGMT2, not MGMT1.
        let cfg = make_idc_config(&[(MGMT1, None), (MGMT2, Some((APP2, "eu-west-1")))]);
        let aws_cfg = cfg.aws().unwrap();
        let (org, idc) = resolve_identity_center(aws_cfg, Some(APP2))
            .unwrap()
            .unwrap();
        assert_eq!(org.management_role, MGMT2);
        assert_eq!(idc.application_arn, APP2);
    }

    // Agent-block tests -------------------------------------------------------
    //
    // These set an env var to simulate an agent environment. The agent check
    // fires as the very first statement in each function, before any config
    // load or network I/O, so the tests do not need real server/config state.

    #[tokio::test]
    #[expect(
        unsafe_code,
        reason = "env mutation to trigger agent detection in an isolated test; var is restored after assertion"
    )]
    async fn agent_block_in_get_idc_credentials_fires_before_config_load() {
        let _guard = crate::commands::credential::aws::test_support::ENV_LOCK
            .lock()
            .await;
        // SAFETY: agent check is the first statement; Config::load is never reached.
        unsafe {
            std::env::set_var("CLAUDECODE", "1");
        }
        let result =
            get_idc_credentials("https://example.com", "111111111111", "Admin", None, None).await;
        // SAFETY: env var restored regardless of assertion outcome.
        unsafe {
            std::env::remove_var("CLAUDECODE");
        }
        let err = result.unwrap_err();
        assert!(
            matches!(
                err.downcast_ref::<crate::exit_code::CliError>(),
                Some(crate::exit_code::CliError::ConfigError(_))
            ),
            "expected ConfigError(aws-err-agent-idc-unsupported), got: {err}"
        );
    }

    #[tokio::test]
    #[expect(
        unsafe_code,
        reason = "env mutation to trigger agent detection in an isolated test; var is restored after assertion"
    )]
    async fn agent_block_in_obtain_identity_center_token_fires_before_network() {
        let _guard = crate::commands::credential::aws::test_support::ENV_LOCK
            .lock()
            .await;
        // SAFETY: agent check is the first statement; no disk or network I/O occurs.
        unsafe {
            std::env::set_var("CLAUDECODE", "1");
        }
        let http_client = reqwest::Client::new();
        let idc = crate::config::AwsIdentityCenter {
            application_arn: APP1.to_string(),
            region: "us-east-1".to_string(),
        };
        let result =
            obtain_identity_center_token(&http_client, "https://example.com", MGMT1, &idc).await;
        // SAFETY: env var restored regardless of assertion outcome.
        unsafe {
            std::env::remove_var("CLAUDECODE");
        }
        let err = result.unwrap_err();
        assert!(
            matches!(
                err.downcast_ref::<crate::exit_code::CliError>(),
                Some(crate::exit_code::CliError::ConfigError(_))
            ),
            "expected ConfigError(aws-err-agent-idc-unsupported), got: {err}"
        );
    }
}
