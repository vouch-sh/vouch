// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS STS (Security Token Service) utilities.
//!
//! Provides shared types and functions for calling AWS STS, with sensitive
//! credential fields protected using `SecretString`.

use anyhow::{Context, Result};
use jiff::Timestamp;
use secrecy::SecretString;
use vouch_cli::{tr, tr_args};

use crate::exit_code::CliError;
pub(crate) use vouch_common::aws::Arn;
use vouch_common::aws::Partition;

/// Parse and validate an IAM role ARN.
///
/// Format: `arn:{partition}:iam::{account}:role/{name}`
///
/// # Errors
///
/// Returns an error if the ARN format is invalid, the partition
/// is unrecognized, or the resource is not an IAM role.
pub(crate) fn parse_role_arn(arn: &str) -> Result<Arn> {
    let parsed =
        Arn::parse(arn).map_err(|e| anyhow::anyhow!(tr_args!("err-", e = e.to_string())))?;

    if !parsed.is_iam_role() {
        return Err(CliError::ConfigError(format!(
            "Invalid role ARN format: {arn}\n\
             Expected: arn:<partition>:iam::<account-id>:role/<role-name>\n\
             Example:  arn:aws:iam::123456789012:role/MyRole"
        ))
        .into());
    }

    Ok(parsed)
}

/// AWS STS temporary credentials.
///
/// Sensitive fields (`secret_access_key`, `session_token`) use `SecretString`
/// for memory protection and automatic zeroing on drop.
pub(crate) struct StsCredentials {
    pub access_key_id: String,
    pub secret_access_key: SecretString,
    pub session_token: SecretString,
    pub expiration: Timestamp,
}

impl std::fmt::Debug for StsCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StsCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field("session_token", &"[REDACTED]")
            .field("expiration", &self.expiration)
            .finish()
    }
}

/// Parameters for `AssumeRoleWithWebIdentity`.
///
/// Session tags and transitive tag keys are embedded in the JWT via the
/// `https://aws.amazon.com/tags` claim (set server-side). AWS extracts
/// them during the call and logs them as `principalTags` in CloudTrail.
/// Tags must NOT also be passed as STS API parameters — AWS rejects
/// requests that include both.
///
/// Similarly, `SourceIdentity` is extracted by AWS from the JWT's
/// `https://aws.amazon.com/source_identity` claim.
pub(crate) struct WebIdentityRequest<'a> {
    pub http_client: &'a reqwest::Client,
    pub role_arn: &'a str,
    pub role_session_name: &'a str,
    pub web_identity_token: &'a str,
    pub region: &'a str,
    pub domain_suffix: &'a str,
    /// Optional AWS managed policy names to attach as session policies.
    /// Names are resolved to partition-appropriate ARNs automatically
    /// (e.g., "ReadOnlyAccess" → `arn:{partition}:iam::aws:policy/ReadOnlyAccess`).
    /// Effective permissions = role policy ∩ session policy (intersection).
    pub session_policy_names: &'a [&'a str],
    /// Optional inline session policy (AWS IAM policy document).
    /// Applied in addition to managed policies. Effective permissions =
    /// role policy ∩ managed policies ∩ inline policy.
    pub session_policy: Option<&'a serde_json::Value>,
}

/// Call AWS STS `AssumeRoleWithWebIdentity`.
///
/// Uses regional STS endpoints to support all AWS partitions
/// (commercial, China, GovCloud, EU Sovereign Cloud).
pub(crate) async fn assume_role_with_web_identity(
    req: WebIdentityRequest<'_>,
) -> Result<StsCredentials> {
    // Use regional STS endpoint for the appropriate partition
    let sts_url = format!("https://sts.{}.{}/", req.region, req.domain_suffix);

    let partition = Partition::from_region(req.region);

    let mut form_params: Vec<(String, String)> = vec![
        (
            "Action".to_string(),
            "AssumeRoleWithWebIdentity".to_string(),
        ),
        ("Version".to_string(), "2011-06-15".to_string()),
        ("RoleArn".to_string(), req.role_arn.to_string()),
        (
            "RoleSessionName".to_string(),
            req.role_session_name.to_string(),
        ),
        (
            "WebIdentityToken".to_string(),
            req.web_identity_token.to_string(),
        ),
    ];

    // Attach managed session policies (intersection model — only restricts).
    for (i, policy_name) in req.session_policy_names.iter().enumerate() {
        let arn = format!("arn:{}:iam::aws:policy/{}", partition.as_str(), policy_name);
        form_params.push((
            format!("PolicyArns.member.{}.arn", i.saturating_add(1)),
            arn,
        ));
    }

    // Attach inline session policy if provided.
    if let Some(policy) = req.session_policy {
        let policy_json = serde_json::to_string(policy).map_err(|e| {
            anyhow::anyhow!(tr_args!(
                "err-failed-serialize-session-policy",
                e = e.to_string()
            ))
        })?;
        form_params.push(("Policy".to_string(), policy_json));
    }

    let response = req
        .http_client
        .post(&sts_url)
        .form(&form_params)
        .send()
        .await
        .context(tr!("err-failed-call-aws-sts"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(
            CliError::NetworkError(format!("AWS STS returned error {status}: {body}")).into(),
        );
    }

    let body = response
        .text()
        .await
        .context(tr!("err-failed-read-sts-response"))?;

    parse_sts_xml_response(&body)
}

/// Parameters for the SigV4 `AssumeRole` call (role chaining).
pub(crate) struct AssumeRoleRequest<'a> {
    pub http_client: &'a reqwest::Client,
    pub role_arn: &'a str,
    pub role_session_name: &'a str,
    pub region: &'a str,
    /// Credentials from the prior `AssumeRoleWithWebIdentity` hop.
    pub source_creds: &'a StsCredentials,
    /// Optional AWS managed policy names to attach as session policies
    /// (see [`WebIdentityRequest::session_policy_names`]).
    pub session_policy_names: &'a [&'a str],
    /// Optional inline session policy
    /// (see [`WebIdentityRequest::session_policy`]).
    pub session_policy: Option<&'a serde_json::Value>,
    /// Optional Identity Center identity context
    /// (`awsAdditionalDetails.identityContext` from `CreateTokenWithIAM`),
    /// attached as `ProvidedContexts` so the resulting role session is
    /// identity-enhanced (`onBehalfOf` in CloudTrail, TIP user-based
    /// authorization). Only SigV4 `AssumeRole` accepts it —
    /// `AssumeRoleWithWebIdentity` does not (#623).
    pub identity_context: Option<&'a str>,
    /// Session duration in seconds (AWS accepts 900–3600 for chained
    /// sessions). Vending uses 3600; the entitlement assumability probe
    /// uses 900 since its session is dropped unused.
    pub duration_seconds: u32,
}

/// Call AWS STS `AssumeRole` using SigV4-signed form POST.
///
/// Used for role chaining: assumes a target role using credentials
/// from a prior `AssumeRoleWithWebIdentity` call.
pub(crate) async fn assume_role(req: AssumeRoleRequest<'_>) -> Result<StsCredentials> {
    use crate::integrations::aws::sigv4::sign_and_send_form_post;
    use vouch_common::aws::Partition;

    let partition = Partition::from_region(req.region);
    let domain_suffix = partition.dns_suffix();
    let endpoint = format!("https://sts.{}.{domain_suffix}/", req.region);

    // Bind owned values to variables first — sign_and_send_form_post takes &[(&str, &str)]
    // so all values must outlive the params slice. This pattern mirrors redshift.rs.
    let duration_str = req.duration_seconds.to_string();

    // Build managed policy ARNs with partition-appropriate prefixes.
    let policy_arns: Vec<String> = req
        .session_policy_names
        .iter()
        .map(|name| format!("arn:{}:iam::aws:policy/{}", partition.as_str(), name))
        .collect();

    let mut params: Vec<(&str, &str)> = vec![
        ("Action", "AssumeRole"),
        ("Version", "2011-06-15"),
        ("RoleArn", req.role_arn),
        ("RoleSessionName", req.role_session_name),
        ("DurationSeconds", &duration_str),
    ];

    // Attach managed session policies (intersection model — only restricts).
    let policy_keys: Vec<String> = (0..policy_arns.len())
        .map(|i| format!("PolicyArns.member.{}.arn", i.saturating_add(1)))
        .collect();
    for (key, arn) in policy_keys.iter().zip(policy_arns.iter()) {
        params.push((key.as_str(), arn.as_str()));
    }

    // Attach inline session policy if provided.
    let policy_json;
    if let Some(policy) = req.session_policy {
        policy_json = serde_json::to_string(policy).map_err(|e| {
            anyhow::anyhow!(tr_args!(
                "err-failed-serialize-session-policy",
                e = e.to_string()
            ))
        })?;
        params.push(("Policy", &policy_json));
    }

    // Attach the Identity Center identity context, if provided.
    if let Some(context) = req.identity_context {
        params.push((
            "ProvidedContexts.member.1.ProviderArn",
            "arn:aws:iam::aws:contextProvider/IdentityCenter",
        ));
        params.push(("ProvidedContexts.member.1.ContextAssertion", context));
    }

    let body = sign_and_send_form_post(
        req.http_client,
        &endpoint,
        "sts",
        req.region,
        req.source_creds,
        &params,
    )
    .await
    .context(tr!("err-failed-call-aws-sts-assumerole"))?;

    parse_sts_xml_response(&body)
}

/// Parameters for the SigV4 `GetScopedCredentials` call.
pub(crate) struct ScopedCredentialsRequest<'a> {
    pub http_client: &'a reqwest::Client,
    /// Region of the STS endpoint to call. The API is regional only: "The
    /// `GetScopedCredentials` API is not available on the AWS STS Global
    /// endpoint."
    pub region: &'a str,
    /// The temporary credentials to narrow. IAM user and root credentials
    /// are refused by AWS.
    pub source_creds: &'a StsCredentials,
    /// Scope-down policy document, at most
    /// [`SCOPE_DOWN_POLICY_MAX_CHARS`] characters.
    pub policy: &'a str,
    /// Free text AWS logs to CloudTrail with the call.
    pub description: &'a str,
}

/// AWS limit on the `Policy` parameter of `GetScopedCredentials`: the API
/// reference gives its length as 1 to 2048 characters.
///
/// <https://docs.aws.amazon.com/STS/latest/APIReference/API_GetScopedCredentials.html>
pub(crate) const SCOPE_DOWN_POLICY_MAX_CHARS: usize = 2048;

/// AWS limit on the `ScopedSessionDescription` parameter (2 to 256
/// characters).
const SCOPED_SESSION_DESCRIPTION_MAX_CHARS: usize = 256;

/// Call AWS STS `GetScopedCredentials` to narrow existing temporary
/// credentials with a scope-down policy.
///
/// The returned credentials keep the caller's session identity and expiry;
/// their permissions are the caller's intersected with `policy`. Used where
/// credentials come from an API that takes no session policy (Identity
/// Center permission sets, account access manager).
///
/// # Errors
///
/// Fails when the calling session lacks `sts:GetScopedCredentials`, when
/// AWS rejects the policy, or when the response does not report at least one
/// scope-down policy in effect. Callers must treat every error as "no
/// credentials": the unscoped input must never be handed out in its place.
///
/// <https://docs.aws.amazon.com/STS/latest/APIReference/API_GetScopedCredentials.html>
pub(crate) async fn get_scoped_credentials(
    req: ScopedCredentialsRequest<'_>,
) -> Result<StsCredentials> {
    use crate::integrations::aws::sigv4::sign_and_send_form_post;

    // AWS would reject it anyway; failing here names the cause.
    if req.policy.chars().count() > SCOPE_DOWN_POLICY_MAX_CHARS {
        anyhow::bail!(tr!("err-sts-scope-down-policy-too-long"));
    }

    let domain_suffix = Partition::from_region(req.region).dns_suffix();
    let endpoint = format!("https://sts.{}.{domain_suffix}/", req.region);
    let description = scoped_session_description(req.description);

    let params: Vec<(&str, &str)> = vec![
        ("Action", "GetScopedCredentials"),
        ("Version", "2011-06-15"),
        ("Policy", req.policy),
        ("ScopedSessionDescription", &description),
    ];

    let body = sign_and_send_form_post(
        req.http_client,
        &endpoint,
        "sts",
        req.region,
        req.source_creds,
        &params,
    )
    .await
    .context(tr!("err-failed-call-aws-sts-getscopedcredentials"))?;

    // Refuse a response that does not confirm the policy took effect, so a
    // success that scoped nothing can never be mistaken for a restriction.
    if scoped_policies_count(&body)? == 0 {
        anyhow::bail!(tr!("err-sts-scoped-policy-not-applied"));
    }

    parse_sts_xml_response(&body)
}

/// Fit free text to the `ScopedSessionDescription` constraints: characters
/// outside printable ASCII are dropped (the documented pattern also admits
/// tab, newline, and Latin-1, none of which a description needs), and the
/// result is capped at the documented maximum.
fn scoped_session_description(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(SCOPED_SESSION_DESCRIPTION_MAX_CHARS)
        .collect();
    // The documented minimum is 2 characters.
    if cleaned.chars().count() < 2 {
        return "vouch".to_string();
    }
    cleaned
}

/// Read `ScopedPoliciesCount` from a `GetScopedCredentials` response.
fn scoped_policies_count(xml: &str) -> Result<u32> {
    let doc = roxmltree::Document::parse(xml).context(tr!("err-failed-parse-sts-xml-response"))?;
    doc.descendants()
        .find(|n| n.has_tag_name("ScopedPoliciesCount"))
        .and_then(|n| n.text())
        .and_then(|t| t.trim().parse::<u32>().ok())
        .with_context(|| tr_args!("err-missing-sts-response", tag = "ScopedPoliciesCount"))
}

/// Parse AWS STS XML response using `roxmltree`.
fn parse_sts_xml_response(xml: &str) -> Result<StsCredentials> {
    let doc = roxmltree::Document::parse(xml).context(tr!("err-failed-parse-sts-xml-response"))?;

    // Find the Credentials element anywhere in the document
    let credentials_node = doc
        .descendants()
        .find(|n| n.has_tag_name("Credentials"))
        .context(tr!("err-missing-credentials-element-in-sts-response"))?;

    let extract_child_text = |parent: roxmltree::Node, tag: &str| -> Result<String> {
        parent
            .children()
            .find(|n| n.has_tag_name(tag))
            .and_then(|n| n.text())
            // Credential values never contain whitespace; a pretty-printed
            // response may wrap them in it.
            .map(|t| t.split_whitespace().collect::<String>())
            .filter(|t| !t.is_empty())
            .with_context(|| tr_args!("err-missing-sts-response", tag = tag))
    };

    let access_key_id = extract_child_text(credentials_node, "AccessKeyId")?;
    let secret_access_key = extract_child_text(credentials_node, "SecretAccessKey")?;
    let session_token = extract_child_text(credentials_node, "SessionToken")?;
    let expiration_str = extract_child_text(credentials_node, "Expiration")?;
    let expiration = expiration_str.parse::<Timestamp>().with_context(|| {
        tr_args!(
            "err-failed-parse-sts-expiration",
            expiration_str = expiration_str
        )
    })?;

    Ok(StsCredentials {
        access_key_id,
        secret_access_key: SecretString::from(secret_access_key),
        session_token: SecretString::from(session_token),
        expiration,
    })
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use vouch_common::aws::Partition;

    // =========================================================================
    // Arn tests
    // =========================================================================

    #[test]
    fn test_parse_role_arn_valid() {
        let arn = parse_role_arn("arn:aws:iam::123456789012:role/MyRole").unwrap();
        assert_eq!(arn.partition, Partition::Aws);
        assert_eq!(arn.account.as_deref(), Some("123456789012"));
        assert_eq!(arn.resource, "role/MyRole");
    }

    #[test]
    fn test_parse_role_arn_china() {
        let arn = parse_role_arn("arn:aws-cn:iam::123456789012:role/MyRole").unwrap();
        assert_eq!(arn.partition, Partition::AwsCn);
    }

    #[test]
    fn test_parse_role_arn_govcloud() {
        let arn = parse_role_arn("arn:aws-us-gov:iam::123456789012:role/MyRole").unwrap();
        assert_eq!(arn.partition, Partition::AwsUsGov);
    }

    #[test]
    fn test_parse_role_arn_with_path() {
        let arn = parse_role_arn("arn:aws:iam::123456789012:role/path/to/MyRole").unwrap();
        assert_eq!(arn.resource, "role/path/to/MyRole");
    }

    #[test]
    fn test_parse_role_arn_invalid() {
        assert!(parse_role_arn("invalid").is_err());
        assert!(parse_role_arn("").is_err());
        assert!(parse_role_arn("arn:aws:s3:::my-bucket").is_err());
        assert!(parse_role_arn("arn:aws:iam::123456789012:user/MyUser").is_err());
        assert!(parse_role_arn("arn:aws:iam::123456789012:role/").is_err());
    }

    #[test]
    fn test_parse_role_arn_unknown_partition() {
        assert!(parse_role_arn("arn:unknown:iam::123456789012:role/MyRole").is_err());
    }

    // =========================================================================
    // STS XML parsing tests
    // =========================================================================

    #[test]
    fn test_parse_sts_xml_response_valid() {
        let xml = r#"
            <AssumeRoleWithWebIdentityResponse>
                <AssumeRoleWithWebIdentityResult>
                    <Credentials>
                        <AccessKeyId>AKIAIOSFODNN7EXAMPLE</AccessKeyId>
                        <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>
                        <SessionToken>FwoGZXIvYXdzEBYaDM...</SessionToken>
                        <Expiration>2024-01-15T18:30:45Z</Expiration>
                    </Credentials>
                </AssumeRoleWithWebIdentityResult>
            </AssumeRoleWithWebIdentityResponse>
        "#;

        let creds = parse_sts_xml_response(xml).expect("valid XML");
        assert_eq!(creds.access_key_id, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(
            creds.expiration,
            "2024-01-15T18:30:45Z".parse::<Timestamp>().unwrap()
        );

        use secrecy::ExposeSecret;
        assert_eq!(
            creds.secret_access_key.expose_secret(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        assert_eq!(creds.session_token.expose_secret(), "FwoGZXIvYXdzEBYaDM...");
    }

    #[test]
    fn test_parse_sts_xml_response_missing_access_key() {
        let xml = r#"
            <AssumeRoleWithWebIdentityResponse>
                <AssumeRoleWithWebIdentityResult>
                    <Credentials>
                        <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>
                        <SessionToken>FwoGZXIvYXdzEBYaDM...</SessionToken>
                        <Expiration>2024-01-15T18:30:45Z</Expiration>
                    </Credentials>
                </AssumeRoleWithWebIdentityResult>
            </AssumeRoleWithWebIdentityResponse>
        "#;

        let result = parse_sts_xml_response(xml);
        assert!(result.is_err());
        let err = result.expect_err("should fail with missing AccessKeyId");
        assert!(err.to_string().contains("AccessKeyId"));
    }

    #[test]
    fn test_credentials_debug_redacted() {
        let creds = StsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: SecretString::from("wJalrXUtnFEMI/K7MDENG".to_string()),
            session_token: SecretString::from("FwoGZXIvYXdzEBYaDM".to_string()),
            expiration: "2024-01-15T18:30:45Z".parse().unwrap(),
        };
        let debug = format!("{:?}", creds);
        assert!(!debug.contains("wJalrXUtnFEMI/K7MDENG"));
        assert!(!debug.contains("FwoGZXIvYXdzEBYaDM"));
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(debug.contains("2024-01-15T18:30:45"));
    }

    // =========================================================================
    // GetScopedCredentials
    // =========================================================================

    /// The sample response from the `GetScopedCredentials` API reference,
    /// including its line-wrapped `SessionToken`.
    const SCOPED_SAMPLE: &str = r#"
<GetScopedCredentialsResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetScopedCredentialsResult>
    <Credentials>
      <AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY</SecretAccessKey>
      <SessionToken>
       AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQW
       +scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==
      </SessionToken>
      <Expiration>2019-11-09T13:34:41Z</Expiration>
    </Credentials>
    <ScopedPoliciesCount>1</ScopedPoliciesCount>
    <SessionInfo>
      <ScopedSessionId>AROAEXAMPLEID:example-session</ScopedSessionId>
      <Arn>arn:aws:sts::123456789012:assumed-role/example-role/example-session</Arn>
    </SessionInfo>
    <SourceIdentity>example-source-identity</SourceIdentity>
  </GetScopedCredentialsResult>
  <ResponseMetadata>
    <RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c7</RequestId>
  </ResponseMetadata>
</GetScopedCredentialsResponse>"#;

    #[test]
    fn scoped_sample_response_parses_with_the_wrapped_token_joined() {
        use secrecy::ExposeSecret;

        let creds = parse_sts_xml_response(SCOPED_SAMPLE).unwrap();
        assert_eq!(creds.access_key_id, "ASIAIOSFODNN7EXAMPLE");
        assert_eq!(
            creds.session_token.expose_secret(),
            "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQW\
             +scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA=="
        );
        assert_eq!(scoped_policies_count(SCOPED_SAMPLE).unwrap(), 1);
    }

    #[test]
    fn scoped_policies_count_is_required() {
        let without = SCOPED_SAMPLE.replace("<ScopedPoliciesCount>1</ScopedPoliciesCount>", "");
        assert!(scoped_policies_count(&without).is_err());
        let zero = SCOPED_SAMPLE.replace(
            "<ScopedPoliciesCount>1</ScopedPoliciesCount>",
            "<ScopedPoliciesCount>0</ScopedPoliciesCount>",
        );
        assert_eq!(scoped_policies_count(&zero).unwrap(), 0);
    }

    #[test]
    fn scoped_session_description_fits_the_documented_constraints() {
        assert_eq!(
            scoped_session_description("vouch AI agent: claude-code/2.1.120/agent"),
            "vouch AI agent: claude-code/2.1.120/agent"
        );
        // Control characters and non-ASCII are dropped.
        assert_eq!(scoped_session_description("a\u{7}b\né"), "ab");
        // Too short after cleaning falls back to a fixed label.
        assert_eq!(scoped_session_description("\u{1}"), "vouch");
        assert_eq!(scoped_session_description(&"x".repeat(400)).len(), 256);
    }
}
