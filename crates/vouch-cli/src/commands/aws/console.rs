// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch aws console` — open the AWS Management Console via federation.
//!
//! Uses the custom identity broker flow described in the AWS documentation:
//! <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html>

use anyhow::{Context, Result};
use secrecy::ExposeSecret;
use serde::Deserialize;

use crate::integrations::aws;

/// Arguments for `vouch aws console`.
#[derive(clap::Args)]
pub(crate) struct ConsoleArgs {
    /// AWS IAM role ARN to assume (auto-detected from ~/.aws/config
    /// if not specified).
    #[arg(long)]
    pub role: Option<String>,
}

/// Response from the AWS federation `getSigninToken` action.
#[derive(Deserialize)]
struct SigninTokenResponse {
    #[serde(rename = "SigninToken")]
    signin_token: String,
}

/// Run `vouch aws console`.
pub(crate) async fn run(server: &str, args: ConsoleArgs) -> Result<()> {
    // 1. Resolve role ARN
    let role_arn = match args.role {
        Some(r) => r,
        None => aws::get_local_aws_role().ok_or_else(|| {
            anyhow::anyhow!(
                "AWS not configured. Run 'vouch setup aws --role \
                 <role-arn>' first, or specify --role."
            )
        })?,
    };

    // 2. Determine partition and federation endpoints from role ARN
    let partition =
        vouch_common::aws::Partition::from_arn(&role_arn).context("invalid role ARN")?;
    let federation_url = partition.federation_endpoint()?;
    let console_url = partition.console_url()?;

    // 3. Resolve region (for STS call)
    let profile_name = aws::resolve_profile(None).unwrap_or_default();
    let region = match aws::resolve_region(None, &profile_name) {
        Ok(r) => r,
        Err(_) => {
            let default = partition.default_sts_region();
            tracing::debug!("no region configured, defaulting to {default}");
            default.to_string()
        }
    };

    // 4. Exchange Vouch session for STS credentials.
    //    Uses exchange_for_sts_credentials directly to keep
    //    SecretAccessKey/SessionToken as SecretString until
    //    serialization.
    let result = crate::commands::credential::aws::exchange_for_sts_credentials(
        server,
        &role_arn,
        &region,
        "vouch-console",
        None,
    )
    .await
    .context("failed to get AWS credentials")?;

    let creds = &result.credentials;

    // 5. Build federation session JSON — expose secrets only here
    let session_encoded = serde_json::to_string(&serde_json::json!({
        "sessionId": creds.access_key_id,
        "sessionKey": creds.secret_access_key.expose_secret(),
        "sessionToken": creds.session_token.expose_secret(),
    }))
    .context("failed to serialize session JSON")?;

    // 6. POST to federation endpoint for a signin token
    let resp = result
        .http_client
        .post(federation_url)
        .form(&[("Action", "getSigninToken"), ("Session", &session_encoded)])
        .send()
        .await
        .context("failed to request signin token")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("federation getSigninToken failed ({status}): {body}");
    }

    let token_resp: SigninTokenResponse = resp
        .json()
        .await
        .context("failed to parse signin token response")?;

    // 7. Construct login URL using url::Url for safe encoding
    let mut login_url =
        url::Url::parse(federation_url).context("invalid federation endpoint URL")?;
    login_url
        .query_pairs_mut()
        .append_pair("Action", "login")
        .append_pair("Issuer", server)
        .append_pair("Destination", console_url)
        .append_pair("SigninToken", &token_resp.signin_token);

    // 8. Open browser (print URL only as fallback)
    let login_str = login_url.as_str();
    match open::that(login_str) {
        Ok(()) => {
            println!("Opening AWS Console...");
        }
        Err(e) => {
            tracing::debug!("failed to open browser: {e}");
            println!("{login_str}");
            eprintln!(
                "Could not open browser automatically. \
                 Open the URL above in your browser."
            );
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_signin_token_response_deserialize() {
        let json = r#"{"SigninToken": "abc123"}"#;
        let resp: SigninTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.signin_token, "abc123");
    }

    #[test]
    fn test_login_url_construction() {
        let mut login_url = url::Url::parse("https://signin.aws.amazon.com/federation").unwrap();
        login_url
            .query_pairs_mut()
            .append_pair("Action", "login")
            .append_pair("Issuer", "https://vouch.example.com")
            .append_pair("Destination", "https://console.aws.amazon.com/")
            .append_pair("SigninToken", "tok-123");

        let s = login_url.as_str();
        assert!(s.starts_with("https://signin.aws.amazon.com/federation?"));
        assert!(s.contains("Action=login"));
        assert!(s.contains("Issuer=https%3A%2F%2Fvouch.example.com"));
        assert!(s.contains("Destination=https%3A%2F%2Fconsole.aws.amazon.com%2F"));
        assert!(s.contains("SigninToken=tok-123"));
    }
}
