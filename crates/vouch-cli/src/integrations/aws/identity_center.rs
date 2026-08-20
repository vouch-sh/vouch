// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS IAM Identity Center trusted-token-issuer exchange.
//!
//! Implements `sso-oidc:CreateTokenWithIAM` with the `jwt-bearer` grant: a
//! Vouch-issued **RS256** JWT (the trusted token issuer's signed token) is
//! exchanged for an Identity Center access token. That token then drives the
//! SSO Portal (`ListAccounts`/`ListAccountRoles`/`GetRoleCredentials`) to reach
//! every account+permission-set the user is assigned to — no role chaining and
//! no per-role IAM trust policy.
//!
//! Unlike the device-authorization flow, this requires no interactive AWS
//! login: the user authenticates once with Vouch (FIDO2), and the management
//! role (assumed via `AssumeRoleWithWebIdentity`) is the SigV4 caller for the
//! exchange.

use anyhow::{Context, Result};
use secrecy::SecretString;
use serde::Deserialize;
use vouch_cli::tr;
use vouch_common::aws::Partition;

use super::sigv4::sign_and_send_json_post;
use super::sts::StsCredentials;

/// OAuth 2.0 JWT bearer grant type (RFC 7523).
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Subset of the `CreateTokenWithIAM` response we consume.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTokenResponse {
    /// The Identity Center access token (presented to the SSO Portal via the
    /// `x-amz-sso_bearer_token` header).
    access_token: SecretString,
    /// Present when the application has trusted identity propagation enabled.
    aws_additional_details: Option<AwsAdditionalDetails>,
}

/// The `awsAdditionalDetails` object of the `CreateTokenWithIAM` response.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AwsAdditionalDetails {
    /// STS identity context: the `ContextAssertion` for `ProvidedContexts`
    /// on a SigV4 `AssumeRole`, yielding an identity-enhanced role session
    /// (`onBehalfOf` in CloudTrail). Valid for the token's lifetime (~1h).
    identity_context: Option<String>,
}

/// Result of the `CreateTokenWithIAM` exchange.
pub(crate) struct IdcTokenExchange {
    /// The Identity Center access token (SSO Portal bearer token).
    pub(crate) access_token: SecretString,
    /// STS identity context for `ProvidedContexts` on `AssumeRole`, when the
    /// application has trusted identity propagation enabled. The SSO Portal
    /// path does not need it — `GetRoleCredentials` mints permission-set
    /// credentials with the identity context already embedded.
    #[expect(
        dead_code,
        reason = "consumed when identity-context attachment on the chaining path lands (#623)"
    )]
    pub(crate) identity_context: Option<SecretString>,
}

/// Exchange a Vouch RS256 JWT for an IAM Identity Center access token via
/// `sso-oidc:CreateTokenWithIAM` (`jwt-bearer` grant).
///
/// `application_arn` is the customer-managed application's ARN (the `clientId`).
/// `assertion_jwt` is the RS256 token from `GET /v1/credentials/aws/token` —
/// the same token used for the management-role `AssumeRoleWithWebIdentity`.
/// `caller_creds` are the SigV4 caller credentials (the management role;
/// the application's resource policy must reference it to authorize
/// `sso-oauth:CreateTokenWithIAM`).
pub(crate) async fn create_token_with_iam(
    http_client: &reqwest::Client,
    region: &str,
    application_arn: &str,
    assertion_jwt: &str,
    caller_creds: &StsCredentials,
) -> Result<IdcTokenExchange> {
    let partition = Partition::from_region(region);
    let endpoint = partition.sso_oidc_endpoint(region);

    let body = serde_json::json!({
        "clientId": application_arn,
        "grantType": JWT_BEARER_GRANT,
        "assertion": assertion_jwt,
    });

    // CreateTokenWithIAM is POST /token?aws_iam=t, signed for the `sso-oauth`
    // service (SigV4). The `aws_iam=t` query param selects the IAM-authenticated
    // variant of CreateToken.
    let response = sign_and_send_json_post(
        http_client,
        &endpoint,
        "/token",
        &[("aws_iam", "t")],
        "sso-oauth",
        region,
        caller_creds,
        &body,
    )
    .await
    .context(tr!("err-createtokenwithiam-exchange-failed"))?;

    let parsed: CreateTokenResponse = serde_json::from_str(&response)
        .context(tr!("err-failed-parse-createtokenwithiam-response"))?;

    Ok(IdcTokenExchange {
        access_token: parsed.access_token,
        identity_context: parsed
            .aws_additional_details
            .and_then(|d| d.identity_context)
            .map(SecretString::from),
    })
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_create_token_response_deserialization() {
        // CreateTokenWithIAM returns additional fields (tokenType, expiresIn,
        // refreshToken, idToken) we ignore; only accessToken is required.
        let json = r#"{
            "accessToken": "ic-access-token-value",
            "tokenType": "Bearer",
            "expiresIn": 3600,
            "refreshToken": "ic-refresh-token",
            "idToken": "ic-id-token"
        }"#;

        let parsed: CreateTokenResponse = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(parsed.access_token.expose_secret(), "ic-access-token-value");
        assert!(
            parsed.aws_additional_details.is_none(),
            "identity context must be None when awsAdditionalDetails is absent"
        );
    }

    #[test]
    fn test_create_token_response_parses_identity_context() {
        let json = r#"{
            "accessToken": "ic-access-token-value",
            "tokenType": "Bearer",
            "expiresIn": 3600,
            "awsAdditionalDetails": {
                "identityContext": "context-assertion-value"
            }
        }"#;

        let parsed: CreateTokenResponse = serde_json::from_str(json).expect("valid JSON");
        let context = parsed
            .aws_additional_details
            .and_then(|d| d.identity_context)
            .expect("identityContext must be parsed");
        assert_eq!(context, "context-assertion-value");
    }

    #[test]
    fn test_create_token_response_tolerates_empty_additional_details() {
        // awsAdditionalDetails present but without identityContext.
        let json = r#"{
            "accessToken": "ic-access-token-value",
            "awsAdditionalDetails": {}
        }"#;

        let parsed: CreateTokenResponse = serde_json::from_str(json).expect("valid JSON");
        assert!(
            parsed
                .aws_additional_details
                .expect("awsAdditionalDetails must be parsed")
                .identity_context
                .is_none()
        );
    }
}
