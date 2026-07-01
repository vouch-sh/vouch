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
//! Unlike the device-authorization flow in [`super::sso`], this requires no
//! interactive AWS login: the user authenticates once with Vouch (FIDO2), and
//! the management role (assumed via `AssumeRoleWithWebIdentity`) is the SigV4
//! caller for the exchange.

use anyhow::{Context, Result};
use secrecy::SecretString;
use serde::Deserialize;
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
    access_token: String,
}

/// Exchange a Vouch RS256 JWT for an IAM Identity Center access token via
/// `sso-oidc:CreateTokenWithIAM` (`jwt-bearer` grant).
///
/// `application_arn` is the customer-managed application's ARN (the `clientId`).
/// `assertion_jwt` is the RS256 token from
/// `GET /v1/credentials/aws/sso/token?audience=<aud>`. `caller_creds` are the
/// SigV4 caller credentials (the management role, assumed via web identity,
/// which must hold `sso-oauth:CreateTokenWithIAM`).
pub(crate) async fn create_token_with_iam(
    http_client: &reqwest::Client,
    region: &str,
    application_arn: &str,
    assertion_jwt: &str,
    caller_creds: &StsCredentials,
) -> Result<SecretString> {
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
    .context("CreateTokenWithIAM exchange failed")?;

    let parsed: CreateTokenResponse =
        serde_json::from_str(&response).context("failed to parse CreateTokenWithIAM response")?;

    Ok(SecretString::from(parsed.access_token))
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

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
        assert_eq!(parsed.access_token, "ic-access-token-value");
    }

    #[test]
    fn test_jwt_bearer_grant_constant() {
        // The grant type must match RFC 7523 exactly — AWS rejects any other value.
        assert_eq!(
            JWT_BEARER_GRANT,
            "urn:ietf:params:oauth:grant-type:jwt-bearer"
        );
    }
}
