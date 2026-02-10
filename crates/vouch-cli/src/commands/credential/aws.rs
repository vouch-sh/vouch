// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS credential command.
//!
//! Obtains temporary AWS credentials using Vouch session and STS.

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::client::VouchClient;
use crate::integrations::aws::sts::{
    assume_role_with_web_identity, extract_partition_from_role_arn,
    get_default_region_for_partition, get_domain_suffix_for_partition,
};
use crate::session::get_user_email;

/// AWS credential process output format.
/// See: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
#[derive(Serialize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "PascalCase")]
struct CredentialProcessOutput {
    version: u32,
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
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
#[derive(Deserialize, zeroize::ZeroizeOnDrop)]
pub(crate) struct OidcTokenResponse {
    pub(crate) id_token: String,
}

impl std::fmt::Debug for OidcTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcTokenResponse")
            .field("id_token", &"[REDACTED]")
            .finish()
    }
}

/// Decode the payload of a JWT without verifying the signature.
///
/// Used by both `aws` and `docker` credential commands to extract claims
/// for STS session tags.
///
/// We trust our own server's tokens, and STS independently verifies them
/// against the OIDC provider's JWKS endpoint. This is only used to extract
/// claims for session tags.
pub(crate) fn decode_jwt_payload(token: &str) -> Result<serde_json::Value> {
    let mut parts = token.split('.');
    // Skip header
    let _header = parts.next().context("JWT missing header segment")?;
    let payload_b64 = parts.next().context("JWT missing payload segment")?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .context("failed to base64url-decode JWT payload")?;

    serde_json::from_slice(&payload_bytes).context("failed to parse JWT payload as JSON")
}

/// Build STS session tags from JWT claims.
///
/// Extracts `email` and `hd` (hosted domain) claims and maps them to
/// session tag key-value pairs for ABAC.
pub(crate) fn build_session_tags(claims: &serde_json::Value) -> Vec<(String, String)> {
    let mut tags = Vec::new();

    if let Some(email) = claims.get("email").and_then(serde_json::Value::as_str) {
        tags.push(("email".to_string(), email.to_string()));
    }

    if let Some(domain) = claims.get("hd").and_then(serde_json::Value::as_str) {
        tags.push(("domain".to_string(), domain.to_string()));
    }

    tags
}

/// Run the AWS credential command.
///
/// This command:
/// 1. Gets an OIDC ID token from the Vouch server
/// 2. Calls AWS STS `AssumeRoleWithWebIdentity`
/// 3. Outputs credentials in `credential_process` format
pub async fn run(server: &str, role_arn: &str, session_name: Option<&str>) -> Result<()> {
    let client = VouchClient::new(server)?;

    // Get OIDC token from Vouch server
    let token_response: OidcTokenResponse = client
        .get_authenticated("/v1/credentials/aws/token")
        .await
        .context("failed to get OIDC token from Vouch server")?;

    // Decode JWT to extract claims for session tags (ABAC)
    let tags = decode_jwt_payload(&token_response.id_token)
        .map(|claims| build_session_tags(&claims))
        .unwrap_or_default();

    // Determine region and domain suffix from role ARN partition
    let partition = extract_partition_from_role_arn(role_arn).unwrap_or("aws");
    let region = get_default_region_for_partition(partition);
    let domain_suffix = get_domain_suffix_for_partition(partition);

    // Call AWS STS AssumeRoleWithWebIdentity
    // Use email as default session name for CloudTrail visibility
    let email = get_user_email(server).await;
    let session = session_name.or(email.as_deref()).unwrap_or("vouch-session");
    let sts_response = assume_role_with_web_identity(
        role_arn,
        session,
        &token_response.id_token,
        region,
        domain_suffix,
        &tags,
    )
    .await
    .context("failed to assume AWS role")?;

    // Output in credential_process format
    let creds = &sts_response
        .assume_role_with_web_identity_result
        .credentials;
    let output = CredentialProcessOutput {
        version: 1,
        access_key_id: creds.access_key_id.clone(),
        secret_access_key: creds.secret_access_key.expose_secret().to_string(),
        session_token: creds.session_token.expose_secret().to_string(),
        expiration: creds.expiration.clone(),
    };

    let json = serde_json::to_string(&output).context("failed to serialize credentials")?;
    println!("{json}");

    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    /// Build a minimal JWT (header.payload.signature) from a JSON payload.
    fn make_jwt(payload: &serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(payload.to_string());
        let signature = URL_SAFE_NO_PAD.encode("fake-signature");
        format!("{header}.{payload}.{signature}")
    }

    #[test]
    fn test_decode_jwt_payload_valid() {
        let claims = serde_json::json!({
            "sub": "alice@example.com",
            "email": "alice@example.com",
            "hd": "example.com",
            "aud": "https://vouch.example.com",
            "iss": "https://vouch.example.com",
            "iat": 1700000000,
            "exp": 1700003600
        });
        let token = make_jwt(&claims);
        let decoded = decode_jwt_payload(&token).expect("valid JWT");
        assert_eq!(
            decoded.get("email").unwrap().as_str().unwrap(),
            "alice@example.com"
        );
        assert_eq!(decoded.get("hd").unwrap().as_str().unwrap(), "example.com");
        assert_eq!(
            decoded.get("sub").unwrap().as_str().unwrap(),
            "alice@example.com"
        );
    }

    #[test]
    fn test_decode_jwt_payload_missing_segments() {
        assert!(decode_jwt_payload("header-only").is_err());
    }

    #[test]
    fn test_decode_jwt_payload_invalid_base64() {
        assert!(decode_jwt_payload("header.!!!invalid-base64!!!.sig").is_err());
    }

    #[test]
    fn test_decode_jwt_payload_invalid_json() {
        let not_json = URL_SAFE_NO_PAD.encode("this is not json");
        let token = format!("header.{not_json}.signature");
        assert!(decode_jwt_payload(&token).is_err());
    }

    #[test]
    fn test_build_session_tags_with_email_and_domain() {
        let claims = serde_json::json!({
            "email": "alice@example.com",
            "hd": "example.com"
        });
        let tags = build_session_tags(&claims);
        assert_eq!(tags.len(), 2);
        assert_eq!(
            tags[0],
            ("email".to_string(), "alice@example.com".to_string())
        );
        assert_eq!(tags[1], ("domain".to_string(), "example.com".to_string()));
    }

    #[test]
    fn test_build_session_tags_email_only() {
        let claims = serde_json::json!({
            "email": "alice@personal.com"
        });
        let tags = build_session_tags(&claims);
        assert_eq!(tags.len(), 1);
        assert_eq!(
            tags[0],
            ("email".to_string(), "alice@personal.com".to_string())
        );
    }

    #[test]
    fn test_build_session_tags_no_claims() {
        let claims = serde_json::json!({
            "sub": "some-subject",
            "aud": "some-audience"
        });
        let tags = build_session_tags(&claims);
        assert!(tags.is_empty());
    }
}
