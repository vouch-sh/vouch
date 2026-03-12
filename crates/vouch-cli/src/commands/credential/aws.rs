// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS credential command.
//!
//! Obtains temporary AWS credentials using Vouch session and STS.

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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
/// role ARN validation → `AssumeRoleWithWebIdentity`.
///
/// The STS session name is always the user's email address (for CloudTrail
/// visibility). Falls back to `fallback_label` if email is unavailable.
pub(crate) async fn exchange_for_sts_credentials(
    server: &str,
    role_arn: &str,
    region: &str,
    fallback_label: &str,
) -> Result<StsExchangeResult> {
    use crate::integrations::aws::sts::{assume_role_with_web_identity, parse_role_arn};

    let arn = parse_role_arn(role_arn)?;
    let domain_suffix = arn.partition.dns_suffix();

    let client = VouchClient::new(server).await?;

    let token_response: OidcTokenResponse = client
        .get_authenticated("/v1/credentials/aws/token")
        .await
        .context("failed to get OIDC token from Vouch server")?;

    let id_token = token_response.id_token.expose_secret();
    let tags = decode_jwt_payload(id_token)
        .map(|claims| build_session_tags(&claims))
        .unwrap_or_default();

    let http_client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context("failed to create HTTP client")?;

    let email = get_user_email(server).await;
    let session = email.as_deref().unwrap_or(fallback_label);
    let credentials = assume_role_with_web_identity(
        &http_client,
        role_arn,
        session,
        id_token,
        region,
        domain_suffix,
        &tags,
    )
    .await
    .context("failed to assume AWS role")?;

    Ok(StsExchangeResult {
        http_client,
        credentials,
        domain_suffix,
    })
}

/// Run the AWS credential command.
///
/// Uses a cache-first strategy via [`super::cache::get_or_fetch`]:
/// 1. Check agent cache — return immediately if valid cached credentials exist
/// 2. Fetch fresh OIDC token from Vouch server, call STS, cache the result
/// 3. On network error, fall back to cached credentials (if any)
pub async fn run(server: &str, role_arn: &str) -> Result<()> {
    let cache_key = format!("aws:{role_arn}");

    let data = super::cache::get_or_fetch(&cache_key, "AWS credentials", || async {
        let output = fetch_and_assume(server, role_arn).await?;
        let expires_at = output.expiration.clone();
        Ok((output.to_json(), expires_at))
    })
    .await?;

    let json = serde_json::to_string(&data).context("failed to serialize credentials")?;
    println!("{json}");
    Ok(())
}

/// Fetch an OIDC token from the Vouch server and exchange it for STS credentials.
pub(crate) async fn fetch_and_assume(
    server: &str,
    role_arn: &str,
) -> Result<CredentialProcessOutput> {
    use crate::integrations::aws;

    let profile_name = aws::resolve_profile(None).unwrap_or_default();
    let region = match aws::resolve_region(None, &profile_name) {
        Ok(r) => r,
        Err(_) => {
            let arn = crate::integrations::aws::sts::parse_role_arn(role_arn)?;
            let default = arn.partition.default_sts_region();
            tracing::debug!("no region configured, defaulting to {default} for STS");
            default.to_string()
        }
    };

    let result = exchange_for_sts_credentials(server, role_arn, &region, "vouch-session").await?;
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
