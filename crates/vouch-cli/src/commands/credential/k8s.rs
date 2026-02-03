// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Kubernetes credential command.
//!
//! Outputs an OIDC token in Kubernetes ExecCredential format for kubectl.
//! See: https://kubernetes.io/docs/reference/config-api/client-authentication.v1/

use anyhow::{Context, Result};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::client::VouchClient;

/// Kubernetes ExecCredential output format.
/// See: https://kubernetes.io/docs/reference/config-api/client-authentication.v1/
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecCredential {
    /// API version (always "client.authentication.k8s.io/v1").
    api_version: String,
    /// Kind (always "ExecCredential").
    kind: String,
    /// Credential status containing the token.
    status: ExecCredentialStatus,
}

/// Status portion of ExecCredential containing the actual token.
#[derive(Serialize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct ExecCredentialStatus {
    /// The bearer token to use for authentication.
    token: String,
    /// RFC 3339 timestamp when the token expires.
    expiration_timestamp: String,
}

impl std::fmt::Debug for ExecCredentialStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecCredentialStatus")
            .field("token", &"[REDACTED]")
            .field("expiration_timestamp", &self.expiration_timestamp)
            .finish()
    }
}

/// Response from Vouch K8s token endpoint.
#[derive(Deserialize, zeroize::ZeroizeOnDrop)]
struct K8sTokenResponse {
    id_token: String,
    expires_in: u64,
}

impl std::fmt::Debug for K8sTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("K8sTokenResponse")
            .field("id_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// Run the Kubernetes credential command.
///
/// This command:
/// 1. Gets an OIDC ID token from the Vouch server
/// 2. Outputs it in Kubernetes ExecCredential format
///
/// kubectl will then use this token to authenticate with the Kubernetes API server.
pub async fn run(server: &str, audience: &str) -> Result<()> {
    // Try to get the token, converting any errors to stderr messages
    // Note: Unlike GCP, kubectl reads errors from stderr, not stdout
    match get_k8s_token(server, audience).await {
        Ok(response) => {
            let json = serde_json::to_string(&response).context("failed to serialize response")?;
            println!("{json}");
            Ok(())
        }
        Err(e) => {
            // kubectl reads errors from stderr
            eprintln!("Error: {e:#}");
            // Return error so kubectl knows authentication failed
            Err(e)
        }
    }
}

/// Get the Kubernetes token from the Vouch server.
async fn get_k8s_token(server: &str, audience: &str) -> Result<ExecCredential> {
    let client = VouchClient::new(server)?;

    // URL-encode the audience parameter using percent encoding
    let encoded_audience: String =
        url::form_urlencoded::byte_serialize(audience.as_bytes()).collect();
    let path = format!("/v1/credentials/k8s/token?audience={encoded_audience}");

    // Get OIDC token from Vouch server
    let token_response: K8sTokenResponse = client
        .get_authenticated(&path)
        .await
        .context("failed to get OIDC token from Vouch server")?;

    // Calculate expiration timestamp in RFC 3339 format
    let now = Timestamp::now();
    let expiration_secs = now.as_second() + i64::try_from(token_response.expires_in).unwrap_or(0);
    let expiration = Timestamp::from_second(expiration_secs)
        .map_err(|e| anyhow::anyhow!("invalid expiration timestamp: {e}"))?;

    Ok(ExecCredential {
        api_version: "client.authentication.k8s.io/v1".to_string(),
        kind: "ExecCredential".to_string(),
        status: ExecCredentialStatus {
            token: token_response.id_token.clone(),
            expiration_timestamp: expiration.to_string(),
        },
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Test that ExecCredential serializes to correct JSON format.
    #[test]
    fn test_exec_credential_serialization() {
        let cred = ExecCredential {
            api_version: "client.authentication.k8s.io/v1".to_string(),
            kind: "ExecCredential".to_string(),
            status: ExecCredentialStatus {
                token: "test-token-123".to_string(),
                expiration_timestamp: "2026-01-30T12:00:00Z".to_string(),
            },
        };

        let json = serde_json::to_value(&cred).expect("should serialize");

        assert_eq!(
            json["apiVersion"], "client.authentication.k8s.io/v1",
            "apiVersion should use camelCase"
        );
        assert_eq!(json["kind"], "ExecCredential");
        assert_eq!(json["status"]["token"], "test-token-123");
        assert_eq!(
            json["status"]["expirationTimestamp"], "2026-01-30T12:00:00Z",
            "expirationTimestamp should use camelCase"
        );
    }

    /// Test that ExecCredential JSON matches kubectl expected format.
    #[test]
    fn test_exec_credential_kubectl_format() {
        let cred = ExecCredential {
            api_version: "client.authentication.k8s.io/v1".to_string(),
            kind: "ExecCredential".to_string(),
            status: ExecCredentialStatus {
                token: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.test".to_string(),
                expiration_timestamp: "2026-01-30T20:00:00Z".to_string(),
            },
        };

        let json_str = serde_json::to_string(&cred).expect("should serialize");

        // Verify it's valid JSON that kubectl can parse
        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).expect("should be valid JSON");

        // kubectl requires these exact fields
        assert!(parsed.get("apiVersion").is_some());
        assert!(parsed.get("kind").is_some());
        assert!(parsed.get("status").is_some());
        assert!(parsed["status"].get("token").is_some());
        assert!(parsed["status"].get("expirationTimestamp").is_some());

        // Should not have unexpected fields at top level
        let obj = parsed.as_object().expect("should be object");
        assert_eq!(obj.len(), 3, "should have exactly 3 top-level fields");
    }

    /// Test that K8sTokenResponse deserializes correctly.
    #[test]
    fn test_k8s_token_response_deserialization() {
        let json = r#"{"id_token":"test.jwt.token","expires_in":28800}"#;
        let response: K8sTokenResponse = serde_json::from_str(json).expect("should deserialize");

        assert_eq!(response.id_token, "test.jwt.token");
        assert_eq!(response.expires_in, 28800);
    }

    /// Test audience URL encoding.
    #[test]
    fn test_audience_url_encoding() {
        // Simple audience should be unchanged
        let simple: String =
            url::form_urlencoded::byte_serialize("my-cluster".as_bytes()).collect();
        assert_eq!(simple, "my-cluster");

        // URL-like audience should be encoded
        let url_aud: String =
            url::form_urlencoded::byte_serialize("https://k8s.example.com:6443".as_bytes())
                .collect();
        assert_eq!(url_aud, "https%3A%2F%2Fk8s.example.com%3A6443");

        // Audience with spaces should be encoded
        let spaced: String =
            url::form_urlencoded::byte_serialize("my cluster".as_bytes()).collect();
        assert_eq!(spaced, "my+cluster");
    }
}
