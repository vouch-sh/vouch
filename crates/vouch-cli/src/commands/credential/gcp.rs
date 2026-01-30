// SPDX-License-Identifier: Apache-2.0 OR MIT
//! GCP credential command.
//!
//! Outputs an OIDC token in GCP's executable-sourced credential format.
//! See: https://google.aip.dev/auth/4117

use anyhow::{Context, Result};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::client::VouchClient;

/// GCP executable-sourced credential output format (success).
/// See: https://google.aip.dev/auth/4117
#[derive(Debug, Serialize)]
struct ExecutableSuccessResponse {
    /// Schema version (always 1).
    version: u32,
    /// Whether the operation succeeded.
    success: bool,
    /// Token type identifier.
    token_type: String,
    /// The OIDC ID token.
    id_token: String,
    /// Expiration time as Unix timestamp.
    expiration_time: i64,
}

/// GCP executable-sourced credential output format (failure).
/// CRITICAL: GCP requires valid JSON even on errors - never write to stderr.
#[derive(Debug, Serialize)]
struct ExecutableErrorResponse {
    /// Schema version (always 1).
    version: u32,
    /// Whether the operation succeeded.
    success: bool,
    /// Error code.
    code: String,
    /// Human-readable error message.
    message: String,
}

/// Response from Vouch GCP token endpoint.
#[derive(Debug, Deserialize)]
struct GcpTokenResponse {
    id_token: String,
    expires_in: u64,
}

/// Run the GCP credential command.
///
/// This command:
/// 1. Gets an OIDC ID token from the Vouch server
/// 2. Outputs it in GCP's executable-sourced credential format
///
/// GCP libraries will then use this token to exchange for GCP credentials
/// via Workload Identity Federation.
pub async fn run(server: &str, audience: &str) -> Result<()> {
    // Try to get the token, converting any errors to the GCP error format
    match get_gcp_token(server, audience).await {
        Ok(response) => {
            let json = serde_json::to_string(&response).context("failed to serialize response")?;
            println!("{json}");
            Ok(())
        }
        Err(e) => {
            // Output error in GCP's expected format
            // CRITICAL: GCP requires JSON on stdout, not stderr
            let error_response = ExecutableErrorResponse {
                version: 1,
                success: false,
                code: "CREDENTIAL_ERROR".to_string(),
                message: format!("{e:#}"),
            };
            let json =
                serde_json::to_string(&error_response).context("failed to serialize error")?;
            println!("{json}");
            // Return Ok because we successfully output the error in the expected format
            // The GCP libraries will handle the error response appropriately
            Ok(())
        }
    }
}

/// Get the GCP token from the Vouch server.
async fn get_gcp_token(server: &str, audience: &str) -> Result<ExecutableSuccessResponse> {
    let client = VouchClient::new(server)?;

    // URL-encode the audience parameter using percent encoding
    let encoded_audience: String =
        url::form_urlencoded::byte_serialize(audience.as_bytes()).collect();
    let path = format!("/v1/credentials/gcp/token?audience={encoded_audience}");

    // Get OIDC token from Vouch server
    let token_response: GcpTokenResponse = client
        .get_authenticated(&path)
        .await
        .context("failed to get OIDC token from Vouch server")?;

    // Calculate expiration timestamp
    let now = Timestamp::now();
    let expiration_time = now.as_second() + i64::try_from(token_response.expires_in).unwrap_or(0);

    Ok(ExecutableSuccessResponse {
        version: 1,
        success: true,
        token_type: "urn:ietf:params:oauth:token-type:id_token".to_string(),
        id_token: token_response.id_token,
        expiration_time,
    })
}
