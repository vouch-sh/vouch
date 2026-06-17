// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Kubernetes OIDC credential command.
//!
//! Fetches a short-lived OIDC ID token from the Vouch server and outputs it
//! as a Kubernetes `ExecCredential` JSON for use as a kubeconfig credential plugin.
//!
//! Protocol:
//! 1. Check agent cache for a valid token
//! 2. RFC 8693 token exchange at POST /oauth/token (audience = <aud>)
//! 3. Output as Kubernetes `ExecCredential` JSON

use anyhow::{Context, Result};
use secrecy::ExposeSecret;

use crate::commands::credential::cache;

/// Default lifetime (seconds) for the ExecCredential when the server does
/// not report an `expires_in` for the issued ID token.
const DEFAULT_EXEC_TTL_SECS: u64 = 600;

/// Run the Kubernetes credential command.
///
/// Outputs a Kubernetes `ExecCredential` JSON to stdout for use as a
/// kubeconfig exec-based credential plugin.
pub(crate) async fn run(server: &str, cluster: &str, audience: Option<&str>) -> Result<()> {
    let aud = audience.unwrap_or("kubernetes");
    let cache_key = format!("k8s:{cluster}:{aud}");

    let data = cache::get_or_fetch(&cache_key, "Kubernetes token", || async {
        let (id_token, expires_in) = super::wif::fetch_assertion(server, Some(aud)).await?;
        let expires_at = expiration_rfc3339(expires_in.unwrap_or(DEFAULT_EXEC_TTL_SECS))?;
        let exec_cred = build_exec_credential(id_token.expose_secret(), &expires_at)?;
        Ok((exec_cred, expires_at))
    })
    .await?;

    let json = serde_json::to_string(&data).context("failed to serialize ExecCredential")?;
    // Machine-readable JSON output: stays English (consumed by kubectl).
    println!("{json}");
    Ok(())
}

/// Build the Kubernetes `ExecCredential` JSON value.
fn build_exec_credential(token: &str, expiration: &str) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "kind": "ExecCredential",
        "apiVersion": "client.authentication.k8s.io/v1",
        "status": {
            "token": token,
            "expirationTimestamp": expiration,
        }
    }))
}

/// Compute the expiration timestamp as RFC 3339 from a TTL in seconds.
fn expiration_rfc3339(expires_in: u64) -> Result<String> {
    let ttl = i64::try_from(expires_in).unwrap_or(3600);
    let expires = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(ttl))
        .context("failed to compute Kubernetes token expiration")?;
    Ok(expires.to_string())
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_build_exec_credential_shape() {
        let token = "eyJhbGciOiJFUzI1NiJ9.test.sig";
        let expiration = "2026-01-01T00:00:00Z";
        let cred = build_exec_credential(token, expiration).expect("should build");

        assert_eq!(cred["kind"], "ExecCredential");
        assert_eq!(cred["apiVersion"], "client.authentication.k8s.io/v1");
        assert_eq!(cred["status"]["token"], token);
        assert_eq!(cred["status"]["expirationTimestamp"], expiration);
    }

    #[test]
    fn test_build_exec_credential_no_extra_fields() {
        let cred = build_exec_credential("token", "2026-01-01T00:00:00Z").expect("should build");
        let obj = cred.as_object().unwrap();
        assert_eq!(obj.len(), 3); // kind, apiVersion, status
        let status = cred["status"].as_object().unwrap();
        assert_eq!(status.len(), 2); // token, expirationTimestamp
    }

    #[test]
    fn test_expiration_rfc3339_valid() {
        let ts = expiration_rfc3339(3600).expect("should compute");
        assert!(ts.parse::<jiff::Timestamp>().is_ok());
    }

    #[test]
    fn test_expiration_rfc3339_is_in_future() {
        let now = jiff::Timestamp::now();
        let ts = expiration_rfc3339(3600).expect("should compute");
        let exp: jiff::Timestamp = ts.parse().unwrap();
        assert!(exp > now);
    }

    #[test]
    fn test_expiration_rfc3339_overflow_falls_back() {
        // u64::MAX exceeds i64::MAX — should fall back to 3600 seconds
        let ts = expiration_rfc3339(u64::MAX).expect("should fall back");
        assert!(ts.parse::<jiff::Timestamp>().is_ok());
    }
}
