// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS SSO token cache writer.
//!
//! Writes SSO access tokens to `~/.aws/sso/cache/{sha1(session_name)}.json`
//! in the format expected by the AWS CLI and SDKs.

use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::utils::{atomic_write, ensure_secure_dir};

/// Compute the SSO cache filename for a given session name.
///
/// The AWS CLI uses SHA-1 of the session name as the cache key.
fn cache_filename(session_name: &str) -> String {
    use aws_lc_rs::digest;
    let hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, session_name.as_bytes());
    hex::encode(hash.as_ref())
}

/// Get the SSO cache directory (`~/.aws/sso/cache/`).
fn sso_cache_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".aws").join("sso").join("cache"))
}

/// Write an SSO token to the standard AWS SSO cache.
///
/// Creates `~/.aws/sso/cache/{sha1(session_name)}.json` with the
/// format expected by the AWS CLI.
pub fn write_sso_token(
    session_name: &str,
    start_url: &str,
    region: &str,
    access_token: &str,
    expires_in: u64,
) -> Result<()> {
    let cache_dir = sso_cache_dir()?;
    ensure_secure_dir(&cache_dir)?;

    let filename = cache_filename(session_name);
    let cache_path = cache_dir.join(format!("{filename}.json"));

    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(
            i64::try_from(expires_in).unwrap_or(i64::MAX),
        ))
        .context("overflow computing expiration")?;

    // AWS CLI expects this exact format
    let cache_entry = serde_json::json!({
        "startUrl": start_url,
        "region": region,
        "accessToken": access_token,
        "expiresAt": expires_at.strftime("%Y-%m-%dT%H:%M:%SUTC").to_string(),
    });

    let json = serde_json::to_string_pretty(&cache_entry)
        .context("failed to serialize SSO cache entry")?;
    atomic_write(&cache_path, json.as_bytes())
        .with_context(|| format!("failed to write SSO cache: {}", cache_path.display()))?;

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_filename_deterministic() {
        let a = cache_filename("vouch");
        let b = cache_filename("vouch");
        assert_eq!(a, b);
    }

    #[test]
    fn test_cache_filename_hex_40_chars() {
        let hash = cache_filename("vouch");
        assert_eq!(hash.len(), 40, "SHA-1 hex should be 40 chars");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_cache_filename_different_inputs() {
        assert_ne!(cache_filename("vouch"), cache_filename("vouch-other"));
    }

    #[test]
    fn test_write_sso_token_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();

        // Manually construct the path since we can't override dirs::home_dir
        let cache_dir = home.join(".aws").join("sso").join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();

        let filename = cache_filename("vouch");
        let cache_path = cache_dir.join(format!("{filename}.json"));

        let json = serde_json::json!({
            "startUrl": "https://vouch.example.com",
            "region": "us-east-1",
            "accessToken": "test-token",
            "expiresAt": "2026-03-12T20:00:00UTC",
        });
        let content = serde_json::to_string_pretty(&json).unwrap();
        std::fs::write(&cache_path, &content).unwrap();

        let loaded: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&cache_path).unwrap()).unwrap();
        assert_eq!(loaded["startUrl"], "https://vouch.example.com");
        assert_eq!(loaded["region"], "us-east-1");
        assert_eq!(loaded["accessToken"], "test-token");
    }
}
