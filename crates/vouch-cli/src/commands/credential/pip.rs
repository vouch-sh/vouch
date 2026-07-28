// SPDX-License-Identifier: Apache-2.0 OR MIT
//! pip keyring credential helper.
//!
//! Implements the `keyring` CLI protocol so pip can dynamically fetch fresh
//! CodeArtifact tokens instead of relying on static tokens that expire in ~12h.
//!
//! pip's keyring subprocess protocol:
//!   `keyring get <service_url> <username>` → prints password to stdout
//!   `keyring set <service_url> <username>` → reads password from stdin (no-op for us)
//!   `keyring del <service_url> <username>` → deletes stored password (no-op for us)
//!
//! Setup configures pip to use vouch as the keyring backend via:
//!   `pip config set global.keyring-provider subprocess`
//! and installs a `keyring` wrapper script that delegates to `vouch credential pip`.

use anyhow::{Context, Result};
use secrecy::ExposeSecret;

use crate::integrations::aws::codeartifact::parse_codeartifact_url;

/// Run the pip keyring credential helper.
///
/// Implements the keyring CLI protocol. Only the `get` operation is meaningful;
/// `set` and `del` are silently ignored since vouch manages tokens dynamically.
pub(crate) async fn run(
    operation: &str,
    service_url: Option<&str>,
    _username: Option<&str>,
) -> Result<()> {
    match operation {
        "get" => {
            let url = service_url.context(
                "keyring get requires a service URL. \
                 Usage: vouch credential pip get <url> [username]",
            )?;
            handle_get(url).await
        }
        // pip calls `set` after a successful auth to cache the password.
        // We don't need to store anything since we fetch dynamically.
        "set" | "del" => Ok(()),
        _ => {
            // Unknown operation — return success silently (keyring protocol convention)
            Ok(())
        }
    }
}

/// Handle `keyring get <url> <username>` — return a fresh CodeArtifact token.
async fn handle_get(url: &str) -> Result<()> {
    let registry = parse_codeartifact_url(url).ok_or_else(|| {
        anyhow::anyhow!(
            "URL does not appear to be a CodeArtifact registry: {url}\n\
             Expected format: https://{{domain}}-{{owner}}.d.codeartifact.{{region}}.amazonaws.com/..."
        )
    })?;

    let session = crate::session::resolve_session()
        .await
        .context("vouch is not enrolled - run 'vouch enroll' to set up authentication")?;

    // The keyring shim carries no arguments, so the AWS account backing this
    // domain is recovered from the saved CodeArtifact profile.
    let target = super::codeartifact::CodeArtifactTarget::new(
        registry.domain,
        registry.domain_owner,
        registry.region,
    );
    let token = super::codeartifact::get_token(&session.server_url, &target)
        .await
        .context("failed to get CodeArtifact token")?;

    // Print the token to stdout (keyring protocol: password on stdout, nothing else)
    print!("{}", token.authorization_token.expose_secret());

    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_codeartifact_from_pip_url() {
        // pip passes the full index URL including /pypi/{repo}/simple/ path
        let url = "https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/pypi/my-repo/simple/";
        let registry = parse_codeartifact_url(url);
        assert!(registry.is_some());
        let r = registry.unwrap();
        assert_eq!(r.domain, "my-domain");
        assert_eq!(r.domain_owner, "123456789012");
        assert_eq!(r.region, "us-east-1");
    }

    #[test]
    fn test_non_codeartifact_url_returns_none() {
        assert!(parse_codeartifact_url("https://pypi.org/simple/").is_none());
        assert!(parse_codeartifact_url("https://files.pythonhosted.org/packages/").is_none());
    }

    #[tokio::test]
    async fn test_set_operation_succeeds_silently() {
        assert!(
            run("set", Some("https://example.com"), Some("user"))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_del_operation_succeeds_silently() {
        assert!(
            run("del", Some("https://example.com"), Some("user"))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_unknown_operation_succeeds_silently() {
        assert!(run("unknown", None, None).await.is_ok());
    }

    #[tokio::test]
    async fn test_get_without_url_returns_error() {
        let result = run("get", None, None).await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("keyring get requires a service URL"));
    }

    #[tokio::test]
    async fn test_get_non_codeartifact_url_returns_error() {
        let result = run("get", Some("https://pypi.org/simple/"), Some("user")).await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("does not appear to be a CodeArtifact registry"));
    }
}
