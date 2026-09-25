// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Session utilities for credential commands.

use crate::config::Config;
use crate::server_url::{InsecureOptIn, ServerUrl};
use anyhow::{Context, Result};
use secrecy::SecretString;
#[cfg(unix)]
use vouch_agent::{AgentClient, AgentError};
use vouch_cli::tr;
use vouch_common::{SessionCookie, write_cookie};

/// A resolved session: server URL and authentication token.
pub(crate) struct ResolvedSession {
    /// The server URL, validated for this invocation.
    pub server_url: ServerUrl,
    /// The session token.
    pub token: SecretString,
}

/// Try to get a full session (server_url + token) from the agent.
///
/// Returns `None` if the agent is not running, has no session, or the
/// session lacks a server URL.
#[cfg(unix)]
async fn try_agent_session() -> Option<(String, SecretString)> {
    let mut agent = vouch_agent::AgentClient::connect().await.ok()?;
    let session_info = agent.get_session().await.ok()?;
    let server_url = session_info.server_url?;
    let token = agent.get_token().await.ok()?;
    Some((server_url, token))
}

/// Try to get the authentication token from the agent.
#[cfg(unix)]
async fn try_agent_token() -> Option<SecretString> {
    let mut agent = vouch_agent::AgentClient::connect().await.ok()?;
    agent.get_token().await.ok()
}

/// Resolve the current session (server URL + token).
///
/// Tries multiple sources in order:
/// 1. Agent (Unix only) - most reliable, always up-to-date
/// 2. Config file - saved during login/enroll
///
/// The server URL is judged by [`ServerUrl::parse`] with this invocation's
/// `opt_in`, whichever source it came from. A stored URL was accepted under
/// the opt-in given at login, which says nothing about this invocation; every
/// caller sends the token to the URL returned here, so this is the one place
/// the check has to happen.
///
/// # Errors
///
/// Returns an error if no session is available, if the stored server URL is
/// plain HTTP to a non-loopback host and `opt_in` does not allow it (a
/// [`ServerUrlError`](crate::server_url::ServerUrlError), so callers can tell
/// it from "not configured"), or if `VOUCH_ALLOW_INSECURE` is unreadable.
pub(crate) async fn resolve_session(opt_in: InsecureOptIn) -> Result<ResolvedSession> {
    let (server_raw, token) = stored_session().await?;
    let server_url = ServerUrl::parse(&server_raw, opt_in.allowed()?)?;
    Ok(ResolvedSession { server_url, token })
}

/// The stored session's server URL (unvalidated) and token.
async fn stored_session() -> Result<(String, SecretString)> {
    // 1. Try agent first (Unix only)
    #[cfg(unix)]
    {
        if let Some(session) = try_agent_session().await {
            return Ok(session);
        }
        if std::io::IsTerminal::is_terminal(&std::io::stderr()) {
            eprintln!(
                "Hint: Agent not running. Start it for faster \
                 auth: vouch-agent --foreground"
            );
        }
    }

    // 2. Fall back to config file
    let config = Config::load().context(tr!("err-failed-load-config"))?;
    let server = config
        .server_url()
        .ok_or(crate::exit_code::CliError::ConfigError(
            "not configured — run 'vouch enroll' first".to_string(),
        ))?
        .to_string();
    let token = config
        .token()
        .ok_or(crate::exit_code::CliError::NotAuthenticated {
            reason: "no session token — run 'vouch login' to authenticate".to_string(),
        })?
        // Clone the secret string before config is dropped
        .clone();

    Ok((server, token))
}

/// Resolve the current authentication token.
///
/// Tries multiple sources in order:
/// 1. Agent (Unix only) - most reliable, always up-to-date
/// 2. Config file - saved during login/enroll
///
/// Returns an error if no token is available.
pub(crate) async fn resolve_token() -> Result<SecretString> {
    // 1. Try agent first (Unix only)
    #[cfg(unix)]
    if let Some(token) = try_agent_token().await {
        return Ok(token);
    }

    // 2. Fall back to config file
    let config = Config::load().context(tr!("err-failed-load-config"))?;
    let token = config
        .token()
        .ok_or(crate::exit_code::CliError::NotAuthenticated {
            reason: "no session token — run 'vouch login' to authenticate".to_string(),
        })?;
    Ok(token.clone())
}

/// Store session in the agent (if running).
///
/// Returns `true` if the session was successfully stored, `false` otherwise.
/// This is a best-effort operation — agent not running is not an error.
#[cfg(unix)]
pub(crate) async fn store_session_in_agent(
    token: &str,
    email: &str,
    expires_at: &str,
    server: &str,
) -> bool {
    match AgentClient::connect().await {
        Ok(mut agent) => {
            match agent
                .store_session(token, email, expires_at, Some(server))
                .await
            {
                Ok(()) => true,
                // The agent answered and refused, e.g. an insecure server URL
                // it was not configured to allow. Surface it: the session is
                // then served from the config file, not the agent.
                Err(e) => {
                    tracing::warn!("The agent did not store the session: {e}");
                    false
                }
            }
        }
        Err(AgentError::NotRunning) => {
            tracing::debug!("Agent not running, session stored in config only");
            false
        }
        Err(e) => {
            tracing::debug!("Failed to connect to agent: {e}");
            false
        }
    }
}

/// Write a Netscape cookie file for `curl -b ~/.local/state/vouch/cookie.txt`.
///
/// Best-effort: logs and swallows errors (cookie file is a convenience,
/// never blocks the login flow).
fn write_session_cookie_file(server: &str, token: &str, expires_at_ts: Option<jiff::Timestamp>) {
    let domain = match url::Url::parse(server) {
        Ok(u) => u.host_str().unwrap_or("localhost").to_string(),
        Err(_) => "localhost".to_string(),
    };

    let expires = expires_at_ts.map_or_else(
        || jiff::Timestamp::now().as_second().saturating_add(28_800),
        |ts| ts.as_second(),
    );

    let cookie = SessionCookie::new(&domain, token, expires);
    if let Err(e) = write_cookie(&cookie) {
        tracing::debug!("Failed to write cookie file: {e}");
    }
}

/// Store session credentials and finalize the post-authentication ceremony.
///
/// This is the shared logic between `login` and `enroll` commands. It:
/// 1. Saves the server URL and token to the config file
/// 2. Stores the session in the agent and writes cookie file concurrently
/// 3. Auto-provisions an SSH certificate
///
/// When `fapi_key` is provided (login flow), it is passed to auto-provision
/// so the SSH cert request uses DPoP without reloading from the keychain.
///
/// Returns whether the agent stored the session successfully.
pub(crate) async fn store_and_finalize(
    server: &str,
    token: &str,
    #[cfg_attr(
        not(unix),
        expect(unused_variables, reason = "parameter consumed only under cfg(unix)")
    )]
    email: &str,
    expires_at_str: &str,
    expires_at_ts: Option<jiff::Timestamp>,
    fapi_key: Option<vouch_cli::fapi::ClientKey>,
) -> Result<bool> {
    // 1. Config save — fast local I/O, do first
    let mut config = Config::load()?;
    config.set_server_url(server);
    config.set_token(token);
    config.save()?;

    // 2. Agent IPC + cookie write run concurrently
    let agent_future = async {
        #[cfg(unix)]
        {
            store_session_in_agent(token, email, expires_at_str, server).await
        }
        #[cfg(not(unix))]
        {
            false
        }
    };

    let cookie_future = async {
        write_session_cookie_file(server, token, expires_at_ts);
    };

    let (agent_stored, ()) = tokio::join!(agent_future, cookie_future);

    // 3. Auto-provision SSH certificate + refresh CodeArtifact in parallel
    let (_, ()) = tokio::join!(
        crate::commands::credential::ssh::auto_provision(server, expires_at_str, fapi_key,),
        crate::commands::setup::codeartifact::auto_refresh_npmrc(server),
    );

    Ok(agent_stored)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::server_url::ServerUrlError;

    const ENV_VARS: [&str; 3] = ["XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "VOUCH_ALLOW_INSECURE"];

    /// Resolve a session stored for `server` in a fresh config directory,
    /// with no agent reachable, once per opt-in, under `ENV_LOCK`.
    ///
    /// `env_opt_in` is the `VOUCH_ALLOW_INSECURE` value seen by
    /// `InsecureOptIn::Env`. The prior environment is restored before the
    /// results are returned, so a failing assertion cannot leak it.
    #[expect(
        unsafe_code,
        reason = "env mutation under ENV_LOCK; the prior values are restored before returning"
    )]
    async fn resolve_stored(
        server: Option<&str>,
        env_opt_in: Option<&str>,
        opt_ins: &[InsecureOptIn],
    ) -> Vec<Result<String>> {
        let _guard = crate::commands::credential::aws::test_support::ENV_LOCK
            .lock()
            .await;
        let dir = tempfile::tempdir().unwrap();
        let prior: Vec<_> = ENV_VARS.iter().map(|k| (*k, std::env::var_os(k))).collect();
        // SAFETY: ENV_LOCK serialises env mutation in this test binary.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", dir.path().join("config"));
            // No socket here, so the agent is "not running".
            std::env::set_var("XDG_RUNTIME_DIR", dir.path().join("run"));
            match env_opt_in {
                Some(v) => std::env::set_var("VOUCH_ALLOW_INSECURE", v),
                None => std::env::remove_var("VOUCH_ALLOW_INSECURE"),
            }
        }
        if let Some(server) = server {
            std::fs::create_dir_all(dir.path().join("config").join("vouch")).unwrap();
            let mut config = Config::default();
            config.set_server_url(server);
            config.set_token("stored-token");
            config.save().unwrap();
        }

        let mut results = Vec::new();
        for opt_in in opt_ins {
            results.push(
                resolve_session(*opt_in)
                    .await
                    .map(|s| s.server_url.as_str().to_string()),
            );
        }

        // SAFETY: as above; restores the prior values.
        unsafe {
            for (key, value) in prior {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
        results
    }

    fn is_url_refusal(result: &Result<String>) -> bool {
        result.as_ref().is_err_and(ServerUrlError::is_in)
    }

    /// A stored non-loopback `http://` URL was accepted under the opt-in
    /// given at login; every later invocation that sends the token to it must
    /// opt in again. `resolve_session` is where every helper gets its URL, so
    /// it refuses without this invocation's opt-in, from the flag or, for a
    /// helper binary, from its own environment.
    #[tokio::test]
    async fn stored_insecure_url_needs_this_invocations_opt_in() {
        let refused = resolve_stored(
            Some("http://vouch.example.com"),
            None,
            &[InsecureOptIn::Cli(false), InsecureOptIn::Env],
        )
        .await;
        let allowed = resolve_stored(
            Some("http://vouch.example.com"),
            Some("1"),
            &[InsecureOptIn::Cli(true), InsecureOptIn::Env],
        )
        .await;

        for result in &refused {
            assert!(
                is_url_refusal(result),
                "refused without an opt-in: {:?}",
                result.as_ref().map_err(|e| format!("{e:#}"))
            );
        }
        for result in allowed {
            assert_eq!(result.unwrap(), "http://vouch.example.com");
        }
    }

    /// HTTPS and loopback HTTP need no opt-in, and the returned URL is the
    /// normalized one.
    #[tokio::test]
    async fn secure_and_loopback_urls_need_no_opt_in() {
        for (stored, expected) in [
            ("https://vouch.example.com/", "https://vouch.example.com"),
            ("http://127.0.0.1:3000", "http://127.0.0.1:3000"),
            ("http://localhost:3000", "http://localhost:3000"),
        ] {
            let results = resolve_stored(
                Some(stored),
                None,
                &[InsecureOptIn::Cli(false), InsecureOptIn::Env],
            )
            .await;
            for result in results {
                assert_eq!(result.unwrap(), expected);
            }
        }
    }

    /// The environment opt-in is read only once there is a URL to judge: with
    /// no stored session the error is still "not configured", and an
    /// unreadable value is refused as a URL error, never read as either
    /// answer.
    #[tokio::test]
    async fn env_opt_in_is_read_only_when_a_url_is_judged() {
        let no_session = resolve_stored(None, Some("maybe"), &[InsecureOptIn::Env]).await;
        let unreadable = resolve_stored(
            Some("https://vouch.example.com"),
            Some("maybe"),
            &[InsecureOptIn::Env],
        )
        .await;

        let err = no_session.into_iter().next().unwrap().unwrap_err();
        assert!(
            matches!(
                err.downcast_ref::<crate::exit_code::CliError>(),
                Some(crate::exit_code::CliError::ConfigError(_))
            ),
            "no session is still not-configured: {err:#}"
        );
        let result = unreadable.into_iter().next().unwrap();
        assert!(is_url_refusal(&result));
    }
}
