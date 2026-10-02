// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Session utilities for credential commands.

#[cfg(unix)]
use crate::client::VouchClient;
use crate::commands::credential::ssh;
use crate::commands::setup::codeartifact;
use crate::config::Config;
use crate::exit_code::CliError;
use crate::server_url::{InsecureOptIn, ServerUrl};
use anyhow::{Context, Result};
#[cfg(unix)]
use secrecy::ExposeSecret;
use secrecy::SecretString;
#[cfg(unix)]
use vouch_agent::protocol::StoreMode;
#[cfg(unix)]
use vouch_agent::{AgentClient, AgentError};
use vouch_cli::fapi::ClientKey;
use vouch_cli::tr;
#[cfg(unix)]
use vouch_common::SessionStatus;

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
    let mut agent = AgentClient::connect().await.ok()?;
    let session_info = agent.get_session().await.ok()?;
    let server_url = session_info.server_url?;
    let token = agent.get_token().await.ok()?;
    Some((server_url, token))
}

/// Try to get the authentication token from the agent.
#[cfg(unix)]
async fn try_agent_token() -> Option<SecretString> {
    let mut agent = AgentClient::connect().await.ok()?;
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
    // 1. Try agent first (Unix only)
    #[cfg(unix)]
    {
        if let Some((server_raw, token)) = try_agent_session().await {
            let server_url = ServerUrl::parse(&server_raw, opt_in.allowed()?)?;
            return Ok(ResolvedSession { server_url, token });
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
    let server_raw = config.server_url().ok_or(CliError::ConfigError(
        "not configured — run 'vouch enroll' first".to_string(),
    ))?;
    let token = config
        .token()
        .ok_or(CliError::NotAuthenticated {
            reason: "no session token — run 'vouch login' to authenticate".to_string(),
        })?
        .clone();
    let session = ResolvedSession {
        server_url: ServerUrl::parse(server_raw, opt_in.allowed()?)?,
        token,
    };
    #[cfg(unix)]
    restore_agent_session(&session).await;
    Ok(session)
}

/// The session token, for requests to `server`.
///
/// A session belongs to the server it was established with. `--server` and
/// `VOUCH_SERVER` can name another one, and sending this token there hands
/// the user's access to that server, which can replay a Bearer token against
/// the one it came from. So the token is returned only when the stored
/// session, from the agent or else the config file, is `server`'s. `server`
/// itself was judged by [`ServerUrl::parse`] when it was resolved.
///
/// # Errors
///
/// Returns an error if no session is available, or if it belongs to another
/// server.
pub(crate) async fn token_for(server: &ServerUrl) -> Result<SecretString> {
    #[cfg(unix)]
    if let Some((stored, token)) = try_agent_session().await {
        belongs_to(server, &stored)?;
        return Ok(token);
    }

    let config = Config::load().context(tr!("err-failed-load-config"))?;
    let token = config
        .token()
        .ok_or(CliError::NotAuthenticated {
            reason: "no session token — run 'vouch login' to authenticate".to_string(),
        })?
        .clone();
    // A token stored without its server cannot show where it belongs.
    belongs_to(server, config.server_url().unwrap_or_default())?;
    #[cfg(unix)]
    restore_agent_session(&ResolvedSession {
        server_url: server.clone(),
        token: token.clone(),
    })
    .await;
    Ok(token)
}

/// Refuse a session stored for another server than `server`.
fn belongs_to(server: &ServerUrl, stored: &str) -> Result<()> {
    if server.names(stored) {
        return Ok(());
    }
    Err(CliError::NotAuthenticated {
        reason: vouch_cli::tr_args!(
            "err-session-for-other-server",
            session = stored,
            server = server.as_str()
        ),
    }
    .into())
}

/// Resolve the current authentication token, whichever server it belongs
/// to.
///
/// Only for handing the token to something outside the CLI's own requests:
/// printing it (`vouch credential token`), or a cargo registry that asked
/// for it. A request the CLI sends to a server takes its token from
/// [`token_for`], which checks the session belongs to that server.
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
        .ok_or(CliError::NotAuthenticated {
            reason: "no session token — run 'vouch login' to authenticate".to_string(),
        })?
        .clone();
    // Only a server URL this invocation's environment accepts may receive
    // the token; without one the agent is simply not restored.
    #[cfg(unix)]
    if let Some(server_url) = config
        .server_url()
        .and_then(|raw| ServerUrl::parse(raw, InsecureOptIn::Env.allowed().ok()?).ok())
    {
        restore_agent_session(&ResolvedSession {
            server_url,
            token: token.clone(),
        })
        .await;
    }
    Ok(token)
}

/// Hand a session found only in the config file back to a running agent.
///
/// The agent keeps no session across a restart and never reads the token
/// itself. When it is running without one, check the stored token with
/// `/v1/auth/status`, signed with this CLI's DPoP key (RFC 9449 §7.1), and
/// store the session in the agent if the server still accepts it and the
/// agent still holds no live session: a `vouch login` that finishes during
/// the check stores a newer session, which this one must not overwrite.
/// Best-effort: a failure leaves the agent as it was, and the caller uses the
/// config session regardless.
#[cfg(unix)]
async fn restore_agent_session(session: &ResolvedSession) {
    if AgentClient::connect().await.is_err() {
        return;
    }
    let status = match VouchClient::from_session(session) {
        Ok(client) => {
            client
                .get_authenticated::<SessionStatus>("/v1/auth/status")
                .await
        }
        Err(e) => Err(e),
    };
    let status = match status {
        Ok(status) => status,
        Err(e) => {
            tracing::debug!("Not restoring the agent session: {e}");
            return;
        }
    };
    let (true, Some(email), Some(expires_in)) = (
        status.authenticated,
        status.email,
        status.expires_in_seconds,
    ) else {
        tracing::debug!("The server no longer accepts the stored session");
        return;
    };
    let Some(expires_at) = i64::try_from(expires_in)
        .ok()
        .and_then(|secs| jiff::Timestamp::now().as_second().checked_add(secs))
        .and_then(|secs| jiff::Timestamp::from_second(secs).ok())
    else {
        return;
    };
    store_session_in_agent(
        session.token.expose_secret(),
        &email,
        &expires_at.to_string(),
        session.server_url.as_str(),
        StoreMode::IfNoLiveSession,
    )
    .await;
}

/// Store session in the agent (if running).
///
/// Returns `true` if the agent stored the session, `false` otherwise: with
/// [`StoreMode::IfNoLiveSession`] the agent keeps a live session it already
/// holds. This is a best-effort operation — agent not running is not an error.
#[cfg(unix)]
pub(crate) async fn store_session_in_agent(
    token: &str,
    email: &str,
    expires_at: &str,
    server: &str,
    mode: StoreMode,
) -> bool {
    match AgentClient::connect().await {
        Ok(mut agent) => {
            match agent
                .store_session(token, email, expires_at, Some(server), mode)
                .await
            {
                Ok(stored) => {
                    if !stored {
                        tracing::debug!("The agent kept its live session");
                    }
                    stored
                }
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

/// Store session credentials and finalize the post-authentication ceremony.
///
/// This is the shared logic between `login` and `enroll` commands. It:
/// 1. Saves the server URL and token to the config file
/// 2. Stores the session in the agent
/// 3. Auto-provisions an SSH certificate
///
/// When `fapi_key` is provided (login flow), it is passed to auto-provision
/// so the SSH cert request uses DPoP without reloading from the keychain.
///
/// Returns whether the agent stored the session successfully.
pub(crate) async fn store_and_finalize(
    server: &ServerUrl,
    token: &str,
    email: &str,
    expires_at_str: &str,
    fapi_key: Option<ClientKey>,
) -> Result<bool> {
    // 1. Config save — fast local I/O, do first
    let mut config = Config::load()?;
    config.set_server_url(server.as_str());
    config.set_token(token);
    config.save()?;

    // 2. Agent IPC
    let agent_stored = {
        #[cfg(unix)]
        {
            store_session_in_agent(
                token,
                email,
                expires_at_str,
                server.as_str(),
                StoreMode::Replace,
            )
            .await
        }
        #[cfg(not(unix))]
        {
            false
        }
    };

    // 3. Auto-provision SSH certificate + refresh CodeArtifact in parallel
    let (_, ()) = tokio::join!(
        ssh::auto_provision(server, email, expires_at_str, fapi_key),
        codeartifact::auto_refresh_npmrc(server),
    );

    Ok(agent_stored)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
pub(crate) mod test_support {
    //! A stored session for tests that read the config file.

    use crate::commands::credential::aws::test_support::ENV_LOCK;
    use crate::config::Config;

    const ENV_VARS: [&str; 3] = ["XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "VOUCH_ALLOW_INSECURE"];

    /// Run `body` against a session stored for `server` in a fresh config
    /// directory, with no agent reachable, under `ENV_LOCK`.
    ///
    /// `env_opt_in` is the `VOUCH_ALLOW_INSECURE` value seen by
    /// `InsecureOptIn::Env`. The prior environment is restored before the
    /// result is returned, so a failing assertion cannot leak it.
    #[expect(
        unsafe_code,
        reason = "env mutation under ENV_LOCK; the prior values are restored before returning"
    )]
    pub(crate) async fn with_stored_session<T>(
        server: Option<&str>,
        env_opt_in: Option<&str>,
        body: impl AsyncFnOnce() -> T,
    ) -> T {
        let _guard = ENV_LOCK.lock().await;
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

        let result = body().await;

        // SAFETY: as above; restores the prior values.
        unsafe {
            for (key, value) in prior {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
        result
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::test_support::with_stored_session;
    use super::*;
    #[cfg(all(unix, feature = "test-utils"))]
    use crate::commands::credential::aws::test_support::ENV_LOCK;
    use crate::server_url::ServerUrlError;

    /// Resolve a session stored for `server`, once per opt-in; see
    /// [`with_stored_session`](super::test_support::with_stored_session).
    async fn resolve_stored(
        server: Option<&str>,
        env_opt_in: Option<&str>,
        opt_ins: &[InsecureOptIn],
    ) -> Vec<Result<String>> {
        with_stored_session(server, env_opt_in, async || {
            let mut results = Vec::new();
            for opt_in in opt_ins {
                results.push(
                    resolve_session(*opt_in)
                        .await
                        .map(|s| s.server_url.as_str().to_string()),
                );
            }
            results
        })
        .await
    }

    /// A session belongs to the server it was established with. A
    /// `--server` or `VOUCH_SERVER` naming another one gets no token, so the
    /// session's token is never sent there; the session's own server, with or
    /// without a trailing slash, gets it.
    #[tokio::test]
    async fn token_goes_only_to_the_sessions_own_server() {
        use secrecy::ExposeSecret;

        let (own, other) = with_stored_session(Some("https://a.example.com/"), None, async || {
            let own = token_for(&ServerUrl::parse("https://a.example.com", false).unwrap())
                .await
                .map(|token| token.expose_secret().to_string());
            let other = token_for(&ServerUrl::parse("https://b.example.com", false).unwrap())
                .await
                .map(|token| token.expose_secret().to_string());
            (own, other)
        })
        .await;

        assert_eq!(own.unwrap(), "stored-token");
        let refusal = other.unwrap_err().to_string();
        assert!(
            refusal.contains("https://b.example.com"),
            "the refusal names the other server: {refusal}"
        );
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
                err.downcast_ref::<CliError>(),
                Some(CliError::ConfigError(_))
            ),
            "no session is still not-configured: {err:#}"
        );
        let result = unreadable.into_iter().next().unwrap();
        assert!(is_url_refusal(&result));
    }

    /// The account of a login that completes during a restore check.
    #[cfg(all(unix, feature = "test-utils"))]
    const LOGIN_EMAIL: &str = "login@example.com";

    /// What a fake server saw on each `/v1/auth/status` request: the
    /// `Authorization` value and whether a `DPoP` header was present.
    #[cfg(all(unix, feature = "test-utils"))]
    type SeenRequests = std::sync::Arc<std::sync::Mutex<Vec<(String, bool)>>>;

    /// Resolve a session stored only in `config.json`, against a fake server
    /// that answers `/v1/auth/status` with `status`, with or without an empty
    /// agent running. With `login_during_check`, the server stores
    /// [`LOGIN_EMAIL`]'s session in the agent before it answers, as a
    /// `vouch login` finishing during the check would. Returns the agent's
    /// session afterwards (`None` when it holds none or is not running) and
    /// the requests the server received.
    #[cfg(all(unix, feature = "test-utils"))]
    #[expect(
        unsafe_code,
        reason = "env mutation under ENV_LOCK; the prior values are restored before returning"
    )]
    async fn restore_from_config(
        status: serde_json::Value,
        agent_running: bool,
        login_during_check: bool,
    ) -> (Option<vouch_agent::SessionInfo>, Vec<(String, bool)>) {
        use std::sync::Arc;
        use tokio::net::{TcpListener, UnixListener};
        use vouch_agent::server::AgentServer;
        use vouch_agent::socket::{prepare_vouch_dir, socket_path};
        use vouch_agent::state::AgentState;
        use vouch_common::paths::client_key_file;

        const VARS: [&str; 4] = [
            "XDG_CONFIG_HOME",
            "XDG_RUNTIME_DIR",
            "XDG_DATA_HOME",
            "VOUCH_ALLOW_INSECURE",
        ];
        let _guard = ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let prior: Vec<_> = VARS.iter().map(|k| (*k, std::env::var_os(k))).collect();
        // SAFETY: ENV_LOCK serialises env mutation in this test binary.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", dir.path().join("config"));
            std::env::set_var("XDG_RUNTIME_DIR", dir.path().join("run"));
            std::env::set_var("XDG_DATA_HOME", dir.path().join("data"));
            std::env::remove_var("VOUCH_ALLOW_INSECURE");
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = format!("http://{}", listener.local_addr().unwrap());
        let seen = SeenRequests::default();
        let seen_by_route = Arc::clone(&seen);
        let server_for_route = server.clone();
        let router = axum::Router::new().route(
            "/v1/auth/status",
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let seen = Arc::clone(&seen_by_route);
                let status = status.clone();
                let server = server_for_route.clone();
                async move {
                    let auth = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    seen.lock()
                        .unwrap()
                        .push((auth, headers.contains_key("dpop")));
                    if login_during_check {
                        let expires_at = jiff::Timestamp::now()
                            .checked_add(jiff::SignedDuration::from_secs(3600))
                            .unwrap()
                            .to_string();
                        let stored = AgentClient::connect()
                            .await
                            .unwrap()
                            .store_session(
                                "login-token",
                                LOGIN_EMAIL,
                                &expires_at,
                                Some(&server),
                                StoreMode::Replace,
                            )
                            .await
                            .unwrap();
                        assert!(stored, "the login's session is stored");
                    }
                    axum::Json(status)
                }
            }),
        );
        let http_task = tokio::spawn(async move { axum::serve(listener, router).await });

        std::fs::create_dir_all(dir.path().join("config").join("vouch")).unwrap();
        let mut config = Config::default();
        config.set_server_url(&server);
        config.set_token("stored-token");
        config.save().unwrap();
        // The CLI's DPoP key. Tests never register a keychain store, so
        // `load_client_key` reads this file.
        ClientKey::generate()
            .unwrap()
            .save(&client_key_file().unwrap())
            .unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let agent_task = if agent_running {
            prepare_vouch_dir().unwrap();
            let listener = UnixListener::bind(socket_path().unwrap()).unwrap();
            let agent = AgentServer::new(AgentState::new(), shutdown_rx);
            Some(tokio::spawn(
                async move { agent.run_listener(listener).await },
            ))
        } else {
            None
        };

        let resolved = resolve_session(InsecureOptIn::Cli(false)).await.unwrap();
        assert_eq!(
            resolved.server_url.as_str(),
            server,
            "the stored session is served"
        );

        let agent_session = if agent_running {
            AgentClient::connect()
                .await
                .unwrap()
                .get_session()
                .await
                .ok()
        } else {
            None
        };
        let seen = seen.lock().unwrap().clone();

        shutdown_tx.send(true).unwrap();
        if let Some(task) = agent_task {
            task.await.unwrap().unwrap();
        }
        http_task.abort();
        // SAFETY: as above; restores the prior values.
        unsafe {
            for (key, value) in prior {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
        (agent_session, seen)
    }

    /// The agent keeps no session across a restart. The first command after
    /// one checks the stored token with the server, signed with the CLI's
    /// DPoP key (RFC 9449 §7.1), and hands the session back to the agent.
    #[cfg(all(unix, feature = "test-utils"))]
    #[tokio::test]
    async fn stored_session_is_checked_with_dpop_and_restored_to_the_agent() {
        let (agent_session, seen) = restore_from_config(
            serde_json::json!({
                "authenticated": true,
                "email": "restored@example.com",
                "expires_in_seconds": 3600,
                "device_name": null,
            }),
            true,
            false,
        )
        .await;

        assert_eq!(seen.len(), 1, "one status check: {seen:?}");
        let (auth, has_dpop) = seen.first().unwrap();
        assert!(
            auth.starts_with("DPoP "),
            "the check uses the DPoP scheme: {auth}"
        );
        assert!(*has_dpop, "the check carries a DPoP proof");
        let session = agent_session.unwrap();
        assert_eq!(session.user_email, "restored@example.com");
        assert!(session.expires_in_seconds > 0);
    }

    /// A `vouch login` that stores its session while the stored token is
    /// being checked keeps it: the older config-file session is not stored
    /// over it.
    #[cfg(all(unix, feature = "test-utils"))]
    #[tokio::test]
    async fn restore_keeps_a_session_stored_during_the_check() {
        let (agent_session, seen) = restore_from_config(
            serde_json::json!({
                "authenticated": true,
                "email": "restored@example.com",
                "expires_in_seconds": 3600,
                "device_name": null,
            }),
            true,
            true,
        )
        .await;

        assert_eq!(seen.len(), 1, "{seen:?}");
        assert_eq!(agent_session.unwrap().user_email, LOGIN_EMAIL);
    }

    /// A token the server no longer accepts is not handed to the agent.
    #[cfg(all(unix, feature = "test-utils"))]
    #[tokio::test]
    async fn rejected_stored_session_is_not_restored() {
        let (agent_session, seen) = restore_from_config(
            serde_json::json!({
                "authenticated": false,
                "email": null,
                "expires_in_seconds": null,
                "device_name": null,
            }),
            true,
            false,
        )
        .await;

        assert_eq!(seen.len(), 1, "{seen:?}");
        assert!(agent_session.is_none(), "{agent_session:?}");
    }

    /// With no agent running there is nothing to restore, so the token is
    /// not sent anywhere.
    #[cfg(all(unix, feature = "test-utils"))]
    #[tokio::test]
    async fn stored_session_is_not_checked_without_an_agent() {
        let (_, seen) = restore_from_config(
            serde_json::json!({
                "authenticated": true,
                "email": "restored@example.com",
                "expires_in_seconds": 3600,
                "device_name": null,
            }),
            false,
            false,
        )
        .await;

        assert!(seen.is_empty(), "{seen:?}");
    }
}
