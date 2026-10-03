// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cargo credential provider for private registries.
//!
//! This module implements Cargo's credential provider protocol (RFC 2730/3139).
//! It answers for two kinds of registry:
//!
//! - AWS CodeArtifact registries, through the Vouch → STS → CodeArtifact flow.
//! - Registries recorded by `vouch setup cargo --registry <name> --audience <aud>`,
//!   which receive a short-lived Vouch OIDC ID token whose `aud` is that audience.
//!
//! Every other registry, crates.io included, gets `url-not-supported` so Cargo
//! moves on to its next provider. The session access token never reaches Cargo.
//!
//! Protocol: Cargo communicates with credential providers via stdin/stdout JSON.
//! See: https://doc.rust-lang.org/cargo/reference/credential-provider-protocol.html
//!
//! Cargo runs `<credential-provider[0]> --cargo-plugin` and sends the remaining
//! `credential-provider` entries in the request's `args`, which this provider
//! ignores. `main.rs` dispatches `--cargo-plugin` here before clap parses.
//!
//! Usage: configure Cargo to use this provider for one registry in ~/.cargo/config.toml:
//!   [registries.my-registry]
//!   credential-provider = ["/path/to/vouch"]

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
use vouch_cli::{tr, tr_args, tr_eprintln};

use crate::config::Config;
use crate::integrations::aws::codeartifact;
use crate::server_url::{InsecureOptIn, ServerUrlError};
use crate::session;

/// Protocol version supported by this credential provider.
const PROTOCOL_VERSION: u32 = 1;

// ============================================================================
// Protocol Messages (matching Cargo's credential-provider-protocol)
// ============================================================================

/// Hello message sent from credential provider to Cargo.
/// Contains the protocol versions supported by this provider.
#[derive(Debug, Serialize)]
struct CredentialHello {
    /// Supported protocol versions.
    v: Vec<u32>,
}

/// Request from Cargo to credential provider.
///
/// The action fields (`kind`, `operation`, ...) sit beside `v` and `registry`
/// in the same JSON object, and unknown fields are ignored.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct CredentialRequest {
    /// Negotiated protocol version.
    v: u32,
    /// Registry information.
    registry: RegistryInfo,
    /// Action to perform.
    #[serde(flatten)]
    action: Action,
}

/// Registry information from Cargo.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RegistryInfo {
    /// Registry index URL, exactly as Cargo sends it (`sparse+https://…/` for sparse registries).
    index_url: String,
    /// Registry name from config (if any).
    name: Option<String>,
}

/// Action requested by Cargo.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum Action {
    /// Get a token for authentication.
    Get(Operation),
    /// Store/login with credentials.
    Login,
    /// Remove stored credentials.
    Logout,
    /// Unknown action (forward compatibility).
    #[serde(other)]
    Unknown,
}

/// Operation details for "get" action.
///
/// Vouch issues the same token for every operation, so the payloads are not read.
#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case")]
enum Operation {
    Read,
    Publish,
    Yank,
    Unyank,
    Owners,
    /// Unknown operation (forward compatibility).
    #[serde(other)]
    Unknown,
}

/// Successful response from credential provider to Cargo.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum CredentialResponse {
    /// Successful get response.
    Get {
        /// The authentication token.
        #[serde(serialize_with = "vouch_common::serialize_secret_string")]
        token: SecretString,
        /// Cache control for the token.
        #[serde(flatten)]
        cache: CacheControl,
        /// Whether the token is independent of the operation.
        operation_independent: bool,
    },
}

impl std::fmt::Debug for CredentialResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get {
                cache,
                operation_independent,
                ..
            } => f
                .debug_struct("CredentialResponse::Get")
                .field("token", &"[REDACTED]")
                .field("cache", cache)
                .field("operation_independent", operation_independent)
                .finish(),
        }
    }
}

/// Cache control for tokens.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "cache", rename_all = "kebab-case")]
enum CacheControl {
    /// Never cache the token.
    Never,
    /// Cache until a specific expiration time (Unix timestamp).
    Expires { expiration: i64 },
}

impl CacheControl {
    /// Cache an ID token until it expires.
    ///
    /// Uses the server-reported `expires_in` when present, else the token's own
    /// `exp` claim, else does not cache.
    fn for_id_token(token: &str, expires_in: Option<u64>, now: i64) -> Self {
        let from_expires_in = expires_in
            .and_then(|secs| i64::try_from(secs).ok())
            .and_then(|secs| now.checked_add(secs));
        match from_expires_in.or_else(|| parse_jwt_expiration(token)) {
            Some(expiration) => Self::Expires { expiration },
            None => Self::Never,
        }
    }
}

/// Error response from credential provider.
///
/// Cargo tries its next provider after `UrlNotSupported`; `Other` is fatal and
/// shown to the user. Cargo discards any message on the payload-free kinds.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum CredentialError {
    /// This provider does not handle the registry URL.
    UrlNotSupported,
    /// There is no credential to return; Cargo expects this for a logout, where
    /// nothing is stored, and moves on to its next provider.
    NotFound,
    /// This provider does not handle the action.
    OperationNotSupported,
    /// Any other failure.
    Other {
        message: String,
        #[serde(rename = "caused-by")]
        caused_by: Vec<String>,
    },
}

impl CredentialError {
    /// Report `error` with its outermost message first and each cause after it.
    fn other(error: &anyhow::Error) -> Self {
        let mut chain = error.chain().map(ToString::to_string);
        Self::Other {
            message: chain.next().unwrap_or_default(),
            caused_by: chain.collect(),
        }
    }
}

impl From<anyhow::Error> for CredentialError {
    fn from(error: anyhow::Error) -> Self {
        Self::other(&error)
    }
}

// ============================================================================
// Routing
// ============================================================================

/// The credential flow that answers for a registry Vouch serves.
#[derive(Debug)]
enum ServedRoute<'a> {
    /// AWS CodeArtifact: exchange the session through STS.
    CodeArtifact(codeartifact::CodeArtifactRegistry),
    /// Registry configured for Vouch: issue an ID token for this audience.
    Vouch { audience: &'a str },
}

impl<'a> ServedRoute<'a> {
    /// Route on the index URL Cargo sends, compared after normalization.
    ///
    /// `None` means Vouch does not serve the registry and Cargo should try its
    /// next provider.
    fn for_index_url(index_url: &str, config: &'a Config) -> Option<Self> {
        if let Some(registry) = codeartifact::parse_codeartifact_url(index_url) {
            return Some(Self::CodeArtifact(registry));
        }
        let audience = config.cargo_registry_audience(index_url)?;
        Some(Self::Vouch { audience })
    }
}

// ============================================================================
// Implementation
// ============================================================================

/// Run the Cargo credential provider.
///
/// This function implements Cargo's credential provider protocol:
/// 1. Send Hello message with supported versions
/// 2. Read CredentialRequest from stdin
/// 3. Handle the request and send the `Ok`/`Err` response to stdout
pub(crate) async fn run(opt_in: InsecureOptIn) -> Result<()> {
    // Send Hello message
    let hello = CredentialHello {
        v: vec![PROTOCOL_VERSION],
    };
    send_message(&hello)?;

    // Read request from stdin
    let request_line = read_line()?;
    let request: CredentialRequest = match serde_json::from_str(&request_line) {
        Ok(request) => request,
        Err(e) => {
            // Cargo shows the `Err` message to the user; without it Cargo
            // reports only a closed pipe.
            let error = anyhow::Error::from(e).context(tr!("err-failed-parse-credential-request"));
            send_message(&Err::<CredentialResponse, _>(CredentialError::other(
                &error,
            )))?;
            // Cargo waits for the child after reading the response and replaces
            // it with "credential process failed with status N" on a nonzero
            // exit, so a response line is always followed by exit 0.
            // https://github.com/rust-lang/cargo/blob/master/src/cargo/util/credential/process.rs
            return Ok(());
        }
    };

    // A corrupt Vouch config is reported as `other` rather than hidden behind
    // `url-not-supported`: the operator needs to see it.
    let outcome = match Config::load() {
        Ok(config) => handle_request(&request, &config, opt_in).await,
        Err(e) => Err(CredentialError::other(
            &e.context(tr!("err-failed-load-vouch-config")),
        )),
    };
    send_message(&outcome)
}

/// Answer one request. The registry is routed before the action, so a registry
/// Vouch does not serve gets `url-not-supported` for every action and Cargo
/// moves on to its next provider.
async fn handle_request(
    request: &CredentialRequest,
    config: &Config,
    opt_in: InsecureOptIn,
) -> Result<CredentialResponse, CredentialError> {
    if request.v != PROTOCOL_VERSION {
        return Err(CredentialError::from(anyhow::anyhow!(tr_args!(
            "cargo-err-unsupported-version",
            version = request.v.to_string(),
            expected = PROTOCOL_VERSION.to_string(),
        ))));
    }

    let Some(route) = ServedRoute::for_index_url(&request.registry.index_url, config) else {
        return Err(CredentialError::UrlNotSupported);
    };

    let registry_name = request
        .registry
        .name
        .as_deref()
        .unwrap_or(&request.registry.index_url);

    // Vouch manages authentication via `vouch login`, not `cargo login`. This
    // is consistent with the AWS/SSH integrations, where the user
    // authenticates with Vouch once and native tools use credential helpers.
    match &request.action {
        Action::Get(Operation::Unknown) | Action::Unknown => {
            Err(CredentialError::OperationNotSupported)
        }
        Action::Get(
            Operation::Read
            | Operation::Publish
            | Operation::Yank
            | Operation::Unyank
            | Operation::Owners,
        ) => handle_get(route, opt_in).await,
        Action::Login => {
            eprintln!();
            tr_eprintln!("credential-cargo-login-needed", registry = registry_name);
            Err(CredentialError::OperationNotSupported)
        }
        Action::Logout => {
            tr_eprintln!("credential-cargo-logout", registry = registry_name);
            Err(CredentialError::NotFound)
        }
    }
}

/// Handle "get" action - return authentication token.
async fn handle_get(
    route: ServedRoute<'_>,
    opt_in: InsecureOptIn,
) -> Result<CredentialResponse, CredentialError> {
    // Resolve session to get server URL (tries agent first, then config)
    let resolved = session::resolve_session(opt_in).await.map_err(|e| {
        // A refused server URL is configured, just not allowed for this
        // invocation; pass its own message on rather than "not configured".
        if ServerUrlError::is_in(&e) {
            e
        } else {
            anyhow::anyhow!(tr!("cargo-err-not-enrolled"))
        }
    })?;
    let server = resolved.server_url;

    match route {
        ServedRoute::CodeArtifact(ca_registry) => {
            let target = super::codeartifact::CodeArtifactTarget::new(
                ca_registry.domain,
                ca_registry.domain_owner,
                ca_registry.region,
            );
            let result = super::codeartifact::get_token(&server, &target)
                .await
                .context(tr!("cargo-err-codeartifact"))?;
            Ok(CredentialResponse::Get {
                token: result.authorization_token,
                cache: CacheControl::Expires {
                    expiration: result.expiration,
                },
                operation_independent: true,
            })
        }
        ServedRoute::Vouch { audience } => {
            let (token, expires_in) = super::wif::fetch_assertion(&server, Some(audience))
                .await
                .context(tr!("cargo-err-id-token"))?;
            let cache = CacheControl::for_id_token(
                token.expose_secret(),
                expires_in,
                jiff::Timestamp::now().as_second(),
            );
            Ok(CredentialResponse::Get {
                token,
                cache,
                // The ID token names no operation, so it serves read, publish, yank, etc.
                operation_independent: true,
            })
        }
    }
}

/// Send a JSON message to stdout.
fn send_message<T: Serialize>(message: &T) -> Result<()> {
    let json = serde_json::to_string(message).context(tr!("err-failed-serialize-message"))?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{json}")?;
    out.flush()?;
    Ok(())
}

/// Read a line from stdin.
fn read_line() -> Result<String> {
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .context(tr!("err-failed-read-from-stdin"))?;
    Ok(line.trim().to_string())
}

/// Parse JWT expiration time (exp claim).
/// Returns the expiration as Unix timestamp, or None if parsing fails.
fn parse_jwt_expiration(token: &str) -> Option<i64> {
    // JWT format: header.payload.signature
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    // Decode the payload (second part)
    use base64::Engine;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts.get(1)?)
        .ok()?;

    // Parse as JSON
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;

    // Get expiration
    claims.get("exp")?.as_i64()
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use base64::Engine;

    // Wire-format tests. The protocol is specified at
    // https://doc.rust-lang.org/cargo/reference/credential-provider-protocol.html
    // and the expected JSON below is copied from cargo-credential's own tests:
    // https://github.com/rust-lang/cargo/blob/master/credential/cargo-credential/src/lib.rs
    // https://github.com/rust-lang/cargo/blob/master/credential/cargo-credential/src/error.rs

    fn request(json: &str) -> CredentialRequest {
        serde_json::from_str(json).unwrap()
    }

    fn config_with(index_url: &str, audience: &str) -> Config {
        let mut config = Config::default();
        config.set_cargo_registry_audience(index_url, audience);
        config
    }

    fn encode<T: Serialize>(message: &T) -> String {
        serde_json::to_string(message).unwrap()
    }

    fn get_response(cache: CacheControl) -> Result<CredentialResponse, CredentialError> {
        Ok(CredentialResponse::Get {
            token: SecretString::from("value".to_string()),
            cache,
            operation_independent: true,
        })
    }

    fn jwt_with_payload(payload: &str) -> String {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
        format!("e30.{encoded}.sig")
    }

    #[test]
    fn test_hello_serialization() {
        let hello = CredentialHello { v: vec![1] };
        let json = serde_json::to_string(&hello).unwrap();
        assert_eq!(json, r#"{"v":[1]}"#);
    }

    #[test]
    fn test_get_response_never_cache_serialization() {
        let json = serde_json::to_string(&get_response(CacheControl::Never)).unwrap();
        assert_eq!(
            json,
            r#"{"Ok":{"kind":"get","token":"value","cache":"never","operation_independent":true}}"#
        );
    }

    #[test]
    fn test_get_response_expires_serialization() {
        let response = get_response(CacheControl::Expires {
            expiration: 1_693_928_537,
        });
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(
            json,
            r#"{"Ok":{"kind":"get","token":"value","cache":"expires","expiration":1693928537,"operation_independent":true}}"#
        );
    }

    #[test]
    fn test_cache_control_serialization() {
        let json = serde_json::to_string(&CacheControl::Expires {
            expiration: 1_693_928_537,
        })
        .unwrap();
        assert_eq!(json, r#"{"cache":"expires","expiration":1693928537}"#);
        let json = serde_json::to_string(&CacheControl::Never).unwrap();
        assert_eq!(json, r#"{"cache":"never"}"#);
    }

    #[test]
    fn test_other_error_serialization() {
        let error = anyhow::anyhow!("E1").context("E2").context("E3");
        let json = serde_json::to_string(&Err::<(), _>(CredentialError::from(error))).unwrap();
        assert_eq!(
            json,
            r#"{"Err":{"kind":"other","message":"E3","caused-by":["E2","E1"]}}"#
        );
    }

    #[test]
    fn test_payload_free_errors_serialization() {
        let json = serde_json::to_string(&CredentialError::UrlNotSupported).unwrap();
        assert_eq!(json, r#"{"kind":"url-not-supported"}"#);
        let json = serde_json::to_string(&CredentialError::OperationNotSupported).unwrap();
        assert_eq!(json, r#"{"kind":"operation-not-supported"}"#);
    }

    #[test]
    fn test_response_debug_redacts_token() {
        let debug = format!("{:?}", get_response(CacheControl::Never).unwrap());
        assert!(!debug.contains("value"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn test_cargo_get_request_deserialization() {
        let json = r#"{"v":1,"registry":{"index-url":"url"},"kind":"get","operation":"owners","name":"pkg"}"#;
        let request: CredentialRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.v, 1);
        assert_eq!(request.registry.index_url, "url");
        assert!(matches!(request.action, Action::Get(Operation::Owners)));
    }

    #[test]
    fn test_request_ignores_unknown_fields() {
        let json = r#"{"v":1,"registry":{"index-url":"url","extra-2":1},"kind":"get","operation":"read","extra-1":true}"#;
        let request: CredentialRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(request.action, Action::Get(Operation::Read)));
    }

    #[test]
    fn test_request_with_name_args_and_headers() {
        let json = r#"{
            "v": 1,
            "registry": {
                "index-url": "sparse+https://index.crates.io/",
                "name": "crates-io",
                "headers": ["WWW-Authenticate: Cargo login_url=\"https://example.com\""]
            },
            "kind": "get",
            "operation": "read",
            "args": ["--flag"]
        }"#;
        let request: CredentialRequest = serde_json::from_str(json).unwrap();
        assert_eq!(
            request.registry.index_url,
            "sparse+https://index.crates.io/"
        );
        assert_eq!(request.registry.name.as_deref(), Some("crates-io"));
    }

    #[test]
    fn test_publish_operation_deserialization() {
        let json = r#"{
            "v": 1,
            "registry": {"index-url": "https://example.com/"},
            "kind": "get",
            "operation": "publish",
            "name": "my-crate",
            "vers": "1.0.0",
            "cksum": "abc123"
        }"#;
        let request: CredentialRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(request.action, Action::Get(Operation::Publish)));
    }

    #[test]
    fn test_login_with_options_deserialization() {
        let json = r#"{
            "v": 1,
            "registry": {"index-url": "https://example.com/"},
            "kind": "login",
            "token": "secret-token",
            "login-url": "https://example.com/login"
        }"#;
        let request: CredentialRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(request.action, Action::Login));
    }

    #[test]
    fn test_logout_deserialization() {
        let json = r#"{"v":1,"registry":{"index-url":"url"},"kind":"logout"}"#;
        let request: CredentialRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(request.action, Action::Logout));
    }

    #[test]
    fn test_unknown_action_kind_deserialization() {
        let json = r#"{"v":1,"registry":{"index-url":"url"},"kind":"rotate"}"#;
        let request: CredentialRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(request.action, Action::Unknown));
    }

    #[test]
    fn test_unknown_operation_deserialization() {
        let json = r#"{"v":1,"registry":{"index-url":"url"},"kind":"get","operation":"audit"}"#;
        let request: CredentialRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(request.action, Action::Get(Operation::Unknown)));
    }

    #[test]
    fn test_request_without_registry_is_rejected() {
        let json = r#"{"v":1,"kind":"get","operation":"read"}"#;
        assert!(serde_json::from_str::<CredentialRequest>(json).is_err());
    }

    #[test]
    fn test_route_codeartifact_url() {
        let config = Config::default();
        let url = "sparse+https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/cargo/my-repo/";
        assert!(matches!(
            ServedRoute::for_index_url(url, &config),
            Some(ServedRoute::CodeArtifact(_))
        ));
    }

    #[test]
    fn test_route_configured_registry_uses_its_audience() {
        let mut config = Config::default();
        config.set_cargo_registry_audience("sparse+https://crates.example.com/", "crates-example");
        match ServedRoute::for_index_url("sparse+https://crates.example.com/", &config) {
            Some(ServedRoute::Vouch { audience }) => assert_eq!(audience, "crates-example"),
            other => panic!("expected Vouch route, got {other:?}"),
        }
    }

    #[test]
    fn test_route_crates_io_is_unsupported() {
        let mut config = Config::default();
        config.set_cargo_registry_audience("sparse+https://crates.example.com/", "crates-example");
        assert!(ServedRoute::for_index_url("sparse+https://index.crates.io/", &config).is_none());
    }

    #[test]
    fn test_route_does_not_match_a_different_index() {
        let config = config_with("sparse+https://crates.example.com/", "crates-example");
        for url in [
            "https://crates.example.com/",
            "sparse+https://crates.example.com/other/",
            "sparse+https://other.example.com/",
        ] {
            assert!(
                ServedRoute::for_index_url(url, &config).is_none(),
                "{url} must not match"
            );
        }
    }

    #[test]
    fn test_route_blank_audience_is_unsupported() {
        let config = config_with("sparse+https://crates.example.com/", "   ");
        assert!(
            ServedRoute::for_index_url("sparse+https://crates.example.com/", &config).is_none()
        );
    }

    #[test]
    fn test_route_matches_after_normalization() {
        let config = config_with("sparse+https://crates.example.com/", "crates-example");
        for url in [
            "sparse+https://CRATES.example.com/",
            "sparse+https://crates.example.com",
        ] {
            assert!(
                matches!(
                    ServedRoute::for_index_url(url, &config),
                    Some(ServedRoute::Vouch { .. })
                ),
                "{url}"
            );
        }
    }

    // Routing precedes the action: a registry Vouch does not serve gets
    // `url-not-supported` for every action, and only a served registry reaches
    // the action-specific answers. None of these reach a session lookup.

    const UNLISTED: &str = r#""registry":{"index-url":"sparse+https://index.crates.io/"}"#;
    const LISTED: &str = r#""registry":{"index-url":"sparse+https://crates.example.com/"}"#;

    async fn answer(registry: &str, rest: &str, config: &Config) -> String {
        let request = request(&format!(r#"{{"v":1,{registry},{rest}}}"#));
        let outcome = handle_request(&request, config, InsecureOptIn::Env).await;
        encode(&outcome)
    }

    #[tokio::test]
    async fn test_unlisted_registry_gets_url_not_supported_for_every_action() {
        let config = config_with("sparse+https://crates.example.com/", "crates-example");
        for rest in [
            r#""kind":"get","operation":"read""#,
            r#""kind":"get","operation":"audit""#,
            r#""kind":"login""#,
            r#""kind":"logout""#,
            r#""kind":"rotate""#,
        ] {
            assert_eq!(
                answer(UNLISTED, rest, &config).await,
                r#"{"Err":{"kind":"url-not-supported"}}"#,
                "{rest}"
            );
        }
    }

    // Cargo expects `not-found` for a logout, where there is nothing to erase:
    // https://doc.rust-lang.org/cargo/reference/credential-provider-protocol.html
    #[tokio::test]
    async fn test_listed_registry_logout_is_not_found() {
        let config = config_with("sparse+https://crates.example.com/", "crates-example");
        assert_eq!(
            answer(LISTED, r#""kind":"logout""#, &config).await,
            r#"{"Err":{"kind":"not-found"}}"#
        );
    }

    #[tokio::test]
    async fn test_listed_registry_rejects_unsupported_actions() {
        let config = config_with("sparse+https://crates.example.com/", "crates-example");
        for rest in [
            r#""kind":"get","operation":"audit""#,
            r#""kind":"login""#,
            r#""kind":"rotate""#,
        ] {
            assert_eq!(
                answer(LISTED, rest, &config).await,
                r#"{"Err":{"kind":"operation-not-supported"}}"#,
                "{rest}"
            );
        }
    }

    #[tokio::test]
    async fn test_unsupported_protocol_version_is_other() {
        let config = Config::default();
        let request =
            request(r#"{"v":2,"registry":{"index-url":"url"},"kind":"get","operation":"read"}"#);
        let outcome = handle_request(&request, &config, InsecureOptIn::Env).await;
        let json = encode(&outcome);
        assert!(
            json.starts_with(r#"{"Err":{"kind":"other","message":""#),
            "{json}"
        );
        assert!(json.contains(r#""caused-by":[]"#), "{json}");
    }

    #[tokio::test]
    async fn test_legacy_provider_args_are_ignored() {
        // Configs written before `--cargo-plugin` dispatch list
        // `["vouch","credential","cargo","--"]`; Cargo delivers the extra
        // entries in the request's `args`, which are not read.
        let config = Config::default();
        let json = answer(
            UNLISTED,
            r#""kind":"get","operation":"read","args":["credential","cargo","--"]"#,
            &config,
        )
        .await;
        assert_eq!(json, r#"{"Err":{"kind":"url-not-supported"}}"#);
    }

    #[test]
    fn test_id_token_cache_prefers_expires_in() {
        let token = jwt_with_payload(r#"{"exp":9999}"#);
        assert_eq!(
            CacheControl::for_id_token(&token, Some(600), 1_000),
            CacheControl::Expires { expiration: 1_600 }
        );
    }

    #[test]
    fn test_id_token_cache_falls_back_to_exp_claim() {
        let token = jwt_with_payload(r#"{"exp":9999}"#);
        assert_eq!(
            CacheControl::for_id_token(&token, None, 1_000),
            CacheControl::Expires { expiration: 9_999 }
        );
    }

    #[test]
    fn test_id_token_cache_without_any_expiry_is_never() {
        assert_eq!(
            CacheControl::for_id_token("not-a-jwt", None, 1_000),
            CacheControl::Never
        );
        let token = jwt_with_payload(r#"{"sub":"u"}"#);
        assert_eq!(
            CacheControl::for_id_token(&token, None, 1_000),
            CacheControl::Never
        );
    }

    #[test]
    fn test_id_token_cache_overflowing_expires_in_falls_back() {
        let token = jwt_with_payload(r#"{"exp":9999}"#);
        assert_eq!(
            CacheControl::for_id_token(&token, Some(u64::MAX), 1_000),
            CacheControl::Expires { expiration: 9_999 }
        );
        assert_eq!(
            CacheControl::for_id_token(&token, Some(1), i64::MAX),
            CacheControl::Expires { expiration: 9_999 }
        );
    }
}
