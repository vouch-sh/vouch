// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cargo credential provider for AWS CodeArtifact registries.
//!
//! This module implements Cargo's credential provider protocol (RFC 2730/3139).
//! It answers for CodeArtifact registries through the Vouch → STS → CodeArtifact
//! flow. Every other registry gets `url-not-supported`, so Cargo moves on to its
//! next provider and the Vouch session token never reaches Cargo.
//!
//! Protocol: Cargo communicates with credential providers via stdin/stdout JSON.
//! See: <https://doc.rust-lang.org/cargo/reference/credential-provider-protocol.html>
//!
//! Cargo runs `<credential-provider[0]> --cargo-plugin` and nothing else; the
//! remaining `credential-provider` entries arrive in the request's `args`
//! field, which this provider ignores. `main.rs` dispatches `--cargo-plugin`
//! here before clap parses.
//!
//! Usage: configure Cargo to use this provider for one registry in
//! `~/.cargo/config.toml`:
//!
//! ```toml
//! [registries.my-registry]
//! credential-provider = ["/path/to/vouch"]
//! ```

use anyhow::{Context, Result};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
use vouch_cli::tr;

use crate::integrations::aws::codeartifact::{self, CodeArtifactToken};
use crate::server_url::InsecureOptIn;
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
/// in the same JSON object. Fields this provider does not read, such as `args`
/// and `registry.headers`, are ignored.
#[derive(Debug, Deserialize)]
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
    /// Registry index URL, as Cargo serializes it (`sparse+https://…/` for
    /// sparse registries).
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
/// Vouch issues the same token for every operation, so the operation payloads
/// (`name`, `vers`, `cksum`) are not read.
#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case")]
enum Operation {
    /// Reading from registry (cargo fetch, build, etc).
    Read,
    /// Publishing a crate.
    Publish,
    /// Yanking a crate version.
    Yank,
    /// Unyanking a crate version.
    Unyank,
    /// Managing crate owners.
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
    /// Successful logout response.
    Logout,
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
            Self::Logout => f.debug_struct("CredentialResponse::Logout").finish(),
        }
    }
}

/// Cache control for tokens.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "cache", rename_all = "kebab-case")]
enum CacheControl {
    /// Cache until a specific expiration time (Unix timestamp).
    Expires { expiration: i64 },
}

/// Error response from credential provider to Cargo.
///
/// Cargo tries its next provider after `UrlNotSupported` and `NotFound`; the
/// other kinds are fatal. Cargo discards any message on the payload-free kinds,
/// so a failure the user needs to read is reported as `Other`.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum CredentialError {
    /// This provider does not handle the registry URL.
    UrlNotSupported,
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

// ============================================================================
// Implementation
// ============================================================================

/// Run the Cargo credential provider.
///
/// This function implements Cargo's credential provider protocol:
/// 1. Send Hello message with supported versions
/// 2. Read CredentialRequest from stdin
/// 3. Handle the request and send the `Ok`/`Err` response to stdout
///
/// A response line is always followed by a successful return, including an
/// `Err` response. Cargo replaces the response with "credential process failed
/// with status N" when the child exits nonzero, so the exit status must be 0
/// for the user to see the message.
///
/// `init` sets up process-wide services (locale, DNS, keyring). It runs after
/// the hello so a failure reaches Cargo as an `other` error instead of
/// "failed to deserialize hello". A failure to read the request is answered the
/// same way.
pub(crate) async fn run(opt_in: InsecureOptIn, init: impl FnOnce() -> Result<()>) -> Result<()> {
    send_message(&CredentialHello {
        v: vec![PROTOCOL_VERSION],
    })?;

    send_message(&answer(opt_in, init).await)
}

/// Initialize, read the request line, and answer it. Every failure along the
/// way, including a broken stdin, becomes the `Err` response.
async fn answer(
    opt_in: InsecureOptIn,
    init: impl FnOnce() -> Result<()>,
) -> Result<CredentialResponse, CredentialError> {
    init().map_err(|e| CredentialError::other(&e))?;
    let request_line = read_line().map_err(|e| CredentialError::other(&e))?;
    let request: CredentialRequest = serde_json::from_str(&request_line)
        .with_context(|| tr!("err-failed-parse-credential-request"))
        .map_err(|e| CredentialError::other(&e))?;
    let fetch = async |registry: &codeartifact::CodeArtifactRegistry| {
        fetch_codeartifact_token(registry, opt_in).await
    };
    handle_request(&request, fetch).await
}

/// Answer one request. The registry is routed before the action, so a registry
/// Vouch does not serve gets `url-not-supported` for every action.
///
/// `fetch` mints the CodeArtifact token for a `get`; it is a parameter so tests
/// can supply a result without a session or network.
async fn handle_request(
    request: &CredentialRequest,
    fetch: impl AsyncFnOnce(&codeartifact::CodeArtifactRegistry) -> Result<CodeArtifactToken>,
) -> Result<CredentialResponse, CredentialError> {
    if request.v != PROTOCOL_VERSION {
        return Err(CredentialError::other(&anyhow::anyhow!(
            "unsupported protocol version {}, expected {PROTOCOL_VERSION}",
            request.v
        )));
    }

    // The parser accepts only HTTPS indexes: Cargo sends credentials to
    // `sparse+http` registries too, and a token minted for one would travel in
    // the clear.
    let Some(registry) = codeartifact::parse_codeartifact_url(&request.registry.index_url) else {
        return Err(CredentialError::UrlNotSupported);
    };

    let registry_name = request
        .registry
        .name
        .as_deref()
        .unwrap_or(&request.registry.index_url);

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
        ) => {
            // Mint the token through the Vouch -> STS -> CodeArtifact flow.
            let token = fetch(&registry)
                .await
                .map_err(|e| CredentialError::other(&e))?;
            Ok(CredentialResponse::Get {
                token: token.authorization_token,
                cache: CacheControl::Expires {
                    expiration: token.expiration,
                },
                operation_independent: true,
            })
        }
        // Vouch manages authentication via `vouch login`, not `cargo login`.
        // This is consistent with AWS/SSH integrations where the user
        // authenticates with Vouch once, and native tools use credential
        // helpers.
        Action::Login => {
            eprintln!();
            vouch_cli::tr_eprintln!("credential-cargo-login-needed", registry = registry_name);
            Err(CredentialError::OperationNotSupported)
        }
        // Vouch's session is not cleared on `cargo logout`, as the user might
        // want to keep using Vouch for other purposes. Just acknowledge.
        Action::Logout => {
            vouch_cli::tr_eprintln!("credential-cargo-logout", registry = registry_name);
            Ok(CredentialResponse::Logout)
        }
    }
}

/// Mint the CodeArtifact token through the Vouch session.
///
/// Errors keep their own message: it names the right next step (`vouch login`
/// for a lapsed session, `vouch enroll` when nothing is configured, the
/// refusal reason for a rejected server URL).
async fn fetch_codeartifact_token(
    registry: &codeartifact::CodeArtifactRegistry,
    opt_in: InsecureOptIn,
) -> Result<CodeArtifactToken> {
    // Resolve session to get server URL (tries agent first, then config)
    let resolved = session::resolve_session(opt_in).await?;

    // Use the shared CodeArtifact credential flow
    let target = super::codeartifact::CodeArtifactTarget::new(
        registry.domain.clone(),
        registry.domain_owner.clone(),
        registry.region.clone(),
    );
    super::codeartifact::get_token(&resolved.server_url, &target)
        .await
        .context("CodeArtifact authentication failed")
}

/// Send a JSON message to stdout.
fn send_message<T: Serialize>(message: &T) -> Result<()> {
    let json =
        serde_json::to_string(message).with_context(|| tr!("err-failed-serialize-message"))?;
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
        .with_context(|| tr!("err-failed-read-from-stdin"))?;
    Ok(line.trim().to_string())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    const CODEARTIFACT_INDEX: &str = "sparse+https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/cargo/my-repo/";

    /// Fetcher for tests where reaching the token flow is itself a failure.
    async fn unexpected_fetch(
        _registry: &codeartifact::CodeArtifactRegistry,
    ) -> Result<CodeArtifactToken> {
        Err(anyhow::anyhow!("fetch must not be called"))
    }

    fn read_request(registry_index: &str) -> CredentialRequest {
        request(&format!(
            r#"{{"v":1,"kind":"get","operation":"read","registry":{{"index-url":"{registry_index}"}}}}"#
        ))
    }

    fn request(json: &str) -> CredentialRequest {
        serde_json::from_str(json).unwrap()
    }

    fn json_of<T: Serialize>(value: &T) -> String {
        serde_json::to_string(value).unwrap()
    }

    // Cargo credential provider protocol, "Credential hello".
    // https://doc.rust-lang.org/cargo/reference/credential-provider-protocol.html
    #[test]
    fn test_hello_serialization() {
        let hello = CredentialHello { v: vec![1] };
        assert_eq!(json_of(&hello), r#"{"v":[1]}"#);
    }

    // cargo-credential `credential_request` test: the action fields are
    // flattened beside `v` and `registry`, and unknown fields are ignored.
    // https://github.com/rust-lang/cargo/blob/master/credential/cargo-credential/src/lib.rs
    #[test]
    fn test_cargo_owners_request_deserialization() {
        let req = request(
            r#"{"extra-1":true,"v":1,"registry":{"index-url":"url","extra-2":true},"kind":"get","operation":"owners","name":"pkg","args":[]}"#,
        );
        assert_eq!(req.v, 1);
        assert_eq!(req.registry.index_url, "url");
        assert!(matches!(req.action, Action::Get(Operation::Owners)));
    }

    // Credential provider protocol, "Read request".
    #[test]
    fn test_doc_read_request_deserialization() {
        let req = request(
            r#"{"v":1,"kind":"get","operation":"read","registry":{"index-url":"sparse+https://registry-url/index/","name":"my-registry"},"args":[]}"#,
        );
        assert_eq!(req.registry.index_url, "sparse+https://registry-url/index/");
        assert_eq!(req.registry.name.as_deref(), Some("my-registry"));
        assert!(matches!(req.action, Action::Get(Operation::Read)));
    }

    // Credential provider protocol, "Publish request".
    #[test]
    fn test_doc_publish_request_deserialization() {
        let req = request(
            r#"{"v":1,"kind":"get","operation":"publish","name":"sample","vers":"0.1.0","cksum":"...","registry":{"index-url":"sparse+https://registry-url/index/","name":"my-registry"},"args":[]}"#,
        );
        assert!(matches!(req.action, Action::Get(Operation::Publish)));
    }

    // Credential provider protocol, "Login request".
    #[test]
    fn test_doc_login_request_deserialization() {
        let req = request(
            r#"{"v":1,"kind":"login","registry":{"index-url":"sparse+https://registry-url/index/","name":"my-registry"},"token":"<the token value>","login-url":"http://registry-url/login","args":[]}"#,
        );
        assert!(matches!(req.action, Action::Login));
    }

    // cargo-credential `credential_request_logout` test.
    #[test]
    fn test_cargo_logout_request_deserialization() {
        let req = request(
            r#"{"v":1,"registry":{"index-url":"url"},"kind":"logout","extra-1":true,"args":[]}"#,
        );
        assert!(matches!(req.action, Action::Logout));
    }

    // cargo-credential `credential_request_unknown` test.
    #[test]
    fn test_cargo_unknown_kind_request_deserialization() {
        let req = request(
            r#"{"v":1,"registry":{"index-url":""},"kind":"unexpected-1","extra-1":true,"args":[]}"#,
        );
        assert!(matches!(req.action, Action::Unknown));
    }

    // Registry information: `headers` is optional and unused.
    #[test]
    fn test_doc_registry_info_with_headers_deserialization() {
        let req = request(
            r#"{"v":1,"kind":"get","operation":"read","registry":{"index-url":"https://github.com/rust-lang/crates.io-index","name":"crates-io","headers":["WWW-Authenticate: cargo"]}}"#,
        );
        assert_eq!(req.registry.name.as_deref(), Some("crates-io"));
    }

    #[test]
    fn test_unknown_operation_deserialization() {
        let req = request(
            r#"{"v":1,"kind":"get","operation":"frobnicate","registry":{"index-url":"url"}}"#,
        );
        assert!(matches!(req.action, Action::Get(Operation::Unknown)));
    }

    #[test]
    fn test_request_without_kind_is_rejected() {
        let result = serde_json::from_str::<CredentialRequest>(
            r#"{"v":1,"registry":{"index-url":"url"},"args":[]}"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_request_without_registry_is_rejected() {
        let result = serde_json::from_str::<CredentialRequest>(r#"{"v":1,"kind":"logout"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_request_with_wrong_version_type_is_rejected() {
        let result = serde_json::from_str::<CredentialRequest>(
            r#"{"v":"1","registry":{"index-url":"url"},"kind":"logout"}"#,
        );
        assert!(result.is_err());
    }

    // cargo-credential `cache_control` and `credential_response` tests: the
    // cache fields are flattened into the get response, and
    // `operation_independent` keeps its underscore.
    #[test]
    fn test_get_response_serialization() {
        let response = CredentialResponse::Get {
            token: SecretString::from("value".to_string()),
            cache: CacheControl::Expires {
                expiration: 1_693_928_537,
            },
            operation_independent: true,
        };
        assert_eq!(
            json_of(&response),
            r#"{"kind":"get","token":"value","cache":"expires","expiration":1693928537,"operation_independent":true}"#
        );
    }

    // Credential provider protocol, "Get success response": wrapped in `Ok`.
    #[test]
    fn test_ok_response_is_wrapped() {
        let outcome: Result<CredentialResponse, CredentialError> = Ok(CredentialResponse::Logout);
        assert_eq!(json_of(&outcome), r#"{"Ok":{"kind":"logout"}}"#);
    }

    // Credential provider protocol, "Failure response (URL not supported)".
    #[test]
    fn test_url_not_supported_is_wrapped() {
        let outcome: Result<CredentialResponse, CredentialError> =
            Err(CredentialError::UrlNotSupported);
        assert_eq!(json_of(&outcome), r#"{"Err":{"kind":"url-not-supported"}}"#);
    }

    // Credential provider protocol, "Failure response (operation not supported)".
    #[test]
    fn test_operation_not_supported_is_wrapped() {
        let outcome: Result<CredentialResponse, CredentialError> =
            Err(CredentialError::OperationNotSupported);
        assert_eq!(
            json_of(&outcome),
            r#"{"Err":{"kind":"operation-not-supported"}}"#
        );
    }

    // cargo-credential error.rs `roundtrip` test: `other` carries the
    // outermost message and the causes, outermost first.
    #[test]
    fn test_other_error_serialization_matches_cargo() {
        let error = anyhow::anyhow!("inner").context("middle").context("outer");
        let outcome: Result<CredentialResponse, CredentialError> =
            Err(CredentialError::other(&error));
        assert_eq!(
            json_of(&outcome),
            r#"{"Err":{"kind":"other","message":"outer","caused-by":["middle","inner"]}}"#
        );
    }

    #[tokio::test]
    async fn test_non_codeartifact_registry_is_url_not_supported() {
        for json in [
            r#"{"v":1,"kind":"get","operation":"read","registry":{"index-url":"sparse+https://index.crates.io/"}}"#,
            r#"{"v":1,"kind":"login","registry":{"index-url":"https://example.com/index"}}"#,
            r#"{"v":1,"kind":"logout","registry":{"index-url":"https://example.com/index"}}"#,
            r#"{"v":1,"kind":"unexpected","registry":{"index-url":"https://example.com/index"}}"#,
        ] {
            let outcome = handle_request(&request(json), unexpected_fetch).await;
            assert!(
                matches!(outcome, Err(CredentialError::UrlNotSupported)),
                "{json}: {outcome:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_unknown_actions_on_codeartifact_are_operation_not_supported() {
        for action in [
            r#""kind":"get","operation":"frobnicate""#,
            r#""kind":"unexpected""#,
            r#""kind":"login""#,
        ] {
            let json =
                format!(r#"{{"v":1,{action},"registry":{{"index-url":"{CODEARTIFACT_INDEX}"}}}}"#);
            let outcome = handle_request(&request(&json), unexpected_fetch).await;
            assert!(
                matches!(outcome, Err(CredentialError::OperationNotSupported)),
                "{json}: {outcome:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_logout_on_codeartifact_acknowledges() {
        let json = format!(
            r#"{{"v":1,"kind":"logout","registry":{{"index-url":"{CODEARTIFACT_INDEX}"}}}}"#
        );
        let outcome = handle_request(&request(&json), unexpected_fetch).await;
        assert!(matches!(outcome, Ok(CredentialResponse::Logout)));
    }

    #[tokio::test]
    async fn test_wrong_protocol_version_is_other() {
        let outcome = handle_request(
            &request(r#"{"v":2,"kind":"logout","registry":{"index-url":"url"}}"#),
            unexpected_fetch,
        )
        .await;
        match outcome {
            Err(CredentialError::Other { message, .. }) => {
                assert_eq!(message, "unsupported protocol version 2, expected 1");
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    // Cargo sends credentials to `sparse+http` registries, so plain-HTTP
    // CodeArtifact lookalikes must not get a token.
    #[tokio::test]
    async fn test_plain_http_codeartifact_is_url_not_supported() {
        for index in [
            "sparse+http://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/cargo/r/",
            "http://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/cargo/r/",
            "my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/cargo/r/",
        ] {
            let outcome = handle_request(&read_request(index), unexpected_fetch).await;
            assert!(
                matches!(outcome, Err(CredentialError::UrlNotSupported)),
                "{index}: {outcome:?}"
            );
        }
    }

    // A failed token flow is `other` carrying the error and its causes; Cargo
    // drops the message of `not-found`.
    #[tokio::test]
    async fn test_token_failure_is_other_with_causes() {
        let outcome = handle_request(
            &read_request(CODEARTIFACT_INDEX),
            async |_: &codeartifact::CodeArtifactRegistry| -> Result<CodeArtifactToken> {
                Err(anyhow::anyhow!("boom").context("CodeArtifact authentication failed"))
            },
        )
        .await;
        match outcome {
            Err(CredentialError::Other { message, caused_by }) => {
                assert_eq!(message, "CodeArtifact authentication failed");
                assert_eq!(caused_by, ["boom"]);
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    // A lapsed session's own message names the right next step and must reach
    // the user unchanged.
    #[tokio::test]
    async fn test_session_error_message_is_passed_through() {
        let outcome = handle_request(
            &read_request(CODEARTIFACT_INDEX),
            async |_: &codeartifact::CodeArtifactRegistry| -> Result<CodeArtifactToken> {
                Err(anyhow::anyhow!("no session token - run 'vouch login'"))
            },
        )
        .await;
        match outcome {
            Err(CredentialError::Other { message, .. }) => {
                assert_eq!(message, "no session token - run 'vouch login'");
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    // Credential provider protocol, "Get success response".
    #[tokio::test]
    async fn test_token_success_is_get_expires() {
        let outcome = handle_request(
            &read_request(CODEARTIFACT_INDEX),
            async |registry: &codeartifact::CodeArtifactRegistry| -> Result<CodeArtifactToken> {
                assert_eq!(registry.domain, "my-domain");
                assert_eq!(registry.domain_owner, "123456789012");
                assert_eq!(registry.region, "us-east-1");
                Ok(CodeArtifactToken {
                    authorization_token: SecretString::from("tok".to_string()),
                    expiration: 1_693_942_857,
                })
            },
        )
        .await;
        assert_eq!(
            json_of(&outcome),
            r#"{"Ok":{"kind":"get","token":"tok","cache":"expires","expiration":1693942857,"operation_independent":true}}"#
        );
    }
}
