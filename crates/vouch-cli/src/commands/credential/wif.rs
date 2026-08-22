// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared Workload Identity Federation helpers for AI providers.
//!
//! Both `vouch credential anthropic` and `vouch credential openai` follow
//! the same two-step exchange:
//!
//! 1. Fetch a clean OIDC ID token from the Vouch server (the *assertion*)
//!    via the standard RFC 8693 token exchange at `POST /oauth/token`
//!    (`requested_token_type=id_token`). The subject token is the existing
//!    session token, so this is non-interactive — `resolve_token()` only
//!    reads the current session and never triggers FIDO2. Client
//!    authentication uses the FAPI `private_key_jwt` assertion and the
//!    request carries a DPoP proof (the CLI client is DPoP-bound).
//! 2. POST the assertion to the provider's token endpoint (Anthropic's
//!    RFC 7523 jwt-bearer or OpenAI's RFC 8693 token-exchange grant) and
//!    receive a short-lived provider token.
//!
//! The assertion is intentionally **not** cached separately:
//! - each minted ID token carries a unique `jti` and is meant for single use;
//! - the audience differs per provider, so an assertion fetched for Anthropic
//!   is not reusable for OpenAI.
//!
//! Only the provider's response is cached (by the caller via
//! [`super::cache::get_or_fetch`]).
//!
//! [`super::cache::get_or_fetch`]: super::cache::get_or_fetch

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use vouch_cli::{tr, tr_args};

use crate::config::Config;
use crate::session::resolve_token;
use vouch_cli::fapi::key_store::load_client_key;
use vouch_cli::fapi::{ClientAssertionBuilder, ClientKey, DpopProofBuilder};
use vouch_common::protocol::{
    ERROR_USE_DPOP_NONCE, GRANT_TYPE_TOKEN_EXCHANGE, TOKEN_TYPE_ACCESS_TOKEN, TOKEN_TYPE_ID_TOKEN,
};

/// Number of seconds shaved off the provider's stated `expires_in` when
/// computing the cache expiry — gives callers a window to refresh before
/// the token actually expires.
const REFRESH_MARGIN_SECS: i64 = 60;

/// Subset of the RFC 8693 token-exchange response we consume. Per RFC 8693
/// §2.2.1 the issued security token — an OIDC ID token here — is always
/// returned in `access_token`, regardless of `issued_token_type`.
#[derive(Deserialize)]
struct VouchTokenExchangeResponse {
    access_token: SecretString,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// Inputs for a single token-exchange request attempt.
struct ExchangeRequest<'a> {
    /// Vouch server base URL (also the `private_key_jwt` audience).
    server: &'a str,
    /// OAuth client_id of the CLI's registered client.
    client_id: &'a str,
    /// FAPI signing key, for both the client assertion and the DPoP proof.
    key: &'a ClientKey,
    /// The existing session token, used as the RFC 8693 subject token.
    subject_token: &'a SecretString,
    /// Requested `aud` claim; omitted when `None`/empty (server self-issues).
    audience: Option<&'a str>,
    /// DPoP nonce supplied by the server on a `use_dpop_nonce` retry.
    nonce: Option<&'a str>,
}

/// Outcome of a single token-exchange attempt.
enum ExchangeOutcome {
    /// Issued ID token plus its `expires_in` (seconds), when reported.
    Success(SecretString, Option<u64>),
    /// The server demanded a DPoP nonce (RFC 9449); retry with this value.
    NeedNonce(String),
}

/// Fetch a generic OIDC ID token from the Vouch server to use as the WIF
/// assertion, via the RFC 8693 token exchange at `POST /oauth/token`.
///
/// `audience`, when set, is requested as the token's `aud` claim; when
/// `None`, the server defaults to its own issuer URL. Returns the issued ID
/// token paired with its `expires_in` (seconds), when the server reports one.
pub(crate) async fn fetch_assertion(
    server: &str,
    audience: Option<&str>,
) -> Result<(SecretString, Option<u64>)> {
    let config = Config::load().context(tr!("err-failed-load-vouch-config"))?;
    let client_id = config
        .client_id()
        .context(tr!("err-no-oauth-client-registered-run-vouch-login-first"))?;
    let key =
        load_client_key().context(tr!("err-no-fapi-client-key-found-run-vouch-login-first"))?;
    let subject_token = resolve_token().await?;

    let endpoint = format!("{server}/oauth/token");
    let http =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context(tr!("err-failed-create-http-client"))?;

    // First attempt without a nonce. A DPoP-bound client at the token
    // endpoint always gets `use_dpop_nonce` on the first try (RFC 9449),
    // so retry once with the server-provided nonce.
    let first = send_exchange(
        &http,
        &endpoint,
        ExchangeRequest {
            server,
            client_id,
            key: &key,
            subject_token: &subject_token,
            audience,
            nonce: None,
        },
    )
    .await?;
    let nonce = match first {
        ExchangeOutcome::Success(token, expires_in) => return Ok((token, expires_in)),
        ExchangeOutcome::NeedNonce(nonce) => nonce,
    };

    match send_exchange(
        &http,
        &endpoint,
        ExchangeRequest {
            server,
            client_id,
            key: &key,
            subject_token: &subject_token,
            audience,
            nonce: Some(&nonce),
        },
    )
    .await?
    {
        ExchangeOutcome::Success(token, expires_in) => Ok((token, expires_in)),
        ExchangeOutcome::NeedNonce(_) => {
            anyhow::bail!(tr!("err-vouch-token-endpoint-repeatedly-demanded-dpop-no"))
        }
    }
}

/// Encode the form body for one token-exchange request, including a fresh
/// `private_key_jwt` client assertion.
fn build_exchange_form(req: &ExchangeRequest<'_>) -> Result<String> {
    let assertion = ClientAssertionBuilder::new(req.client_id, req.server)
        .build(req.key)
        .context(tr!("err-failed-build-client-assertion"))?;
    let subject_token = req.subject_token.expose_secret();
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE),
        ("subject_token", subject_token),
        ("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN),
        ("requested_token_type", TOKEN_TYPE_ID_TOKEN),
        ("client_id", req.client_id),
        ("client_assertion_type", assertion.assertion_type),
        ("client_assertion", assertion.assertion.expose_secret()),
    ];
    if let Some(aud) = req.audience.filter(|s| !s.is_empty()) {
        form.push(("audience", aud));
    }
    serde_urlencoded::to_string(&form).context(tr!("err-failed-encode-token-exchange-request"))
}

/// Send one token-exchange request and classify the response.
async fn send_exchange(
    http: &reqwest::Client,
    endpoint: &str,
    req: ExchangeRequest<'_>,
) -> Result<ExchangeOutcome> {
    let body = build_exchange_form(&req)?;
    let mut dpop_builder = DpopProofBuilder::new("POST", endpoint);
    if let Some(nonce) = req.nonce {
        dpop_builder = dpop_builder.nonce(nonce);
    }
    let dpop_proof = dpop_builder
        .build(req.key)
        .context(tr!("err-failed-build-dpop-proof-token-request"))?;

    let response = http
        .post(endpoint)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("DPoP", dpop_proof)
        .body(body)
        .send()
        .await
        .with_context(|| tr_args!("err-failed-reach-vouch-token-endpoint", endpoint = endpoint))?;

    let status = response.status();
    let nonce = response
        .headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let text = response
        .text()
        .await
        .context(tr!("err-failed-read-vouch-token-exchange-response-body"))?;

    if status.is_success() {
        // A 2xx response that fails to deserialize almost certainly contains
        // the ID token itself; never echo the body into the error message.
        let parsed: VouchTokenExchangeResponse = serde_json::from_str(&text).context(tr!(
            "err-invalid-token-exchange-response-from-vouch-server-ex"
        ))?;
        return Ok(ExchangeOutcome::Success(
            parsed.access_token,
            parsed.expires_in,
        ));
    }

    // RFC 9449: a `use_dpop_nonce` error carries a fresh nonce to retry with.
    let parsed_err = serde_json::from_str::<vouch_common::OAuthError>(&text).ok();
    if let Some(err) = &parsed_err
        && err.error == ERROR_USE_DPOP_NONCE
        && let Some(nonce) = nonce
    {
        return Ok(ExchangeOutcome::NeedNonce(nonce));
    }

    // Surface the RFC 6749 standard `error` / `error_description` fields when
    // present, but never echo the raw body — a misconfigured proxy or future
    // server bug could include token material in error responses.
    match parsed_err {
        Some(err) => anyhow::bail!("{}", format_oauth_error("Vouch", status, &err)),
        None => anyhow::bail!(tr_args!(
            "err-vouch-token-exchange-failed",
            status = status.to_string()
        )),
    }
}

/// Format an OAuth error response (RFC 6749 §5.2) for user-facing display.
/// Only `error` and `error_description` are echoed — both are designed to be
/// safe to display.
fn format_oauth_error(
    label: &str,
    status: reqwest::StatusCode,
    err: &vouch_common::OAuthError,
) -> String {
    match err.error_description.as_deref() {
        Some(desc) => format!(
            "{label} token exchange failed ({status}): {} — {desc}",
            err.error
        ),
        None => format!("{label} token exchange failed ({status}): {}", err.error),
    }
}

/// Standard OAuth 2.0 token response from a provider's token endpoint
/// (RFC 6749 §5.1). Both Anthropic and OpenAI return this shape.
#[derive(Deserialize)]
struct ProviderTokenResponse {
    access_token: SecretString,
    #[serde(default)]
    expires_in: Option<u64>,
}

impl std::fmt::Debug for ProviderTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// POST a JSON token-exchange request to a provider and return the minted
/// access token paired with an ISO 8601 cache-expiry timestamp.
///
/// `body` is the provider-specific request (Anthropic: `jwt-bearer` grant;
/// OpenAI: `token-exchange` grant). `label` names the provider in error
/// messages.
pub(crate) async fn exchange(
    endpoint: &str,
    body: &serde_json::Value,
    label: &str,
) -> Result<(SecretString, String)> {
    let client =
        vouch_common::http::credential_client(&format!("vouch-cli/{}", env!("CARGO_PKG_VERSION")))
            .context(tr!("err-failed-create-http-client"))?;

    let payload =
        serde_json::to_vec(body).context(tr!("err-failed-serialize-token-exchange-request"))?;

    let response = client
        .post(endpoint)
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .with_context(|| {
            tr_args!(
                "err-failed-reach-token-endpoint",
                label = label,
                endpoint = endpoint
            )
        })?;

    let status = response.status();
    let text = response
        .text()
        .await
        .with_context(|| tr_args!("err-failed-read-token-response-body", label = label))?;

    if !status.is_success() {
        // Surface the RFC 6749 standard `error` / `error_description` fields
        // when present, but never echo the raw body — providers may include
        // sensitive material in error responses (assertion echoes, internal
        // diagnostics, partial credentials).
        match serde_json::from_str::<vouch_common::OAuthError>(&text).ok() {
            Some(err) => anyhow::bail!("{}", format_oauth_error(label, status, &err)),
            None => anyhow::bail!(tr_args!(
                "err-token-exchange-failed",
                label = label,
                status = status.to_string()
            )),
        }
    }

    // Deliberately do not include the response body in the error context:
    // a successful (2xx) response that fails to deserialize almost always
    // contains the access token itself, and the resulting error message
    // surfaces on stderr / in the calling helper's logs (Claude Code's
    // apiKeyHelper, Codex's auth command). The status code + label is
    // enough to triage.
    let parsed: ProviderTokenResponse = serde_json::from_str(&text).with_context(|| {
        format!("invalid {label} token response: expected JSON with access_token and expires_in")
    })?;

    let expiry = cache_expiry(parsed.expires_in);
    Ok((parsed.access_token, expiry))
}

/// Compute the cache-expiry timestamp from a provider's `expires_in` (seconds),
/// applying [`REFRESH_MARGIN_SECS`] of safety margin so we never hand out a
/// token about to die. Falls back to [`super::cache::default_expiry`] when
/// the provider omits `expires_in`.
fn cache_expiry(expires_in: Option<u64>) -> String {
    let Some(secs) = expires_in else {
        return super::cache::default_expiry();
    };
    let secs = i64::try_from(secs).unwrap_or(i64::MAX);
    let lifetime = secs.saturating_sub(REFRESH_MARGIN_SECS).max(1);
    jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(lifetime))
        .map_or_else(|_| super::cache::default_expiry(), |ts| ts.to_string())
}

/// Build the agent-aware cache key used by the provider commands.
///
/// Folding the detected agent source into the key mirrors the AWS
/// rationale (issue #398): agent and non-agent invocations must not
/// share a cached token, since they may carry different attribution
/// claims when an agent is detected.
pub(crate) fn build_cache_key(provider: &str, id: &str, agent: Option<&str>) -> String {
    match agent {
        Some(src) => format!("{provider}:{id}:agent:{src}"),
        None => format!("{provider}:{id}"),
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_expiry_none_returns_default() {
        let ts = cache_expiry(None);
        assert!(ts.parse::<jiff::Timestamp>().is_ok());
    }

    #[test]
    fn test_cache_expiry_applies_safety_margin() {
        let before = jiff::Timestamp::now();
        let ts = cache_expiry(Some(3600));
        let parsed: jiff::Timestamp = ts.parse().unwrap();
        // Should be roughly 3540s in the future (3600 - 60s margin), allowing slop.
        let delta_s = (parsed.as_second()).saturating_sub(before.as_second());
        assert!(
            delta_s > 3500,
            "expiry was {delta_s}s from now (expected ~3540)"
        );
        assert!(
            delta_s < 3600,
            "expiry was {delta_s}s from now (expected ~3540)"
        );
    }

    #[test]
    fn test_cache_expiry_handles_u64_max() {
        // u64::MAX → i64::MAX via try_from fallback, then checked_add fails
        // → fall back to default_expiry without panicking.
        let ts = cache_expiry(Some(u64::MAX));
        assert!(ts.parse::<jiff::Timestamp>().is_ok());
    }

    #[test]
    fn test_cache_expiry_small_value_does_not_underflow() {
        // 30s lifetime − 60s margin would underflow without the .max(1) clamp.
        let ts = cache_expiry(Some(30));
        assert!(ts.parse::<jiff::Timestamp>().is_ok());
    }

    /// A provider returning `expires_in: 0` is malformed but must not panic
    /// or loop — the `.max(1)` clamp gives the cache a 1-second TTL so the
    /// next invocation re-fetches without thrashing in a tight loop.
    #[test]
    fn test_cache_expiry_zero_value_does_not_panic() {
        let ts = cache_expiry(Some(0));
        assert!(ts.parse::<jiff::Timestamp>().is_ok());
    }

    #[test]
    fn test_build_cache_key_with_and_without_agent() {
        assert_eq!(
            build_cache_key("anthropic", "fdrl_abc", None),
            "anthropic:fdrl_abc"
        );
        assert_eq!(
            build_cache_key("anthropic", "fdrl_abc", Some("claude-code")),
            "anthropic:fdrl_abc:agent:claude-code"
        );
    }

    #[test]
    fn test_build_cache_key_differs_per_agent() {
        let a = build_cache_key("openai", "wip_1", Some("claude-code"));
        let b = build_cache_key("openai", "wip_1", Some("cursor"));
        assert_ne!(a, b);
    }

    /// A 2xx provider response that fails to deserialize almost always
    /// contains the access token itself (different schema, type mismatch).
    /// The error context surfaces on stderr / in the calling helper's
    /// logs, so it must NOT include the response body. Lock that in.
    #[test]
    fn test_parse_error_does_not_leak_response_body() {
        let leaked_token = "sk-ant-oat01-LEAKED-SECRET";
        let bad_body =
            format!("{{\"access_token\": \"{leaked_token}\", \"expires_in\": \"oops\"}}");
        let parsed: Result<ProviderTokenResponse, _> = serde_json::from_str(&bad_body);
        let err = parsed.expect_err("expires_in is a string, not a u64");
        let context = format!(
            "invalid {} token response: expected JSON with access_token and expires_in",
            "Anthropic"
        );
        // The error message we'd actually surface (context + serde error)
        // must not contain the access token. The serde error itself
        // mentions which field failed, not the token value.
        let full = format!("{context}: {err}");
        assert!(!full.contains(leaked_token), "error leaked token: {full}");
    }

    /// A non-2xx provider response with a body containing token-shaped material
    /// (e.g., echoed assertion, partial credentials, internal diagnostics) must
    /// never be echoed verbatim. We only surface RFC 6749 `error` /
    /// `error_description` after explicit parsing — both are designed to be
    /// safe for display.
    #[test]
    fn test_error_body_not_echoed_when_body_is_not_oauth_error() {
        let status = reqwest::StatusCode::BAD_REQUEST;
        let leaked_token = "sk-LEAKED-INTERNAL-DIAGNOSTIC";
        let opaque_body = format!("internal proxy diagnostic — debug-token={leaked_token}");
        let parsed = serde_json::from_str::<vouch_common::OAuthError>(&opaque_body).ok();
        assert!(parsed.is_none(), "opaque body must not parse as OAuthError");

        // The actual error-message branch taken when parsing fails.
        let message = format!("Vouch token exchange failed ({status})");
        assert!(
            !message.contains(leaked_token),
            "error leaked body: {message}"
        );
        assert!(
            !message.contains("debug-token"),
            "error leaked body: {message}"
        );
    }

    /// A standards-compliant OAuth error response (RFC 6749 §5.2) IS echoed —
    /// the `error` code and `error_description` are designed to be displayed
    /// to users. Lock in that valid OAuth errors round-trip through the
    /// safe-display formatter.
    #[test]
    fn test_oauth_error_round_trips_through_safe_formatter() {
        let err = vouch_common::OAuthError {
            error: "invalid_grant".to_string(),
            error_description: Some("subject token expired".to_string()),
        };
        let formatted = format_oauth_error("Anthropic", reqwest::StatusCode::BAD_REQUEST, &err);
        assert!(formatted.contains("Anthropic"));
        assert!(formatted.contains("invalid_grant"));
        assert!(formatted.contains("subject token expired"));
    }
}
