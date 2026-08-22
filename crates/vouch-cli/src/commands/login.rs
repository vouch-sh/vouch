// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Login command - authenticate with your `YubiKey` via FAPI 2.0.
//!
//! The flow is structured so that all async I/O (server calls) happens on the
//! tokio runtime while all FIDO2 device operations run on a plain OS thread
//! via [`crate::fido2::spawn_fido2`]. See the module-level docs in
//! [`crate::fido2`] for why this separation is required.
//!
//! ## FAPI 2.0 flow
//!
//! 1. Ensure a FAPI client is registered (load or register on demand).
//! 2. POST `/oauth/fido2/challenge` → `{ challenge, rp_id, state }`.
//! 3. CTAP2 `get_assertion` on a plain OS thread (touch YubiKey, PIN).
//! 4. POST `/oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:fido2-assertion`,
//!    `client_assertion` (private_key_jwt), `DPoP` proof, and the base64url-encoded
//!    assertion payload in the `assertion` form field.
//! 5. Store the resulting DPoP-bound access token via [`crate::session::store_and_finalize`].

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::ExposeSecret;
use serde::Serialize;
use vouch_cli::fapi::{ClientAssertionBuilder, ClientKey, DpopProofBuilder, FapiInteraction};
use vouch_common::{Fido2ChallengeResponse, protocol};

use super::enroll::expiry_offset_seconds;
use crate::client::VouchClient;
use crate::config::Config;
use crate::fido2::{self, FidoDevice, YubiKey};
use crate::session;
use vouch_cli::{tr, tr_args, tr_println};

/// Run the login command.
///
/// Uses the FAPI 2.0 FIDO2 assertion grant flow. Requires a FAPI client key.
/// If no client key exists, one is generated and registered automatically.
///
/// The execution order is intentional:
/// 1. Contact the server first (async) — fail fast if unreachable.
/// 2. All FIDO2 device work on a plain OS thread (wait, PIN, authenticate).
/// 3. Complete authentication with the server (async).
pub(crate) async fn run(server: &str, timeout_secs: u64) -> Result<()> {
    tr_println!("login-starting");
    println!();

    let client = VouchClient::unauthenticated(server)?;

    // Load or generate the FAPI client key (required for FAPI 2.0 flow)
    let fapi_key = vouch_cli::fapi::key_store::load_or_create_client_key()?;

    run_fapi_login(&client, server, timeout_secs, &fapi_key).await
}

// ============================================================================
// FAPI 2.0 login path
// ============================================================================

/// FAPI 2.0 assertion grant request form fields.
///
/// Sent as `application/x-www-form-urlencoded` to `POST /oauth/token`.
#[derive(Clone, Serialize)]
struct Fido2AssertionTokenRequest {
    grant_type: &'static str,
    client_assertion_type: &'static str,
    #[serde(serialize_with = "vouch_common::serialize_secret_string")]
    client_assertion: secrecy::SecretString,
    #[serde(serialize_with = "vouch_common::serialize_secret_string")]
    assertion: secrecy::SecretString,
    scope: &'static str,
    /// RFC 9396: Device posture as authorization_details JSON array.
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_details: Option<String>,
}

// RFC 7521/7523: both the client assertion and the FIDO2 assertion are
// credentials presented to the token endpoint, so neither is derived.
impl std::fmt::Debug for Fido2AssertionTokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fido2AssertionTokenRequest")
            .field("grant_type", &self.grant_type)
            .field("client_assertion_type", &self.client_assertion_type)
            .field("client_assertion", &"[REDACTED]")
            .field("assertion", &"[REDACTED]")
            .field("scope", &self.scope)
            .field("authorization_details", &self.authorization_details)
            .finish()
    }
}

/// JSON payload encoded into the `assertion` form field.
///
/// Base64url-encoded JSON blob sent in the token request.
#[derive(Debug, Serialize)]
struct AssertionPayload {
    state: String,
    credential_id: String,
    authenticator_data: String,
    signature: String,
    client_data_json: String,
    user_handle: String,
}

/// Response from the FAPI 2.0 token endpoint.
#[derive(Debug, serde::Deserialize)]
struct Fapi2TokenResponse {
    access_token: secrecy::SecretString,
    expires_in: u64,
    email: String,
    /// `expires_at` may be included by some server versions.
    #[serde(default)]
    expires_at: Option<String>,
}

/// Run FAPI 2.0 login using the FIDO2 assertion grant.
#[expect(
    clippy::too_many_lines,
    reason = "linear FAPI 2.0 login flow: challenge, assertion, token, session"
)]
async fn run_fapi_login(
    client: &VouchClient,
    server: &str,
    timeout_secs: u64,
    fapi_key: &ClientKey,
) -> Result<()> {
    print!("{} ", tr_args!("login-contacting-server", server = server));

    // Step 1: Ensure the client is registered.
    let client_id = ensure_client_registered(client, fapi_key).await?;

    // Step 2: Obtain a FIDO2 challenge from the server.
    let token_endpoint_url = format!("{server}/oauth/token");
    let challenge_url = format!("{server}/oauth/fido2/challenge");

    let dpop_proof = DpopProofBuilder::new("POST", &challenge_url)
        .build(fapi_key)
        .context(tr!("err-failed-build-dpop-proof-challenge-request"))?;

    let interaction = FapiInteraction::new();
    let fapi_headers = interaction.headers();

    let response = client
        .raw_client()
        .post(&challenge_url)
        .header("DPoP", dpop_proof)
        .header(fapi_headers[0].0, fapi_headers[0].1)
        .header(fapi_headers[1].0, fapi_headers[1].1)
        .json(&serde_json::json!({}))
        .send()
        .await
        .context(tr!("err-failed-request-fido2-challenge"))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(crate::exit_code::CliError::NetworkError(format!(
            "challenge request failed (HTTP {status}): {body}"
        ))
        .into());
    }

    // RFC 9449 §8.2: Capture DPoP-Nonce from challenge response so we can
    // include it in the token request, avoiding a use_dpop_nonce rejection.
    let challenge_dpop_nonce = response
        .headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let challenge_resp: Fido2ChallengeResponse = response
        .json()
        .await
        .context(tr!("err-failed-parse-challenge-response"))?;

    tr_println!("login-contact-ok");

    // Step 3: Start posture collection early — it runs during the FIDO2 wait
    // (human touch takes 5-30s, posture takes 100ms-2s).
    let posture_handle = tokio::task::spawn_blocking(vouch_cli::posture::collect);

    // Step 4: FIDO2 assertion on a plain OS thread.
    let rp_id = challenge_resp.rp_id.clone();
    let challenge_b64 = challenge_resp.challenge.clone();

    // Decode the base64url challenge into raw bytes for the FIDO2 library.
    let challenge_bytes = URL_SAFE_NO_PAD
        .decode(&challenge_b64)
        .context(tr!("err-challenge-is-not-valid-base64url"))?;

    let assertion_result = fido2::spawn_fido2(move || {
        let key = YubiKey::wait_for_device(timeout_secs)?;
        key.authenticate(&rp_id, &challenge_bytes)
    })
    .await?;

    // Step 5: Encode the assertion as a base64url JSON blob.
    let payload = AssertionPayload {
        state: challenge_resp.state,
        credential_id: URL_SAFE_NO_PAD.encode(assertion_result.credential_id.as_bytes()),
        authenticator_data: URL_SAFE_NO_PAD.encode(assertion_result.authenticator_data.as_bytes()),
        signature: URL_SAFE_NO_PAD.encode(assertion_result.signature.as_bytes()),
        client_data_json: URL_SAFE_NO_PAD.encode(assertion_result.client_data_json.as_bytes()),
        user_handle: URL_SAFE_NO_PAD.encode(assertion_result.user_handle.as_bytes()),
    };

    let payload_json =
        serde_json::to_vec(&payload).context(tr!("err-failed-serialize-assertion-payload"))?;
    let assertion_b64 = URL_SAFE_NO_PAD.encode(&payload_json);

    // Step 6: Await posture collection (started before FIDO2 wait).
    // Cap total time to avoid blocking login if any command hangs.
    let authorization_details = {
        let posture_result =
            tokio::time::timeout(std::time::Duration::from_secs(2), posture_handle).await;
        match posture_result {
            Ok(Ok(posture)) => {
                tracing::debug!(
                    os = posture.os.as_ref().map(|o| o.as_str()),
                    os_version = posture.os_version.as_deref(),
                    disk_encrypted = posture.disk_encryption_enabled,
                    firewall = posture.firewall_enabled,
                    screen_lock = posture.screen_lock_enabled,
                    secure_boot = posture.secure_boot_enabled,
                    edr_count = posture.edr.len(),
                    mdm_count = posture.mdm.len(),
                    "Collected device posture"
                );
                let json = posture.to_authorization_details_json().ok();
                if let Some(ref j) = json {
                    tracing::trace!(payload = %j, "Device posture payload");
                }
                json
            }
            Ok(Err(e)) => {
                tracing::debug!("Posture collection task failed: {e}");
                None
            }
            Err(_) => {
                tracing::debug!("Posture collection timed out, continuing without posture");
                None
            }
        }
    };

    // Step 7: Build client_assertion (private_key_jwt) and DPoP proof.
    // FAPI 2.0 Section 5.3.2.1-8: audience must be the issuer URL (base URL).
    let client_assertion = ClientAssertionBuilder::new(&client_id, server).build(fapi_key)?;

    let mut dpop_builder = DpopProofBuilder::new("POST", &token_endpoint_url);
    if let Some(ref nonce) = challenge_dpop_nonce {
        dpop_builder = dpop_builder.nonce(nonce);
    }
    let dpop_proof = dpop_builder
        .build(fapi_key)
        .context(tr!("err-failed-build-dpop-proof-token-request"))?;

    let token_request = Fido2AssertionTokenRequest {
        grant_type: protocol::GRANT_TYPE_FIDO2_ASSERTION,
        client_assertion_type: protocol::CLIENT_ASSERTION_TYPE_JWT_BEARER,
        client_assertion: client_assertion.assertion,
        assertion: assertion_b64.into(),
        scope: "openid email",
        authorization_details,
    };

    // FIDO2 touch just completed — we have hardware proof of user presence.
    let interaction = FapiInteraction::with_presence(true);
    let fapi_headers = interaction.headers();

    let form_body = serde_urlencoded::to_string(&token_request)
        .context(tr!("err-failed-encode-token-request"))?;

    let token_resp = client
        .raw_client()
        .post(&token_endpoint_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("DPoP", dpop_proof)
        .header(fapi_headers[0].0, fapi_headers[0].1)
        .header(fapi_headers[1].0, fapi_headers[1].1)
        .body(form_body)
        .send()
        .await
        .context(tr!("err-failed-send-token-request"))?;

    let token_status = token_resp.status();

    // Capture DPoP-Nonce for potential retry (RFC 9449 nonce flow).
    let dpop_nonce = token_resp
        .headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    if !token_status.is_success() {
        let body = token_resp.text().await.unwrap_or_default();

        // RFC 9449: if use_dpop_nonce is returned, retry once with the nonce.
        if let Ok(oauth_err) = serde_json::from_str::<vouch_common::OAuthError>(&body)
            && oauth_err.error == protocol::ERROR_USE_DPOP_NONCE
            && let Some(nonce) = dpop_nonce
        {
            return run_fapi_login_with_nonce(
                client,
                server,
                fapi_key,
                &client_id,
                &token_request,
                &nonce,
            )
            .await;
        }

        return Err(token_error(&body, token_status));
    }

    let fapi_token: Fapi2TokenResponse = token_resp
        .json()
        .await
        .context(tr!("err-failed-parse-token-response"))?;

    // Derive expiry: prefer server-provided `expires_at`, else compute from `expires_in`.
    let (expires_at_str, expires_at_ts) =
        resolve_expiry(fapi_token.expires_at.as_deref(), fapi_token.expires_in);

    let email = fapi_token.email;

    // Reconstruct an owned key for auto-provision (avoids keychain
    // round-trip that can silently fail on some platforms).
    let owned_key = fapi_key
        .to_key_file()
        .ok()
        .and_then(|kf| ClientKey::from_key_file(&kf).ok());

    let agent_stored = session::store_and_finalize(
        server,
        fapi_token.access_token.expose_secret(),
        &email,
        &expires_at_str,
        Some(expires_at_ts),
        owned_key,
    )
    .await?;

    finalize_login_output(&email, &expires_at_str, agent_stored);

    Ok(())
}

/// Retry the token request with a server-provided DPoP nonce (RFC 9449).
async fn run_fapi_login_with_nonce(
    client: &VouchClient,
    server: &str,
    fapi_key: &ClientKey,
    client_id: &str,
    request: &Fido2AssertionTokenRequest,
    nonce: &str,
) -> Result<()> {
    let token_endpoint_url = format!("{server}/oauth/token");

    // Rebuild client_assertion and DPoP proof with the nonce.
    // FAPI 2.0 Section 5.3.2.1-8: audience must be the issuer URL (base URL).
    let client_assertion = ClientAssertionBuilder::new(client_id, server).build(fapi_key)?;

    let dpop_proof = DpopProofBuilder::new("POST", &token_endpoint_url)
        .nonce(nonce)
        .build(fapi_key)
        .context(tr!("err-failed-build-dpop-proof-with-nonce"))?;

    let retry_request = Fido2AssertionTokenRequest {
        grant_type: request.grant_type,
        client_assertion_type: request.client_assertion_type,
        client_assertion: client_assertion.assertion,
        assertion: request.assertion.clone(),
        scope: request.scope,
        authorization_details: request.authorization_details.clone(),
    };

    // Still within the same FIDO2 session — user presence confirmed by prior touch.
    let interaction = FapiInteraction::with_presence(true);
    let fapi_headers = interaction.headers();

    let form_body = serde_urlencoded::to_string(&retry_request)
        .context(tr!("err-failed-encode-token-request"))?;

    let token_resp = client
        .raw_client()
        .post(&token_endpoint_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("DPoP", dpop_proof)
        .header(fapi_headers[0].0, fapi_headers[0].1)
        .header(fapi_headers[1].0, fapi_headers[1].1)
        .body(form_body)
        .send()
        .await
        .context(tr!("err-failed-send-token-request-nonce-retry"))?;

    let token_status = token_resp.status();
    if !token_status.is_success() {
        let body = token_resp.text().await.unwrap_or_default();
        return Err(token_error(&body, token_status));
    }

    let fapi_token: Fapi2TokenResponse = token_resp
        .json()
        .await
        .context(tr!("err-failed-parse-token-response"))?;

    let (expires_at_str, expires_at_ts) =
        resolve_expiry(fapi_token.expires_at.as_deref(), fapi_token.expires_in);

    let email = fapi_token.email;

    // Reconstruct an owned key for auto-provision.
    let owned_key = fapi_key
        .to_key_file()
        .ok()
        .and_then(|kf| ClientKey::from_key_file(&kf).ok());

    let agent_stored = session::store_and_finalize(
        server,
        fapi_token.access_token.expose_secret(),
        &email,
        &expires_at_str,
        Some(expires_at_ts),
        owned_key,
    )
    .await?;

    finalize_login_output(&email, &expires_at_str, agent_stored);

    Ok(())
}

/// Ensure the FAPI client is registered, registering on demand if needed.
///
/// Validates the stored registration in two ways before using it:
/// 1. **Key match**: the current FAPI key's `kid` must match the stored
///    `dpop_key_id`. If the key changed (keychain reset, re-enrollment),
///    the old registration is useless.
/// 2. **Server check**: calls the RFC 7592 management endpoint to confirm
///    the client still exists on the server (handles DB resets, revocation).
///
/// If either check fails, clears FAPI config and re-registers.
///
/// Returns the `client_id` on success.
async fn ensure_client_registered(client: &VouchClient, fapi_key: &ClientKey) -> Result<String> {
    let base_url = client.base_url().to_string();

    if let Ok(mut config) = Config::load() {
        config.set_server_url(&base_url);
        if let Some(id) = config.client_id() {
            // Check 1: does the current key match what was registered?
            let key_matches = config
                .dpop_key_id()
                .is_some_and(|stored_kid| stored_kid == fapi_key.kid());

            if !key_matches {
                tracing::debug!(
                    "Key mismatch (stored={:?}, current={}), re-registering",
                    config.dpop_key_id(),
                    fapi_key.kid()
                );
            } else if let Some(uri) = config.registration_client_uri()
                && let Some(token) = config.registration_access_token()
            {
                // Check 2: does the registration URI match the
                // current server? A mismatch means stale config
                // from a different server (e.g. localhost vs prod).
                let uri_matches_server = crate::config::hostname_from_url(uri).ok()
                    == crate::config::hostname_from_url(&base_url).ok();

                if !uri_matches_server {
                    tracing::debug!(
                        "Registration URI {uri} does not match \
                         server {base_url}, re-registering"
                    );
                } else {
                    // Check 2b: skip server check if verified recently
                    // (within 24 hours). Saves one HTTP round-trip.
                    if recently_verified(config.registration_verified_at()) {
                        tracing::debug!(
                            "Registration verified recently, skipping \
                             server check"
                        );
                        return Ok(id.to_string());
                    }

                    // Check 3: is the registration still active?
                    match vouch_cli::fapi::registration::is_client_registered(
                        client.raw_client(),
                        uri,
                        token.expose_secret(),
                    )
                    .await
                    {
                        Ok(true) => {
                            // Cache the verification timestamp; cache write
                            // failures are non-fatal — next login revalidates.
                            let now = jiff::Timestamp::now().to_string();
                            let _cached = Config::modify(|cfg| {
                                cfg.set_server_url(&base_url);
                                cfg.set_registration_verified_at(&now);
                            });
                            return Ok(id.to_string());
                        }
                        Ok(false) => {
                            tracing::debug!(
                                "Client {id} no longer registered, \
                                 re-registering"
                            );
                        }
                        Err(e) => {
                            // Network error — trust the stored
                            // client_id; login will fail with a
                            // clearer error at the challenge step.
                            tracing::debug!("Could not validate registration: {e}");
                            return Ok(id.to_string());
                        }
                    }
                }
            } else {
                // No RFC 7592 credentials (pre-7592 config) but key
                // matches — trust the stored client_id.
                return Ok(id.to_string());
            }
        }
    }

    // Register (or re-register) now.
    tracing::debug!("Registering FAPI client");

    let result = vouch_cli::fapi::registration::register_fapi_client(
        client.raw_client(),
        &base_url,
        None,
        fapi_key,
    )
    .await
    .context(tr!("err-failed-register-fapi-client"))?;

    // Persist the registration to config.
    Config::modify(|config| {
        config.set_server_url(&base_url);
        config.clear_fapi();
        config.set_client_id(&result.client_id);
        if let Some(ref rat) = result.registration_access_token {
            config.set_registration_access_token(secrecy::ExposeSecret::expose_secret(rat));
        }
        if let Some(ref uri) = result.registration_client_uri {
            config.set_registration_client_uri(uri);
        }
        config.set_dpop_key_id(&result.dpop_key_id);
    })
    .context(tr!("err-failed-save-fapi-registration-config"))?;

    Ok(result.client_id)
}

// ============================================================================
// Helpers
// ============================================================================

/// Check if registration was verified within the last 24 hours.
fn recently_verified(verified_at: Option<&str>) -> bool {
    let Some(s) = verified_at else {
        return false;
    };
    let Ok(ts) = s.parse::<jiff::Timestamp>() else {
        return false;
    };
    let elapsed = jiff::Timestamp::now().duration_since(ts);
    elapsed.as_secs() < 86_400
}

/// Compute `(expires_at_string, expires_at_timestamp)` from the token response.
///
/// Uses the server-provided `expires_at` string when available; otherwise
/// computes it from `expires_in` seconds.
fn resolve_expiry(expires_at: Option<&str>, expires_in: u64) -> (String, jiff::Timestamp) {
    if let Some(s) = expires_at
        && let Ok(ts) = s.parse::<jiff::Timestamp>()
    {
        return (s.to_string(), ts);
    }

    let ts = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(expiry_offset_seconds(
            expires_in,
        )))
        .unwrap_or_else(|_| jiff::Timestamp::now());

    (ts.to_string(), ts)
}

/// Print the post-login success message.
fn finalize_login_output(email: &str, expires_at: &str, agent_stored: bool) {
    if email.is_empty() {
        tr_println!("login-success");
    } else {
        tr_println!("login-success-as", email = email);
    }
    tr_println!("login-session-expires", expiry = format_expiry(expires_at));

    println!();
    if agent_stored {
        tr_println!("session-agent-ready");
    } else {
        tr_println!("session-agent-not-running");
        tr_println!("session-stored-locally");
    }
}

/// Map an OAuth token error response to an actionable CLI error.
///
/// Parses the JSON body and adds user-facing hints for recoverable errors.
fn token_error(body: &str, status: reqwest::StatusCode) -> anyhow::Error {
    if let Ok(oauth_err) = serde_json::from_str::<vouch_common::OAuthError>(body) {
        let hint = match oauth_err.error.as_str() {
            "invalid_grant" => format!("\n\n{}", tr!("login-err-not-registered")),
            "invalid_client" => format!("\n\n{}", tr!("login-err-invalid-client")),
            _ => String::new(),
        };
        let desc = oauth_err
            .error_description
            .as_deref()
            .unwrap_or("(no description)");
        anyhow::anyhow!("{}: {desc}{hint}", oauth_err.error)
    } else {
        anyhow::anyhow!(tr_args!(
            "err-token-request-failed-http",
            status = status.to_string(),
            body = body
        ))
    }
}

/// Format an ISO 8601 expiry timestamp as a human-readable relative time.
///
/// Example: "in 8h (2026-01-27 12:25 UTC)"
fn format_expiry(expires_at: &str) -> String {
    let Ok(ts) = expires_at.parse::<jiff::Timestamp>() else {
        return expires_at.to_string();
    };

    let secs = ts.duration_since(jiff::Timestamp::now()).as_secs().max(0);
    // 60 is non-zero; unwrap_or arm is unreachable.
    let remaining = jiff::SignedDuration::from_mins(secs.checked_div(60).unwrap_or(0));
    let local = ts.to_zoned(jiff::tz::TimeZone::system());
    let datetime = local.strftime("%Y-%m-%d %H:%M %Z");

    format!("in {remaining:#} ({datetime})")
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
    fn test_format_expiry_invalid_timestamp_returns_as_is() {
        let result = format_expiry("not-a-timestamp");
        assert_eq!(result, "not-a-timestamp");
    }

    #[test]
    fn test_format_expiry_valid_future_timestamp() {
        let future = jiff::Timestamp::now()
            .checked_add(jiff::SignedDuration::from_hours(2))
            .unwrap();
        let s = future.to_string();
        let result = format_expiry(&s);
        assert!(result.starts_with("in"), "should start with 'in': {result}");
    }

    #[test]
    fn test_resolve_expiry_uses_provided_expires_at() {
        let future = jiff::Timestamp::now()
            .checked_add(jiff::SignedDuration::from_hours(1))
            .unwrap();
        let s = future.to_string();
        let (str_result, ts_result) = resolve_expiry(Some(&s), 3600);
        assert_eq!(str_result, s);
        // Timestamps should be close (within 1 second due to string round-trip)
        let diff = ts_result.duration_since(future).as_secs().unsigned_abs();
        assert!(diff <= 1, "timestamp round-trip should be within 1s");
    }

    #[test]
    fn test_resolve_expiry_falls_back_to_expires_in() {
        let (str_result, ts_result) = resolve_expiry(None, 3600);
        // Should be a valid timestamp close to now + 3600 - 30 = 3570 s
        let ts: jiff::Timestamp = str_result.parse().unwrap();
        let diff = ts.duration_since(jiff::Timestamp::now()).as_secs();
        // Allow generous window for test execution time
        assert!(
            diff > 3500 && diff <= 3570,
            "expected ~3570s in future, got {diff}"
        );
        let diff2 = ts_result.duration_since(jiff::Timestamp::now()).as_secs();
        assert!(diff2 > 3500 && diff2 <= 3570);
    }

    #[test]
    fn test_resolve_expiry_invalid_expires_at_falls_back() {
        let (str_result, _) = resolve_expiry(Some("not-a-timestamp"), 3600);
        // Should fall back and produce a valid timestamp string
        let ts: jiff::Timestamp = str_result
            .parse()
            .expect("should fall back to valid timestamp");
        let diff = ts.duration_since(jiff::Timestamp::now()).as_secs();
        assert!(diff > 3500 && diff <= 3570);
    }

    #[test]
    fn test_resolve_expiry_short_ttl_does_not_set_past_expiry() {
        let (str_result, ts_result) = resolve_expiry(None, 0);
        let ts: jiff::Timestamp = str_result.parse().unwrap();
        let diff = ts.duration_since(jiff::Timestamp::now()).as_secs();
        assert!(
            (-2..=1).contains(&diff),
            "expected near-now expiry, got {diff}"
        );
        let diff2 = ts_result.duration_since(jiff::Timestamp::now()).as_secs();
        assert!(
            (-2..=1).contains(&diff2),
            "expected near-now expiry, got {diff2}"
        );
    }
}
