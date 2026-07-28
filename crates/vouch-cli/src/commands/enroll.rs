// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Enroll command - RFC 8628 Device Authorization Grant with FAPI 2.0 support.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use std::io::{IsTerminal, Write, stdout};
use vouch_common::{
    DeviceCodeRequest, DeviceCodeResponse, DeviceTokenRequest, OAuthError, RegisterCompleteRequest,
    RegisterCompleteResponse, RegisterStartRequest, RegisterStartResponse,
};

use crate::client::VouchClient;
use crate::config::Config;
use crate::fido2::{self, FidoDevice, YubiKey};
use crate::session;
use vouch_cli::{tr, tr_args, tr_println};

/// Response from device token endpoint.
#[derive(serde::Deserialize)]
struct DeviceTokenResponse {
    access_token: SecretString,
    expires_in: u64,
    email: String,
}

impl std::fmt::Debug for DeviceTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .field("email", &self.email)
            .finish()
    }
}

/// Run the enroll command.
pub(crate) async fn run(server: &str) -> Result<()> {
    let client = VouchClient::unauthenticated(server)?;

    tr_println!("enroll-starting");
    println!();

    // Step 1: Generate or load the FAPI client key. This key signs DPoP
    // proofs and every post-enrollment `/v1/*` request (RFC 9421), so it is
    // required — without it, enrollment cannot produce a client that can call
    // the credential and key-management endpoints.
    let fapi_key = vouch_cli::fapi::key_store::load_or_create_client_key()
        .with_context(|| tr!("enroll-err-key-init"))?;

    // Step 2: Register as a FAPI 2.0 client BEFORE the device code flow
    // (open registration — no auth token required).
    //
    // This ensures we have a client_id before the device authorization
    // request so the token binds to our registered client (and its JWKS)
    // from the start. Registration is required: the post-enrollment
    // `/v1/keys/register/*` calls are signed and the server can only verify
    // them against the JWKS we register here.
    let pre_registered_client_id =
        register_fapi_client_open(client.raw_client(), server, &fapi_key).await?;

    // Step 3: Request device code (RFC 8628 Section 3.1).
    let device_response = request_device_code(
        &client,
        server,
        Some(&fapi_key),
        Some(pre_registered_client_id),
    )
    .await?;

    // Step 4: Open browser and display instructions.
    // Prefer the RFC 8628 §3.3.1 verification_uri_complete (embeds user_code) so the
    // /device form is pre-filled; fall back to the plain verification_uri.
    let open_url = device_response
        .verification_uri_complete
        .as_deref()
        .unwrap_or(&device_response.verification_uri);
    let verification_url = &device_response.verification_uri;

    // Try to open the browser automatically
    match open::that(open_url) {
        Ok(()) => tr_println!(
            "enroll-browser-block",
            url = verification_url.as_str(),
            code = device_response.user_code.as_str(),
        ),
        Err(e) => {
            tracing::debug!("Failed to open browser: {e}");
            tr_println!(
                "enroll-manual-block",
                url = verification_url.as_str(),
                code = device_response.user_code.as_str(),
            );
        }
    }
    println!();
    tr_println!("enroll-waiting");

    // Step 5: Poll for token (with optional DPoP proofs).
    let token_response = poll_for_token(&client, &device_response, Some(&fapi_key)).await?;

    // Step 6: Compute expiration timestamp from expires_in.
    let expires_at = compute_session_expires_at(token_response.expires_in);
    let expires_at_str = expires_at.to_string();

    // Step 7: Store session, cookie, and auto-provision SSH.
    // Enrollment uses device authorization grant (no FAPI key / no DPoP).
    let agent_stored = session::store_and_finalize(
        server,
        token_response.access_token.expose_secret(),
        &token_response.email,
        &expires_at_str,
        Some(expires_at),
        None,
    )
    .await?;

    println!();
    tr_println!(
        "enroll-success-block",
        email = token_response.email.as_str()
    );

    // Step 8: Auto-register the inserted YubiKey if not already known.
    // The enrollment token is a full OAuth access token that can call
    // the /v1/keys/register/* endpoints (same as `vouch register`).
    if let Err(e) = register_current_key(server, token_response.access_token.clone()).await {
        tracing::debug!("Auto-registration skipped: {e}");
    }

    println!();
    if agent_stored {
        tr_println!("session-agent-ready");
    } else {
        tr_println!("session-agent-not-running");
    }

    println!();
    tr_println!("enroll-next-steps");

    Ok(())
}

/// Request a device code (RFC 8628 Section 3.1), including the client_id
/// if FAPI pre-registration succeeded.
///
/// If the request fails with a cached client_id, the id may be stale (e.g.
/// the server DB was reset): FAPI state is cleared, the client re-registers,
/// and the request is retried once.
async fn request_device_code(
    client: &VouchClient,
    server: &str,
    fapi_key: Option<&vouch_cli::fapi::ClientKey>,
    pre_registered_client_id: Option<String>,
) -> Result<DeviceCodeResponse> {
    let device_request = DeviceCodeRequest {
        client_id: pre_registered_client_id.clone(),
        scope: None,
    };

    match client.post_form("/oauth/device", &device_request).await {
        Ok(resp) => Ok(resp),
        Err(e) if pre_registered_client_id.is_some() => {
            tracing::info!(
                "Device code request failed with cached client_id, re-registering: {e:#}"
            );
            if let Err(clear_err) = Config::modify(|c| {
                c.set_server_url(server);
                c.clear_fapi();
            }) {
                tracing::warn!("Failed to clear stale FAPI config: {clear_err}");
            }

            let new_client_id = if let Some(key) = fapi_key {
                Some(register_fapi_client_open(client.raw_client(), server, key).await?)
            } else {
                None
            };

            let retry_request = DeviceCodeRequest {
                client_id: new_client_id,
                scope: None,
            };
            client
                .post_form("/oauth/device", &retry_request)
                .await
                .with_context(|| tr!("enroll-err-start"))
        }
        Err(e) => Err(e.context(tr!("enroll-err-start"))),
    }
}

/// Attempt open (unauthenticated) FAPI client registration.
///
/// This is called before the device code flow so the resulting token will
/// be bound to the registered client from the start. The server accepts
/// `POST /oauth/register` without a Bearer token when open registration
/// is enabled.
///
/// Returns the registered `client_id`. Registration is required for
/// enrollment, so any failure is returned as an error.
async fn register_fapi_client_open(
    http_client: &reqwest::Client,
    base_url: &str,
    key: &vouch_cli::fapi::ClientKey,
) -> Result<String> {
    // Reuse the cached client_id only when it was registered with the *current*
    // signing key. If the key was rotated or recreated while a stale client_id
    // lingers in config, the server JWKS holds the old public key and every
    // signed `/v1/*` request would fail verification. In that case fall through
    // and re-register so the token binds to the key we actually sign with.
    if let Ok(mut config) = Config::load() {
        config.set_server_url(base_url);
        if let Some(id) = config.client_id() {
            let key_matches = config
                .dpop_key_id()
                .is_some_and(|stored_kid| stored_kid == key.kid());
            if key_matches {
                tracing::debug!("FAPI client already registered: client_id={id}");
                return Ok(id.to_string());
            }
            tracing::debug!(
                "cached client_id but signing key kid changed; re-registering FAPI client"
            );
        }
    }

    // Open registration — no auth token. This is required: every `/v1/*`
    // request the CLI makes after enrollment must carry an RFC 9421
    // signature, and the server resolves the verifying key from the OAuth
    // client's registered JWKS. Without a registered client_id the issued
    // access token would not bind to our JWKS and signed requests could not
    // be verified, so a failure here is fatal.
    let result =
        vouch_cli::fapi::registration::register_fapi_client(http_client, base_url, None, key)
            .await
            .with_context(|| tr!("enroll-err-register"))?;

    let client_id = result.client_id.clone();

    // Save registration results to config.
    let url = base_url.to_string();
    if let Err(e) = Config::modify(|config| {
        config.set_server_url(&url);
        config.set_client_id(&result.client_id);
        if let Some(ref rat) = result.registration_access_token {
            config.set_registration_access_token(rat);
        }
        if let Some(ref uri) = result.registration_client_uri {
            config.set_registration_client_uri(uri);
        }
        config.set_dpop_key_id(&result.dpop_key_id);
    }) {
        tracing::warn!("Failed to save FAPI registration to config: {e}");
    }

    Ok(client_id)
}

/// Poll the token endpoint until authorization is complete or timeout.
///
/// If a FAPI key is provided, includes DPoP proofs on token requests
/// and handles DPoP nonce retry from the server.
async fn poll_for_token(
    client: &VouchClient,
    device_response: &DeviceCodeResponse,
    fapi_key: Option<&vouch_cli::fapi::ClientKey>,
) -> Result<DeviceTokenResponse> {
    let request = DeviceTokenRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        device_code: device_response.device_code.clone(),
    };

    let interval = std::time::Duration::from_secs(device_response.interval);
    let timeout = std::time::Duration::from_secs(device_response.expires_in);
    let start = std::time::Instant::now();

    let mut dots: usize = 0;
    // Track server-provided DPoP nonce for RFC 9449 nonce binding
    let mut dpop_nonce: Option<String> = None;

    loop {
        // Check timeout
        if start.elapsed() > timeout {
            anyhow::bail!(tr!("enroll-err-timeout"));
        }

        // Wait before polling
        tokio::time::sleep(interval).await;

        // Show progress (only on interactive terminals)
        if stdout().is_terminal() {
            dots = dots.saturating_add(1) % 4;
            print!("\r{}{}", tr!("enroll-waiting-progress"), ".".repeat(dots),);
            print!("{}", " ".repeat(3_usize.saturating_sub(dots)));
            stdout().flush().ok();
        }

        // Poll for token (with optional DPoP proof)
        match poll_once(client, &request, fapi_key, dpop_nonce.as_deref()).await {
            Ok(response) => {
                println!(); // Clear the progress line
                return Ok(response);
            }
            Err(PollError::Pending) => {
                // Keep waiting
            }
            Err(PollError::SlowDown) => {
                // Increase interval and continue
                tokio::time::sleep(interval).await;
            }
            Err(PollError::DpopNonce(nonce)) => {
                // Server requires a DPoP nonce — retry immediately
                tracing::debug!("Server requires DPoP nonce, retrying");
                dpop_nonce = Some(nonce);
            }
            Err(PollError::Denied) => {
                println!();
                return Err(
                    crate::exit_code::CliError::PermissionDenied(tr!("enroll-err-denied")).into(),
                );
            }
            Err(PollError::Expired) => {
                println!();
                anyhow::bail!(tr!("enroll-err-code-expired"));
            }
            Err(PollError::Other(msg)) => {
                println!();
                anyhow::bail!(tr_args!("enroll-err-failed", reason = msg));
            }
        }
    }
}

/// Compute seconds to add to now when deriving session expiry from `expires_in`.
///
/// Subtracts 30 seconds as a safety margin and saturates at zero for short TTLs.
pub(super) fn expiry_offset_seconds(expires_in: u64) -> i64 {
    i64::try_from(expires_in)
        .unwrap_or(28_800)
        .saturating_sub(30)
        .max(0)
}

/// Compute absolute session expiry from an `expires_in` TTL.
fn compute_session_expires_at(expires_in: u64) -> jiff::Timestamp {
    jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(expiry_offset_seconds(
            expires_in,
        )))
        .unwrap_or_else(|_| jiff::Timestamp::now())
}

/// Result of a single poll attempt.
enum PollError {
    Pending,
    SlowDown,
    Denied,
    Expired,
    /// Server returned `use_dpop_nonce` — retry with the provided nonce.
    DpopNonce(String),
    Other(String),
}

/// Make a single poll request to the token endpoint.
///
/// Includes DPoP proof and FAPI headers if a client key is available.
async fn poll_once(
    client: &VouchClient,
    request: &DeviceTokenRequest,
    fapi_key: Option<&vouch_cli::fapi::ClientKey>,
    dpop_nonce: Option<&str>,
) -> Result<DeviceTokenResponse, PollError> {
    let url = format!("{}/oauth/token", client.base_url());

    // Build the request with form encoding
    let mut builder = client.raw_client().post(&url).form(request);

    // Add DPoP proof if we have a FAPI key
    if let Some(key) = fapi_key {
        let mut dpop_builder = vouch_cli::fapi::DpopProofBuilder::new("POST", &url);
        if let Some(nonce) = dpop_nonce {
            dpop_builder = dpop_builder.nonce(nonce);
        }
        match dpop_builder.build(key) {
            Ok(proof) => {
                builder = builder.header("DPoP", proof);
            }
            Err(e) => {
                tracing::debug!("Failed to build DPoP proof: {e}");
                // Continue without DPoP — server will issue
                // a non-DPoP-bound token
            }
        }
    }

    // Add FAPI interaction headers only when FAPI key is present
    // (consistent with VouchClient::build_fapi_request)
    if fapi_key.is_some() {
        let interaction = vouch_cli::fapi::FapiInteraction::new();
        let fapi_headers = interaction.headers();
        for (name, value) in &fapi_headers {
            builder = builder.header(*name, *value);
        }
    }

    let response = builder
        .send()
        .await
        .map_err(|e| PollError::Other(e.to_string()))?;

    let status = response.status();

    // Capture DPoP-Nonce header for use_dpop_nonce flow (RFC 9449)
    let response_dpop_nonce = response
        .headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    if status.is_success() {
        let token_response: DeviceTokenResponse = response
            .json()
            .await
            .map_err(|e| PollError::Other(e.to_string()))?;
        return Ok(token_response);
    }

    // Parse error response
    let error_text = response.text().await.unwrap_or_default();

    if let Ok(oauth_error) = serde_json::from_str::<OAuthError>(&error_text) {
        match oauth_error.error.as_str() {
            "authorization_pending" => {
                return Err(PollError::Pending);
            }
            "slow_down" => return Err(PollError::SlowDown),
            "access_denied" => return Err(PollError::Denied),
            "expired_token" => return Err(PollError::Expired),
            "use_dpop_nonce" => {
                // RFC 9449: Server requires a DPoP nonce
                if let Some(nonce) = response_dpop_nonce {
                    return Err(PollError::DpopNonce(nonce));
                }
                // No nonce header — treat as a generic error
                return Err(PollError::Other(
                    "Server requires DPoP nonce but did not \
                     provide one"
                        .to_string(),
                ));
            }
            _ => {
                let msg = oauth_error.error_description.unwrap_or(oauth_error.error);
                return Err(PollError::Other(msg));
            }
        }
    }

    Err(PollError::Other(format!("HTTP {status}: {error_text}")))
}

/// Register the currently-inserted YubiKey using the enrollment token.
///
/// Called after enrollment succeeds. If the YubiKey is already registered
/// (credential ID is in the exclude list), this is a no-op. If no YubiKey
/// is inserted, or registration fails, the error is returned but should
/// not block the enrollment flow.
async fn register_current_key(server: &str, token: SecretString) -> Result<()> {
    let client = VouchClient::with_token(server, token)?;

    let start_resp: RegisterStartResponse = client
        .post_authenticated(
            "/v1/keys/register/start",
            &RegisterStartRequest {
                name: "YubiKey".to_string(),
            },
        )
        .await
        .context(tr!("err-failed-start-key-registration"))?;

    // If the server already has credentials for this user (browser just
    // registered one), skip CLI registration — the browser-created
    // discoverable credential works for CLI login via getAssertion too.
    if !start_resp.exclude_credential_ids.is_empty() {
        tracing::debug!(
            "Skipping CLI auto-registration: {} credential(s) already \
             registered during browser enrollment",
            start_resp.exclude_credential_ids.len()
        );
        return Ok(());
    }

    println!();
    tr_println!("enroll-registering-key");

    let rp_id = start_resp.rp_id.clone();
    let rp_name = start_resp.rp_name.clone();
    let challenge = start_resp.challenge.clone();
    let user_id = start_resp.user_id;
    let user_name = start_resp.user_name.clone();

    // Short timeout — the key should already be inserted from
    // the enrollment flow. Don't block the user for long.
    // Note: exclude list is always empty here (non-empty returns
    // early above), but we pass &[] explicitly for clarity.
    let result = fido2::spawn_fido2(move || {
        let key = YubiKey::wait_for_device(10)?;
        key.register(
            &rp_id,
            &rp_name,
            &challenge,
            user_id.as_bytes(),
            &user_name,
            &[],
        )
    })
    .await?;

    let complete_resp: RegisterCompleteResponse = client
        .post_authenticated(
            "/v1/keys/register/complete",
            &RegisterCompleteRequest {
                state: start_resp.state,
                credential_id: result.credential_id,
                public_key: result.public_key,
                attestation_object: result.attestation_object,
                client_data_json: result.client_data_json,
            },
        )
        .await
        .context(tr!("err-failed-complete-key-registration"))?;

    tr_println!(
        "enroll-key-registered",
        device_id = complete_resp.device_id.to_string(),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::expiry_offset_seconds;

    #[test]
    fn test_expiry_offset_seconds_saturates_for_short_ttls() {
        assert_eq!(expiry_offset_seconds(0), 0);
        assert_eq!(expiry_offset_seconds(1), 0);
        assert_eq!(expiry_offset_seconds(29), 0);
        assert_eq!(expiry_offset_seconds(30), 0);
    }

    #[test]
    fn test_expiry_offset_seconds_subtracts_margin_for_normal_ttl() {
        assert_eq!(expiry_offset_seconds(31), 1);
        assert_eq!(expiry_offset_seconds(3600), 3570);
    }

    #[test]
    fn test_expiry_offset_seconds_uses_default_on_overflow() {
        assert_eq!(expiry_offset_seconds(u64::MAX), 28_770);
    }
}
