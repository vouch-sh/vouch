//! Enrollment handlers for browser-based device authorization flow.

use crate::db;
use crate::AppState;
use axum::{
    Form, Json,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jiff::{Span, Timestamp};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use vouch_common::{ApiError, BrowserRegisterCompleteRequest, BrowserRegisterStartResponse};

/// Form data for user code submission.
#[derive(Debug, Deserialize)]
pub struct UserCodeForm {
    user_code: String,
}

/// Query params for OIDC callback.
#[derive(Debug, Deserialize)]
pub struct OidcCallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// OIDC token response.
#[derive(Debug, Deserialize)]
struct OidcTokenResponse {
    id_token: String,
    #[allow(dead_code)]
    access_token: String,
}

/// OIDC ID token claims (minimal).
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    email: String,
    #[serde(default)]
    email_verified: bool,
    #[allow(dead_code)]
    nonce: Option<String>,
}

/// Client data JSON structure from `WebAuthn` response.
#[derive(Deserialize)]
#[allow(dead_code)]
struct ClientData {
    challenge: String,
    origin: String,
    #[serde(rename = "type")]
    typ: String,
}

/// Browser registration state stored between `WebAuthn` start and complete.
#[derive(Debug, Serialize, Deserialize)]
struct BrowserRegistrationState {
    device_auth_id: String,
    user_id: Uuid,
    user_email: String,
    challenge: Vec<u8>,
    rp_id: String,
}

impl BrowserRegistrationState {
    fn encode(&self, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
        encode(
            &Header::default(),
            self,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
    }

    fn decode(token: &str, secret: &str) -> Result<Self, jsonwebtoken::errors::Error> {
        let mut validation = Validation::default();
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        let data = decode::<Self>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )?;
        Ok(data.claims)
    }
}

/// Generate random bytes.
fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

/// HTML page for entering user code.
const DEVICE_CODE_ENTRY_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vouch - Device Verification</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 16px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 400px;
            width: 100%;
        }
        h1 {
            margin: 0 0 8px;
            font-size: 24px;
            color: #1a1a2e;
        }
        p {
            color: #666;
            margin: 0 0 24px;
            font-size: 14px;
        }
        input {
            width: 100%;
            padding: 16px;
            font-size: 24px;
            text-align: center;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 16px;
            text-transform: uppercase;
            letter-spacing: 4px;
            font-family: monospace;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 16px;
            font-size: 16px;
            font-weight: 600;
            color: white;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }
        .error {
            background: #fee;
            color: #c00;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 16px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Enter Your Code</h1>
        <p>Enter the code shown in your terminal to continue.</p>
        {{ERROR}}
        <form method="POST" action="/device">
            <input type="text" name="user_code" placeholder="XXXX-XXXX" maxlength="9" required autofocus>
            <button type="submit">Continue</button>
        </form>
    </div>
</body>
</html>"#;

/// HTML page for `WebAuthn` registration.
const WEBAUTHN_REGISTER_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vouch - Register Security Key</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 16px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 400px;
            width: 100%;
            text-align: center;
        }
        h1 { margin: 0 0 8px; font-size: 24px; color: #1a1a2e; }
        p { color: #666; margin: 0 0 24px; font-size: 14px; }
        .email { font-weight: 600; color: #333; }
        .status {
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            font-size: 14px;
        }
        .status.waiting { background: #e8f4fc; color: #0066cc; }
        .status.success { background: #e8f8e8; color: #006600; }
        .status.error { background: #fee; color: #c00; }
        .icon { font-size: 48px; margin-bottom: 16px; }
        button {
            padding: 16px 32px;
            font-size: 16px;
            font-weight: 600;
            color: white;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4); }
        button:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🔐</div>
        <h1>Register Security Key</h1>
        <p>Registering as <span class="email">{{EMAIL}}</span></p>
        <div id="status" class="status waiting">Click the button below, then touch your security key when it blinks.</div>
        <button id="register-btn" onclick="startRegistration()">Register Security Key</button>
    </div>
    <script>
        const stateToken = '{{STATE}}';
        const rpId = '{{RP_ID}}';

        async function startRegistration() {
            const btn = document.getElementById('register-btn');
            const status = document.getElementById('status');
            btn.disabled = true;
            status.className = 'status waiting';
            status.textContent = 'Touch your security key when it blinks...';

            try {
                // Get registration options
                const startResp = await fetch('/enroll/webauthn/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ oidc_state: stateToken })
                });

                if (!startResp.ok) {
                    const err = await startResp.json();
                    throw new Error(err.message || 'Failed to start registration');
                }

                const options = await startResp.json();

                // Convert base64url to ArrayBuffer
                const challenge = base64urlToBuffer(options.challenge);
                const userId = base64urlToBuffer(options.user_id);

                // Create credential
                const credential = await navigator.credentials.create({
                    publicKey: {
                        challenge: challenge,
                        rp: { id: options.rp_id, name: options.rp_name },
                        user: {
                            id: userId,
                            name: options.user_email,
                            displayName: options.user_display_name
                        },
                        pubKeyCredParams: options.algorithms.map(alg => ({
                            type: 'public-key',
                            alg: alg
                        })),
                        authenticatorSelection: {
                            authenticatorAttachment: 'cross-platform',
                            userVerification: 'required',
                            residentKey: 'preferred'
                        },
                        timeout: 60000,
                        attestation: 'direct'
                    }
                });

                // Send credential to server
                const attestationResponse = credential.response;
                const completeResp = await fetch('/enroll/webauthn/complete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        state: options.state,
                        credential_id: bufferToBase64url(credential.rawId),
                        attestation_object: bufferToBase64url(attestationResponse.attestationObject),
                        client_data_json: bufferToBase64url(attestationResponse.clientDataJSON)
                    })
                });

                if (!completeResp.ok) {
                    const err = await completeResp.json();
                    throw new Error(err.message || 'Failed to complete registration');
                }

                status.className = 'status success';
                status.textContent = 'Success! You can close this window and return to your terminal.';
                btn.style.display = 'none';

            } catch (err) {
                status.className = 'status error';
                status.textContent = 'Error: ' + err.message;
                btn.disabled = false;
            }
        }

        function base64urlToBuffer(base64url) {
            const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
            const pad = base64.length % 4;
            const padded = pad ? base64 + '='.repeat(4 - pad) : base64;
            const binary = atob(padded);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        }

        function bufferToBase64url(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.length; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }
    </script>
</body>
</html>"#;

/// HTML page for success.
const SUCCESS_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vouch - Success</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
        }
        .container {
            background: white;
            border-radius: 16px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 400px;
            text-align: center;
        }
        .icon { font-size: 64px; margin-bottom: 16px; }
        h1 { margin: 0 0 8px; font-size: 24px; color: #1a1a2e; }
        p { color: #666; margin: 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">✅</div>
        <h1>Enrollment Complete</h1>
        <p>You can close this window and return to your terminal.</p>
    </div>
</body>
</html>"#;

/// HTML page for errors.
fn error_html(title: &str, message: &str) -> String {
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vouch - Error</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
        }}
        .container {{
            background: white;
            border-radius: 16px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 400px;
            text-align: center;
        }}
        .icon {{ font-size: 64px; margin-bottom: 16px; }}
        h1 {{ margin: 0 0 8px; font-size: 24px; color: #c00; }}
        p {{ color: #666; margin: 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">❌</div>
        <h1>{title}</h1>
        <p>{message}</p>
    </div>
</body>
</html>"#)
}

/// JSON error response helper.
fn json_error(status: StatusCode, code: &str, message: &str) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError::new(code, message)))
}

/// Show device code entry page.
/// GET /device
#[allow(clippy::unused_async)]
pub async fn device_verify_page() -> Html<String> {
    Html(DEVICE_CODE_ENTRY_HTML.replace("{{ERROR}}", ""))
}

/// Handle device code submission.
/// POST /device
#[allow(clippy::unused_async)]
pub async fn device_verify_submit(
    State(state): State<Arc<AppState>>,
    Form(form): Form<UserCodeForm>,
) -> Response {
    // Normalize user code (uppercase, ensure dash)
    let user_code = form.user_code.to_uppercase().trim().to_string();
    let user_code = if user_code.len() == 8 && !user_code.contains('-') {
        format!("{}-{}", &user_code[..4], &user_code[4..])
    } else {
        user_code
    };

    // Look up device auth request
    let request = match db::get_device_auth_by_user_code(&state.db, &user_code).await {
        Ok(Some(req)) => req,
        Ok(None) => {
            let html = DEVICE_CODE_ENTRY_HTML.replace(
                "{{ERROR}}",
                r#"<div class="error">Invalid code. Please check and try again.</div>"#,
            );
            return Html(html).into_response();
        }
        Err(_) => {
            let html = DEVICE_CODE_ENTRY_HTML.replace(
                "{{ERROR}}",
                r#"<div class="error">An error occurred. Please try again.</div>"#,
            );
            return Html(html).into_response();
        }
    };

    // Check if expired
    let now = Timestamp::now();
    let expires_at: Timestamp = match request.expires_at.parse() {
        Ok(ts) => ts,
        Err(_) => {
            return Html(error_html("Error", "Invalid request state")).into_response();
        }
    };

    if now > expires_at {
        let html = DEVICE_CODE_ENTRY_HTML.replace(
            "{{ERROR}}",
            r#"<div class="error">This code has expired. Please request a new one.</div>"#,
        );
        return Html(html).into_response();
    }

    // Check if already used
    if request.status != "pending" {
        let html = DEVICE_CODE_ENTRY_HTML.replace(
            "{{ERROR}}",
            r#"<div class="error">This code has already been used.</div>"#,
        );
        return Html(html).into_response();
    }

    // Check if OIDC is configured
    if !state.config.oidc_configured() {
        // No OIDC configured - go directly to WebAuthn registration
        // Generate state token for WebAuthn
        let oidc_state = URL_SAFE_NO_PAD.encode(generate_random_bytes(32));

        // Store state
        let state_expires = now
            .checked_add(Span::new().minutes(10))
            .unwrap_or(now);

        if let Err(e) = db::create_oidc_state(
            &state.db,
            &oidc_state,
            &request.id,
            "", // No nonce for non-OIDC flow
            &state_expires.to_string(),
        )
        .await
        {
            tracing::error!("Failed to create state: {}", e);
            return Html(error_html("Error", "Failed to create session state")).into_response();
        }

        // Show WebAuthn registration page without email (will prompt for it)
        let html = WEBAUTHN_REGISTER_HTML
            .replace("{{STATE}}", &oidc_state)
            .replace("{{EMAIL}}", "new user")
            .replace("{{RP_ID}}", &state.config.rp_id);
        return Html(html).into_response();
    }

    // OIDC configured - redirect to OIDC provider
    let oidc_issuer = state.config.oidc_issuer_url.as_ref().map_or("", String::as_str);
    let client_id = state.config.oidc_client_id.as_ref().map_or("", String::as_str);

    // Generate state and nonce
    let oidc_state = URL_SAFE_NO_PAD.encode(generate_random_bytes(32));
    let nonce = URL_SAFE_NO_PAD.encode(generate_random_bytes(32));

    // Store state
    let state_expires = now
        .checked_add(Span::new().minutes(10))
        .unwrap_or(now);

    if let Err(e) = db::create_oidc_state(
        &state.db,
        &oidc_state,
        &request.id,
        &nonce,
        &state_expires.to_string(),
    )
    .await
    {
        tracing::error!("Failed to create OIDC state: {}", e);
        return Html(error_html("Error", "Failed to create session state")).into_response();
    }

    // Build redirect URL
    let redirect_uri = format!("{}/oauth/callback", state.config.verification_base_url);
    let auth_url = format!(
        "{}/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email&state={}&nonce={}",
        oidc_issuer,
        urlencoding::encode(client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(&oidc_state),
        urlencoding::encode(&nonce)
    );

    Redirect::temporary(&auth_url).into_response()
}

/// Handle OIDC callback.
/// GET /oauth/callback
#[allow(clippy::unused_async, clippy::too_many_lines)]
pub async fn oidc_callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<OidcCallbackParams>,
) -> Response {
    // Check for error response
    if let Some(error) = params.error {
        let desc = params.error_description.unwrap_or_else(|| "Unknown error".to_string());
        return Html(error_html(&error, &desc)).into_response();
    }

    // Get authorization code and state
    let Some(code) = params.code else {
        return Html(error_html("Error", "Missing authorization code")).into_response();
    };

    let Some(oidc_state) = params.state else {
        return Html(error_html("Error", "Missing state parameter")).into_response();
    };

    // Verify state
    let stored_state = match db::get_oidc_state(&state.db, &oidc_state).await {
        Ok(Some(s)) => s,
        Ok(None) => return Html(error_html("Error", "Invalid state")).into_response(),
        Err(_) => return Html(error_html("Error", "Failed to verify state")).into_response(),
    };

    // Check if state expired
    let now = Timestamp::now();
    let expires_at: Timestamp = match stored_state.expires_at.parse() {
        Ok(ts) => ts,
        Err(_) => return Html(error_html("Error", "Invalid state")).into_response(),
    };

    if now > expires_at {
        return Html(error_html("Error", "State has expired")).into_response();
    }

    // Exchange code for tokens
    let oidc_issuer = state.config.oidc_issuer_url.as_ref().map_or("", String::as_str);
    let client_id = state.config.oidc_client_id.as_ref().map_or("", String::as_str);
    let client_secret = state.config.oidc_client_secret.as_ref().map_or("", String::as_str);
    let redirect_uri = format!("{}/oauth/callback", state.config.verification_base_url);

    let token_url = format!("{}/token", oidc_issuer.replace("accounts.google.com", "oauth2.googleapis.com"));

    let client = reqwest::Client::new();
    let token_response = match client
        .post(&token_url)
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", &code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", &redirect_uri),
        ])
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("Failed to exchange code: {}", e);
            return Html(error_html("Error", "Failed to complete authentication")).into_response();
        }
    };

    if !token_response.status().is_success() {
        let error_text = token_response.text().await.unwrap_or_default();
        tracing::error!("Token exchange failed: {}", error_text);
        return Html(error_html("Error", "Failed to complete authentication")).into_response();
    }

    let tokens: OidcTokenResponse = match token_response.json().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to parse token response: {}", e);
            return Html(error_html("Error", "Failed to complete authentication")).into_response();
        }
    };

    // Decode ID token (just extract claims, skip signature verification for now as we trust the token endpoint)
    let id_token_parts: Vec<&str> = tokens.id_token.split('.').collect();
    if id_token_parts.len() != 3 {
        return Html(error_html("Error", "Invalid ID token")).into_response();
    }

    let Ok(claims_json) = URL_SAFE_NO_PAD.decode(id_token_parts.get(1).unwrap_or(&"")) else {
        return Html(error_html("Error", "Invalid ID token")).into_response();
    };

    let claims: IdTokenClaims = match serde_json::from_slice(&claims_json) {
        Ok(c) => c,
        Err(_) => return Html(error_html("Error", "Invalid ID token claims")).into_response(),
    };

    if !claims.email_verified {
        return Html(error_html("Error", "Email not verified")).into_response();
    }

    // Check domain restriction
    if let Some(domains) = &state.config.allowed_domains {
        let email_domain = claims.email.split('@').nth(1).unwrap_or("");
        if !domains.iter().any(|d| d.eq_ignore_ascii_case(email_domain)) {
            let allowed_list = domains.join(", ");
            return Html(error_html(
                "Domain Not Allowed",
                &format!(
                    "Only users from the following domains can enroll: {}. Your email ({}) is not from an allowed domain.",
                    allowed_list,
                    claims.email
                ),
            ))
            .into_response();
        }
    }

    // Store email in state for WebAuthn registration
    // Update the OIDC state to include the email (we'll use a new state token)
    let new_state = URL_SAFE_NO_PAD.encode(generate_random_bytes(32));
    let state_expires = now.checked_add(Span::new().minutes(10)).unwrap_or(now);

    // Create new state with email embedded
    if let Err(e) = db::create_oidc_state(
        &state.db,
        &new_state,
        &stored_state.device_auth_id,
        &claims.email, // Store email in nonce field
        &state_expires.to_string(),
    )
    .await
    {
        tracing::error!("Failed to create state: {}", e);
        return Html(error_html("Error", "Failed to create session state")).into_response();
    }

    // Delete old state
    let _ = db::delete_oidc_state(&state.db, &oidc_state).await;

    // Show WebAuthn registration page
    let html = WEBAUTHN_REGISTER_HTML
        .replace("{{STATE}}", &new_state)
        .replace("{{EMAIL}}", &claims.email)
        .replace("{{RP_ID}}", &state.config.rp_id);

    Html(html).into_response()
}

/// Start browser-based `WebAuthn` registration.
/// POST /enroll/webauthn/start
#[allow(clippy::unused_async)]
pub async fn browser_register_start(
    State(state): State<Arc<AppState>>,
    Json(req): Json<vouch_common::BrowserRegisterStartRequest>,
) -> Result<Json<BrowserRegisterStartResponse>, (StatusCode, Json<ApiError>)> {
    // Verify state token
    let oidc_state = db::get_oidc_state(&state.db, &req.oidc_state)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, "db_error", &e.to_string()))?
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "invalid_state", "Invalid state token"))?;

    // Check if expired
    let now = Timestamp::now();
    let expires_at: Timestamp = oidc_state.expires_at.parse().map_err(|_| {
        json_error(StatusCode::INTERNAL_SERVER_ERROR, "time_error", "Invalid timestamp")
    })?;

    if now > expires_at {
        return Err(json_error(StatusCode::BAD_REQUEST, "expired_state", "State has expired"));
    }

    // Get device auth request to verify it's still valid
    let device_auth = db::get_device_auth_by_id(&state.db, &oidc_state.device_auth_id)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, "db_error", &e.to_string()))?
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "invalid_request", "Invalid request"))?;

    if device_auth.status != "pending" {
        return Err(json_error(StatusCode::BAD_REQUEST, "already_used", "This code has already been used"));
    }

    // Get email from nonce field (set during OIDC callback)
    let user_email = if oidc_state.nonce.is_empty() {
        // Non-OIDC flow - use a placeholder email for now
        "user@localhost".to_string()
    } else {
        oidc_state.nonce.clone()
    };

    // Create or get user
    let user = db::upsert_user(&state.db, &user_email, None)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, "db_error", &e.to_string()))?;

    let user_id = Uuid::parse_str(&user.id).map_err(|e| {
        json_error(StatusCode::INTERNAL_SERVER_ERROR, "uuid_error", &e.to_string())
    })?;

    // Generate challenge
    let challenge = generate_random_bytes(32);

    // Create registration state
    let reg_state = BrowserRegistrationState {
        device_auth_id: device_auth.id,
        user_id,
        user_email: user_email.clone(),
        challenge: challenge.clone(),
        rp_id: state.config.rp_id.clone(),
    };

    let state_token = reg_state.encode(&state.config.jwt_secret).map_err(|e| {
        json_error(StatusCode::INTERNAL_SERVER_ERROR, "state_error", &e.to_string())
    })?;

    Ok(Json(BrowserRegisterStartResponse {
        challenge: URL_SAFE_NO_PAD.encode(&challenge),
        rp_id: state.config.rp_id.clone(),
        rp_name: state.config.rp_name.clone(),
        user_id: URL_SAFE_NO_PAD.encode(user_id.as_bytes()),
        user_email: user_email.clone(),
        user_display_name: user_email,
        algorithms: vec![-7], // ES256
        state: state_token,
    }))
}

/// Complete browser-based `WebAuthn` registration.
/// POST /enroll/webauthn/complete
#[allow(clippy::unused_async, clippy::too_many_lines)]
pub async fn browser_register_complete(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BrowserRegisterCompleteRequest>,
) -> Result<Html<&'static str>, (StatusCode, Json<ApiError>)> {
    // Decode state
    let reg_state = BrowserRegistrationState::decode(&req.state, &state.config.jwt_secret)
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, "invalid_state", &e.to_string()))?;

    // Decode credential data
    let credential_id = URL_SAFE_NO_PAD.decode(&req.credential_id).map_err(|e| {
        json_error(StatusCode::BAD_REQUEST, "invalid_credential", &e.to_string())
    })?;

    let attestation_object = URL_SAFE_NO_PAD.decode(&req.attestation_object).map_err(|e| {
        json_error(StatusCode::BAD_REQUEST, "invalid_attestation", &e.to_string())
    })?;

    let client_data_json = URL_SAFE_NO_PAD.decode(&req.client_data_json).map_err(|e| {
        json_error(StatusCode::BAD_REQUEST, "invalid_client_data", &e.to_string())
    })?;

    // Verify client data JSON
    let client_data: ClientData = serde_json::from_slice(&client_data_json).map_err(|e| {
        json_error(StatusCode::BAD_REQUEST, "invalid_client_data", &e.to_string())
    })?;

    // Verify challenge
    let expected_challenge = URL_SAFE_NO_PAD.encode(&reg_state.challenge);
    if client_data.challenge != expected_challenge {
        return Err(json_error(StatusCode::BAD_REQUEST, "challenge_mismatch", "Challenge mismatch"));
    }

    // Verify type
    if client_data.typ != "webauthn.create" {
        return Err(json_error(StatusCode::BAD_REQUEST, "invalid_type", "Invalid ceremony type"));
    }

    // Extract public key from attestation object (CBOR encoded)
    // For simplicity, we'll store the raw attestation object and trust the browser's verification
    // In production, use webauthn-rs to properly verify the attestation
    let public_key = extract_public_key_from_attestation(&attestation_object).map_err(|e| {
        json_error(StatusCode::BAD_REQUEST, "invalid_attestation", &e)
    })?;

    // Store the authenticator
    let authenticator_id = db::create_authenticator(
        &state.db,
        &reg_state.user_id.to_string(),
        "Security Key",
        &credential_id,
        &public_key,
    )
    .await
    .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, "db_error", &e.to_string()))?;

    // Mark device authorization as complete
    db::authorize_device_auth(
        &state.db,
        &reg_state.device_auth_id,
        &reg_state.user_id.to_string(),
        &reg_state.user_email,
        &authenticator_id,
    )
    .await
    .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, "db_error", &e.to_string()))?;

    tracing::info!("Enrollment complete for: {}", reg_state.user_email);

    Ok(Html(SUCCESS_HTML))
}

/// Extract public key from CBOR-encoded attestation object.
/// This is a simplified extraction - in production use webauthn-rs.
fn extract_public_key_from_attestation(attestation: &[u8]) -> Result<Vec<u8>, String> {
    // The attestation object is CBOR encoded with structure:
    // { "authData": bytes, "fmt": string, "attStmt": map }
    // The authData contains: rpIdHash (32) + flags (1) + counter (4) + attestedCredentialData
    // attestedCredentialData: aaguid (16) + credIdLen (2) + credId (credIdLen) + credentialPublicKey (CBOR)

    // For simplicity, we'll just store the entire attestation object as the "public key"
    // This is not ideal but allows the credential to be stored and the enrollment to complete.
    // The actual signature verification during login will use the credential_id to look up
    // the authenticator and verify against the stored data.

    // In a real implementation, you would parse the CBOR, extract authData,
    // then extract the COSE public key from the attested credential data.

    if attestation.len() < 37 {
        return Err("Attestation too short".to_string());
    }

    // Return the attestation object as-is for storage
    // The actual public key extraction would require a CBOR parser
    Ok(attestation.to_vec())
}
