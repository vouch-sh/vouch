// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Enrollment handlers for browser-based device authorization flow.

use crate::AppState;
use crate::db::ClientInfo;
use crate::db::{self, AuthEventParams, AuthEventType};
use crate::impl_template_response;
use crate::infra::i18n::Tr;
use askama::Template;
use axum::{
    Form, Json,
    body::Body,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use vouch_common::{BrowserRegisterCompleteRequest, BrowserRegisterStartResponse};

use super::session::AuthContext;
use super::{
    create_session_cookie, extract_session_from_cookie, hash_token,
    validate_registration_attestation,
};
use crate::error::ServiceError;
use crate::redact_email;
use crate::services::auth::{
    ClientAuthProof, CreateOAuthTokenParams, GrantProof, SenderConstraintProof, TokenIssuanceProof,
    create_oauth_access_token,
};
use crate::services::idp::IdentityResult;
use crate::services::keys as key_svc;
use crate::services::oidc::ScopeSet;

// ============================================================================
// Templates
// ============================================================================

/// Device code entry page template.
#[derive(Template)]
#[template(path = "device_verify.html")]
pub(crate) struct DeviceVerifyTemplate {
    pub error: Option<String>,
    /// Pre-filled code from `verification_uri_complete` (RFC 8628 §3.3.1),
    /// already normalized and format-validated; `None` leaves the box empty.
    pub user_code: Option<String>,
}

/// A single security key, pre-formatted for server-side rendering.
///
/// The created-at timestamp is formatted here so the template renders
/// display-ready text — escaping is handled structurally by Askama, so no
/// client-side DOM construction is needed.
pub(crate) struct KeyDisplay {
    pub id: String,
    pub name: String,
    pub device_model: Option<String>,
    /// Human-readable registration date, e.g. "Jun 09, 2026".
    pub created_at: String,
}

/// Key management page template (shown after OAuth callback).
/// Authentication is via cookie, not state token in template.
///
/// The key list is rendered server-side via the `enroll_keys_container.html`
/// partial (`{% include %}`); mutations (register/delete) reload the page and
/// rename is a form POST, matching the server-rendered pattern used by the
/// admin pages.
#[derive(Template)]
#[template(path = "enroll_keys.html")]
pub(crate) struct EnrollKeysTemplate {
    /// Authentication context for header display.
    pub auth: AuthContext,
    /// Registered keys, rendered server-side.
    pub keys: Vec<KeyDisplay>,
    /// Whether delete controls are shown (a user must keep at least one key).
    pub can_delete: bool,
    /// One-shot error message from a prior failed form POST (e.g. rename).
    pub flash_message: Option<String>,
}

/// Success page template.
#[derive(Template)]
#[template(path = "success.html")]
pub(crate) struct SuccessTemplate;

/// Error page template.
#[derive(Template)]
#[template(path = "error.html")]
pub(crate) struct ErrorTemplate {
    pub title: String,
    pub message: String,
    pub back_url: Option<String>,
}

/// SAML POST binding auto-submit form template.
///
/// Rendered when the upstream IdP uses SAML POST binding. The page
/// auto-submits via `onload` JavaScript; the `<noscript>` fallback
/// handles browsers without JavaScript.
#[derive(Template)]
#[template(path = "saml_post_form.html")]
pub(crate) struct SamlPostFormTemplate {
    pub action_url: String,
    pub saml_request: String,
    pub relay_state: String,
}

/// Identity provider chooser shown when multiple IdPs are configured and
/// the user has not yet selected one.
///
/// `is_post = true` renders each IdP as a submit button inside a form
/// (used by `POST /device`, which must carry the validated `user_code`
/// forward as a hidden field). `is_post = false` renders each IdP as a
/// link to `{action}?provider=<slug>` (used by `GET /enroll/start`).
#[derive(Template)]
#[template(path = "select_idp.html")]
pub(crate) struct SelectIdpTemplate {
    /// Form action URL or link base URL (e.g., `/device`, `/enroll/start`).
    pub action: String,
    /// Render as POST form (true) or anchor links with `?provider=` (false).
    pub is_post: bool,
    /// Hidden `user_code` carried forward when `is_post` is true.
    pub user_code: Option<String>,
    /// IdPs to show, in `VOUCH_IDPS` order.
    pub idp_entries: Vec<super::home::IdpEntry>,
}

impl_template_response!(
    DeviceVerifyTemplate,
    EnrollKeysTemplate,
    SuccessTemplate,
    ErrorTemplate,
    SamlPostFormTemplate,
    SelectIdpTemplate,
);

// ============================================================================
// Request/Response Types
// ============================================================================

/// Form data for user code submission.
///
/// `provider` is set on the second POST when the chooser is rendered
/// (multiple IdPs configured). On the initial POST it is `None` and the
/// handler either auto-selects the single IdP, renders the chooser (multiple
/// IdPs), or returns a "Not Configured" error (no IdPs — server should have
/// refused to start).
#[derive(Debug, Deserialize)]
pub(crate) struct UserCodeForm {
    user_code: String,
    #[serde(default)]
    provider: Option<String>,
}

/// Query params for OIDC callback.
#[derive(Debug, Deserialize)]
pub(crate) struct OidcCallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// OIDC token response.
#[derive(Deserialize)]
struct OidcTokenResponse {
    id_token: secrecy::SecretString,
    #[expect(dead_code, reason = "reserved for serde DTO conformance / future use")]
    access_token: secrecy::SecretString,
}

// Custom Debug that redacts both tokens to prevent accidental log exposure of
// the upstream IdP's credentials for this user.
impl std::fmt::Debug for OidcTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcTokenResponse")
            .field("id_token", &"[REDACTED]")
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

/// Client data JSON structure from `WebAuthn` response.
#[derive(Deserialize)]
#[expect(dead_code, reason = "reserved for serde DTO conformance / future use")]
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
    /// Serialized webauthn-rs PasskeyRegistration state for verification.
    webauthn_state: webauthn_rs::prelude::PasskeyRegistration,
    /// RFC 8725 §3.11: Issued at time for expiration enforcement.
    iat: i64,
    /// RFC 8725 §3.11: Expiration time (5 minutes).
    exp: i64,
}

impl BrowserRegistrationState {
    async fn encode(
        &self,
        signer: &crate::crypto::jwt::StateTokenSigner,
    ) -> Result<String, crate::crypto::jwt::StateTokenError> {
        signer
            .encode_state_token(self, crate::crypto::jwt::JwtType::BrowserRegistrationState)
            .await
    }

    async fn decode(
        token: &str,
        signer: &crate::crypto::jwt::StateTokenSigner,
    ) -> Result<Self, crate::crypto::jwt::StateTokenError> {
        signer
            .decode_state_token(token, crate::crypto::jwt::JwtType::BrowserRegistrationState)
            .await
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// Query parameters for the device verification page.
#[derive(Debug, Deserialize)]
pub(crate) struct DeviceVerifyQuery {
    /// RFC 8628 §3.3.1 `user_code` carried by `verification_uri_complete`.
    user_code: Option<String>,
}

/// Show device code entry page.
/// GET /device[?user_code=XXXX-XXXX]
pub(crate) async fn device_verify_page(
    Query(query): Query<DeviceVerifyQuery>,
) -> impl IntoResponse {
    // Pre-fill only well-formed codes; arbitrary query input is never reflected.
    let user_code = query
        .user_code
        .map(|c| normalize_user_code(&c))
        .filter(|c| is_valid_user_code_format(c));
    DeviceVerifyTemplate {
        error: None,
        user_code,
    }
}

/// Handle device code submission.
/// POST /device
pub(crate) async fn device_verify_submit(
    State(state): State<Arc<AppState>>,
    Form(form): Form<UserCodeForm>,
) -> Response {
    // Normalize user code (uppercase, strip whitespace, ensure dash)
    let user_code = normalize_user_code(&form.user_code);

    // Validate user code format before DB lookup.
    // Valid codes are "XXXX-XXXX" where X is from the device code alphabet
    // (consonants: BCDFGHJKLMNPQRSTVWXZ). Reject anything else immediately.
    if !is_valid_user_code_format(&user_code) {
        return DeviceVerifyTemplate {
            error: Some("Invalid code. Please check and try again.".to_string()),
            user_code: None,
        }
        .into_response();
    }

    // Look up device auth request
    let request = match db::get_device_auth_by_user_code(&state.store, &user_code).await {
        Ok(Some(req)) => req,
        Ok(None) => {
            return DeviceVerifyTemplate {
                error: Some("Invalid code. Please check and try again.".to_string()),
                user_code: None,
            }
            .into_response();
        }
        Err(_) => {
            return DeviceVerifyTemplate {
                error: Some("An error occurred. Please try again.".to_string()),
                user_code: None,
            }
            .into_response();
        }
    };

    // Check if expired
    let now = Timestamp::now();
    if now > request.expires_at {
        return DeviceVerifyTemplate {
            error: Some("This code has expired. Please request a new one.".to_string()),
            user_code: None,
        }
        .into_response();
    }

    // Check if already used
    if !matches!(request.state, db::DeviceAuthState::Pending) {
        return DeviceVerifyTemplate {
            error: Some("This code has already been used.".to_string()),
            user_code: None,
        }
        .into_response();
    }

    // Select which upstream IdP to use:
    //   * `form.provider` set → user picked from the chooser; validate slug.
    //   * Zero IdPs configured → refuse: without IdP auth we cannot verify
    //     an email, enforce allowed_domains, or bind a key to a real user.
    //   * One IdP configured → auto-select (no UI choice to make).
    //   * Two+ IdPs configured, no choice yet → render the chooser. The
    //     validated `user_code` is carried as a hidden field, which doubles
    //     as an implicit CSRF token (the attacker must already hold it).
    let base_url = state.config().base_url.clone();
    let chosen_idp: &crate::services::idp::ConfiguredIdp = match form
        .provider
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(slug) => match state.idp(slug) {
            Some(idp) => idp,
            None => {
                return ErrorTemplate {
                    title: Tr::new("enroll-error-unknown-provider-title").to_string(),
                    message: Tr::new("enroll-error-unknown-provider")
                        .arg("slug", slug)
                        .to_string(),
                    back_url: Some("/device".to_string()),
                }
                .into_response();
            }
        },
        None => {
            if state.idps.len() > 1 {
                return SelectIdpTemplate {
                    action: "/device".to_string(),
                    is_post: true,
                    user_code: Some(user_code.clone()),
                    idp_entries: super::home::build_idp_entries(&state.idps),
                }
                .into_response();
            }
            match state.idps.first() {
                Some(idp) => idp,
                None => {
                    return ErrorTemplate {
                        title: Tr::new("enroll-error-not-configured-title").to_string(),
                        message: Tr::new("enroll-error-idp-not-configured").to_string(),
                        back_url: Some("/".to_string()),
                    }
                    .into_response();
                }
            }
        }
    };

    let auth_provider_id = chosen_idp.id().to_string();
    let auth_request_result = chosen_idp.initiate_auth(&base_url);

    let auth_request = match auth_request_result {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to initiate auth: {e:#}");
            return ErrorTemplate {
                title: Tr::new("error-heading").to_string(),
                message: Tr::new("enroll-error-auth-start-failed").to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    let state_expires = now.checked_add(Span::new().minutes(10)).unwrap_or(now);

    if let Err(e) = db::create_oidc_state(
        &state.store,
        &auth_request.state_key,
        Some(&request.id),
        &auth_request.nonce,
        &auth_request.code_verifier,
        state_expires,
        &auth_provider_id,
    )
    .await
    {
        tracing::error!("Failed to create auth state: {}", e);
        return ErrorTemplate {
            title: Tr::new("error-heading").to_string(),
            message: Tr::new("enroll-error-state-create-failed").to_string(),
            back_url: None,
        }
        .into_response();
    }

    // Use 303 See Other (not 307) to ensure browser converts POST to GET
    // A 307 would preserve the POST method and body, sending user_code to the IdP
    match auth_request.action {
        crate::services::idp::AuthAction::Redirect { url } => Redirect::to(&url).into_response(),
        crate::services::idp::AuthAction::PostForm {
            action_url,
            saml_request,
            relay_state,
        } => SamlPostFormTemplate {
            action_url,
            saml_request,
            relay_state,
        }
        .into_response(),
    }
}

/// Handle OIDC callback.
/// GET /oauth/callback
#[expect(
    clippy::too_many_lines,
    reason = "axum handler; OIDC callback orchestrates IdP exchange and enrollment"
)]
pub(crate) async fn oidc_callback(
    State(state): State<Arc<AppState>>,
    client_info: ClientInfo,
    Query(params): Query<OidcCallbackParams>,
) -> Response {
    // Check for error response
    if let Some(error) = params.error {
        let desc = params
            .error_description
            .unwrap_or_else(|| "Unknown error".to_string());
        return ErrorTemplate {
            title: error,
            message: desc,
            back_url: None,
        }
        .into_response();
    }

    // Get authorization code and state
    let Some(code) = params.code else {
        return ErrorTemplate {
            title: Tr::new("error-heading").to_string(),
            message: Tr::new("enroll-error-missing-code").to_string(),
            back_url: None,
        }
        .into_response();
    };

    let Some(oidc_state) = params.state else {
        return ErrorTemplate {
            title: Tr::new("error-heading").to_string(),
            message: Tr::new("enroll-error-missing-state").to_string(),
            back_url: None,
        }
        .into_response();
    };

    // Validate state length before DB lookup.
    // OIDC state is base64url-encoded 32 random bytes (43 chars).
    if oidc_state.len() > 128 {
        return ErrorTemplate {
            title: Tr::new("error-heading").to_string(),
            message: Tr::new("enroll-error-invalid-state").to_string(),
            back_url: None,
        }
        .into_response();
    }

    // Atomically consume the OIDC state. The returned witness is the
    // structural proof threaded into TokenIssuanceProof below — the only
    // path to `GrantProof::EnrollmentBootstrap`. Replaces the prior
    // get-then-delete pattern, closing the read-vs-consume TOCTOU that
    // let two concurrent callbacks both pass validation and issue tokens.
    let (stored_state, oidc_state_claim) =
        match db::try_consume_oidc_state(&state.store, &oidc_state).await {
            Ok(pair) => pair,
            Err(db::ClaimError::AlreadyConsumed) => {
                return ErrorTemplate {
                    title: Tr::new("error-heading").to_string(),
                    message: Tr::new("enroll-error-state-expired").to_string(),
                    back_url: None,
                }
                .into_response();
            }
            Err(e) => {
                tracing::error!("Failed to consume OIDC state: {e:#}");
                return ErrorTemplate {
                    title: Tr::new("error-heading").to_string(),
                    message: Tr::new("enroll-error-state-verify-failed").to_string(),
                    back_url: None,
                }
                .into_response();
            }
        };

    // Exchange code for tokens using discovered OIDC token endpoint.
    // This handler is OIDC-specific: SAML responses go to POST /saml/acs.
    //
    // Look up the IdP by the slug stored in the OIDC state doc. Fall back to the
    // first configured OIDC IdP for state docs written before multi-IdP support
    // (rolling deploy compatibility).
    let oidc_provider = if stored_state.provider_id.is_empty() {
        state.idps.iter().find_map(|i| match i {
            crate::services::idp::ConfiguredIdp::Oidc(p) => Some(p),
            crate::services::idp::ConfiguredIdp::Saml(_) => None,
        })
    } else {
        state.idp(&stored_state.provider_id).and_then(|i| match i {
            crate::services::idp::ConfiguredIdp::Oidc(p) => Some(p),
            crate::services::idp::ConfiguredIdp::Saml(_) => None,
        })
    };
    let Some(oidc_provider) = oidc_provider else {
        return ErrorTemplate {
            title: Tr::new("error-heading").to_string(),
            message: Tr::new("enroll-error-oidc-not-configured").to_string(),
            back_url: None,
        }
        .into_response();
    };
    let config = state.config();
    let client_id = oidc_provider.client_id.as_str();
    let client_secret = oidc_provider.client_secret.expose_secret();
    let redirect_uri = format!("{}/oauth/callback", config.base_url);

    let token_url = oidc_provider.provider.token_endpoint.as_str();

    // RFC 7636: Include code_verifier in token exchange (PKCE).
    // Build form params dynamically to only include code_verifier when present.
    let mut form_params = vec![
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code", code.as_str()),
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect_uri.as_str()),
    ];
    if !stored_state.code_verifier.is_empty() {
        form_params.push(("code_verifier", stored_state.code_verifier.as_str()));
    }

    let token_response = match state
        .http_client
        .post(token_url)
        .form(&form_params)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("Failed to exchange code: {}", e);
            return ErrorTemplate {
                title: Tr::new("error-heading").to_string(),
                message: Tr::new("enroll-error-auth-complete-failed").to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    if !token_response.status().is_success() {
        let error_text = token_response.text().await.unwrap_or_default();
        tracing::error!("Token exchange failed: {}", error_text);
        return ErrorTemplate {
            title: Tr::new("error-heading").to_string(),
            message: Tr::new("enroll-error-auth-complete-failed").to_string(),
            back_url: None,
        }
        .into_response();
    }

    let tokens: OidcTokenResponse = match token_response.json().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to parse token response: {}", e);
            return ErrorTemplate {
                title: Tr::new("error-heading").to_string(),
                message: Tr::new("enroll-error-auth-complete-failed").to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    // Verify ID token: signature, issuer, audience, nonce, email_verified,
    // and extract domain (OIDC Core Section 3.1.3.7).
    let identity = match crate::services::idp::oidc::verify_id_token(
        &state.http_client,
        &oidc_provider.provider,
        tokens.id_token.expose_secret(),
        client_id,
        &stored_state.nonce,
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("ID token verification failed: {e:#}");
            return ErrorTemplate {
                title: Tr::new("error-heading").to_string(),
                message: Tr::new("enroll-error-token-verify-failed").to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    complete_enrollment_after_identity(
        &state,
        &stored_state,
        identity,
        oidc_state_claim,
        client_info,
    )
    .await
}

#[expect(
    clippy::too_many_lines,
    reason = "linear enrollment completion sequence after IdP identity"
)]
pub(crate) async fn complete_enrollment_after_identity(
    state: &Arc<AppState>,
    stored_state: &db::OidcState,
    identity: IdentityResult,
    oidc_state_claim: db::OidcStateClaim,
    client_info: ClientInfo,
) -> Response {
    // Check domain restriction.
    // For Google consumers (no `hd` claim), `identity.domain` is `None`,
    // so `email_domain` becomes "" and will never match an allowed domain.
    if let Some(domains) = state
        .config()
        .allowed_domains
        .as_ref()
        .filter(|d| !d.is_empty())
    {
        let email_domain = identity.domain.as_deref().unwrap_or("");
        if !domains.iter().any(|d| d.eq_ignore_ascii_case(email_domain)) {
            let allowed_list = domains.join(", ");
            return ErrorTemplate {
                title: Tr::new("enroll-error-domain-not-allowed-title").to_string(),
                message: Tr::new("enroll-error-domain-not-allowed")
                    .arg("domains", allowed_list.as_str())
                    .arg("email", identity.email.as_str())
                    .to_string(),
                back_url: None,
            }
            .into_response();
        }
    }

    // Enroll user with organization in a single atomic transaction.
    // This ensures that if org creation succeeds but user creation fails,
    // the entire operation is rolled back to prevent orphaned state.
    // Account matching keys on the upstream (issuer, subject) pair first;
    // email is only a linking fallback for accounts with no binding yet.
    let user = match db::enroll_user_with_org(
        &state.store,
        &identity.email,
        None,
        identity.domain.as_deref(),
        identity.upstream.as_ref(),
    )
    .await
    {
        Ok(user) => user,
        Err(db::EnrollUserError::IdentityConflict { user_id, issuer }) => {
            // The email matched an existing account already bound to this
            // issuer, and this login either asserted a different subject
            // or (a non-durable NameID/sub format) asserted none at all.
            // Both are the shape of an upstream email reassignment
            // (account-takeover attempt) or a login too weak to trust for
            // an already-bound account, so refuse to link and leave an
            // audit trail.
            tracing::warn!(
                user_id = %user_id,
                issuer = %issuer,
                email = %redact_email(&identity.email),
                "Refusing IdP login: could not reassert the subject bound \
                 to the account with this email for this issuer"
            );
            let event = db::AuthEventParams {
                user_id,
                event_type: db::AuthEventType::IdentityBindRefused,
                success: false,
                failure_reason: Some(
                    "upstream subject did not match the bound subject".to_string(),
                ),
                idp_issuer: Some(issuer),
                client: client_info,
                ..Default::default()
            };
            db::spawn_audit_event(&state.audit, event, Some(identity.email.clone()));
            return ErrorTemplate {
                title: Tr::new("enroll-error-identity-conflict-title").to_string(),
                message: Tr::new("enroll-error-identity-conflict").to_string(),
                back_url: None,
            }
            .into_response();
        }
        Err(db::EnrollUserError::Deactivated { user_id, email }) => {
            // The account exists but is deactivated (SCIM `active: false` or
            // admin deactivation). Every other login path refuses these
            // accounts; the SSO front door must too — otherwise deactivation
            // is a soft-delete the user can undo by signing in again.
            tracing::warn!(
                user_id = %user_id,
                email = %redact_email(&email),
                "Refusing IdP login for deactivated account"
            );
            let event = db::AuthEventParams {
                user_id,
                event_type: db::AuthEventType::LoginFailed,
                success: false,
                failure_reason: Some("user_deactivated".to_string()),
                client: client_info,
                ..Default::default()
            };
            db::spawn_audit_event(&state.audit, event, Some(email));
            return ErrorTemplate {
                title: Tr::new("enroll-error-account-deactivated-title").to_string(),
                message: Tr::new("enroll-error-account-deactivated").to_string(),
                back_url: None,
            }
            .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to enroll user: {}", e);
            return ErrorTemplate {
                title: Tr::new("error-heading").to_string(),
                message: Tr::new("enroll-error-user-create-failed").to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    // The account email is canonical. If the IdP asserted a different
    // address for a (issuer, subject)-matched account, the drift is
    // logged but never written back: there is no email-change machinery,
    // and downstream artifacts (sessions, certs, audit) must stay
    // consistent with the stored account.
    if user.email != crate::email::Email::new(&identity.email).as_str() {
        tracing::warn!(
            user_id = %user.id,
            account_email = %redact_email(&user.email),
            asserted_email = %redact_email(&identity.email),
            "Upstream email differs from account email; keeping account email"
        );
    }

    if user.newly_bound
        && let Some(ref upstream) = identity.upstream
    {
        let event = db::AuthEventParams {
            user_id: user.id.clone(),
            event_type: db::AuthEventType::IdentityBound,
            success: true,
            idp_issuer: Some(upstream.issuer.clone()),
            client: client_info.clone(),
            ..Default::default()
        };
        db::spawn_audit_event(&state.audit, event, Some(user.email.clone()));
    }

    // Create session for this user (using session cookie instead of enrollment cookie)
    let now = Timestamp::now();
    let session_hours = i64::try_from(state.config().session_hours).unwrap_or(8);
    let duration = Span::new().hours(session_hours);
    let expires = match now.checked_add(duration) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("Failed to calculate session expiration: {}", e);
            return ErrorTemplate {
                title: Tr::new("error-heading").to_string(),
                message: Tr::new("enroll-error-session-failed").to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    // Get authenticator (if any) for session claims
    let existing_auths = db::get_authenticators_for_user(&state.store, &user.id)
        .await
        .unwrap_or_default();
    let existing_authenticator = existing_auths.first();
    let authenticator_id = existing_authenticator.map(|a| a.id.clone());
    let hardware_aaguid = existing_authenticator.and_then(|a| a.aaguid.clone());

    // Snapshot org domain so the enrollment session carries the federation
    // claims that match the user's state at this moment. Fail closed: the
    // snapshot is captured exactly once, so silently dropping a transient
    // DB error would permanently degrade this session's `hd` claim.
    let org_domain = match user.org_id.as_deref() {
        Some(org_id) => match db::get_organization_domain(&state.store, org_id).await {
            Ok(domain) => domain,
            Err(e) => {
                tracing::error!("Failed to snapshot org domain: {}", e);
                return ErrorTemplate {
                    title: Tr::new("error-heading").to_string(),
                    message: Tr::new("enroll-error-session-failed").to_string(),
                    back_url: None,
                }
                .into_response();
            }
        },
        None => None,
    };

    // Issue an OAuth access token for the enrollment session.
    // This session is created after upstream IdP auth (OIDC/SAML) but BEFORE
    // FIDO2 WebAuthn registration — do NOT claim AAL3 or FIDO2 amr here.
    // The proper FIDO2 claims are set later in browser_register_complete.
    let client_id_for_token = state.config().base_url.clone();
    let session_result = match create_oauth_access_token(
        state,
        CreateOAuthTokenParams {
            user_id: &user.id,
            email: &user.email,
            authenticator_id: authenticator_id.as_deref(),
            client_id: &client_id_for_token,
            scope: Some(ScopeSet::all()),
            dpop_jkt: None,
            mtls_cert_thumbprint: None,
            act: None,
            audience: None,
            auth_time: Some(now.as_second()),
            hardware_verification: crate::services::auth::HardwareVerification::NotVerified,
            session_purpose: db::SessionPurpose::OAuthAccessToken,
            authorization_details: None,
            hardware_aaguid: hardware_aaguid.as_deref(),
            org_domain: org_domain.as_deref(),
        },
        TokenIssuanceProof {
            grant: GrantProof::EnrollmentBootstrap(oidc_state_claim),
            client_auth: ClientAuthProof::NoAuth(
                crate::services::auth::NoClientAuth::internal_endpoint(),
            ),
            sender_constraint: SenderConstraintProof::no_registered_client(),
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to create session: {}", e);
            return ErrorTemplate {
                title: Tr::new("error-heading").to_string(),
                message: Tr::new("enroll-error-session-failed").to_string(),
                back_url: None,
            }
            .into_response();
        }
    };
    let token = session_result.token;
    let token_hash = hash_token(token.expose_secret());

    // Handle CLI-initiated device auth flow. Direct browser sign-ins carry
    // no device_auth_id in the OIDC state (see direct_enroll_start).
    //
    // Either way the CLI is released by a key ceremony, never by the IdP
    // sign-in alone, which authenticates the person rather than the hardware.
    let mut require_assertion = false;

    if let Some(device_auth_id) = stored_state.device_auth_id.as_deref() {
        // Refuse before the key ceremony if the request the CLI is waiting on
        // is gone or already settled — the row expired and was reclaimed, or
        // the callback was submitted twice. Continuing would walk the user
        // through a touch that could never release the CLI (#746).
        let pending = db::get_device_auth_by_id(&state.store, device_auth_id)
            .await
            .ok()
            .flatten()
            .is_some_and(|r| matches!(r.state, db::DeviceAuthState::Pending));
        if !pending {
            tracing::error!("Device auth '{device_auth_id}' is missing or already settled");
            return ErrorTemplate {
                title: Tr::new("error-heading").to_string(),
                message: Tr::new("enroll-error-device-auth-approve-failed").to_string(),
                back_url: None,
            }
            .into_response();
        }

        // Carry the device_auth_id in an enrollment session so whichever
        // ceremony follows can authorize it: browser_register_complete after
        // a first-key registration, browser_login_complete after an assertion.
        if let Err(e) = db::create_enrollment_session(
            &state.store,
            &user.id,
            &user.email,
            &token_hash,
            Some(device_auth_id),
            expires,
        )
        .await
        {
            // Without this row neither ceremony can authorize the device
            // auth, so continuing would walk the user through a key
            // ceremony that could never release the waiting CLI.
            tracing::error!("Failed to create enrollment session for CLI: {}", e);
            return ErrorTemplate {
                title: Tr::new("error-heading").to_string(),
                message: Tr::new("enroll-error-session-create-failed").to_string(),
                back_url: None,
            }
            .into_response();
        }
        require_assertion = authenticator_id.is_some();
    } else if authenticator_id.is_some() {
        // Returning user signing in directly via the website (upstream IdP,
        // no CLI). No FIDO2 assertion happened, so authenticator_id stays
        // empty — distinguishing this from passkey logins. Fresh enrollees
        // are covered by the Enrollment event in browser_register_complete.
        let event = db::AuthEventParams {
            user_id: user.id.clone(),
            event_type: db::AuthEventType::LoginSuccess,
            success: true,
            client: client_info,
            ..Default::default()
        };
        db::spawn_audit_event(&state.audit, event, Some(user.email.clone()));
    }

    // No explicit state delete here — `try_consume_oidc_state` already
    // marked the row `consumed_at = Some(now)` (replay-blocking) and
    // `delete_expired_oidc_states` will reclaim the row at expiry.

    // A returning user with a CLI waiting goes to the login page to assert
    // with their key; everyone else lands on the keys page, where a
    // first-time enrollee registers one.
    let destination = if require_assertion {
        "/login"
    } else {
        "/enroll/keys"
    };

    tracing::info!("Session created for user: {}", redact_email(&user.email));
    tracing::debug!("Setting session cookie and redirecting to {destination}");

    let cookie = create_session_cookie(token.expose_secret(), session_hours.saturating_mul(3600));

    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, destination)
        .header(header::SET_COOKIE, cookie.to_string())
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Serve the key management page.
/// Fetch the user's keys and pre-format them for server-side rendering.
///
/// Returns the display rows plus whether delete controls should be shown
/// (a user must always retain at least one key).
async fn load_keys_for_display(
    state: &Arc<AppState>,
    user_sub: &str,
    authenticator_id: Option<&str>,
) -> Result<(Vec<KeyDisplay>, bool), ServiceError> {
    let keys = key_svc::list_keys_for_user(&state.store, user_sub, authenticator_id).await?;
    let can_delete = keys.len() > 1;
    let display = keys
        .into_iter()
        .map(|k| KeyDisplay {
            id: k.id,
            name: k.name,
            device_model: k.device_model,
            created_at: k.created_at.strftime("%b %d, %Y").to_string(),
        })
        .collect();
    Ok((display, can_delete))
}

/// GET /enroll/keys
/// Authentication is via session cookie (set by oidc_callback).
pub(crate) async fn enroll_keys_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Response {
    tracing::debug!("enroll_keys_page: checking for session cookie");

    // Get session from cookie
    match extract_session_from_cookie(&state, &jar).await {
        Ok(token) => {
            let email = token.email.clone().unwrap_or_default();
            tracing::debug!(
                "enroll_keys_page: found valid session for {}",
                redact_email(&email)
            );

            // Render the key list server-side.
            let (keys, can_delete) =
                match load_keys_for_display(&state, &token.sub, token.authenticator_id.as_deref())
                    .await
                {
                    Ok(result) => result,
                    Err(err) => {
                        tracing::error!(error = ?err, "enroll_keys_page: failed to load keys");
                        return err.into_response();
                    }
                };

            // Look up user to check org membership
            let (has_org, is_org_admin) = match db::get_user_by_id(&state.store, &token.sub).await {
                Ok(Some(user)) => (user.org_id.is_some(), user.is_org_admin),
                _ => (false, false),
            };
            let auth = AuthContext {
                authenticated: true,
                user_id: Some(token.sub),
                user_email: Some(email),
                has_org,
                is_org_admin,
            };

            // Consume any flash error set by a prior failed form POST (rename),
            // expiring the cookie in the response — the PRG pattern used by the
            // admin pages. Scoped to the keys path so admin flashes never
            // surface (or get cleared) here.
            let flash_message = super::admin::flash::read(&jar).err;
            let jar = super::admin::flash::clear_at(jar, super::admin::flash::KEYS_PATH);

            (
                jar,
                EnrollKeysTemplate {
                    auth,
                    keys,
                    can_delete,
                    flash_message,
                },
            )
                .into_response()
        }
        Err(err) => {
            tracing::warn!(
                error = ?err,
                "enroll_keys_page: session extraction failed, redirecting to /enroll/start"
            );
            // No valid session - redirect to sign in
            Redirect::to("/enroll/start").into_response()
        }
    }
}

/// Start browser-based `WebAuthn` registration.
/// POST /enroll/webauthn/start
/// Authentication is via session cookie (set by oidc_callback).
pub(crate) async fn browser_register_start(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<BrowserRegisterStartResponse>, ServiceError> {
    // Get session from cookie
    let token = extract_session_from_cookie(&state, &jar)
        .await
        .map_err(|_| {
            ServiceError::api(
                StatusCode::UNAUTHORIZED,
                "invalid_session",
                "Invalid or expired session",
            )
        })?;

    let user_id = Uuid::parse_str(&token.sub).map_err(|e| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "uuid_error",
            e.to_string(),
        )
    })?;

    let user_email = token.email.clone().unwrap_or_default();

    // A deactivated user's surviving enrollment cookie must not begin new
    // hardware-key registration. `extract_session_from_cookie` deliberately
    // skips the `active` check, so this mutating endpoint carries its own
    // guard (per-handler point-fix pattern).
    let account = db::get_user_by_id(&state.store, &token.sub)
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;
    if let Some(account) = account
        && !account.active
    {
        return Err(ServiceError::Forbidden("user_deactivated"));
    }

    // Get device_auth_id from enrollment session if available (for CLI polling).
    // Look up by session token hash, since oidc_callback stores the
    // enrollment session keyed to the same token.
    let device_auth_id = match jar
        .get(vouch_common::SESSION_COOKIE_NAME)
        .map(|c| c.value())
    {
        Some(cookie_val) => {
            let token_hash = hash_token(cookie_val);
            let enrollment_session =
                db::get_enrollment_session_by_token_hash(&state.store, &token_hash)
                    .await
                    .map_err(|e| {
                        tracing::error!("Failed to look up enrollment session: {}", e);
                        ServiceError::api(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "db_error",
                            "Failed to look up enrollment session",
                        )
                    })?;
            enrollment_session
                .and_then(|es| es.device_auth_id)
                .unwrap_or_default()
        }
        None => String::new(),
    };

    tracing::debug!(
        "browser_register_start: resolved device_auth_id='{}'",
        if device_auth_id.is_empty() {
            "(empty)"
        } else {
            &device_auth_id
        }
    );

    // Get any existing credentials for this user to exclude them
    let existing_auths = db::get_authenticators_for_user(&state.store, &token.sub).await?;

    tracing::info!(
        "browser_register_start: user {} has {} existing credentials",
        redact_email(&user_email),
        existing_auths.len()
    );

    let exclude_credentials: Vec<webauthn_rs::prelude::CredentialID> = existing_auths
        .iter()
        .map(|a| webauthn_rs::prelude::CredentialID::from(a.credential_id.clone()))
        .collect();

    // Build exclude_credential_ids for browser (base64url encoded)
    let exclude_credential_ids: Vec<String> = existing_auths
        .iter()
        .map(|a| {
            let encoded = URL_SAFE_NO_PAD.encode(&a.credential_id);
            tracing::debug!(
                "Excluding credential: {} (len={})",
                encoded,
                a.credential_id.len()
            );
            encoded
        })
        .collect();

    // Use webauthn-rs to generate proper registration options with cryptographic verification
    let (mut ccr, webauthn_state) = state
        .webauthn
        .start_passkey_registration(user_id, &user_email, &user_email, Some(exclude_credentials))
        .map_err(|e| {
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "webauthn_error",
                e.to_string(),
            )
        })?;

    // Request direct attestation so the browser forwards the x5c certificate
    // chain. This enables attestation chain validation against pinned Yubico
    // root CAs and AAGUID extraction from the leaf certificate.
    ccr.public_key.attestation = Some(webauthn_rs_proto::AttestationConveyancePreference::Direct);

    // Signal that only cross-platform security keys (USB/NFC) are accepted.
    // This suppresses the macOS "Scan QR Code" (hybrid/caBLE) option and
    // platform authenticator prompts (Touch ID, Windows Hello).
    if let Some(ref mut sel) = ccr.public_key.authenticator_selection {
        sel.authenticator_attachment =
            Some(webauthn_rs_proto::AuthenticatorAttachment::CrossPlatform);
    } else {
        ccr.public_key.authenticator_selection =
            Some(webauthn_rs_proto::AuthenticatorSelectionCriteria {
                authenticator_attachment: Some(
                    webauthn_rs_proto::AuthenticatorAttachment::CrossPlatform,
                ),
                ..Default::default()
            });
    }
    ccr.public_key.hints = Some(vec![
        webauthn_rs_proto::PublicKeyCredentialHints::SecurityKey,
    ]);

    // Create registration state with webauthn verification state
    let now = jiff::Timestamp::now();
    let reg_exp = now
        .checked_add(jiff::Span::new().minutes(5))
        .map_or(now.as_second().saturating_add(300), |t| t.as_second());
    let reg_state = BrowserRegistrationState {
        device_auth_id,
        user_id,
        user_email: user_email.clone(),
        webauthn_state,
        iat: now.as_second(),
        exp: reg_exp,
    };

    let state_token = reg_state.encode(&state.state_signer).await.map_err(|e| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "state_error",
            e.to_string(),
        )
    })?;

    // Extract challenge from webauthn-rs generated options
    // The challenge is exposed via the public_key.challenge field
    let challenge_bytes: &[u8] = ccr.public_key.challenge.as_ref();
    let challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);

    Ok(Json(BrowserRegisterStartResponse {
        challenge,
        rp_id: state.config().rp_id.clone(),
        rp_name: state.config().rp_name.clone(),
        user_id: URL_SAFE_NO_PAD.encode(user_id.as_bytes()),
        user_email: user_email.clone(),
        user_display_name: user_email,
        algorithms: vec![-7, -257], // ES256, RS256
        state: state_token,
        exclude_credential_ids,
    }))
}

/// Maximum encoded length for `credential_id` (base64url).
/// WebAuthn spec allows up to 1023 bytes raw ≈ 1364 chars encoded.
const MAX_CREDENTIAL_ID_LEN: usize = 1400;

/// Maximum encoded length for `attestation_object` (base64url).
/// Hardware key attestations with certificate chains are typically under 4 KB.
const MAX_ATTESTATION_OBJECT_LEN: usize = 16 * 1024;

/// Maximum encoded length for `client_data_json` (base64url).
/// Client data JSON is a small JSON object (origin, type, challenge).
const MAX_CLIENT_DATA_JSON_LEN: usize = 4 * 1024;

/// Maximum encoded length for the registration `state` JWT.
const MAX_STATE_TOKEN_LEN: usize = 8 * 1024;

/// Minimum decoded byte length for a valid credential ID.
const MIN_CREDENTIAL_ID_BYTES: usize = 16;

/// Maximum decoded byte length for a valid credential ID (WebAuthn spec).
const MAX_CREDENTIAL_ID_BYTES: usize = 1023;

/// Complete browser-based `WebAuthn` registration.
/// POST /enroll/webauthn/complete
///
/// Validation is ordered to fail fast before any database access:
/// 1. Field length bounds (reject obviously oversized/empty fields)
/// 2. State JWT decode + expiration check
/// 3. Base64url decode all fields
/// 4. Credential ID byte length validation
/// 5. Client data JSON structure validation (type, origin)
/// 6. Hardware attestation validation (reject software passkeys)
/// 7. WebAuthn cryptographic verification
/// 8. Database operations (duplicate check, store, authorize)
#[expect(
    clippy::too_many_lines,
    reason = "axum handler; FIDO2 registration completion: attestation, db, session"
)]
pub(crate) async fn browser_register_complete(
    State(state): State<Arc<AppState>>,
    client_info: ClientInfo,
    Json(req): Json<BrowserRegisterCompleteRequest>,
) -> Result<impl IntoResponse, ServiceError> {
    // ── Phase 1: Field length bounds ────────────────────────────────────
    // Reject obviously oversized or empty fields before any processing.
    if req.state.len() > MAX_STATE_TOKEN_LEN {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "State token exceeds maximum length",
        ));
    }
    if req.credential_id.is_empty() || req.credential_id.len() > MAX_CREDENTIAL_ID_LEN {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_credential",
            "Credential ID is empty or exceeds maximum length",
        ));
    }
    if req.attestation_object.is_empty()
        || req.attestation_object.len() > MAX_ATTESTATION_OBJECT_LEN
    {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_attestation",
            "Attestation object is empty or exceeds maximum length",
        ));
    }
    if req.client_data_json.is_empty() || req.client_data_json.len() > MAX_CLIENT_DATA_JSON_LEN {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_client_data",
            "Client data JSON is empty or exceeds maximum length",
        ));
    }

    // ── Phase 2: State JWT decode + expiration ──────────────────────────
    let reg_state = BrowserRegistrationState::decode(&req.state, &state.state_signer)
        .await
        .map_err(|e| ServiceError::api(StatusCode::BAD_REQUEST, "invalid_state", e.to_string()))?;

    // ── Phase 2a: Account must be active ────────────────────────────────
    // A user deactivated after obtaining the registration state (valid for
    // five minutes) must not register a new hardware key.
    let account = db::get_user_by_id(&state.store, &reg_state.user_id.to_string())
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;
    if let Some(account) = account
        && !account.active
    {
        return Err(ServiceError::Forbidden("user_deactivated"));
    }

    // ── Phase 2b: Single-use enforcement ───────────────────────────────
    // Consume the state token before any WebAuthn work so that a captured
    // state JWT cannot be replayed within the 5-minute validity window.
    // The witness is threaded into TokenIssuanceProof below — the only
    // path to `GrantProof::EnrollmentComplete`.
    let registration_claim = match key_svc::consume_registration_state(
        &state.store,
        &req.state,
        reg_state.exp,
    )
    .await?
    {
        key_svc::RegistrationStateConsumed::Won(claim) => claim,
        key_svc::RegistrationStateConsumed::Replay => {
            tracing::warn!(
                user_id = %reg_state.user_id,
                "browser registration state replay rejected"
            );
            let audit_data = crate::db::documents::audit::RegistrationReplayData {
                flow: "browser_register",
                success: false,
                error_code: "state_already_used",
            };
            if let Err(e) = state
                .audit
                .insert_event(
                    db::AuditEventKind::KeyRegistrationReplay,
                    Some(&reg_state.user_id.to_string()),
                    Some(&reg_state.user_email),
                    &audit_data,
                )
                .await
            {
                tracing::warn!(error = %e, "failed to write key_registration_replay audit event");
            }
            return Err(ServiceError::api(
                StatusCode::BAD_REQUEST,
                "state_already_used",
                "This registration link has already been used",
            ));
        }
    };

    // ── Phase 3: Base64url decode all fields ────────────────────────────
    let credential_id_bytes = URL_SAFE_NO_PAD.decode(&req.credential_id).map_err(|e| {
        ServiceError::api(StatusCode::BAD_REQUEST, "invalid_credential", e.to_string())
    })?;

    let attestation_object = URL_SAFE_NO_PAD
        .decode(&req.attestation_object)
        .map_err(|e| {
            ServiceError::api(
                StatusCode::BAD_REQUEST,
                "invalid_attestation",
                e.to_string(),
            )
        })?;

    let client_data_json = URL_SAFE_NO_PAD.decode(&req.client_data_json).map_err(|e| {
        ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_client_data",
            e.to_string(),
        )
    })?;

    // ── Phase 4: Credential ID byte length validation ───────────────────
    if credential_id_bytes.len() < MIN_CREDENTIAL_ID_BYTES
        || credential_id_bytes.len() > MAX_CREDENTIAL_ID_BYTES
    {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_credential",
            "Credential ID length is outside the valid range (16-1023 bytes)",
        ));
    }

    // ── Phase 5: Client data JSON structure validation ──────────────────
    // Parse and validate the client data before any DB or crypto operations.
    let client_data_str = std::str::from_utf8(&client_data_json).map_err(|_| {
        ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_client_data",
            "Client data JSON is not valid UTF-8",
        )
    })?;

    let client_data: ClientData = serde_json::from_str(client_data_str).map_err(|e| {
        ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_client_data",
            format!("Client data JSON is malformed: {e}"),
        )
    })?;

    if client_data.typ != "webauthn.create" {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_client_data",
            "Client data type must be 'webauthn.create'",
        ));
    }

    // Verify the origin matches the server's base URL.
    let expected_origin = &state.config().base_url;
    if client_data.origin != *expected_origin {
        tracing::warn!(
            "Origin mismatch: got '{}', expected '{}'",
            client_data.origin,
            expected_origin
        );
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_client_data",
            "Client data origin does not match the server",
        ));
    }

    // ── Phase 6: Hardware attestation validation ────────────────────────
    // Reject software passkeys, platform authenticators, and disallowed AAGUIDs.
    let validated = validate_registration_attestation(
        &attestation_object,
        &state.config().allowed_aaguids,
        state.config().require_attestation_cert,
    )?;

    // ── Phase 6b: Extract x5c certs before attestation_object is moved ─
    let x5c_certs = crate::attestation::extract_x5c_from_attestation(&attestation_object);

    // ── Phase 7: WebAuthn cryptographic verification ────────────────────
    use webauthn_rs::prelude::Base64UrlSafeData;
    let reg_credential = webauthn_rs_proto::RegisterPublicKeyCredential {
        id: req.credential_id.clone(),
        raw_id: Base64UrlSafeData::from(credential_id_bytes.clone()),
        response: webauthn_rs_proto::AuthenticatorAttestationResponseRaw {
            attestation_object: Base64UrlSafeData::from(attestation_object),
            client_data_json: Base64UrlSafeData::from(client_data_json),
            transports: None,
        },
        extensions: webauthn_rs_proto::RegistrationExtensionsClientOutputs::default(),
        type_: "public-key".to_string(),
    };

    let passkey = state
        .webauthn
        .finish_passkey_registration(&reg_credential, &reg_state.webauthn_state)
        .map_err(|e| {
            tracing::warn!("WebAuthn verification failed: {}", e);
            ServiceError::api(
                StatusCode::BAD_REQUEST,
                "attestation_failed",
                format!("Attestation verification failed: {e}"),
            )
        })?;

    // ── Phase 8: Database operations ────────────────────────────────────
    // All cheap validation passed — now check for duplicate credentials.
    if let Some(_existing) =
        db::get_authenticator_by_credential_id(&state.store, &credential_id_bytes).await?
    {
        tracing::warn!(
            "Rejected duplicate credential registration for user: {}",
            reg_state.user_id
        );
        return Err(ServiceError::api(
            StatusCode::CONFLICT,
            "credential_already_registered",
            "This security key is already registered",
        ));
    }

    // Extract COSE public key and convert to raw CBOR bytes for storage
    // This ensures compatibility with our server-side WebAuthn verification
    let cose_key = passkey.get_public_key();

    let public_key_cbor = crate::crypto::cose::cose_key_to_cbor(cose_key).map_err(|e| {
        tracing::error!("Failed to serialize COSE key to CBOR: {e}");
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cbor_error",
            "Failed to serialize key",
        )
    })?;

    // Use the credential_id from the passkey (parsed by webauthn-rs from the attestation)
    // rather than the one from the request, to ensure consistency with what the YubiKey has stored.
    let cred_id_to_store = passkey.cred_id().to_vec();

    // ── Phase 8b: x5c attestation chain validation (browser enrollment) ──
    // The browser enrollment path uses webauthn-rs for verification, so we
    // additionally validate the x5c chain here for attestation_verified status.
    let mut validated = validated;
    if let Some(x5c_certs) = x5c_certs {
        match crate::crypto::attestation_chain::validate_attestation_chain(
            &x5c_certs,
            validated.aaguid.as_deref(),
        ) {
            Ok(_chain_result) => {
                validated.attestation_verified = true;
                tracing::info!(
                    attestation_verified = true,
                    "Browser enrollment: x5c chain validated"
                );
            }
            Err(e) => {
                if state.config().require_attestation_cert {
                    tracing::warn!(
                        "Browser enrollment: x5c chain validation \
                         failed (fatal, require_attestation_cert=true): {e}"
                    );
                    return Err(ServiceError::api(
                        StatusCode::BAD_REQUEST,
                        "attestation_chain_invalid",
                        "Attestation certificate chain could not be \
                         verified against trusted roots. Only genuine \
                         hardware authenticators with valid attestation \
                         chains are accepted.",
                    ));
                }
                tracing::warn!(
                    "Browser enrollment: x5c chain validation \
                     failed (non-fatal): {e}"
                );
            }
        }
    }

    // Store the authenticator with verified credential
    // user_handle is the user_id as bytes (for discoverable credentials)
    let user_handle = reg_state.user_id.as_bytes().to_vec();
    let authenticator_id = db::create_authenticator(
        &state.store,
        &db::CreateAuthenticatorParams {
            user_id: &reg_state.user_id.to_string(),
            user_email: &reg_state.user_email,
            name: &validated.device_name,
            credential_id: &cred_id_to_store,
            public_key: &public_key_cbor,
            aaguid: validated.aaguid.as_deref(),
            user_handle: Some(&user_handle),
            attestation_verified: validated.attestation_verified,
        },
    )
    .await?;

    // Mark device authorization as complete (only for CLI-initiated flows)
    if reg_state.device_auth_id.is_empty() {
        tracing::debug!(
            "browser_register_complete: no device_auth_id, skipping device auth authorization \
             (direct browser enrollment)"
        );
    } else {
        db::authorize_device_auth(
            &state.store,
            db::AuthorizeDeviceAuthParams {
                id: &reg_state.device_auth_id,
                user_id: &reg_state.user_id.to_string(),
                user_email: &reg_state.user_email,
                authenticator_id: &authenticator_id,
                // The WebAuthn registration ceremony just completed above.
                hardware_verified: true,
            },
        )
        .await
        .inspect_err(|e| {
            tracing::error!(
                "Failed to authorize device auth '{}': {}",
                reg_state.device_auth_id,
                e
            );
        })?;

        let event = db::AuthEventParams {
            user_id: reg_state.user_id.to_string(),
            event_type: db::AuthEventType::DeviceAuthApproved,
            authenticator_id: Some(authenticator_id.clone()),
            success: true,
            client: client_info.clone(),
            ..Default::default()
        };
        db::spawn_audit_event(&state.audit, event, Some(reg_state.user_email.clone()));
    }

    // Log enrollment event (fire-and-forget)
    let auth_event_params = AuthEventParams {
        user_id: reg_state.user_id.to_string(),
        event_type: AuthEventType::Enrollment,
        authenticator_id: Some(authenticator_id.clone()),
        success: true,
        client: client_info,
        ..AuthEventParams::default()
    };
    db::spawn_audit_event(
        &state.audit,
        auth_event_params,
        Some(reg_state.user_email.clone()),
    );

    crate::infra::metrics::record_auth_event("enrollment");

    tracing::info!(
        "Enrollment complete for: {} with {} (AAGUID: {})",
        redact_email(&reg_state.user_email),
        validated.device_name,
        validated.aaguid.as_deref().unwrap_or("unknown")
    );

    // Create a session for the browser so the user stays logged in
    let session_hours = i64::try_from(state.config().session_hours).map_err(|_| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "time_error",
            "Invalid session hours",
        )
    })?;

    // Issue an OAuth access token (RFC 9068) — the server acts as both issuer and audience
    let enroll_client_id = state.config().base_url.clone();
    let user_id_str = reg_state.user_id.to_string();

    // Snapshot org domain for federation claims tied to this session. Fail
    // closed: the snapshot is captured exactly once, so silently dropping a
    // transient DB error would permanently degrade this session's `hd` claim.
    let snapshot_error = |err: anyhow::Error| {
        tracing::error!("Failed to snapshot org domain: {}", err);
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Failed to create session",
        )
    };
    let org_domain = match db::get_user_by_id(&state.store, &user_id_str)
        .await
        .map_err(snapshot_error)?
    {
        Some(u) => match u.org_id {
            Some(org_id) => db::get_organization_domain(&state.store, &org_id)
                .await
                .map_err(snapshot_error)?,
            None => None,
        },
        None => None,
    };

    // Capture the FIDO2 authentication timestamp — the user just completed
    // WebAuthn registration, which is an authentication event (amr/acr below
    // claim hardware verification). This must be `Some(now)` for consistency
    // with every other `HardwareVerification::Verified` flow and so the
    // `require_fresh_timestamp` freshness gate on key deletion does not treat
    // the freshly-minted session as Unix epoch (`unwrap_or(0)`).
    let auth_now = Timestamp::now();

    let session_result = create_oauth_access_token(
        &state,
        CreateOAuthTokenParams {
            user_id: &user_id_str,
            email: &reg_state.user_email,
            authenticator_id: Some(&authenticator_id),
            client_id: &enroll_client_id,
            scope: Some(ScopeSet::all()),
            dpop_jkt: None,
            mtls_cert_thumbprint: None,
            act: None,
            audience: None,
            auth_time: Some(auth_now.as_second()),
            hardware_verification: crate::services::auth::HardwareVerification::Verified,
            session_purpose: db::SessionPurpose::OAuthAccessToken,
            authorization_details: None,
            hardware_aaguid: validated.aaguid.as_deref(),
            org_domain: org_domain.as_deref(),
        },
        TokenIssuanceProof {
            grant: GrantProof::EnrollmentComplete(registration_claim),
            client_auth: ClientAuthProof::NoAuth(
                crate::services::auth::NoClientAuth::internal_endpoint(),
            ),
            sender_constraint: SenderConstraintProof::no_registered_client(),
        },
    )
    .await
    .map_err(|e| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "session_error",
            e.to_string(),
        )
    })?;
    let token = session_result.token;

    // Return success template with session cookie
    let cookie = create_session_cookie(token.expose_secret(), session_hours.saturating_mul(3600));
    let html = SuccessTemplate.render().map_err(|e| {
        tracing::error!("Template render error: {}", e);
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "render_error",
            "Failed to render template",
        )
    })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::SET_COOKIE, cookie.to_string())
        .body(Body::from(html))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()))
}

// ============================================================================
// Direct Enrollment (Browser-only, no CLI)
// ============================================================================

/// Query parameters for direct enrollment start.
#[derive(Deserialize)]
pub(crate) struct DirectEnrollQuery {
    /// Optional OIDC provider slug (e.g. "google"). If absent, uses first provider.
    pub provider: Option<String>,
}

/// Start direct browser enrollment (no CLI required).
/// GET /enroll/start[?provider=<slug>]
///
/// This initiates OIDC authentication directly from the browser,
/// without requiring the CLI to create a device authorization request.
/// After successful enrollment, the user can download the CLI and login.
pub(crate) async fn direct_enroll_start(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DirectEnrollQuery>,
) -> Response {
    // Render the IdP chooser before creating any state rows when multiple
    // IdPs are configured and the caller has not yet picked one. Doing this
    // first avoids orphaning `device_auth_requests` rows for clicks that
    // never proceed past the chooser.
    let provider_choice = query
        .provider
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if provider_choice.is_none() && state.idps.len() > 1 {
        return SelectIdpTemplate {
            action: "/enroll/start".to_string(),
            is_post: false,
            user_code: None,
            idp_entries: super::home::build_idp_entries(&state.idps),
        }
        .into_response();
    }

    let now = Timestamp::now();

    // Initiate upstream IdP authentication.
    // If a provider slug was specified, require it to exist — do not fall
    // through. When unspecified, the chooser above has already returned for
    // the multi-IdP case, so `state.idps.first()` here is the single
    // configured IdP (config validation ensures at least one IdP is present).
    let base_url = state.config().base_url.clone();
    let chosen_idp: Option<&crate::services::idp::ConfiguredIdp> = match provider_choice {
        Some(slug) => match state.idp(slug) {
            Some(i) => Some(i),
            None => {
                return ErrorTemplate {
                    title: Tr::new("enroll-error-unknown-provider-title").to_string(),
                    message: Tr::new("enroll-error-unknown-provider")
                        .arg("slug", slug)
                        .to_string(),
                    back_url: Some("/".to_string()),
                }
                .into_response();
            }
        },
        None => state.idps.first(),
    };

    let Some(idp) = chosen_idp else {
        return ErrorTemplate {
            title: Tr::new("enroll-error-not-configured-title").to_string(),
            message: Tr::new("enroll-error-idp-not-configured").to_string(),
            back_url: Some("/".to_string()),
        }
        .into_response();
    };

    let provider_id = idp.id().to_string();
    let auth_request = match idp.initiate_auth(&base_url) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                "Failed to initiate {} auth for IdP '{}' (direct enrollment): {e:#}",
                idp.kind().as_str(),
                provider_id
            );
            return ErrorTemplate {
                title: Tr::new("error-heading").to_string(),
                message: Tr::new("enroll-error-enrollment-start-failed").to_string(),
                back_url: Some("/".to_string()),
            }
            .into_response();
        }
    };
    let (auth_request, provider_id) = (auth_request, provider_id);

    let state_expires = now.checked_add(Span::new().minutes(10)).unwrap_or(now);

    // Direct browser sign-in: no CLI device authorization involved, so the
    // state row carries no device_auth_id — the marker
    // complete_enrollment_after_identity uses to skip the CLI flow.
    if let Err(e) = db::create_oidc_state(
        &state.store,
        &auth_request.state_key,
        None,
        &auth_request.nonce,
        &auth_request.code_verifier,
        state_expires,
        &provider_id,
    )
    .await
    {
        tracing::error!("Failed to create auth state: {}", e);
        return ErrorTemplate {
            title: Tr::new("error-heading").to_string(),
            message: Tr::new("enroll-error-enrollment-start-failed").to_string(),
            back_url: Some("/".to_string()),
        }
        .into_response();
    }

    match auth_request.action {
        crate::services::idp::AuthAction::Redirect { url } => Redirect::to(&url).into_response(),
        crate::services::idp::AuthAction::PostForm {
            action_url,
            saml_request,
            relay_state,
        } => SamlPostFormTemplate {
            action_url,
            saml_request,
            relay_state,
        }
        .into_response(),
    }
}

/// Characters used for user code generation (consonants only, no ambiguous chars).
/// Must match the alphabet in `device.rs`.
const USER_CODE_CHARS: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

/// Normalize a user- or URL-supplied device code to canonical `XXXX-XXXX`
/// form: uppercase, trimmed, with a dash inserted for bare 8-char input.
///
/// Shared by the `GET /device` pre-fill path and the `POST /device` submit
/// path so both accept identical inputs.
fn normalize_user_code(raw: &str) -> String {
    let upper = raw.to_uppercase();
    let trimmed = upper.trim();
    if trimmed.chars().count() == 8 && !trimmed.contains('-') {
        format!(
            "{}-{}",
            trimmed.chars().take(4).collect::<String>(),
            trimmed.chars().skip(4).collect::<String>(),
        )
    } else {
        trimmed.to_string()
    }
}

/// Validate that a user code matches the expected `XXXX-XXXX` format
/// where each character is from the device code alphabet.
///
/// This rejects obviously invalid codes before hitting the database.
fn is_valid_user_code_format(code: &str) -> bool {
    let bytes = code.as_bytes();
    // Must be exactly 9 characters: 4 letters, dash, 4 letters
    if bytes.len() != 9 {
        return false;
    }
    if bytes.get(4).copied() != Some(b'-') {
        return false;
    }
    bytes
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 4)
        .all(|(_, &b)| USER_CODE_CHARS.contains(&b))
}

#[cfg(test)]
mod tests;
