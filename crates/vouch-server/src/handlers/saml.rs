// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SAML 2.0 HTTP handlers.
//!
//! Two endpoints:
//! - `GET /saml/metadata` — Returns SP metadata XML for IdP configuration.
//! - `POST /saml/acs` — Assertion Consumer Service: validates SAML responses and
//!   completes the enrollment flow.

use std::sync::Arc;

use axum::{
    Form,
    body::Body,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use jiff::Timestamp;
use secrecy::ExposeSecret;
use serde::Deserialize;

use crate::AppState;
use crate::db;
use crate::handlers::enroll::ErrorTemplate;
use crate::handlers::{create_session_cookie, hash_token};
use crate::redact_email;
use crate::services::auth::{CreateOAuthTokenParams, create_oauth_access_token};
use crate::services::idp::IdentityResult;
use crate::services::oidc::scope::ScopeSet;

// ============================================================================
// Request types
// ============================================================================

/// Form parameters posted by the IdP to the Assertion Consumer Service.
#[derive(Deserialize)]
pub struct SamlAcsForm {
    /// Base64-encoded SAML Response XML.
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    /// Opaque state token passed through the IdP (matches `state` in oidc_state table).
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

// ============================================================================
// Handlers
// ============================================================================

/// Return SP metadata XML.
/// GET /saml/metadata
#[allow(clippy::unused_async)]
pub async fn metadata(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let config = state.config();
    let sp_entity_id = config
        .saml_sp_entity_id
        .clone()
        .unwrap_or_else(|| config.base_url.clone());
    let acs_url = format!("{}/saml/acs", config.base_url);
    let xml = crate::services::idp::saml::metadata::generate_sp_metadata(&sp_entity_id, &acs_url);
    (
        [(header::CONTENT_TYPE, "application/samlmetadata+xml")],
        xml,
    )
}

/// SAML Assertion Consumer Service.
/// POST /saml/acs
///
/// Receives the IdP's SAML Response, validates it, and completes the
/// enrollment flow identically to `oidc_callback()`.
#[allow(clippy::too_many_lines)]
pub async fn acs(State(state): State<Arc<AppState>>, Form(form): Form<SamlAcsForm>) -> Response {
    // Step 1: RelayState is required — it's our CSRF/state token.
    let relay_state = match form.relay_state {
        Some(rs) if !rs.is_empty() => rs,
        _ => {
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Missing RelayState parameter".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    // Step 2: Validate RelayState length before DB lookup.
    if relay_state.len() > 128 {
        return ErrorTemplate {
            title: "Error".to_string(),
            message: "Invalid RelayState parameter".to_string(),
            back_url: None,
        }
        .into_response();
    }

    // Step 3: Look up stored SAML state by RelayState (= state column in oidc_state table).
    let stored_state = match db::get_oidc_state(&state.store, &relay_state).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Invalid or expired state".to_string(),
                back_url: None,
            }
            .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to look up SAML state: {e:#}");
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to verify state".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    // Step 4: Check if state has expired.
    let now = Timestamp::now();
    if now > stored_state.expires_at {
        return ErrorTemplate {
            title: "Error".to_string(),
            message: "State has expired. Please start the enrollment process again.".to_string(),
            back_url: None,
        }
        .into_response();
    }

    // Step 5: Require SAML IdP to be configured.
    let Some(crate::services::idp::UpstreamIdp::Saml(saml_provider)) = state.upstream_idp.as_ref()
    else {
        return ErrorTemplate {
            title: "Error".to_string(),
            message: "SAML is not configured. If using OIDC, responses go to /oauth/callback."
                .to_string(),
            back_url: None,
        }
        .into_response();
    };

    // Step 6: Validate the SAML response. The stored nonce is the AuthnRequest ID.
    let assertion = match crate::services::idp::saml::response::validate_saml_response(
        &form.saml_response,
        &stored_state.nonce,
        saml_provider,
    ) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!("SAML response validation failed: {e:#}");
            return ErrorTemplate {
                title: "Authentication Failed".to_string(),
                message: "Failed to verify SAML response. Please try again.".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    // Step 7: Convert SamlAssertion to the protocol-agnostic IdentityResult.
    let identity = IdentityResult {
        email: assertion.email,
        domain: assertion.domain,
    };

    // Step 8: Delete consumed state record (replay prevention).
    if let Err(e) = db::delete_oidc_state(&state.store, &relay_state).await {
        tracing::warn!("Failed to delete SAML state: {e}");
    }

    // ── From here, identical to oidc_callback() ────────────────────────────

    // Check domain restriction.
    if let Some(domains) = state
        .config()
        .allowed_domains
        .as_ref()
        .filter(|d| !d.is_empty())
    {
        let email_domain =
            crate::services::idp::extract_email_domain(identity.domain.as_deref(), &identity.email)
                .unwrap_or("");
        if !domains.iter().any(|d| d.eq_ignore_ascii_case(email_domain)) {
            let allowed_list = domains.join(", ");
            return ErrorTemplate {
                title: "Domain Not Allowed".to_string(),
                message: format!(
                    "Only users from the following domains can enroll: {}. \
                     Your email ({}) is not from an allowed domain.",
                    allowed_list, identity.email
                ),
                back_url: None,
            }
            .into_response();
        }
    }

    // Enroll user with organization.
    let enrollment = match db::enroll_user_with_org(
        &state.store,
        &identity.email,
        None,
        identity.domain.as_deref(),
    )
    .await
    {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("Failed to enroll user: {e}");
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to create user".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    let user = enrollment.user;

    let session_hours = i64::try_from(state.config().session_hours).unwrap_or(8);
    let duration = jiff::Span::new().hours(session_hours);
    let expires = match now.checked_add(duration) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("Failed to calculate session expiration: {e}");
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to create session".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };

    let existing_auths = db::get_authenticators_for_user(&state.store, &user.id)
        .await
        .unwrap_or_default();
    let authenticator_id = existing_auths.first().map(|a| a.id.clone());

    let client_id_for_token = state.config().base_url.clone();
    let session_result = match create_oauth_access_token(
        &state,
        CreateOAuthTokenParams {
            user_id: &user.id,
            email: &user.email,
            authenticator_id: authenticator_id.as_deref(),
            client_id: &client_id_for_token,
            scope: Some(ScopeSet::all()),
            dpop_jkt: None,
            act: None,
            audience: None,
            auth_time: Some(now.as_second()),
            amr: None,
            acr: None,
            hardware_verified: false,
            session_purpose: db::SessionPurpose::OAuthAccessToken,
            authorization_details: None,
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to create session: {e}");
            return ErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to create session".to_string(),
                back_url: None,
            }
            .into_response();
        }
    };
    let token = session_result.token;
    let token_hash = hash_token(token.expose_secret());

    // Handle CLI-initiated device auth flow (device_auth_id comes from stored state).
    let is_cli_flow = !stored_state.device_auth_id.is_empty()
        && !stored_state.device_auth_id.starts_with("DIRECT-");

    if is_cli_flow {
        if let Some(ref auth_id) = authenticator_id {
            if let Err(e) = db::authorize_device_auth(
                &state.store,
                &stored_state.device_auth_id,
                &user.id,
                &identity.email,
                auth_id,
            )
            .await
            {
                tracing::warn!("Failed to authorize device auth: {e}");
            }
        } else {
            if let Err(e) = db::create_enrollment_session(
                &state.store,
                &user.id,
                &identity.email,
                &token_hash,
                Some(&stored_state.device_auth_id),
                expires,
            )
            .await
            {
                tracing::warn!("Failed to create enrollment session for CLI: {e}");
            }
        }
    }

    tracing::info!(
        "SAML session created for user: {}",
        redact_email(&identity.email)
    );
    tracing::debug!("Setting session cookie and redirecting to /enroll/keys");

    let cookie = create_session_cookie(token.expose_secret(), session_hours * 3600);
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/enroll/keys")
        .header(header::SET_COOKIE, cookie.to_string())
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use crate::test_utils::{http_get_full, http_post_form, test_app};
    use axum::http::StatusCode;

    #[tokio::test]
    async fn metadata_endpoint_returns_xml_content_type() {
        let (app, _state) = test_app().await;
        let resp = http_get_full(&app, "/saml/metadata", &[]).await;
        assert_eq!(resp.status, StatusCode::OK);
        let content_type = resp
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            content_type.contains("samlmetadata+xml") || content_type.contains("xml"),
            "Expected XML content type, got: {content_type}"
        );
    }

    #[tokio::test]
    async fn metadata_endpoint_returns_entity_descriptor() {
        let (app, _state) = test_app().await;
        let resp = http_get_full(&app, "/saml/metadata", &[]).await;
        assert_eq!(resp.status, StatusCode::OK);
        assert!(
            resp.body.contains("EntityDescriptor"),
            "Expected EntityDescriptor in metadata: {}",
            resp.body
        );
        assert!(
            resp.body.contains("AssertionConsumerService"),
            "Expected AssertionConsumerService in metadata: {}",
            resp.body
        );
    }

    #[tokio::test]
    async fn acs_missing_relay_state_returns_error() {
        let (app, _state) = test_app().await;
        // Post SAMLResponse without RelayState — serde fills with None for Option
        let form_body = "SAMLResponse=dGVzdA%3D%3D"; // base64("test")
        let (status, _body) = http_post_form(&app, "/saml/acs", form_body, &[]).await;
        // Should return an error page (200 HTML) — handler renders error, not 4xx
        assert!(
            status == StatusCode::OK || status.is_client_error(),
            "Expected error response for missing RelayState, got: {status}"
        );
    }

    #[tokio::test]
    async fn acs_invalid_state_returns_error_page() {
        let (app, _state) = test_app().await;
        // Post with a RelayState that doesn't match any DB record
        let form_body = "SAMLResponse=dGVzdA%3D%3D&RelayState=nonexistent_state_token";
        let (status, body) = http_post_form(&app, "/saml/acs", form_body, &[]).await;
        // Should render an error page
        assert_eq!(
            status,
            StatusCode::OK,
            "Error page should return 200 OK: {body}"
        );
        assert!(
            body.contains("Invalid") || body.contains("Error") || body.contains("expired"),
            "Expected error content in response: {body}"
        );
    }
}
