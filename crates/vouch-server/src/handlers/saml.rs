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
    extract::State,
    http::header,
    response::{IntoResponse, Response},
};
use jiff::Timestamp;
use serde::Deserialize;

use crate::AppState;
use crate::db;
use crate::handlers::enroll::{ErrorTemplate, complete_enrollment_after_identity};
use crate::services::idp::IdentityResult;

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

    complete_enrollment_after_identity(&state, &stored_state, &relay_state, identity).await
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
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
