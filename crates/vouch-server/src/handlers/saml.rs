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
use serde::Deserialize;

use crate::AppState;
use crate::db::{self, ClientInfo};
use crate::handlers::enroll::{ErrorTemplate, complete_enrollment_after_identity};
use crate::services::idp::IdentityResult;

// ============================================================================
// Request types
// ============================================================================

/// Form parameters posted by the IdP to the Assertion Consumer Service.
#[derive(Deserialize)]
pub(crate) struct SamlAcsForm {
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
///
/// Returns the SP entity ID from the first configured SAML IdP. If multiple
/// SAML IdPs are configured with different SP entity IDs, this returns the
/// first one's; operators can fetch per-IdP metadata via `?idp=<slug>` if
/// that becomes a real need.
pub(crate) async fn metadata(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let config = state.config();
    let sp_entity_id = state
        .idps
        .iter()
        .find_map(|i| match i {
            crate::services::idp::ConfiguredIdp::Saml(p) => Some(p.sp_entity_id.clone()),
            crate::services::idp::ConfiguredIdp::Oidc(_) => None,
        })
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
pub(crate) async fn acs(
    State(state): State<Arc<AppState>>,
    client_info: ClientInfo,
    Form(form): Form<SamlAcsForm>,
) -> Response {
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

    // Step 3: Atomically consume the SAML state record (stored in the
    // shared oidc_state table). The returned witness is threaded into the
    // downstream TokenIssuanceProof and is the only path to
    // `GrantProof::EnrollmentBootstrap`. Replaces the prior
    // get-then-delete pattern, closing the read-vs-consume TOCTOU.
    let (stored_state, oidc_state_claim) =
        match db::try_consume_oidc_state(&state.store, &relay_state).await {
            Ok(pair) => pair,
            Err(db::ClaimError::AlreadyConsumed) => {
                return ErrorTemplate {
                    title: "Error".to_string(),
                    message: "Invalid or expired state".to_string(),
                    back_url: None,
                }
                .into_response();
            }
            Err(e) => {
                tracing::error!("Failed to consume SAML state: {e:#}");
                return ErrorTemplate {
                    title: "Error".to_string(),
                    message: "Failed to verify state".to_string(),
                    back_url: None,
                }
                .into_response();
            }
        };

    // Step 5: Look up the SAML IdP by the slug stored in the state row.
    // Fall back to the first configured SAML IdP for state docs written before
    // multi-IdP support (rolling deploy compatibility).
    let saml_provider = if stored_state.provider_id.is_empty() {
        state.idps.iter().find_map(|i| match i {
            crate::services::idp::ConfiguredIdp::Saml(p) => Some(p),
            crate::services::idp::ConfiguredIdp::Oidc(_) => None,
        })
    } else {
        state.idp(&stored_state.provider_id).and_then(|i| match i {
            crate::services::idp::ConfiguredIdp::Saml(p) => Some(p),
            crate::services::idp::ConfiguredIdp::Oidc(_) => None,
        })
    };
    let Some(saml_provider) = saml_provider else {
        return ErrorTemplate {
            title: "Error".to_string(),
            message: "SAML IdP not configured for this state. If using OIDC, \
                      responses go to /oauth/callback."
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
    let upstream = saml_upstream_login(
        &saml_provider.idp_metadata.entity_id,
        assertion.name_id.as_deref(),
        assertion.name_id_format.as_deref(),
    );
    if assertion.name_id.is_some() && upstream.durable_subject.is_none() {
        tracing::debug!(
            idp = %saml_provider.id,
            name_id_format = assertion.name_id_format.as_deref().unwrap_or("(missing)"),
            "SAML NameID format is not persistent; this login cannot create or \
             satisfy an identity binding (account matching falls back to email \
             only, and is refused if the account is already bound for this IdP)"
        );
    }
    let identity = IdentityResult {
        email: assertion.email,
        domain: assertion.domain,
        upstream: Some(upstream),
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

/// SAML 2.0 NameID format the OASIS Core spec (§8.3.7) defines specifically
/// for durable cross-session account linking: the IdP guarantees the same
/// value for the same principal and must not reassign it to another one.
const NAMEID_PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

/// Build the upstream login for a SAML sign-in.
///
/// `issuer` (the IdP entity ID) is always known once a configured SAML
/// provider has handled the response. `durable_subject` is set only for
/// a `persistent`-format NameID — the one format the SAML spec designates
/// for durable cross-session account linking. Every other format is not a
/// durable per-principal identifier: an IdP may mint a new NameID on
/// every login without declaring `transient` (many default to
/// `unspecified`), and `emailAddress` carries the same reassignment risk
/// that motivates keying binding on something other than the email
/// address in the first place. A missing `Format` attribute defaults to
/// `unspecified` per the SAML core spec and is treated the same way.
///
/// A login with no durable subject still carries the issuer, so
/// `enroll_user_with_org` can refuse it outright if the matched account
/// is already bound for this issuer, rather than silently downgrading to
/// an email-only check — see its "Identity matching" docs.
fn saml_upstream_login(
    entity_id: &str,
    name_id: Option<&str>,
    name_id_format: Option<&str>,
) -> crate::db::UpstreamLogin {
    let durable_subject = match (name_id, name_id_format) {
        (Some(id), Some(NAMEID_PERSISTENT)) => Some(id.to_string()),
        _ => None,
    };
    crate::db::UpstreamLogin {
        issuer: entity_id.to_string(),
        durable_subject,
    }
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

    // ========================================================================
    // saml_upstream_login: NameID format eligibility for identity binding
    // ========================================================================

    #[test]
    fn saml_upstream_login_binds_on_persistent_format() {
        let upstream = super::saml_upstream_login(
            "https://idp.example.com/entity",
            Some("stable-subject-1"),
            Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
        );
        assert_eq!(upstream.issuer, "https://idp.example.com/entity");
        assert_eq!(
            upstream.durable_subject.as_deref(),
            Some("stable-subject-1")
        );
    }

    // emailAddress-format NameIDs carry the exact reassignment risk that
    // identity binding exists to close (see PR discussion on issuer/subject
    // vs. email as the durable link) — must not produce a durable subject.
    // The issuer is still carried, so an account already bound for this
    // issuer is not silently bypassed (see enrollment.rs resolve_user).
    #[test]
    fn saml_upstream_login_skips_email_format() {
        let upstream = super::saml_upstream_login(
            "https://idp.example.com/entity",
            Some("alice@example.com"),
            Some("urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"),
        );
        assert_eq!(upstream.issuer, "https://idp.example.com/entity");
        assert!(upstream.durable_subject.is_none());
    }

    // A rotating NameID sent under `unspecified` (or any format other than
    // `persistent`) must not produce a durable subject either — otherwise
    // the first login lazily binds a value that never recurs, and every
    // later login is refused as an identity conflict (the #837 lockout
    // this guards against).
    #[test]
    fn saml_upstream_login_skips_unspecified_format() {
        let upstream = super::saml_upstream_login(
            "https://idp.example.com/entity",
            Some("rotates-every-login"),
            Some("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"),
        );
        assert!(upstream.durable_subject.is_none());
    }

    #[test]
    fn saml_upstream_login_skips_transient_format() {
        let upstream = super::saml_upstream_login(
            "https://idp.example.com/entity",
            Some("one-time-value"),
            Some("urn:oasis:names:tc:SAML:2.0:nameid-format:transient"),
        );
        assert!(upstream.durable_subject.is_none());
    }

    // A missing `Format` attribute defaults to `unspecified` per the SAML
    // core spec — no stability guarantee, so no durable subject.
    #[test]
    fn saml_upstream_login_skips_missing_format() {
        let upstream = super::saml_upstream_login(
            "https://idp.example.com/entity",
            Some("some-subject"),
            None,
        );
        assert!(upstream.durable_subject.is_none());
    }

    #[test]
    fn saml_upstream_login_skips_missing_name_id() {
        let upstream = super::saml_upstream_login(
            "https://idp.example.com/entity",
            None,
            Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
        );
        assert!(upstream.durable_subject.is_none());
        assert_eq!(upstream.issuer, "https://idp.example.com/entity");
    }
}
