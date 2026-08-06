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

/// SAML NameID formats stable enough to bind as a durable identity.
///
/// Only these are bound as the account's `(issuer, subject)` identity.
/// Any other format — `transient` (rotates by design), `unspecified`,
/// an unknown URN, or an absent `Format` attribute — may change between
/// logins; binding one would lazily bind the first value and then refuse
/// the next login for the same email as an identity conflict, locking
/// the user out. Those cases fall back to email-only matching (logged).
const STABLE_NAMEID_FORMATS: &[&str] = &[
    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
];

/// Build the durable upstream identity from a validated SAML assertion.
///
/// Returns `Some` only for a NameID whose `Format` is in
/// [`STABLE_NAMEID_FORMATS`]; every other case (including an absent
/// format or a missing NameID) returns `None`, leaving account matching
/// to fall back to email alone.
fn saml_upstream_identity(
    entity_id: &str,
    name_id: Option<&str>,
    name_id_format: Option<&str>,
) -> Option<db::IdpIdentity> {
    let name_id = name_id?;
    match name_id_format {
        Some(format) if STABLE_NAMEID_FORMATS.contains(&format) => Some(db::IdpIdentity {
            issuer: entity_id.to_string(),
            subject: name_id.to_string(),
        }),
        _ => None,
    }
}

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
    // The upstream identity is (IdP entity ID, NameID), bound only for
    // NameID formats that are stable across logins (see
    // `saml_upstream_identity`). Anything else falls back to email-only
    // matching so a rotating NameID cannot lock the user out.
    let upstream = saml_upstream_identity(
        &saml_provider.idp_metadata.entity_id,
        assertion.name_id.as_deref(),
        assertion.name_id_format.as_deref(),
    );
    if upstream.is_none() && assertion.name_id.is_some() {
        tracing::warn!(
            idp = %saml_provider.id,
            name_id_format = ?assertion.name_id_format,
            "SAML NameID format is not stable (need persistent or emailAddress); \
             skipping identity binding (account matching falls back to email only)"
        );
    }
    let identity = IdentityResult {
        email: assertion.email,
        domain: assertion.domain,
        upstream,
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::saml_upstream_identity;
    use crate::test_utils::{http_get_full, http_post_form, test_app};
    use axum::http::StatusCode;

    const ENTITY: &str = "https://idp.example.com/saml";

    #[test]
    fn saml_binds_persistent_and_email_formats() {
        let persistent = saml_upstream_identity(
            ENTITY,
            Some("stable-1"),
            Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
        )
        .expect("persistent NameID must bind");
        assert_eq!(persistent.issuer, ENTITY);
        assert_eq!(persistent.subject, "stable-1");

        let email = saml_upstream_identity(
            ENTITY,
            Some("user@example.com"),
            Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
        )
        .expect("emailAddress NameID must bind");
        assert_eq!(email.subject, "user@example.com");
    }

    #[test]
    fn saml_skips_unstable_or_unknown_formats() {
        // Transient, unspecified, an unknown URN, and an absent Format all
        // may rotate per login, so none may be bound — binding them would
        // lock the user out on their second sign-in.
        for format in [
            Some("urn:oasis:names:tc:SAML:2.0:nameid-format:transient"),
            Some("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"),
            Some("urn:example:custom-format"),
            None,
        ] {
            assert!(
                saml_upstream_identity(ENTITY, Some("rotating-value"), format).is_none(),
                "format {format:?} must not be bound"
            );
        }
    }

    #[test]
    fn saml_skips_when_name_id_absent() {
        assert!(
            saml_upstream_identity(
                ENTITY,
                None,
                Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
            )
            .is_none(),
            "a missing NameID cannot be bound"
        );
    }

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
