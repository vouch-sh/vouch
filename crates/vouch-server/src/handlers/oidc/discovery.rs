// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OIDC Discovery and JWKS endpoint handlers.
//!
//! Implements:
//! - OIDC Discovery 1.0 Section 4 - Obtaining OpenID Provider Configuration Information
//! - RFC 7517 Section 5 - JWK Set Format

use crate::AppState;
use crate::db;
use crate::infra::org_host;
use crate::services::oidc::discovery as svc;
use axum::Json;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

/// Cache-Control header for OIDC metadata endpoints.
///
/// These documents change infrequently (key rotation, issuer config), so a 1-hour
/// public cache reduces load on relying parties performing discovery.
const OIDC_CACHE_CONTROL: (axum::http::header::HeaderName, &str) =
    (axum::http::header::CACHE_CONTROL, "public, max-age=3600");

/// Discovery and JWKS bodies differ per issuer host (per-org keys), so any
/// shared cache in front of the server must key on the Host header — a
/// Host-normalizing cache would otherwise serve one org's keys at another
/// org's issuer.
const OIDC_VARY_HOST: (axum::http::header::HeaderName, &str) = (axum::http::header::VARY, "Host");

/// GET /.well-known/openid-configuration
///
/// OIDC Discovery 1.0 Section 4: The OpenID Provider Metadata is published at a
/// well-known URL derived from the Issuer Identifier.
///
/// On an org issuer-subdomain host (`{label}.{primary_host}`) this serves the
/// minimal federation discovery document for the claiming org's issuer — and
/// 404s for unclaimed labels, so a relying party's OIDC provider cannot be
/// created for a label no org owns. Primary-host requests are byte-identical
/// to before.
pub(crate) async fn discovery(
    State(state): State<Arc<AppState>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    if let Some(label) = org_host::org_label_from_request(&headers, &uri, &state.config()) {
        return org_discovery(&state, &label).await;
    }
    (
        [OIDC_CACHE_CONTROL, OIDC_VARY_HOST],
        Json(svc::build_discovery_document(&state)),
    )
        .into_response()
}

/// Serve the minimal federation discovery document for a claimed org subdomain.
///
/// Unclaimed labels 404 without a cache header, so a fresh claim becomes
/// visible immediately rather than after the 1-hour metadata cache expires.
async fn org_discovery(state: &Arc<AppState>, label: &str) -> Response {
    match db::find_org_by_subdomain(&state.store, label).await {
        Ok(Some(_org)) => {
            let Some(issuer) = state.config().org_issuer(label) else {
                tracing::error!("could not build org issuer for label '{label}' from base_url");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            };
            (
                [OIDC_CACHE_CONTROL, OIDC_VARY_HOST],
                Json(svc::build_wif_discovery_document(state, &issuer)),
            )
                .into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!("org subdomain lookup failed for '{label}': {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// GET /oauth/jwks
///
/// RFC 7517 Section 5: Returns the JWK Set containing the public keys used to
/// verify token signatures.
///
/// On an org issuer-subdomain host this serves **that org's** keys (which sign
/// its OIDC federation tokens), so the issuer host is a real cryptographic
/// boundary — a token for one org does not verify against another org's JWKS.
/// Unclaimed labels 404 (like discovery). Primary-host requests are unchanged.
pub(crate) async fn jwks(
    State(state): State<Arc<AppState>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    if let Some(label) = org_host::org_label_from_request(&headers, &uri, &state.config()) {
        return org_jwks(&state, &label).await;
    }
    match svc::build_jwks(&state) {
        Ok(jwks) => ([OIDC_CACHE_CONTROL, OIDC_VARY_HOST], Json(jwks)).into_response(),
        Err(e) => {
            tracing::error!("JWKS generation failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Serve the JWK Set for a claimed org issuer-subdomain host.
async fn org_jwks(state: &Arc<AppState>, label: &str) -> Response {
    match db::find_org_by_subdomain(&state.store, label).await {
        Ok(Some(org)) => match crate::services::oidc::org_jwks(state, &org).await {
            Ok(jwks) => ([OIDC_CACHE_CONTROL, OIDC_VARY_HOST], Json(jwks)).into_response(),
            Err(e) => {
                tracing::error!("org JWKS generation failed for '{label}': {e}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!("org subdomain lookup failed for '{label}': {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
