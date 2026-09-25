// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authorization error responses, rendered in the client's `response_mode`.
//!
//! Every error exit from `/oauth/authorize` that reaches a validated
//! `redirect_uri` goes through [`oauth_error_response`]. That is the point of
//! this module: [`build_authorization_redirect`] is private to it, so a new
//! exit cannot render a bare 302 and ignore the mode the client asked for.
//! Two exits previously did, and a `form_post` client that receives query
//! parameters on its redirect_uri has no way to read them.
//!
//! The JWT modes are stricter still. JARM §2.1 requires a JWT "even in case
//! of an error response", and clients "MUST NOT" accept `alg: none`, so
//! there is no unsigned form to fall back to — a signing failure has to
//! surface as a server error rather than as plain parameters the client is
//! obliged to discard.

use super::*;

/// Build an authorization redirect URL with the given query parameters.
fn build_authorization_redirect(redirect_uri: &str, params: &[(&str, &str)]) -> Response {
    match build_redirect_url_with_params(redirect_uri, params) {
        Ok(url) => Redirect::to(&url).into_response(),
        Err(_) => Redirect::to(redirect_uri).into_response(),
    }
}

/// Create an OAuth error response, dispatching on `response_mode`.
///
/// - `Jwt`: wraps error in a JARM signed JWT (needs `client` for signing).
/// - `FormPost`: delivers error via HTML auto-submitting form.
/// - `Query`: delivers via query-string redirect (RFC 6749).
///
/// Includes the `iss` parameter per RFC 9207 in all modes.
///
/// The `FormPost` and `Query` arms never read `client` — the response is built
/// from `redirect_uri` + issuer config — so they are routed through
/// [`oauth_error_response_unsigned`], which a caller without a client record
/// (certification `deny_login` after the client was hard-deleted mid-flow) can
/// reach directly. Sharing the unsigned dispatcher keeps the two entry points
/// from drifting on the unsigned response shape.
pub(crate) async fn oauth_error_response(
    app_state: &Arc<AppState>,
    client: &OAuthClient,
    redirect_uri: &str,
    error: OAuthErrorCode,
    description: &str,
    oauth_state: Option<&str>,
    response_mode: ResponseMode,
) -> Response {
    match response_mode {
        ResponseMode::Jwt => {
            oauth_error_redirect_jarm(
                app_state,
                client,
                redirect_uri,
                error,
                description,
                oauth_state,
            )
            .await
        }
        ResponseMode::FormPost | ResponseMode::Query => oauth_error_response_unsigned(
            app_state,
            redirect_uri,
            error,
            description,
            oauth_state,
            response_mode,
        ),
    }
}

/// Build an OAuth error response for the **unsigned** response modes — `Query`
/// (RFC 6749 §4.1.2.1 query redirect) and `FormPost` (OAuth 2.0 Form Post
/// Response Mode). These modes need only `redirect_uri` + issuer config; the
/// client record is *not* consulted, so a caller that has none can still
/// deliver a conformant `access_denied` — certification `deny_login` after the
/// client was hard-deleted within the pending TTL, or any flow where a client
/// lookup would be gratuitous. (`oauth_error_response` delegates its
/// `FormPost`/`Query` arms here for the same reason.)
///
/// Includes the `iss` parameter per RFC 9207 in both modes.
///
/// `ResponseMode::Jwt` has no conformant unsigned form — JARM §2.1 requires the
/// JWT "even in case of an error response" and a client "MUST NOT" accept
/// `alg: none` — so a Jwt-mode caller MUST use [`oauth_error_response`] with the
/// client record. This entry point fail-closes with `500` on `Jwt` rather than
/// emit parameters a JARM client is obliged to discard; no current caller reaches
/// that branch (deny_login loads the client and routes the Jwt path through
/// `oauth_error_response`), so it exists only as a programmer-error guardrail.
pub(crate) fn oauth_error_response_unsigned(
    app_state: &Arc<AppState>,
    redirect_uri: &str,
    error: OAuthErrorCode,
    description: &str,
    oauth_state: Option<&str>,
    response_mode: ResponseMode,
) -> Response {
    match response_mode {
        ResponseMode::FormPost => {
            let mut params = vec![
                ("error".to_string(), error.as_str().to_string()),
                ("error_description".to_string(), description.to_string()),
                ("iss".to_string(), app_state.config().base_url.to_string()),
            ];
            if let Some(s) = oauth_state {
                params.push(("state".to_string(), s.to_string()));
            }
            FormPostResponseTemplate {
                redirect_uri: redirect_uri.to_string(),
                params,
            }
            .into_response()
        }
        ResponseMode::Query => {
            let issuer = &app_state.config().base_url;
            let mut params = vec![
                ("error", error.as_str()),
                ("error_description", description),
            ];
            if let Some(state_param) = oauth_state {
                params.push(("state", state_param));
            }
            params.push(("iss", issuer));
            build_authorization_redirect(redirect_uri, &params)
        }
        ResponseMode::Jwt => {
            // JARM has no unsigned form (JARM §2.1); fail closed rather than
            // emit parameters a JARM client MUST discard. Unreachable by any
            // current caller — see the doc above.
            tracing::error!(
                "oauth_error_response_unsigned called with ResponseMode::Jwt, \
                 which has no conformant unsigned form; failing closed"
            );
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Create an OAuth error redirect response using JARM encoding.
///
/// Fails closed when signing fails: JARM permits no unsigned form, so there
/// is nothing conformant to put on the redirect and it is not taken.
pub(super) async fn oauth_error_redirect_jarm(
    state: &Arc<AppState>,
    client: &OAuthClient,
    redirect_uri: &str,
    error: OAuthErrorCode,
    description: &str,
    oauth_state: Option<&str>,
) -> Response {
    match crate::services::oidc::jarm::build_jarm_error_jwt(
        state,
        client,
        error,
        Some(description),
        oauth_state,
    )
    .await
    {
        Ok(jwt) => {
            let url = build_jarm_redirect_url(redirect_uri, &jwt);
            axum::response::Redirect::to(&url).into_response()
        }
        Err(e) => {
            // Fail closed. JARM leaves no room for an unsigned fallback:
            //
            //   "The JWT MUST furthermore contain the authorization endpoint
            //    response parameters as defined for the particular response
            //    types, even in case of an error response."
            //   — JARM §2.1
            //
            // and the client is required to reject one anyway:
            //
            //   "The client MUST check the signature of the JWT according to
            //    [RFC7515] and the algorithm 'none' ('"alg":"none"') MUST NOT
            //    be accepted."
            //
            // Returning plain query parameters therefore sends the client
            // exactly what it is obliged to discard, while looking to the user
            // like the flow completed. With no JWT there is nothing
            // conformant to put on the redirect, so the redirect is not taken
            // at all and the failure surfaces here.
            tracing::error!("Failed to build JARM error JWT: {e}");
            AuthorizeDeniedTemplate {
                client_name: client.name.clone(),
                error_message: Tr::new("authorize-denied-jarm-signing-failed"),
            }
            .into_response()
        }
    }
}
