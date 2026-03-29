// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared client authentication extraction for OAuth endpoints.
//!
//! Provides client authentication logic used by both the token endpoint
//! (RFC 6749 Section 3.2) and the PAR endpoint (RFC 9126 Section 2).

use crate::AppState;
use crate::services::error::OAuthErrorResponse;
use crate::services::oidc::{
    jwt_bearer::client_auth::{PendingJti, authenticate_client_jwt},
    token::{AuthenticatedClient, ClientCredentials, authenticate_client},
};
use axum::{
    Json,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::SecretString;
use std::sync::Arc;

/// RFC 7521 Section 4.2: Expected client assertion type for JWT bearer.
const JWT_BEARER_CLIENT_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Extracted client authentication method from a request.
///
/// Represents the mutually-exclusive authentication methods that a client
/// can use at OAuth endpoints (RFC 7521 Section 4.2).
pub(crate) enum ExtractedClientAuth {
    /// Client secret via Basic header or body params.
    Secret(ClientCredentials),
    /// JWT assertion (RFC 7523).
    JwtAssertion {
        client_assertion: String,
        client_id: Option<String>,
    },
    /// Public client with only client_id.
    PublicClient { client_id: String },
    /// No authentication provided.
    None,
}

/// Fields needed for client authentication extraction.
///
/// Both `TokenRequest` and `ParRequest` implement this trait so the shared
/// extraction logic can work with either.
pub(crate) trait ClientAuthFields {
    fn client_id(&self) -> Option<&str>;
    fn client_secret(&self) -> Option<SecretString>;
    fn client_assertion(&self) -> Option<&str>;
    fn client_assertion_type(&self) -> Option<&str>;
}

/// Extract client credentials from Authorization header or request body.
///
/// Supports both `client_secret_basic` (RFC 6749 Section 2.3.1) and
/// `client_secret_post` (RFC 6749 Section 2.3.1) authentication methods.
pub(crate) fn extract_client_credentials(
    headers: &HeaderMap,
    client_id_param: Option<&str>,
    client_secret_param: Option<SecretString>,
) -> Option<ClientCredentials> {
    // Try Authorization header first (client_secret_basic)
    if let Some(auth_header) = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Basic "))
        && let Ok(decoded) = base64::engine::general_purpose::STANDARD
            .decode(auth_header.trim())
            .or_else(|_| URL_SAFE_NO_PAD.decode(auth_header.trim()))
        && let Ok(creds) = String::from_utf8(decoded)
        && let Some((id, secret)) = creds.split_once(':')
    {
        // RFC 6749 Section 2.3.1: URL-decode client_id and client_secret after base64 decoding
        let decoded_id =
            urlencoding::decode(id).map_or_else(|_| id.to_string(), |d| d.into_owned());
        let decoded_secret =
            urlencoding::decode(secret).map_or_else(|_| secret.to_string(), |d| d.into_owned());
        return Some(ClientCredentials {
            client_id: decoded_id,
            client_secret: Some(SecretString::from(decoded_secret)),
        });
    }

    // Fall back to request body parameters (client_secret_post)
    client_id_param.map(|id| ClientCredentials {
        client_id: id.to_string(),
        client_secret: client_secret_param,
    })
}

/// Extract client authentication from a request (RFC 7521 Section 4.2).
///
/// Handles mutual exclusion: a request MUST NOT use more than one client
/// authentication method (e.g., Basic auth header + client_assertion = error).
#[allow(clippy::result_large_err)]
pub(crate) fn extract_client_auth<T: ClientAuthFields>(
    headers: &HeaderMap,
    params: &T,
) -> Result<ExtractedClientAuth, Response> {
    let has_basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| h.starts_with("Basic "));

    let has_client_secret = params.client_secret().is_some();
    let has_client_assertion = params.client_assertion().is_some();

    // RFC 7521 Section 4.2: MUST NOT use more than one method
    if has_client_assertion && (has_basic || has_client_secret) {
        return Err(oauth_error_response(
            "invalid_request",
            "client_assertion cannot be combined with Basic auth or client_secret",
        ));
    }

    // JWT client assertion
    if let Some(assertion) = params.client_assertion() {
        // Validate assertion type
        let assertion_type = params.client_assertion_type().unwrap_or("");
        if assertion_type != JWT_BEARER_CLIENT_ASSERTION_TYPE {
            return Err(oauth_error_response(
                "invalid_request",
                &format!(
                    "Unsupported client_assertion_type. Expected: {JWT_BEARER_CLIENT_ASSERTION_TYPE}"
                ),
            ));
        }

        return Ok(ExtractedClientAuth::JwtAssertion {
            client_assertion: assertion.to_string(),
            client_id: params.client_id().map(String::from),
        });
    }

    // Secret-based auth (Basic header or body params)
    if let Some(creds) =
        extract_client_credentials(headers, params.client_id(), params.client_secret())
    {
        if creds.client_secret.is_some() || has_basic {
            return Ok(ExtractedClientAuth::Secret(creds));
        }
        // client_id only, no secret
        return Ok(ExtractedClientAuth::PublicClient {
            client_id: creds.client_id,
        });
    }

    Ok(ExtractedClientAuth::None)
}

/// Authenticate a client using any supported method.
///
/// Dispatches to secret-based or JWT-based authentication depending on
/// the extracted authentication method.
///
/// For JWT assertions, returns a [`PendingJti`] that MUST be committed via
/// [`crate::services::oidc::jwt_bearer::client_auth::commit_jti`] after the
/// full request succeeds. For all other auth methods, returns `None` for the
/// pending JTI.
pub(crate) async fn authenticate_client_any(
    state: &Arc<AppState>,
    auth: ExtractedClientAuth,
) -> Result<Option<(AuthenticatedClient, String, Option<PendingJti>)>, Response> {
    match auth {
        ExtractedClientAuth::Secret(creds) => {
            let client_id = creds.client_id.clone();
            match authenticate_client(state, &creds).await {
                Ok(client) => Ok(Some((client, client_id, None))),
                Err(e) => Err(e.into_service_error().into_oauth_response().into_response()),
            }
        }
        ExtractedClientAuth::JwtAssertion {
            client_assertion,
            client_id,
        } => match authenticate_client_jwt(state, &client_assertion, client_id.as_deref()).await {
            Ok((client, pending_jti)) => {
                let cid = client.client.client_id.clone();
                Ok(Some((client, cid, Some(pending_jti))))
            }
            Err(e) => Err(e.into_service_error().into_oauth_response().into_response()),
        },
        ExtractedClientAuth::PublicClient { client_id } => {
            // Public client — create credentials without a secret for authenticate_client
            let creds = ClientCredentials {
                client_id: client_id.clone(),
                client_secret: None,
            };
            match authenticate_client(state, &creds).await {
                Ok(client) => Ok(Some((client, client_id, None))),
                Err(e) => Err(e.into_service_error().into_oauth_response().into_response()),
            }
        }
        ExtractedClientAuth::None => Ok(None),
    }
}

/// Build an OAuth error response for parameter validation failures.
fn oauth_error_response(error: &str, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(OAuthErrorResponse {
            error: error.to_string(),
            error_description: Some(description.to_string()),
            error_uri: None,
        }),
    )
        .into_response()
}
