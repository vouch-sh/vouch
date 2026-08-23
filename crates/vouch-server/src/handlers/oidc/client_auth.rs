// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared client authentication extraction for OAuth endpoints.
//!
//! Provides client authentication logic used by both the token endpoint
//! (RFC 6749 Section 3.2) and the PAR endpoint (RFC 9126 Section 2).

use crate::AppState;
use crate::error::{OAuthErrorCode, OAuthErrorResponse};
use crate::services::oidc::{
    jwt_bearer::client_auth::{PendingJti, authenticate_client_jwt},
    token::{AuthenticatedClient, ClientCredentials, authenticate_client},
};
use axum::{
    Json,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::SecretString;
use std::sync::Arc;
use vouch_common::protocol;

/// RFC 7521 Section 4.2: Expected client assertion type for JWT bearer.
///
/// The value itself is fixed by RFC 7523 §2.2 and shared with the CLI via
/// [`vouch_common::protocol`].
const JWT_BEARER_CLIENT_ASSERTION_TYPE: &str = protocol::CLIENT_ASSERTION_TYPE_JWT_BEARER;

/// Extracted client authentication method from a request.
///
/// Represents the mutually-exclusive authentication methods that a client
/// can use at OAuth endpoints (RFC 7521 Section 4.2).
pub(crate) enum ExtractedClientAuth {
    /// Client secret via Basic header or body params.
    Secret {
        creds: ClientCredentials,
        presentation: ClientAuthPresentation,
    },
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

/// Strip the `Basic ` auth-scheme prefix, matching case-insensitively.
///
/// RFC 9110 Section 11.1 and RFC 7617 Section 2 require the auth-scheme
/// token to be matched case-insensitively, so `basic` and `BASIC` are as
/// valid as `Basic`.
fn strip_basic_scheme(header: &str) -> Option<&str> {
    let (scheme, rest) = header.split_once(' ')?;
    scheme.eq_ignore_ascii_case("Basic").then_some(rest)
}

/// Where the client presented its credentials (RFC 6749 Section 2.3.1).
///
/// Recorded because RFC 6749 Section 5.2 makes the `WWW-Authenticate`
/// response header mandatory on a 401 only when the client authenticated
/// via the `Authorization` request header field. That condition is a
/// property of the request, not of the error code, so it has to travel
/// with the credentials rather than be re-derived at each failure site.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ClientAuthPresentation {
    /// `Authorization: Basic` header — `client_secret_basic`.
    AuthorizationHeader,
    /// Request-body parameters — `client_secret_post`, or a bare `client_id`.
    RequestBody,
    /// The request carried no client credentials at all.
    NoCredentials,
}

impl ClientAuthPresentation {
    /// Classify how the client presented credentials on this request, by
    /// inspecting both the `Authorization` header and the request body.
    ///
    /// A malformed `Authorization: Basic` header still counts as
    /// [`Self::AuthorizationHeader`]: RFC 6749 Section 5.2 binds on the
    /// client having *attempted* header authentication, not on the attempt
    /// having parsed.
    pub(crate) fn of<T: ClientAuthFields>(headers: &HeaderMap, params: &T) -> Self {
        let used_header = headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .is_some_and(|h| strip_basic_scheme(h).is_some());
        if used_header {
            Self::AuthorizationHeader
        } else if params.client_id().is_some() || params.client_secret().is_some() {
            Self::RequestBody
        } else {
            Self::NoCredentials
        }
    }

    /// The `WWW-Authenticate` challenge matching the scheme the client used,
    /// or `None` when the client did not use the `Authorization` header.
    fn challenge(self) -> Option<HeaderValue> {
        match self {
            Self::AuthorizationHeader => Some(HeaderValue::from_static("Basic")),
            // RFC 6749 Section 5.2 mandates a challenge only for header
            // authentication. Advertising `Basic` to a client that used
            // neither would name a scheme it did not attempt.
            Self::RequestBody | Self::NoCredentials => None,
        }
    }
}

/// Attach the RFC 6749 Section 5.2 `WWW-Authenticate` challenge to a
/// client-authentication failure.
///
/// RFC 6749 Section 5.2, `specs/rfc/rfc6749.txt:2493-2498`: "If the client
/// attempted to authenticate via the "Authorization" request header field,
/// the authorization server MUST respond with an HTTP 401 (Unauthorized)
/// status code and include the "WWW-Authenticate" response header field
/// matching the authentication scheme used by the client."
///
/// Only 401s are touched. `OAuthErrorCode::status_code` already maps
/// `invalid_client` to 401, so every failure this MUST binds arrives here
/// with that status; a non-401 response means the failure was something
/// other than client authentication and carries no challenge.
pub(crate) fn with_client_auth_challenge(
    presentation: ClientAuthPresentation,
    mut response: Response,
) -> Response {
    if response.status() == StatusCode::UNAUTHORIZED
        && let Some(challenge) = presentation.challenge()
        && !response.headers().contains_key(header::WWW_AUTHENTICATE)
    {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, challenge);
    }
    response
}

/// Extract client credentials from Authorization header or request body.
///
/// Supports both `client_secret_basic` (RFC 6749 Section 2.3.1) and
/// `client_secret_post` (RFC 6749 Section 2.3.1) authentication methods.
/// The returned [`ClientAuthPresentation`] records which the client used,
/// so a later failure can emit the matching challenge.
pub(crate) fn extract_client_credentials<T: ClientAuthFields>(
    headers: &HeaderMap,
    params: &T,
) -> Option<(ClientCredentials, ClientAuthPresentation)> {
    // Try Authorization header first (client_secret_basic)
    if let Some(auth_header) = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(strip_basic_scheme)
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
        return Some((
            ClientCredentials {
                client_id: decoded_id,
                client_secret: Some(SecretString::from(decoded_secret)),
            },
            ClientAuthPresentation::AuthorizationHeader,
        ));
    }

    // Fall back to request body parameters (client_secret_post).
    params.client_id().map(|id| {
        (
            ClientCredentials {
                client_id: id.to_string(),
                client_secret: params.client_secret(),
            },
            ClientAuthPresentation::of(headers, params),
        )
    })
}

/// Extract client authentication from a request (RFC 7521 Section 4.2).
///
/// Handles mutual exclusion: a request MUST NOT use more than one client
/// authentication method (e.g., Basic auth header + client_assertion = error).
#[expect(
    clippy::result_large_err,
    reason = "Err is an HTTP Response; size is acceptable in error path"
)]
pub(crate) fn extract_client_auth<T: ClientAuthFields>(
    headers: &HeaderMap,
    params: &T,
) -> Result<ExtractedClientAuth, Response> {
    let has_basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| strip_basic_scheme(h).is_some());

    let has_client_secret = params.client_secret().is_some();
    let has_client_assertion = params.client_assertion().is_some();

    // RFC 7521 Section 4.2: MUST NOT use more than one method
    if has_client_assertion && (has_basic || has_client_secret) {
        return Err(oauth_error_response(
            OAuthErrorCode::InvalidRequest,
            "client_assertion cannot be combined with Basic auth or client_secret",
        ));
    }

    // JWT client assertion
    if let Some(assertion) = params.client_assertion() {
        // Validate assertion type
        let assertion_type = params.client_assertion_type().unwrap_or("");
        if assertion_type != JWT_BEARER_CLIENT_ASSERTION_TYPE {
            return Err(oauth_error_response(
                OAuthErrorCode::InvalidRequest,
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
    if let Some((creds, presentation)) = extract_client_credentials(headers, params) {
        if creds.client_secret.is_some() || has_basic {
            return Ok(ExtractedClientAuth::Secret {
                creds,
                presentation,
            });
        }
        // client_id only, no secret
        return Ok(ExtractedClientAuth::PublicClient {
            client_id: creds.client_id,
        });
    }

    Ok(ExtractedClientAuth::None)
}

/// Result of a successful `complete_client_auth` dispatch.
pub(crate) struct ClientAuthOutcome {
    pub(crate) client: AuthenticatedClient,
    pub(crate) client_id: String,
    /// `Some` only for JWT-authenticated clients — caller must commit.
    pub(crate) pending_jti: Option<PendingJti>,
    /// `Some` only for JWT-authenticated clients — pair with `pending_jti.commit()`
    /// to construct `ClientAuthProof::PrivateKeyJwt`. Independent of jti presence
    /// because RFC 7523 §3 makes `jti` OPTIONAL for non-FAPI clients.
    pub(crate) jwt_auth: Option<crate::services::oidc::jwt_bearer::client_auth::JwtAuthSucceeded>,
    /// `Some` only when a `client_secret` was validated.
    pub(crate) secret_verification: Option<crate::services::oidc::token::ClientSecretVerification>,
}

/// Authenticate a client using any supported method.
///
/// Dispatches to secret-based or JWT-based authentication depending on
/// the extracted authentication method. Returns the verification witnesses
/// produced by the dispatched method (JTI claim for JWT, secret-verification
/// for client_secret_basic/post). mTLS verification is performed separately
/// by the handler via [`validate_mtls_client_auth`] because it requires the
/// client certificate from the request extractor.
pub(crate) async fn complete_client_auth(
    state: &Arc<AppState>,
    auth: ExtractedClientAuth,
) -> Result<Option<ClientAuthOutcome>, Response> {
    match auth {
        ExtractedClientAuth::Secret {
            creds,
            presentation,
        } => {
            let client_id = creds.client_id.clone();
            match authenticate_client(state, &creds).await {
                Ok((client, secret_verification)) => Ok(Some(ClientAuthOutcome {
                    client,
                    client_id,
                    pending_jti: None,
                    jwt_auth: None,
                    secret_verification,
                })),
                Err(e) => Err(with_client_auth_challenge(
                    presentation,
                    e.into_service_error().into_oauth_response().into_response(),
                )),
            }
        }
        ExtractedClientAuth::JwtAssertion {
            client_assertion,
            client_id,
        } => match authenticate_client_jwt(state, &client_assertion, client_id.as_deref()).await {
            Ok((client, pending_jti, jwt_auth)) => {
                let cid = client.client.client_id.clone();
                Ok(Some(ClientAuthOutcome {
                    client,
                    client_id: cid,
                    pending_jti: Some(pending_jti),
                    jwt_auth: Some(jwt_auth),
                    secret_verification: None,
                }))
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
                Ok((client, secret_verification)) => Ok(Some(ClientAuthOutcome {
                    client,
                    client_id,
                    pending_jti: None,
                    jwt_auth: None,
                    secret_verification,
                })),
                Err(e) => Err(e.into_service_error().into_oauth_response().into_response()),
            }
        }
        ExtractedClientAuth::None => Ok(None),
    }
}

/// Build an OAuth error response for parameter validation failures.
fn oauth_error_response(code: OAuthErrorCode, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(OAuthErrorResponse {
            error: code.as_str().to_string(),
            error_description: Some(description.to_string()),
            error_uri: None,
        }),
    )
        .into_response()
}

/// Derive the authentication method ACTUALLY used on this request from the
/// verification witnesses, as opposed to the registered
/// `token_endpoint_auth_method` (which the presented credentials do not have
/// to match — e.g. a stale client secret on a client since migrated to
/// `private_key_jwt`).
///
/// * `jwt_auth` — a `client_assertion` was verified (RFC 7523).
/// * `secret_auth` — a `client_secret` (Basic or body) was verified.
/// * `mtls_auth` — a TLS client certificate was verified (RFC 8705). mTLS
///   verification only runs for clients registered with a TLS method, so
///   `registered` names the exact variant in that case.
///
/// A verified secret is reported as the registered secret variant when the
/// client is registered with one (error-message fidelity); Basic vs Post is
/// not distinguishable from the witness, and both are equally rejected for
/// FAPI clients.
pub(crate) fn actual_auth_method(
    registered: crate::db::TokenEndpointAuthMethod,
    jwt_auth: bool,
    secret_auth: bool,
    mtls_auth: bool,
) -> crate::db::TokenEndpointAuthMethod {
    use crate::db::TokenEndpointAuthMethod;
    if jwt_auth {
        TokenEndpointAuthMethod::PrivateKeyJwt
    } else if secret_auth {
        match registered {
            m @ (TokenEndpointAuthMethod::ClientSecretBasic
            | TokenEndpointAuthMethod::ClientSecretPost) => m,
            _ => TokenEndpointAuthMethod::ClientSecretBasic,
        }
    } else if mtls_auth {
        registered
    } else {
        TokenEndpointAuthMethod::None
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use base64::Engine;

    fn basic_header(scheme: &str) -> HeaderMap {
        let creds = base64::engine::general_purpose::STANDARD.encode("client-1:s3cret");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("{scheme} {creds}").parse().expect("valid header"),
        );
        headers
    }

    /// Request body carrying whichever client credentials a test needs.
    #[derive(Default)]
    struct BodyParams {
        client_id: Option<String>,
        client_secret: Option<String>,
    }

    impl ClientAuthFields for BodyParams {
        fn client_id(&self) -> Option<&str> {
            self.client_id.as_deref()
        }
        fn client_secret(&self) -> Option<SecretString> {
            self.client_secret.clone().map(SecretString::from)
        }
        fn client_assertion(&self) -> Option<&str> {
            None
        }
        fn client_assertion_type(&self) -> Option<&str> {
            None
        }
    }

    /// RFC 9110 Section 11.1 / RFC 7617 Section 2: the auth-scheme token is
    /// case-insensitive, so `basic` and `BASIC` must work like `Basic`.
    #[test]
    fn test_extract_client_credentials_scheme_case_insensitive() {
        for scheme in ["Basic", "basic", "BASIC", "bAsIc"] {
            let headers = basic_header(scheme);
            let creds = extract_client_credentials(&headers, &BodyParams::default());
            assert!(creds.is_some(), "{scheme} scheme must be accepted");
            let (creds, presentation) = creds.expect("checked above");
            assert_eq!(creds.client_id, "client-1", "{scheme}");
            assert!(creds.client_secret.is_some(), "{scheme}");
            assert_eq!(
                presentation,
                ClientAuthPresentation::AuthorizationHeader,
                "{scheme} is header authentication regardless of casing"
            );
        }
    }

    /// Each variant must be a fact the classifier established, not an
    /// assumption: `RequestBody` requires credentials actually in the body,
    /// and a request with none at all is neither.
    #[test]
    fn test_presentation_distinguishes_header_body_and_absent_credentials() {
        let mut malformed = HeaderMap::new();
        malformed.insert(
            header::AUTHORIZATION,
            "Basic !!!not-base64!!!".parse().expect("valid header"),
        );

        let empty_body = BodyParams::default();
        let id_only = BodyParams {
            client_id: Some("client-1".to_string()),
            client_secret: None,
        };
        let secret_only = BodyParams {
            client_id: None,
            client_secret: Some("s3cret".to_string()),
        };

        // RFC 6749 Section 5.2 binds on the client having *attempted* header
        // authentication, so an undecodable header still classifies as one —
        // and outranks body credentials.
        assert_eq!(
            ClientAuthPresentation::of(&malformed, &empty_body),
            ClientAuthPresentation::AuthorizationHeader
        );
        assert_eq!(
            ClientAuthPresentation::of(&malformed, &id_only),
            ClientAuthPresentation::AuthorizationHeader
        );

        // Either body credential alone is enough to be body authentication.
        assert_eq!(
            ClientAuthPresentation::of(&HeaderMap::new(), &id_only),
            ClientAuthPresentation::RequestBody
        );
        assert_eq!(
            ClientAuthPresentation::of(&HeaderMap::new(), &secret_only),
            ClientAuthPresentation::RequestBody
        );

        // No header, no body credentials: previously mislabelled as
        // `RequestBody` on the strength of the header check alone.
        assert_eq!(
            ClientAuthPresentation::of(&HeaderMap::new(), &empty_body),
            ClientAuthPresentation::NoCredentials
        );
    }

    #[test]
    fn test_strip_basic_scheme_rejects_other_schemes() {
        assert!(strip_basic_scheme("Bearer abc").is_none());
        assert!(strip_basic_scheme("Basicabc").is_none());
        assert!(strip_basic_scheme("Basic creds").is_some());
    }

    /// The witness-derived method must reflect what the request actually
    /// authenticated with, regardless of the registered method (#706).
    #[test]
    fn test_actual_auth_method_from_witnesses() {
        use crate::db::TokenEndpointAuthMethod as M;

        // A verified JWT assertion is private_key_jwt no matter what is registered.
        assert_eq!(
            actual_auth_method(M::ClientSecretBasic, true, false, false),
            M::PrivateKeyJwt
        );
        // A verified secret on a private_key_jwt-registered client is a
        // secret method, NOT the registered method.
        assert_eq!(
            actual_auth_method(M::PrivateKeyJwt, false, true, false),
            M::ClientSecretBasic
        );
        // A verified secret on a secret-registered client keeps the variant.
        assert_eq!(
            actual_auth_method(M::ClientSecretPost, false, true, false),
            M::ClientSecretPost
        );
        // mTLS verification only runs when a TLS method is registered.
        assert_eq!(
            actual_auth_method(M::SelfSignedTlsClientAuth, false, false, true),
            M::SelfSignedTlsClientAuth
        );
        // No witness at all is the public-client "none" method.
        assert_eq!(
            actual_auth_method(M::PrivateKeyJwt, false, false, false),
            M::None
        );
    }
}
