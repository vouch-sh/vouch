// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Pushed Authorization Request (PAR) endpoint handler (RFC 9126).

use super::client_auth::{ClientAuthFields, complete_client_auth, extract_client_auth};
use crate::AppState;
use crate::db::{self, CreateParParams, PAR_EXPIRES_IN};
use crate::services::ServiceError;
use crate::services::auth::{ClientAuthProof, ParCreationProof};
use crate::services::error::OAuthErrorResponse;
use crate::services::oidc::DpopError;
use crate::services::oidc::authorization::{
    AuthorizeRequestParams, Prompt, require_pkce_for_client, validate_authorize_request,
};
use crate::services::oidc::jar::{validate_request_object, validate_request_object_header};
use crate::services::oidc::token::{ClientAuthError, validate_dpop_if_present};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// PAR response (RFC 9126 Section 2.2).
#[derive(Serialize)]
struct ParResponse {
    /// The request URI that the client uses at the authorization endpoint.
    request_uri: String,
    /// Lifetime of the request URI in seconds.
    expires_in: i64,
}

/// PAR request body (RFC 9126 Section 2.1).
///
/// Contains the same parameters as an authorization request, plus client
/// authentication fields.
#[derive(Debug, Deserialize)]
pub(crate) struct ParRequest {
    /// RFC 6749 Section 4.1.1: Response type (must be "code").
    #[serde(default)]
    response_type: Option<String>,
    /// RFC 6749 Section 4.1.1: Client identifier.
    #[serde(default)]
    client_id: Option<String>,
    /// RFC 6749 Section 4.1.1: Redirect URI for the response.
    #[serde(default)]
    redirect_uri: Option<String>,
    /// RFC 6749 Section 3.3: Requested scope.
    #[serde(default)]
    scope: Option<String>,
    /// RFC 6749 Section 4.1.1: State parameter.
    #[serde(default)]
    state: Option<String>,
    /// OIDC Core Section 3.1.2.1: Nonce value.
    #[serde(default)]
    nonce: Option<String>,
    /// RFC 7636 Section 4.2: PKCE code challenge.
    #[serde(default)]
    code_challenge: Option<String>,
    /// RFC 7636 Section 4.3: PKCE code challenge method.
    #[serde(default)]
    code_challenge_method: Option<String>,
    /// RFC 8707 Section 2: Target resource indicator.
    #[serde(default)]
    resource: Option<String>,
    /// RFC 9470: Requested authentication context class references.
    #[serde(default)]
    acr_values: Option<String>,
    /// RFC 9470 / OIDC Core Section 3.1.2.1: Maximum authentication age in seconds.
    #[serde(default)]
    max_age: Option<u64>,
    /// OIDC Core Section 3.1.2.1: Requested prompt behavior.
    #[serde(default)]
    prompt: Option<String>,
    /// RFC 9126 Section 2.1: MUST NOT include request_uri in PAR request.
    #[serde(default)]
    request_uri: Option<String>,
    /// RFC 6749 Section 2.3.1: Client secret.
    #[serde(default)]
    client_secret: Option<SecretString>,
    /// RFC 7521 Section 4.2: Client assertion for JWT client authentication.
    #[serde(default)]
    client_assertion: Option<String>,
    /// RFC 7521 Section 4.2: Client assertion type.
    #[serde(default)]
    client_assertion_type: Option<String>,
    /// RFC 9101: JWT-Secured Authorization Request (Request Object).
    #[serde(default)]
    request: Option<String>,
    /// RFC 9449 Section 10: DPoP JWK thumbprint for authorization code binding.
    #[serde(default)]
    dpop_jkt: Option<String>,
    /// RFC 9396: Rich authorization details (JSON array).
    #[serde(default)]
    authorization_details: Option<String>,
    /// JARM: Requested authorization response mode.
    #[serde(default)]
    response_mode: Option<String>,
}

/// Implement `ClientAuthFields` for `ParRequest` to enable shared client
/// authentication extraction.
impl ClientAuthFields for ParRequest {
    fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    fn client_secret(&self) -> Option<SecretString> {
        self.client_secret.clone()
    }

    fn client_assertion(&self) -> Option<&str> {
        self.client_assertion.as_deref()
    }

    fn client_assertion_type(&self) -> Option<&str> {
        self.client_assertion_type.as_deref()
    }
}

/// POST /oauth/par
///
/// Pushed Authorization Request endpoint (RFC 9126 Section 2).
///
/// Allows clients to POST authorization request parameters directly,
/// receiving a `request_uri` reference in exchange. The client then
/// redirects the user to the authorization endpoint with only
/// `client_id` and `request_uri`.
///
/// ## Requirements
///
/// - Client authentication is REQUIRED (RFC 9126 Section 2).
/// - The `request_uri` parameter MUST NOT be present in the request.
/// - All standard authorization request parameters are accepted.
///
/// ## Response
///
/// Returns 201 Created with a JSON body containing `request_uri` and `expires_in`.
pub(crate) async fn par(
    State(state): State<Arc<AppState>>,
    client_cert: crate::handlers::extractors::OptionalClientCert,
    headers: HeaderMap,
    axum::Form(params): axum::Form<ParRequest>,
) -> Response {
    // RFC 9126 Section 2.1: request_uri MUST NOT be provided in a PAR request
    if params.request_uri.is_some() {
        return par_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request_uri must not be provided in a pushed authorization request",
        );
    }

    // RFC 9101: If a Request Object is present, validate its header algorithm BEFORE
    // client authentication. When alg=none is used, the unsigned JWT would otherwise
    // be mistaken for a client_assertion and produce `invalid_client` instead of the
    // correct `invalid_request_object`.
    if let Some(ref request_jwt) = params.request
        && let Err(e) = validate_request_object_header(request_jwt)
    {
        let description = match &e {
            crate::services::ServiceError::OAuth { description, .. } => description.clone(),
            _ => e.to_string(),
        };
        return par_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            &description,
        );
    }

    // Extract and authenticate the client (required for PAR)
    let client_auth = match extract_client_auth(&headers, &params) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };

    // RFC 9126 Section 2: Client authentication is REQUIRED
    let Some(any_auth) = (match complete_client_auth(&state, client_auth).await {
        Ok(result) => result,
        Err(resp) => return resp,
    }) else {
        return par_error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Client authentication is required for pushed authorization requests",
        );
    };
    let authenticated_client = any_auth.client;
    let pending_jti = any_auth.pending_jti;
    let jwt_auth = any_auth.jwt_auth;
    let secret_verification = any_auth.secret_verification;

    // RFC 8705 §2 / FAPI 2.0 §5.2.2: mTLS dispatch. When the client is
    // registered with `tls_client_auth` or `self_signed_tls_client_auth`
    // and no body-level credential has authenticated it, verify the TLS
    // client certificate. Must run before FAPI auth-method validation so
    // a successfully mTLS-authenticated client is accepted by that gate.
    let mtls_verification = if pending_jti.is_none()
        && secret_verification.is_none()
        && matches!(
            authenticated_client.client.token_endpoint_auth_method,
            crate::db::TokenEndpointAuthMethod::TlsClientAuth
                | crate::db::TokenEndpointAuthMethod::SelfSignedTlsClientAuth
        ) {
        let Some(cert) = client_cert.0.as_ref() else {
            return par_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "mTLS client certificate required",
            );
        };
        let jwks_cache_value =
            crate::db::get_jwks_cache(&state.store, &authenticated_client.client.id)
                .await
                .ok()
                .flatten()
                .map(|c| c.value);
        match crate::services::oidc::token::authenticate_client_mtls(
            &authenticated_client.client,
            cert,
            jwks_cache_value.as_ref(),
        ) {
            Ok(verification) => Some(verification),
            Err(e) => return e.into_service_error().into_oauth_response().into_response(),
        }
    } else {
        None
    };

    // FAPI 2.0: Validate client authentication method.
    //
    // FAPI 2.0 Section 5.2.2 requires `private_key_jwt`. Client secrets and
    // public-client ("none") authentication are rejected for FAPI clients.
    if let Err(e) = crate::services::oidc::fapi::validate_fapi_client_auth_method(
        &authenticated_client.client,
        authenticated_client.client.token_endpoint_auth_method,
    ) {
        let desc = match &e {
            ServiceError::OAuth { description, .. } => description.clone(),
            _ => e.to_string(),
        };
        return par_error_response(StatusCode::UNAUTHORIZED, "invalid_client", &desc);
    }

    // RFC 9101: Enforce require_signed_request_object for this client.
    // If the client requires signed request objects and no `request` JWT was
    // provided, reject the PAR request.  Use `invalid_request` per PAR-2.3:
    // the request itself is invalid (missing required parameter), not a
    // malformed request object.
    if authenticated_client.client.require_signed_request_object == Some(true)
        && params.request.is_none()
    {
        return par_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "This client requires a signed Request Object (RFC 9101)",
        );
    }

    // RFC 9449 Section 10: Capture DPoP proof at PAR for authorization code binding.
    // If a DPoP proof is provided, bind the JWK thumbprint to the PAR record so
    // that the same key must be used at the token endpoint.
    let dpop_header = headers.get("DPoP").and_then(|v| v.to_str().ok());
    let dpop_proof = match validate_dpop_if_present(&state, dpop_header, "POST", "/oauth/par").await
    {
        Ok(proof) => proof,
        Err(DpopError::UseNonce(nonce)) => {
            return (
                StatusCode::BAD_REQUEST,
                [(
                    axum::http::header::HeaderName::from_static("dpop-nonce"),
                    nonce.to_string(),
                )],
                Json(OAuthErrorResponse {
                    error: "use_dpop_nonce".to_string(),
                    error_description: Some(
                        "Authorization server requires nonce in DPoP proof".to_string(),
                    ),
                    error_uri: None,
                }),
            )
                .into_response();
        }
        Err(e @ DpopError::Database(_)) => {
            return par_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            );
        }
        Err(e) => {
            return par_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_dpop_proof",
                &e.to_string(),
            );
        }
    };
    let dpop_jkt = dpop_proof.as_ref().map(|p| p.jkt.as_str());

    // RFC 9449 Section 10: If both a DPoP proof header and a dpop_jkt request
    // parameter are present, the JWK thumbprints MUST match.
    if let (Some(proof_jkt), Some(param_jkt)) = (dpop_jkt, &params.dpop_jkt) {
        let is_match: bool = proof_jkt.as_bytes().ct_eq(param_jkt.as_bytes()).into();
        if !is_match {
            return par_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_dpop_proof",
                "dpop_jkt parameter does not match DPoP proof JWK thumbprint",
            );
        }
    }

    // Helper: convert ServiceError to PAR error response fields.
    let service_error_codes = |e: &ServiceError| -> (&str, String) {
        match e {
            ServiceError::OAuth { code, description } => (code.as_str(), description.clone()),
            _ => ("server_error", e.to_string()),
        }
    };

    // RFC 9101: If request parameter is present, validate the Request Object JWT
    // and extract parameters from it instead of using the form fields.
    let (validated, jar_response_mode) = if let Some(ref request_jwt) = params.request {
        let request_params =
            match validate_request_object(&state, request_jwt, &authenticated_client.client, None)
                .await
            {
                Ok(params) => params,
                Err(e) => {
                    let (error_code, description) = service_error_codes(&e);
                    return par_error_response(StatusCode::BAD_REQUEST, error_code, &description);
                }
            };

        // client_id from JWT must match the authenticated client
        if request_params.client_id != authenticated_client.client.client_id {
            return par_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_object",
                "client_id in Request Object does not match authenticated client",
            );
        }

        // Capture response_mode from the JAR claims before consuming request_params.
        // JAR claims take precedence over the plain form body.
        let jar_rm = request_params.response_mode.clone();
        let v = match validate_authorize_request(request_params) {
            Ok(v) => v,
            Err(e) => {
                let (error_code, description) = service_error_codes(&e);
                return par_error_response(StatusCode::BAD_REQUEST, error_code, &description);
            }
        };
        (v, jar_rm)
    } else {
        // Validate prompt before constructing params
        let parsed_prompt = match params.prompt.as_deref() {
            Some(p) => match Prompt::parse(p) {
                Some(prompt) => Some(prompt),
                None => {
                    return par_error_response(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "Unsupported prompt value. Only 'login' and 'none' are supported",
                    );
                }
            },
            None => None,
        };

        let request_params = AuthorizeRequestParams {
            response_type: params.response_type.unwrap_or_default(),
            client_id: authenticated_client.client.client_id.clone(),
            redirect_uri: params.redirect_uri.clone().unwrap_or_default(),
            scope: params.scope.clone(),
            state: params.state.clone(),
            nonce: params.nonce.clone(),
            code_challenge: params.code_challenge.clone(),
            code_challenge_method: params.code_challenge_method.clone(),
            resource: params.resource.clone(),
            acr_values: params.acr_values.clone(),
            max_age: params.max_age,
            prompt: parsed_prompt,
            dpop_jkt: params.dpop_jkt.clone(),
            authorization_details: params.authorization_details.clone(),
            response_mode: params.response_mode.clone(),
        };

        let v = match validate_authorize_request(request_params) {
            Ok(v) => v,
            Err(e) => {
                let (error_code, description) = service_error_codes(&e);
                return par_error_response(StatusCode::BAD_REQUEST, error_code, &description);
            }
        };
        (v, None)
    };

    // RFC 9700: PKCE required for public clients and Native/SPA types.
    if let Err(e) = require_pkce_for_client(&validated, &authenticated_client.client) {
        let description = match &e {
            ServiceError::OAuth { description, .. } => description.clone(),
            _ => e.to_string(),
        };
        return par_error_response(StatusCode::BAD_REQUEST, "invalid_request", &description);
    }

    // Validate redirect_uri against registered URIs
    if !authenticated_client
        .client
        .is_valid_redirect_uri(validated.redirect_uri())
    {
        return par_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is not registered for this client",
        );
    }

    // RFC 8707: Validate resource parameter against registered URIs
    if let Some(resource) = validated.resource()
        && !authenticated_client.client.is_valid_resource_uri(resource)
    {
        return par_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "The requested resource is not registered for this client",
        );
    }

    // Store the pushed authorization request.
    // RFC 9449 Section 10: dpop_jkt can come from the request parameter
    // (in the authorization request body) or from the DPoP proof header.
    // The request parameter takes precedence since it's the explicit binding.
    let effective_dpop_jkt = validated.dpop_jkt().or(dpop_jkt);

    // RFC 9449 Section 10: When a dpop_jkt value is present (either from the
    // JAR claims or the plain form body) AND a DPoP proof header was provided,
    // the two JWK thumbprints MUST match. The earlier check (above) only covers
    // params.dpop_jkt; this covers the JAR-sourced dpop_jkt value.
    if let (Some(requested_jkt), Some(proof)) = (effective_dpop_jkt, &dpop_proof) {
        let is_match: bool = requested_jkt.as_bytes().ct_eq(proof.jkt.as_bytes()).into();
        if !is_match {
            return par_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_dpop_proof",
                "dpop_jkt does not match DPoP proof JWK thumbprint",
            );
        }
    }

    let scope_str = validated.scope().to_space_separated();
    let max_age_i64 = validated.max_age().and_then(|v| i64::try_from(v).ok());
    let ad_value = validated.authorization_details_value();
    // JAR claims take precedence over the plain form body for response_mode.
    let response_mode_str = jar_response_mode
        .as_deref()
        .or(params.response_mode.as_deref());
    let response_mode = match response_mode_str {
        None | Some("query") => crate::db::documents::oauth::ResponseMode::Query,
        Some(mode) => match crate::db::documents::oauth::ResponseMode::parse(mode) {
            Some(m) => m,
            None => {
                return par_error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Unsupported response_mode. Supported values: query, jwt, query.jwt",
                );
            }
        },
    };

    let create_params = CreateParParams {
        client_id: validated.client_id(),
        response_type: "code",
        redirect_uri: validated.redirect_uri(),
        scope: Some(&scope_str),
        state: validated.state(),
        nonce: validated.nonce(),
        code_challenge: validated.code_challenge(),
        code_challenge_method: validated.code_challenge_method().map(|m| m.as_str()),
        resource: validated.resource(),
        acr_values: validated.acr_values(),
        max_age: max_age_i64,
        prompt: validated.prompt().map(|p| p.as_str()),
        dpop_jkt: effective_dpop_jkt,
        authorization_details: ad_value.as_ref(),
        response_mode,
    };

    let jti_claim = match pending_jti {
        Some(p) => match p.commit(&state).await {
            Ok(claim) => claim,
            Err(e) => {
                tracing::warn!("JTI commit failed for PAR: {e:?}");
                // Distinguish replay (client-auth failure) from transient DB error
                // (server problem). Returning 401 for a DB outage tells well-behaved
                // clients to abandon credentials they should reuse on retry; returning
                // 500 for a replay tempts them to retry-loop with a consumed JTI.
                return match e {
                    ClientAuthError::InvalidCredentials => par_error_response(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "Client authentication failed",
                    ),
                    _ => par_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "Failed to complete client authentication",
                    ),
                };
            }
        },
        None => None,
    };
    // Resolve client-auth proof by precedence: JWT → secret → mTLS. If
    // none succeeded, fall back to `for_public_client` against the loaded
    // client — fails for confidential clients that should have authed.
    //
    // RFC 7523 §3 makes `jti` OPTIONAL — so JWT auth can succeed with
    // `jti_claim == None`. We gate on the `jwt_auth` witness, not on
    // `jti_claim`, to avoid silently rejecting a non-FAPI client that
    // legitimately omitted `jti`.
    let par_client_auth = if let Some(auth) = jwt_auth {
        ClientAuthProof::PrivateKeyJwt(crate::services::auth::JwtClientAuthProof::new(
            auth, jti_claim,
        ))
    } else if let Some(s) = secret_verification {
        ClientAuthProof::ClientSecret(s)
    } else if let Some(v) = mtls_verification {
        ClientAuthProof::MutualTls(v)
    } else {
        let witness = match crate::services::auth::NoClientAuth::for_public_client(
            &authenticated_client.client,
        ) {
            Ok(w) => w,
            Err(svc) => return svc.into_oauth_response().into_response(),
        };
        ClientAuthProof::NoAuth(witness)
    };
    let proof = ParCreationProof {
        client_auth: par_client_auth,
    };

    // RFC 9126 Section 2.2: Return 201 Created
    match db::create_pushed_authorization_request(&state.store, create_params, proof).await {
        Ok((_id, request_uri)) => (
            StatusCode::CREATED,
            Json(ParResponse {
                request_uri,
                expires_in: PAR_EXPIRES_IN,
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to create pushed authorization request: {}", e);
            par_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to store pushed authorization request",
            )
        }
    }
}

/// Build a PAR error response.
fn par_error_response(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(OAuthErrorResponse {
            error: error.to_string(),
            error_description: Some(description.to_string()),
            error_uri: None,
        }),
    )
        .into_response()
}
