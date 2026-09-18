// SPDX-License-Identifier: Apache-2.0 OR MIT
//! FIDO2 challenge endpoint for the FIDO2 assertion grant.
//!
//! `POST /oauth/fido2/challenge` — Issues a short-lived challenge for CTAP2
//! assertion. The CLI calls this before performing a local FIDO2 assertion
//! and exchanging it at the token endpoint.
//!
//! The endpoint is rate-limited. During a staged rollout it accepts two
//! shapes of request: a `private_key_jwt`-authenticated form body, which
//! stamps the authenticated `client_id` into the returned state JWT so it
//! can be checked at redemption — binding the ceremony to the initiating
//! client, mirroring `authorization_code` and `device_code`, so a captured
//! state+assertion cannot be replayed under a different client — and an
//! unauthenticated request, including the JSON `{}` body sent by CLI
//! versions built before client authentication existed here, which mints a
//! state JWT with no `client_id` and is redeemable by any registered client,
//! exactly as before this change. Accepting the unauthenticated form is
//! deliberate: it keeps already-released CLIs working and lets a state token
//! minted by an old server instance still decode on a new one during a
//! rolling deploy. Client authentication becomes mandatory — the
//! unauthenticated branch removed — once the rollout completes in a later
//! release. The returned `state` token is an HS256 JWT
//! (`vouch-fido2-challenge+jwt`) containing the challenge, RP ID, optional
//! client_id, and expiration.

use crate::AppState;
use crate::arrival::ArrivalTime;
use crate::crypto::jwt::JwtType;
use crate::db;
use crate::error::{OAuthErrorCode, ServiceError};
use crate::handlers::extractors::OAuthFormOrLegacyEmpty;
use crate::handlers::generate_challenge;
use crate::handlers::oidc::client_auth::{
    ClientAuthFields, ClientAuthPresentation, ExtractedClientAuth, extract_client_auth,
    with_client_auth_challenge,
};
use crate::services::oidc::fido2_grant::Fido2ChallengeState;
use crate::services::oidc::grant_type::OAuthGrantType;
use crate::services::oidc::jwt_bearer::client_auth::authenticate_client_jwt;
use crate::services::oidc::validated_client::ValidatedOAuthClient;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use jiff::Timestamp;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vouch_common::encoding::{Base64Url, ConvertEncoding, Raw};
use vouch_common::fido2_types::Challenge;
use vouch_common::protocol;

/// Response from `POST /oauth/fido2/challenge`.
#[derive(Debug, Serialize)]
pub(super) struct Fido2ChallengeResponse {
    /// Base64url-encoded 32-byte challenge.
    pub challenge: Challenge<Base64Url>,
    /// Relying Party ID.
    pub rp_id: String,
    /// HS256 state JWT to return with the assertion at the token endpoint.
    pub state: String,
}

/// Form body of `POST /oauth/fido2/challenge`. Carries only the RFC 6749 §2.3
/// client-authentication parameters; the endpoint takes no grant parameters.
/// All fields are optional on the wire so [`extract_client_auth`] can run
/// its own missing-credential handling: a request carrying no credentials is
/// classified `None`, which this endpoint currently accepts as an
/// unauthenticated legacy request rather than rejecting outright — see the
/// module doc. `Default` also stands in for the request body during the
/// staged rollout: [`OAuthFormOrLegacyEmpty`] returns it unchanged for any
/// non-form body, such as the legacy JSON `{}` the CLI used to send.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct Fido2ChallengeRequest {
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<SecretString>,
    #[serde(default)]
    pub client_assertion: Option<SecretString>,
    #[serde(default)]
    pub client_assertion_type: Option<String>,
}

impl ClientAuthFields for Fido2ChallengeRequest {
    fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    fn client_secret(&self) -> Option<SecretString> {
        self.client_secret.clone()
    }

    fn client_assertion(&self) -> Option<&str> {
        self.client_assertion
            .as_ref()
            .map(secrecy::ExposeSecret::expose_secret)
    }

    fn client_assertion_type(&self) -> Option<&str> {
        self.client_assertion_type.as_deref()
    }
}

/// `POST /oauth/fido2/challenge` — Generate a FIDO2 challenge for the
/// assertion grant type.
///
/// Accepts `private_key_jwt` client authentication (the same method the
/// FIDO2 assertion grant requires at the token endpoint) and, during this
/// staged rollout, an unauthenticated request as well — see the module doc.
/// A client that does authenticate must be registered for the
/// `fido2-assertion` grant, and its `client_id` is stamped into the state
/// JWT so the token endpoint can reject a state+assertion presented by a
/// different client. An unauthenticated request mints a state JWT with no
/// `client_id`, which the token endpoint accepts from any client — matching
/// this endpoint's behavior before the fix. A request that attempts client
/// authentication by some other method (a shared secret, mTLS, a bare
/// `client_id`) is still rejected as `invalid_client`: only "no credentials
/// at all" and `private_key_jwt` are accepted.
#[expect(
    clippy::disallowed_methods,
    reason = "mints the challenge state token's expiry"
)]
pub(crate) async fn fido2_challenge(
    arrival: ArrivalTime,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    OAuthFormOrLegacyEmpty(req): OAuthFormOrLegacyEmpty<Fido2ChallengeRequest>,
) -> Response {
    let presentation = ClientAuthPresentation::of(&headers, &req);

    // Authenticate the client via private_key_jwt when credentials are
    // present. Like the FIDO2 token endpoint, only the JWT-bearer assertion
    // method is accepted; a request attempting a different method is
    // `invalid_client`. This mirrors `handlers::device::authenticate_device_client`
    // authenticating the client at `POST /oauth/device` before creating the
    // device code, and is the issuance-side half of the cross-client binding
    // the token endpoint enforces in `exchange_fido2_assertion`. A request
    // with no credentials at all is accepted unauthenticated for now — see
    // the module doc — and mints a state JWT with no `client_id`.
    let client_auth = match extract_client_auth(&headers, &req) {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };
    let client_id = match client_auth {
        ExtractedClientAuth::JwtAssertion {
            client_assertion,
            client_id,
        } => {
            let authenticated_client = match authenticate_client_jwt(
                &state,
                &client_assertion,
                client_id.as_deref(),
                arrival,
            )
            .await
            {
                Ok((client, _jti_claim, _auth)) => client,
                Err(e) => {
                    return with_client_auth_challenge(
                        presentation,
                        e.into_service_error().into_oauth_response().into_response(),
                    );
                }
            };

            // RFC 7591 §2 `grant_types`: the client must be registered for
            // the fido2-assertion grant to start its ceremony, so an
            // unauthorized client neither gets a usable state JWT nor learns
            // whether one would mint a token. Mirrors
            // `ValidatedOAuthClient::for_grant` at the token endpoint.
            let client = match ValidatedOAuthClient::for_grant(
                authenticated_client,
                OAuthGrantType::Fido2Assertion,
            ) {
                Ok(c) => c,
                Err(e) => return e.into_oauth_response().into_response(),
            };
            Some(client.client_id.clone())
        }
        ExtractedClientAuth::None => None,
        ExtractedClientAuth::Secret { .. } | ExtractedClientAuth::PublicClient { .. } => {
            return with_client_auth_challenge(
                presentation,
                ServiceError::oauth(
                    OAuthErrorCode::InvalidClient,
                    "fido2-assertion challenge requires private_key_jwt client authentication",
                )
                .into_oauth_response()
                .into_response(),
            );
        }
    };

    let challenge = match generate_challenge() {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": OAuthErrorCode::ServerError.as_str(),
                    "error_description": "Failed to generate challenge"
                })),
            )
                .into_response();
        }
    };

    let challenge: Challenge<Raw> = challenge.into();
    let now = Timestamp::now();
    let exp = now
        .checked_add(jiff::Span::new().minutes(5))
        .map_or(now.as_second().saturating_add(300), |t| t.as_second());

    let challenge_state = Fido2ChallengeState {
        challenge: challenge.clone(),
        rp_id: state.config().rp_id.clone(),
        client_id,
        iat: now.as_second(),
        exp,
    };

    let state_token = match state
        .state_signer
        .encode_state_token(&challenge_state, JwtType::Fido2ChallengeState)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to encode FIDO2 challenge state: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": OAuthErrorCode::ServerError.as_str(),
                    "error_description": "Failed to create challenge state"
                })),
            )
                .into_response();
        }
    };

    // RFC 9449 §8.2: Pre-generate a DPoP nonce so the CLI can include it
    // in the token request, avoiding a use_dpop_nonce round-trip in the
    // common case. If the nonce expires before the token request (e.g.
    // very slow touch), the existing use_dpop_nonce retry path handles it.
    let dpop_nonce = db::generate_dpop_nonce(
        &state.store,
        crate::services::oidc::dpop::nonce_validity_seconds(state.config().dpop_max_age_seconds),
    )
    .await;

    let mut response = (
        StatusCode::OK,
        [
            ("cache-control", "no-cache, no-store, must-revalidate"),
            ("pragma", "no-cache"),
            ("expires", "0"),
        ],
        Json(Fido2ChallengeResponse {
            challenge: challenge.to_base64url(),
            rp_id: state.config().rp_id.clone(),
            state: state_token,
        }),
    )
        .into_response();

    if let Ok(ref nonce) = dpop_nonce
        && let Ok(value) = axum::http::HeaderValue::from_str(nonce)
    {
        response
            .headers_mut()
            .insert(protocol::HEADER_DPOP_NONCE, value);
    }

    response
}
