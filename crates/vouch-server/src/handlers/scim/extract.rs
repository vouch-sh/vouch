// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Request extractors and response shaping that keep every SCIM error in the
//! RFC 7644 §3.12 JSON format.
//!
//! [`ScimJson`] and [`ScimQuery`] replace axum's `Json` and `Query` in SCIM
//! handlers: their rejections carry a SCIM error body and the §3.12 status and
//! `scimType` for the failure, where axum's are plain text. [`scim_error_body`]
//! covers the responses no handler produces — rate limiting, unrouted
//! methods, and unknown endpoints.

use axum::{
    Json,
    extract::{
        FromRequest, FromRequestParts, Query, Request,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode, header, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;

use super::types::ScimError;

/// Largest non-JSON error body carried into a SCIM `detail`. Rejection
/// messages are one line; anything longer is not a message worth relaying.
const MAX_DETAIL_BYTES: usize = 4096;

/// A SCIM request body, deserialized as `Json<T>` would be.
pub(crate) struct ScimJson<T>(pub T);

impl<S, T> FromRequest<S> for ScimJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<ScimError>);

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(json_rejection_response(&rejection)),
        }
    }
}

/// Maps a JSON body rejection onto its SCIM error (RFC 7644 §3.12).
///
/// A body that is valid JSON but does not fit the resource schema — a missing
/// required attribute, a wrong type — is 400 `invalidValue`; one that is not
/// JSON at all is 400 `invalidSyntax`. Axum answers the first with 422, which
/// §3.12 does not list. Content-type and body-size failures keep their status.
fn json_rejection_response(rejection: &JsonRejection) -> (StatusCode, Json<ScimError>) {
    let (status, scim_type) = match rejection {
        JsonRejection::JsonDataError(_) => (StatusCode::BAD_REQUEST, Some("invalidValue")),
        JsonRejection::JsonSyntaxError(_) => (StatusCode::BAD_REQUEST, Some("invalidSyntax")),
        // `JsonRejection` is `#[non_exhaustive]`, so a wildcard is required.
        _ => (rejection.status(), None),
    };
    scim_error(status, rejection.body_text(), scim_type)
}

/// SCIM list query parameters, deserialized as `Query<T>` would be.
pub(crate) struct ScimQuery<T>(pub T);

impl<S, T> FromRequestParts<S> for ScimQuery<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<ScimError>);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(value)) => Ok(Self(value)),
            Err(rejection) => Err(query_rejection_response(&rejection)),
        }
    }
}

/// Maps a query-string rejection onto 400 `invalidValue`, which RFC 7644
/// §3.12 Table 9 lists for GET (Section 3.4.2): a parameter such as
/// `startIndex=abc` is not compatible with the parameter's type.
fn query_rejection_response(rejection: &QueryRejection) -> (StatusCode, Json<ScimError>) {
    scim_error(
        StatusCode::BAD_REQUEST,
        rejection.body_text(),
        Some("invalidValue"),
    )
}

fn scim_error(
    status: StatusCode,
    detail: String,
    scim_type: Option<&str>,
) -> (StatusCode, Json<ScimError>) {
    let error = ScimError::new(status.as_u16(), detail);
    let error = match scim_type {
        Some(scim_type) => error.with_type(scim_type),
        None => error,
    };
    (status, Json(error))
}

/// `ANY /scim/v2/{*path}` — an endpoint the SCIM API does not define.
///
/// RFC 7644 §3.12: 404 is "Specified resource (e.g., User) or endpoint does
/// not exist."
pub(crate) async fn unknown_endpoint() -> (StatusCode, Json<ScimError>) {
    (
        StatusCode::NOT_FOUND,
        Json(ScimError::new(404, "Endpoint not found")),
    )
}

/// Gives an error response produced outside a SCIM handler a SCIM error body.
///
/// RFC 7644 §3.12 requires the JSON error body on every error, but the rate
/// limiter and the method router answer before any handler runs, in plain
/// text or with no body. Error responses that are already JSON pass through;
/// the rest keep their status and headers (`Retry-After`, `Allow`) and carry
/// their text, or the status reason when there is none, as `detail`.
pub(crate) async fn scim_error_body(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    let status = response.status();
    if !(status.is_client_error() || status.is_server_error()) || is_json(response.headers()) {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    let detail = match axum::body::to_bytes(body, MAX_DETAIL_BYTES).await {
        Ok(bytes) if !bytes.trim_ascii().is_empty() => String::from_utf8_lossy(&bytes).into_owned(),
        Ok(_) | Err(_) => status.canonical_reason().unwrap_or_default().to_string(),
    };
    parts.headers.remove(header::CONTENT_TYPE);
    parts.headers.remove(header::CONTENT_LENGTH);
    (parts, Json(ScimError::new(status.as_u16(), detail))).into_response()
}

/// Whether the response declares a JSON media type (`application/json` or a
/// `+json` suffix such as `application/scim+json`).
fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|essence| {
            let essence = essence.trim();
            essence.eq_ignore_ascii_case("application/json")
                || essence
                    .rsplit_once('+')
                    .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("json"))
        })
}
