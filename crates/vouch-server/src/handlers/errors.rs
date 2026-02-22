// SPDX-License-Identifier: BUSL-1.1
//! Error response helpers for HTTP handlers.

use axum::Json;
use axum::http::StatusCode;
use vouch_common::ApiError;

/// JSON error response helper.
///
/// Creates a standardized error response tuple suitable for returning from
/// handlers that have `Result<T, (StatusCode, Json<ApiError>)>` return types.
pub fn json_error(status: StatusCode, code: &str, message: &str) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError::new(code, message)))
}
