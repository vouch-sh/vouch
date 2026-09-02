// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HTTP request extractors for authentication context.

use std::sync::Arc;

use axum::extract::rejection::PathRejection;
use axum::extract::{FromRequest, FromRequestParts, Path};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use http::request::Parts;
use serde::Deserialize;

use crate::AppState;
use crate::db;
use crate::db::ClientInfo;
use crate::error::ServiceError;
use crate::handlers::session::extract_org_admin;
use crate::infra::rate_limit::resolve_client_ip;
use axum_extra::extract::cookie::CookieJar;

/// A validated UUID string. Rejects during deserialization if not valid.
/// Derefs to `&str` so it can be passed directly to db functions.
/// Normalizes to lowercase (UUIDs are case-insensitive per RFC 9562).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidUuid(String);

impl std::ops::Deref for ValidUuid {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ValidUuid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ValidUuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ValidUuid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let parsed = uuid::Uuid::try_parse(&s)
            .map_err(|_| serde::de::Error::custom("invalid UUID format"))?;
        Ok(Self(parsed.to_string()))
    }
}

/// Path extractor that converts `PathRejection` into `ServiceError`.
/// Use instead of `axum::extract::Path` when the handler returns `ServiceError`.
pub(crate) struct ValidPath<T>(pub T);

impl<T, S> FromRequestParts<S> for ValidPath<T>
where
    T: serde::de::DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = ServiceError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Path::<T>::from_request_parts(parts, state).await {
            Ok(Path(value)) => Ok(Self(value)),
            Err(rejection) => {
                let message = match rejection {
                    PathRejection::FailedToDeserializePathParams(e) => e.body_text(),
                    PathRejection::MissingPathParams(_) => "Missing path parameters".to_string(),
                    _ => "Invalid path parameters".to_string(),
                };
                Err(ServiceError::api(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    message,
                ))
            }
        }
    }
}

/// JSON body extractor that converts `JsonRejection` into `ServiceError`.
/// Use instead of [`axum::Json`] when the handler returns `ServiceError` and
/// the caller reads the error out of the JSON envelope.
///
/// Axum's own rejection answers with a `text/plain` body, which the browser
/// WebAuthn flows cannot read — they surface `errResp.message` from the JSON.
/// Body-typed validation (a `credential_id` that is not base64url, a field of
/// the wrong JSON type) lands here rather than in the handler, so this keeps
/// the shape of the response the same either way.
pub(crate) struct ValidJson<T>(pub T);

impl<T, S> FromRequest<S> for ValidJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ServiceError;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(ServiceError::api(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                rejection.body_text(),
            )),
        }
    }
}

/// Deserialize form-encoded parameters with the empty-valued ones dropped.
///
/// RFC 6749 §3.1 (authorization endpoint) and §3.2 (token endpoint) carry the
/// same paragraph:
///
/// > Parameters sent without a value MUST be treated as if they were omitted
/// > from the request. The authorization server MUST ignore unrecognized
/// > request parameters. Request and response parameters MUST NOT be included
/// > more than once.
///
/// Dropping the empty-valued pairs before deserialization is what makes
/// `scope=` and an omitted `scope` arrive as the same `None`. Unrecognized
/// parameters are ignored by `T`'s derived deserializer, which also rejects a
/// repeated recognized one — RFC 6749 §5.2 defines `invalid_request` as
/// covering a request that "includes a parameter more than once". A repeated
/// *unrecognized* parameter stays ignored, since the sentence before it
/// requires exactly that.
fn deserialize_present_params<T: serde::de::DeserializeOwned>(encoded: &[u8]) -> Result<T, String> {
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_bytes(encoded).map_err(|e| e.to_string())?;
    let present: Vec<(String, String)> = pairs.into_iter().filter(|(_, v)| !v.is_empty()).collect();
    let reencoded = serde_urlencoded::to_string(&present).map_err(|e| e.to_string())?;
    serde_urlencoded::from_str::<T>(&reencoded).map_err(|e| e.to_string())
}

/// Build the OAuth `invalid_request` envelope (RFC 6749 §5.2) for a request
/// whose parameters could not be read.
fn reject_oauth_params(description: String) -> axum::response::Response {
    ServiceError::oauth(crate::error::OAuthErrorCode::InvalidRequest, description)
        .into_oauth_response()
        .into_response()
}

/// Form-body extractor for the OAuth endpoints, applying the RFC 6749 §3.2
/// parameter rules that `axum::Form` does not — see
/// [`deserialize_present_params`].
///
/// Rejections carry the OAuth error envelope rather than axum's `text/plain`
/// body, so a client parsing `error`/`error_description` reads a malformed
/// request the same way it reads every other failure.
pub(crate) struct OAuthForm<T>(pub T);

impl<T, S> FromRequest<S> for OAuthForm<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = axum::response::Response;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        // RFC 6749 §4.1.3: request parameters are sent "in the HTTP request
        // entity-body using the application/x-www-form-urlencoded format".
        // Any other media type is unsupported rather than malformed.
        let is_form = req
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                // The media type may carry parameters (`; charset=utf-8`).
                let media_type = v.split(';').next().unwrap_or(v).trim();
                media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded")
            });
        if !is_form {
            return Err((
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                axum::Json(crate::error::OAuthErrorResponse {
                    error: crate::error::OAuthErrorCode::InvalidRequest
                        .as_str()
                        .to_string(),
                    error_description: Some(
                        "Expected application/x-www-form-urlencoded request body".to_string(),
                    ),
                    error_uri: None,
                }),
            )
                .into_response());
        }

        let body = axum::body::Bytes::from_request(req, state)
            .await
            .map_err(|e| reject_oauth_params(e.body_text()))?;

        deserialize_present_params(&body)
            .map(Self)
            .map_err(reject_oauth_params)
    }
}

/// Query-string extractor for the OAuth endpoints, applying the RFC 6749 §3.1
/// parameter rules that `axum::extract::Query` does not — see
/// [`deserialize_present_params`]. The authorization endpoint's counterpart to
/// [`OAuthForm`].
pub(crate) struct OAuthQuery<T>(pub T);

impl<T, S> FromRequestParts<S> for OAuthQuery<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = axum::response::Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let query = parts.uri.query().unwrap_or_default();
        deserialize_present_params(query.as_bytes())
            .map(Self)
            .map_err(reject_oauth_params)
    }
}

/// Maximum length for hostname values (RFC 1035: 253 chars).
const MAX_HOSTNAME_LEN: usize = 253;
/// Maximum length for other client metadata header values.
const MAX_CLIENT_HEADER_LEN: usize = 256;

impl FromRequestParts<Arc<AppState>> for ClientInfo {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let peer_ip = parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip().to_canonical());

        let config = state.config.load();
        let client_ip = resolve_client_ip(peer_ip, &parts.headers, &config.trusted_proxies);

        let mut info = Self::from(&parts.headers);
        info.client_ip = client_ip;
        Ok(info)
    }
}

impl From<&HeaderMap> for ClientInfo {
    fn from(headers: &HeaderMap) -> Self {
        let user_agent = headers
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .map(String::from);

        let client_hostname =
            extract_validated_header(headers, "vouch-client-hostname", MAX_HOSTNAME_LEN);
        let client_os = extract_validated_header(headers, "vouch-client-os", MAX_CLIENT_HEADER_LEN);
        let client_arch =
            extract_validated_header(headers, "vouch-client-arch", MAX_CLIENT_HEADER_LEN);
        let client_version =
            extract_validated_header(headers, "vouch-client-version", MAX_CLIENT_HEADER_LEN);

        Self {
            client_ip: None,
            user_agent,
            client_hostname,
            client_os,
            client_arch,
            client_version,
        }
    }
}

/// Extract and validate a client metadata header value.
///
/// Returns `None` if the header is missing, empty, exceeds `max_len`,
/// or contains non-printable ASCII characters (control chars, null bytes).
fn extract_validated_header(headers: &HeaderMap, name: &str, max_len: usize) -> Option<String> {
    let value = headers.get(name).and_then(|h| h.to_str().ok())?;
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > max_len {
        return None;
    }
    if !trimmed.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return None;
    }
    Some(trimmed.to_string())
}

/// Optional client certificate extracted from mTLS connection.
///
/// Reads the certificate from [`PeerClientCert`] injected via
/// [`axum::extract::ConnectInfo`] when the request arrives on the mTLS
/// port (direct TLS handshake).
///
/// On the main (non-mTLS) port this always yields `None`.
#[derive(Debug, Clone)]
pub(crate) struct OptionalClientCert(pub Option<crate::services::oidc::mtls::ClientCertificate>);

impl FromRequestParts<Arc<AppState>> for OptionalClientCert {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let from_tls = parts
            .extensions
            .get::<axum::extract::ConnectInfo<crate::infra::mtls_listener::PeerClientCert>>()
            .and_then(|ci| ci.0.0.as_ref())
            .and_then(|der| crate::services::oidc::mtls::parse_client_certificate(der).ok());

        Ok(Self(from_tls))
    }
}

/// An organization administrator holding a hardware-verified session.
///
/// The proof is the type: a handler that mutates org-wide state takes
/// `OrgAdmin` in its signature and cannot run without the admin-role and
/// key-ceremony checks in [`extract_org_admin`] — the same reasoning
/// [`super::session::HardwareVerifiedToken`] applies to credential issuance.
pub(crate) struct OrgAdmin {
    /// The administrator's user record (active, org member, admin).
    pub(crate) user: db::User,
    /// The organization the administrator belongs to.
    pub(crate) org_id: String,
}

impl axum::extract::FromRequestParts<Arc<AppState>> for OrgAdmin {
    type Rejection = ServiceError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let axum::extract::OriginalUri(uri) =
            axum::extract::OriginalUri::from_request_parts(parts, state)
                .await
                .unwrap_or_else(|infallible| match infallible {});
        let client_cert = OptionalClientCert::from_request_parts(parts, state)
            .await
            .unwrap_or_else(|infallible| match infallible {});
        let jar = CookieJar::from_headers(&parts.headers);
        let (user, org_id) = extract_org_admin(
            state,
            &parts.headers,
            &jar,
            parts.method.as_str(),
            uri.path(),
            client_cert.0.as_ref(),
        )
        .await?;
        Ok(Self { user, org_id })
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // ========================================================================
    // ClientInfo Header Extraction Tests
    // ========================================================================

    #[test]
    fn test_extract_user_agent() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            HeaderValue::from_static("vouch-cli/0.1.0 (macos; aarch64)"),
        );

        let info = ClientInfo::from(&headers);
        assert_eq!(
            info.user_agent,
            Some("vouch-cli/0.1.0 (macos; aarch64)".to_string())
        );
    }

    #[test]
    fn test_extract_no_headers() {
        let headers = HeaderMap::new();
        let info = ClientInfo::from(&headers);
        assert_eq!(info.client_ip, None);
        assert_eq!(info.user_agent, None);
        assert_eq!(info.client_hostname, None);
        assert_eq!(info.client_os, None);
        assert_eq!(info.client_arch, None);
        assert_eq!(info.client_version, None);
    }

    // ========================================================================
    // Vouch-Client-* Header Extraction Tests
    // ========================================================================

    #[test]
    fn test_extract_vouch_client_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "vouch-client-hostname",
            HeaderValue::from_static("dev.local"),
        );
        headers.insert("vouch-client-os", HeaderValue::from_static("macos"));
        headers.insert("vouch-client-arch", HeaderValue::from_static("aarch64"));
        headers.insert("vouch-client-version", HeaderValue::from_static("1.2.3"));

        let info = ClientInfo::from(&headers);
        assert_eq!(info.client_hostname.as_deref(), Some("dev.local"));
        assert_eq!(info.client_os.as_deref(), Some("macos"));
        assert_eq!(info.client_arch.as_deref(), Some("aarch64"));
        assert_eq!(info.client_version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn test_extract_vouch_client_header_rejects_too_long() {
        let mut headers = HeaderMap::new();
        let long_value = "a".repeat(MAX_CLIENT_HEADER_LEN + 1);
        headers.insert(
            "vouch-client-os",
            HeaderValue::from_str(&long_value).unwrap(),
        );

        let info = ClientInfo::from(&headers);
        assert_eq!(info.client_os, None);
    }

    #[test]
    fn test_extract_vouch_client_header_rejects_empty() {
        let mut headers = HeaderMap::new();
        headers.insert("vouch-client-os", HeaderValue::from_static(""));

        let info = ClientInfo::from(&headers);
        assert_eq!(info.client_os, None);
    }

    #[test]
    fn test_extract_vouch_client_header_trims_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert("vouch-client-os", HeaderValue::from_static("  macos  "));

        let info = ClientInfo::from(&headers);
        assert_eq!(info.client_os.as_deref(), Some("macos"));
    }

    #[test]
    fn test_extract_vouch_client_hostname_max_length() {
        let mut headers = HeaderMap::new();
        // Exactly at the 253-char limit should be accepted
        let hostname = "a".repeat(MAX_HOSTNAME_LEN);
        headers.insert(
            "vouch-client-hostname",
            HeaderValue::from_str(&hostname).unwrap(),
        );
        let info = ClientInfo::from(&headers);
        assert_eq!(info.client_hostname.as_deref(), Some(hostname.as_str()));

        // One over should be rejected
        let too_long = "a".repeat(MAX_HOSTNAME_LEN + 1);
        let mut headers2 = HeaderMap::new();
        headers2.insert(
            "vouch-client-hostname",
            HeaderValue::from_str(&too_long).unwrap(),
        );
        let info2 = ClientInfo::from(&headers2);
        assert_eq!(info2.client_hostname, None);
    }

    #[test]
    fn test_extract_validated_header_rejects_control_chars() {
        let mut headers = HeaderMap::new();
        // Tab character (0x09) is a control character
        headers.insert(
            "vouch-client-os",
            HeaderValue::from_bytes(b"mac\tos").unwrap(),
        );

        let info = ClientInfo::from(&headers);
        assert_eq!(info.client_os, None);
    }

    #[test]
    fn test_extract_validated_header_accepts_printable_ascii() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "vouch-client-version",
            HeaderValue::from_static("1.2.3-beta+build.456"),
        );

        let info = ClientInfo::from(&headers);
        assert_eq!(info.client_version.as_deref(), Some("1.2.3-beta+build.456"));
    }

    #[test]
    fn test_valid_uuid_accepts_valid() {
        let json = "\"019508a7-cc17-7a7c-a00b-632964b2750e\"";
        let uuid: ValidUuid = serde_json::from_str(json).unwrap();
        assert_eq!(&*uuid, "019508a7-cc17-7a7c-a00b-632964b2750e");
    }

    #[test]
    fn test_valid_uuid_normalizes_uppercase() {
        let json = "\"019508A7-CC17-7A7C-A00B-632964B2750E\"";
        let uuid: ValidUuid = serde_json::from_str(json).unwrap();
        assert_eq!(&*uuid, "019508a7-cc17-7a7c-a00b-632964b2750e");
    }

    #[test]
    fn test_valid_uuid_rejects_invalid() {
        let json = "\"not-a-uuid\"";
        let result: Result<ValidUuid, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_uuid_rejects_empty() {
        let json = "\"\"";
        let result: Result<ValidUuid, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_uuid_display() {
        let json = "\"019508a7-cc17-7a7c-a00b-632964b2750e\"";
        let uuid: ValidUuid = serde_json::from_str(json).unwrap();
        assert_eq!(format!("{uuid}"), "019508a7-cc17-7a7c-a00b-632964b2750e");
    }

    #[test]
    fn test_valid_uuid_as_ref() {
        let json = "\"019508a7-cc17-7a7c-a00b-632964b2750e\"";
        let uuid: ValidUuid = serde_json::from_str(json).unwrap();
        let s: &str = uuid.as_ref();
        assert_eq!(s, "019508a7-cc17-7a7c-a00b-632964b2750e");
    }

    #[test]
    fn test_valid_uuid_accepts_v4() {
        // UUID v4 (random) format is valid
        let json = "\"550e8400-e29b-41d4-a716-446655440000\"";
        let result: Result<ValidUuid, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        assert_eq!(&*result.unwrap(), "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_valid_uuid_accepts_compact_no_hyphens() {
        // The uuid crate accepts compact format (no hyphens) and normalizes it
        let json = "\"019508a7cc177a7ca00b632964b2750e\"";
        let result: Result<ValidUuid, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        // uuid crate normalizes to hyphenated lowercase
        assert_eq!(&*result.unwrap(), "019508a7-cc17-7a7c-a00b-632964b2750e");
    }

    #[test]
    fn test_valid_uuid_accepts_null_uuid() {
        // Nil UUID is syntactically valid
        let json = "\"00000000-0000-0000-0000-000000000000\"";
        let result: Result<ValidUuid, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        assert_eq!(&*result.unwrap(), "00000000-0000-0000-0000-000000000000");
    }

    // ========================================================================
    // OptionalClientCert Tests
    // ========================================================================

    /// When `PeerClientCert` contains invalid DER bytes, the `.ok()` in
    /// `from_request_parts` swallows the parse error and yields `None` rather
    /// than returning an error response. This keeps the extractor infallible.
    #[tokio::test]
    async fn test_optional_client_cert_with_invalid_der_returns_none() {
        use crate::infra::mtls_listener::PeerClientCert;
        use axum::extract::ConnectInfo;

        let mut request = http::Request::builder().body(()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(PeerClientCert(Some(vec![
                0xFF, 0xFF, 0xDE, 0xAD,
            ]))));
        let (parts, _) = request.into_parts();

        // OptionalClientCert::from_request_parts requires Arc<AppState>, but all it
        // does with _state is ignore it — the cert extraction only reads extensions.
        // We exercise the same code path by replicating the extractor logic inline,
        // which lets us verify the `.ok()` swallows the DER parse error.
        let cert = parts
            .extensions
            .get::<ConnectInfo<PeerClientCert>>()
            .and_then(|ci| ci.0.0.as_ref())
            .and_then(|der| crate::services::oidc::mtls::parse_client_certificate(der).ok());

        assert!(
            cert.is_none(),
            "Invalid DER must yield None, not an error or panic"
        );
    }

    /// When no `PeerClientCert` extension is present (non-mTLS connection),
    /// the extractor must yield `None` without panicking.
    #[tokio::test]
    async fn test_optional_client_cert_no_extension_returns_none() {
        use crate::infra::mtls_listener::PeerClientCert;
        use axum::extract::ConnectInfo;

        let request = http::Request::builder().body(()).unwrap();
        let (parts, _) = request.into_parts();

        let cert = parts
            .extensions
            .get::<ConnectInfo<PeerClientCert>>()
            .and_then(|ci| ci.0.0.as_ref())
            .and_then(|der| crate::services::oidc::mtls::parse_client_certificate(der).ok());

        assert!(cert.is_none(), "Missing extension must yield None");
    }

    /// When `PeerClientCert` wraps `None` (client connected but presented no cert),
    /// the extractor must yield `None` without panicking.
    #[tokio::test]
    async fn test_optional_client_cert_with_none_der_returns_none() {
        use crate::infra::mtls_listener::PeerClientCert;
        use axum::extract::ConnectInfo;

        let mut request = http::Request::builder().body(()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(PeerClientCert(None)));
        let (parts, _) = request.into_parts();

        let cert = parts
            .extensions
            .get::<ConnectInfo<PeerClientCert>>()
            .and_then(|ci| ci.0.0.as_ref())
            .and_then(|der| crate::services::oidc::mtls::parse_client_certificate(der).ok());

        assert!(cert.is_none(), "PeerClientCert(None) must yield None");
    }

    #[test]
    fn test_valid_uuid_rejects_wrong_segment_count() {
        // Too few segments to be a UUID
        let json = "\"not-valid\"";
        let result: Result<ValidUuid, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_uuid_rejects_wrong_length() {
        // Correct hyphen positions but wrong total length (one char short)
        let json = "\"019508a7-cc17-7a7c-a00b-632964b2750\"";
        let result: Result<ValidUuid, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_uuid_rejects_non_hex_chars() {
        // UUID-shaped but contains non-hex characters
        let json = "\"zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz\"";
        let result: Result<ValidUuid, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_uuid_output_is_always_hyphenated_lowercase() {
        // Compact input normalizes to canonical hyphenated form
        let compact = "\"019508a7cc177a7ca00b632964b2750e\"";
        let uuid: ValidUuid = serde_json::from_str(compact).unwrap();
        let output = uuid.to_string();
        // Must contain hyphens
        assert!(output.contains('-'), "output must be hyphenated: {output}");
        // Must be lowercase
        assert_eq!(
            output,
            output.to_lowercase(),
            "output must be lowercase: {output}"
        );
    }
}

#[cfg(test)]
mod oauth_params_tests {
    #![expect(
        clippy::expect_used,
        reason = "test code: panic on assertion failure is acceptable"
    )]
    use super::deserialize_present_params;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Params {
        required: String,
        #[serde(default)]
        optional: Option<String>,
    }

    /// RFC 6749 §3.1/§3.2: "Parameters sent without a value MUST be treated as
    /// if they were omitted from the request."
    #[test]
    fn empty_valued_parameter_arrives_as_omitted() {
        let empty: Params =
            deserialize_present_params(b"required=r&optional=").expect("empty value is dropped");
        let omitted: Params = deserialize_present_params(b"required=r").expect("valid");
        assert_eq!(empty, omitted);
        assert_eq!(empty.optional, None);
    }

    /// The same rule applied to a REQUIRED parameter: emptying it makes the
    /// request one that is missing it, rather than one carrying an empty value.
    #[test]
    fn empty_required_parameter_is_missing_not_empty() {
        let err = deserialize_present_params::<Params>(b"required=&optional=o")
            .expect_err("an emptied REQUIRED parameter is a missing one");
        assert!(
            err.contains("required"),
            "the rejection must name the missing field, got: {err}"
        );
    }

    /// "The authorization server MUST ignore unrecognized request parameters."
    #[test]
    fn unrecognized_parameters_are_ignored() {
        let value: Params = deserialize_present_params(b"required=r&surprise=1&surprise=2")
            .expect("unrecognized parameters are ignored, repeated or not");
        assert_eq!(value.required, "r");
    }

    /// "Request and response parameters MUST NOT be included more than once."
    /// A repeated *recognized* parameter fails, which the callers report as
    /// `invalid_request` (RFC 6749 §5.2: "includes a parameter more than once").
    #[test]
    fn repeated_recognized_parameter_is_rejected() {
        let err = deserialize_present_params::<Params>(b"required=a&required=b")
            .expect_err("a repeated recognized parameter must not deserialize");
        assert!(
            err.contains("duplicate"),
            "expected a duplicate-field rejection, got: {err}"
        );
    }

    /// A value that is only *syntactically* empty after decoding still counts:
    /// `%20` is a space, not nothing, so it is a present value.
    #[test]
    fn whitespace_value_is_present() {
        let value: Params =
            deserialize_present_params(b"required=r&optional=%20").expect("a space is a value");
        assert_eq!(value.optional.as_deref(), Some(" "));
    }
}
