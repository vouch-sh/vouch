// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Prometheus metrics endpoint and HTTP request instrumentation.
//!
//! Exposes a `/metrics` endpoint in Prometheus text format and provides
//! middleware for automatic HTTP request duration and count tracking.
//! The endpoint is gated behind a bearer token for security.
//!
//! Every label value this module emits is drawn from a finite set, which is
//! what bounds the number of Prometheus series the recorder holds. Nothing
//! here is installed with an idle timeout, so a series that is created is
//! never evicted; a label built from request data would therefore grow without
//! limit. New metrics belong in this module so that property stays checkable
//! in one place.

use std::sync::Arc;

use axum::extract::MatchedPath;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;

/// State for the authenticated metrics endpoint.
pub struct MetricsState {
    pub handle: PrometheusHandle,
    pub bearer_token: SecretString,
}

/// The one process-global recorder. The `metrics` crate allows a single
/// global recorder per process, so the handle is installed once and shared
/// by every later caller (server rebuilds, tests in one binary).
static RECORDER: std::sync::LazyLock<
    Result<PrometheusHandle, metrics_exporter_prometheus::BuildError>,
> = std::sync::LazyLock::new(|| PrometheusBuilder::new().install_recorder());

/// Install the Prometheus metrics recorder and return a handle for rendering.
///
/// Idempotent: the first call installs the recorder; later calls return a
/// clone of the same handle.
///
/// # Errors
///
/// Returns an error if the global recorder was already installed outside this
/// function, in which case no renderable handle exists.
pub fn install_recorder()
-> Result<PrometheusHandle, &'static metrics_exporter_prometheus::BuildError> {
    RECORDER.as_ref().map(Clone::clone)
}

/// Extract the bearer token from an `Authorization` header value.
fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let token = crate::http::bearer_token(headers)?;
    if token.is_empty() {
        return None;
    }
    Some(token)
}

/// Axum handler that validates a bearer token before rendering metrics.
///
/// Returns 401 if the token is missing or invalid (constant-time comparison).
pub async fn authenticated_metrics_handler(
    axum::extract::State(state): axum::extract::State<Arc<MetricsState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(provided) = extract_bearer_token(&headers) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };

    let expected = state.bearer_token.expose_secret().as_bytes();
    let provided_bytes = provided.as_bytes();

    if expected.ct_eq(provided_bytes).into() {
        state.handle.render().into_response()
    } else {
        (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
    }
}

/// `path` label for a request that matched no route.
///
/// `MatchedPath` is absent on a 404, and the request target is chosen by the
/// caller. Recording it verbatim would let any client mint an unbounded number
/// of Prometheus series. No route template can collide with this value because
/// every template begins with `/`.
const UNMATCHED_PATH_LABEL: &str = "<unmatched>";

/// `method` label for a request method outside the standard set.
///
/// RFC 9110 Section 9.1 defines the grammar as `method = token`, so any token
/// is a syntactically valid method, and `http::Method` accepts arbitrary
/// extension tokens (heap-allocating past its inline capacity). The method is
/// therefore caller-controlled in exactly the way the request target is.
const OTHER_METHOD_LABEL: &str = "OTHER";

/// Map an HTTP method onto a bounded set of Prometheus label values.
///
/// The nine methods registered by RFC 9110 pass through unchanged; every other
/// token folds into [`OTHER_METHOD_LABEL`]. The wildcard arm is load-bearing
/// rather than a stand-in for unhandled cases: the input domain is unbounded
/// strings, and collapsing it is the point.
fn metrics_method_label(method: &Method) -> &'static str {
    match method.as_str() {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "CONNECT" => "CONNECT",
        "OPTIONS" => "OPTIONS",
        "TRACE" => "TRACE",
        "PATCH" => "PATCH",
        _ => OTHER_METHOD_LABEL,
    }
}

/// Middleware that records HTTP request metrics (counter + duration histogram).
///
/// Every label value is drawn from a finite set — a route template or
/// [`UNMATCHED_PATH_LABEL`] for `path`, [`metrics_method_label`] for `method`,
/// and a status code for `status` — so the series count has a ceiling that no
/// request can raise.
///
/// `router::build_app` applies this OUTSIDE the request `TimeoutLayer` so that
/// timed-out requests are still recorded; see the ordering note there.
pub async fn metrics_middleware(req: Request<axum::body::Body>, next: Next) -> impl IntoResponse {
    let method = metrics_method_label(req.method()).to_owned();
    let path = req.extensions().get::<MatchedPath>().map_or_else(
        || UNMATCHED_PATH_LABEL.to_owned(),
        |p| p.as_str().to_string(),
    );
    let start = std::time::Instant::now();

    let response = next.run(req).await;

    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();
    let labels = [("method", method), ("path", path), ("status", status)];
    metrics::counter!("http_requests_total", &labels).increment(1);
    metrics::histogram!("http_request_duration_seconds", &labels[..2]).record(duration);

    response
}

/// Record an authentication event (login success, login failure, etc.).
pub fn record_auth_event(event_type: &str) {
    metrics::counter!(
        "vouch_auth_events_total",
        "event_type" => event_type.to_string()
    )
    .increment(1);
}

/// Record a credential issuance event (ssh, aws, oidc, github).
pub fn record_credential_issuance(credential_type: &str) {
    metrics::counter!(
        "vouch_credential_issuance_total",
        "type" => credential_type.to_string()
    )
    .increment(1);
}

/// Record a posture/temporal policy decision. `policy` is the denying
/// policy's slug (or "custom" / "unattributed"); "none" for allows.
pub fn record_policy_decision(outcome: &str, policy: &str) {
    metrics::counter!(
        "vouch_policy_decisions_total",
        "outcome" => outcome.to_string(),
        "policy" => policy.to_string()
    )
    .increment(1);
}

/// Record how long a policy decision took. Split by whether the org's set
/// reads event history: only those decisions pay the audit query and
/// replay, whose cost grows with the user's recent activity.
pub fn record_policy_decision_duration(seconds: f64, temporal: bool) {
    metrics::histogram!(
        "vouch_policy_decision_duration_seconds",
        "temporal" => if temporal { "true" } else { "false" }
    )
    .record(seconds);
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    use axum::Router;
    use axum::body::Body;
    use axum::routing::get;
    use tower::ServiceExt;

    /// The nine standard methods label as themselves and every other token
    /// collapses to one value, so the `method` label has a finite range. See
    /// [`OTHER_METHOD_LABEL`] for why an arbitrary token can arrive here.
    ///
    /// This pins label cardinality, not HTTP method semantics: it makes no
    /// claim about which status code an unrecognized method earns.
    #[test]
    fn metrics_method_label_admits_only_the_standard_methods() {
        for standard in [
            "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
        ] {
            let method = Method::from_bytes(standard.as_bytes()).expect("standard method");
            assert_eq!(
                metrics_method_label(&method),
                standard,
                "{standard} is registered by RFC 9110 and must label as itself"
            );
        }

        // Extension tokens, including one past `InlineExtension`'s capacity so
        // the heap-allocated representation is covered too.
        for extension in [
            "FROBNICATE",
            "get",
            "Get",
            "M-SEARCH",
            "AVERYLONGEXTENSIONMETHODNAMEWELLPASTTHEINLINECAPACITY",
        ] {
            let method = Method::from_bytes(extension.as_bytes()).expect("valid token");
            assert_eq!(
                metrics_method_label(&method),
                OTHER_METHOD_LABEL,
                "{extension} is an extension token and must not reach a metric label"
            );
        }
    }

    /// The `path` and `method` labels on `http_requests_total` are copied into
    /// a Prometheus series key, so echoing caller-supplied values lets any
    /// client allocate unbounded series and exhaust server memory. `path` must
    /// collapse to `<unmatched>` when no route matched, and `method` to
    /// `OTHER` for any non-standard token.
    ///
    /// Asserts on the absence of the caller's tokens rather than on a series
    /// count, so it stays correct alongside other tests sharing the
    /// process-global recorder.
    #[tokio::test]
    async fn metrics_labels_do_not_echo_caller_input() {
        let handle = install_recorder().expect("prometheus recorder");

        let router = Router::new()
            .route("/label-cardinality-probe", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(metrics_middleware));

        // Unmatched targets: each one would previously become its own series.
        let unmatched: Vec<String> = (0..25)
            .map(|i| format!("/no-such-route-cardinality-{i}"))
            .collect();
        for target in &unmatched {
            let req = Request::builder()
                .method("GET")
                .uri(target.as_str())
                .body(Body::empty())
                .expect("valid request");
            let resp = router.clone().oneshot(req).await.expect("oneshot succeeds");
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "{target} must not match a route"
            );
        }

        // Extension methods against a MATCHED route: this vector never yields a
        // 404, so bounding `path` alone would leave it open.
        let extensions: Vec<String> = (0..25)
            .map(|i| format!("FROBNICATECARDINALITY{i}"))
            .collect();
        for extension in &extensions {
            let req = Request::builder()
                .method(extension.as_str())
                .uri("/label-cardinality-probe")
                .body(Body::empty())
                .expect("valid request");
            let resp = router.clone().oneshot(req).await.expect("oneshot succeeds");
            assert_eq!(
                resp.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{extension} must not match a method route"
            );
        }

        let text = handle.render();

        for target in &unmatched {
            assert!(
                !text.contains(target.as_str()),
                "unmatched target {target} must not reach a metric label; got:\n{text}"
            );
        }
        for extension in &extensions {
            assert!(
                !text.contains(extension.as_str()),
                "extension method {extension} must not reach a metric label; got:\n{text}"
            );
        }
        assert!(
            text.contains(r#"path="<unmatched>""#),
            "unmatched requests must collapse to a single path label; got:\n{text}"
        );
        assert!(
            text.contains(r#"method="OTHER""#),
            "extension methods must collapse to a single method label; got:\n{text}"
        );
    }

    fn headers_with_auth(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", value.parse().expect("valid header value"));
        headers
    }

    /// RFC 9110 Section 11.1: the auth-scheme token is case-insensitive, so
    /// `BEARER`, `bearer`, and `BeArEr` must all match like `Bearer`.
    #[test]
    fn extract_bearer_token_accepts_scheme_case_variants() {
        for scheme in ["Bearer", "BEARER", "bearer", "BeArEr"] {
            let headers = headers_with_auth(&format!("{scheme} tok"));
            assert_eq!(
                extract_bearer_token(&headers),
                Some("tok"),
                "{scheme} scheme must be accepted (RFC 9110 case-insensitivity)"
            );
        }
    }

    #[test]
    fn extract_bearer_token_rejects_unrecognized_scheme() {
        for value in ["Basic dXNlcjpwYXNz", "DPoP tok", "Beareralone"] {
            assert_eq!(extract_bearer_token(&headers_with_auth(value)), None);
        }
    }

    #[test]
    fn extract_bearer_token_rejects_empty_token_and_missing_header() {
        assert_eq!(extract_bearer_token(&headers_with_auth("Bearer ")), None);
        assert_eq!(extract_bearer_token(&HeaderMap::new()), None);
    }
}
