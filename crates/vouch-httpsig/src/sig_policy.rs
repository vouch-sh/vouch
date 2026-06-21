// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9421 signature-requirement policy for `/v1/*` routes.
//!
//! This module is the **single source of truth** for which vouch-server `/v1`
//! paths require an RFC 9421 HTTP Message Signature.  Both the CLI and the
//! server middleware consult it at runtime so the two never drift apart.
//!
//! ## Scoping
//!
//! The predicate is scoped to vouch-server traffic only.  The CLI also
//! constructs paths starting with `/v1` when talking to AWS endpoints (e.g.
//! CodeArtifact, CodeCommit) — those calls go through separate signing paths
//! (`sign_and_send_rest` / SigV4) and never reach `requires_signature`.
//!
//! ## Failure posture
//!
//! Within `/v1`, the default is **require** (deny by default).  A new protected
//! route is over-protected (loud / 401) rather than silently left unsigned.
//! Routes that must be publicly accessible are explicitly listed in
//! `PUBLIC_V1_PATHS`.
//!
//! ## Template matching
//!
//! `PUBLIC_V1_PATHS` contains route **templates** (e.g. `/v1/credentials/ssh/krl/{serial}`).
//! Both the CLI (which supplies **concrete** paths such as `/v1/credentials/ssh/krl/123`)
//! and the server (which supplies the axum `MatchedPath` template) are accepted as
//! inputs.  A `{…}` brace token on **either** side (pattern *or* input) matches any
//! single path segment and never crosses a `/` boundary.

/// Route templates that are publicly accessible without an RFC 9421 signature.
///
/// These five routes answer without authentication and must remain unsigned
/// so that the CLI, SSH agents, and third-party tooling can call them freely.
pub const PUBLIC_V1_PATHS: &[&str] = &[
    "/v1/auth/status",
    "/v1/credentials/ssh/ca",
    "/v1/credentials/ssh/krl",
    "/v1/credentials/ssh/krl/{serial}",
    "/v1/credentials/github/status",
];

/// Return `true` when a request to `path` must carry an RFC 9421 signature.
///
/// The predicate is **scoped to `/v1`**: any path that does not start with
/// `/v1/` or equal `/v1` is considered out of scope and returns `false`
/// (e.g. `/oauth/*`, `/health`, `/.well-known/*`).
///
/// Within `/v1`, every path is required **unless** it matches one of
/// [`PUBLIC_V1_PATHS`].  Matching is segment-exact: a `{…}` brace token on
/// either the pattern side or the input side matches any single path segment
/// and must not cross a `/` boundary (see [`path_matches`]).
///
/// # Examples
///
/// ```
/// use vouch_httpsig::sig_policy::requires_signature;
///
/// // Public routes — no signature needed
/// assert!(!requires_signature("/v1/auth/status"));
/// assert!(!requires_signature("/v1/credentials/ssh/ca"));
/// assert!(!requires_signature("/v1/credentials/ssh/krl/123"));
///
/// // Protected routes — signature required
/// assert!(requires_signature("/v1/keys"));
/// assert!(requires_signature("/v1/keys/abc"));
/// assert!(requires_signature("/v1/credentials/ssh"));
///
/// // Non-/v1 paths — out of scope
/// assert!(!requires_signature("/oauth/token"));
/// assert!(!requires_signature("/health"));
/// ```
#[must_use]
pub fn requires_signature(path: &str) -> bool {
    // Only /v1/* is in scope.
    if path != "/v1" && !path.starts_with("/v1/") {
        return false;
    }

    // Default-deny: require unless explicitly exempted.
    for &exempt in PUBLIC_V1_PATHS {
        if path_matches(exempt, path) {
            return false;
        }
    }
    true
}

/// Return `true` when `input` matches the route `pattern`.
///
/// Matching rules:
/// - Trailing slashes and empty segments are rejected in both pattern and input
///   (they indicate a malformed path and are always non-matching).
/// - Segment counts must be equal.
/// - Each segment pair is compared literally, **except** when either the pattern
///   segment or the input segment is a `{…}` brace token — in that case the
///   segment pair always matches.
///
/// The symmetric brace rule allows the server to pass the axum `MatchedPath`
/// template (e.g. `/v1/credentials/ssh/krl/{serial}`) where the last segment is
/// `{serial}`, and have it match the same `PUBLIC_V1_PATHS` entry which also has
/// `{serial}` in that position.  It also lets the CLI pass the concrete path
/// `/v1/credentials/ssh/krl/123`, which matches because `{serial}` is a wildcard.
#[must_use]
pub fn path_matches(pattern: &str, input: &str) -> bool {
    debug_assert!(pattern.starts_with('/'), "pattern must be an absolute path");
    debug_assert!(input.starts_with('/'), "input must be an absolute path");

    // Reject empty or trailing-slash paths.
    if pattern.is_empty() || input.is_empty() || pattern.ends_with('/') || input.ends_with('/') {
        return false;
    }

    let pat_segs: Vec<&str> = pattern.split('/').skip(1).collect();
    let inp_segs: Vec<&str> = input.split('/').skip(1).collect();

    // Reject paths with empty segments (e.g. double slashes).
    if pat_segs.iter().any(|s| s.is_empty()) || inp_segs.iter().any(|s| s.is_empty()) {
        return false;
    }

    if pat_segs.len() != inp_segs.len() {
        return false;
    }

    for (p, i) in pat_segs.iter().zip(inp_segs.iter()) {
        // A {…} brace token on either side matches any single segment.
        let pat_is_wildcard = p.starts_with('{') && p.ends_with('}');
        let inp_is_wildcard = i.starts_with('{') && i.ends_with('}');
        if !pat_is_wildcard && !inp_is_wildcard && p != i {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- path_matches unit tests ---

    #[test]
    fn test_exact_match() {
        assert!(path_matches("/v1/auth/status", "/v1/auth/status"));
    }

    #[test]
    fn test_pattern_wildcard_matches_concrete() {
        // Pattern has {serial}, input has concrete value — CLI use case.
        assert!(path_matches(
            "/v1/credentials/ssh/krl/{serial}",
            "/v1/credentials/ssh/krl/123"
        ));
    }

    #[test]
    fn test_template_as_input_matches_template_pattern() {
        // Server feeds MatchedPath which is already a template — critic S1.
        assert!(path_matches(
            "/v1/credentials/ssh/krl/{serial}",
            "/v1/credentials/ssh/krl/{serial}"
        ));
    }

    #[test]
    fn test_wildcard_does_not_cross_slash() {
        // {serial} must not match a path with fewer or more segments.
        assert!(!path_matches(
            "/v1/credentials/ssh/krl/{serial}",
            "/v1/credentials/ssh/krl"
        ));
        assert!(!path_matches(
            "/v1/credentials/ssh/krl/{serial}",
            "/v1/credentials/ssh/krl/123/extra"
        ));
    }

    #[test]
    fn test_input_wildcard_matches_pattern_literal() {
        // Symmetric: input has brace token, pattern is literal (uncommon but valid).
        assert!(path_matches("/v1/keys/abc", "/v1/keys/{id}"));
    }

    #[test]
    fn test_trailing_slash_rejected() {
        assert!(!path_matches("/v1/auth/status/", "/v1/auth/status"));
        assert!(!path_matches("/v1/auth/status", "/v1/auth/status/"));
    }

    #[test]
    fn test_empty_segment_rejected() {
        // Double slash produces an empty segment.
        assert!(!path_matches("/v1//auth", "/v1/auth/status"));
    }

    #[test]
    fn test_segment_count_mismatch() {
        assert!(!path_matches("/v1/auth", "/v1/auth/status"));
    }

    // --- requires_signature unit tests ---

    // Public routes must return false in BOTH template and concrete form (critic S1).

    #[test]
    fn test_auth_status_is_public() {
        // Concrete form (only one form for this route — no params).
        assert!(!requires_signature("/v1/auth/status"));
    }

    #[test]
    fn test_ssh_ca_is_public() {
        assert!(!requires_signature("/v1/credentials/ssh/ca"));
    }

    #[test]
    fn test_ssh_krl_is_public() {
        assert!(!requires_signature("/v1/credentials/ssh/krl"));
    }

    #[test]
    fn test_ssh_krl_serial_concrete_is_public() {
        // CLI passes concrete path.
        assert!(!requires_signature("/v1/credentials/ssh/krl/123"));
    }

    #[test]
    fn test_ssh_krl_serial_template_is_public() {
        // Server passes MatchedPath template — critic S1.
        assert!(!requires_signature("/v1/credentials/ssh/krl/{serial}"));
    }

    #[test]
    fn test_github_status_is_public() {
        assert!(!requires_signature("/v1/credentials/github/status"));
    }

    // Protected routes must return true in BOTH template and concrete form.

    #[test]
    fn test_keys_list_requires_signature() {
        assert!(requires_signature("/v1/keys"));
    }

    #[test]
    fn test_keys_id_concrete_requires_signature() {
        assert!(requires_signature("/v1/keys/abc"));
    }

    #[test]
    fn test_keys_id_template_requires_signature() {
        assert!(requires_signature("/v1/keys/{id}"));
    }

    #[test]
    fn test_keys_register_start_requires_signature() {
        assert!(requires_signature("/v1/keys/register/start"));
    }

    #[test]
    fn test_keys_register_complete_requires_signature() {
        assert!(requires_signature("/v1/keys/register/complete"));
    }

    #[test]
    fn test_ssh_credential_requires_signature() {
        assert!(requires_signature("/v1/credentials/ssh"));
    }

    #[test]
    fn test_aws_token_requires_signature() {
        assert!(requires_signature("/v1/credentials/aws/token"));
    }

    #[test]
    fn test_github_token_requires_signature() {
        assert!(requires_signature("/v1/credentials/github/token"));
    }

    // Non-/v1 paths are out of scope.

    #[test]
    fn test_oauth_token_out_of_scope() {
        assert!(!requires_signature("/oauth/token"));
    }

    #[test]
    fn test_health_out_of_scope() {
        assert!(!requires_signature("/health"));
    }

    #[test]
    fn test_root_out_of_scope() {
        assert!(!requires_signature("/"));
    }

    #[test]
    fn test_well_known_out_of_scope() {
        assert!(!requires_signature("/.well-known/openid-configuration"));
    }

    // Document the old client.rs:376 predicate's incorrect behavior on the
    // four routes it wrongly treated as requiring signatures.
    #[test]
    fn test_old_predicate_was_wrong_for_public_routes() {
        // The old code: path.starts_with("/v1/") && path != "/v1/auth/status"
        // This incorrectly required signatures for the following routes:
        let wrongly_required = [
            "/v1/credentials/ssh/ca",
            "/v1/credentials/ssh/krl",
            "/v1/credentials/ssh/krl/123",
            "/v1/credentials/github/status",
        ];
        for path in wrongly_required {
            let old_predicate = path.starts_with("/v1/") && path != "/v1/auth/status";
            assert!(
                old_predicate,
                "old predicate required sig for public path: {path}"
            );
            // New predicate correctly exempts them:
            assert!(
                !requires_signature(path),
                "new predicate correctly exempts: {path}"
            );
        }
    }
}
