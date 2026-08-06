// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS CodeCommit SigV4 credential signing.
//!
//! Generates SigV4-signed credentials for authenticating with AWS CodeCommit.
//! Used by both the git credential helper (`vouch credential codecommit`) and
//! the git remote helper (`git-remote-codecommit` symlink).
//!
//! The CodeCommit signing differs from standard SigV4 JSON-RPC calls:
//! - HTTP method is `GIT` (not `GET`/`POST`)
//! - Only the `host` header is signed
//! - The "password" is `{timestamp}Z{signature}` where timestamp has NO trailing Z
//!   (unlike standard SigV4 X-Amz-Date). The Z serves as a separator only.
//! - The "username" is `{access_key_id}%{session_token}` for temporary credentials

use secrecy::{ExposeSecret, SecretString};

use super::sigv4;
use super::sts::StsCredentials;

/// SigV4-signed credentials for CodeCommit.
pub(crate) struct CodeCommitCredentials {
    /// Username: `{access_key_id}%{session_token}` for temporary credentials.
    /// Stored as `SecretString` because it may contain the session token.
    pub username: SecretString,
    /// Password: `{YYYYMMDDTHHMMSSZ}{hex_signature}`.
    pub password: SecretString,
}

impl std::fmt::Debug for CodeCommitCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeCommitCredentials")
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Format timestamp for CodeCommit SigV4 signing (`YYYYMMDDTHHMMSS`, no trailing Z).
///
/// CodeCommit's SigV4 variant omits the trailing `Z` from the timestamp used in
/// the string-to-sign. This differs from standard SigV4 (which uses `YYYYMMDDTHHMMSSZ`).
///
/// In the AWS reference implementation (`git-remote-codecommit`), the timestamp is
/// stored in `request.context['timestamp']` using `strftime('%Y%m%dT%H%M%S')` (no Z):
///   <https://github.com/aws/git-remote-codecommit/blob/master/git_remote_codecommit/__init__.py>
///
/// botocore's `SigV4Auth.string_to_sign()` uses this value directly (no re-formatting):
///   <https://github.com/boto/botocore/blob/develop/botocore/auth.py>
///
/// The `Z` only appears as a separator between timestamp and signature in the
/// password output: `{timestamp}Z{hex_signature}`.
fn format_codecommit_timestamp(now: jiff::Timestamp) -> String {
    let dt = now.to_zoned(jiff::tz::TimeZone::UTC);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

/// Generate SigV4-signed credentials for a CodeCommit repository.
///
/// The signing uses the `GIT` HTTP method with only the `host` header,
/// matching the format expected by CodeCommit's authentication layer.
///
/// # Arguments
/// * `creds` - Temporary AWS credentials from STS
/// * `hostname` - CodeCommit hostname (e.g., `git-codecommit.us-east-1.amazonaws.com`)
/// * `path` - Repository path with leading slash (e.g., `/v1/repos/my-repo`)
/// * `region` - AWS region (e.g., `us-east-1`)
#[must_use]
pub(crate) fn sign_request(
    creds: &StsCredentials,
    hostname: &str,
    path: &str,
    region: &str,
) -> CodeCommitCredentials {
    let now = jiff::Timestamp::now();
    let timestamp = format_codecommit_timestamp(now);
    let date_stamp = sigv4::format_date_stamp(now);

    // Canonical request: GIT method, repository path, host-only header.
    // CodeCommit uses a non-standard SigV4 canonical request: no payload hash,
    // just a trailing newline after signed headers.
    // Ref: https://github.com/aws/git-remote-codecommit
    let canonical_headers = format!("host:{hostname}\n");
    let signed_headers = "host";

    let canonical_request = format!("GIT\n{path}\n\n{canonical_headers}\n{signed_headers}\n");

    let canonical_request_hash = sigv4::sha256_hex(canonical_request.as_bytes());

    // String to sign — uses timestamp WITHOUT trailing Z (CodeCommit-specific)
    let credential_scope = format!("{date_stamp}/{region}/codecommit/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{timestamp}\n{credential_scope}\n{canonical_request_hash}");

    // Sign
    let signing_key =
        sigv4::derive_signing_key(&creds.secret_access_key, &date_stamp, region, "codecommit");
    let signature = hex::encode(sigv4::hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    // Username: access_key_id + session token (separated by %)
    let session_token = creds.session_token.expose_secret();
    let username = if session_token.is_empty() {
        SecretString::from(creds.access_key_id.clone())
    } else {
        SecretString::from(format!("{}%{session_token}", creds.access_key_id))
    };

    // Password: timestamp (no Z) + 'Z' separator + hex signature
    let password = SecretString::from(format!("{timestamp}Z{signature}"));

    CodeCommitCredentials { username, password }
}

/// Parsed components of a `codecommit://` URL.
///
/// Supports two formats:
/// - `codecommit://[profile@]repo-name`
/// - `codecommit::region://[profile@]repo-name`
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodeCommitUrl {
    /// AWS profile name (optional, from `profile@` prefix).
    pub profile: Option<String>,
    /// Repository name.
    pub repository: String,
    /// AWS region (optional, from `codecommit::region://` prefix).
    pub region: Option<String>,
}

/// Parse a `codecommit://` URL into its components.
///
/// # Examples
/// - `codecommit://my-repo` → repo=my-repo
/// - `codecommit://profile@my-repo` → profile=profile, repo=my-repo
/// - `codecommit::us-east-1://my-repo` → region=us-east-1, repo=my-repo
/// - `codecommit::us-east-1://profile@my-repo` → all three
#[must_use]
pub(crate) fn parse_codecommit_url(url: &str) -> Option<CodeCommitUrl> {
    // Format 1: codecommit::region://[profile@]repo
    // Format 2: codecommit://[profile@]repo
    // Format 3: region://[profile@]repo
    //
    // Format 3 is what the remote helper actually receives for format 1. Per
    // gitremote-helpers(7): "A URL of the form <transport>::<address> explicitly
    // instructs Git to invoke git remote-<transport> with <address> as the
    // second argument" — so `codecommit::us-east-1://repo` arrives as
    // `us-east-1://repo`. Format 2 matches the neighbouring rule, where Git
    // "invokes git remote-<transport> with the full URL", and is seen whole.
    // Format 1 still has to parse for direct/manual invocation.
    let (region, remainder) = if let Some(after_double_colon) = url.strip_prefix("codecommit::") {
        // codecommit::region://...
        let (region, rest) = after_double_colon.split_once("://")?;
        if region.is_empty() {
            return None;
        }
        (Some(region.to_string()), rest)
    } else if let Some(rest) = url.strip_prefix("codecommit://") {
        // codecommit://...
        (None, rest)
    } else {
        // region://... — requires a region-shaped scheme so ordinary URLs
        // (https://, ssh://) are still rejected.
        let (region, rest) = url.split_once("://")?;
        if !is_region_like(region) {
            return None;
        }
        (Some(region.to_string()), rest)
    };

    if remainder.is_empty() {
        return None;
    }

    // Parse [profile@]repo
    let (profile, repository) = if let Some((prof, repo)) = remainder.split_once('@') {
        if prof.is_empty() || repo.is_empty() {
            return None;
        }
        (Some(prof.to_string()), repo.to_string())
    } else {
        (None, remainder.to_string())
    };

    // Reject repository names containing path separators to prevent path traversal
    if repository.contains('/') || repository.contains('\\') {
        return None;
    }

    Some(CodeCommitUrl {
        profile,
        repository,
        region,
    })
}

/// Check whether a URL scheme looks like an AWS region.
///
/// AWS regions are `<group>-<direction>-<number>`, e.g. `us-east-1`,
/// `ap-southeast-2`, `us-gov-west-1`, `cn-north-1`. Requiring that shape keeps
/// the bare `<region>://` form from swallowing `https://` and friends.
fn is_region_like(scheme: &str) -> bool {
    let mut parts = scheme.split('-');

    let Some(first) = parts.next() else {
        return false;
    };
    if first.len() < 2 || !first.chars().all(|c| c.is_ascii_lowercase()) {
        return false;
    }

    let mut middle_parts = 0usize;
    let mut last = None;
    for part in parts {
        if let Some(previous) = last.replace(part) {
            if previous.is_empty() || !previous.chars().all(|c| c.is_ascii_lowercase()) {
                return false;
            }
            middle_parts = middle_parts.saturating_add(1);
        }
    }

    // At least one middle segment (`us` + `east` + `1`) and a trailing number.
    middle_parts >= 1
        && last.is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
}

/// Extract the AWS region from a CodeCommit hostname.
///
/// # Examples
/// - `git-codecommit.us-east-1.amazonaws.com` → `Some("us-east-1")`
/// - `git-codecommit.cn-north-1.amazonaws.com.cn` → `Some("cn-north-1")`
#[must_use]
pub(crate) fn extract_region_from_hostname(hostname: &str) -> Option<&str> {
    let rest = hostname.strip_prefix("git-codecommit.")?;
    // rest = "us-east-1.amazonaws.com" or "cn-north-1.amazonaws.com.cn"
    let dot_idx = rest.find('.')?;
    let region = rest.get(..dot_idx)?;
    if region.is_empty() {
        return None;
    }
    Some(region)
}

/// Known CodeCommit domain suffixes by partition.
///
/// Note: CodeCommit domain suffixes differ from STS (e.g., China uses
/// `amazonaws.com.cn` for CodeCommit but `amazonaws.cn` for STS).
const CODECOMMIT_DOMAINS: &[&str] = &[
    "amazonaws.com",    // Commercial (aws) + GovCloud (aws-us-gov)
    "amazonaws.com.cn", // China (aws-cn)
    "amazonaws.eu",     // European Sovereign Cloud (future)
];

/// Check if a hostname is a CodeCommit host in any partition.
///
/// Git's credential protocol includes the port in the `host` field when the
/// URL explicitly specifies one (e.g., `git-codecommit.us-east-1.amazonaws.com:443`).
/// The standard HTTPS port is stripped before matching so that explicit `:443`
/// doesn't cause the host check — and thus the entire credential helper — to
/// fail silently. Non-standard ports are intentionally not stripped: the helper
/// should decline to provide CodeCommit credentials for them.
#[must_use]
pub(crate) fn is_codecommit_host(host: &str) -> bool {
    let host = host.strip_suffix(":443").unwrap_or(host);
    if !host.starts_with("git-codecommit.") {
        return false;
    }
    CODECOMMIT_DOMAINS
        .iter()
        .any(|domain| host.ends_with(domain))
}

/// Get the CodeCommit hostname for a given region.
///
/// Maps region prefixes to their partition's CodeCommit domain suffix:
/// - `cn-*` → `amazonaws.com.cn` (China)
/// - `eu-isoe-*` → `amazonaws.eu` (European Sovereign Cloud, future)
/// - All others → `amazonaws.com` (Commercial, GovCloud)
#[must_use]
pub(crate) fn hostname_for_region(region: &str) -> String {
    let domain = codecommit_domain_for_region(region);
    format!("git-codecommit.{region}.{domain}")
}

/// Get the CodeCommit domain suffix for a region.
///
/// Note: CodeCommit domain suffixes differ from STS domains in some partitions
/// (e.g., China uses `amazonaws.com.cn` here vs `amazonaws.cn` for STS).
fn codecommit_domain_for_region(region: &str) -> &'static str {
    if region.starts_with("cn-") {
        "amazonaws.com.cn"
    } else if region.starts_with("eu-isoe-") {
        "amazonaws.eu"
    } else {
        "amazonaws.com"
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::string_slice,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    // -- URL parsing tests --

    #[test]
    fn test_parse_simple_repo() {
        let result = parse_codecommit_url("codecommit://my-repo").unwrap();
        assert_eq!(result.repository, "my-repo");
        assert_eq!(result.profile, None);
        assert_eq!(result.region, None);
    }

    #[test]
    fn test_parse_profile_and_repo() {
        let result = parse_codecommit_url("codecommit://my-profile@my-repo").unwrap();
        assert_eq!(result.repository, "my-repo");
        assert_eq!(result.profile, Some("my-profile".to_string()));
        assert_eq!(result.region, None);
    }

    #[test]
    fn test_parse_region_and_repo() {
        let result = parse_codecommit_url("codecommit::us-east-1://my-repo").unwrap();
        assert_eq!(result.repository, "my-repo");
        assert_eq!(result.profile, None);
        assert_eq!(result.region, Some("us-east-1".to_string()));
    }

    #[test]
    fn test_parse_region_profile_and_repo() {
        let result = parse_codecommit_url("codecommit::eu-west-2://prod-profile@my-repo").unwrap();
        assert_eq!(result.repository, "my-repo");
        assert_eq!(result.profile, Some("prod-profile".to_string()));
        assert_eq!(result.region, Some("eu-west-2".to_string()));
    }

    #[test]
    fn test_parse_china_region() {
        let result = parse_codecommit_url("codecommit::cn-north-1://my-repo").unwrap();
        assert_eq!(result.region, Some("cn-north-1".to_string()));
    }

    #[test]
    fn test_parse_govcloud_region() {
        let result = parse_codecommit_url("codecommit::us-gov-west-1://my-repo").unwrap();
        assert_eq!(result.region, Some("us-gov-west-1".to_string()));
    }

    #[test]
    fn test_parse_empty_repo() {
        assert!(parse_codecommit_url("codecommit://").is_none());
    }

    #[test]
    fn test_parse_empty_profile() {
        assert!(parse_codecommit_url("codecommit://@my-repo").is_none());
    }

    #[test]
    fn test_parse_empty_repo_with_profile() {
        assert!(parse_codecommit_url("codecommit://profile@").is_none());
    }

    #[test]
    fn test_parse_empty_region() {
        assert!(parse_codecommit_url("codecommit:://my-repo").is_none());
    }

    #[test]
    fn test_parse_repo_with_slash() {
        assert!(parse_codecommit_url("codecommit://my/repo").is_none());
    }

    #[test]
    fn test_parse_repo_with_backslash() {
        assert!(parse_codecommit_url("codecommit://my\\repo").is_none());
    }

    /// Git strips everything through the first `::` before invoking a remote
    /// helper, so `codecommit::us-east-1://repo` arrives here as
    /// `us-east-1://repo`. Rejecting that form broke every regional clone,
    /// including the verification command `vouch setup codecommit` prints.
    #[test]
    fn test_parse_post_strip_region_form() {
        let parsed = parse_codecommit_url("us-east-1://my-repo").expect("should parse");
        assert_eq!(parsed.region, Some("us-east-1".to_string()));
        assert_eq!(parsed.repository, "my-repo");
        assert_eq!(parsed.profile, None);
    }

    #[test]
    fn test_parse_post_strip_region_and_profile() {
        let parsed =
            parse_codecommit_url("ap-southeast-2://vouch-demo@my-repo").expect("should parse");
        assert_eq!(parsed.region, Some("ap-southeast-2".to_string()));
        assert_eq!(parsed.profile, Some("vouch-demo".to_string()));
        assert_eq!(parsed.repository, "my-repo");
    }

    #[test]
    fn test_parse_post_strip_govcloud_region() {
        let parsed = parse_codecommit_url("us-gov-west-1://my-repo").expect("should parse");
        assert_eq!(parsed.region, Some("us-gov-west-1".to_string()));
    }

    /// The bare `<region>://` form must not turn every URL into a CodeCommit
    /// one — only region-shaped schemes qualify.
    #[test]
    fn test_parse_rejects_non_region_schemes() {
        assert!(parse_codecommit_url("ssh://git@example.com").is_none());
        assert!(parse_codecommit_url("http://my-repo").is_none());
        assert!(parse_codecommit_url("git://my-repo").is_none());
        assert!(parse_codecommit_url("us-east://my-repo").is_none());
        assert!(parse_codecommit_url("useast1://my-repo").is_none());
    }

    #[test]
    fn test_parse_not_codecommit() {
        assert!(parse_codecommit_url("https://github.com/repo").is_none());
    }

    // -- Region extraction tests --

    #[test]
    fn test_extract_region_commercial() {
        assert_eq!(
            extract_region_from_hostname("git-codecommit.us-east-1.amazonaws.com"),
            Some("us-east-1")
        );
    }

    #[test]
    fn test_extract_region_china() {
        assert_eq!(
            extract_region_from_hostname("git-codecommit.cn-north-1.amazonaws.com.cn"),
            Some("cn-north-1")
        );
    }

    #[test]
    fn test_extract_region_govcloud() {
        assert_eq!(
            extract_region_from_hostname("git-codecommit.us-gov-west-1.amazonaws.com"),
            Some("us-gov-west-1")
        );
    }

    #[test]
    fn test_extract_region_not_codecommit() {
        assert!(extract_region_from_hostname("github.com").is_none());
    }

    #[test]
    fn test_extract_region_malformed() {
        assert!(extract_region_from_hostname("git-codecommit.").is_none());
    }

    // -- Host detection tests --

    #[test]
    fn test_is_codecommit_host_commercial() {
        assert!(is_codecommit_host("git-codecommit.us-east-1.amazonaws.com"));
    }

    #[test]
    fn test_is_codecommit_host_china() {
        assert!(is_codecommit_host(
            "git-codecommit.cn-north-1.amazonaws.com.cn"
        ));
    }

    #[test]
    fn test_is_codecommit_host_govcloud() {
        assert!(is_codecommit_host(
            "git-codecommit.us-gov-west-1.amazonaws.com"
        ));
    }

    #[test]
    fn test_is_codecommit_host_eusc() {
        assert!(is_codecommit_host(
            "git-codecommit.eu-isoe-west-1.amazonaws.eu"
        ));
    }

    #[test]
    fn test_is_codecommit_host_not_codecommit() {
        assert!(!is_codecommit_host("github.com"));
        assert!(!is_codecommit_host("git-codecommit.us-east-1.example.com"));
    }

    // -- Host detection tests: explicit standard port (:443) --

    /// Git's credential protocol includes the port in the `host` field when the
    /// URL explicitly specifies one. The standard HTTPS port must be stripped
    /// before matching so explicit `:443` doesn't silently fail the helper.
    #[test]
    fn test_is_codecommit_host_with_port_443() {
        assert!(is_codecommit_host(
            "git-codecommit.us-east-1.amazonaws.com:443"
        ));
        assert!(is_codecommit_host(
            "git-codecommit.cn-north-1.amazonaws.com.cn:443"
        ));
    }

    /// Non-standard ports are intentionally NOT stripped: CodeCommit only
    /// serves HTTPS on 443, so a request to a different port should not be
    /// treated as a CodeCommit host. The helper declines with no output and
    /// git falls through to other helpers.
    #[test]
    fn test_is_codecommit_host_rejects_non_standard_port() {
        assert!(!is_codecommit_host(
            "git-codecommit.us-east-1.amazonaws.com:8443"
        ));
        assert!(!is_codecommit_host(
            "git-codecommit.us-east-1.amazonaws.com:80"
        ));
    }

    /// A bare `:443` suffix on a non-CodeCommit host must not produce a false
    /// positive. The prefix/suffix checks still apply after port stripping.
    #[test]
    fn test_is_codecommit_host_with_port_443_not_codecommit() {
        assert!(!is_codecommit_host("github.com:443"));
        assert!(!is_codecommit_host(
            "git-codecommit.us-east-1.example.com:443"
        ));
    }

    /// `extract_region_from_hostname` receives the same `host` string git
    /// emitted (after the caller strips `:443`). It extracts the region from
    /// before the first `.` after the `git-codecommit.` prefix, so a trailing
    /// `:443` wouldn't affect it — but verify that explicitly to guard the
    /// signing pipeline against regressions if the extraction logic changes.
    #[test]
    fn test_extract_region_with_port_443() {
        assert_eq!(
            extract_region_from_hostname("git-codecommit.us-east-1.amazonaws.com:443"),
            Some("us-east-1")
        );
        assert_eq!(
            extract_region_from_hostname("git-codecommit.cn-north-1.amazonaws.com.cn:443"),
            Some("cn-north-1")
        );
    }

    // -- Hostname construction tests --

    #[test]
    fn test_hostname_commercial() {
        assert_eq!(
            hostname_for_region("us-east-1"),
            "git-codecommit.us-east-1.amazonaws.com"
        );
    }

    #[test]
    fn test_hostname_china() {
        assert_eq!(
            hostname_for_region("cn-north-1"),
            "git-codecommit.cn-north-1.amazonaws.com.cn"
        );
    }

    #[test]
    fn test_hostname_govcloud() {
        assert_eq!(
            hostname_for_region("us-gov-west-1"),
            "git-codecommit.us-gov-west-1.amazonaws.com"
        );
    }

    #[test]
    fn test_hostname_eusc() {
        assert_eq!(
            hostname_for_region("eu-isoe-west-1"),
            "git-codecommit.eu-isoe-west-1.amazonaws.eu"
        );
    }

    // -- Signing tests --

    #[test]
    fn test_sign_request_format() {
        let creds = StsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: SecretString::from(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            ),
            session_token: SecretString::from("FwoGZXIvYXdzEBYaDM".to_string()),
            expiration: "2024-01-15T18:30:45Z".parse().unwrap(),
        };

        let result = sign_request(
            &creds,
            "git-codecommit.us-east-1.amazonaws.com",
            "/v1/repos/my-repo",
            "us-east-1",
        );

        // Username should be access_key%session_token
        let username = result.username.expose_secret();
        assert!(username.starts_with("AKIAIOSFODNN7EXAMPLE%"));
        assert!(username.contains("FwoGZXIvYXdzEBYaDM"));

        // Password should be {timestamp}Z{signature} where Z is a separator
        let password = result.password.expose_secret();
        // Format: YYYYMMDDTHHMMSSZhexsignature (Z is separator, not part of timestamp)
        assert!(password.len() > 16, "password too short: {password}");
        // The Z is at position 15 (0-indexed)
        assert_eq!(
            password.as_bytes().get(15).copied(),
            Some(b'Z'),
            "expected Z at position 15 in password"
        );
        // After the Z (position 16+) should be hex signature (64 chars for SHA-256)
        let signature_part = password.get(16..).unwrap_or("");
        assert_eq!(
            signature_part.len(),
            64,
            "expected 64-char hex signature, got {}",
            signature_part.len()
        );
        assert!(
            signature_part.chars().all(|c| c.is_ascii_hexdigit()),
            "signature should be hex"
        );
    }

    /// Verify the canonical request format matches the AWS reference implementation
    /// (git-remote-codecommit). CodeCommit's SigV4 canonical request does NOT include
    /// a payload hash — it ends with just a trailing newline after signed headers.
    #[test]
    fn test_canonical_request_no_payload_hash() {
        let hostname = "git-codecommit.us-east-1.amazonaws.com";
        let path = "/v1/repos/my-repo";
        let canonical_headers = format!("host:{hostname}\n");
        let signed_headers = "host";

        let canonical_request = format!("GIT\n{path}\n\n{canonical_headers}\n{signed_headers}\n");

        // Must end with "host\n" — no SHA-256 payload hash after it
        assert!(
            canonical_request.ends_with("host\n"),
            "canonical request should end with 'host\\n', not a payload hash"
        );

        // Must NOT contain the SHA-256 hash of empty payload
        let empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(
            !canonical_request.contains(empty_hash),
            "canonical request must not contain empty payload hash"
        );

        // Verify exact format matches AWS reference:
        // 'GIT\n{path}\n\nhost:{hostname}\n\nhost\n'
        let expected = format!("GIT\n{path}\n\nhost:{hostname}\n\nhost\n");
        assert_eq!(canonical_request, expected);
    }

    #[test]
    fn test_format_codecommit_timestamp() {
        // Create a known timestamp: 2024-01-15 10:50:45 UTC
        let ts = jiff::Timestamp::from_second(1705315845).expect("valid timestamp");
        let result = format_codecommit_timestamp(ts);
        // Must NOT have trailing Z (unlike standard SigV4 format_amz_date)
        assert_eq!(result, "20240115T105045");
        assert!(
            !result.ends_with('Z'),
            "CodeCommit timestamp must not end with Z"
        );
    }

    /// Verify the string-to-sign uses a timestamp WITHOUT trailing Z.
    ///
    /// The AWS reference implementation (`git-remote-codecommit`) stores the
    /// timestamp as `%Y%m%dT%H%M%S` (no Z) and uses it directly in
    /// `string_to_sign`. CodeCommit recomputes the signature server-side
    /// using this format, so a trailing Z causes a signature mismatch (403).
    #[test]
    fn test_string_to_sign_no_trailing_z() {
        let hostname = "git-codecommit.us-east-1.amazonaws.com";
        let path = "/v1/repos/my-repo";
        let region = "us-east-1";

        // Build string-to-sign the same way sign_request does
        let ts = jiff::Timestamp::from_second(1705315845).expect("valid timestamp");
        let timestamp = format_codecommit_timestamp(ts);
        let date_stamp = sigv4::format_date_stamp(ts);

        let canonical_headers = format!("host:{hostname}\n");
        let signed_headers = "host";
        let canonical_request = format!("GIT\n{path}\n\n{canonical_headers}\n{signed_headers}\n");
        let canonical_request_hash = sigv4::sha256_hex(canonical_request.as_bytes());

        let credential_scope = format!("{date_stamp}/{region}/codecommit/aws4_request");
        let string_to_sign =
            format!("AWS4-HMAC-SHA256\n{timestamp}\n{credential_scope}\n{canonical_request_hash}");

        // Line 2 of string-to-sign should be timestamp WITHOUT Z
        let lines: Vec<&str> = string_to_sign.split('\n').collect();
        let timestamp_line = lines.get(1).copied();
        assert_eq!(timestamp_line, Some("20240115T105045"));
        assert!(
            !timestamp_line.unwrap().ends_with('Z'),
            "string-to-sign timestamp must not have trailing Z"
        );
    }

    #[test]
    fn test_sign_request_no_session_token() {
        let creds = StsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: SecretString::from("secret".to_string()),
            session_token: SecretString::from(String::new()),
            expiration: "2024-01-15T18:30:45Z".parse().unwrap(),
        };

        let result = sign_request(
            &creds,
            "git-codecommit.us-east-1.amazonaws.com",
            "/v1/repos/my-repo",
            "us-east-1",
        );

        // Without session token, username should be just the access key
        let username = result.username.expose_secret();
        assert_eq!(username, "AKIAIOSFODNN7EXAMPLE");
        assert!(!username.contains('%'));
    }

    /// End-to-end signature verification for `sign_request`.
    ///
    /// Calls the function, extracts the dynamic timestamp from the
    /// password, then independently reconstructs the SigV4 signing
    /// calculation and verifies the signature matches.
    #[test]
    fn test_codecommit_signature_verification() {
        let creds = StsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: SecretString::from(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            ),
            session_token: SecretString::from("AQtoken123".to_string()),
            expiration: "2024-01-15T18:30:45Z".parse().unwrap(),
        };

        let result = sign_request(
            &creds,
            "git-codecommit.us-east-1.amazonaws.com",
            "/v1/repos/my-repo",
            "us-east-1",
        );

        let password = result.password.expose_secret();
        // Password: {YYYYMMDDTHHMMSS}Z{hex_signature}
        let timestamp = &password[..15];
        let actual_sig = &password[16..];
        let date_stamp = &timestamp[..8];

        // Reconstruct the signing independently
        let hostname = "git-codecommit.us-east-1.amazonaws.com";
        let path = "/v1/repos/my-repo";
        let canonical_headers = format!("host:{hostname}\n");
        let canonical_request = format!("GIT\n{path}\n\n{canonical_headers}\nhost\n");
        let cr_hash = sigv4::sha256_hex(canonical_request.as_bytes());

        let scope = format!("{date_stamp}/us-east-1/codecommit/aws4_request");
        let string_to_sign = format!("AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{cr_hash}");

        let key = sigv4::derive_signing_key(
            &creds.secret_access_key,
            date_stamp,
            "us-east-1",
            "codecommit",
        );
        let expected_sig = hex::encode(sigv4::hmac_sha256(&key, string_to_sign.as_bytes()));

        assert_eq!(actual_sig, expected_sig, "CodeCommit signature mismatch");
    }
}
