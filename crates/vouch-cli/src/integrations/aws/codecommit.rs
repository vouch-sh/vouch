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
pub struct CodeCommitCredentials {
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
pub fn sign_request(
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
pub struct CodeCommitUrl {
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
pub fn parse_codecommit_url(url: &str) -> Option<CodeCommitUrl> {
    // Format 1: codecommit::region://[profile@]repo
    // Format 2: codecommit://[profile@]repo
    let (region, remainder) = if let Some(after_double_colon) = url.strip_prefix("codecommit::") {
        // codecommit::region://...
        let (region, rest) = after_double_colon.split_once("://")?;
        if region.is_empty() {
            return None;
        }
        (Some(region.to_string()), rest)
    } else {
        // codecommit://...
        let rest = url.strip_prefix("codecommit://")?;
        (None, rest)
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

/// Extract the AWS region from a CodeCommit hostname.
///
/// # Examples
/// - `git-codecommit.us-east-1.amazonaws.com` → `Some("us-east-1")`
/// - `git-codecommit.cn-north-1.amazonaws.com.cn` → `Some("cn-north-1")`
#[must_use]
pub fn extract_region_from_hostname(hostname: &str) -> Option<&str> {
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
#[must_use]
pub fn is_codecommit_host(host: &str) -> bool {
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
pub fn hostname_for_region(region: &str) -> String {
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
#[allow(clippy::expect_used, clippy::unwrap_used)]
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
            expiration: "2024-01-15T18:30:45Z".to_string(),
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
            expiration: "2024-01-15T18:30:45Z".to_string(),
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
}
