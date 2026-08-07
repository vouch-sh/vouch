// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CodeCommit credential helper and remote helper.
//!
//! Provides two modes of operation:
//!
//! 1. **Git credential helper** (`vouch credential codecommit get`):
//!    Called by git for `https://git-codecommit.*.amazonaws.com` URLs.
//!    Reads the git credential protocol from stdin, signs with SigV4,
//!    and outputs username/password.
//!
//! 2. **Git remote helper** (invoked as `git-remote-codecommit`):
//!    Called by git for `codecommit://` URLs. Generates a signed HTTPS URL
//!    and delegates to `git remote-http`.
//!
//! Both modes use the same signing core: Vouch OIDC -> STS -> SigV4 for CodeCommit.

use anyhow::{Context, Result};
use secrecy::ExposeSecret;
use vouch_cli::{tr, tr_args};

use crate::commands::credential::git_protocol::read_credential_input;
use crate::integrations::aws::codecommit::{
    extract_region_from_hostname, hostname_for_region, is_codecommit_host, parse_codecommit_url,
    sign_request,
};
use crate::integrations::aws::sts::StsCredentials;
use crate::integrations::aws::{ProfileOverride, resolve_vouch_profile, select_vouch_profile};

/// Run the git credential helper for CodeCommit.
///
/// # Arguments
/// * `operation` - The git credential operation ("get", "store", or "erase")
/// * `profile` - AWS profile in `~/.aws/config` that mints the credentials
pub(crate) async fn run(operation: &str, profile: Option<&str>) -> Result<()> {
    match operation {
        "get" => get_credential(profile).await,
        "store" | "erase" => {
            // No-ops for Vouch — we don't store credentials
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Handle the "get" operation — provide CodeCommit credentials to git.
///
/// Git supplies only `protocol`, `host` and `path`, so `profile` can only reach
/// here from the helper line `vouch setup codecommit` writes into git config.
async fn get_credential(profile: Option<&str>) -> Result<()> {
    let input = read_credential_input()?;

    let protocol = input.protocol.as_deref().unwrap_or("");
    let original_host = input.host.as_deref().unwrap_or("");

    if protocol != "https" || !is_codecommit_host(original_host) {
        return Ok(());
    }

    // Git's credential protocol includes the port in the `host` field when the
    // URL explicitly specifies one (e.g., `git-codecommit.us-east-1.amazonaws.com:443`).
    // `is_codecommit_host` already accepts that form, but libcurl strips the
    // default `:443` from the HTTP `Host` header it sends to CodeCommit. SigV4
    // signs the host header value, so signing with the port-annotated hostname
    // would produce a signature mismatch and a 403 from AWS. Strip the
    // standard HTTPS port for signing only — the original `host` must be
    // echoed back to git verbatim so its credential cache can match on
    // subsequent requests (git uses exact string comparison on `host`, with no
    // normalization, when looking up cached credentials).
    let signing_host = strip_default_port(original_host);

    // Path is required for signing (useHttpPath must be true in git config)
    let path = input.path.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "git did not provide the repository path.\n\
             Ensure useHttpPath is set:\n  \
             git config --global credential.\"https://git-codecommit.*.amazonaws.com\".useHttpPath true"
        )
    })?;

    let region = extract_region_from_hostname(signing_host)
        .context(tr!("err-could-not-extract-region-from-codecommit-hostname"))?;

    // Path from git doesn't have leading slash; SigV4 canonical URI requires it
    let canonical_path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };

    let vouch_profile = resolve_vouch_profile(profile, ProfileOverride::Profile)?;
    // Credentials are partition-scoped, so signing a request to a host in
    // another partition is guaranteed a 403. Decline with no output instead of
    // erroring: git then continues to any other configured credential helper,
    // which may legitimately serve this host.
    if let Err(e) =
        crate::integrations::aws::validate_region_for_role(region, &vouch_profile.role_arn)
    {
        vouch_cli::tr_eprintln!(
            "credential-codecommit-warn-partition-mismatch",
            error = e.to_string()
        );
        return Ok(());
    }
    let creds = get_sts_credentials(&vouch_profile.role_arn).await?;
    let signed = sign_request(&creds, signing_host, &canonical_path, region);

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    super::git_protocol::write_credential_output(
        &mut out,
        protocol,
        original_host,
        signed.username.expose_secret(),
        signed.password.expose_secret(),
    )?;

    Ok(())
}

/// Strip the standard HTTPS port (`:443`) from a git credential `host` value.
///
/// Git includes the port in `host` whenever the remote URL specifies one
/// explicitly. The default HTTPS port is removed for SigV4 signing (libcurl
/// omits `:443` from the `Host` header it sends, so the signed hostname must
/// match), but the original `host` is still what git caches and looks up.
/// Non-standard ports are left untouched — they would already have failed
/// `is_codecommit_host`, so reaching here with one is unexpected.
///
/// Split out from [`get_credential`] so the port-stripping decision is
/// unit-testable without a live Vouch session or network. This mirrors the
/// `select_region` / `resolve_region` split already used in this file.
fn strip_default_port(host: &str) -> &str {
    host.strip_suffix(":443").unwrap_or(host)
}

/// Run the git remote helper for `codecommit://` URLs.
///
/// Called when the binary is invoked as `git-remote-codecommit`.
/// Parses the `codecommit://` URL, generates a signed HTTPS URL,
/// and delegates to `git remote-http`.
///
/// # Arguments
/// * `remote_name` - The git remote name (e.g., "origin")
/// * `url` - The `codecommit://` URL
pub(crate) async fn run_remote_helper(remote_name: &str, url: &str) -> Result<()> {
    let parsed = parse_codecommit_url(url).ok_or_else(|| {
        anyhow::anyhow!(
            "invalid CodeCommit URL: {url}\n\
             Expected: codecommit://[profile@]repo-name\n\
             Or:       codecommit::<region>://[profile@]repo-name\n\
             \n\
             The profile selects the AWS profile in ~/.aws/config that mints \
             credentials, and its region."
        )
    })?;

    // Resolve region: URL > AWS config > default
    let region = resolve_region(parsed.region.as_deref(), parsed.profile.as_deref())?;

    let hostname = hostname_for_region(&region);
    let path = format!("/v1/repos/{}", parsed.repository);

    // The URL profile selects the account, not just the region.
    let vouch_profile = resolve_vouch_profile(parsed.profile.as_deref(), ProfileOverride::Profile)?;
    // The endpoint above is built from `region` while credentials mint under
    // the role's partition; a cross-partition pair is guaranteed an opaque
    // 403 from CodeCommit at git time, so fail now with a clear message.
    crate::integrations::aws::validate_region_for_role(&region, &vouch_profile.role_arn)?;
    let creds = get_sts_credentials(&vouch_profile.role_arn).await?;
    let signed = sign_request(&creds, &hostname, &path, &region);

    // Percent-encode credentials for URL embedding
    let encoded_username = percent_encode(signed.username.expose_secret());
    let encoded_password = percent_encode(signed.password.expose_secret());

    let signed_url = format!("https://{encoded_username}:{encoded_password}@{hostname}{path}");

    // Delegate to git remote-http, replacing this process on Unix
    exec_git_remote_http(remote_name, &signed_url)
}

/// Get temporary AWS credentials via Vouch OIDC -> STS flow, with caching.
///
/// Reuses the shared `fetch_and_assume` from the AWS credential module to avoid
/// duplicating the OIDC → STS logic, and wraps it with the agent credential
/// cache. The role is resolved by the caller so both CodeCommit flows can
/// validate the target region's partition against it before signing anything.
async fn get_sts_credentials(role_arn: &str) -> Result<StsCredentials> {
    let session = crate::session::resolve_session()
        .await
        .context(tr!("err-not-configured-run-vouch-enroll-first"))?;

    let server = session.server_url;

    let data = super::aws::get_aws_credentials(&server, role_arn).await?;

    // Extract STS credentials from the cached JSON
    let access_key_id = data
        .get("AccessKeyId")
        .and_then(serde_json::Value::as_str)
        .context(tr!("err-missing-accesskeyid-in-cached-credentials"))?
        .to_string();
    let secret_access_key = data
        .get("SecretAccessKey")
        .and_then(serde_json::Value::as_str)
        .context(tr!("err-missing-secretaccesskey-in-cached-credentials"))?
        .to_string();
    let session_token = data
        .get("SessionToken")
        .and_then(serde_json::Value::as_str)
        .context(tr!("err-missing-sessiontoken-in-cached-credentials"))?
        .to_string();
    let expiration_str = data
        .get("Expiration")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let expiration: jiff::Timestamp = expiration_str.parse().with_context(|| {
        tr_args!(
            "err-failed-parse-cached-expiration",
            expiration_str = expiration_str
        )
    })?;

    Ok(StsCredentials {
        access_key_id,
        secret_access_key: secrecy::SecretString::from(secret_access_key),
        session_token: secrecy::SecretString::from(session_token),
        expiration,
    })
}

/// Resolve the AWS region for a CodeCommit operation.
///
/// Priority:
/// 1. Explicit URL region (`codecommit::us-east-1://repo`)
/// 2. Specified profile's region (`codecommit://profile@repo`)
/// 3. Vouch AWS profile's region
/// 4. `AWS_DEFAULT_REGION` env var
/// 5. `AWS_REGION` env var
/// 6. Default: `us-east-1`
fn resolve_region(url_region: Option<&str>, profile: Option<&str>) -> Result<String> {
    if let Some(region) = url_region {
        return Ok(region.to_string());
    }

    if let Ok(aws_config) = crate::integrations::aws::AwsConfig::load() {
        let env_profile = std::env::var("AWS_PROFILE").ok();
        if let Some(region) = select_region(&aws_config, profile, env_profile.as_deref()) {
            return Ok(region);
        }
    }

    // Check environment variables
    if let Ok(r) = std::env::var("AWS_DEFAULT_REGION") {
        return Ok(r);
    }
    if let Ok(r) = std::env::var("AWS_REGION") {
        return Ok(r);
    }

    // Default to us-east-1
    Ok("us-east-1".to_string())
}

/// Pure region selection against an already-loaded config.
///
/// Split from [`resolve_region`] so the priority order can be tested without
/// touching the filesystem or the process environment, mirroring the
/// `select_vouch_profile` / `resolve_vouch_profile` split.
///
/// Implements priorities 2 and 3 of [`resolve_region`]: the specified
/// profile's region, then the resolved Vouch profile's region. The Vouch
/// profile is resolved with the same `explicit` -> `$AWS_PROFILE` -> sole
/// profile ordering used for role resolution in [`run_remote_helper`], so a
/// machine with several Vouch profiles never borrows an unrelated profile's
/// region — region and credentials come from the same profile. Returns `None`
/// when neither source names a region, leaving the caller to fall back to env
/// vars and the `us-east-1` default.
fn select_region(
    config: &crate::integrations::aws::AwsConfig,
    profile: Option<&str>,
    env_profile: Option<&str>,
) -> Option<String> {
    // Priority 2: the profile named in the URL (`codecommit://profile@repo`).
    if let Some(profile_name) = profile
        && let Some(profile_data) = config.get_profile(profile_name)
        && let Some(region) = profile_data.region
    {
        return Some(region);
    }

    // Priority 3: the Vouch profile that mints the credentials. Resolved with
    // the explicit profile first so region follows the same account as the
    // role resolved for credential minting; an ambiguous or missing choice
    // is not fatal here — region still has an env/us-east-1 fallback.
    let vouch_profile =
        select_vouch_profile(config, profile, env_profile, ProfileOverride::Profile).ok()?;
    config
        .get_profile(&vouch_profile.name)
        .and_then(|p| p.region)
}

/// Percent-encode a string for use in a URL.
///
/// Encodes all characters except unreserved characters (RFC 3986):
/// `A-Z a-z 0-9 - _ . ~`
fn percent_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    encoded
}

/// Execute `git remote-http` with the signed URL.
///
/// On Unix, this replaces the current process using `exec`.
/// On other platforms, it spawns a subprocess and waits.
fn exec_git_remote_http(remote_name: &str, signed_url: &str) -> Result<()> {
    let mut cmd = std::process::Command::new("git");
    cmd.args(["remote-http", remote_name, signed_url]);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // exec replaces this process — only returns on error
        let err = cmd.exec();
        Err(crate::exit_code::CliError::ConfigError(tr_args!(
            "credential-codecommit-err-exec-git",
            error = err.to_string()
        ))
        .into())
    }

    #[cfg(not(unix))]
    {
        let status = cmd
            .status()
            .context(tr!("err-failed-run-git-remote-http"))?;
        if !status.success() {
            let code = status.code().unwrap_or(1);
            // Match Unix `exec()` semantics: the child's exit code becomes
            // vouch's exit code. Returning an `anyhow::Error` here would lose
            // the numeric code to `classify()`'s `GENERAL` fallback (exit 1).
            #[expect(
                clippy::exit,
                reason = "propagate child exit code on non-Unix; matches Unix exec()"
            )]
            std::process::exit(code);
        }
        Ok(())
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::commands::credential::git_protocol;
    use crate::integrations::aws::AwsConfig;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn load_config(content: &str) -> AwsConfig {
        let mut file = NamedTempFile::new().expect("failed to create temp file");
        file.write_all(content.as_bytes())
            .expect("failed to write temp file");
        AwsConfig::load_from(file.path().to_path_buf()).expect("failed to load aws config")
    }

    /// Two Vouch-managed profiles, each with a distinct region and account.
    /// Mirrors the multi-account setup that surfaced the bug: `AWS_PROFILE`
    /// points at one profile while the URL names the other.
    const TWO_PROFILES: &str = r#"
[profile alpha-admin]
credential_process = vouch credential aws --role arn:aws:iam::111111111111:role/vouch/VouchAdmin
region = us-west-2

[profile vouch-dev]
credential_process = vouch credential aws --role arn:aws:iam::222222222222:role/Developer
region = us-east-1
"#;

    /// The exact reproduction from the bug report: the URL-named profile has
    /// no `region` field, while the `AWS_PROFILE`-named profile does. Before
    /// the fix, region resolution borrowed `AWS_PROFILE`'s region (eu-west-1)
    /// instead of falling through to env vars / the us-east-1 default.
    const SPLIT_PROFILE_REGION: &str = r#"
[profile vouch-admin]
credential_process = vouch credential aws --role arn:aws:iam::111111111111:role/Admin
region = eu-west-1

[profile vouch-dev]
credential_process = vouch credential aws --role arn:aws:iam::222222222222:role/Developer
"#;

    // -- select_region: priority 1 is handled by resolve_region, not select_region --

    /// Priority 2: the profile named in the URL supplies its own region.
    #[test]
    fn select_region_uses_specified_profile_region() {
        let aws = load_config(TWO_PROFILES);
        let region =
            select_region(&aws, Some("alpha-admin"), None).expect("specified profile has a region");
        assert_eq!(region, "us-west-2");
    }

    /// The bug: when the URL-named profile has no region, region resolution
    /// must NOT borrow the `AWS_PROFILE`-named profile's region. Before the
    /// fix, `select_region` returned `Some("eu-west-1")` from `vouch-admin`;
    /// after the fix it returns `None` so the caller falls through to env
    /// vars / the us-east-1 default.
    #[test]
    fn select_region_does_not_borrow_aws_profile_region_when_specified_has_none() {
        let aws = load_config(SPLIT_PROFILE_REGION);
        // Explicit profile is vouch-dev (no region). AWS_PROFILE is
        // vouch-admin (has region eu-west-1). With the bug, select_region
        // ignored the explicit profile, resolved vouch-admin, and returned
        // Some("eu-west-1"). With the fix, select_region resolves vouch-dev
        // (the explicit profile), which has no region, so returns None.
        assert_eq!(
            select_region(&aws, Some("vouch-dev"), Some("vouch-admin")),
            None,
            "must not borrow AWS_PROFILE's region when the explicit profile has none"
        );
    }

    /// Priority 3: with no explicit profile and a single Vouch profile, the
    /// Vouch profile's region is used. This is the "sole vouch profile"
    /// fallback the original comment described, and it must still work.
    #[test]
    fn select_region_falls_back_to_sole_vouch_profile_region() {
        let aws = load_config(
            r#"
[profile vouch-demo]
credential_process = vouch credential aws --role arn:aws:iam::222222222222:role/demo
region = ap-southeast-2
"#,
        );
        let region = select_region(&aws, None, None).expect("sole profile has a region");
        assert_eq!(region, "ap-southeast-2");
    }

    /// Priority 3 with `AWS_PROFILE`: when no profile is in the URL,
    /// `$AWS_PROFILE` (naming a Vouch profile) supplies the region. This
    /// preserves the documented behavior for users who set `AWS_PROFILE`
    /// instead of putting the profile in the URL.
    #[test]
    fn select_region_uses_aws_profile_when_no_explicit_profile() {
        let aws = load_config(TWO_PROFILES);
        let region = select_region(&aws, None, Some("vouch-dev"))
            .expect("AWS_PROFILE names a vouch profile with a region");
        assert_eq!(region, "us-east-1");
    }

    /// Explicit profile outranks `AWS_PROFILE` for region resolution, just
    /// as it does for role resolution. This is the invariant the bug
    /// violated: the explicit profile must select the same account for both
    /// credentials and region.
    #[test]
    fn select_region_explicit_profile_outranks_aws_profile_for_region() {
        let aws = load_config(TWO_PROFILES);
        // explicit alpha-admin (us-west-2) beats AWS_PROFILE=vouch-dev (us-east-1)
        let region = select_region(&aws, Some("alpha-admin"), Some("vouch-dev"))
            .expect("explicit profile has a region");
        assert_eq!(region, "us-west-2");
    }

    #[test]
    fn test_percent_encode_simple() {
        assert_eq!(percent_encode("AKIAEXAMPLE"), "AKIAEXAMPLE");
    }

    #[test]
    fn test_percent_encode_special_chars() {
        assert_eq!(percent_encode("a/b+c=d"), "a%2Fb%2Bc%3Dd");
    }

    #[test]
    fn test_percent_encode_unreserved() {
        assert_eq!(percent_encode("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn test_percent_encode_percent() {
        assert_eq!(percent_encode("50%done"), "50%25done");
    }

    // -- strip_default_port: SigV4 signing host vs. git cache key --

    /// The standard HTTPS port is stripped for SigV4 signing so the signed
    /// hostname matches the `Host` header libcurl sends (which omits `:443`).
    #[test]
    fn test_strip_default_port_removes_443() {
        assert_eq!(
            strip_default_port("git-codecommit.us-east-1.amazonaws.com:443"),
            "git-codecommit.us-east-1.amazonaws.com"
        );
        assert_eq!(
            strip_default_port("git-codecommit.cn-north-1.amazonaws.com.cn:443"),
            "git-codecommit.cn-north-1.amazonaws.com.cn"
        );
    }

    /// Non-standard ports must NOT be stripped — CodeCommit only serves HTTPS
    /// on 443, so a different port should not produce a signing host that
    /// matches a real CodeCommit endpoint. Such hosts already fail
    /// `is_codecommit_host`, so `get_credential` returns before signing.
    #[test]
    fn test_strip_default_port_keeps_non_standard_port() {
        assert_eq!(
            strip_default_port("git-codecommit.us-east-1.amazonaws.com:8443"),
            "git-codecommit.us-east-1.amazonaws.com:8443"
        );
        assert_eq!(
            strip_default_port("git-codecommit.us-east-1.amazonaws.com:80"),
            "git-codecommit.us-east-1.amazonaws.com:80"
        );
    }

    /// Regression guard for the cache-key bug: the `host` value written back
    /// to git must be the original (port-bearing) value, while the value used
    /// for SigV4 signing must have `:443` stripped. Git's credential cache
    /// matches `host` by exact string comparison with no normalization, so
    /// echoing a stripped host back to git causes a cache miss on the next
    /// request for the same `:443` URL.
    ///
    /// This models the two `host` values `get_credential` derives from a
    /// single git input and asserts the invariant the bug violated:
    ///   - `signing_host` (passed to `sign_request`) has `:443` removed
    ///   - `original_host` (passed to `write_credential_output`) is unchanged
    #[test]
    fn get_credential_returns_original_host_to_git_but_signs_with_stripped() {
        let original_host = "git-codecommit.us-east-1.amazonaws.com:443";
        let signing_host = strip_default_port(original_host);

        // The signing host fed to `sign_request` / `extract_region_from_hostname`
        // drops the default port so the SigV4 signature matches libcurl's Host
        // header (which omits `:443`).
        assert_eq!(
            signing_host, "git-codecommit.us-east-1.amazonaws.com",
            "signing host must have :443 stripped to match libcurl's Host header"
        );

        // The host written back to git must be byte-for-byte identical to the
        // input. Git caches credentials keyed on the exact `host` string, so
        // any modification — including a "harmless" default-port strip —
        // breaks cache lookups for `:443` URLs on subsequent operations.
        assert_ne!(
            original_host, signing_host,
            "original host and signing host must differ when the URL has an explicit :443; \
             if they were equal, the bug (returning the stripped host to git) would recur"
        );

        // Verify the actual git credential protocol output carries the
        // original host, proving the value reaches git unchanged. This is the
        // line git's `credential_read()` uses to overwrite its in-memory
        // `c->host` before caching.
        let mut buf = Vec::new();
        git_protocol::write_credential_output(
            &mut buf,
            "https",
            original_host,
            "AKIAEXAMPLE%token",
            "20240114T100000Zabc123",
        )
        .expect("write should succeed");
        let output = String::from_utf8(buf).expect("valid UTF-8");
        assert!(
            output.contains("host=git-codecommit.us-east-1.amazonaws.com:443\n"),
            "git credential output must echo the original (port-bearing) host so the cache key \
             matches; got: {output}"
        );
        assert!(
            !output.contains("host=git-codecommit.us-east-1.amazonaws.com\n"),
            "git credential output must NOT contain the stripped host; got: {output}"
        );
    }
}
