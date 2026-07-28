// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CodeCommit setup command.
//!
//! Configures Git to use Vouch's native CodeCommit support:
//!
//! 1. **Credential helper** — for `https://git-codecommit.*.amazonaws.com` URLs:
//!    git asks for credentials → `vouch credential codecommit` signs with SigV4
//!
//! 2. **Remote helper** — for `codecommit://` URLs:
//!    `git-remote-codecommit` symlink → `vouch` binary → signs and delegates to `git remote-http`
//!
//! No AWS CLI dependency required. Vouch handles the full chain:
//! OIDC token → STS AssumeRoleWithWebIdentity → SigV4 signing for CodeCommit.

use anyhow::{Context, Result};

use crate::config::Config;
use crate::install_path::resolve_install_path;
use crate::integrations::aws::resolve_vouch_profile;

/// Git config patterns for CodeCommit credential helper by partition.
///
/// All partition patterns are always configured — non-matching entries are
/// harmless and it avoids needing partition-specific flags.
const PARTITION_PATTERNS: &[&str] = &[
    "https://git-codecommit.*.amazonaws.com", // Commercial + GovCloud
    "https://git-codecommit.*.amazonaws.com.cn", // China
    "https://git-codecommit.*.amazonaws.eu",  // European Sovereign Cloud (future)
];

/// Run the CodeCommit setup command.
///
/// This command:
/// 1. Verifies the user is enrolled
/// 2. Checks AWS is configured and shows profile/role
/// 3. Creates the `git-remote-codecommit` symlink for `codecommit://` URLs
/// 4. Configures git to use `vouch credential codecommit` for HTTPS URLs
///
/// # Arguments
/// * `region` - Optional specific region (default: wildcard `*` matching all regions)
/// * `profile` - Optional AWS profile name (default: auto-detect vouch profile)
/// * `configure` - If true, automatically configure; if false, just show instructions
pub(crate) async fn run(
    region: Option<&str>,
    profile: Option<&str>,
    configure: bool,
) -> Result<()> {
    use vouch_cli::{tr, tr_args, tr_println};

    // Load config to verify enrollment
    let config = Config::load().with_context(|| tr!("setup-err-load-config"))?;
    let _server = config
        .server_url()
        .with_context(|| tr!("setup-err-not-configured"))?;

    tr_println!("setup-codecommit-header");
    println!();

    // Resolve the AWS profile now: its name is baked into the helper command, so
    // the helper resolves the same account at run time that we report here.
    let vouch_profile = resolve_vouch_profile(profile)?;
    let profile_name = vouch_profile.name;
    tr_println!(
        "setup-codecommit-aws-profile",
        profile = profile_name.as_str()
    );
    tr_println!(
        "setup-codecommit-aws-role",
        role = vouch_profile.role_arn.as_str()
    );
    println!();

    // Get vouch binary path for the credential helper command and symlink
    let vouch_path = resolve_install_path();

    // Build the native credential helper command.
    //
    // The leading `!` is required: git only runs a helper value through a shell
    // when it starts with `!` or is literally an absolute path. A value starting
    // with `"` matches neither, so git would build `git credential-"<path>"` and
    // fail with "is not a git command". The `!` also preserves the quoting that
    // keeps a vouch binary under a path containing spaces working.
    //
    let helper_command = credential_helper_command(&vouch_path, &profile_name)?;

    // Determine the credential pattern(s)
    let patterns: Vec<String> = if let Some(r) = region {
        // Region-specific: replace wildcard with actual region in each partition pattern
        PARTITION_PATTERNS
            .iter()
            .map(|p| p.replace('*', r))
            .collect()
    } else {
        PARTITION_PATTERNS
            .iter()
            .map(|p| (*p).to_string())
            .collect()
    };

    // Symlink path for git-remote-codecommit
    let symlink_path = crate::utils::vouch_helper_path("git-remote-codecommit")?;

    if configure {
        // Check for conflicting credential helpers
        detect_conflicting_helpers();

        // 1. Create git-remote-codecommit symlink for codecommit:// URLs
        create_remote_helper_symlink(&vouch_path, &symlink_path)?;

        // 2. Configure git credential helper for HTTPS URLs
        for pattern in &patterns {
            let config_key = format!("credential.{pattern}.helper");
            let use_http_path_key = format!("credential.{pattern}.useHttpPath");

            if !crate::git_config::set_global(&config_key, &helper_command)
                .with_context(|| tr!("setup-codecommit-err-run-config"))?
            {
                return Err(crate::exit_code::CliError::ConfigError(tr_args!(
                    "setup-codecommit-err-helper-pattern",
                    pattern = pattern,
                ))
                .into());
            }

            // useHttpPath is critical — git must pass the full path (region + repo)
            if !crate::git_config::set_global(&use_http_path_key, "true")
                .with_context(|| tr!("setup-codecommit-err-run-config"))?
            {
                return Err(crate::exit_code::CliError::ConfigError(tr_args!(
                    "setup-codecommit-err-http-path",
                    pattern = pattern,
                ))
                .into());
            }
        }

        println!();
        tr_println!("setup-codecommit-success-block");
        for pattern in &patterns {
            tr_println!(
                "setup-codecommit-helper-pair",
                indent = "  ",
                pattern = pattern.as_str(),
                helper = helper_command.as_str(),
            );
        }
        println!();
        tr_println!(
            "setup-codecommit-remote-helper-block",
            symlink = symlink_path.display().to_string(),
            vouch = vouch_path.display().to_string(),
        );
    } else {
        tr_println!(
            "setup-codecommit-step1-block",
            vouch = vouch_path.display().to_string(),
            symlink = symlink_path.display().to_string(),
        );

        println!();
        tr_println!("setup-codecommit-step2");
        println!();
        // Git config block: machine-readable, stays English.
        for pattern in &patterns {
            println!("[credential \"{pattern}\"]");
            println!("    helper = {helper_command}");
            println!("    useHttpPath = true");
            println!();
        }
        tr_println!("setup-codecommit-or-run");
    }

    let example_region = region.unwrap_or("us-east-1");
    println!();
    tr_println!(
        "setup-codecommit-tail-block",
        region = example_region,
        path = symlink_path.display().to_string(),
    );
    for pattern in &patterns {
        tr_println!(
            "setup-codecommit-undo-config",
            indent = "  ",
            pattern = pattern,
        );
    }

    Ok(())
}

/// Build the `credential.<pattern>.helper` value git will execute.
///
/// The leading `!` is required: git only runs a helper value through a shell
/// when it starts with `!` or is literally an absolute path. A value starting
/// with a quote matches neither, so git would build `git credential-"<path>"`
/// and fail with "is not a git command".
///
/// The install path is single-quoted because it routinely contains spaces
/// (`/Users/John Smith/.cargo/bin/vouch`), and single quotes make every other
/// character literal to the shell. The profile name is not quoted: it is
/// screened to the characters the AWS CLI can actually address, which excludes
/// whitespace and every shell metacharacter.
///
/// The profile has to be baked in at all because git passes a credential helper
/// only `protocol`, `host` and `path` — there is no other channel for it.
///
/// # Errors
/// Returns an error when the profile name is not one the AWS CLI could address.
fn credential_helper_command(vouch_path: &std::path::Path, profile_name: &str) -> Result<String> {
    reject_unaddressable_profile(profile_name)?;
    let quoted_path = crate::utils::shell_single_quote(&vouch_path.display().to_string());
    Ok(format!(
        "!{quoted_path} credential codecommit --profile {profile_name}"
    ))
}

/// Reject profile names the AWS CLI itself cannot address.
///
/// `[profile my dev]` is silently unusable — the AWS CLI reports "The config
/// profile (my dev) could not be found" — so there is no working setup to
/// preserve by accepting one. Screening here also keeps shell metacharacters
/// out of the `!`-prefixed helper value, which a shell evaluates on every
/// credential request.
fn reject_unaddressable_profile(profile_name: &str) -> Result<()> {
    let addressable = !profile_name.is_empty()
        && profile_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@' | '+' | '='));

    if !addressable {
        return Err(crate::exit_code::CliError::ConfigError(format!(
            "AWS profile name {profile_name:?} cannot be used with CodeCommit.\n\
             Use a name of letters, digits and _-.@+= — the AWS CLI cannot \
             address profiles containing spaces or other characters either."
        ))
        .into());
    }

    Ok(())
}

/// Create the `git-remote-codecommit` symlink pointing to the vouch binary.
fn create_remote_helper_symlink(
    vouch_path: &std::path::Path,
    symlink_path: &std::path::Path,
) -> Result<()> {
    // The batch file sets VOUCH_GIT_REMOTE_CODECOMMIT=1 so vouch can detect
    // it was invoked as a remote helper (argv[0] detection doesn't work through .bat)
    let batch_content = format!(
        "@echo off\r\nset VOUCH_GIT_REMOTE_CODECOMMIT=1\r\n\"{}\" %*\r\n",
        vouch_path.display()
    );
    crate::utils::create_symlink_with_fallback(vouch_path, symlink_path, &batch_content)
}

/// Detect credential helpers that may conflict with Vouch.
fn detect_conflicting_helpers() {
    use vouch_cli::tr_println;

    for line in crate::git_config::get_regexp_global(r"credential.*codecommit.*helper") {
        // Skip entries that already use vouch. Match the bare binary name, not
        // "vouch credential codecommit": git returns the value with the path's
        // closing quote attached (`"…/vouch" credential codecommit`) and the
        // binary is `vouch.exe` on Windows, so neither substring is adjacent.
        if line.contains("vouch") {
            continue;
        }
        if line.contains("aws codecommit credential-helper")
            || line.contains("git-remote-codecommit")
        {
            tr_println!("setup-codecommit-warn-existing-block", line = line);
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    /// Call the real constructor; a duplicated format string here is what let
    /// the unusable-helper bug ship with a passing test.
    fn helper_command(vouch_path: &std::path::Path, profile: &str) -> String {
        super::credential_helper_command(vouch_path, profile).expect("safe profile name")
    }

    /// Git runs credential helpers through a shell, so a vouch binary path
    /// containing spaces must stay quoted as a single token. This guards
    /// against re-dropping the quotes (the bug regressed once via the #597
    /// revert).
    #[test]
    fn helper_command_quotes_path_with_spaces() {
        let vouch_path = std::path::Path::new("/Users/John Smith/.cargo/bin/vouch");

        assert_eq!(
            helper_command(vouch_path, "vouch-demo"),
            "!'/Users/John Smith/.cargo/bin/vouch' credential codecommit --profile vouch-demo"
        );
    }

    /// Git only executes a credential helper value that starts with `!` or is
    /// literally an absolute path; a value starting with `"` takes neither
    /// branch and git builds `git credential-"<path>"` instead.
    #[test]
    fn helper_command_is_shell_prefixed() {
        let value = helper_command(
            std::path::Path::new("/opt/homebrew/bin/vouch"),
            "vouch-demo",
        );
        assert!(
            value.starts_with('!'),
            "git will not execute a helper value that lacks the '!' prefix: {value}"
        );
    }

    /// The `!` prefix means a shell evaluates this value on every credential
    /// request, so names carrying shell syntax must be refused. The AWS CLI
    /// cannot address any of these either — `[profile my dev]` reports "The
    /// config profile (my dev) could not be found" — so nothing usable is lost.
    #[test]
    fn unaddressable_profile_names_are_refused() {
        for name in [
            "",
            "my dev",
            "demo\"; id; \"",
            "demo$(whoami)",
            "demo`id`",
            "demo\\bad",
            "demo\nhost=evil",
            "demo'quote",
        ] {
            assert!(
                super::reject_unaddressable_profile(name).is_err(),
                "should refuse {name:?}"
            );
        }
    }

    #[test]
    fn ordinary_profile_names_are_accepted() {
        for name in ["vouch-demo", "vouch", "acct.prod_1", "team@corp", "a+b=c"] {
            assert!(
                super::reject_unaddressable_profile(name).is_ok(),
                "should accept {name:?}"
            );
        }
    }

    /// Drive a real `git credential fill` against a stub helper installed at a
    /// path containing a space, and return git's stdout.
    ///
    /// The stub echoes back argv so callers can assert how the shell split the
    /// helper value: `$3` and `$4` are the `--profile` flag and its value.
    #[cfg(unix)]
    fn run_helper_via_git(profile: &str) -> String {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("create temp dir");
        let bin_dir = dir.path().join("bin with space");
        std::fs::create_dir_all(&bin_dir).expect("create bin dir");
        let stub = bin_dir.join("vouch");
        std::fs::write(
            &stub,
            "#!/bin/sh\necho \"username=$3|$4\"\necho password=stub-pass\n",
        )
        .expect("write stub helper");
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
            .expect("chmod stub helper");

        // Write the value through `git config`, exactly as `run` does. This has
        // to be a real config file: `git -c key=value` runs the value through
        // git's config *value* parser, which consumes the double quotes, while
        // `git config` writes them escaped so they survive the round trip.
        let gitconfig = dir.path().join("gitconfig");
        let status = std::process::Command::new("git")
            .args(["config", "--file"])
            .arg(&gitconfig)
            .arg("credential.https://example.com.helper")
            .arg(helper_command(&stub, profile))
            .status()
            .expect("write helper into a git config file");
        assert!(status.success(), "git config write failed");

        let mut child = std::process::Command::new("git")
            // Isolate from the developer's real git configuration.
            .env("GIT_CONFIG_GLOBAL", &gitconfig)
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args(["credential", "fill"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn git credential fill");

        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(b"protocol=https\nhost=example.com\n\n")
            .expect("write credential request");

        let output = child.wait_with_output().expect("wait for git");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "git credential fill failed: {stderr}"
        );

        // Keep only the helper-supplied lines; git echoes protocol/host back.
        stdout
            .lines()
            .filter(|l| l.starts_with("username=") || l.starts_with("password="))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// End-to-end proof that git runs the helper and reads its output.
    ///
    /// The previous string-shape assertion passed while the configured helper
    /// was unusable, so this drives real `git credential fill` against a stub on
    /// a path containing a space — catching both a missing `!` and dropped
    /// quotes around the binary path.
    #[cfg(unix)]
    #[test]
    fn git_executes_the_helper_command() {
        let output = run_helper_via_git("vouch-demo");
        assert!(
            output.contains("username=--profile|vouch-demo"),
            "git did not run the helper with the baked-in profile: {output}"
        );
        assert!(
            output.contains("password=stub-pass"),
            "git did not read the helper output: {output}"
        );
    }
}
