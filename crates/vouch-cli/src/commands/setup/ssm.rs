// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS Systems Manager Session Manager setup command.
//!
//! Configures SSH to use `session-manager-plugin` as a proxy so users can SSH
//! to EC2 instances via SSM using Vouch-provided AWS credentials:
//!
//! ```text
//! vouch login && ssh ec2-user@i-0abc123
//! ```

use anyhow::{Context, Result, bail};
use std::fs;

use crate::commands::setup::ssh::ssh_config_path;
use crate::integrations::aws;
use crate::integrations::ssm as ssm_integration;
use crate::utils::ensure_secure_dir;
use vouch_common::fs::atomic_write_secure;

/// Marker comment used for idempotency detection.
pub(crate) const SSM_MARKER: &str = "# Vouch SSM Configuration";

/// Default SSH host patterns for SSM proxying.
pub(crate) const DEFAULT_HOST_PATTERN: &str = "i-* mi-*";

/// Validate that a value is safe for interpolation into a shell command and SSH config.
///
/// Allows only alphanumeric characters, underscores, hyphens, dots, asterisks,
/// and question marks. This covers AWS profile names, regions, and SSH host glob
/// patterns while rejecting shell metacharacters and SSH config injection.
fn validate_shell_safe(value: &str, label: &str) -> Result<()> {
    use vouch_cli::tr_args;

    if value.is_empty() {
        bail!(tr_args!("setup-ssm-err-empty", label = label));
    }

    // Reject newlines (SSH config directive injection)
    if value.contains('\n') || value.contains('\r') {
        bail!(tr_args!("setup-ssm-err-newline", label = label));
    }

    // Allow only safe characters
    for ch in value.chars() {
        if !ch.is_ascii_alphanumeric()
            && ch != '_'
            && ch != '-'
            && ch != '.'
            && ch != '*'
            && ch != '?'
            && ch != ' '
        {
            bail!(tr_args!(
                "setup-ssm-err-invalid-char",
                label = label,
                char = ch.to_string()
            ));
        }
    }

    Ok(())
}

/// Check that `session-manager-plugin` is installed and on PATH.
fn check_session_manager_plugin() -> Result<()> {
    if !ssm_integration::is_plugin_available() {
        bail!(vouch_cli::tr!("setup-ssm-err-plugin-missing"));
    }
    Ok(())
}

/// Build the SSH config block for SSM proxying.
fn build_ssh_config_block(host_pattern: &str, profile_name: &str, region_name: &str) -> String {
    let proxy_command = format!(
        "aws ssm start-session \
         --target %h \
         --document-name AWS-StartSSHSession \
         --parameters 'portNumber=%p' \
         --profile {profile_name} \
         --region {region_name}"
    );

    format!(
        "\n\
         {SSM_MARKER}\n\
         # Added by: vouch setup ssm\n\
         Host {host_pattern}\n\
         \x20   ProxyCommand sh -c \"{proxy_command}\"\n"
    )
}

/// Extract the host pattern from the `Host` line inside the Vouch SSM block.
///
/// Scans only lines at or after `SSM_MARKER`, so `Host` entries the user
/// keeps elsewhere in their SSH config are never picked up.
fn ssm_block_host_pattern(content: &str) -> Option<&str> {
    let mut marker_seen = false;
    for line in content.lines() {
        if line.contains(SSM_MARKER) {
            marker_seen = true;
            continue;
        }
        if marker_seen && let Some(rest) = line.strip_prefix("Host ") {
            let trimmed = rest.trim();
            if !trimmed.is_empty() && trimmed != "*" {
                return Some(trimmed);
            }
        }
    }
    None
}

/// Is this line the start of a top-level `ssh_config` stanza?
///
/// Stanza keywords sit in column 0; anything indented belongs to the stanza
/// above it. Matched case-insensitively, and `Host=x` is accepted alongside
/// `Host x`, because failing to recognize a stanza start is what makes
/// [`strip_ssm_block`] delete a user's entries.
fn is_stanza_start(line: &str) -> bool {
    if line.starts_with([' ', '\t']) {
        return false;
    }
    let keyword = line.split([' ', '\t', '=']).next().unwrap_or("");
    keyword.eq_ignore_ascii_case("Host") || keyword.eq_ignore_ascii_case("Match")
}

/// Remove an existing SSM config block from the SSH config content.
///
/// The block runs from `SSM_MARKER` to the next blank line, the next top-level
/// stanza, or end of file — whichever comes first. Terminating on a stanza
/// matters because the block is not required to be followed by a blank line;
/// keying only on `"\n\n"` ran to end of file and deleted every entry the user
/// kept after it.
///
/// The block emits its own column-0 `Host` line, so the first stanza start
/// after the marker is part of the block; only the second one ends it.
///
/// Lines are reassembled with their original terminators, so content outside
/// the block round-trips byte for byte.
fn strip_ssm_block(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let mut in_block = false;
    let mut block_seen = false;
    let mut own_stanza_seen = false;

    for line in content.split_inclusive('\n') {
        if !in_block {
            if !block_seen && line.contains(SSM_MARKER) {
                // The block is written with a blank separator line before the
                // marker; drop it so removal doesn't leave a widening gap.
                if result.ends_with("\n\n") {
                    result.pop();
                }
                in_block = true;
                block_seen = true;
            } else {
                result.push_str(line);
            }
            continue;
        }

        let trimmed = line.trim_end_matches(['\n', '\r']);
        let ends_block = if trimmed.is_empty() {
            true
        } else if is_stanza_start(trimmed) {
            // First stanza after the marker is the block's own `Host` line.
            let is_own = !own_stanza_seen;
            own_stanza_seen = true;
            !is_own
        } else {
            false
        };

        if ends_block {
            in_block = false;
            result.push_str(line);
        }
    }

    result
}

/// Resolve the AWS profile name for the SSM SSH config block.
///
/// Unlike every other AWS-backed command here, SSM never mints credentials
/// through Vouch: `aws ssm start-session --profile <name>` resolves that
/// profile's `credential_process` directly through the AWS CLI, so the named
/// profile does not need to be Vouch-managed. An explicit `--profile` is used
/// as-is (matching the AWS CLI's own lack of validation); with none given,
/// fall back to the auto-detected Vouch profile.
fn resolve_ssm_profile(profile: Option<&str>) -> Result<String> {
    if let Some(name) = profile {
        return Ok(name.to_string());
    }
    Ok(aws::resolve_vouch_profile(None, aws::ProfileOverride::Profile)?.name)
}

/// Run the SSM setup command.
///
/// 1. Validates inputs for shell safety
/// 2. Checks that `session-manager-plugin` is on PATH
/// 3. Resolves AWS profile and region
/// 4. Appends an SSH config block to `~/.ssh/config`
pub(crate) async fn run(
    profile: Option<&str>,
    region: Option<&str>,
    hosts: &str,
    force: bool,
) -> Result<()> {
    // Check for session-manager-plugin
    check_session_manager_plugin()?;

    // Auto-discover profile and region
    let profile_name = resolve_ssm_profile(profile)?;
    let region_name = aws::resolve_region(region, &profile_name)?;
    let host_pattern = hosts;

    // Validate all inputs before building the config block
    validate_shell_safe(&profile_name, "--profile")?;
    validate_shell_safe(&region_name, "--region")?;
    validate_shell_safe(host_pattern, "--hosts")?;

    use vouch_cli::{tr_args, tr_println};

    tr_println!("setup-ssm-header");
    println!();
    tr_println!(
        "setup-ssm-summary",
        profile = profile_name.as_str(),
        region = region_name.as_str(),
        hosts = host_pattern,
    );
    println!();

    // Read existing SSH config
    let config_path = ssh_config_path()?;

    // Ensure .ssh directory exists with secure permissions
    if let Some(parent) = config_path.parent() {
        ensure_secure_dir(parent)?;
    }

    let existing = if config_path.exists() {
        fs::read_to_string(&config_path).with_context(|| {
            tr_args!(
                "setup-ssm-err-read",
                path = config_path.display().to_string()
            )
        })?
    } else {
        String::new()
    };

    // Check for existing Vouch SSM configuration (idempotency)
    if existing.contains(SSM_MARKER) {
        if !force {
            tr_println!("setup-ssm-already-configured");

            // Show existing configuration details
            if let Some(proxy_line) = existing
                .lines()
                .find(|l| l.contains("aws ssm start-session"))
            {
                if let Some(p) = ssm_integration::extract_flag_value(proxy_line, "--profile") {
                    tr_println!("setup-ssm-existing-profile", indent = "  ", value = p);
                }
                if let Some(r) = ssm_integration::extract_flag_value(proxy_line, "--region") {
                    tr_println!("setup-ssm-existing-region", indent = "  ", value = r);
                }
            }
            // Show the host pattern from the Host line inside our block
            if let Some(hosts) = ssm_block_host_pattern(&existing) {
                tr_println!("setup-ssm-existing-hosts", indent = "  ", value = hosts);
            }

            println!();
            tr_println!(
                "setup-ssm-reconfigure-hint",
                marker = SSM_MARKER,
                path = config_path.display().to_string(),
            );
            return Ok(());
        }

        // --force: strip the existing block before appending the new one
        tr_println!("setup-ssm-replacing");
        println!();
    }

    // Build the SSH config block
    let ssm_config = build_ssh_config_block(host_pattern, &profile_name, &region_name);

    let base = if force && existing.contains(SSM_MARKER) {
        strip_ssm_block(&existing)
    } else {
        existing
    };

    let new_config = format!("{base}{ssm_config}");
    atomic_write_secure(&config_path, new_config.as_bytes()).with_context(|| {
        tr_args!(
            "setup-ssm-err-write",
            path = config_path.display().to_string()
        )
    })?;

    tr_println!(
        "setup-ssm-result-block",
        path = config_path.display().to_string()
    );
    println!();
    tr_println!(
        "setup-ssm-undo",
        marker = SSM_MARKER,
        path = config_path.display().to_string()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssm_marker_constant() {
        assert!(SSM_MARKER.starts_with('#'));
        assert!(SSM_MARKER.contains("SSM"));
    }

    #[test]
    fn test_default_host_pattern() {
        assert!(DEFAULT_HOST_PATTERN.contains("i-*"));
        assert!(DEFAULT_HOST_PATTERN.contains("mi-*"));
    }

    #[test]
    fn test_idempotency_detection() {
        let existing = format!(
            "Host *\n    ServerAliveInterval 60\n\n{SSM_MARKER}\n# Added by: vouch setup ssm\n\
             Host i-* mi-*\n    ProxyCommand sh -c \"aws ssm start-session ...\"\n"
        );
        assert!(existing.contains(SSM_MARKER));
    }

    #[test]
    fn test_no_marker_in_clean_config() {
        let existing = "Host *\n    ServerAliveInterval 60\n";
        assert!(!existing.contains(SSM_MARKER));
    }

    #[test]
    fn test_ssh_config_block_format() {
        let block = build_ssh_config_block("i-* mi-*", "vouch", "us-east-1");

        assert!(block.contains(SSM_MARKER));
        assert!(block.contains("Host i-* mi-*"));
        assert!(block.contains("--profile vouch"));
        assert!(block.contains("--region us-east-1"));
        assert!(block.contains("--target %h"));
        assert!(block.contains("portNumber=%p"));
        assert!(block.contains("AWS-StartSSHSession"));
    }

    #[test]
    fn test_custom_host_pattern() {
        let block = build_ssh_config_block("i-0abc*", "vouch", "us-west-2");
        assert!(block.contains("Host i-0abc*"));
    }

    // ---- validate_shell_safe tests ----

    #[test]
    fn test_validate_shell_safe_valid_profile() {
        assert!(validate_shell_safe("vouch", "--profile").is_ok());
        assert!(validate_shell_safe("my-profile", "--profile").is_ok());
        assert!(validate_shell_safe("my_profile", "--profile").is_ok());
        assert!(validate_shell_safe("profile.name", "--profile").is_ok());
    }

    #[test]
    fn test_validate_shell_safe_valid_region() {
        assert!(validate_shell_safe("us-east-1", "--region").is_ok());
        assert!(validate_shell_safe("eu-west-2", "--region").is_ok());
        assert!(validate_shell_safe("ap-southeast-1", "--region").is_ok());
    }

    #[test]
    fn test_validate_shell_safe_valid_hosts() {
        assert!(validate_shell_safe("i-* mi-*", "--hosts").is_ok());
        assert!(validate_shell_safe("i-0abc*", "--hosts").is_ok());
        assert!(validate_shell_safe("i-???????", "--hosts").is_ok());
    }

    #[test]
    fn test_validate_shell_safe_rejects_shell_metacharacters() {
        assert!(validate_shell_safe("bad;value", "--profile").is_err());
        assert!(validate_shell_safe("bad`cmd`", "--profile").is_err());
        assert!(validate_shell_safe("bad$var", "--profile").is_err());
        assert!(validate_shell_safe("bad$(cmd)", "--profile").is_err());
        assert!(validate_shell_safe("bad\"quote", "--profile").is_err());
        assert!(validate_shell_safe("bad'quote", "--profile").is_err());
        assert!(validate_shell_safe("bad|pipe", "--profile").is_err());
        assert!(validate_shell_safe("bad&bg", "--profile").is_err());
        assert!(validate_shell_safe("bad>redir", "--profile").is_err());
        assert!(validate_shell_safe("bad<redir", "--profile").is_err());
    }

    #[test]
    fn test_validate_shell_safe_rejects_newlines() {
        assert!(validate_shell_safe("i-*\nHost evil", "--hosts").is_err());
        assert!(validate_shell_safe("i-*\r\nHost evil", "--hosts").is_err());
    }

    #[test]
    fn test_validate_shell_safe_rejects_empty() {
        assert!(validate_shell_safe("", "--profile").is_err());
    }

    // ---- ssm_block_host_pattern tests ----

    #[test]
    fn test_host_pattern_skips_blocks_before_marker() {
        let existing = format!(
            "Host bastion\n    HostName bastion.example.com\n\
             \nHost *\n    ServerAliveInterval 60\n\
             \n{SSM_MARKER}\n# Added by: vouch setup ssm\n\
             Host i-* mi-*\n    ProxyCommand sh -c \"aws ssm start-session ...\"\n"
        );
        assert_eq!(ssm_block_host_pattern(&existing), Some("i-* mi-*"));
    }

    #[test]
    fn test_host_pattern_without_marker_returns_none() {
        let existing = "Host bastion\n    HostName bastion.example.com\n";
        assert_eq!(ssm_block_host_pattern(existing), None);
    }

    #[test]
    fn test_host_pattern_marker_only_block() {
        let existing = format!("{SSM_MARKER}\n# Added by: vouch setup ssm\n");
        assert_eq!(ssm_block_host_pattern(&existing), None);
    }

    // ---- strip_ssm_block tests ----

    #[test]
    fn test_strip_ssm_block_removes_block() {
        let content = format!(
            "Host *\n    ServerAliveInterval 60\n\
             \n{SSM_MARKER}\n# Added by: vouch setup ssm\n\
             Host i-* mi-*\n    ProxyCommand sh -c \"aws ssm start-session\"\n\
             \nHost other\n    Port 22\n"
        );
        let result = strip_ssm_block(&content);
        assert!(!result.contains(SSM_MARKER));
        assert!(result.contains("Host other"));
        assert!(result.contains("ServerAliveInterval"));
    }

    #[test]
    fn test_strip_ssm_block_at_end() {
        let content = format!(
            "Host *\n    ServerAliveInterval 60\n\
             \n{SSM_MARKER}\n# Added by: vouch setup ssm\n\
             Host i-* mi-*\n    ProxyCommand sh -c \"aws ssm start-session\"\n"
        );
        let result = strip_ssm_block(&content);
        assert!(!result.contains(SSM_MARKER));
        assert!(result.contains("ServerAliveInterval"));
    }

    #[test]
    fn test_strip_ssm_block_no_marker() {
        let content = "Host *\n    ServerAliveInterval 60\n";
        let result = strip_ssm_block(content);
        assert_eq!(result, content);
    }

    /// The regression for #741: without a blank line after the SSM block, the
    /// old `find("\n\n")` fell through to end of file and deleted the rest of
    /// the user's config.
    #[test]
    fn test_strip_ssm_block_keeps_adjacent_host_without_blank_line() {
        let content = format!(
            "Host *\n    ServerAliveInterval 60\n\
             \n{SSM_MARKER}\n# Added by: vouch setup ssm\n\
             Host i-* mi-*\n    ProxyCommand sh -c \"aws ssm start-session\"\n\
             Host other\n    Port 22\n"
        );
        let result = strip_ssm_block(&content);

        // The following entry survives in full.
        assert!(result.contains("Host other"), "result: {result:?}");
        assert!(result.contains("Port 22"), "result: {result:?}");
        assert!(result.contains("ServerAliveInterval"), "result: {result:?}");

        // ...and the block is gone in full. The block emits its own column-0
        // `Host` line, so a scan that stops at the first stanza start would
        // leave the ProxyCommand line orphaned under `Host *`.
        assert!(!result.contains(SSM_MARKER), "result: {result:?}");
        assert!(!result.contains("Added by"), "result: {result:?}");
        assert!(!result.contains("i-* mi-*"), "result: {result:?}");
        assert!(!result.contains("ProxyCommand"), "result: {result:?}");
    }

    #[test]
    fn test_strip_ssm_block_stops_at_match_stanza() {
        let content = format!(
            "{SSM_MARKER}\n# Added by: vouch setup ssm\n\
             Host i-* mi-*\n    ProxyCommand sh -c \"aws ssm start-session\"\n\
             Match host bastion\n    User admin\n"
        );
        let result = strip_ssm_block(&content);
        assert!(!result.contains("ProxyCommand"), "result: {result:?}");
        assert_eq!(result, "Match host bastion\n    User admin\n");
    }

    /// Content outside the block must survive byte for byte, including the
    /// absence of a trailing newline.
    #[test]
    fn test_strip_ssm_block_preserves_surrounding_bytes() {
        let content = format!(
            "Host a\n    Port 1\n\
             \n{SSM_MARKER}\n# Added by: vouch setup ssm\n\
             Host i-*\n    ProxyCommand sh -c \"x\"\n\
             \nHost b\n    Port 2"
        );
        let result = strip_ssm_block(&content);
        assert_eq!(result, "Host a\n    Port 1\n\nHost b\n    Port 2");
    }
}
