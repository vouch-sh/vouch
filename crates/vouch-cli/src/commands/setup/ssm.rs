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

/// Remove an existing SSM config block from the SSH config content.
///
/// Finds the block starting with `SSM_MARKER` and removes everything up to
/// the next blank line or end of file.
fn strip_ssm_block(content: &str) -> String {
    let Some(start) = content.find(SSM_MARKER) else {
        return content.to_string();
    };

    // Walk backwards from the marker to consume the leading newline
    let block_start =
        if start > 0 && content.as_bytes().get(start.saturating_sub(1)) == Some(&b'\n') {
            start.saturating_sub(1)
        } else {
            start
        };

    // Split safely at ASCII boundaries (SSM_MARKER and newlines are ASCII)
    let (before, from_marker) = content.split_at(block_start);

    // Find the end of the block in the remaining content: look for a blank
    // line or treat everything as the block.
    let marker_offset = start.saturating_sub(block_start);
    let after_marker = from_marker.get(marker_offset..).unwrap_or("");
    let block_rest_len = after_marker.find("\n\n").map_or(from_marker.len(), |pos| {
        marker_offset.saturating_add(pos).saturating_add(1)
    });

    let after = from_marker.get(block_rest_len..).unwrap_or("");

    let mut result = String::with_capacity(content.len());
    result.push_str(before);
    result.push_str(after);
    result
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
    let profile_name = aws::resolve_profile(profile)?;
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
            // Show host pattern from the Host line
            for line in existing.lines() {
                if let Some(rest) = line.strip_prefix("Host ") {
                    let trimmed = rest.trim();
                    // Only show the host line that follows our marker
                    if !trimmed.is_empty() && trimmed != "*" {
                        tr_println!("setup-ssm-existing-hosts", indent = "  ", value = trimmed);
                        break;
                    }
                }
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
}
