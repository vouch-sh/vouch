// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SSH setup command.
//!
//! Configures SSH to use Vouch-issued certificates.

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use vouch_cli::{tr, tr_args, tr_println};
use vouch_common::SshCaPublicKeyResponse;

use crate::client::VouchClient;
use crate::utils::ensure_secure_dir;
use vouch_common::fs::{atomic_write, atomic_write_secure};

/// Get the SSH config path (~/.ssh/config).
pub(crate) fn ssh_config_path() -> Result<PathBuf> {
    let home = dirs::home_dir().with_context(|| tr!("setup-err-no-home"))?;
    Ok(home.join(".ssh").join("config"))
}

/// Get the known hosts path (~/.ssh/known_hosts).
fn known_hosts_path() -> Result<PathBuf> {
    let home = dirs::home_dir().with_context(|| tr!("setup-err-no-home"))?;
    Ok(home.join(".ssh").join("known_hosts"))
}

/// Get the CA public key path.
fn ca_key_path(server: &str) -> Result<PathBuf> {
    let home = dirs::home_dir().with_context(|| tr!("setup-err-no-home"))?;
    // Sanitize server URL for filename: strip scheme, replace non-alphanumeric with underscores,
    // and collapse multiple underscores. e.g. "https://us.vouch.sh" → "vouch_ca_us_vouch_sh.pub"
    let safe_host = server
        .replace("https://", "")
        .replace("http://", "")
        .replace(|c: char| !c.is_ascii_alphanumeric(), "_");
    // Collapse consecutive underscores and trim trailing ones
    let mut collapsed = String::with_capacity(safe_host.len());
    let mut prev_underscore = false;
    for c in safe_host.chars() {
        if c == '_' {
            if !prev_underscore {
                collapsed.push('_');
            }
            prev_underscore = true;
        } else {
            collapsed.push(c);
            prev_underscore = false;
        }
    }
    let safe_host = collapsed.trim_end_matches('_');
    Ok(home.join(".ssh").join(format!("vouch_ca_{safe_host}.pub")))
}

/// Get the default SSH key path (~/.ssh/id_ed25519_vouch).
fn default_key_path() -> Result<PathBuf> {
    let home = dirs::home_dir().with_context(|| tr!("setup-err-no-home"))?;
    Ok(home.join(".ssh").join("id_ed25519_vouch"))
}

/// Run the SSH setup command.
///
/// This command:
/// 1. Downloads the CA public key from the server
/// 2. Saves it to ~/.ssh/
/// 3. Optionally updates ~/.ssh/known_hosts to trust the CA for host verification
/// 4. Optionally updates ~/.ssh/config to use the Vouch SSH agent
/// 5. Shows instructions for SSH config
pub(crate) async fn run(server: &str, hosts: Option<&str>) -> Result<()> {
    let client = VouchClient::new(server).await?;

    // Download CA public key
    tr_println!("setup-ssh-downloading-ca");
    let ca_response: SshCaPublicKeyResponse = client
        .get_authenticated("/v1/credentials/ssh/ca")
        .await
        .with_context(|| tr!("setup-ssh-err-get-ca"))?;

    // Save CA public key
    let ca_path = ca_key_path(server)?;
    let ca_content = format!("{} {}\n", ca_response.public_key, ca_response.comment);

    // Ensure .ssh directory exists with secure permissions
    if let Some(parent) = ca_path.parent() {
        ensure_secure_dir(parent)?;
    }

    atomic_write(&ca_path, ca_content.as_bytes()).with_context(|| {
        tr_args!(
            "setup-ssh-err-write-ca",
            path = ca_path.display().to_string()
        )
    })?;
    tr_println!("setup-ssh-saved-ca", path = ca_path.display().to_string());

    // If hosts are specified, add TrustedUserCAKeys entry to known_hosts
    if let Some(host_patterns) = hosts {
        add_trusted_ca_to_known_hosts(&ca_path, host_patterns)?;
    }

    // Configure SSH to use the Vouch identity and certificate
    configure_ssh_config(hosts)?;

    println!();
    tr_println!(
        "setup-ssh-complete-block",
        ca_path = ca_path.display().to_string()
    );

    Ok(())
}

/// True if `line` is an `IdentityAgent` directive pointing at the legacy
/// `~/.vouch/ssh-agent.sock` socket (ignoring leading indentation).
///
/// Deliberately narrow: a stray mention of the path in a comment or unrelated
/// directive does not match, so it cannot trigger a spurious rewrite.
fn is_stale_identity_agent_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("IdentityAgent") && trimmed.contains(".vouch/ssh-agent.sock")
}

/// Configure SSH config with Vouch identity and certificate.
///
/// If `--hosts` is provided, creates a host-specific block with `IdentityAgent`
/// so it doesn't conflict with other SSH agents (e.g., 1Password).
/// The `IdentityFile` and `CertificateFile` are always added to a `Host *` block
/// since those directives are additive and safe to combine.
fn configure_ssh_config(hosts: Option<&str>) -> Result<()> {
    let config_path = ssh_config_path()?;
    let key_path = default_key_path()?;
    let cert_path = PathBuf::from(format!("{}-cert.pub", key_path.display()));
    // The SSH agent socket is Unix-only: vouch-agent exposes a Unix domain socket
    // for SSH agent forwarding, which has no equivalent on other platforms.
    // On Unix, propagate the error rather than falling back to a stale literal
    // (the legacy ~/.vouch/ssh-agent.sock no longer exists after the XDG migration).
    // On non-Unix, no IdentityAgent directive is emitted at all.
    #[cfg(unix)]
    let agent_socket = vouch_agent::ssh_agent_socket_path()
        .map(|p| p.display().to_string())
        .with_context(|| tr!("setup-ssh-err-agent-socket"))?;

    // Read existing config
    let existing = if config_path.exists() {
        fs::read_to_string(&config_path).with_context(|| {
            tr_args!(
                "setup-ssh-err-read-config",
                path = config_path.display().to_string()
            )
        })?
    } else {
        String::new()
    };

    // Normalize a stale IdentityAgent left over from the legacy ~/.vouch layout.
    // Older versions wrote the agent socket under ~/.vouch/ssh-agent.sock; the
    // socket now lives in the XDG runtime directory. Only an actual
    // `IdentityAgent ...~/.vouch/ssh-agent.sock` line is rewritten (not a stray
    // mention in a comment), and we fall through to the normal setup path
    // afterwards rather than returning early — so a first run that also needs
    // the IdentityFile/CertificateFile block still gets it.
    // The SSH agent is Unix-only; on other platforms there is no IdentityAgent
    // to rewrite and no agent socket to advertise.
    #[cfg(unix)]
    let existing = {
        let has_stale_identity_agent = existing.lines().any(is_stale_identity_agent_line);
        if has_stale_identity_agent {
            let mut rewritten = existing
                .lines()
                .map(|line| {
                    if is_stale_identity_agent_line(line) {
                        let indent: String =
                            line.chars().take_while(|c| c.is_whitespace()).collect();
                        format!("{indent}IdentityAgent {agent_socket}")
                    } else {
                        line.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            if existing.ends_with('\n') {
                rewritten.push('\n');
            }
            atomic_write_secure(&config_path, rewritten.as_bytes()).with_context(|| {
                tr_args!(
                    "setup-ssh-err-write-config",
                    path = config_path.display().to_string()
                )
            })?;
            tr_println!(
                "setup-ssh-stale-agent-rewrite",
                config_path = config_path.display().to_string(),
                agent_socket = agent_socket.as_str(),
            );
            rewritten
        } else {
            existing
        }
    };

    // Check if Vouch config already exists.
    // On Unix, also check for the agent socket path so we don't duplicate it.
    #[cfg(unix)]
    let already_configured =
        existing.contains("# Vouch SSH Configuration") || existing.contains(&agent_socket);
    #[cfg(not(unix))]
    let already_configured = existing.contains("# Vouch SSH Configuration");

    if already_configured {
        tr_println!("setup-ssh-already-configured");
        return Ok(());
    }

    // Build the config block.
    // On Unix with --hosts, add IdentityAgent for the matching hosts so the
    // vouch SSH agent is used for those connections without conflicting with
    // other SSH agents (e.g., 1Password).  On non-Unix there is no SSH agent
    // support, so IdentityAgent is never emitted.
    let vouch_config = {
        #[cfg(unix)]
        let host_block = hosts.map(|host_pattern| {
            format!(
                r#"Host {host_pattern}
    IdentityAgent {agent_socket}
    IdentityFile {key_path}
    CertificateFile {cert_path}
"#,
                key_path = key_path.display(),
                cert_path = cert_path.display()
            )
        });
        #[cfg(not(unix))]
        let host_block: Option<String> = None;

        if let Some(block) = host_block {
            format!(
                r#"
# Vouch SSH Configuration
# Added by: vouch setup ssh
{block}"#
            )
        } else {
            // No hosts specified (or non-Unix): only add IdentityFile and
            // CertificateFile globally.  These are additive and won't conflict
            // with other agents.  IdentityAgent is omitted.
            format!(
                r#"
# Vouch SSH Configuration
# Added by: vouch setup ssh
Host *
    IdentityFile {key_path}
    CertificateFile {cert_path}
"#,
                key_path = key_path.display(),
                cert_path = cert_path.display()
            )
        }
    };

    let new_config = format!("{existing}{vouch_config}");
    atomic_write_secure(&config_path, new_config.as_bytes()).with_context(|| {
        tr_args!(
            "setup-ssh-err-write-config",
            path = config_path.display().to_string()
        )
    })?;

    tr_println!(
        "setup-ssh-updated-config",
        path = config_path.display().to_string()
    );
    if hosts.is_some() {
        tr_println!("setup-ssh-added-host-agent", indent = "  ");
    } else {
        tr_println!("setup-ssh-added-identity-block", indent = "  ");
    }

    Ok(())
}

/// Add a @cert-authority entry to known_hosts for the given host patterns.
///
/// Uses advisory file locking (`File::lock`) to prevent concurrent
/// modifications from corrupting the file. The lock is held for the
/// entire read-modify-write cycle.
fn add_trusted_ca_to_known_hosts(ca_path: &std::path::Path, host_patterns: &str) -> Result<()> {
    let known_hosts_path = known_hosts_path()?;
    let ca_pub_key = fs::read_to_string(ca_path)?;
    // Extract "algorithm base64key" from the first line (strip comment, trailing newline)
    let ca_pub_key = ca_pub_key
        .lines()
        .next()
        .with_context(|| tr!("setup-ssh-err-ca-empty"))?
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    if ca_pub_key.is_empty() {
        return Err(
            crate::exit_code::CliError::ConfigError(tr!("setup-ssh-err-ca-invalid")).into(),
        );
    }

    // Create entry
    let entry = format!("@cert-authority {} {}\n", host_patterns, ca_pub_key);

    // Ensure .ssh directory exists
    if let Some(parent) = known_hosts_path.parent() {
        ensure_secure_dir(parent)?;
    }

    // Acquire advisory lock for the read-modify-write cycle
    let lock_path = known_hosts_path.with_added_extension("lock");
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&lock_path)
        .with_context(|| {
            tr_args!(
                "setup-ssh-err-lock-file",
                path = lock_path.display().to_string()
            )
        })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best-effort tightening of lock file permissions.
        let _chmod = fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600));
    }

    lock_file
        .lock()
        .with_context(|| tr!("setup-ssh-err-lock-acquire"))?;

    // Read existing known_hosts under the lock
    let existing = if known_hosts_path.exists() {
        fs::read_to_string(&known_hosts_path)?
    } else {
        String::new()
    };

    // Check if entry already exists
    if existing.contains(&ca_pub_key) {
        tr_println!("setup-ssh-ca-already-trusted");
        // Lock released on drop
        drop(lock_file);
        return Ok(());
    }

    // Append entry
    let new_content = format!("{existing}{entry}");
    atomic_write_secure(&known_hosts_path, new_content.as_bytes())?;

    // Lock released on drop
    drop(lock_file);

    tr_println!("setup-ssh-added-ca-trust", hosts = host_patterns);

    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_key_path_https() {
        let path = ca_key_path("https://us.vouch.sh").unwrap();
        let filename = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(filename, "vouch_ca_us_vouch_sh.pub");
    }

    #[test]
    fn test_ca_key_path_localhost() {
        let path = ca_key_path("http://localhost:3000").unwrap();
        let filename = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(filename, "vouch_ca_localhost_3000.pub");
    }

    #[test]
    fn test_ca_key_path_with_port() {
        let path = ca_key_path("https://vouch.example.com:8443").unwrap();
        let filename = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(filename, "vouch_ca_vouch_example_com_8443.pub");
    }

    #[test]
    fn test_ca_key_path_trailing_slash() {
        let path = ca_key_path("https://us.vouch.sh/").unwrap();
        let filename = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(filename, "vouch_ca_us_vouch_sh.pub");
    }

    #[test]
    fn stale_identity_agent_line_matches_only_real_directive() {
        // Actual directive (with and without indentation) -> stale.
        assert!(is_stale_identity_agent_line(
            "    IdentityAgent ~/.vouch/ssh-agent.sock"
        ));
        assert!(is_stale_identity_agent_line(
            "IdentityAgent /home/u/.vouch/ssh-agent.sock"
        ));

        // A comment or unrelated line mentioning the path must NOT match,
        // so it cannot trigger a spurious rewrite / early skip.
        assert!(!is_stale_identity_agent_line(
            "# old path was ~/.vouch/ssh-agent.sock"
        ));
        assert!(!is_stale_identity_agent_line(
            "IdentityFile ~/.ssh/id_ed25519"
        ));
        // A directive pointing at the new XDG socket is not stale.
        assert!(!is_stale_identity_agent_line(
            "    IdentityAgent /run/user/1000/vouch/ssh-agent.sock"
        ));
    }
}
