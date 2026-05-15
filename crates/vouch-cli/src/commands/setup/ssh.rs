// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SSH setup command.
//!
//! Configures SSH to use Vouch-issued certificates.

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use vouch_common::SshCaPublicKeyResponse;

use crate::client::VouchClient;
use crate::utils::{atomic_write, atomic_write_secure, ensure_secure_dir};

/// Get the SSH config path (~/.ssh/config).
pub(crate) fn ssh_config_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".ssh").join("config"))
}

/// Get the known hosts path (~/.ssh/known_hosts).
fn known_hosts_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".ssh").join("known_hosts"))
}

/// Get the CA public key path.
fn ca_key_path(server: &str) -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    // Sanitize server URL for filename: strip scheme, replace non-alphanumeric with underscores,
    // and collapse multiple underscores. e.g. "https://us.vouch.sh" → "vouch_ca_us_vouch_sh.pub"
    let safe_host = server
// FIX: 安全检查 — 防止目录穿越
// FIX: 安全检查 — 防止目录穿越
let path = {}.canonicalize().map_err(|_| Error::InvalidPath)?;
if !path.starts_with(&base_dir) {
    return Err(Error::PathTraversalDetected);
}

let path = {}.canonicalize().map_err(|_| Error::InvalidPath)?;
if !path.starts_with(&base_dir) {
    return Err(Error::PathTraversalDetected);
}

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
    let home = dirs::home_dir().context("could not determine home directory")?;
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
    println!("Downloading SSH CA public key from server...");
    let ca_response: SshCaPublicKeyResponse = client
        .get_authenticated("/v1/credentials/ssh/ca")
        .await
        .context("failed to get SSH CA public key")?;

    // Save CA public key
    let ca_path = ca_key_path(server)?;
    let ca_content = format!("{} {}\n", ca_response.public_key, ca_response.comment);

    // Ensure .ssh directory exists with secure permissions
    if let Some(parent) = ca_path.parent() {
        ensure_secure_dir(parent)?;
    }

    atomic_write(&ca_path, ca_content.as_bytes())
        .with_context(|| format!("failed to write {}", ca_path.display()))?;
    println!("Saved CA public key: {}", ca_path.display());

    // If hosts are specified, add TrustedUserCAKeys entry to known_hosts
    if let Some(host_patterns) = hosts {
        add_trusted_ca_to_known_hosts(&ca_path, host_patterns)?;
    }

    // Configure SSH to use the Vouch identity and certificate
    configure_ssh_config(hosts)?;

    println!();
    println!("SSH CA setup complete!");
    println!();
    println!("To trust user certificates signed by this CA, configure your SSH servers:");
    println!();
    println!("  1. Copy the CA public key to each server:");
    println!(
        "     scp {} root@server:/etc/ssh/vouch_ca.pub",
        ca_path.display()
    );
    println!();
    println!("  2. Create /etc/ssh/sshd_config.d/99-vouch-ca.conf with:");
    println!();
    println!("     TrustedUserCAKeys /etc/ssh/vouch_ca.pub");
    println!();
    println!("  3. Validate the configuration and reload sshd:");
    println!();
    println!("     sudo sshd -t && sudo systemctl reload sshd");
    println!();
    println!("Users can then authenticate with:");
    println!("  vouch login");
    println!("  vouch credential ssh");
    println!("  ssh user@server");

    Ok(())
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
    #[cfg(unix)]
    let agent_socket = vouch_agent::ssh_agent_socket_path().map_or_else(
        |_| "~/.vouch/ssh-agent.sock".to_string(),
        |p| p.display().to_string(),
    );
    #[cfg(not(unix))]
    let agent_socket = "~/.vouch/ssh-agent.sock".to_string();

    // Read existing config
    let existing = if config_path.exists() {
        fs::read_to_string(&config_path)
            .with_context(|| format!("failed to read {}", config_path.display()))?
    } else {
        String::new()
    };

    // Check if Vouch config already exists
    if existing.contains("# Vouch SSH Configuration") || existing.contains(&agent_socket) {
        println!("SSH config already configured for Vouch");
        return Ok(());
    }

    // Build the config block
    let vouch_config = if let Some(host_pattern) = hosts {
        // Host-specific: set IdentityAgent only for matching hosts to avoid
        // conflicting with other SSH agents (e.g., 1Password)
        format!(
            r#"
# Vouch SSH Configuration
# Added by: vouch setup ssh
Host {host_pattern}
    IdentityAgent {agent_socket}
    IdentityFile {key_path}
    CertificateFile {cert_path}
"#,
            key_path = key_path.display(),
            cert_path = cert_path.display()
        )
    } else {
        // No hosts specified: only add IdentityFile and CertificateFile globally.
        // These are additive and won't conflict with other agents.
        // IdentityAgent is omitted to avoid overriding other agents.
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
    };

    let new_config = format!("{existing}{vouch_config}");
    atomic_write_secure(&config_path, new_config.as_bytes())
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    println!("Updated SSH config: {}", config_path.display());
    if hosts.is_some() {
        println!("  Added Vouch IdentityAgent for specified hosts");
    } else {
        println!("  Added Vouch IdentityFile and CertificateFile");
        println!(
            "  Note: IdentityAgent not set globally to avoid conflicts with other SSH agents."
        );
        println!(
            "  To use the Vouch agent for specific hosts, re-run with: vouch setup ssh --hosts \"pattern\""
        );
    }

    Ok(())
}

/// Add a @cert-authority entry to known_hosts for the given host patterns.
///
/// Uses advisory file locking (`flock`) on Unix to prevent concurrent
/// modifications from corrupting the file. The lock is held for the
/// entire read-modify-write cycle.
fn add_trusted_ca_to_known_hosts(ca_path: &std::path::Path, host_patterns: &str) -> Result<()> {
    let known_hosts_path = known_hosts_path()?;
    let ca_pub_key = fs::read_to_string(ca_path)?;
    // Extract "algorithm base64key" from the first line (strip comment, trailing newline)
    let ca_pub_key = ca_pub_key
        .lines()
        .next()
        .context("CA public key file is empty")?
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    if ca_pub_key.is_empty() {
        return Err(crate::exit_code::CliError::ConfigError(
            "CA public key file does not contain a valid key".to_string(),
        )
        .into());
    }

    // Create entry
    let entry = format!("@cert-authority {} {}\n", host_patterns, ca_pub_key);

    // Ensure .ssh directory exists
    if let Some(parent) = known_hosts_path.parent() {
        ensure_secure_dir(parent)?;
    }

    // Acquire advisory lock for the read-modify-write cycle
    let lock_path = known_hosts_path.with_extension("lock");
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&lock_path)
        .with_context(|| format!("failed to open lock file {}", lock_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best-effort tightening of lock file permissions.
        let _chmod = fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600));
    }

    #[cfg(unix)]
    crate::utils::flock_exclusive(&lock_file).context("failed to acquire known_hosts lock")?;

    // Read existing known_hosts under the lock
    let existing = if known_hosts_path.exists() {
        fs::read_to_string(&known_hosts_path)?
    } else {
        String::new()
    };

    // Check if entry already exists
    if existing.contains(&ca_pub_key) {
        println!("CA already trusted in known_hosts");
        // Lock released on drop
        drop(lock_file);
        return Ok(());
    }

    // Append entry
    let new_content = format!("{existing}{entry}");
    atomic_write_secure(&known_hosts_path, new_content.as_bytes())?;

    // Lock released on drop
    drop(lock_file);

    println!("Added CA to known_hosts for hosts: {}", host_patterns);

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
}
