//! SSH certificate credential command.
//!
//! Generates a local SSH keypair (if not exists), requests a certificate
//! from the Vouch server, and stores the certificate alongside the key.

use anyhow::{Context, Result};
use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey, rand_core::OsRng};
use std::path::PathBuf;
use vouch_common::{SshCertificateRequest, SshCertificateResponse};

use crate::client::VouchClient;

/// Default SSH key filename (without extension).
const DEFAULT_KEY_NAME: &str = "id_ed25519_vouch";

/// Get the SSH directory path (~/.ssh).
fn ssh_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".ssh"))
}

/// Get the default SSH key path.
fn default_key_path() -> Result<PathBuf> {
    Ok(ssh_dir()?.join(DEFAULT_KEY_NAME))
}

/// Generate a new Ed25519 SSH keypair if it doesn't exist.
fn ensure_keypair(key_path: &PathBuf) -> Result<PublicKey> {
    let pub_path = key_path.with_extension("pub");

    if key_path.exists() && pub_path.exists() {
        // Load existing public key
        let pub_key_str = std::fs::read_to_string(&pub_path)
            .with_context(|| format!("failed to read {}", pub_path.display()))?;
        let pub_key = PublicKey::from_openssh(&pub_key_str)
            .map_err(|e| anyhow::anyhow!("failed to parse public key: {e}"))?;
        return Ok(pub_key);
    }

    // Ensure .ssh directory exists
    let ssh_dir = ssh_dir()?;
    if !ssh_dir.exists() {
        std::fs::create_dir_all(&ssh_dir)
            .with_context(|| format!("failed to create {}", ssh_dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    // Generate new keypair
    println!("Generating new SSH keypair...");
    let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .map_err(|e| anyhow::anyhow!("failed to generate SSH key: {e}"))?;

    // Save private key
    let private_key_str = private_key
        .to_openssh(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("failed to serialize private key: {e}"))?;
    std::fs::write(key_path, private_key_str.as_bytes())
        .with_context(|| format!("failed to write {}", key_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Save public key
    let public_key = private_key.public_key();
    let pub_key_str = public_key
        .to_openssh()
        .map_err(|e| anyhow::anyhow!("failed to serialize public key: {e}"))?;
    std::fs::write(&pub_path, format!("{pub_key_str}\n"))
        .with_context(|| format!("failed to write {}", pub_path.display()))?;

    println!("Created: {}", key_path.display());
    println!("Created: {}", pub_path.display());

    Ok(public_key.clone())
}

/// Run the SSH credential command.
///
/// This command:
/// 1. Generates an SSH keypair if it doesn't exist
/// 2. Requests a certificate from the Vouch server
/// 3. Stores the certificate alongside the key
pub async fn run(server: &str, key_path: Option<&str>) -> Result<()> {
    // Determine key path
    let key_path = match key_path {
        Some(p) => PathBuf::from(p),
        None => default_key_path()?,
    };

    // Ensure keypair exists
    let public_key = ensure_keypair(&key_path)?;
    let pub_key_str = public_key
        .to_openssh()
        .map_err(|e| anyhow::anyhow!("failed to format public key: {e}"))?;

    // Request certificate from server
    let client = VouchClient::new(server)?;
    let request = SshCertificateRequest {
        public_key: pub_key_str,
    };

    println!("Requesting SSH certificate from server...");
    let response: SshCertificateResponse = client
        .post_authenticated("/v1/credentials/ssh", &request)
        .await
        .context("failed to get SSH certificate")?;

    // Save certificate (the correct extension for SSH certificates is -cert.pub)
    let cert_path = PathBuf::from(format!("{}-cert.pub", key_path.display()));
    std::fs::write(&cert_path, format!("{}\n", response.certificate))
        .with_context(|| format!("failed to write {}", cert_path.display()))?;

    // Calculate expiration time
    let valid_hours = response.valid_for_seconds / 3600;
    let valid_minutes = (response.valid_for_seconds % 3600) / 60;

    println!();
    println!("SSH certificate issued successfully!");
    println!("  Certificate: {}", cert_path.display());
    println!("  Serial: {}", response.serial);
    println!("  Principals: {}", response.principals.join(", "));
    println!("  Valid for: {}h {}m", valid_hours, valid_minutes);

    // Try to store credentials in the agent for SSH agent protocol
    if let Ok(mut agent_client) = vouch_agent::AgentClient::connect().await {
        let key_path_str = key_path.to_string_lossy().to_string();
        let cert_path_str = cert_path.to_string_lossy().to_string();
        if agent_client
            .store_ssh_credentials(&key_path_str, &cert_path_str)
            .await
            .is_ok()
        {
            println!();
            println!("SSH credentials loaded into agent.");
            println!(
                "  SSH agent socket: {}",
                vouch_agent::ssh_agent_socket_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "~/.vouch/ssh-agent.sock".to_string())
            );
            println!();
            println!("To use the agent, set SSH_AUTH_SOCK:");
            println!(
                "  export SSH_AUTH_SOCK={}",
                vouch_agent::ssh_agent_socket_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "~/.vouch/ssh-agent.sock".to_string())
            );
        }
    } else {
        println!();
        println!("To use this certificate, add to your ~/.ssh/config:");
        println!();
        println!("  Host *");
        println!("      IdentityFile {}", key_path.display());
        println!("      CertificateFile {}", cert_path.display());
    }

    Ok(())
}
