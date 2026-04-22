// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SSH certificate credential command.
//!
//! Generates a local SSH keypair (if not exists), requests a certificate
//! from the Vouch server, and stores the certificate alongside the key.

use anyhow::{Context, Result};
use ssh_key::{
    Algorithm, LineEnding, PrivateKey, PublicKey, certificate::Certificate, rand_core::OsRng,
};
use std::path::{Path, PathBuf};
use vouch_common::{SshCertificateRequest, SshCertificateResponse};

use crate::client::VouchClient;

/// Default SSH key filename (without extension).
const DEFAULT_KEY_NAME: &str = "id_ed25519_vouch";

/// What happened when ensuring a keypair exists.
pub(crate) enum KeypairAction {
    /// An existing keypair was loaded.
    Loaded(PublicKey),
    /// A new keypair was generated.
    Generated(PublicKey),
}

impl KeypairAction {
    /// Get the public key regardless of action.
    pub(crate) fn public_key(&self) -> &PublicKey {
        match self {
            Self::Loaded(pk) | Self::Generated(pk) => pk,
        }
    }
}

/// Get the SSH directory path (~/.ssh).
pub(crate) fn ssh_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".ssh"))
}

/// Get the default SSH key path.
pub(crate) fn default_key_path() -> Result<PathBuf> {
    Ok(ssh_dir()?.join(DEFAULT_KEY_NAME))
}

/// Generate a new Ed25519 SSH keypair if it doesn't exist.
/// Returns what action was taken (loaded existing vs generated new).
pub(crate) fn ensure_keypair(key_path: &Path) -> Result<KeypairAction> {
    let pub_path = key_path.with_extension("pub");

    if key_path.exists() && pub_path.exists() {
        // Load existing public key
        let pub_key_str = std::fs::read_to_string(&pub_path)
            .with_context(|| format!("failed to read {}", pub_path.display()))?;
        let pub_key = PublicKey::from_openssh(&pub_key_str)
            .map_err(|e| anyhow::anyhow!("failed to parse public key: {e}"))?;
        return Ok(KeypairAction::Loaded(pub_key));
    }

    // Ensure .ssh directory exists with secure permissions
    crate::utils::ensure_secure_dir(&ssh_dir()?)?;

    // Generate new keypair
    let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .map_err(|e| anyhow::anyhow!("failed to generate SSH key: {e}"))?;

    // Save private key (atomic + secure permissions)
    let private_key_str = private_key
        .to_openssh(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("failed to serialize private key: {e}"))?;
    crate::utils::atomic_write_secure(key_path, private_key_str.as_bytes())
        .with_context(|| format!("failed to write {}", key_path.display()))?;

    // Save public key (atomic)
    let public_key = private_key.public_key();
    let pub_key_str = public_key
        .to_openssh()
        .map_err(|e| anyhow::anyhow!("failed to serialize public key: {e}"))?;
    crate::utils::atomic_write(&pub_path, format!("{pub_key_str}\n").as_bytes())
        .with_context(|| format!("failed to write {}", pub_path.display()))?;

    Ok(KeypairAction::Generated(public_key.clone()))
}

/// Result of SSH certificate provisioning.
pub(crate) struct SshProvisionResult {
    /// Path to the private key.
    pub key_path: PathBuf,
    /// Path to the certificate file.
    pub cert_path: PathBuf,
    /// Server response with certificate details.
    pub response: SshCertificateResponse,
    /// Whether a new keypair was generated (vs loading existing).
    pub keypair_generated: bool,
    /// Whether the result was returned from on-disk cache (no server call).
    pub cached: bool,
}

/// Check if an existing certificate on disk is still valid with enough time remaining.
///
/// Returns `Some(SshProvisionResult)` if the certificate exists, is not expired,
/// and has more than `SSH_CERT_REFRESH_THRESHOLD_SECS` remaining. Returns `None`
/// otherwise so the caller falls through to server issuance.
fn check_existing_certificate(key_path: &Path) -> Option<SshProvisionResult> {
    let cert_path_str = format!("{}-cert.pub", key_path.display());
    let cert_data = std::fs::read_to_string(&cert_path_str).ok()?;
    let cert = Certificate::from_openssh(cert_data.trim()).ok()?;

    let valid_before = cert.valid_before();
    let valid_before_i64 = i64::try_from(valid_before).unwrap_or(i64::MAX);
    let now_unix = jiff::Timestamp::now().as_second();

    if valid_before_i64 <= now_unix {
        tracing::debug!("Cached SSH certificate is expired");
        return None;
    }

    let remaining_secs = valid_before_i64 - now_unix;
    if remaining_secs <= vouch_common::SSH_CERT_REFRESH_THRESHOLD_SECS {
        tracing::debug!(
            remaining_secs,
            threshold = vouch_common::SSH_CERT_REFRESH_THRESHOLD_SECS,
            "Cached SSH certificate is below refresh threshold"
        );
        return None;
    }

    tracing::debug!(remaining_secs, "Using cached SSH certificate");

    let principals: Vec<String> = cert
        .valid_principals()
        .iter()
        .map(|s| s.to_string())
        .collect();
    let response = SshCertificateResponse {
        certificate: cert_data.trim().to_string(),
        valid_for_seconds: u64::try_from(remaining_secs).unwrap_or(0),
        principals,
        serial: cert.serial(),
    };

    Some(SshProvisionResult {
        key_path: key_path.to_path_buf(),
        cert_path: PathBuf::from(cert_path_str),
        response,
        keypair_generated: false,
        cached: true,
    })
}

/// Core provisioning: ensure keypair, request cert from server, write cert to disk.
/// No stdout output — callers decide what to print.
///
/// When `fapi_key` is provided, the client uses it directly for DPoP proof
/// generation instead of reloading from the keychain. This avoids a storage
/// round-trip that can fail on some platforms.
pub(crate) async fn provision_ssh_certificate(
    server: &str,
    key_path: Option<&str>,
    fapi_key: Option<vouch_cli::fapi::ClientKey>,
    force: bool,
) -> Result<SshProvisionResult> {
    // Determine key path
    let key_path = match key_path {
        Some(p) => PathBuf::from(p),
        None => default_key_path()?,
    };

    // Check if existing certificate is still valid (skip server call)
    if !force && let Some(cached) = check_existing_certificate(&key_path) {
        return Ok(cached);
    }

    // Ensure keypair exists
    let action = ensure_keypair(&key_path)?;
    let keypair_generated = matches!(action, KeypairAction::Generated(_));
    let public_key = action.public_key();
    let pub_key_str = public_key
        .to_openssh()
        .map_err(|e| anyhow::anyhow!("failed to format public key: {e}"))?;

    // Request certificate from server
    let mut client = VouchClient::new(server).await?;
    if let Some(key) = fapi_key {
        client.set_fapi_key(key);
    }
    let request = SshCertificateRequest {
        public_key: pub_key_str,
    };

    let response: SshCertificateResponse = client
        .post_authenticated("/v1/credentials/ssh", &request)
        .await
        .context("failed to get SSH certificate")?;

    // Save certificate (atomic)
    let cert_path = PathBuf::from(format!("{}-cert.pub", key_path.display()));
    crate::utils::atomic_write(&cert_path, format!("{}\n", response.certificate).as_bytes())
        .with_context(|| format!("failed to write {}", cert_path.display()))?;

    Ok(SshProvisionResult {
        key_path,
        cert_path,
        response,
        keypair_generated,
        cached: false,
    })
}

/// Auto-provision SSH certificate after authentication (best-effort).
///
/// When `fapi_key` is provided, passes it to the client so DPoP proofs
/// are generated without reloading from the keychain.
/// Returns `true` if provisioning succeeded.
pub(crate) async fn auto_provision(
    server: &str,
    expires_at: &str,
    fapi_key: Option<vouch_cli::fapi::ClientKey>,
) -> bool {
    match provision_ssh_certificate(server, None, fapi_key, false).await {
        Ok(result) => {
            // Store in agent with session linkage (Unix only)
            #[cfg(unix)]
            if let Ok(mut agent) = vouch_agent::AgentClient::connect().await {
                let _ = agent
                    .store_ssh_credentials_with_session(
                        &result.key_path.to_string_lossy(),
                        &result.cert_path.to_string_lossy(),
                        Some(expires_at),
                        Some(server),
                    )
                    .await;
            }

            if result.cached {
                let valid_hours = result.response.valid_for_seconds / 3600;
                let valid_minutes = (result.response.valid_for_seconds % 3600) / 60;
                println!(
                    "SSH certificate still valid ({}h {}m remaining).",
                    valid_hours, valid_minutes
                );
            } else {
                if result.keypair_generated {
                    println!("Generated SSH keypair: {}", result.key_path.display());
                }

                let valid_hours = result.response.valid_for_seconds / 3600;
                let valid_minutes = (result.response.valid_for_seconds % 3600) / 60;
                println!(
                    "SSH certificate provisioned (valid for {}h {}m).",
                    valid_hours, valid_minutes
                );
            }
            true
        }
        Err(e) => {
            let err_str = format!("{e}");
            // Silence errors that indicate the server doesn't support SSH certs
            if err_str.contains("404") || err_str.contains("501") {
                tracing::debug!("Server does not support SSH certificates: {e}");
            } else {
                tracing::warn!("Auto SSH provisioning failed: {e}");
                println!("SSH certificate not provisioned ({e}). Run: vouch credential ssh");
            }
            false
        }
    }
}

/// Run the SSH credential command.
///
/// This command:
/// 1. Generates an SSH keypair if it doesn't exist
/// 2. Requests a certificate from the Vouch server
/// 3. Stores the certificate alongside the key
pub(crate) async fn run(server: &str, key_path: Option<&str>, force: bool) -> Result<()> {
    let result = provision_ssh_certificate(server, key_path, None, force).await?;

    if result.cached {
        let valid_hours = result.response.valid_for_seconds / 3600;
        let valid_minutes = (result.response.valid_for_seconds % 3600) / 60;

        println!("SSH certificate still valid.");
        println!("  Certificate: {}", result.cert_path.display());
        println!("  Serial: {}", result.response.serial);
        println!("  Principals: {}", result.response.principals.join(", "));
        println!("  Remaining: {}h {}m", valid_hours, valid_minutes);
        println!();
        println!("Use --force to re-issue.");
        return Ok(());
    }

    if result.keypair_generated {
        println!("Generating new SSH keypair...");
        println!("Created: {}", result.key_path.display());
        println!(
            "Created: {}",
            result.key_path.with_extension("pub").display()
        );
    }

    // Calculate expiration time
    let valid_hours = result.response.valid_for_seconds / 3600;
    let valid_minutes = (result.response.valid_for_seconds % 3600) / 60;

    println!();
    println!("SSH certificate issued successfully!");
    println!("  Certificate: {}", result.cert_path.display());
    println!("  Serial: {}", result.response.serial);
    println!("  Principals: {}", result.response.principals.join(", "));
    println!("  Valid for: {}h {}m", valid_hours, valid_minutes);

    // Try to store credentials in the agent for SSH agent protocol (Unix only)
    #[cfg(unix)]
    {
        if let Ok(mut agent_client) = vouch_agent::AgentClient::connect().await {
            let key_path_str = result.key_path.to_string_lossy().to_string();
            let cert_path_str = result.cert_path.to_string_lossy().to_string();
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
            println!("      IdentityFile {}", result.key_path.display());
            println!("      CertificateFile {}", result.cert_path.display());
        }
    }
    #[cfg(not(unix))]
    {
        println!();
        println!("To use this certificate, add to your ~/.ssh/config:");
        println!();
        println!("  Host *");
        println!("      IdentityFile {}", result.key_path.display());
        println!("      CertificateFile {}", result.cert_path.display());
    }

    Ok(())
}
