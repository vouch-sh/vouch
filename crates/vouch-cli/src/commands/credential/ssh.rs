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

/// How the SSH certificate was obtained.
pub(crate) enum ProvisionOutcome {
    /// Certificate served from on-disk cache; no server call.
    Cached,
    /// Certificate freshly issued from the server.
    Issued,
    /// Certificate freshly issued; a new keypair was also generated.
    IssuedWithNewKeypair,
}

/// Result of SSH certificate provisioning.
pub(crate) struct SshProvisionResult {
    /// Path to the private key.
    pub key_path: PathBuf,
    /// Path to the certificate file.
    pub cert_path: PathBuf,
    /// Certificate details (from server or reconstructed from disk).
    pub response: SshCertificateResponse,
    /// How the certificate was obtained.
    pub outcome: ProvisionOutcome,
}

/// Format seconds as a human-readable "Xh Ym" duration string.
fn format_duration(secs: u64) -> String {
    // 3600 and 60 are non-zero; unwrap_or arms are unreachable.
    let hours = secs.checked_div(3600).unwrap_or(0);
    let minutes = (secs % 3600).checked_div(60).unwrap_or(0);
    format!("{hours}h {minutes}m")
}

/// Check if an existing certificate on disk is still valid with
/// enough time remaining.
///
/// Returns `Some(SshProvisionResult)` if the certificate exists, is
/// not expired, and has more than `SSH_CERT_REFRESH_THRESHOLD_SECS`
/// remaining. Returns `None` otherwise so the caller falls through
/// to server issuance.
fn check_existing_certificate(key_path: &Path) -> Option<SshProvisionResult> {
    // Verify the private key still exists — a cert without its key
    // is useless
    if !key_path.exists() {
        tracing::debug!("Private key missing, skipping certificate cache");
        return None;
    }

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

    let remaining_secs = valid_before_i64.saturating_sub(now_unix);
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
        outcome: ProvisionOutcome::Cached,
    })
}

/// Core provisioning: ensure keypair, request cert from server, write
/// cert to disk. No stdout output — callers decide what to print.
///
/// When `fapi_key` is provided, the client uses it directly for DPoP
/// proof generation instead of reloading from the keychain. This avoids
/// a storage round-trip that can fail on some platforms.
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
    let outcome = match action {
        KeypairAction::Generated(_) => ProvisionOutcome::IssuedWithNewKeypair,
        KeypairAction::Loaded(_) => ProvisionOutcome::Issued,
    };
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
        outcome,
    })
}

/// Auto-provision SSH certificate after authentication (best-effort).
///
/// When `fapi_key` is provided, passes it to the client so DPoP proofs
/// are generated without reloading from the keychain.
/// Returns `true` if provisioning succeeded.
pub(crate) async fn auto_provision(
    server: &str,
    #[cfg_attr(
        not(unix),
        expect(unused_variables, reason = "parameter consumed only under cfg(unix)")
    )]
    expires_at: &str,
    fapi_key: Option<vouch_cli::fapi::ClientKey>,
) -> bool {
    match provision_ssh_certificate(server, None, fapi_key, false).await {
        Ok(result) => {
            // Store in agent with session linkage (Unix only)
            #[cfg(unix)]
            if let Ok(mut agent) = vouch_agent::AgentClient::connect().await {
                // Best-effort agent push; SSH cert is already on disk.
                let _stored = agent
                    .store_ssh_credentials_with_session(
                        &result.key_path.to_string_lossy(),
                        &result.cert_path.to_string_lossy(),
                        Some(expires_at),
                        Some(server),
                    )
                    .await;
            }

            match result.outcome {
                ProvisionOutcome::Cached => {
                    println!(
                        "SSH certificate still valid ({} remaining).",
                        format_duration(result.response.valid_for_seconds)
                    );
                }
                ProvisionOutcome::IssuedWithNewKeypair => {
                    println!("Generated SSH keypair: {}", result.key_path.display());
                    println!(
                        "SSH certificate provisioned (valid for {}).",
                        format_duration(result.response.valid_for_seconds)
                    );
                }
                ProvisionOutcome::Issued => {
                    println!(
                        "SSH certificate provisioned (valid for {}).",
                        format_duration(result.response.valid_for_seconds)
                    );
                }
            }
            true
        }
        Err(e) => {
            let err_str = format!("{e}");
            // Silence errors that indicate the server doesn't
            // support SSH certs
            if err_str.contains("404") || err_str.contains("501") {
                tracing::debug!("Server does not support SSH certificates: {e}");
            } else {
                tracing::warn!("Auto SSH provisioning failed: {e}");
                println!(
                    "SSH certificate not provisioned ({e}). \
                     Run: vouch credential ssh"
                );
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

    if matches!(result.outcome, ProvisionOutcome::Cached) {
        // Ensure agent has credentials loaded even for a cached cert.
        // Uses store_ssh_credentials (without session linkage) because
        // `run()` is invoked standalone and has no session context.
        // The agent's lazy-load and background refresh handle session
        // association independently.
        #[cfg(unix)]
        if let Ok(mut agent_client) = vouch_agent::AgentClient::connect().await {
            let key_str = result.key_path.to_string_lossy().to_string();
            let cert_str = result.cert_path.to_string_lossy().to_string();
            // Best-effort agent push; SSH cert is already on disk.
            let _stored = agent_client
                .store_ssh_credentials(&key_str, &cert_str)
                .await;
        }

        println!("SSH certificate still valid.");
        println!("  Certificate: {}", result.cert_path.display());
        println!("  Serial: {}", result.response.serial);
        println!("  Principals: {}", result.response.principals.join(", "));
        println!(
            "  Remaining: {}",
            format_duration(result.response.valid_for_seconds)
        );
        println!();
        println!("Use --force to re-issue.");
        return Ok(());
    }

    if matches!(result.outcome, ProvisionOutcome::IssuedWithNewKeypair) {
        println!("Generating new SSH keypair...");
        println!("Created: {}", result.key_path.display());
        println!(
            "Created: {}",
            result.key_path.with_extension("pub").display()
        );
    }

    println!();
    println!("SSH certificate issued successfully!");
    println!("  Certificate: {}", result.cert_path.display());
    println!("  Serial: {}", result.response.serial);
    println!("  Principals: {}", result.response.principals.join(", "));
    println!(
        "  Valid for: {}",
        format_duration(result.response.valid_for_seconds)
    );

    // Try to store credentials in the agent (Unix only)
    #[cfg(unix)]
    {
        if let Ok(mut agent_client) = vouch_agent::AgentClient::connect().await {
            let key_str = result.key_path.to_string_lossy().to_string();
            let cert_str = result.cert_path.to_string_lossy().to_string();
            if agent_client
                .store_ssh_credentials(&key_str, &cert_str)
                .await
                .is_ok()
            {
                println!();
                println!("SSH credentials loaded into agent.");
                println!(
                    "  SSH agent socket: {}",
                    vouch_agent::ssh_agent_socket_path().map_or_else(
                        |_| "~/.vouch/ssh-agent.sock".to_string(),
                        |p| p.display().to_string()
                    )
                );
                println!();
                println!("To use the agent, set SSH_AUTH_SOCK:");
                println!(
                    "  export SSH_AUTH_SOCK={}",
                    vouch_agent::ssh_agent_socket_path().map_or_else(
                        |_| "~/.vouch/ssh-agent.sock".to_string(),
                        |p| p.display().to_string()
                    )
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

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use ssh_key::certificate::Builder;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Create a test certificate with the given validity window and
    /// write it to `cert_path`. Also writes the private key to
    /// `key_path`.
    fn write_test_cert(key_path: &Path, cert_path: &Path, valid_after: u64, valid_before: u64) {
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let user_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();

        // Write private key
        let key_str = user_key.to_openssh(LineEnding::LF).unwrap();
        std::fs::write(key_path, key_str.as_bytes()).unwrap();

        // Build and sign certificate
        let mut builder = Builder::new_with_random_nonce(
            &mut OsRng,
            user_key.public_key(),
            valid_after,
            valid_before,
        )
        .unwrap();
        builder.serial(42).unwrap();
        builder.key_id("test@example.com").unwrap();
        builder.valid_principal("testuser").unwrap();

        let cert = builder.sign(&ca_key).unwrap();
        let cert_str = cert.to_openssh().unwrap();
        std::fs::write(cert_path, format!("{cert_str}\n")).unwrap();
    }

    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn test_check_existing_certificate_valid() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id_ed25519_vouch");
        let cert_path_str = format!("{}-cert.pub", key_path.display());
        let cert_path = Path::new(&cert_path_str);

        let now = now_unix();
        // Certificate valid for 8 hours — well above the 1-hour
        // threshold
        write_test_cert(&key_path, cert_path, now - 60, now + 8 * 3600);

        let result = check_existing_certificate(&key_path);
        assert!(result.is_some(), "expected cache hit for valid cert");

        let result = result.unwrap();
        assert!(matches!(result.outcome, ProvisionOutcome::Cached));
        assert_eq!(result.response.serial, 42);
        assert_eq!(result.response.principals, vec!["testuser"]);
        assert!(result.response.valid_for_seconds > 7 * 3600);
    }

    #[test]
    fn test_check_existing_certificate_expired() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id_ed25519_vouch");
        let cert_path_str = format!("{}-cert.pub", key_path.display());
        let cert_path = Path::new(&cert_path_str);

        let now = now_unix();
        // Certificate expired 10 minutes ago
        write_test_cert(&key_path, cert_path, now - 3600, now - 600);

        let result = check_existing_certificate(&key_path);
        assert!(result.is_none(), "expected None for expired cert");
    }

    #[test]
    fn test_check_existing_certificate_below_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id_ed25519_vouch");
        let cert_path_str = format!("{}-cert.pub", key_path.display());
        let cert_path = Path::new(&cert_path_str);

        let now = now_unix();
        // Certificate has 30 minutes remaining — below the 1-hour
        // threshold
        write_test_cert(&key_path, cert_path, now - 3600, now + 30 * 60);

        let result = check_existing_certificate(&key_path);
        assert!(result.is_none(), "expected None when below threshold");
    }

    #[test]
    fn test_check_existing_certificate_at_threshold_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id_ed25519_vouch");
        let cert_path_str = format!("{}-cert.pub", key_path.display());
        let cert_path = Path::new(&cert_path_str);

        let now = now_unix();
        // Certificate has exactly 1 hour remaining — at the boundary
        // (uses <=, so exactly-at-threshold should return None)
        write_test_cert(&key_path, cert_path, now - 3600, now + 3600);

        let result = check_existing_certificate(&key_path);
        assert!(
            result.is_none(),
            "expected None at exact threshold boundary"
        );
    }

    #[test]
    fn test_check_existing_certificate_missing_key() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id_ed25519_vouch");
        let cert_path_str = format!("{}-cert.pub", key_path.display());
        let cert_path = Path::new(&cert_path_str);

        let now = now_unix();
        // Write cert but NOT the private key
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let user_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut builder = Builder::new_with_random_nonce(
            &mut OsRng,
            user_key.public_key(),
            now - 60,
            now + 8 * 3600,
        )
        .unwrap();
        builder.serial(1).unwrap();
        builder.key_id("test").unwrap();
        builder.valid_principal("testuser").unwrap();
        let cert = builder.sign(&ca_key).unwrap();
        std::fs::write(cert_path, cert.to_openssh().unwrap()).unwrap();

        let result = check_existing_certificate(&key_path);
        assert!(
            result.is_none(),
            "expected None when private key is missing"
        );
    }

    #[test]
    fn test_check_existing_certificate_no_cert_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id_ed25519_vouch");

        // Write private key but no cert file
        let user_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let key_str = user_key.to_openssh(LineEnding::LF).unwrap();
        std::fs::write(&key_path, key_str.as_bytes()).unwrap();

        let result = check_existing_certificate(&key_path);
        assert!(result.is_none(), "expected None when cert file is missing");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(0), "0h 0m");
        assert_eq!(format_duration(3600), "1h 0m");
        assert_eq!(format_duration(5400), "1h 30m");
        assert_eq!(format_duration(8 * 3600 + 15 * 60), "8h 15m");
        assert_eq!(format_duration(59), "0h 0m");
        assert_eq!(format_duration(60), "0h 1m");
    }
}
