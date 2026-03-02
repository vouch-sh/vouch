// SPDX-License-Identifier: BUSL-1.1
//! SSH Certificate Authority for signing user SSH certificates.
//!
//! This module provides functionality to:
//! - Generate and manage an Ed25519 CA keypair (Local variant)
//! - Sign using AWS KMS Ed25519 keys (Kms variant)
//! - Sign user SSH public keys as certificates
//! - Extract principals from user email addresses

use anyhow::{Context, Result, bail};
use ssh_key::{
    Algorithm, LineEnding, PrivateKey, PublicKey,
    certificate::{Builder, CertType},
    rand_core::OsRng,
};
use std::path::Path;

use super::kms_signer::KmsSignerEd25519;

/// SSH Certificate Authority.
///
/// Supports two modes:
/// - `Local`: Uses a local Ed25519 private key (file or PEM content)
/// - `Kms`: Uses an AWS KMS Ed25519 key via `kms:Sign`
pub enum SshCa {
    /// Local Ed25519 private key for signing certificates.
    Local {
        /// CA private key for signing certificates.
        private_key: Box<PrivateKey>,
        /// Relying party ID (used in certificate key ID).
        rp_id: String,
    },
    /// AWS KMS Ed25519 key for signing certificates.
    Kms {
        /// KMS signer that calls `kms:Sign` for each operation.
        signer: KmsSignerEd25519,
        /// Relying party ID (used in certificate key ID).
        rp_id: String,
    },
}

impl SshCa {
    /// Load the SSH CA from PEM content directly.
    ///
    /// This is used when the key content is provided via environment variable
    /// rather than a file path. Supports both raw PEM and base64-encoded PEM.
    pub fn from_pem(pem_content: &str, rp_id: &str) -> Result<Self> {
        let pem =
            super::pem::decode_base64_pem(pem_content).context("Failed to decode SSH CA key")?;
        let private_key = PrivateKey::from_openssh(pem.trim())
            .map_err(|e| anyhow::anyhow!("Failed to parse SSH CA key from PEM: {e}"))?;

        tracing::info!(
            "SSH CA loaded from PEM: {}",
            private_key
                .public_key()
                .to_openssh()
                .unwrap_or_else(|_| String::from("<unable to display>"))
        );

        Ok(Self::Local {
            private_key: Box::new(private_key),
            rp_id: rp_id.to_string(),
        })
    }

    /// Create a KMS-backed SSH CA.
    ///
    /// Calls `kms:GetPublicKey` to fetch and cache the Ed25519 public key.
    pub async fn from_kms(
        kms_client: aws_sdk_kms::Client,
        key_id: String,
        rp_id: &str,
    ) -> Result<Self> {
        let signer = KmsSignerEd25519::new(kms_client, key_id).await?;
        Ok(Self::Kms {
            signer,
            rp_id: rp_id.to_string(),
        })
    }

    /// Load or create the SSH CA keypair.
    ///
    /// If the key file exists, it loads the private key.
    /// Otherwise, it generates a new Ed25519 keypair and saves it.
    pub fn load_or_create(key_path: &Path, rp_id: &str) -> Result<Self> {
        let private_key = if key_path.exists() {
            Self::load_private_key(key_path)?
        } else {
            Self::create_and_save_key(key_path, rp_id)?
        };

        Ok(Self::Local {
            private_key: Box::new(private_key),
            rp_id: rp_id.to_string(),
        })
    }

    /// Load from PEM content if provided, otherwise load from file path.
    ///
    /// Priority: PEM content > file path > generate new key
    pub fn load(
        pem_content: Option<&str>,
        key_path: Option<&str>,
        rp_id: &str,
    ) -> Result<Option<Self>> {
        // First, check if PEM content is provided
        if let Some(pem) = pem_content
            && !pem.trim().is_empty()
        {
            return Ok(Some(Self::from_pem(pem, rp_id)?));
        }

        // Second, check if key path is provided
        if let Some(path) = key_path {
            if path.is_empty() {
                tracing::info!("SSH CA disabled (empty key path)");
                return Ok(None);
            }
            return Ok(Some(Self::load_or_create(Path::new(path), rp_id)?));
        }

        // No configuration provided
        Ok(None)
    }

    /// Load an existing private key from file.
    fn load_private_key(path: &Path) -> Result<PrivateKey> {
        let key_data = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read SSH CA key from {}", path.display()))?;
        PrivateKey::from_openssh(&key_data)
            .map_err(|e| anyhow::anyhow!("Failed to parse SSH CA key: {e}"))
    }

    /// Generate a new Ed25519 keypair and save it.
    fn create_and_save_key(path: &Path, rp_id: &str) -> Result<PrivateKey> {
        tracing::info!("Generating new SSH CA keypair at {}", path.display());

        // Generate new Ed25519 keypair
        let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .map_err(|e| anyhow::anyhow!("Failed to generate SSH CA key: {e}"))?;

        // Create parent directory if needed
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {}", parent.display()))?;
        }

        // Save private key with comment
        let comment = format!("vouch-ca@{rp_id}");
        let key_data = private_key
            .to_openssh(LineEnding::LF)
            .map_err(|e| anyhow::anyhow!("Failed to serialize SSH CA key: {e}"))?;
        std::fs::write(path, key_data.as_bytes())
            .with_context(|| format!("Failed to write SSH CA key to {}", path.display()))?;

        // Set restrictive permissions on the key file (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)
                .with_context(|| format!("Failed to set permissions on {}", path.display()))?;
        }

        tracing::info!(
            "SSH CA keypair created: {}",
            private_key
                .public_key()
                .to_openssh()
                .unwrap_or_else(|_| String::from("<unable to display>"))
        );

        // Also save public key alongside private key for convenience
        let pub_path = path.with_extension("pub");
        let pub_key_str = format!(
            "{} {}\n",
            private_key
                .public_key()
                .to_openssh()
                .map_err(|e| anyhow::anyhow!("Failed to serialize CA public key: {e}"))?,
            comment
        );
        std::fs::write(&pub_path, pub_key_str)
            .with_context(|| format!("Failed to write CA public key to {}", pub_path.display()))?;

        Ok(private_key)
    }

    /// Get the CA public key in OpenSSH format.
    pub fn public_key(&self) -> Result<String> {
        match self {
            Self::Local { private_key, .. } => private_key
                .public_key()
                .to_openssh()
                .map_err(|e| anyhow::anyhow!("Failed to format CA public key: {e}")),
            Self::Kms { signer, .. } => signer
                .ssh_public_key()?
                .to_openssh()
                .map_err(|e| anyhow::anyhow!("Failed to format KMS CA public key: {e}")),
        }
    }

    /// Get the CA public key comment.
    #[must_use]
    pub fn public_key_comment(&self) -> String {
        let rp_id = match self {
            Self::Local { rp_id, .. } | Self::Kms { rp_id, .. } => rp_id,
        };
        format!("vouch-ca@{rp_id}")
    }

    /// Sign a user's public key and return an SSH certificate.
    ///
    /// # Arguments
    /// * `user_public_key` - The user's SSH public key in OpenSSH format
    /// * `user_email` - The user's email address (used for principals)
    /// * `valid_seconds` - How long the certificate should be valid (in seconds)
    ///
    /// # Returns
    /// The signed SSH certificate in OpenSSH format
    pub fn sign_certificate(
        &self,
        user_public_key: &str,
        user_email: &str,
        valid_seconds: u64,
    ) -> Result<SignedCertificate> {
        // Parse the user's public key
        let user_key = PublicKey::from_openssh(user_public_key)
            .map_err(|e| anyhow::anyhow!("Invalid SSH public key: {e}"))?;

        // Extract principals from email
        let principals = Self::extract_principals(user_email)?;
        if principals.is_empty() {
            bail!("Could not extract valid principals from email");
        }

        // Generate serial number: timestamp in upper 32 bits, random in lower 32
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut rand_bytes = [0u8; 4];
        aws_lc_rs::rand::fill(&mut rand_bytes)
            .map_err(|_| anyhow::anyhow!("Failed to generate random serial bytes"))?;
        let rand_part = u32::from_be_bytes(rand_bytes) as u64;
        let serial = (now << 32) | rand_part;

        // Calculate validity period
        let valid_after = now;
        let valid_before = now.saturating_add(valid_seconds);

        // Create key ID (identifies the certificate)
        let rp_id = match self {
            Self::Local { rp_id, .. } | Self::Kms { rp_id, .. } => rp_id,
        };
        let key_id = format!("{user_email}@{rp_id}");

        // Build the certificate
        let mut builder =
            Builder::new_with_random_nonce(&mut OsRng, user_key, valid_after, valid_before)
                .map_err(|e| anyhow::anyhow!("Failed to create certificate builder: {e}"))?;

        builder
            .serial(serial)
            .map_err(|e| anyhow::anyhow!("Failed to set serial: {e}"))?;
        builder
            .key_id(&key_id)
            .map_err(|e| anyhow::anyhow!("Failed to set key ID: {e}"))?;
        builder
            .cert_type(CertType::User)
            .map_err(|e| anyhow::anyhow!("Failed to set cert type: {e}"))?;

        for principal in &principals {
            builder
                .valid_principal(principal)
                .map_err(|e| anyhow::anyhow!("Failed to add principal {principal}: {e}"))?;
        }

        // Add standard OpenSSH extensions for user certificates
        builder
            .extension("permit-X11-forwarding", "")
            .map_err(|e| anyhow::anyhow!("Failed to add extension: {e}"))?;
        builder
            .extension("permit-agent-forwarding", "")
            .map_err(|e| anyhow::anyhow!("Failed to add extension: {e}"))?;
        builder
            .extension("permit-port-forwarding", "")
            .map_err(|e| anyhow::anyhow!("Failed to add extension: {e}"))?;
        builder
            .extension("permit-pty", "")
            .map_err(|e| anyhow::anyhow!("Failed to add extension: {e}"))?;
        builder
            .extension("permit-user-rc", "")
            .map_err(|e| anyhow::anyhow!("Failed to add extension: {e}"))?;

        // Sign the certificate — both variants produce ssh-ed25519 certificates
        let certificate = match self {
            Self::Local { private_key, .. } => builder
                .sign(private_key.as_ref())
                .map_err(|e| anyhow::anyhow!("Failed to sign certificate: {e}"))?,
            Self::Kms { signer, .. } => builder
                .sign(signer)
                .map_err(|e| anyhow::anyhow!("Failed to sign certificate via KMS: {e}"))?,
        };

        // Convert to OpenSSH format
        let cert_string = certificate
            .to_openssh()
            .map_err(|e| anyhow::anyhow!("Failed to serialize certificate: {e}"))?;

        Ok(SignedCertificate {
            certificate: cert_string,
            serial,
            principals,
            valid_for_seconds: valid_seconds,
        })
    }

    /// Extract principals (usernames) from an email address.
    ///
    /// Returns two principals:
    /// 1. The full email address (user@domain.com)
    /// 2. The username part (user)
    fn extract_principals(email: &str) -> Result<Vec<String>> {
        let email = email.trim().to_lowercase();

        // Validate email format
        let at_pos = email
            .find('@')
            .ok_or_else(|| anyhow::anyhow!("Invalid email format: {email}"))?;
        if email.is_empty() || at_pos == 0 {
            bail!("Invalid email format: {email}");
        }

        let username = email
            .get(..at_pos)
            .ok_or_else(|| anyhow::anyhow!("Invalid email format: {email}"))?;

        // Return both the full email and the username as principals
        // This allows SSH hosts to accept either format
        Ok(vec![email.clone(), username.to_string()])
    }
}

/// A signed SSH certificate with metadata.
pub struct SignedCertificate {
    /// The certificate in OpenSSH format.
    pub certificate: String,
    /// Certificate serial number.
    pub serial: u64,
    /// Valid principals (usernames).
    pub principals: Vec<String>,
    /// Validity period in seconds.
    pub valid_for_seconds: u64,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_principals_valid() {
        let principals = SshCa::extract_principals("john@example.com").unwrap();
        assert_eq!(principals.len(), 2);
        assert_eq!(principals.first(), Some(&"john@example.com".to_string()));
        assert_eq!(principals.get(1), Some(&"john".to_string()));
    }

    #[test]
    fn test_extract_principals_uppercase() {
        let principals = SshCa::extract_principals("John.Doe@Example.COM").unwrap();
        assert_eq!(principals.len(), 2);
        assert_eq!(
            principals.first(),
            Some(&"john.doe@example.com".to_string())
        );
        assert_eq!(principals.get(1), Some(&"john.doe".to_string()));
    }

    #[test]
    fn test_extract_principals_invalid() {
        assert!(SshCa::extract_principals("notanemail").is_err());
        assert!(SshCa::extract_principals("").is_err());
        assert!(SshCa::extract_principals("@domain.com").is_err());
    }

    #[test]
    fn test_certificate_includes_standard_extensions() {
        use ssh_key::certificate::Certificate;

        // Generate a CA keypair
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let ca = SshCa::Local {
            private_key: Box::new(ca_key),
            rp_id: "test.example.com".to_string(),
        };

        // Generate a user keypair
        let user_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let user_pub = user_key.public_key().to_openssh().unwrap();

        // Sign a certificate
        let signed = ca
            .sign_certificate(&user_pub, "alice@example.com", 3600)
            .unwrap();

        // Parse the certificate back
        let cert = Certificate::from_openssh(&signed.certificate).unwrap();
        let extensions = cert.extensions();

        // Verify all five standard OpenSSH extensions are present
        let expected = [
            "permit-X11-forwarding",
            "permit-agent-forwarding",
            "permit-port-forwarding",
            "permit-pty",
            "permit-user-rc",
        ];
        for ext in &expected {
            assert!(
                extensions.get(*ext).is_some(),
                "Missing expected extension: {ext}"
            );
        }
    }
}
