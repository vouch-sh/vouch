// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SSH credentials and certificate metadata.

use crate::error::{AgentError, Result};
use jiff::Timestamp;
use ssh_key::{PrivateKey, certificate::Certificate};
use zeroize::Zeroizing;

/// Certificate metadata for cache management.
#[derive(Clone, Debug)]
pub struct CertificateMetadata {
    /// When the certificate was issued.
    pub issued_at: Timestamp,
    /// When the certificate expires.
    pub expires_at: Timestamp,
    /// Certificate serial number.
    pub serial: u64,
    /// Principals (users) the certificate is valid for.
    pub principals: Vec<String>,
}

impl CertificateMetadata {
    /// Create metadata from a certificate.
    pub fn from_certificate(cert: &Certificate) -> Result<Self> {
        // Extract validity times from certificate
        let valid_after = cert.valid_after();
        let valid_before = cert.valid_before();

        // Convert Unix timestamps to jiff::Timestamp
        let issued_at = Timestamp::from_second(i64::try_from(valid_after).unwrap_or(0))
            .map_err(|e| AgentError::Protocol(format!("invalid valid_after timestamp: {e}")))?;
        let expires_at = Timestamp::from_second(i64::try_from(valid_before).unwrap_or(i64::MAX))
            .map_err(|e| AgentError::Protocol(format!("invalid valid_before timestamp: {e}")))?;

        // Extract principals
        let principals = cert
            .valid_principals()
            .iter()
            .map(|s| s.to_string())
            .collect();

        Ok(Self {
            issued_at,
            expires_at,
            serial: cert.serial(),
            principals,
        })
    }

    /// Check if the certificate has expired.
    pub fn is_expired(&self) -> bool {
        let now = Timestamp::now();
        self.expires_at < now
    }
}

/// SSH credentials stored by the agent.
#[derive(Clone)]
pub struct SshCredentials {
    /// User's SSH private key.
    pub(super) private_key: PrivateKey,
    /// Certificate in OpenSSH format (for returning to clients).
    pub(super) certificate_blob: Vec<u8>,
    /// Comment for the key.
    pub(super) comment: String,
    /// Certificate metadata for cache management.
    pub metadata: CertificateMetadata,
}

impl SshCredentials {
    /// Create new SSH credentials.
    pub fn new(
        private_key: PrivateKey,
        certificate: &Certificate,
        comment: String,
    ) -> Result<Self> {
        // Get the certificate blob for the identities response
        let cert_openssh = certificate
            .to_openssh()
            .map_err(|e| AgentError::Protocol(format!("failed to serialize certificate: {e}")))?;
        let certificate_blob = parse_openssh_public_key(&cert_openssh)?;

        // Create metadata from certificate
        let metadata = CertificateMetadata::from_certificate(certificate)?;

        Ok(Self {
            private_key,
            certificate_blob,
            comment,
            metadata,
        })
    }

    /// Load credentials from files.
    pub fn load(key_path: &std::path::Path, cert_path: &std::path::Path) -> Result<Self> {
        // Load private key (zeroized on drop to prevent lingering in memory)
        let key_data = Zeroizing::new(
            std::fs::read_to_string(key_path)
                .map_err(|e| AgentError::Protocol(format!("failed to read private key: {e}")))?,
        );
        let private_key = PrivateKey::from_openssh(&key_data)
            .map_err(|e| AgentError::Protocol(format!("failed to parse private key: {e}")))?;

        // Load certificate
        let cert_data = std::fs::read_to_string(cert_path)
            .map_err(|e| AgentError::Protocol(format!("failed to read certificate: {e}")))?;
        let certificate = Certificate::from_openssh(&cert_data)
            .map_err(|e| AgentError::Protocol(format!("failed to parse certificate: {e}")))?;

        // Generate comment from certificate key ID
        let comment = certificate.key_id().to_string();

        Self::new(private_key, &certificate, comment)
    }

    /// Check if the certificate has expired.
    pub fn is_expired(&self) -> bool {
        self.metadata.is_expired()
    }
}

/// Parse an OpenSSH public key/certificate to get the binary blob.
pub(super) fn parse_openssh_public_key(openssh: &str) -> Result<Vec<u8>> {
    // Format: "ssh-ed25519-cert-v01@openssh.com AAAA... comment"
    let parts: Vec<&str> = openssh.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(AgentError::Protocol(
            "invalid OpenSSH key format".to_string(),
        ));
    }

    let blob = parts
        .get(1)
        .ok_or_else(|| AgentError::Protocol("missing key data".to_string()))?;

    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(blob)
        .map_err(|e| AgentError::Protocol(format!("invalid base64: {e}")))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_openssh_public_key() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKtVCCk2pTkSR/wP3nXdjT4WKXV2+d3pvhYbYUV4Z/Kc test@example.com";
        let result = parse_openssh_public_key(key);
        assert!(result.is_ok());
        let blob = result.unwrap();
        assert!(!blob.is_empty());
    }

    #[test]
    fn test_parse_openssh_public_key_invalid() {
        let result = parse_openssh_public_key("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_certificate_metadata_expiration() {
        // Create a metadata with future expiration
        let future_expires = Timestamp::from_second(Timestamp::now().as_second() + 3600).unwrap();
        let metadata = CertificateMetadata {
            issued_at: Timestamp::now(),
            expires_at: future_expires,
            serial: 1,
            principals: vec!["user".to_string()],
        };

        assert!(!metadata.is_expired());
    }

    #[test]
    fn test_certificate_metadata_expired() {
        // Create a metadata with past expiration
        let past_expires = Timestamp::from_second(Timestamp::now().as_second() - 100).unwrap();
        let metadata = CertificateMetadata {
            issued_at: Timestamp::now(),
            expires_at: past_expires,
            serial: 1,
            principals: vec!["user".to_string()],
        };

        assert!(metadata.is_expired());
    }
}
