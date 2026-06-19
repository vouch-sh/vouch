// SPDX-License-Identifier: Apache-2.0 OR MIT
//! FIDO2 test fixture data structures.
//!
//! This module defines structures for storing and loading real YubiKey
//! registration and authentication data for golden file tests.

use serde::{Deserialize, Serialize};

/// A complete FIDO2 test fixture containing registration and authentication data.
///
/// This can be captured from a real YubiKey using `vouch diag --export-fixture`
/// and used in tests to verify signature validation without a physical device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2Fixture {
    /// Metadata about the fixture
    pub metadata: FixtureMetadata,
    /// Registration data
    pub registration: RegistrationFixture,
    /// Authentication data
    pub authentication: AuthenticationFixture,
}

/// Metadata about the fixture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureMetadata {
    /// Description of the fixture
    pub description: String,
    /// YubiKey model if known (e.g., "YubiKey 5 NFC")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_model: Option<String>,
    /// AAGUID of the authenticator
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aaguid: Option<String>,
    /// When the fixture was created (ISO 8601)
    pub created_at: String,
    /// RP ID used for the fixture
    pub rp_id: String,
}

/// Registration (makeCredential) fixture data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationFixture {
    /// Challenge used for registration (hex-encoded)
    pub challenge_hex: String,
    /// Client data JSON
    pub client_data_json: String,
    /// Credential ID (hex-encoded)
    pub credential_id_hex: String,
    /// COSE public key (hex-encoded)
    pub public_key_cose_hex: String,
    /// Authenticator data (hex-encoded)
    pub auth_data_hex: String,
    /// Attestation object (hex-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_object_hex: Option<String>,
    /// Extracted x coordinate (hex-encoded, 32 bytes for P-256)
    pub x_hex: String,
    /// Extracted y coordinate (hex-encoded, 32 bytes for P-256)
    pub y_hex: String,
}

/// Authentication (getAssertion) fixture data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationFixture {
    /// Challenge used for authentication (hex-encoded)
    pub challenge_hex: String,
    /// Client data JSON
    pub client_data_json: String,
    /// Authenticator data (hex-encoded)
    pub auth_data_hex: String,
    /// Signature (hex-encoded, DER format)
    pub signature_hex: String,
    /// User handle (hex-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_handle_hex: Option<String>,
}

impl Fido2Fixture {
    /// Load a fixture from a JSON file
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let fixture: Self = serde_json::from_str(&content)?;
        Ok(fixture)
    }

    /// Save the fixture to a JSON file
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Get the challenge bytes for authentication
    pub fn authentication_challenge(&self) -> Result<Vec<u8>, hex::FromHexError> {
        hex::decode(&self.authentication.challenge_hex)
    }

    /// Get the credential ID bytes
    pub fn credential_id(&self) -> Result<Vec<u8>, hex::FromHexError> {
        hex::decode(&self.registration.credential_id_hex)
    }

    /// Get the COSE public key bytes
    pub fn public_key_cose(&self) -> Result<Vec<u8>, hex::FromHexError> {
        hex::decode(&self.registration.public_key_cose_hex)
    }

    /// Get the authentication authenticator data bytes
    pub fn auth_authenticator_data(&self) -> Result<Vec<u8>, hex::FromHexError> {
        hex::decode(&self.authentication.auth_data_hex)
    }

    /// Get the authentication signature bytes
    pub fn auth_signature(&self) -> Result<Vec<u8>, hex::FromHexError> {
        hex::decode(&self.authentication.signature_hex)
    }

    /// Get the SEC1 uncompressed public key point (0x04 || x || y)
    pub fn public_key_sec1(&self) -> Result<Vec<u8>, hex::FromHexError> {
        let x = hex::decode(&self.registration.x_hex)?;
        let y = hex::decode(&self.registration.y_hex)?;
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        Ok(point)
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_fixture_serialization() {
        let fixture = Fido2Fixture {
            metadata: FixtureMetadata {
                description: "Test fixture".to_string(),
                device_model: Some("YubiKey 5 NFC".to_string()),
                aaguid: Some("2fc0579f811347eab116bb5a8db9202a".to_string()),
                created_at: "2024-01-01T00:00:00Z".to_string(),
                rp_id: "test.local".to_string(),
            },
            registration: RegistrationFixture {
                challenge_hex: "00".repeat(32),
                client_data_json: r#"{"type":"webauthn.create"}"#.to_string(),
                credential_id_hex: "01".repeat(32),
                public_key_cose_hex: "a5".to_string(),
                auth_data_hex: "00".repeat(37),
                attestation_object_hex: None,
                x_hex: "00".repeat(32),
                y_hex: "00".repeat(32),
            },
            authentication: AuthenticationFixture {
                challenge_hex: "ff".repeat(32),
                client_data_json: r#"{"type":"webauthn.get"}"#.to_string(),
                auth_data_hex: "00".repeat(37),
                signature_hex: "3045".to_string(),
                user_handle_hex: None,
            },
        };

        let json = serde_json::to_string_pretty(&fixture).unwrap();
        let decoded: Fido2Fixture = serde_json::from_str(&json).unwrap();

        assert_eq!(fixture.metadata.rp_id, decoded.metadata.rp_id);
        assert_eq!(
            fixture.registration.credential_id_hex,
            decoded.registration.credential_id_hex
        );
    }
}
