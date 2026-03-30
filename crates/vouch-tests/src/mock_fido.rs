// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Mock FIDO2 device for integration testing.
//!
//! This module provides additional helper methods for integration testing
//! on top of the MockFidoDevice from vouch-cli.

use anyhow::Result;

use vouch_cli::{AuthenticationResult, FidoDevice, MockFidoDevice, RegistrationResult};

/// Extended mock device for integration testing.
///
/// This wraps MockFidoDevice with additional helper methods
/// specific to integration testing scenarios.
pub struct IntegrationMockDevice {
    inner: MockFidoDevice,
}

impl IntegrationMockDevice {
    /// Create a new integration mock device.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: MockFidoDevice::new(),
        }
    }

    /// Get the underlying mock device.
    #[must_use]
    pub fn device(&self) -> &MockFidoDevice {
        &self.inner
    }

    /// Get the public key in COSE format.
    #[must_use]
    pub fn public_key_cose(&self) -> Vec<u8> {
        self.inner.public_key_cose()
    }

    /// Get the credential ID.
    #[must_use]
    pub fn credential_id(&self) -> Vec<u8> {
        self.inner.credential_id().to_vec()
    }

    /// Get the current counter.
    #[must_use]
    pub fn counter(&self) -> u32 {
        self.inner.counter()
    }

    /// Perform registration with the mock device.
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails.
    pub fn register(
        &self,
        rp_id: &str,
        challenge: &[u8],
        user_id: &[u8],
        user_name: &str,
    ) -> Result<RegistrationResult> {
        self.inner
            .register(rp_id, "Test RP", challenge, user_id, user_name, "", &[])
    }

    /// Perform authentication with the mock device.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails.
    pub fn authenticate(&self, rp_id: &str, challenge: &[u8]) -> Result<AuthenticationResult> {
        self.inner.authenticate(rp_id, challenge, "")
    }
}

impl Default for IntegrationMockDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for IntegrationMockDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntegrationMockDevice")
            .field("credential_id", &hex::encode(self.credential_id()))
            .field("counter", &self.counter())
            .finish()
    }
}
