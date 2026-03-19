// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SAML 2.0 Service Provider stub.
//!
//! This module provides the `SamlProvider` type used by the `UpstreamIdp` enum.
//! Actual SAML logic (metadata parsing, `AuthnRequest` generation, response
//! validation) will be implemented in Phase 2.

/// SAML 2.0 Service Provider (stub).
///
/// In Phase 2, this will contain `IdpMetadata`, SP entity ID, ACS URL,
/// and attribute mapping configuration.
#[derive(Debug)]
pub struct SamlProvider {
    /// IdP entity ID (used for brand detection).
    pub entity_id: String,
}
