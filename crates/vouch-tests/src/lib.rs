// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integration test utilities for Vouch.
//!
//! Shared fixtures for the cross-crate tests in `tests/it`: the CLI's mock
//! FIDO2 device wired to the server's verifier, and the WebAuthn contract
//! validators. The server test harness lives in `vouch_server::test_utils`.

pub mod contracts;
pub mod mock_fido;

pub use mock_fido::IntegrationMockDevice;

// Re-export commonly used types from other crates
pub use vouch_agent::{TestTransport, TestTransportPair};
pub use vouch_cli::{FidoDevice, HttpClient, MockFidoDevice, TestHttpClient};
pub use vouch_server::crypto::webauthn_verify::{CoseVerifier, RealCoseVerifier, TestCoseVerifier};
