// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integration test utilities for Vouch.
//!
//! This crate provides test harnesses and utilities for integration testing
//! across the Vouch workspace.

pub mod harness;
pub mod mock_fido;

pub use harness::TestHarness;
pub use mock_fido::IntegrationMockDevice;

// Re-export commonly used types from other crates
pub use vouch_agent::{AgentTransport, TestTransport, TestTransportPair};
pub use vouch_cli::{FidoDevice, HttpClient, MockFidoDevice, TestHttpClient};
pub use vouch_common::{Clock, SystemClock, TestClock};
pub use vouch_server::{CoseVerifier, RealCoseVerifier, TestCoseVerifier};
