// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Vouch CLI library.
//!
//! This crate provides the Vouch CLI for hardware-backed identity,
//! along with reusable components for testing.

pub mod client;
pub mod config;
pub mod fido2;
pub mod http;

// Re-export commonly used types
pub use client::VouchClient;
pub use fido2::{AuthenticationResult, FidoDevice, RegistrationResult, YubiKey};
pub use http::{HttpClient, HttpClientExt, HttpResponse, ReqwestClient};

#[cfg(feature = "test-utils")]
pub use fido2::MockFidoDevice;

#[cfg(feature = "test-utils")]
pub use http::TestHttpClient;
