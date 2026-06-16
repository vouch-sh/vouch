// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Vouch CLI library.
//!
//! This crate provides the Vouch CLI for hardware-backed identity,
//! along with reusable components for testing.

pub(crate) mod install_path;
pub(crate) mod utils;

pub mod fapi;
pub mod fido2;
pub mod http;
pub mod i18n;
pub mod posture;

// Re-export commonly used types
pub use fido2::{AuthenticationResult, FidoDevice, RegistrationResult};
pub use http::{HttpClient, HttpResponse};

#[cfg(feature = "test-utils")]
pub use fido2::MockFidoDevice;

#[cfg(feature = "test-utils")]
pub use http::TestHttpClient;
