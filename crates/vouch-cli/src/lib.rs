// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Vouch CLI library.
//!
//! This crate provides the Vouch CLI for hardware-backed identity,
//! along with reusable components for testing.

// File replacement goes through `vouch_common::fs::atomic_write`, which keeps
// symlinks. `disallowed_methods` is configured in `.clippy.toml` and left at
// `allow` workspace-wide; this is where it is switched on. Clock reads carry an
// `#[expect]`: a client has no request instant to anchor to.
#![warn(clippy::disallowed_methods)]
#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "stdout and stderr are this binary's user interface"
)]
pub mod fapi;
pub mod fido2;
pub mod http;
pub mod i18n;
pub mod posture;
pub mod server_url;

// Re-export commonly used types
pub use fido2::{AuthenticationResult, FidoDevice, RegistrationResult};
pub use http::{HttpClient, HttpResponse};

#[cfg(feature = "test-utils")]
pub use fido2::MockFidoDevice;

#[cfg(feature = "test-utils")]
pub use http::TestHttpClient;
