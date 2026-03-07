// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device posture detection.
//!
//! Collects system signals about the client machine's security posture.
//! All detection is best-effort, requires no elevated privileges, and
//! fails gracefully (returning `None` for any signal that can't be read).

mod common;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

use vouch_common::posture::{DevicePosture, OperatingSystem};

/// Collect device posture from the current system.
///
/// Runs all available detection checks for the current platform.
/// Any check that fails simply produces `None` for that field.
#[must_use]
pub fn collect() -> DevicePosture {
    let mut posture = DevicePosture::new();

    // Cross-platform basics
    posture.os = Some(OperatingSystem::from_env());
    posture.arch = Some(std::env::consts::ARCH.to_string());
    posture.cli_version = Some(env!("CARGO_PKG_VERSION").to_string());
    posture.collected_at = Some(jiff::Timestamp::now().to_string());

    // Cross-platform: SSH session, execution context
    common::detect(&mut posture);

    // Platform-specific detection
    #[cfg(target_os = "macos")]
    macos::detect(&mut posture);

    #[cfg(target_os = "linux")]
    linux::detect(&mut posture);

    #[cfg(target_os = "windows")]
    windows::detect(&mut posture);

    posture.normalize();
    posture
}
