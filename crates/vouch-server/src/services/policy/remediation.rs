// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OS-specific remediation guidance for preconfigured policies.

use super::preconfigured::PreconfiguredSlug;

/// Get OS-specific remediation guidance for a preconfigured policy.
#[must_use]
pub(crate) fn remediation_for_slug(slug: PreconfiguredSlug, os: Option<&str>) -> String {
    let os = os.unwrap_or("unknown");

    match (slug, os) {
        // Disk encryption
        (PreconfiguredSlug::DiskEncryption, "macos") => {
            "Enable FileVault in System Settings > Privacy & Security".to_string()
        }
        (PreconfiguredSlug::DiskEncryption, "linux") => {
            "Enable LUKS encryption with cryptsetup".to_string()
        }
        (PreconfiguredSlug::DiskEncryption, "windows") => {
            "Enable BitLocker in Settings > Device encryption".to_string()
        }
        (PreconfiguredSlug::DiskEncryption, _) => {
            "Enable full-disk encryption on your device".to_string()
        }

        // Firewall
        (PreconfiguredSlug::Firewall, "macos") => {
            "Enable Firewall in System Settings > Network > Firewall".to_string()
        }
        (PreconfiguredSlug::Firewall, "linux") => {
            "Enable firewall with: sudo ufw enable".to_string()
        }
        (PreconfiguredSlug::Firewall, "windows") => {
            "Enable Windows Firewall in Windows Security".to_string()
        }
        (PreconfiguredSlug::Firewall, _) => "Enable your system firewall".to_string(),

        // Screen lock
        (PreconfiguredSlug::ScreenLock, "macos") => {
            "Set screen lock in System Settings > Lock Screen".to_string()
        }
        (PreconfiguredSlug::ScreenLock, "linux") => {
            "Configure screen lock in your display settings. \
             If authenticating via SSH, screen lock status may not be \
             detectable — try authenticating from a graphical session"
                .to_string()
        }
        (PreconfiguredSlug::ScreenLock, "windows") => {
            "Set screen lock in Settings > Accounts > Sign-in options".to_string()
        }
        (PreconfiguredSlug::ScreenLock, _) => "Enable screen lock on your device".to_string(),

        // Endpoint protection
        (PreconfiguredSlug::EndpointProtection, "macos" | "linux") => {
            "Install an EDR agent (e.g., CrowdStrike, SentinelOne)".to_string()
        }
        (PreconfiguredSlug::EndpointProtection, "windows") => {
            "Install an EDR agent (e.g., CrowdStrike, \
             Microsoft Defender for Endpoint)"
                .to_string()
        }
        (PreconfiguredSlug::EndpointProtection, _) => {
            "Install an endpoint detection and response (EDR) agent".to_string()
        }

        // Platform integrity
        (PreconfiguredSlug::PlatformIntegrity, "macos") => {
            "Secure Boot is managed by Apple and should be enabled \
             by default"
                .to_string()
        }
        (PreconfiguredSlug::PlatformIntegrity, "linux" | "windows") => {
            "Enable Secure Boot in your UEFI/BIOS firmware settings".to_string()
        }
        (PreconfiguredSlug::PlatformIntegrity, _) => {
            "Enable Secure Boot on your device".to_string()
        }

        // OS currency
        (PreconfiguredSlug::OsRecency, "macos") => {
            "Update macOS to a supported version (14 or later)".to_string()
        }
        (PreconfiguredSlug::OsRecency, "windows") => {
            "Update Windows to a supported version (build 26100 \
             or later)"
                .to_string()
        }
        (PreconfiguredSlug::OsRecency, "linux") => {
            "Linux is not covered by the built-in OS recency check. \
             Your organization may have a custom policy for your distribution"
                .to_string()
        }
        (PreconfiguredSlug::OsRecency, _) => {
            "Update your operating system to a supported version".to_string()
        }

        // Temporal policies — remediation is not OS-specific.
        (PreconfiguredSlug::IssuanceRateLimit, _) => {
            "Too many token issuances in the last hour. Wait and retry".to_string()
        }
        (PreconfiguredSlug::FailedLoginBurst, _) => {
            "Too many failed login attempts recently. Wait a few minutes and retry".to_string()
        }
        (PreconfiguredSlug::TokenExchangeStepUp, _) => {
            "A recent hardware login is required. Run `vouch login` and retry".to_string()
        }
        (PreconfiguredSlug::ExchangeIpConsistency, _) => {
            "This request came from a different network than your recent login. \
             Run `vouch login` from this network and retry"
                .to_string()
        }
        (PreconfiguredSlug::LogoutInvalidatesExchange, _) => {
            "You logged out since your last login. Run `vouch login` and retry".to_string()
        }
    }
}
