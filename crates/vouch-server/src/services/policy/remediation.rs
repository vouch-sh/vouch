// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OS-specific remediation guidance for preconfigured policies.
//!
//! The guidance is user-facing text shown by the CLI, so the catalog holds
//! the wording and this module only selects the id.

use super::preconfigured::PreconfiguredSlug;
use crate::infra::i18n::Tr;

/// Get OS-specific remediation guidance for a preconfigured policy, in the
/// requesting client's locale.
#[must_use]
pub(crate) fn remediation_for_slug(slug: PreconfiguredSlug, os: Option<&str>) -> String {
    let os = os.unwrap_or("unknown");

    match (slug, os) {
        // Disk encryption
        (PreconfiguredSlug::DiskEncryption, "macos") => {
            Tr::new("admin-policies-fix-disk-encryption-macos").to_string()
        }
        (PreconfiguredSlug::DiskEncryption, "linux") => {
            Tr::new("admin-policies-fix-disk-encryption-linux").to_string()
        }
        (PreconfiguredSlug::DiskEncryption, "windows") => {
            Tr::new("admin-policies-fix-disk-encryption-windows").to_string()
        }
        (PreconfiguredSlug::DiskEncryption, _) => {
            Tr::new("admin-policies-fix-disk-encryption").to_string()
        }

        // Firewall
        (PreconfiguredSlug::Firewall, "macos") => {
            Tr::new("admin-policies-fix-firewall-macos").to_string()
        }
        (PreconfiguredSlug::Firewall, "linux") => {
            Tr::new("admin-policies-fix-firewall-linux").to_string()
        }
        (PreconfiguredSlug::Firewall, "windows") => {
            Tr::new("admin-policies-fix-firewall-windows").to_string()
        }
        (PreconfiguredSlug::Firewall, _) => Tr::new("admin-policies-fix-firewall").to_string(),

        // Screen lock
        (PreconfiguredSlug::ScreenLock, "macos") => {
            Tr::new("admin-policies-fix-screen-lock-macos").to_string()
        }
        (PreconfiguredSlug::ScreenLock, "linux") => {
            Tr::new("admin-policies-fix-screen-lock-linux").to_string()
        }
        (PreconfiguredSlug::ScreenLock, "windows") => {
            Tr::new("admin-policies-fix-screen-lock-windows").to_string()
        }
        (PreconfiguredSlug::ScreenLock, _) => Tr::new("admin-policies-fix-screen-lock").to_string(),

        // Endpoint protection
        (PreconfiguredSlug::EndpointProtection, "macos" | "linux") => {
            Tr::new("admin-policies-fix-endpoint-protection-macos").to_string()
        }
        (PreconfiguredSlug::EndpointProtection, "windows") => {
            Tr::new("admin-policies-fix-endpoint-protection-windows").to_string()
        }
        (PreconfiguredSlug::EndpointProtection, _) => {
            Tr::new("admin-policies-fix-endpoint-protection").to_string()
        }

        // MDM enrollment — the fix is org-specific on every platform.
        (PreconfiguredSlug::MdmEnrollment, _) => {
            Tr::new("admin-policies-fix-mdm-enrollment").to_string()
        }

        // Platform integrity
        (PreconfiguredSlug::PlatformIntegrity, "macos") => {
            Tr::new("admin-policies-fix-platform-integrity-macos").to_string()
        }
        (PreconfiguredSlug::PlatformIntegrity, "linux" | "windows") => {
            Tr::new("admin-policies-fix-platform-integrity-windows").to_string()
        }
        (PreconfiguredSlug::PlatformIntegrity, _) => {
            Tr::new("admin-policies-fix-platform-integrity").to_string()
        }

        // OS currency
        (PreconfiguredSlug::OsRecency, "macos") => {
            Tr::new("admin-policies-fix-os-recency-macos").to_string()
        }
        (PreconfiguredSlug::OsRecency, "windows") => {
            Tr::new("admin-policies-fix-os-recency-windows").to_string()
        }
        (PreconfiguredSlug::OsRecency, "linux") => {
            Tr::new("admin-policies-fix-os-recency-linux").to_string()
        }
        (PreconfiguredSlug::OsRecency, _) => Tr::new("admin-policies-fix-os-recency").to_string(),

        // Temporal policies — the advice is the same on every platform.
        (PreconfiguredSlug::IssuanceRateLimit, _) => {
            Tr::new("admin-policies-fix-issuance-rate-limit").to_string()
        }
        (PreconfiguredSlug::ExchangeRateLimit, _) => {
            Tr::new("admin-policies-fix-exchange-rate-limit").to_string()
        }
        (PreconfiguredSlug::FailedLoginBurst, _) => {
            Tr::new("admin-policies-fix-failed-login-burst").to_string()
        }
        (PreconfiguredSlug::TokenExchangeStepUp, _) => {
            Tr::new("admin-policies-fix-token-exchange-step-up").to_string()
        }
        (PreconfiguredSlug::ExchangeIpConsistency, _) => {
            Tr::new("admin-policies-fix-exchange-ip-consistency").to_string()
        }
        (PreconfiguredSlug::LogoutInvalidatesExchange, _) => {
            Tr::new("admin-policies-fix-logout-invalidates-exchange").to_string()
        }
    }
}
