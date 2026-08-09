// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Preconfigured posture policies, defined in code (updatable via deploy).
//!
//! Each policy is a Cedar `forbid … unless { <requirement> }` over the
//! always-present `context.device` record. The composed policy set
//! (see `mod.rs`) starts with one base `permit` — Cedar is deny-by-default,
//! forbids override permits, so all active policies are effectively ANDed,
//! matching the CEL engine's semantics.

/// Maximum number of active policies (preconfigured + custom combined).
/// There are 11 preconfigured policies, so 13 allows all 11 + 2 custom —
/// preserving the 2 custom slots orgs had under the CEL engine's 6 + 2.
pub(crate) const MAX_ACTIVE_POLICIES: usize = 13;

/// The always-present base permits for the two decision actions. Custom
/// `permit`s an admin writes are harmless (these already allow; forbids
/// always override).
pub(crate) const BASE_ALLOW: &str = r#"@id("base_allow_issue")
permit (principal, action == Vouch::Action::"IssueToken", resource);

@id("base_allow_exchange")
permit (principal, action == Vouch::Action::"ExchangeToken", resource);"#;

/// Number of policies in [`BASE_ALLOW`] — the composed set's forbids start
/// at this rule index.
pub(crate) const BASE_ALLOW_RULES: usize = 2;

/// Identifies a preconfigured posture policy.
///
/// Using an enum makes invalid slugs unrepresentable at compile time.
/// Adding a new preconfigured policy requires adding a variant here,
/// which produces compile errors everywhere that needs updating
/// (remediation hints, template icons, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PreconfiguredSlug {
    DiskEncryption,
    Firewall,
    ScreenLock,
    EndpointProtection,
    PlatformIntegrity,
    OsRecency,
    IssuanceRateLimit,
    FailedLoginBurst,
    TokenExchangeStepUp,
    ExchangeIpConsistency,
    LogoutInvalidatesExchange,
}

impl PreconfiguredSlug {
    /// The slug string stored in the DB and used in API responses.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::DiskEncryption => "disk_encryption",
            Self::Firewall => "firewall",
            Self::ScreenLock => "screen_lock",
            Self::EndpointProtection => "endpoint_protection",
            Self::PlatformIntegrity => "platform_integrity",
            Self::OsRecency => "os_recency",
            Self::IssuanceRateLimit => "issuance_rate_limit",
            Self::FailedLoginBurst => "failed_login_burst",
            Self::TokenExchangeStepUp => "token_exchange_step_up",
            Self::ExchangeIpConsistency => "exchange_ip_consistency",
            Self::LogoutInvalidatesExchange => "logout_invalidates_exchange",
        }
    }

    /// Whether this policy evaluates device posture. Temporal policies
    /// only consult the event history — an org running exclusively
    /// temporal policies does not demand posture data from clients.
    #[must_use]
    pub(crate) const fn requires_posture(self) -> bool {
        match self {
            Self::DiskEncryption
            | Self::Firewall
            | Self::ScreenLock
            | Self::EndpointProtection
            | Self::PlatformIntegrity
            | Self::OsRecency => true,
            Self::IssuanceRateLimit
            | Self::FailedLoginBurst
            | Self::TokenExchangeStepUp
            | Self::ExchangeIpConsistency
            | Self::LogoutInvalidatesExchange => false,
        }
    }
}

impl std::str::FromStr for PreconfiguredSlug {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "disk_encryption" => Ok(Self::DiskEncryption),
            "firewall" => Ok(Self::Firewall),
            "screen_lock" => Ok(Self::ScreenLock),
            "endpoint_protection" => Ok(Self::EndpointProtection),
            "platform_integrity" => Ok(Self::PlatformIntegrity),
            "os_recency" => Ok(Self::OsRecency),
            "issuance_rate_limit" => Ok(Self::IssuanceRateLimit),
            "failed_login_burst" => Ok(Self::FailedLoginBurst),
            "token_exchange_step_up" => Ok(Self::TokenExchangeStepUp),
            "exchange_ip_consistency" => Ok(Self::ExchangeIpConsistency),
            "logout_invalidates_exchange" => Ok(Self::LogoutInvalidatesExchange),
            _ => Err(format!("unknown preconfigured slug: {s}")),
        }
    }
}

impl std::fmt::Display for PreconfiguredSlug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A preconfigured posture policy defined in code.
pub(crate) struct PreconfiguredPolicy {
    pub slug: PreconfiguredSlug,
    pub name: &'static str,
    pub description: &'static str,
    pub policy_text: &'static str,
}

/// All preconfigured policies. Updated by deploying new code.
pub(crate) const PRECONFIGURED_POLICIES: &[PreconfiguredPolicy] = &[
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::DiskEncryption,
        name: "Disk Encryption",
        description: "Require full-disk encryption (FileVault, BitLocker, LUKS)",
        policy_text: r#"@id("disk_encryption")
forbid (principal, action == Vouch::Action::"IssueToken", resource)
unless { context.device.disk_encryption_enabled };"#,
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::Firewall,
        name: "Firewall",
        description: "Require an active firewall",
        policy_text: r#"@id("firewall")
forbid (principal, action == Vouch::Action::"IssueToken", resource)
unless { context.device.firewall_enabled };"#,
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::ScreenLock,
        name: "Screen Lock",
        description: "Require screen lock on idle",
        policy_text: r#"@id("screen_lock")
forbid (principal, action == Vouch::Action::"IssueToken", resource)
unless { context.device.screen_lock_enabled };"#,
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::EndpointProtection,
        name: "Endpoint Protection",
        description: "Require at least one EDR agent installed",
        policy_text: r#"@id("endpoint_protection")
forbid (principal, action == Vouch::Action::"IssueToken", resource)
unless { context.device.edr_count > 0 };"#,
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::PlatformIntegrity,
        name: "Platform Integrity",
        description: "Require Secure Boot to be enabled",
        policy_text: r#"@id("platform_integrity")
forbid (principal, action == Vouch::Action::"IssueToken", resource)
unless { context.device.secure_boot_enabled };"#,
    },
    // OS version thresholds — review with each major OS release.
    // Last updated: 2026-06-21
    //   macOS: 14.0.0 (intentionally lenient N-2 floor) — as of June 2026,
    //     macOS 26 "Tahoe" (Darwin 25) is current (N), 15.x "Sequoia" is N-1,
    //     and 14.x "Sonoma" is N-2. The floor accepts N-2 to avoid disrupting
    //     Sonoma users during a transition year. Uses the marketing version as
    //     reported by `sw_vers -productVersion` on the client (os_version_num
    //     = semver encoding, so 14.0.0 → 14_000_000). Darwin kernel versions
    //     (25.x) must NOT be used here.
    //   Windows: build 26100 = 24H2. Compared via `os_build_num` (not
    //     os_version) because the Windows CLI reports `os_version` as a
    //     4-component string (e.g., "10.0.26100.0") that the semver encoding
    //     rejects (os_version_num = -1). `os_build` is the registry
    //     `CurrentBuild` value, a plain integer string like "26100".
    // Linux is excluded — distributions manage versions independently; a
    // Linux device fails both disjuncts. Admins can create custom policies
    // for specific distro versions (e.g.,
    // `context.device.os_distribution == "ubuntu" &&
    //  context.device.os_version_num >= 22004000`).
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::OsRecency,
        name: "OS Recency",
        description: "Require a supported OS version (N-1)",
        policy_text: r#"@id("os_recency")
forbid (principal, action == Vouch::Action::"IssueToken", resource)
unless {
    (context.device.os == "macos" && context.device.os_version_num >= 14000000) ||
    (context.device.os == "windows" && context.device.os_build_num >= 26100)
};"#,
    },
    // ── Temporal policies (event-history conditions) ─────────────────
    //
    // Recency-style rules (fresh login, same network, no logout since
    // login) gate `ExchangeToken` — the RFC 8693 path that WIF/agent
    // credential helpers use — because a token-exchange request arrives
    // WITHOUT a fresh hardware login. They would be vacuous on
    // `IssueToken`: the FIDO2 grant *is* a login, so "logged in recently"
    // is true by construction there. `IssueToken` gets the aggregation
    // rules instead (rate limit, failed-login burst), which count prior
    // audit history.
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::IssuanceRateLimit,
        name: "Issuance Rate Limit",
        description: "Deny token issuance after 10 issuances within one hour",
        policy_text: r#"@id("issuance_rate_limit")
forbid (principal, action == Vouch::Action::"IssueToken", resource)
when temporal {
    exists (n: Long). (
        (count_within(1h, Vouch::Action::"IssueToken"::response{ callerPrincipal: principal })) == n
        && n >= 10
    )
};"#,
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::FailedLoginBurst,
        name: "Failed Login Burst",
        description: "Deny token issuance after 5 failed logins within ten minutes",
        policy_text: r#"@id("failed_login_burst")
forbid (principal, action == Vouch::Action::"IssueToken", resource)
when temporal {
    exists (n: Long). (
        (count_within(10m, Vouch::Action::"Login"::response{ output.result: false })) == n
        && n >= 5
    )
};"#,
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::TokenExchangeStepUp,
        name: "Token Exchange Step-Up",
        description: "Token exchange (WIF/agent credentials) requires a hardware login within 15 minutes",
        policy_text: r#"@id("token_exchange_step_up")
forbid (principal, action == Vouch::Action::"ExchangeToken", resource)
when temporal {
    !(formerly within 15m Vouch::Action::"Login"::response{ output.result: true })
};"#,
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::ExchangeIpConsistency,
        name: "Exchange IP Consistency",
        description: "Token exchange must come from the same IP as a successful login within 8 hours",
        policy_text: r#"@id("exchange_ip_consistency")
forbid (principal, action == Vouch::Action::"ExchangeToken", resource)
when temporal {
    !(formerly within 8h Vouch::Action::"Login"::response{
        input.ip: context.input.ip,
        output.result: true
    })
};"#,
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::LogoutInvalidatesExchange,
        name: "Logout Invalidates Exchange",
        description: "Token exchange is denied after logout until the user logs in again",
        policy_text: r#"@id("logout_invalidates_exchange")
forbid (principal, action == Vouch::Action::"ExchangeToken", resource)
when temporal {
    !(
        (!Vouch::Action::"Logout"::response{ callerPrincipal: principal })
        since within 24h
        Vouch::Action::"Login"::response{ output.result: true }
    )
};"#,
    },
];

/// Check if a slug string is a valid preconfigured policy.
#[must_use]
pub(crate) fn is_valid_preconfigured_slug(slug: &str) -> bool {
    slug.parse::<PreconfiguredSlug>().is_ok()
}
