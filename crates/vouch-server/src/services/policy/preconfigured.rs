// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Preconfigured posture policies, defined in code (updatable via deploy).
//!
//! The policy text lives in `policies/<slug>.dw` next to the schema it is
//! written against, and is embedded at build time. Keeping it out of Rust
//! string literals means the rules read as policy in review, and the
//! `dogwood` CLI can check a file directly.
//!
//! Each policy is a `forbid … unless { <requirement> }` over the
//! always-present `context.device` record, or a `when temporal { … }`
//! condition over the event history. The composed set opens with the base
//! permits: Cedar denies by default and a forbid overrides any permit, so
//! every active policy must be satisfied for a decision to allow.

/// Active custom policies an org may run alongside the built-ins.
///
/// A guardrail against an admin enabling more rules than they can reason
/// about, not a cost limit: evaluation is dominated by fixed per-decision
/// overhead, so the policy count barely moves it (13 policies measured
/// within a rounding error of 2). Orgs may author up to
/// `MAX_CUSTOM_POLICIES`; this bounds how many run at once.
pub(crate) const MAX_ACTIVE_CUSTOM_POLICIES: usize = 10;

/// Maximum number of active policies (preconfigured + custom combined).
///
/// Derived rather than written out: the admin UI counts both kinds against
/// one budget, so a hardcoded total silently shrinks the custom allowance
/// every time a built-in policy is added.
pub(crate) const MAX_ACTIVE_POLICIES: usize =
    PRECONFIGURED_POLICIES.len() + MAX_ACTIVE_CUSTOM_POLICIES;

/// The always-present base permits for the two decision actions. Custom
/// `permit`s an admin writes are harmless (these already allow; forbids
/// always override).
pub(crate) const BASE_ALLOW: &str = include_str!("policies/base_allow.dw");

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

    /// Display name, in the requesting client's locale.
    #[must_use]
    pub(crate) fn name(self) -> String {
        match self {
            Self::DiskEncryption => {
                crate::infra::i18n::Tr::new("admin-policies-name-disk-encryption").to_string()
            }
            Self::Firewall => {
                crate::infra::i18n::Tr::new("admin-policies-name-firewall").to_string()
            }
            Self::ScreenLock => {
                crate::infra::i18n::Tr::new("admin-policies-name-screen-lock").to_string()
            }
            Self::EndpointProtection => {
                crate::infra::i18n::Tr::new("admin-policies-name-endpoint-protection").to_string()
            }
            Self::PlatformIntegrity => {
                crate::infra::i18n::Tr::new("admin-policies-name-platform-integrity").to_string()
            }
            Self::OsRecency => {
                crate::infra::i18n::Tr::new("admin-policies-name-os-recency").to_string()
            }
            Self::IssuanceRateLimit => {
                crate::infra::i18n::Tr::new("admin-policies-name-issuance-rate-limit").to_string()
            }
            Self::FailedLoginBurst => {
                crate::infra::i18n::Tr::new("admin-policies-name-failed-login-burst").to_string()
            }
            Self::TokenExchangeStepUp => {
                crate::infra::i18n::Tr::new("admin-policies-name-token-exchange-step-up")
                    .to_string()
            }
            Self::ExchangeIpConsistency => {
                crate::infra::i18n::Tr::new("admin-policies-name-exchange-ip-consistency")
                    .to_string()
            }
            Self::LogoutInvalidatesExchange => {
                crate::infra::i18n::Tr::new("admin-policies-name-logout-invalidates-exchange")
                    .to_string()
            }
        }
    }

    /// One-line description, in the requesting client's locale.
    #[must_use]
    pub(crate) fn description(self) -> String {
        match self {
            Self::DiskEncryption => {
                crate::infra::i18n::Tr::new("admin-policies-desc-disk-encryption").to_string()
            }
            Self::Firewall => {
                crate::infra::i18n::Tr::new("admin-policies-desc-firewall").to_string()
            }
            Self::ScreenLock => {
                crate::infra::i18n::Tr::new("admin-policies-desc-screen-lock").to_string()
            }
            Self::EndpointProtection => {
                crate::infra::i18n::Tr::new("admin-policies-desc-endpoint-protection").to_string()
            }
            Self::PlatformIntegrity => {
                crate::infra::i18n::Tr::new("admin-policies-desc-platform-integrity").to_string()
            }
            Self::OsRecency => {
                crate::infra::i18n::Tr::new("admin-policies-desc-os-recency").to_string()
            }
            Self::IssuanceRateLimit => {
                crate::infra::i18n::Tr::new("admin-policies-desc-issuance-rate-limit").to_string()
            }
            Self::FailedLoginBurst => {
                crate::infra::i18n::Tr::new("admin-policies-desc-failed-login-burst").to_string()
            }
            Self::TokenExchangeStepUp => {
                crate::infra::i18n::Tr::new("admin-policies-desc-token-exchange-step-up")
                    .to_string()
            }
            Self::ExchangeIpConsistency => {
                crate::infra::i18n::Tr::new("admin-policies-desc-exchange-ip-consistency")
                    .to_string()
            }
            Self::LogoutInvalidatesExchange => {
                crate::infra::i18n::Tr::new("admin-policies-desc-logout-invalidates-exchange")
                    .to_string()
            }
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

/// A preconfigured posture policy defined in code. The display name and
/// description are not stored here: they are user-facing text and live in
/// the i18n catalog, keyed by slug (see [`PreconfiguredSlug::name`]).
pub(crate) struct PreconfiguredPolicy {
    pub slug: PreconfiguredSlug,
    pub policy_text: &'static str,
}

/// All preconfigured policies. Updated by deploying new code.
pub(crate) const PRECONFIGURED_POLICIES: &[PreconfiguredPolicy] = &[
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::DiskEncryption,
        policy_text: include_str!("policies/disk_encryption.dw"),
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::Firewall,
        policy_text: include_str!("policies/firewall.dw"),
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::ScreenLock,
        policy_text: include_str!("policies/screen_lock.dw"),
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::EndpointProtection,
        policy_text: include_str!("policies/endpoint_protection.dw"),
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::PlatformIntegrity,
        policy_text: include_str!("policies/platform_integrity.dw"),
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::OsRecency,
        policy_text: include_str!("policies/os_recency.dw"),
    },
    // ── Temporal policies (event-history conditions) ─────────────────
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::IssuanceRateLimit,
        policy_text: include_str!("policies/issuance_rate_limit.dw"),
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::FailedLoginBurst,
        policy_text: include_str!("policies/failed_login_burst.dw"),
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::TokenExchangeStepUp,
        policy_text: include_str!("policies/token_exchange_step_up.dw"),
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::ExchangeIpConsistency,
        policy_text: include_str!("policies/exchange_ip_consistency.dw"),
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::LogoutInvalidatesExchange,
        policy_text: include_str!("policies/logout_invalidates_exchange.dw"),
    },
];

/// A built-in's text prepared as the starting point for a custom policy.
///
/// Drops the explanatory header, which describes the built-in's intent and
/// maintenance rather than the admin's copy, and the `@id` annotation, so
/// the copy does not claim the built-in's identity.
#[must_use]
pub(crate) fn as_editable(policy_text: &str) -> String {
    policy_text
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//") && !trimmed.starts_with("@id(")
        })
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

/// Check if a slug string is a valid preconfigured policy.
#[must_use]
pub(crate) fn is_valid_preconfigured_slug(slug: &str) -> bool {
    slug.parse::<PreconfiguredSlug>().is_ok()
}
