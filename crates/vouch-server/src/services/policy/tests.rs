// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Unit tests for the Dogwood policy engine, ported from the CEL engine's
//! suite (services/posture.rs) plus new validator-quality and field-parity
//! coverage the CEL engine could not express.
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable"
)]

use super::preconfigured::BASE_ALLOW;
use super::*;
use vouch_common::posture::{EdrAgent, MdmAgent, OperatingSystem, PostureTypeTag};

fn sample_posture() -> DevicePosture {
    DevicePosture {
        detail_type: PostureTypeTag,
        posture_version: 1,
        os: Some(OperatingSystem::MacOs),
        os_version: Some("15.3.1".to_string()),
        disk_encryption_enabled: Some(true),
        disk_encryption_technology: Some("filevault".to_string()),
        firewall_enabled: Some(true),
        firewall_technology: Some("application firewall".to_string()),
        screen_lock_enabled: Some(true),
        screen_lock_idle_timeout_secs: Some(300),
        secure_boot_enabled: Some(true),
        sip_enabled: Some(true),
        edr: vec![EdrAgent::CrowdStrike],
        mdm: vec![MdmAgent::Jamf],
        elevated: Some(false),
        tty: Some(true),
        ..Default::default()
    }
}

/// A posture with every field populated — used by the parity test so
/// "non-default value reachable" checks hold for all 31 record fields.
fn full_posture() -> DevicePosture {
    let mut posture = sample_posture();
    posture.os_distribution = Some("macos".to_string());
    posture.os_build = Some("26100".to_string());
    posture.arch = Some("aarch64".to_string());
    posture.tpm_present = Some(true);
    posture.tpm_version = Some("2.0".to_string());
    posture.auto_update_enabled = Some(true);
    posture.auto_update_technology = Some("softwareupdate".to_string());
    posture.uptime_secs = Some(86400);
    posture.access_control_enforcing = Some(true);
    posture.access_control_technology = Some("gatekeeper".to_string());
    posture.parent_process = Some("zsh".to_string());
    posture.cli_version = Some("1.2.3".to_string());
    posture.collected_at = Some("2026-08-08t00:00:00z".to_string());
    posture
}

fn minimal_posture() -> DevicePosture {
    DevicePosture::new()
}

/// The policy text of a preconfigured policy, by slug.
fn preconfigured_text(slug: PreconfiguredSlug) -> &'static str {
    PRECONFIGURED_POLICIES
        .iter()
        .find(|p| p.slug == slug)
        .unwrap()
        .policy_text
}

/// Evaluate a single policy text (plus the base permit) against a posture.
/// Engine-level failures panic — these tests only exercise valid text.
fn evaluate_one(policy_text: &str, posture: &DevicePosture) -> bool {
    let composed = compose(&[policy_text]);
    let event = issue_token_request(posture, "test-user", "test-org");
    match decide(&composed, &event) {
        Ok(EngineDecision::Allow) => true,
        Ok(EngineDecision::Deny) => false,
        Err(e) => panic!("engine error: {e}"),
    }
}

/// Wrap a boolean requirement expression in the standard forbid shape —
/// the idiom admins use for custom policies.
fn requirement(expr: &str) -> String {
    format!(
        "forbid (principal, action == Vouch::Action::\"IssueToken\", resource) \
         unless {{ {expr} }};"
    )
}

// ============================================================
// Validation
// ============================================================

#[test]
fn test_validate_policy_text_valid() {
    validate_policy_text(&requirement("context.device.disk_encryption_enabled")).unwrap();
    validate_policy_text(&requirement("context.device.edr_count > 0")).unwrap();
    validate_policy_text(&requirement(
        "context.device.os == \"macos\" || context.device.os == \"linux\"",
    ))
    .unwrap();
}

#[test]
fn test_validate_policy_text_invalid() {
    // Empty and whitespace-only text
    assert!(validate_policy_text("").is_err());
    assert!(validate_policy_text("   ").is_err());
    // Unterminated string literal
    assert!(validate_policy_text(&requirement("context.device.os == \"unterminated")).is_err());
    // Truncated policy
    assert!(validate_policy_text("forbid (principal, action ==").is_err());
    // Leftover CEL text from before the migration must be rejected
    assert!(validate_policy_text("posture.disk_encryption_enabled == true").is_err());
}

#[test]
fn test_validate_policy_text_catches_typoed_field() {
    // The CEL engine silently evaluated unknown fields to a runtime miss;
    // the Dogwood validator reports them as type errors.
    let result = validate_policy_text(&requirement("context.device.disk_encryption_enabledz"));
    assert!(result.is_err(), "typo'd posture field must fail validation");
}

// ============================================================
// Preconfigured policy evaluation
// ============================================================

#[test]
fn test_evaluate_disk_encryption_pass_and_fail() {
    let text = preconfigured_text(PreconfiguredSlug::DiskEncryption);
    assert!(evaluate_one(text, &sample_posture()));
    assert!(!evaluate_one(text, &minimal_posture()));
}

#[test]
fn test_evaluate_firewall_pass() {
    assert!(evaluate_one(
        preconfigured_text(PreconfiguredSlug::Firewall),
        &sample_posture()
    ));
}

#[test]
fn test_evaluate_screen_lock_pass() {
    assert!(evaluate_one(
        preconfigured_text(PreconfiguredSlug::ScreenLock),
        &sample_posture()
    ));
}

#[test]
fn test_evaluate_edr_pass_and_fail_empty() {
    let text = preconfigured_text(PreconfiguredSlug::EndpointProtection);
    assert!(evaluate_one(text, &sample_posture()));
    assert!(!evaluate_one(text, &minimal_posture()));
}

#[test]
fn test_evaluate_secure_boot_pass() {
    assert!(evaluate_one(
        preconfigured_text(PreconfiguredSlug::PlatformIntegrity),
        &sample_posture()
    ));
}

#[test]
fn test_none_fields_default_to_false() {
    let minimal = minimal_posture();
    for slug in [
        PreconfiguredSlug::DiskEncryption,
        PreconfiguredSlug::Firewall,
        PreconfiguredSlug::ScreenLock,
        PreconfiguredSlug::PlatformIntegrity,
    ] {
        assert!(
            !evaluate_one(preconfigured_text(slug), &minimal),
            "absent posture fields must default to false and deny '{slug}'"
        );
    }
}

#[test]
fn test_none_string_fields_default_to_empty() {
    assert!(evaluate_one(
        &requirement("context.device.os == \"\""),
        &minimal_posture()
    ));
}

// ============================================================
// OS recency matrix
// ============================================================

#[test]
fn test_evaluate_os_recency_macos_pass() {
    assert!(evaluate_one(
        preconfigured_text(PreconfiguredSlug::OsRecency),
        &sample_posture()
    ));
}

/// Regression for #544: macOS 15.x must pass OsRecency — the threshold
/// compares the marketing version reported by `sw_vers -productVersion`,
/// not the Darwin kernel version.
#[test]
fn test_os_recency_macos_15_passes() {
    let mut posture = sample_posture();
    posture.os_version = Some("15.3.1".to_string());
    assert!(
        evaluate_one(preconfigured_text(PreconfiguredSlug::OsRecency), &posture),
        "macOS 15.3.1 (Sequoia) must pass OsRecency (>= 14.0.0)"
    );
}

/// Regression for #544: macOS 13.x must fail OsRecency (older than N-1).
#[test]
fn test_os_recency_macos_13_fails() {
    let mut posture = sample_posture();
    posture.os_version = Some("13.7.0".to_string());
    assert!(
        !evaluate_one(preconfigured_text(PreconfiguredSlug::OsRecency), &posture),
        "macOS 13.7.0 (Ventura) must fail OsRecency (< 14.0.0)"
    );
}

#[test]
fn test_evaluate_os_recency_linux_does_not_pass() {
    let mut posture = minimal_posture();
    posture.os = Some(OperatingSystem::Linux);
    // Linux is not covered by the preconfigured os_recency policy;
    // admins should create per-distro custom policies instead.
    assert!(!evaluate_one(
        preconfigured_text(PreconfiguredSlug::OsRecency),
        &posture
    ));
}

/// Regression for the Windows OsRecency 4-component version bug.
///
/// The Windows CLI reports `os_version` as a 4-component string
/// (e.g., "10.0.26100.0") which the semver encoding rejects
/// (`os_version_num` = -1). The preconfigured OsRecency policy must compare
/// Windows by `os_build_num` (the registry `CurrentBuild` integer), not
/// `os_version`.
#[test]
fn test_os_recency_windows_24h2_four_component_version_passes() {
    let mut posture = sample_posture();
    posture.os = Some(OperatingSystem::Windows);
    posture.os_version = Some("10.0.26100.0".to_string());
    posture.os_build = Some("26100".to_string());
    assert!(
        evaluate_one(preconfigured_text(PreconfiguredSlug::OsRecency), &posture),
        "Windows 11 24H2 (build 26100) must pass OsRecency even though \
         os_version has 4 components"
    );
}

/// Windows builds below the 26100 threshold (e.g., 22631 = 23H2) must fail.
#[test]
fn test_os_recency_windows_old_build_fails() {
    let mut posture = sample_posture();
    posture.os = Some(OperatingSystem::Windows);
    posture.os_version = Some("10.0.22631.0".to_string());
    posture.os_build = Some("22631".to_string()); // 23H2
    assert!(
        !evaluate_one(preconfigured_text(PreconfiguredSlug::OsRecency), &posture),
        "Windows 11 23H2 (build 22631) must fail OsRecency (< 26100)"
    );
}

/// Windows OsRecency must pass when `os_version` is absent entirely.
#[test]
fn test_os_recency_windows_missing_os_version_passes_on_build() {
    let mut posture = sample_posture();
    posture.os = Some(OperatingSystem::Windows);
    posture.os_version = None;
    posture.os_build = Some("26100".to_string());
    assert!(
        evaluate_one(preconfigured_text(PreconfiguredSlug::OsRecency), &posture),
        "Windows with a compliant os_build but missing os_version must pass"
    );
}

/// Windows OsRecency must fail when `os_build` is below the threshold, even
/// if `os_version` looks like a 3-component semver that would have passed
/// the old (buggy) comparison.
#[test]
fn test_os_recency_windows_ignores_os_version_for_comparison() {
    let mut posture = sample_posture();
    posture.os = Some(OperatingSystem::Windows);
    posture.os_version = Some("10.0.26100".to_string());
    posture.os_build = Some("22631".to_string()); // 23H2
    assert!(
        !evaluate_one(preconfigured_text(PreconfiguredSlug::OsRecency), &posture),
        "Windows OsRecency must compare os_build_num, not os_version"
    );
}

// ============================================================
// Preconfigured set health
// ============================================================

/// Every preconfigured policy must lower AND validate cleanly against the
/// embedded schema — stronger than the CEL compile-only check.
#[test]
fn test_all_preconfigured_policies_lower_and_validate() {
    for policy in PRECONFIGURED_POLICIES {
        validate_policy_text(policy.policy_text)
            .unwrap_or_else(|e| panic!("policy '{}' failed validation: {e:?}", policy.slug));
    }
}

#[test]
fn test_all_preconfigured_pass_with_full_posture() {
    let posture = sample_posture();
    for policy in PRECONFIGURED_POLICIES {
        assert!(
            evaluate_one(policy.policy_text, &posture),
            "Policy '{}' should pass with full posture",
            policy.slug
        );
    }
}

// ============================================================
// Playground (test_policy_text)
// ============================================================

#[test]
fn test_test_policy_text_pass() {
    let result = test_policy_text(
        &requirement("context.device.disk_encryption_enabled"),
        &sample_posture(),
    )
    .unwrap();
    assert!(result.pass);
    assert!(
        !result.reads_history,
        "a posture-only policy does not read event history"
    );
}

#[test]
fn test_test_policy_text_fail() {
    let result = test_policy_text(
        &requirement("context.device.disk_encryption_enabled"),
        &minimal_posture(),
    )
    .unwrap();
    assert!(!result.pass);
}

#[test]
fn test_test_policy_text_invalid() {
    let posture = minimal_posture();
    assert!(test_policy_text("", &posture).is_err());
    assert!(
        test_policy_text(
            &requirement("context.device.os == \"unterminated"),
            &posture
        )
        .is_err()
    );
}

/// A custom `permit` an admin writes is harmless: the base permit already
/// allows, and forbids always override permits.
#[test]
fn test_custom_permit_cannot_widen_access() {
    let permit_everything =
        "permit (principal, action == Vouch::Action::\"IssueToken\", resource);";
    assert!(
        test_policy_text(permit_everything, &minimal_posture())
            .unwrap()
            .pass
    );
    // ...but an active forbid still denies even alongside a custom permit.
    let contradictory = format!(
        "{permit_everything}\n\n{}",
        requirement("context.device.disk_encryption_enabled")
    );
    assert!(
        !test_policy_text(&contradictory, &minimal_posture())
            .unwrap()
            .pass
    );
}

// ============================================================
// Remediation and slugs
// ============================================================

#[test]
fn test_remediation_macos() {
    let r = remediation_for_slug(PreconfiguredSlug::DiskEncryption, Some("macos"));
    assert!(r.contains("FileVault"));
}

#[test]
fn test_remediation_linux() {
    let r = remediation_for_slug(PreconfiguredSlug::Firewall, Some("linux"));
    assert!(r.contains("ufw"));
}

#[test]
fn test_remediation_windows() {
    let r = remediation_for_slug(PreconfiguredSlug::ScreenLock, Some("windows"));
    assert!(r.contains("Sign-in options"));
}

#[test]
fn test_preconfigured_slug_round_trip() {
    assert_eq!(
        "disk_encryption".parse::<PreconfiguredSlug>(),
        Ok(PreconfiguredSlug::DiskEncryption)
    );
    assert_eq!(
        "os_recency".parse::<PreconfiguredSlug>(),
        Ok(PreconfiguredSlug::OsRecency)
    );
    assert!("custom".parse::<PreconfiguredSlug>().is_err());
    assert_eq!(
        PreconfiguredSlug::DiskEncryption.as_str(),
        "disk_encryption"
    );
}

#[test]
fn test_is_valid_preconfigured_slug() {
    assert!(is_valid_preconfigured_slug("disk_encryption"));
    assert!(is_valid_preconfigured_slug("os_recency"));
    assert!(!is_valid_preconfigured_slug("custom"));
}

/// Enabling every built-in must still leave an org its custom-policy
/// allowance — adding a built-in must not quietly consume one.
#[test]
fn test_all_builtins_active_still_leaves_custom_budget() {
    let remaining = MAX_ACTIVE_POLICIES.saturating_sub(PRECONFIGURED_POLICIES.len());
    assert_eq!(
        remaining,
        preconfigured::MAX_ACTIVE_CUSTOM_POLICIES,
        "with all {} built-ins active, an org must still have {} custom slots",
        PRECONFIGURED_POLICIES.len(),
        preconfigured::MAX_ACTIVE_CUSTOM_POLICIES
    );
}

// ============================================================
// semver encoding
// ============================================================

#[test]
fn test_semver_num_encoding() {
    assert_eq!(posture_input::semver_num("15.3.1"), Some(15_003_001));
    assert_eq!(posture_input::semver_num("15.3"), Some(15_003_000));
    assert_eq!(posture_input::semver_num("15"), Some(15_000_000));
    assert_eq!(posture_input::semver_num("9.0.0"), Some(9_000_000));
    // 4-component (Windows) and non-numeric versions are rejected
    assert_eq!(posture_input::semver_num("10.0.26100.0"), None);
    assert_eq!(posture_input::semver_num("24h2"), None);
    assert_eq!(posture_input::semver_num(""), None);
}

#[test]
fn test_semver_comparison_via_policy() {
    // 15.3.1 >= 14.0.0 (passes the lenient N-2 OsRecency floor)
    assert!(evaluate_one(
        &requirement("context.device.os_version_num >= 14000000"),
        &sample_posture()
    ));
    // 15.3.1 < 16.0.0 (does not meet a hypothetical next-year floor)
    assert!(evaluate_one(
        &requirement("context.device.os_version_num < 16000000"),
        &sample_posture()
    ));
    // 9.0.0 must NOT be >= 14.0.0 (unlike lexicographic comparison)
    let mut old = minimal_posture();
    old.os_version = Some("9.0.0".to_string());
    assert!(!evaluate_one(
        &requirement("context.device.os_version_num >= 14000000"),
        &old
    ));
}

// ============================================================
// Device posture extraction (RFC 9396)
// ============================================================

#[test]
fn test_extract_device_posture_from_ad() {
    let value: serde_json::Value = serde_json::from_str(
        r#"[{"type":"device_posture","posture_version":1,"os":"macos","disk_encryption_enabled":true}]"#,
    )
    .unwrap();
    let posture = extract_device_posture(Some(&value)).unwrap();
    assert_eq!(posture.os, Some(OperatingSystem::MacOs));
    assert_eq!(posture.disk_encryption_enabled, Some(true));
}

#[test]
fn test_extract_device_posture_missing() {
    assert!(extract_device_posture(None).is_err());
}

#[test]
fn test_extract_device_posture_no_posture_entry() {
    let value: serde_json::Value = serde_json::from_str(r#"[{"type":"other_thing"}]"#).unwrap();
    assert!(extract_device_posture(Some(&value)).is_err());
}

// ============================================================
// Field parity
// ============================================================

/// One schema-validated check per Posture record field, true for
/// `full_posture()`. Together with the exhaustive destructuring in
/// `posture_fields`, this guarantees every `DevicePosture` field (plus the
/// four derived fields) is reachable — and correctly valued — from policy
/// text.
const POSTURE_FIELD_CHECKS: &[(&str, &str)] = &[
    ("os", "context.device.os == \"macos\""),
    ("os_version", "context.device.os_version == \"15.3.1\""),
    (
        "os_version_num",
        "context.device.os_version_num == 15003001",
    ),
    (
        "os_distribution",
        "context.device.os_distribution == \"macos\"",
    ),
    ("os_build", "context.device.os_build == \"26100\""),
    ("os_build_num", "context.device.os_build_num == 26100"),
    ("arch", "context.device.arch == \"aarch64\""),
    (
        "disk_encryption_enabled",
        "context.device.disk_encryption_enabled",
    ),
    (
        "disk_encryption_technology",
        "context.device.disk_encryption_technology == \"filevault\"",
    ),
    ("screen_lock_enabled", "context.device.screen_lock_enabled"),
    (
        "screen_lock_idle_timeout_secs",
        "context.device.screen_lock_idle_timeout_secs == 300",
    ),
    ("firewall_enabled", "context.device.firewall_enabled"),
    (
        "firewall_technology",
        "context.device.firewall_technology == \"application firewall\"",
    ),
    ("secure_boot_enabled", "context.device.secure_boot_enabled"),
    ("sip_enabled", "context.device.sip_enabled"),
    ("tpm_present", "context.device.tpm_present"),
    ("tpm_version", "context.device.tpm_version == \"2.0\""),
    ("auto_update_enabled", "context.device.auto_update_enabled"),
    (
        "auto_update_technology",
        "context.device.auto_update_technology == \"softwareupdate\"",
    ),
    ("uptime_secs", "context.device.uptime_secs == 86400"),
    (
        "access_control_enforcing",
        "context.device.access_control_enforcing",
    ),
    (
        "access_control_technology",
        "context.device.access_control_technology == \"gatekeeper\"",
    ),
    ("edr", "context.device.edr.contains(\"crowdstrike\")"),
    ("edr_count", "context.device.edr_count == 1"),
    ("mdm", "context.device.mdm.contains(\"jamf\")"),
    ("mdm_count", "context.device.mdm_count == 1"),
    ("elevated", "context.device.elevated == false"),
    ("tty", "context.device.tty"),
    ("parent_process", "context.device.parent_process == \"zsh\""),
    ("cli_version", "context.device.cli_version == \"1.2.3\""),
    (
        "collected_at",
        "context.device.collected_at == \"2026-08-08t00:00:00z\"",
    ),
];

#[test]
fn test_posture_field_parity() {
    let posture = full_posture();

    // Completeness: the check list covers exactly the record's fields.
    let record = posture_input::posture_fields(&posture);
    let checked: std::collections::BTreeSet<&str> = POSTURE_FIELD_CHECKS
        .iter()
        .map(|(field, _)| *field)
        .collect();
    let present: std::collections::BTreeSet<&str> = record.keys().map(String::as_str).collect();
    assert_eq!(
        checked, present,
        "POSTURE_FIELD_CHECKS must cover exactly the posture record fields"
    );

    // Reachability + value fidelity, through schema validation and the
    // full engine (validate catches typos; evaluate catches wrong values).
    for (field, expr) in POSTURE_FIELD_CHECKS {
        let policy = requirement(expr);
        validate_policy_text(&policy)
            .unwrap_or_else(|e| panic!("field '{field}' check failed validation: {e:?}"));
        assert!(
            evaluate_one(&policy, &posture),
            "Field '{field}' not accessible or wrongly valued (expr: {expr})"
        );
    }
}

// ============================================================
// Fail-closed behavior
// ============================================================

/// A policy that fails to lower (leftover CEL text) must be an engine
/// error — enforcement treats it as a deny, never a pass.
#[test]
fn test_unlowerable_policy_is_fail_closed() {
    let composed = compose(&["posture.disk_encryption_enabled == true"]);
    let event = issue_token_request(&sample_posture(), "test-user", "test-org");
    assert!(
        decide(&composed, &event).is_err(),
        "CEL text must be an engine error (deny)"
    );
}

/// The base permit alone allows — no active forbids means issuance passes.
#[test]
fn test_base_allow_alone_allows() {
    let event = issue_token_request(&minimal_posture(), "test-user", "test-org");
    let allowed = match decide(BASE_ALLOW, &event) {
        Ok(EngineDecision::Allow) => true,
        Ok(EngineDecision::Deny) | Err(_) => false,
    };
    assert!(allowed, "base permit alone must allow");
}

// ============================================================
// Per-principal history slicing invariant
// ============================================================

fn history_row(kind: &str, user_id: &str, secs_ago: i64, seq: u32) -> crate::db::audit::AuditEvent {
    crate::db::audit::AuditEvent {
        id: format!("row-{seq:04}"),
        event_type: kind.to_string(),
        user_id: Some(user_id.to_string()),
        email_domain: None,
        email_hmac: None,
        data: "{}".to_string(),
        created_at: jiff::Timestamp::now()
            .checked_sub(jiff::Span::new().seconds(secs_ago))
            .unwrap(),
    }
}

/// The invariant the per-decision design rests on: no temporal predicate
/// crosses principals (the default event schema pins `callerPrincipal`).
/// Checked from both directions — another principal's history can neither
/// trip an aggregation cap nor satisfy a recency window.
#[test]
fn test_temporal_policies_ignore_other_principals_history() {
    let now = jiff::Timestamp::now().as_second();

    // Aggregations: user B's 10 issuances and 5 failed logins must not
    // deny user A's issuance.
    let set = compose_org_set(
        &[
            "issuance_rate_limit".to_string(),
            "failed_login_burst".to_string(),
        ],
        &[],
    );
    let lowered = LoweredPolicySet::from_str(
        &set.composed,
        schema::service_schema(),
        schema::policy_schema().unwrap(),
    )
    .unwrap();
    let mut history = Vec::new();
    for i in 0..10_u32 {
        history.push(history_row(
            "oauth_token_issued",
            "user-b",
            600 + i64::from(i),
            i,
        ));
    }
    for i in 0..5_u32 {
        history.push(history_row(
            "login_failed",
            "user-b",
            120 + i64::from(i),
            100 + i,
        ));
    }
    history.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
    let posture = sample_posture();
    let decision = engine::evaluate(lowered, &set.refs, &history, "org-1", now, |ts| {
        decision_event(
            &DecisionKind::IssueToken {
                posture: &posture,
                ip: None,
                client_id: "cli",
            },
            "user-a",
            "org-1",
            ts,
        )
    })
    .unwrap();
    let allowed = match decision {
        engine::OrgDecision::Allow => true,
        engine::OrgDecision::Deny(_) => false,
    };
    assert!(
        allowed,
        "another principal's history must not trip aggregation caps"
    );

    // Recency: user B's fresh login must not satisfy user A's step-up.
    let set = compose_org_set(&["token_exchange_step_up".to_string()], &[]);
    let lowered = LoweredPolicySet::from_str(
        &set.composed,
        schema::service_schema(),
        schema::policy_schema().unwrap(),
    )
    .unwrap();
    let history = vec![history_row("login_success", "user-b", 60, 0)];
    let decision = engine::evaluate(lowered, &set.refs, &history, "org-1", now, |ts| {
        decision_event(
            &DecisionKind::ExchangeToken {
                ip: None,
                client_id: "cli",
                audience: None,
            },
            "user-a",
            "org-1",
            ts,
        )
    })
    .unwrap();
    let denied_by = match decision {
        engine::OrgDecision::Deny(Some(engine::DenyingPolicy::Preconfigured(slug))) => Some(slug),
        engine::OrgDecision::Allow | engine::OrgDecision::Deny(_) => None,
    };
    assert_eq!(
        denied_by,
        Some(PreconfiguredSlug::TokenExchangeStepUp),
        "another principal's login must not satisfy the step-up window"
    );
}

// ============================================================
// Schema ↔ ingestion parity
// ============================================================

/// Every `input`/`output` field the schema declares on a history event must
/// be written by the ingestion mapping. A declared-but-unwritten field type
/// checks fine and then silently never matches — the exact failure mode the
/// typed-validation migration is supposed to eliminate.
#[test]
fn test_history_projection_matches_schema() {
    use std::collections::BTreeSet;

    // What ingestion writes, per action (from `history_event`).
    let mut written: std::collections::BTreeMap<String, BTreeSet<String>> = Default::default();
    for kind in events::HISTORY_KINDS {
        let row = history_row(kind.as_str(), "user-a", 60, 0);
        let event = events::history_event(&row, "org-1", 0)
            .unwrap_or_else(|| panic!("history kind '{}' has no mapping arm", kind.as_str()));
        assert!(
            event.principal().is_some(),
            "history event for '{}' must carry a principal",
            kind.as_str()
        );
        let mut fields = BTreeSet::new();
        for group in ["input", "output"] {
            for (name, _) in event.fields(group) {
                fields.insert(format!("{group}.{name}"));
            }
        }
        // Actions are many-to-one with kinds (credential kinds share
        // IssueCredential); union the fields written for each action.
        let action_name = dogwood_action_of(kind);
        written
            .entry(action_name.to_string())
            .or_default()
            .extend(fields);
    }

    // What the schema declares, per action (from the lowered policy set's
    // event signatures — the authoritative view of a `::response` shape).
    let set = compose_org_set(&[], &[]);
    let lowered = LoweredPolicySet::from_str(
        &set.composed,
        schema::service_schema(),
        schema::policy_schema().unwrap(),
    )
    .unwrap();
    for signature in lowered.event_signatures() {
        if signature.kind() != "response" {
            continue;
        }
        let action = format!(
            "{}::\"{}\"",
            signature.namespace().join("::"),
            signature.action()
        );
        // `Vouch::Action::"Login"` in signature form; ingestion uses the
        // builder's unquoted form.
        let action = action.replace('"', "");
        let Some(written_fields) = written.get(&action) else {
            continue; // not a history action (decision-only, or unmapped)
        };
        let declared: BTreeSet<String> = signature
            .fields()
            .filter_map(|f| {
                let path = f.path().join(".");
                (path.starts_with("input.") || path.starts_with("output.")).then_some(path)
            })
            .collect();
        assert_eq!(
            &declared, written_fields,
            "action '{action}' response fields: schema declares {declared:?}, \
             ingestion writes {written_fields:?} — every declared field must be \
             written (else temporal predicates over it never match), and every \
             written field must be declared"
        );
    }
}

/// The qualified Dogwood action an audit kind ingests as.
fn dogwood_action_of(kind: &crate::db::AuditEventKind) -> &'static str {
    use crate::db::AuditEventKind as K;
    match kind {
        K::LoginSuccess | K::LoginFailed => "Vouch::Action::Login",
        K::Logout => "Vouch::Action::Logout",
        K::OauthTokenIssued => "Vouch::Action::IssueToken",
        K::OauthTokenRevoked => "Vouch::Action::RevokeToken",
        K::TokenExchange => "Vouch::Action::ExchangeToken",
        K::SshCredential | K::AwsCredential | K::GitHubCredential => {
            "Vouch::Action::IssueCredential"
        }
        other => panic!("kind {other:?} is in HISTORY_KINDS but has no action mapping"),
    }
}

/// Posture lives in a request-only context group, so a temporal predicate
/// over posture is a *schema error* at save time rather than a policy that
/// lowers cleanly and then never matches.
#[test]
fn test_temporal_predicate_over_posture_is_rejected() {
    let policy = r#"
        forbid (principal, action == Vouch::Action::"IssueToken", resource)
        when temporal {
            formerly within 1h Vouch::Action::"IssueToken"::response{
                input.posture.os: "macos"
            }
        };
    "#;
    assert!(
        validate_policy_text(policy).is_err(),
        "a temporal predicate over posture must be rejected: audit history \
         carries no posture, so such a policy could never match"
    );
}

/// A temporal policy's playground verdict reflects an empty history, so it
/// must be labelled rather than presented as a plain pass/fail.
#[test]
fn test_playground_flags_temporal_policies() {
    let temporal = r#"forbid (principal, action == Vouch::Action::"ExchangeToken", resource)
when temporal {
    !(formerly within 15m Vouch::Action::"Login"::response{ output.result: true })
};"#;
    let result = test_policy_text(temporal, &sample_posture()).unwrap();
    assert!(
        result.reads_history,
        "a temporal policy's playground result must be flagged as history-dependent"
    );
}

// ============================================================
// Precheck cache + broken-custom attribution
// ============================================================

/// The precheck cache is keyed by config fingerprint: a hit skips
/// recomputation, and a config change (new fingerprint) recomputes.
#[test]
fn test_precheck_cache_hits_by_fingerprint_and_misses_on_change() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let cache = engine::PolicyEngine::default();
    let computed = AtomicUsize::new(0);
    let compute = || {
        computed.fetch_add(1, Ordering::SeqCst);
        engine::Precheck::Ok {
            uses_temporal: false,
        }
    };

    let fp_a = engine::fingerprint(&["disk_encryption".to_string()], &[]);
    cache.precheck("org-1", fp_a, compute);
    cache.precheck("org-1", fp_a, compute);
    assert_eq!(
        computed.load(Ordering::SeqCst),
        1,
        "a second decision with unchanged policy config must reuse the cached verdict"
    );

    // An admin edits the org's policies: new fingerprint, recompute.
    let fp_b = engine::fingerprint(
        &["disk_encryption".to_string(), "firewall".to_string()],
        &[],
    );
    cache.precheck("org-1", fp_b, compute);
    assert_eq!(
        computed.load(Ordering::SeqCst),
        2,
        "a policy config change must invalidate the cached verdict"
    );

    // A different org never reads org-1's verdict.
    cache.precheck("org-2", fp_a, compute);
    assert_eq!(
        computed.load(Ordering::SeqCst),
        3,
        "the cache must be scoped per org"
    );
}

/// A custom policy that no longer lowers (leftover CEL text) is attributed
/// by name, so the org's other policies are not blamed and the admin can
/// find the broken one.
#[test]
fn test_precheck_attributes_broken_custom_by_name() {
    let custom = vec![
        db::CustomPosturePolicy {
            id: "p1".to_string(),
            name: "Working".to_string(),
            description: None,
            policy_text: requirement("context.device.firewall_enabled"),
            active: true,
            org_id: "org-1".to_string(),
            created_at: jiff::Timestamp::now(),
            updated_at: jiff::Timestamp::now(),
        },
        db::CustomPosturePolicy {
            id: "p2".to_string(),
            name: "Leftover CEL".to_string(),
            description: None,
            policy_text: "posture.disk_encryption_enabled == true".to_string(),
            active: true,
            org_id: "org-1".to_string(),
            created_at: jiff::Timestamp::now(),
            updated_at: jiff::Timestamp::now(),
        },
    ];
    let set = compose_org_set(&[], &custom);
    match run_precheck(&set.composed, &custom) {
        engine::Precheck::BrokenCustom(name) => assert_eq!(
            name, "Leftover CEL",
            "the precheck must name the policy that fails, not a working one"
        ),
        engine::Precheck::Ok { .. } => {
            panic!("a policy set containing CEL text must not pass precheck")
        }
        engine::Precheck::EngineError(msg) => {
            panic!("failure must be attributed to the custom policy, got engine error: {msg}")
        }
    }
}

/// A deny is attributed to the failing policy, and the message carries that
/// policy's remediation — the text the user sees.
#[test]
fn test_deny_error_names_policy_and_remediation() {
    let err = deny_error(
        Some(engine::DenyingPolicy::Preconfigured(
            PreconfiguredSlug::DiskEncryption,
        )),
        Some("macos"),
    );
    let rendered = format!("{err:?}");
    assert!(
        rendered.contains("Disk Encryption"),
        "deny must name the policy: {rendered}"
    );
    assert!(
        rendered.contains("FileVault"),
        "deny must carry OS-specific remediation: {rendered}"
    );
}

/// The precheck reports whether an org's set reads event history. Only
/// those decisions pay the audit query and replay, so a posture-only org
/// must come back non-temporal.
#[test]
fn test_precheck_reports_whether_history_is_needed() {
    let posture_only = compose_org_set(
        &[
            "disk_encryption".to_string(),
            "firewall".to_string(),
            "os_recency".to_string(),
        ],
        &[],
    );
    match run_precheck(&posture_only.composed, &[]) {
        engine::Precheck::Ok { uses_temporal } => assert!(
            !uses_temporal,
            "a posture-only policy set must not require event history"
        ),
        other => panic!("posture-only set must pass precheck, got {other:?}"),
    }

    let with_temporal = compose_org_set(
        &[
            "disk_encryption".to_string(),
            "token_exchange_step_up".to_string(),
        ],
        &[],
    );
    match run_precheck(&with_temporal.composed, &[]) {
        engine::Precheck::Ok { uses_temporal } => assert!(
            uses_temporal,
            "a set containing a temporal policy must require event history"
        ),
        other => panic!("mixed set must pass precheck, got {other:?}"),
    }
}

/// Each policy file must carry the `@id` its slug expects: the id is what
/// deny diagnostics map back to, so a mismatched file would attribute a
/// denial to the wrong policy.
#[test]
fn test_policy_files_declare_their_slug_id() {
    for policy in PRECONFIGURED_POLICIES {
        let expected = format!("@id(\"{}\")", policy.slug.as_str());
        assert!(
            policy.policy_text.contains(&expected),
            "policy file for '{}' must declare {expected}",
            policy.slug
        );
    }
}
