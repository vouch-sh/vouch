// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Unit tests for the policy engine: policy evaluation, schema/ingestion
//! parity, validator behaviour, and fail-closed error paths.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::get_unwrap,
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
    // A bare boolean expression is not a policy: it must be rejected.
    assert!(validate_policy_text("posture.disk_encryption_enabled == true").is_err());
}

#[test]
fn test_validate_policy_text_catches_typoed_field() {
    // An unknown field is a type error, caught when the policy is saved
    // rather than silently never matching at evaluation time.
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

/// Windows is judged by `os_build_num`, never `os_version`: a build below
/// the threshold must fail even when `os_version` parses as a version that
/// would clear it.
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
/// embedded schema, so a shipped policy cannot fail at a login.
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
        catalog::DecisionPoint::IssueToken,
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
        catalog::DecisionPoint::IssueToken,
    )
    .unwrap();
    assert!(!result.pass);
}

#[test]
fn test_test_policy_text_invalid() {
    let posture = minimal_posture();
    assert!(test_policy_text("", &posture, catalog::DecisionPoint::IssueToken).is_err());
    assert!(
        test_policy_text(
            &requirement("context.device.os == \"unterminated"),
            &posture,
            catalog::DecisionPoint::IssueToken,
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
        test_policy_text(
            permit_everything,
            &minimal_posture(),
            catalog::DecisionPoint::IssueToken
        )
        .unwrap()
        .pass
    );
    // ...but an active forbid still denies even alongside a custom permit.
    let contradictory = format!(
        "{permit_everything}\n\n{}",
        requirement("context.device.disk_encryption_enabled")
    );
    assert!(
        !test_policy_text(
            &contradictory,
            &minimal_posture(),
            catalog::DecisionPoint::IssueToken
        )
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
// Field parity (catalog ↔ posture_fields ↔ schema ↔ generator)
// ============================================================

/// The catalog is the single field list the builder, the reference table,
/// and the generator all read. Together with the exhaustive destructuring
/// in `posture_fields`, this guarantees every `DevicePosture` field (plus
/// the four derived fields) is present in the catalog with the right type,
/// and reachable — and correctly valued — from policy text.
#[test]
fn test_posture_field_parity() {
    let posture = full_posture();

    // Completeness: the catalog covers exactly the record's fields.
    let record = posture_input::posture_fields(&posture);
    let cataloged: std::collections::BTreeSet<&str> =
        catalog::DEVICE_FIELDS.iter().map(|f| f.name).collect();
    let present: std::collections::BTreeSet<&str> = record.keys().map(String::as_str).collect();
    assert_eq!(
        cataloged, present,
        "catalog::DEVICE_FIELDS must cover exactly the device record fields"
    );

    // Type fidelity: each catalog kind matches the value the record
    // actually carries, so the builder never offers the wrong operators.
    for field in catalog::DEVICE_FIELDS {
        let value = record.get(field.name).unwrap();
        let matches = match field.kind {
            catalog::FieldKind::Bool => matches!(value, Value::Bool(_)),
            catalog::FieldKind::Long
            | catalog::FieldKind::VersionNum { .. }
            | catalog::FieldKind::BuildNum { .. } => matches!(value, Value::Int(_)),
            catalog::FieldKind::Text | catalog::FieldKind::TextEnum(_) => {
                matches!(value, Value::String(_))
            }
            catalog::FieldKind::StringSet(_) => matches!(value, Value::Array(_)),
        };
        assert!(
            matches,
            "catalog kind {:?} does not match the record value for '{}'",
            field.kind, field.name
        );
    }

    // Reachability + value fidelity, through schema validation and the
    // full engine (validate catches typos; evaluate catches wrong values).
    for field in catalog::DEVICE_FIELDS {
        let policy = requirement(field.sample_check);
        validate_policy_text(&policy)
            .unwrap_or_else(|e| panic!("field '{}' check failed validation: {e:?}", field.name));
        assert!(
            evaluate_one(&policy, &posture),
            "Field '{}' not accessible or wrongly valued (expr: {})",
            field.name,
            field.sample_check
        );
    }
}

/// A default one-condition spec for a field, shaped like the builder's
/// first offering for that kind.
fn default_field_spec(field: &catalog::FieldMeta) -> serde_json::Value {
    let (op, value) = match field.kind {
        catalog::FieldKind::Bool => ("eq", serde_json::json!(true)),
        catalog::FieldKind::Long => ("ge", serde_json::json!(1)),
        catalog::FieldKind::BuildNum { .. } => ("ge", serde_json::json!(26100)),
        catalog::FieldKind::VersionNum { .. } => ("ge", serde_json::json!("15.3.1")),
        catalog::FieldKind::Text => ("eq", serde_json::json!("sample")),
        catalog::FieldKind::TextEnum(values) | catalog::FieldKind::StringSet(values) => {
            let first = values.first().expect("closed enum has values");
            let op = if matches!(field.kind, catalog::FieldKind::StringSet(_)) {
                "contains"
            } else {
                "eq"
            };
            (op, serde_json::json!(first))
        }
    };
    serde_json::json!({
        "decision": "issue_token",
        "body": {
            "kind": "device",
            "conditions": [
                { "kind": "field", "field": field.name, "op": op, "value": value }
            ]
        }
    })
}

/// Every catalog field, with its default operator and a kind-appropriate
/// value, must generate text the validator accepts — the builder can never
/// offer a field the engine then rejects.
#[test]
fn test_every_catalog_field_generates_valid_policy() {
    for field in catalog::DEVICE_FIELDS {
        let spec: rule::RuleSpec = serde_json::from_value(default_field_spec(field))
            .unwrap_or_else(|e| panic!("spec for '{}' does not deserialize: {e}", field.name));
        let text = rule::generate(&spec)
            .unwrap_or_else(|e| panic!("field '{}' does not generate: {e}", field.name));
        validate_policy_text(&text).unwrap_or_else(|e| {
            panic!(
                "generated text for '{}' fails validation: {e:?}\n{text}",
                field.name
            )
        });
    }
}

/// Every history event × every shape must generate text the validator
/// accepts — this is the guard that catches Dogwood grammar drift on a
/// dependency bump, next to `dogwood_smoke.rs`.
#[test]
fn test_every_history_event_and_shape_generates_valid_policy() {
    let shapes = [
        "happened_within",
        "not_happened_within",
        "count_at_least",
        "not_since",
    ];
    for event in catalog::HISTORY_EVENTS {
        for shape in shapes {
            let mut condition = serde_json::json!({
                "shape": shape,
                "window": { "amount": 1, "unit": "h" }
            });
            if shape == "not_since" {
                condition["anchor"] = serde_json::json!(event.key);
                condition["cancelled_by"] = serde_json::json!("logout");
            } else {
                condition["event"] = serde_json::json!(event.key);
            }
            if shape == "count_at_least" {
                condition["threshold"] = serde_json::json!(5);
            }
            let spec: rule::RuleSpec = serde_json::from_value(serde_json::json!({
                "decision": "exchange_token",
                "body": { "kind": "history", "conditions": [condition] }
            }))
            .unwrap_or_else(|e| panic!("{}/{shape} does not deserialize: {e}", event.key));
            let text = rule::generate(&spec)
                .unwrap_or_else(|e| panic!("{}/{shape} does not generate: {e}", event.key));
            validate_policy_text(&text).unwrap_or_else(|e| {
                panic!(
                    "{}/{shape} generated text fails validation: {e:?}\n{text}",
                    event.key
                )
            });
        }
    }
}

/// The catalog's history events mirror the audit → event ingestion: same
/// count, and every ingested audit kind's action appears in the catalog.
#[test]
fn test_history_events_match_ingested_kinds() {
    assert_eq!(
        catalog::HISTORY_EVENTS.len(),
        events::HISTORY_KINDS.len(),
        "one builder event per ingested audit kind"
    );
    let keys: std::collections::BTreeSet<&str> =
        catalog::HISTORY_EVENTS.iter().map(|e| e.key).collect();
    assert_eq!(
        keys.len(),
        catalog::HISTORY_EVENTS.len(),
        "history event keys must be unique"
    );
}

/// The builder's window cap and the replay window must agree: a window the
/// builder allows must be fully served by the history a decision fetches.
#[test]
fn test_builder_window_cap_matches_replay_window() {
    assert_eq!(
        i64::try_from(catalog::MAX_WINDOW_SECS).unwrap(),
        events::REPLAY_WINDOW_HOURS * 3600,
    );
}

/// The generated event reference lists exactly the fields ingestion writes,
/// per action, with the right types — so the on-page table for hand-written
/// temporal rules can never drift from what actually matches.
#[test]
fn test_event_reference_matches_ingestion() {
    use std::collections::{BTreeMap, BTreeSet};

    // Fields written per action, with the value shapes and (for strings)
    // the literal values seen — built the same way the projection test
    // builds its ingestion view.
    let mut written: BTreeMap<String, BTreeMap<String, (bool, BTreeSet<String>)>> = BTreeMap::new();
    for kind in events::HISTORY_KINDS {
        let row = history_row(kind.as_str(), "user-a", 60, 0);
        let event = events::history_event(&row, "org-1", 0)
            .unwrap_or_else(|| panic!("history kind '{}' has no mapping arm", kind.as_str()));
        let per_action = written
            .entry(dogwood_action_of(kind).to_string())
            .or_default();
        for group in ["input", "output"] {
            for (name, value) in event.fields(group) {
                let entry = per_action
                    .entry(format!("{group}.{name}"))
                    .or_insert_with(|| (false, BTreeSet::new()));
                match value {
                    Value::Bool(_) => entry.0 = true,
                    Value::String(s) => {
                        entry.1.insert(s.clone());
                    }
                    _ => {}
                }
            }
        }
    }

    // Same actions, by bare name.
    let cataloged: BTreeSet<&str> = catalog::HISTORY_ACTION_FIELDS
        .iter()
        .map(|a| a.action)
        .collect();
    let ingested: BTreeSet<String> = written
        .keys()
        .filter_map(|full| full.rsplit("::").next().map(ToString::to_string))
        .collect();
    assert_eq!(
        cataloged,
        ingested.iter().map(String::as_str).collect::<BTreeSet<_>>(),
        "the event reference must cover exactly the ingested actions"
    );

    for action_meta in catalog::HISTORY_ACTION_FIELDS {
        let Some((_, fields)) = written
            .iter()
            .find(|(full, _)| full.rsplit("::").next() == Some(action_meta.action))
        else {
            panic!("no ingestion view for '{}'", action_meta.action);
        };
        let cataloged_paths: BTreeSet<&str> = action_meta.fields.iter().map(|f| f.path).collect();
        let written_paths: BTreeSet<&str> = fields.keys().map(String::as_str).collect();
        assert_eq!(
            cataloged_paths, written_paths,
            "field list for '{}' must match ingestion",
            action_meta.action
        );
        for field in action_meta.fields {
            let (is_bool, string_values) = fields.get(field.path).unwrap();
            match field.kind {
                catalog::FieldKind::Bool => {
                    assert!(is_bool, "'{}' is not a boolean in ingestion", field.path);
                }
                catalog::FieldKind::TextEnum(values) => {
                    // Closed values come from the ingestion arms (one per
                    // credential audit kind), so the lists must agree.
                    let listed: BTreeSet<&str> = values.iter().copied().collect();
                    let seen: BTreeSet<&str> = string_values.iter().map(String::as_str).collect();
                    assert_eq!(
                        listed, seen,
                        "closed values for '{}' must match ingestion",
                        field.path
                    );
                }
                catalog::FieldKind::Text => {
                    assert!(
                        !is_bool,
                        "'{}' is declared text but ingestion writes booleans",
                        field.path
                    );
                }
                catalog::FieldKind::Long
                | catalog::FieldKind::StringSet(_)
                | catalog::FieldKind::VersionNum { .. }
                | catalog::FieldKind::BuildNum { .. } => {
                    panic!("event fields are text or boolean, got {:?}", field.kind)
                }
            }
        }
    }
}

// ============================================================
// Fail-closed behavior
// ============================================================

/// A policy that fails to lower must surface as an engine error;
/// enforcement treats that as a deny, never a pass.
#[test]
fn test_unlowerable_policy_is_fail_closed() {
    let composed = compose(&["posture.disk_encryption_enabled == true"]);
    let event = issue_token_request(&sample_posture(), "test-user", "test-org");
    assert!(
        decide(&composed, &event).is_err(),
        "unparseable text must surface as an engine error, which callers deny on"
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
/// checks fine and then silently never matches, which no amount of policy
/// review would catch.
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
    let result = test_policy_text(
        temporal,
        &sample_posture(),
        catalog::DecisionPoint::ExchangeToken,
    )
    .unwrap();
    assert!(
        result.reads_history,
        "a temporal policy's playground result must be flagged as history-dependent"
    );
    // Evaluated as the decision it gates, the empty-history step-up rule
    // denies. Evaluated as IssueToken it would trivially pass — the bug the
    // decision parameter exists to fix.
    assert!(
        !result.pass,
        "an exchange-scoped forbid must actually fire when tested as an exchange"
    );
    let as_issue = test_policy_text(
        temporal,
        &sample_posture(),
        catalog::DecisionPoint::IssueToken,
    )
    .unwrap();
    assert!(
        as_issue.pass,
        "the same policy never matches an IssueToken event"
    );
}

/// `reads_history` is structural (from the lowered set), not a text scan:
/// the phrase "when temporal" in a comment must not flag a plain policy.
#[test]
fn test_playground_reads_history_is_structural() {
    let commented = format!(
        "// when temporal is not used here\n{}",
        requirement("context.device.disk_encryption_enabled")
    );
    let result = test_policy_text(
        &commented,
        &sample_posture(),
        catalog::DecisionPoint::IssueToken,
    )
    .unwrap();
    assert!(
        !result.reads_history,
        "a comment mentioning temporal syntax must not mark the policy history-dependent"
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
            reads_device: false,
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

/// A custom policy that fails to lower is attributed by name, so the org's
/// working policies are not blamed and the admin can find the broken one.
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
            builder_spec: None,
            created_at: jiff::Timestamp::now(),
            updated_at: jiff::Timestamp::now(),
        },
        db::CustomPosturePolicy {
            id: "p2".to_string(),
            name: "Unparseable".to_string(),
            description: None,
            policy_text: "posture.disk_encryption_enabled == true".to_string(),
            active: true,
            org_id: "org-1".to_string(),
            builder_spec: None,
            created_at: jiff::Timestamp::now(),
            updated_at: jiff::Timestamp::now(),
        },
    ];
    let set = compose_org_set(&[], &custom);
    match run_precheck(&set.composed, &custom) {
        engine::Precheck::BrokenCustom(name) => assert_eq!(
            name, "Unparseable",
            "the precheck must name the policy that fails, not a working one"
        ),
        engine::Precheck::Ok { .. } => {
            panic!("a set containing unparseable text must not pass precheck")
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
        engine::Precheck::Ok { uses_temporal, .. } => assert!(
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
        engine::Precheck::Ok { uses_temporal, .. } => assert!(
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

/// Cedar is deny-by-default, so a set containing only `forbid` rules denies
/// even when every requirement is met. The base permits in `base_allow.dw`
/// are what turn "no forbid fired" into an allow — without them the engine
/// would deny every request.
#[test]
fn test_forbid_only_set_denies_even_when_satisfied() {
    let requirement_met = preconfigured_text(PreconfiguredSlug::DiskEncryption);
    let posture = sample_posture(); // disk encryption enabled — the forbid does not fire
    let event = issue_token_request(&posture, "test-user", "test-org");

    let without_permit = matches!(
        decide(requirement_met, &event),
        Ok(EngineDecision::Deny) | Err(_)
    );
    assert!(
        without_permit,
        "a forbid-only set must deny: nothing grants access"
    );

    // The same policy composed with the base permits allows.
    assert!(evaluate_one(requirement_met, &posture));
}

/// A custom policy that only reads event history must not force clients to
/// send device posture — the precheck reports what the set actually reads.
#[test]
fn test_precheck_reports_whether_posture_is_read() {
    let temporal_only = vec![db::CustomPosturePolicy {
        id: "p1".to_string(),
        name: "Exchange step-up".to_string(),
        description: None,
        policy_text: r#"forbid (principal, action == Vouch::Action::"ExchangeToken", resource)
when temporal {
    !(formerly within 15m Vouch::Action::"Login"::response{ output.result: true })
};"#
        .to_string(),
        active: true,
        org_id: "org-1".to_string(),
        builder_spec: None,
        created_at: jiff::Timestamp::now(),
        updated_at: jiff::Timestamp::now(),
    }];
    let set = compose_org_set(&[], &temporal_only);
    match run_precheck(&set.composed, &temporal_only) {
        engine::Precheck::Ok {
            uses_temporal,
            reads_device,
        } => {
            assert!(uses_temporal, "the policy reads event history");
            assert!(
                !reads_device,
                "a history-only policy must not demand device posture"
            );
        }
        other => panic!("expected a clean precheck, got {other:?}"),
    }

    // A posture policy does read the device record.
    let posture_set = compose_org_set(&["disk_encryption".to_string()], &[]);
    match run_precheck(&posture_set.composed, &[]) {
        engine::Precheck::Ok { reads_device, .. } => {
            assert!(reads_device, "a posture policy reads the device record");
        }
        other => panic!("expected a clean precheck, got {other:?}"),
    }
}

/// Ingestion reads audit payloads by key, so the keys must match what the
/// writers actually serialize. Serializing the real payload types and
/// asserting the values arrive catches a rename on either side — the parity
/// test cannot, since it only checks that a field is written at all.
#[test]
fn test_ingestion_reads_the_keys_writers_serialize() {
    use crate::db::documents::audit::{OAuthUsageData, TokenExchangeDetails};

    let exchange = serde_json::to_string(&TokenExchangeDetails {
        client_id: "client-abc".to_string(),
        audience: Some("https://aud.example".to_string()),
        scope: None,
        issued_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        token_expires_at: None,
    })
    .unwrap();
    let row = crate::db::audit::AuditEvent {
        id: "row-1".to_string(),
        event_type: "token_exchange".to_string(),
        user_id: Some("user-a".to_string()),
        email_domain: None,
        email_hmac: None,
        data: exchange,
        created_at: jiff::Timestamp::now(),
    };
    let event = events::history_event(&row, "org-1", 0).expect("exchange row must map");
    assert_eq!(
        event.field("input", "client_id"),
        Some(&dogwood_language::Value::String("client-abc".to_string())),
        "exchange history must carry the client id the writer stored"
    );
    assert_eq!(
        event.field("input", "audience"),
        Some(&dogwood_language::Value::String(
            "https://aud.example".to_string()
        )),
        "exchange history must carry the audience the writer stored"
    );

    let issuance = serde_json::to_string(&OAuthUsageData {
        oauth_client_id: "client-xyz".to_string(),
        details: None,
        client_ip: Some("10.1.2.3".to_string()),
        user_agent: None,
        country_code: None,
        asn: None,
        org_name: None,
    })
    .unwrap();
    let row = crate::db::audit::AuditEvent {
        id: "row-2".to_string(),
        event_type: "oauth_token_issued".to_string(),
        user_id: Some("user-a".to_string()),
        email_domain: None,
        email_hmac: None,
        data: issuance,
        created_at: jiff::Timestamp::now(),
    };
    let event = events::history_event(&row, "org-1", 0).expect("issuance row must map");
    assert_eq!(
        event.field("input", "client_id"),
        Some(&dogwood_language::Value::String("client-xyz".to_string())),
        "issuance history must carry the client id the writer stored"
    );
    assert_eq!(
        event.field("input", "ip"),
        Some(&dogwood_language::Value::String("10.1.2.3".to_string())),
        "issuance history must carry the client address the writer stored"
    );
}

/// The editable copy of a built-in drops its explanatory header and `@id`,
/// leaving a rule an admin can adapt without inheriting the built-in's
/// identity or its maintenance notes. What remains must still validate.
#[test]
fn test_as_editable_strips_comments_and_id() {
    for policy in PRECONFIGURED_POLICIES {
        let editable = as_editable(policy.policy_text);
        assert!(
            !editable.contains("//") && !editable.contains("@id("),
            "'{}' must copy without comments or an id: {editable}",
            policy.slug
        );
        assert!(
            editable.starts_with("forbid") || editable.starts_with("permit"),
            "'{}' must copy as a rule: {editable}",
            policy.slug
        );
        validate_policy_text(&editable)
            .unwrap_or_else(|e| panic!("copy of '{}' must validate: {e:?}", policy.slug));
    }
}

// ============================================================
// Multi-rule policy attribution (regression for rule-index mapping)
// ============================================================

/// `rule_count` parses policy text (the schema-independent phase) and
/// returns the number of Dogwood rules it contains — one per `forbid` or
/// `permit` statement. This is the count `compose_org_set` uses to size
/// `refs`, so it must agree with what lowering actually emits.
#[test]
fn test_rule_count_matches_policy_statements() {
    // Base permits: two `permit` statements.
    assert_eq!(rule_count(BASE_ALLOW), preconfigured::BASE_ALLOW_RULES);
    // Every preconfigured policy is a single rule.
    for policy in PRECONFIGURED_POLICIES {
        assert_eq!(
            rule_count(policy.policy_text),
            1,
            "preconfigured policy '{}' should be one rule",
            policy.slug
        );
    }
    // A single forbid is one rule.
    assert_eq!(
        rule_count(&requirement("context.device.disk_encryption_enabled")),
        1
    );
    // Two forbids in one text are two rules.
    let two_rules = format!(
        "{}\n{}",
        requirement("context.device.disk_encryption_enabled"),
        requirement("context.device.firewall_enabled"),
    );
    assert_eq!(rule_count(&two_rules), 2);
    // Three forbids are three rules.
    let three_rules = format!(
        "{two_rules}\n{}",
        requirement("context.device.screen_lock_enabled"),
    );
    assert_eq!(rule_count(&three_rules), 3);
    // A `permit` + `forbid` mix is two rules (permits count too: Dogwood
    // assigns them a rule_index).
    let mixed = format!(
        "permit (principal, action == Vouch::Action::\"IssueToken\", resource);\n{}",
        requirement("context.device.firewall_enabled"),
    );
    assert_eq!(rule_count(&mixed), 2);
}

/// The `BASE_ALLOW_RULES` constant must match the actual rule count of
/// `base_allow.dw` — the composed set's forbids start at this index, so a
/// stale constant would shift every attribution.
#[test]
fn test_base_allow_rules_constant_matches_actual() {
    assert_eq!(
        rule_count(BASE_ALLOW),
        preconfigured::BASE_ALLOW_RULES,
        "BASE_ALLOW_RULES must match the rule count of base_allow.dw"
    );
}

/// A custom policy with multiple `forbid` statements is valid Dogwood:
/// `validate_policy_text` checks syntax and types, not rule count. This
/// pins that acceptance so the attribution fix is exercised against the
/// same text an admin can actually save.
#[test]
fn test_multi_rule_custom_policy_validates() {
    let multi_rule = format!(
        "{}\n{}",
        requirement("context.device.disk_encryption_enabled"),
        requirement("context.device.firewall_enabled"),
    );
    validate_policy_text(&multi_rule)
        .unwrap_or_else(|e| panic!("multi-rule custom policy must validate: {e:?}"));
}

/// `refs` must carry one entry per Dogwood rule in the composed set, not
/// one per policy text. Dogwood assigns `rule_index` per rule in the
/// composed set, so `refs.len()` must equal the lowered set's total rule
/// count — otherwise `refs.get(rule_index)` returns `None` for rules
/// beyond the per-text entries.
#[test]
fn test_refs_align_with_lowered_rule_count() {
    let policy_schema = schema::policy_schema().expect("schema");
    let check = |slugs: &[String], custom: &[db::CustomPosturePolicy], label: &str| {
        let set = compose_org_set(slugs, custom);
        let lowered =
            LoweredPolicySet::from_str(&set.composed, schema::service_schema(), policy_schema)
                .unwrap_or_else(|e| panic!("'{label}': composed set must lower: {e}"));
        let total_rules = lowered.rules().count();
        assert_eq!(
            set.refs.len(),
            total_rules,
            "'{label}': refs must have one entry per Dogwood rule \
             (refs={}, rules={})",
            set.refs.len(),
            total_rules,
        );
    };

    // Base permits only.
    check(&[], &[], "base only");

    // All preconfigured policies active.
    let all_slugs: Vec<String> = PRECONFIGURED_POLICIES
        .iter()
        .map(|p| p.slug.as_str().to_string())
        .collect();
    check(&all_slugs, &[], "all preconfigured");

    // Single-rule custom policy.
    let single = vec![custom_policy(
        "single",
        &requirement("context.device.disk_encryption_enabled"),
    )];
    check(&[], &single, "single-rule custom");

    // Multi-rule custom policy (two forbids in one text).
    let multi_text = format!(
        "{}\n{}",
        requirement("context.device.disk_encryption_enabled"),
        requirement("context.device.firewall_enabled"),
    );
    let multi = vec![custom_policy("multi", &multi_text)];
    check(&[], &multi, "multi-rule custom");

    // Mixed: a preconfigured policy + a single-rule custom + a multi-rule
    // custom, all active together.
    check(
        &["disk_encryption".to_string()],
        &[
            custom_policy("single", &requirement("context.device.firewall_enabled")),
            custom_policy("multi", &multi_text),
        ],
        "mixed",
    );
}

/// The core regression: a multi-rule custom policy whose **second** `forbid`
/// triggers must be attributed to the custom policy by name. Before the
/// fix, `refs` had one entry per policy text, so `refs.get(rule_index)`
/// returned `None` for the second rule — an unattributed deny.
#[test]
fn test_multi_rule_custom_policy_second_rule_attributed() {
    let multi_rule_text = format!(
        "{}\n{}",
        requirement("context.device.disk_encryption_enabled"),
        requirement("context.device.firewall_enabled"),
    );
    let custom = vec![custom_policy("multi_rule", &multi_rule_text)];
    let set = compose_org_set(&[], &custom);

    // The composed set has 2 base permits + 2 forbids = 4 rules.
    let policy_schema = schema::policy_schema().expect("schema");
    let lowered =
        LoweredPolicySet::from_str(&set.composed, schema::service_schema(), policy_schema)
            .expect("must lower");
    assert_eq!(lowered.rules().count(), 4, "2 base permits + 2 forbids");
    assert_eq!(
        set.refs.len(),
        4,
        "refs must have one entry per rule, not per policy text"
    );

    // Posture where the first forbid's requirement is met (disk_encryption
    // enabled) but the second's is not (firewall disabled): the second
    // forbid fires at rule_index 3, which must map to the custom policy.
    let mut posture = sample_posture();
    posture.disk_encryption_enabled = Some(true);
    posture.firewall_enabled = Some(false);

    let now = jiff::Timestamp::now().as_second();
    let decision = engine::evaluate(lowered, &set.refs, &[], "org-1", now, |ts| {
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

    match decision {
        engine::OrgDecision::Deny(Some(engine::DenyingPolicy::Custom { name })) => {
            assert_eq!(
                name, "multi_rule",
                "the second forbid's deny must be attributed to the custom policy"
            );
        }
        engine::OrgDecision::Deny(None) => {
            panic!(
                "BUG: second forbid's deny is unattributed \
                 (refs.len()={}, expected 4)",
                set.refs.len()
            );
        }
        engine::OrgDecision::Allow => panic!("firewall disabled must deny"),
        engine::OrgDecision::Deny(Some(other)) => {
            panic!("unexpected denying policy: {other:?}");
        }
    }
}

/// The first rule of a multi-rule custom policy must be attributed
/// correctly — attribution entries exist for *all* rules, not only the
/// rules after the first.
#[test]
fn test_multi_rule_custom_policy_first_rule_attributed() {
    let multi_rule_text = format!(
        "{}\n{}",
        requirement("context.device.disk_encryption_enabled"),
        requirement("context.device.firewall_enabled"),
    );
    let custom = vec![custom_policy("multi_rule", &multi_rule_text)];
    let set = compose_org_set(&[], &custom);

    // Posture where the first forbid's requirement is NOT met (disk
    // encryption disabled) but the second's IS (firewall enabled): the
    // first forbid fires at rule_index 2.
    let mut posture = sample_posture();
    posture.disk_encryption_enabled = Some(false);
    posture.firewall_enabled = Some(true);

    let policy_schema = schema::policy_schema().expect("schema");
    let lowered =
        LoweredPolicySet::from_str(&set.composed, schema::service_schema(), policy_schema)
            .expect("must lower");
    let now = jiff::Timestamp::now().as_second();
    let decision = engine::evaluate(lowered, &set.refs, &[], "org-1", now, |ts| {
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

    match decision {
        engine::OrgDecision::Deny(Some(engine::DenyingPolicy::Custom { name })) => {
            assert_eq!(name, "multi_rule", "first forbid must be attributed too");
        }
        engine::OrgDecision::Deny(None) => panic!("BUG: first forbid unattributed"),
        engine::OrgDecision::Allow => panic!("disk encryption disabled must deny"),
        engine::OrgDecision::Deny(Some(other)) => {
            panic!("unexpected denying policy: {other:?}");
        }
    }
}

/// When both rules of a multi-rule policy fire, the deny must be attributed
/// to the custom policy — either rule's index maps to the same policy name.
#[test]
fn test_multi_rule_custom_policy_both_rules_attributed() {
    let multi_rule_text = format!(
        "{}\n{}",
        requirement("context.device.disk_encryption_enabled"),
        requirement("context.device.firewall_enabled"),
    );
    let custom = vec![custom_policy("multi_rule", &multi_rule_text)];
    let set = compose_org_set(&[], &custom);

    // Both requirements unmet: both forbids fire.
    let mut posture = sample_posture();
    posture.disk_encryption_enabled = Some(false);
    posture.firewall_enabled = Some(false);

    let policy_schema = schema::policy_schema().expect("schema");
    let lowered =
        LoweredPolicySet::from_str(&set.composed, schema::service_schema(), policy_schema)
            .expect("must lower");
    let now = jiff::Timestamp::now().as_second();
    let decision = engine::evaluate(lowered, &set.refs, &[], "org-1", now, |ts| {
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

    match decision {
        engine::OrgDecision::Deny(Some(engine::DenyingPolicy::Custom { name })) => {
            assert_eq!(name, "multi_rule", "both rules map to the same policy");
        }
        engine::OrgDecision::Deny(None) => panic!("BUG: deny unattributed when both rules fire"),
        engine::OrgDecision::Allow => panic!("both requirements unmet must deny"),
        engine::OrgDecision::Deny(Some(other)) => {
            panic!("unexpected denying policy: {other:?}");
        }
    }
}

/// A multi-rule custom policy that is satisfied (neither forbid fires)
/// must still allow — attribution is bookkeeping and must not change
/// enforcement.
#[test]
fn test_multi_rule_custom_policy_allows_when_satisfied() {
    let multi_rule_text = format!(
        "{}\n{}",
        requirement("context.device.disk_encryption_enabled"),
        requirement("context.device.firewall_enabled"),
    );
    let custom = vec![custom_policy("multi_rule", &multi_rule_text)];
    let set = compose_org_set(&[], &custom);

    // Both requirements met: neither forbid fires.
    let posture = sample_posture();

    let policy_schema = schema::policy_schema().expect("schema");
    let lowered =
        LoweredPolicySet::from_str(&set.composed, schema::service_schema(), policy_schema)
            .expect("must lower");
    let now = jiff::Timestamp::now().as_second();
    let decision = engine::evaluate(lowered, &set.refs, &[], "org-1", now, |ts| {
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

    assert!(
        matches!(decision, engine::OrgDecision::Allow),
        "both requirements met must allow, got {decision:?}"
    );
}

/// Build a `CustomPosturePolicy` for tests with the given name and text.
fn custom_policy(name: &str, policy_text: &str) -> db::CustomPosturePolicy {
    db::CustomPosturePolicy {
        id: format!("id-{name}"),
        name: name.to_string(),
        description: None,
        policy_text: policy_text.to_string(),
        active: true,
        org_id: "org-1".to_string(),
        builder_spec: None,
        created_at: jiff::Timestamp::now(),
        updated_at: jiff::Timestamp::now(),
    }
}

// ============================================================
// Deny attribution: metrics label vs. audit policy name
// ============================================================

/// A custom policy deny must record the actual policy name for the audit
/// record (not the generic "custom" label), while metrics keep "custom" to
/// avoid cardinality explosion from unbounded admin-chosen names.
#[test]
fn test_deny_attribution_custom_uses_name_for_audit() {
    let (metrics_label, audit_policy) = deny_attribution(&Some(engine::DenyingPolicy::Custom {
        name: "Corporate Security Policy".to_string(),
    }));
    assert_eq!(
        metrics_label, "custom",
        "metrics label for custom policies is the generic 'custom' \
         (cardinality control)"
    );
    assert_eq!(
        audit_policy, "Corporate Security Policy",
        "audit record must carry the actual custom policy name, not 'custom'"
    );
}

/// A preconfigured policy deny uses the slug for both metrics and audit —
/// the slug is a bounded, low-cardinality identifier that is also specific
/// enough for admin identification.
#[test]
fn test_deny_attribution_preconfigured_uses_slug_for_both() {
    let (metrics_label, audit_policy) = deny_attribution(&Some(
        engine::DenyingPolicy::Preconfigured(PreconfiguredSlug::DiskEncryption),
    ));
    assert_eq!(metrics_label, "disk_encryption");
    assert_eq!(audit_policy, "disk_encryption");
}

/// An unattributed deny (no determining rule found) uses "unattributed"
/// for both metrics and audit.
#[test]
fn test_deny_attribution_unattributed_uses_label_for_both() {
    let (metrics_label, audit_policy) = deny_attribution(&None);
    assert_eq!(metrics_label, "unattributed");
    assert_eq!(audit_policy, "unattributed");
}

/// Read back the single `policy_denied` audit event for a user and return
/// its parsed JSON data. Panics if there is not exactly one event.
async fn single_denial_audit_data(state: &crate::AppState, user_id: &str) -> serde_json::Value {
    let events = state
        .audit
        .query_events(&db::AuditEventFilter {
            event_types: Some(vec!["policy_denied".to_string()]),
            user_id: Some(user_id.to_string()),
            ..db::AuditEventFilter::default()
        })
        .await
        .expect("audit query");
    assert_eq!(
        events.len(),
        1,
        "expected exactly one policy_denied audit event, got {}",
        events.len()
    );
    serde_json::from_str(&events[0].data).expect("audit data is valid JSON")
}

/// When a custom posture policy denies during token issuance, the
/// `policy_denied` audit event must carry the actual policy name — not the
/// generic "custom" label. This is the end-to-end regression for the
/// audit-log policy-name bug: `authorize_decision` writes the audit record
/// through `record_denial`, and the record's `policy` field is what admins
/// see in the audit log.
#[tokio::test]
async fn test_authorize_decision_records_custom_policy_name_in_audit() {
    let state = crate::test_utils::test_app_state().await;

    // A custom posture policy that requires disk encryption. Minimal
    // posture does not have it, so this policy denies.
    let custom = vec![custom_policy(
        "Corporate Security Policy",
        &requirement("context.device.disk_encryption_enabled"),
    )];
    let posture = minimal_posture();
    let result = authorize_decision(
        &state,
        DecisionRequest {
            org_id: "org-1",
            user_id: "user-1",
            user_email: "alice@example.com",
            kind: DecisionKind::IssueToken {
                posture: &posture,
                ip: None,
                client_id: "test-client",
            },
            os: None,
        },
        &[],
        &custom,
    )
    .await;
    assert!(result.is_err(), "minimal posture must be denied");

    let data = single_denial_audit_data(&state, "user-1").await;
    assert_eq!(
        data["policy"].as_str(),
        Some("Corporate Security Policy"),
        "audit record must carry the actual custom policy name, not 'custom'"
    );
    assert_eq!(
        data["action"].as_str(),
        Some("issue_token"),
        "audit record must carry the decision action"
    );
    assert_eq!(
        data["org_id"].as_str(),
        Some("org-1"),
        "audit record must carry the org id"
    );
}

/// A preconfigured policy deny records the slug in the audit record — the
/// slug is already specific enough for admin identification, and is the
/// same value used for metrics (no cardinality concern).
#[tokio::test]
async fn test_authorize_decision_records_preconfigured_slug_in_audit() {
    let state = crate::test_utils::test_app_state().await;

    let slugs = vec!["disk_encryption".to_string()];
    let posture = minimal_posture();
    let result = authorize_decision(
        &state,
        DecisionRequest {
            org_id: "org-1",
            user_id: "user-2",
            user_email: "bob@example.com",
            kind: DecisionKind::IssueToken {
                posture: &posture,
                ip: None,
                client_id: "test-client",
            },
            os: None,
        },
        &slugs,
        &[],
    )
    .await;
    assert!(
        result.is_err(),
        "minimal posture must be denied by disk_encryption"
    );

    let data = single_denial_audit_data(&state, "user-2").await;
    assert_eq!(
        data["policy"].as_str(),
        Some("disk_encryption"),
        "audit record must carry the preconfigured slug"
    );
    assert_eq!(data["action"].as_str(), Some("issue_token"),);
}

/// When a custom temporal policy denies token exchange, the audit record
/// must carry the actual policy name and the `exchange_token` action. This
/// verifies the fix on the ExchangeToken path (no device posture), with a
/// temporal policy that denies when there is no recent login in history.
#[tokio::test]
async fn test_authorize_decision_exchange_records_custom_policy_name_in_audit() {
    let state = crate::test_utils::test_app_state().await;

    let custom = vec![custom_policy(
        "Exchange Step-Up",
        r#"forbid (principal, action == Vouch::Action::"ExchangeToken", resource)
when temporal {
    !(formerly within 15m Vouch::Action::"Login"::response{ output.result: true })
};"#,
    )];
    let result = authorize_decision(
        &state,
        DecisionRequest {
            org_id: "org-1",
            user_id: "user-3",
            user_email: "carol@example.com",
            kind: DecisionKind::ExchangeToken {
                ip: None,
                client_id: "test-client",
                audience: None,
            },
            os: None,
        },
        &[],
        &custom,
    )
    .await;
    assert!(
        result.is_err(),
        "exchange with no recent login must be denied by the step-up policy"
    );

    let data = single_denial_audit_data(&state, "user-3").await;
    assert_eq!(
        data["policy"].as_str(),
        Some("Exchange Step-Up"),
        "audit record must carry the actual custom policy name for exchange denials"
    );
    assert_eq!(
        data["action"].as_str(),
        Some("exchange_token"),
        "audit record must carry the exchange_token action"
    );
}

/// A multi-rule custom policy deny must record the actual policy name in
/// the audit record — the attribution fix (one ref per rule) and the
/// audit-name fix (actual name, not "custom") compose correctly.
#[tokio::test]
async fn test_authorize_decision_multi_rule_custom_policy_name_in_audit() {
    let state = crate::test_utils::test_app_state().await;

    let multi_rule = format!(
        "{}\n{}",
        requirement("context.device.disk_encryption_enabled"),
        requirement("context.device.firewall_enabled"),
    );
    let custom = vec![custom_policy("Multi-Rule Policy", &multi_rule)];

    // Posture where the first requirement is met but the second is not:
    // the second forbid fires, and must be attributed to the custom policy.
    let mut posture = sample_posture();
    posture.disk_encryption_enabled = Some(true);
    posture.firewall_enabled = Some(false);

    let result = authorize_decision(
        &state,
        DecisionRequest {
            org_id: "org-1",
            user_id: "user-4",
            user_email: "dave@example.com",
            kind: DecisionKind::IssueToken {
                posture: &posture,
                ip: None,
                client_id: "test-client",
            },
            os: None,
        },
        &[],
        &custom,
    )
    .await;
    assert!(result.is_err(), "firewall disabled must deny");

    let data = single_denial_audit_data(&state, "user-4").await;
    assert_eq!(
        data["policy"].as_str(),
        Some("Multi-Rule Policy"),
        "audit record must carry the custom policy name even when the \
         second rule of a multi-rule policy fires"
    );
}
