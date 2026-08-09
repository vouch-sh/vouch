// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `DevicePosture` → Dogwood context record.
//!
//! Builds the `context.input.posture` record every policy evaluates against.
//! Every schema field is always present: absent `Option` fields get typed
//! defaults (`false` / `""` / `0` / empty set) so policies can reference any
//! field without runtime errors — the same guarantee `FIELD_DEFAULTS` gave
//! the CEL engine. Four derived fields are computed here in Rust instead of
//! registering an engine function: `os_version_num` (the old `semver()`),
//! `os_build_num`, `edr_count`, `mdm_count`.

use dogwood_language::Value;
use std::collections::BTreeMap;
use vouch_common::posture::DevicePosture;

/// Sentinel for "not parseable as a version/build number": every `>=`
/// threshold comparison fails against it (fail-closed, and matches the old
/// CEL behavior where a `semver()` error propagated to a policy failure).
const NOT_A_NUMBER: i64 = -1;

/// `"15.3.1"` → `15_003_001`, the old CEL `semver()` encoding.
///
/// Accepts 1–3 dot-separated integer components ("15" → 15_000_000,
/// "15.3" → 15_003_000). Four or more components (Windows' "10.0.26100.0")
/// and non-numeric components return `None`.
pub(crate) fn semver_num(version: &str) -> Option<i64> {
    let mut parts = version.splitn(4, '.');
    let major: i64 = parts.next().and_then(|s| s.parse().ok())?;
    let minor: i64 = match parts.next() {
        Some(s) => s.parse().ok()?,
        None => 0,
    };
    let patch: i64 = match parts.next() {
        Some(s) => s.parse().ok()?,
        None => 0,
    };
    if parts.next().is_some() {
        return None;
    }
    Some(
        major
            .saturating_mul(1_000_000)
            .saturating_add(minor.saturating_mul(1_000))
            .saturating_add(patch),
    )
}

fn string_value(value: &Option<String>) -> Value {
    Value::String(value.clone().unwrap_or_default())
}

fn bool_value(value: Option<bool>) -> Value {
    Value::Bool(value.unwrap_or(false))
}

fn long_value(value: Option<u64>) -> Value {
    Value::Int(value.map_or(0, |v| i64::try_from(v).unwrap_or(i64::MAX)))
}

/// Build the posture fields for the `device` context group, as
/// `(field name, value)` pairs — the event builder writes one
/// `group.field` at a time, so policies read `context.device.<field>`.
///
/// The exhaustive destructuring is deliberate: adding a field to
/// `DevicePosture` breaks this function at compile time, forcing the schema
/// (`vouch.cedarschema`) and the parity test to be updated with it.
pub(crate) fn posture_fields(posture: &DevicePosture) -> BTreeMap<String, Value> {
    let DevicePosture {
        detail_type: _,
        posture_version: _,
        os,
        os_version,
        os_distribution,
        os_build,
        arch,
        disk_encryption_enabled,
        disk_encryption_technology,
        screen_lock_enabled,
        screen_lock_idle_timeout_secs,
        firewall_enabled,
        firewall_technology,
        secure_boot_enabled,
        sip_enabled,
        tpm_present,
        tpm_version,
        auto_update_enabled,
        auto_update_technology,
        uptime_secs,
        access_control_enforcing,
        access_control_technology,
        edr,
        mdm,
        elevated,
        tty,
        parent_process,
        cli_version,
        collected_at,
    } = posture;

    let os_version_str = os_version.clone().unwrap_or_default();
    let os_build_str = os_build.clone().unwrap_or_default();
    let edr_names: Vec<Value> = edr
        .iter()
        .map(|a| Value::String(a.as_str().to_string()))
        .collect();
    let mdm_names: Vec<Value> = mdm
        .iter()
        .map(|a| Value::String(a.as_str().to_string()))
        .collect();

    let mut record: BTreeMap<String, Value> = BTreeMap::new();
    record.insert(
        "os".to_string(),
        Value::String(
            os.as_ref()
                .map(|o| o.as_str().to_string())
                .unwrap_or_default(),
        ),
    );
    record.insert(
        "os_version".to_string(),
        Value::String(os_version_str.clone()),
    );
    record.insert(
        "os_version_num".to_string(),
        Value::Int(semver_num(&os_version_str).unwrap_or(NOT_A_NUMBER)),
    );
    record.insert("os_distribution".to_string(), string_value(os_distribution));
    record.insert("os_build".to_string(), Value::String(os_build_str.clone()));
    record.insert(
        "os_build_num".to_string(),
        Value::Int(os_build_str.parse::<i64>().unwrap_or(NOT_A_NUMBER)),
    );
    record.insert("arch".to_string(), string_value(arch));
    record.insert(
        "disk_encryption_enabled".to_string(),
        bool_value(*disk_encryption_enabled),
    );
    record.insert(
        "disk_encryption_technology".to_string(),
        string_value(disk_encryption_technology),
    );
    record.insert(
        "screen_lock_enabled".to_string(),
        bool_value(*screen_lock_enabled),
    );
    record.insert(
        "screen_lock_idle_timeout_secs".to_string(),
        long_value(*screen_lock_idle_timeout_secs),
    );
    record.insert(
        "firewall_enabled".to_string(),
        bool_value(*firewall_enabled),
    );
    record.insert(
        "firewall_technology".to_string(),
        string_value(firewall_technology),
    );
    record.insert(
        "secure_boot_enabled".to_string(),
        bool_value(*secure_boot_enabled),
    );
    record.insert("sip_enabled".to_string(), bool_value(*sip_enabled));
    record.insert("tpm_present".to_string(), bool_value(*tpm_present));
    record.insert("tpm_version".to_string(), string_value(tpm_version));
    record.insert(
        "auto_update_enabled".to_string(),
        bool_value(*auto_update_enabled),
    );
    record.insert(
        "auto_update_technology".to_string(),
        string_value(auto_update_technology),
    );
    record.insert("uptime_secs".to_string(), long_value(*uptime_secs));
    record.insert(
        "access_control_enforcing".to_string(),
        bool_value(*access_control_enforcing),
    );
    record.insert(
        "access_control_technology".to_string(),
        string_value(access_control_technology),
    );
    record.insert(
        "edr_count".to_string(),
        Value::Int(i64::try_from(edr_names.len()).unwrap_or(i64::MAX)),
    );
    record.insert("edr".to_string(), Value::Array(edr_names));
    record.insert(
        "mdm_count".to_string(),
        Value::Int(i64::try_from(mdm_names.len()).unwrap_or(i64::MAX)),
    );
    record.insert("mdm".to_string(), Value::Array(mdm_names));
    record.insert("elevated".to_string(), bool_value(*elevated));
    record.insert("tty".to_string(), bool_value(*tty));
    record.insert("parent_process".to_string(), string_value(parent_process));
    record.insert("cli_version".to_string(), string_value(cli_version));
    record.insert("collected_at".to_string(), string_value(collected_at));

    record
}
