// SPDX-License-Identifier: BUSL-1.1
//! Device posture policy evaluation using CEL (Common Expression Language).
//!
//! Provides preconfigured policies defined in code (updatable via deploy)
//! and evaluation of custom CEL expressions against device posture data.
//! All active policies are ANDed — every active policy must pass for
//! token issuance to succeed.

use crate::db;
use crate::db::store::DocumentStore;
use crate::services::{OAuthErrorCode, ServiceError, ServiceResult};
use cel::{Context, Program, Value};
use std::collections::HashMap;
use vouch_common::posture::DevicePosture;

/// Maximum number of active policies (preconfigured + custom combined).
pub const MAX_ACTIVE_POLICIES: usize = 5;

// ============================================================
// Preconfigured Policies (code-defined)
// ============================================================

/// A preconfigured posture policy defined in code.
pub struct PreconfiguredPolicy {
    pub slug: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub cel_expression: &'static str,
}

/// All preconfigured policies. Updated by deploying new code.
pub const PRECONFIGURED_POLICIES: &[PreconfiguredPolicy] = &[
    PreconfiguredPolicy {
        slug: "disk_encryption",
        name: "Disk Encryption",
        description: "Require full-disk encryption (FileVault, BitLocker, LUKS)",
        cel_expression: "posture.disk_encryption_enabled == true",
    },
    PreconfiguredPolicy {
        slug: "firewall",
        name: "Firewall",
        description: "Require an active firewall",
        cel_expression: "posture.firewall_enabled == true",
    },
    PreconfiguredPolicy {
        slug: "screen_lock",
        name: "Screen Lock",
        description: "Require screen lock on idle",
        cel_expression: "posture.screen_lock_enabled == true",
    },
    PreconfiguredPolicy {
        slug: "endpoint_protection",
        name: "Endpoint Protection",
        description: "Require at least one EDR agent installed",
        cel_expression: "size(posture.edr) > 0",
    },
    PreconfiguredPolicy {
        slug: "platform_integrity",
        name: "Platform Integrity",
        description: "Require Secure Boot to be enabled",
        cel_expression: "posture.secure_boot_enabled == true",
    },
    PreconfiguredPolicy {
        slug: "os_currency",
        name: "OS Currency",
        description: "Require a supported OS version (N-1)",
        // macOS 14+ (Sonoma), Windows 10 build 26100+, Linux always passes
        cel_expression: concat!(
            "(posture.os == \"macos\" && posture.os_version >= \"14\")",
            " || (posture.os == \"windows\"",
            " && posture.os_version >= \"10.0.26100\")",
            " || (posture.os == \"linux\")",
        ),
    },
];

/// Look up a preconfigured policy by slug.
#[must_use]
pub fn get_preconfigured_policy(slug: &str) -> Option<&'static PreconfiguredPolicy> {
    PRECONFIGURED_POLICIES.iter().find(|p| p.slug == slug)
}

/// Check if a slug is a valid preconfigured policy.
#[must_use]
pub fn is_valid_preconfigured_slug(slug: &str) -> bool {
    PRECONFIGURED_POLICIES.iter().any(|p| p.slug == slug)
}

// ============================================================
// CEL Expression Validation
// ============================================================

/// Validate a CEL expression for syntax correctness.
///
/// Returns `Ok(())` if the expression parses successfully, or a
/// `ServiceError` with the parse error details.
pub fn validate_cel_expression(expression: &str) -> ServiceResult<()> {
    let trimmed = expression.trim();
    if trimmed.is_empty() {
        return Err(ServiceError::api(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_cel_expression",
            "CEL expression must not be empty",
        ));
    }
    // Program::compile may panic on certain malformed inputs (e.g.
    // unterminated string literals), so catch panics and treat them
    // as validation failures.
    let compile_result = std::panic::catch_unwind(|| Program::compile(trimmed));
    match compile_result {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(ServiceError::api(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_cel_expression",
            format!("Invalid CEL expression: {e}"),
        )),
        Err(_) => Err(ServiceError::api(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_cel_expression",
            "Invalid CEL expression: failed to parse",
        )),
    }
}

// ============================================================
// CEL Context Building
// ============================================================

/// Convert a `DevicePosture` into a CEL context with a `posture` map variable.
///
/// Optional fields default to safe values when `None`:
/// - `Option<bool>` → `false`
/// - `Option<String>` → `""`
/// - `Option<u64>` → `0`
/// - `Vec<String>` → empty list
fn build_cel_context(posture: &DevicePosture) -> Context<'_> {
    let mut ctx = Context::default();

    let mut map: HashMap<String, Value> = HashMap::new();

    // OS info
    map.insert(
        "os".into(),
        Value::String(posture.os.as_deref().unwrap_or("").to_string().into()),
    );
    map.insert(
        "os_version".into(),
        Value::String(
            posture
                .os_version
                .as_deref()
                .unwrap_or("")
                .to_string()
                .into(),
        ),
    );
    map.insert(
        "os_distribution".into(),
        Value::String(
            posture
                .os_distribution
                .as_deref()
                .unwrap_or("")
                .to_string()
                .into(),
        ),
    );
    map.insert(
        "os_build".into(),
        Value::String(posture.os_build.as_deref().unwrap_or("").to_string().into()),
    );
    map.insert(
        "arch".into(),
        Value::String(posture.arch.as_deref().unwrap_or("").to_string().into()),
    );

    // Disk encryption
    map.insert(
        "disk_encryption_enabled".into(),
        Value::Bool(posture.disk_encryption_enabled.unwrap_or(false)),
    );
    map.insert(
        "disk_encryption_technology".into(),
        Value::String(
            posture
                .disk_encryption_technology
                .as_deref()
                .unwrap_or("")
                .to_string()
                .into(),
        ),
    );

    // Screen lock
    map.insert(
        "screen_lock_enabled".into(),
        Value::Bool(posture.screen_lock_enabled.unwrap_or(false)),
    );
    map.insert(
        "screen_lock_idle_timeout_secs".into(),
        Value::UInt(posture.screen_lock_idle_timeout_secs.unwrap_or(0)),
    );

    // Firewall
    map.insert(
        "firewall_enabled".into(),
        Value::Bool(posture.firewall_enabled.unwrap_or(false)),
    );
    map.insert(
        "firewall_technology".into(),
        Value::String(
            posture
                .firewall_technology
                .as_deref()
                .unwrap_or("")
                .to_string()
                .into(),
        ),
    );

    // Secure boot / TPM
    map.insert(
        "secure_boot_enabled".into(),
        Value::Bool(posture.secure_boot_enabled.unwrap_or(false)),
    );
    map.insert(
        "sip_enabled".into(),
        Value::Bool(posture.sip_enabled.unwrap_or(false)),
    );
    map.insert(
        "tpm_present".into(),
        Value::Bool(posture.tpm_present.unwrap_or(false)),
    );
    map.insert(
        "tpm_version".into(),
        Value::String(
            posture
                .tpm_version
                .as_deref()
                .unwrap_or("")
                .to_string()
                .into(),
        ),
    );

    // Auto-update
    map.insert(
        "auto_update_enabled".into(),
        Value::Bool(posture.auto_update_enabled.unwrap_or(false)),
    );
    map.insert(
        "auto_update_technology".into(),
        Value::String(
            posture
                .auto_update_technology
                .as_deref()
                .unwrap_or("")
                .to_string()
                .into(),
        ),
    );

    // Uptime
    map.insert(
        "uptime_secs".into(),
        Value::UInt(posture.uptime_secs.unwrap_or(0)),
    );

    // Access control
    map.insert(
        "access_control_enforcing".into(),
        Value::Bool(posture.access_control_enforcing.unwrap_or(false)),
    );
    map.insert(
        "access_control_technology".into(),
        Value::String(
            posture
                .access_control_technology
                .as_deref()
                .unwrap_or("")
                .to_string()
                .into(),
        ),
    );

    // EDR (list of strings)
    let edr_list: Vec<Value> = posture
        .edr
        .iter()
        .map(|s| Value::String(s.clone().into()))
        .collect();
    map.insert("edr".into(), Value::List(edr_list.into()));

    // MDM (list of strings)
    let mdm_list: Vec<Value> = posture
        .mdm
        .iter()
        .map(|s| Value::String(s.clone().into()))
        .collect();
    map.insert("mdm".into(), Value::List(mdm_list.into()));

    // Execution context
    map.insert(
        "elevated".into(),
        Value::Bool(posture.elevated.unwrap_or(false)),
    );
    map.insert("tty".into(), Value::Bool(posture.tty.unwrap_or(false)));
    map.insert(
        "parent_process".into(),
        Value::String(
            posture
                .parent_process
                .as_deref()
                .unwrap_or("")
                .to_string()
                .into(),
        ),
    );

    // Meta
    map.insert(
        "cli_version".into(),
        Value::String(
            posture
                .cli_version
                .as_deref()
                .unwrap_or("")
                .to_string()
                .into(),
        ),
    );

    ctx.add_variable("posture", Value::Map(map.into()))
        .unwrap_or(());

    ctx
}

// ============================================================
// CEL Evaluation
// ============================================================

/// Evaluate a single CEL expression against a posture context.
///
/// Returns `true` if the policy passes, `false` if it fails.
/// Runtime evaluation errors are treated as failures (fail-closed).
fn evaluate_cel(expression: &str, ctx: &Context<'_>) -> bool {
    let compile_result = std::panic::catch_unwind(|| Program::compile(expression));
    let program = match compile_result {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            tracing::warn!("CEL compile error during evaluation: {e}");
            return false;
        }
        Err(_) => {
            tracing::warn!("CEL parser panicked during evaluation");
            return false;
        }
    };

    match program.execute(ctx) {
        Ok(Value::Bool(result)) => result,
        Ok(_) => {
            tracing::warn!("CEL expression returned non-bool value");
            false
        }
        Err(e) => {
            tracing::warn!("CEL evaluation error: {e}");
            false
        }
    }
}

/// Evaluate a CEL expression against a sample `DevicePosture` for validation.
///
/// Returns `Ok(true)` if the policy passes, `Ok(false)` if it fails,
/// or `Err` if the expression cannot be compiled.
pub fn test_cel_expression(expression: &str, posture: &DevicePosture) -> ServiceResult<bool> {
    // Reuse validation (handles empty, panics, parse errors)
    validate_cel_expression(expression)?;

    // Safe to compile again — validation passed, so this won't panic.
    let program = Program::compile(expression).map_err(|e| {
        ServiceError::api(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_cel_expression",
            format!("Invalid CEL expression: {e}"),
        )
    })?;

    let ctx = build_cel_context(posture);

    match program.execute(&ctx) {
        Ok(Value::Bool(result)) => Ok(result),
        Ok(_) => Ok(false),
        Err(e) => {
            tracing::warn!("CEL test evaluation error: {e}");
            Ok(false)
        }
    }
}

// ============================================================
// Remediation Guidance
// ============================================================

/// Get OS-specific remediation guidance for a preconfigured policy slug.
#[must_use]
pub fn remediation_for_slug(slug: &str, os: Option<&str>) -> String {
    let os = os.unwrap_or("unknown");

    match (slug, os) {
        // Disk encryption
        ("disk_encryption", "macos") => {
            "Enable FileVault in System Settings > Privacy & Security".to_string()
        }
        ("disk_encryption", "linux") => "Enable LUKS encryption with cryptsetup".to_string(),
        ("disk_encryption", "windows") => {
            "Enable BitLocker in Settings > Device encryption".to_string()
        }
        ("disk_encryption", _) => "Enable full-disk encryption on your device".to_string(),

        // Firewall
        ("firewall", "macos") => {
            "Enable Firewall in System Settings > Network > Firewall".to_string()
        }
        ("firewall", "linux") => "Enable firewall with: sudo ufw enable".to_string(),
        ("firewall", "windows") => "Enable Windows Firewall in Windows Security".to_string(),
        ("firewall", _) => "Enable your system firewall".to_string(),

        // Screen lock
        ("screen_lock", "macos") => "Set screen lock in System Settings > Lock Screen".to_string(),
        ("screen_lock", "linux") => "Configure screen lock in your display settings".to_string(),
        ("screen_lock", "windows") => {
            "Set screen lock in Settings > Accounts > Sign-in options".to_string()
        }
        ("screen_lock", _) => "Enable screen lock on your device".to_string(),

        // Endpoint protection
        ("endpoint_protection", "macos" | "linux") => {
            "Install an EDR agent (e.g., CrowdStrike, SentinelOne)".to_string()
        }
        ("endpoint_protection", "windows") => "Install an EDR agent (e.g., CrowdStrike, \
             Microsoft Defender for Endpoint)"
            .to_string(),
        ("endpoint_protection", _) => {
            "Install an endpoint detection and response (EDR) agent".to_string()
        }

        // Platform integrity
        ("platform_integrity", "macos") => "Secure Boot is managed by Apple and should be enabled \
             by default"
            .to_string(),
        ("platform_integrity", "linux" | "windows") => {
            "Enable Secure Boot in your UEFI/BIOS firmware settings".to_string()
        }
        ("platform_integrity", _) => "Enable Secure Boot on your device".to_string(),

        // OS currency
        ("os_currency", "macos") => "Update macOS to a supported version (14 or later)".to_string(),
        ("os_currency", "windows") => "Update Windows to a supported version (build 26100 \
             or later)"
            .to_string(),
        ("os_currency", _) => "Update your operating system to a supported version".to_string(),

        // Unknown slug (custom policy)
        _ => "Contact your organization administrator for device \
             compliance requirements"
            .to_string(),
    }
}

// ============================================================
// Policy Enforcement
// ============================================================

/// Evaluate all active posture policies for an org against device posture.
///
/// Called during FIDO2 token issuance (between assertion verification
/// and access token creation).
///
/// # Errors
///
/// Returns `ServiceError::OAuth { AccessDenied, ... }` if:
/// - Active policies exist but no device posture was provided
/// - Any active policy's CEL expression evaluates to `false`
pub async fn evaluate_posture_policies(
    store: &DocumentStore,
    org_id: &str,
    authorization_details_json: Option<&str>,
) -> ServiceResult<()> {
    // Load active preconfigured slugs
    let active_slugs = db::get_active_preconfigured_slugs(store, org_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to load posture config: {e}")))?;

    // Load active custom policies
    let active_custom = db::get_active_custom_policies(store, org_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to load custom policies: {e}")))?;

    // No active policies → no enforcement
    if active_slugs.is_empty() && active_custom.is_empty() {
        return Ok(());
    }

    // Parse device posture from authorization_details
    let posture = extract_device_posture(authorization_details_json)?;

    let ctx = build_cel_context(&posture);
    let os = posture.os.as_deref();

    // Evaluate preconfigured policies
    for slug in &active_slugs {
        if let Some(policy) = get_preconfigured_policy(slug)
            && !evaluate_cel(policy.cel_expression, &ctx)
        {
            let remediation = remediation_for_slug(policy.slug, os);
            return Err(ServiceError::oauth(
                OAuthErrorCode::AccessDenied,
                format!(
                    "Device posture policy '{}' not satisfied. \
                     {remediation}",
                    policy.name
                ),
            ));
        }
    }

    // Evaluate custom policies
    for policy in &active_custom {
        if !evaluate_cel(&policy.cel_expression, &ctx) {
            let remediation = "Contact your organization \
                administrator for device compliance requirements"
                .to_string();
            return Err(ServiceError::oauth(
                OAuthErrorCode::AccessDenied,
                format!(
                    "Device posture policy '{}' not satisfied. \
                     {remediation}",
                    policy.name
                ),
            ));
        }
    }

    Ok(())
}

/// Extract `DevicePosture` from the `authorization_details` JSON string.
///
/// Looks for an entry with `type: "device_posture"` in the RFC 9396 array.
fn extract_device_posture(ad_json: Option<&str>) -> ServiceResult<DevicePosture> {
    let json = ad_json.ok_or_else(|| {
        ServiceError::oauth(
            OAuthErrorCode::AccessDenied,
            "Device posture data is required by organization policy",
        )
    })?;

    let entries: Vec<serde_json::Value> = serde_json::from_str(json).map_err(|e| {
        ServiceError::oauth(
            OAuthErrorCode::AccessDenied,
            format!("Invalid authorization_details format: {e}"),
        )
    })?;

    for entry in &entries {
        let type_name = entry.get("type").and_then(serde_json::Value::as_str);
        if type_name == Some(vouch_common::posture::POSTURE_TYPE) {
            let posture: DevicePosture = serde_json::from_value(entry.clone()).map_err(|e| {
                ServiceError::oauth(
                    OAuthErrorCode::AccessDenied,
                    format!("Invalid device posture data: {e}"),
                )
            })?;
            return Ok(posture);
        }
    }

    Err(ServiceError::oauth(
        OAuthErrorCode::AccessDenied,
        "Device posture data is required by organization policy",
    ))
}

// ============================================================
// Posture Schema (for admin UI reference)
// ============================================================

/// Returns the posture field schema as a JSON-serializable map.
///
/// Used by the list endpoint to provide field reference for custom CEL.
#[must_use]
pub fn posture_schema() -> serde_json::Value {
    serde_json::json!({
        "os": "string",
        "os_version": "string",
        "os_distribution": "string",
        "os_build": "string",
        "arch": "string",
        "disk_encryption_enabled": "bool",
        "disk_encryption_technology": "string",
        "screen_lock_enabled": "bool",
        "screen_lock_idle_timeout_secs": "uint",
        "firewall_enabled": "bool",
        "firewall_technology": "string",
        "secure_boot_enabled": "bool",
        "sip_enabled": "bool",
        "tpm_present": "bool",
        "tpm_version": "string",
        "auto_update_enabled": "bool",
        "auto_update_technology": "string",
        "uptime_secs": "uint",
        "access_control_enforcing": "bool",
        "access_control_technology": "string",
        "edr": "list<string>",
        "mdm": "list<string>",
        "elevated": "bool",
        "tty": "bool",
        "parent_process": "string",
        "cli_version": "string"
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    fn sample_posture() -> DevicePosture {
        DevicePosture {
            detail_type: "device_posture".to_string(),
            posture_version: 1,
            os: Some("macos".to_string()),
            os_version: Some("15.3.1".to_string()),
            disk_encryption_enabled: Some(true),
            disk_encryption_technology: Some("filevault".to_string()),
            firewall_enabled: Some(true),
            firewall_technology: Some("application firewall".to_string()),
            screen_lock_enabled: Some(true),
            screen_lock_idle_timeout_secs: Some(300),
            secure_boot_enabled: Some(true),
            sip_enabled: Some(true),
            edr: vec!["crowdstrike".to_string()],
            mdm: vec!["jamf".to_string()],
            elevated: Some(false),
            tty: Some(true),
            ..Default::default()
        }
    }

    fn minimal_posture() -> DevicePosture {
        DevicePosture::new()
    }

    #[test]
    fn test_validate_cel_expression_valid() {
        validate_cel_expression("posture.disk_encryption_enabled == true").unwrap();
        validate_cel_expression("size(posture.edr) > 0").unwrap();
        validate_cel_expression("posture.os == \"macos\" || posture.os == \"linux\"").unwrap();
    }

    #[test]
    fn test_validate_cel_expression_invalid() {
        // Empty expression
        assert!(validate_cel_expression("").is_err());
        // Whitespace-only expression
        assert!(validate_cel_expression("   ").is_err());
        // Unterminated string literal (causes parser panic, caught)
        assert!(validate_cel_expression("posture.os == \"unterminated").is_err());
    }

    #[test]
    fn test_evaluate_disk_encryption_pass() {
        let posture = sample_posture();
        let ctx = build_cel_context(&posture);
        assert!(evaluate_cel(
            "posture.disk_encryption_enabled == true",
            &ctx
        ));
    }

    #[test]
    fn test_evaluate_disk_encryption_fail() {
        let posture = minimal_posture();
        let ctx = build_cel_context(&posture);
        assert!(!evaluate_cel(
            "posture.disk_encryption_enabled == true",
            &ctx
        ));
    }

    #[test]
    fn test_evaluate_firewall_pass() {
        let posture = sample_posture();
        let ctx = build_cel_context(&posture);
        assert!(evaluate_cel("posture.firewall_enabled == true", &ctx));
    }

    #[test]
    fn test_evaluate_screen_lock_pass() {
        let posture = sample_posture();
        let ctx = build_cel_context(&posture);
        assert!(evaluate_cel("posture.screen_lock_enabled == true", &ctx));
    }

    #[test]
    fn test_evaluate_edr_pass() {
        let posture = sample_posture();
        let ctx = build_cel_context(&posture);
        assert!(evaluate_cel("size(posture.edr) > 0", &ctx));
    }

    #[test]
    fn test_evaluate_edr_fail_empty() {
        let posture = minimal_posture();
        let ctx = build_cel_context(&posture);
        assert!(!evaluate_cel("size(posture.edr) > 0", &ctx));
    }

    #[test]
    fn test_evaluate_secure_boot_pass() {
        let posture = sample_posture();
        let ctx = build_cel_context(&posture);
        assert!(evaluate_cel("posture.secure_boot_enabled == true", &ctx));
    }

    #[test]
    fn test_evaluate_os_currency_macos_pass() {
        let posture = sample_posture();
        let ctx = build_cel_context(&posture);
        let expr = PRECONFIGURED_POLICIES
            .iter()
            .find(|p| p.slug == "os_currency")
            .unwrap()
            .cel_expression;
        assert!(evaluate_cel(expr, &ctx));
    }

    #[test]
    fn test_evaluate_os_currency_old_macos_fail() {
        let mut posture = sample_posture();
        posture.os_version = Some("13.0".to_string());
        let ctx = build_cel_context(&posture);
        let expr = PRECONFIGURED_POLICIES
            .iter()
            .find(|p| p.slug == "os_currency")
            .unwrap()
            .cel_expression;
        assert!(!evaluate_cel(expr, &ctx));
    }

    #[test]
    fn test_evaluate_os_currency_linux_always_passes() {
        let mut posture = minimal_posture();
        posture.os = Some("linux".to_string());
        let ctx = build_cel_context(&posture);
        let expr = PRECONFIGURED_POLICIES
            .iter()
            .find(|p| p.slug == "os_currency")
            .unwrap()
            .cel_expression;
        assert!(evaluate_cel(expr, &ctx));
    }

    #[test]
    fn test_none_fields_default_to_false() {
        let posture = minimal_posture();
        let ctx = build_cel_context(&posture);
        assert!(!evaluate_cel(
            "posture.disk_encryption_enabled == true",
            &ctx
        ));
        assert!(!evaluate_cel("posture.firewall_enabled == true", &ctx));
        assert!(!evaluate_cel("posture.screen_lock_enabled == true", &ctx));
        assert!(!evaluate_cel("posture.secure_boot_enabled == true", &ctx));
    }

    #[test]
    fn test_none_string_fields_default_to_empty() {
        let posture = minimal_posture();
        let ctx = build_cel_context(&posture);
        assert!(evaluate_cel("posture.os == \"\"", &ctx));
    }

    #[test]
    fn test_all_preconfigured_policies_compile() {
        for policy in PRECONFIGURED_POLICIES {
            Program::compile(policy.cel_expression)
                .unwrap_or_else(|e| panic!("Policy '{}' failed to compile: {e}", policy.slug));
        }
    }

    #[test]
    fn test_all_preconfigured_pass_with_full_posture() {
        let posture = sample_posture();
        let ctx = build_cel_context(&posture);
        for policy in PRECONFIGURED_POLICIES {
            assert!(
                evaluate_cel(policy.cel_expression, &ctx),
                "Policy '{}' should pass with full posture",
                policy.slug
            );
        }
    }

    #[test]
    fn test_test_cel_expression_pass() {
        let posture = sample_posture();
        let result =
            test_cel_expression("posture.disk_encryption_enabled == true", &posture).unwrap();
        assert!(result);
    }

    #[test]
    fn test_test_cel_expression_fail() {
        let posture = minimal_posture();
        let result =
            test_cel_expression("posture.disk_encryption_enabled == true", &posture).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_test_cel_expression_invalid() {
        let posture = minimal_posture();
        // Empty expression rejected
        assert!(test_cel_expression("", &posture).is_err());
        // Unterminated string (parser panic caught)
        assert!(test_cel_expression("posture.os == \"unterminated", &posture).is_err());
    }

    #[test]
    fn test_remediation_macos() {
        let r = remediation_for_slug("disk_encryption", Some("macos"));
        assert!(r.contains("FileVault"));
    }

    #[test]
    fn test_remediation_linux() {
        let r = remediation_for_slug("firewall", Some("linux"));
        assert!(r.contains("ufw"));
    }

    #[test]
    fn test_remediation_windows() {
        let r = remediation_for_slug("screen_lock", Some("windows"));
        assert!(r.contains("Sign-in options"));
    }

    #[test]
    fn test_remediation_unknown_slug() {
        let r = remediation_for_slug("custom_thing", Some("macos"));
        assert!(r.contains("Contact your organization"));
    }

    #[test]
    fn test_get_preconfigured_policy() {
        assert!(get_preconfigured_policy("disk_encryption").is_some());
        assert!(get_preconfigured_policy("firewall").is_some());
        assert!(get_preconfigured_policy("nonexistent").is_none());
    }

    #[test]
    fn test_is_valid_preconfigured_slug() {
        assert!(is_valid_preconfigured_slug("disk_encryption"));
        assert!(is_valid_preconfigured_slug("os_currency"));
        assert!(!is_valid_preconfigured_slug("custom"));
    }

    #[test]
    fn test_extract_device_posture_from_ad() {
        let json = r#"[{"type":"device_posture","posture_version":1,"os":"macos","disk_encryption_enabled":true}]"#;
        let posture = extract_device_posture(Some(json)).unwrap();
        assert_eq!(posture.os.as_deref(), Some("macos"));
        assert_eq!(posture.disk_encryption_enabled, Some(true));
    }

    #[test]
    fn test_extract_device_posture_missing() {
        let result = extract_device_posture(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_device_posture_no_posture_entry() {
        let json = r#"[{"type":"other_thing"}]"#;
        let result = extract_device_posture(Some(json));
        assert!(result.is_err());
    }

    #[test]
    fn test_posture_schema_has_expected_fields() {
        let schema = posture_schema();
        assert_eq!(schema["os"], "string");
        assert_eq!(schema["disk_encryption_enabled"], "bool");
        assert_eq!(schema["edr"], "list<string>");
        assert_eq!(schema["uptime_secs"], "uint");
    }
}
