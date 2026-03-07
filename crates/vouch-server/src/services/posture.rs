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
use cel::{Context, ExecutionError, FunctionContext, Program, Value};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use vouch_common::posture::DevicePosture;

/// Maximum number of active policies (preconfigured + custom combined).
/// There are 6 preconfigured policies, so 8 allows all 6 + 2 custom.
pub const MAX_ACTIVE_POLICIES: usize = 8;

// ============================================================
// Preconfigured Policies (code-defined)
// ============================================================

/// Identifies a preconfigured posture policy.
///
/// Using an enum makes invalid slugs unrepresentable at compile time.
/// Adding a new preconfigured policy requires adding a variant here,
/// which produces compile errors everywhere that needs updating
/// (remediation hints, template icons, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PreconfiguredSlug {
    DiskEncryption,
    Firewall,
    ScreenLock,
    EndpointProtection,
    PlatformIntegrity,
    OsRecency,
}

impl PreconfiguredSlug {
    /// The slug string stored in the DB and used in API responses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DiskEncryption => "disk_encryption",
            Self::Firewall => "firewall",
            Self::ScreenLock => "screen_lock",
            Self::EndpointProtection => "endpoint_protection",
            Self::PlatformIntegrity => "platform_integrity",
            Self::OsRecency => "os_recency",
        }
    }

    /// Parse a slug string into a `PreconfiguredSlug`.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "disk_encryption" => Some(Self::DiskEncryption),
            "firewall" => Some(Self::Firewall),
            "screen_lock" => Some(Self::ScreenLock),
            "endpoint_protection" => Some(Self::EndpointProtection),
            "platform_integrity" => Some(Self::PlatformIntegrity),
            "os_recency" => Some(Self::OsRecency),
            _ => None,
        }
    }
}

impl std::fmt::Display for PreconfiguredSlug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A preconfigured posture policy defined in code.
pub struct PreconfiguredPolicy {
    pub slug: PreconfiguredSlug,
    pub name: &'static str,
    pub description: &'static str,
    pub cel_expression: &'static str,
}

/// Compiled CEL programs for preconfigured policies.
/// Compiled once on first access (avoids recompiling on every evaluation).
static COMPILED_PRECONFIGURED: LazyLock<HashMap<PreconfiguredSlug, Program>> =
    LazyLock::new(|| {
        let mut map = HashMap::new();
        for policy in PRECONFIGURED_POLICIES {
            match Program::compile(policy.cel_expression) {
                Ok(program) => {
                    map.insert(policy.slug, program);
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to compile preconfigured CEL policy '{}': {e}",
                        policy.slug
                    );
                }
            }
        }
        map
    });

/// All preconfigured policies. Updated by deploying new code.
pub const PRECONFIGURED_POLICIES: &[PreconfiguredPolicy] = &[
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::DiskEncryption,
        name: "Disk Encryption",
        description: "Require full-disk encryption (FileVault, BitLocker, LUKS)",
        cel_expression: "posture.disk_encryption_enabled == true",
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::Firewall,
        name: "Firewall",
        description: "Require an active firewall",
        cel_expression: "posture.firewall_enabled == true",
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::ScreenLock,
        name: "Screen Lock",
        description: "Require screen lock on idle",
        cel_expression: "posture.screen_lock_enabled == true",
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::EndpointProtection,
        name: "Endpoint Protection",
        description: "Require at least one EDR agent installed",
        cel_expression: "size(posture.edr) > 0",
    },
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::PlatformIntegrity,
        name: "Platform Integrity",
        description: "Require Secure Boot to be enabled",
        cel_expression: "posture.secure_boot_enabled == true",
    },
    // OS version thresholds — review with each major OS release.
    // Last updated: 2026-03-06
    //   macOS: 25.0.0 = Sequoia (N-1 from Tahoe 26)
    //   Windows: 10.0.26100 = 24H2
    // Linux is excluded — distributions manage versions independently.
    // Admins can create custom policies for specific distro versions
    // (e.g., `posture.os_distribution == "ubuntu" && semver(posture.os_version) >= semver("22.04.0")`).
    PreconfiguredPolicy {
        slug: PreconfiguredSlug::OsRecency,
        name: "OS Recency",
        description: "Require a supported OS version (N-1)",
        cel_expression: concat!(
            "(posture.os == \"macos\"",
            " && semver(posture.os_version) >= semver(\"25.0.0\"))",
            " || (posture.os == \"windows\"",
            " && semver(posture.os_version) >= semver(\"10.0.26100\"))",
        ),
    },
];

/// Check if a slug string is a valid preconfigured policy.
#[must_use]
pub fn is_valid_preconfigured_slug(slug: &str) -> bool {
    PreconfiguredSlug::from_str(slug).is_some()
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
        tracing::debug!("CEL validation rejected: empty expression");
        return Err(ServiceError::api(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_cel_expression",
            "CEL expression must not be empty",
        ));
    }
    tracing::debug!(expression_len = trimmed.len(), "Validating CEL expression");
    // The cel 0.12.0 ANTLR parser contains `panic!` and `expect()` in
    // its parse tree visitor. With `panic = "abort"` (release profile),
    // `catch_unwind` is a no-op — the primary defense is auth-before-
    // compilation so only org admins can trigger parsing, plus the 1024-
    // char input limit. `catch_unwind` still protects debug/test builds
    // where `panic = "unwind"` is used.
    let compile_result = std::panic::catch_unwind(|| Program::compile(trimmed));
    match compile_result {
        Ok(Ok(_)) => {
            tracing::debug!("CEL expression validated successfully");
            Ok(())
        }
        Ok(Err(e)) => {
            tracing::warn!("CEL validation failed: {e}");
            Err(ServiceError::api(
                axum::http::StatusCode::BAD_REQUEST,
                "invalid_cel_expression",
                format!("Invalid CEL expression: {e}"),
            ))
        }
        Err(_) => {
            tracing::error!("CEL parser panicked during validation");
            Err(ServiceError::api(
                axum::http::StatusCode::BAD_REQUEST,
                "invalid_cel_expression",
                "Invalid CEL expression: failed to parse",
            ))
        }
    }
}

// ============================================================
// CEL Context Building
// ============================================================

/// CEL function: `semver("15.3.1")` → integer for numeric comparison.
///
/// Parses a version string into `major * 1_000_000 + minor * 1_000 + patch`.
/// Supports 1-3 components: "15" → 15_000_000, "15.3" → 15_003_000,
/// "15.3.1" → 15_003_001. Use for correct version comparisons:
/// `semver(posture.os_version) >= semver("14.0.0")`
fn cel_semver(ftx: &FunctionContext, value: Arc<String>) -> Result<Value, ExecutionError> {
    let mut parts = value.splitn(4, '.');
    let parse = |s: &str, ftx: &FunctionContext| -> Result<i64, ExecutionError> {
        s.parse::<i64>()
            .map_err(|_| ftx.error(format!("invalid semver component: '{s}'")))
    };
    let major = parts
        .next()
        .ok_or_else(|| ftx.error("empty version string"))?;
    let major = parse(major, ftx)?;
    let minor = parts
        .next()
        .map(|s| parse(s, ftx))
        .transpose()?
        .unwrap_or(0);
    let patch = parts
        .next()
        .map(|s| parse(s, ftx))
        .transpose()?
        .unwrap_or(0);
    if parts.next().is_some() {
        return Err(ftx.error("expected 1-3 version components"));
    }
    Ok(Value::Int(major * 1_000_000 + minor * 1_000 + patch))
}

/// Convert a `serde_json::Value` to a CEL `Value`.
///
/// Applies safe defaults so CEL expressions can always access fields:
/// - JSON `null` → `false` (bool), `""` (string), `0` (number)
/// - JSON arrays → CEL lists
/// - JSON objects → CEL maps (recursed)
fn json_to_cel(json: &serde_json::Value) -> Value {
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Value::UInt(u)
            } else if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else {
                Value::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => Value::String(s.clone().into()),
        serde_json::Value::Array(arr) => {
            let items: Vec<Value> = arr.iter().map(json_to_cel).collect();
            Value::List(items.into())
        }
        serde_json::Value::Object(obj) => {
            let map: HashMap<String, Value> = obj
                .iter()
                .map(|(k, v)| (k.clone(), json_to_cel(v)))
                .collect();
            Value::Map(map.into())
        }
    }
}

/// Fields that `skip_serializing_if` omits when `None`/empty.
/// We inject safe defaults so CEL expressions can always reference them.
static FIELD_DEFAULTS: LazyLock<HashMap<&'static str, Value>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    // Option<bool> → false
    for key in [
        "disk_encryption_enabled",
        "screen_lock_enabled",
        "firewall_enabled",
        "secure_boot_enabled",
        "sip_enabled",
        "tpm_present",
        "auto_update_enabled",
        "access_control_enforcing",
        "elevated",
        "tty",
    ] {
        m.insert(key, Value::Bool(false));
    }
    // Option<String> → ""
    for key in [
        "os",
        "os_version",
        "os_distribution",
        "os_build",
        "arch",
        "disk_encryption_technology",
        "firewall_technology",
        "tpm_version",
        "auto_update_technology",
        "access_control_technology",
        "parent_process",
        "cli_version",
        "collected_at",
    ] {
        m.insert(key, Value::String(String::new().into()));
    }
    // Option<u64> → 0
    for key in ["screen_lock_idle_timeout_secs", "uptime_secs"] {
        m.insert(key, Value::UInt(0));
    }
    // Vec → empty list
    for key in ["edr", "mdm"] {
        m.insert(key, Value::List(Vec::new().into()));
    }
    m
});

/// Convert a `DevicePosture` into a CEL context with a `posture` map.
///
/// Serializes the struct to JSON, then converts to CEL values. Fields
/// omitted by `skip_serializing_if` get safe defaults injected so CEL
/// expressions can always reference any field without runtime errors.
fn build_cel_context(posture: &DevicePosture) -> Context<'_> {
    let mut ctx = Context::default();

    // Serialize to JSON, then convert to a CEL map
    let json = serde_json::to_value(posture).unwrap_or_default();

    let mut map: HashMap<String, Value> = HashMap::new();

    // Start with defaults for all fields
    for (key, default) in &*FIELD_DEFAULTS {
        map.insert((*key).to_string(), default.clone());
    }

    // Overlay with actual values from serialization
    if let serde_json::Value::Object(obj) = &json {
        for (key, value) in obj {
            // Skip the "type" field — it's the RFC 9396 discriminator
            if key == "type" || key == "posture_version" {
                continue;
            }
            map.insert(key.clone(), json_to_cel(value));
        }
    }

    if let Err(e) = ctx.add_variable("posture", Value::Map(map.into())) {
        tracing::error!("Failed to add posture variable to CEL context: {e}");
    }

    ctx.add_function("semver", cel_semver);

    ctx
}

// ============================================================
// CEL Evaluation
// ============================================================

/// Execute a pre-compiled CEL program against a context.
///
/// Returns `true` if the policy passes, `false` if it fails.
/// Runtime evaluation errors are treated as failures (fail-closed).
fn execute_program(program: &Program, ctx: &Context<'_>) -> bool {
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

/// Compile and evaluate a CEL expression against a posture context.
///
/// Used for custom policies that are compiled on demand.
/// Preconfigured policies should use `execute_program` with the cached
/// `COMPILED_PRECONFIGURED` programs instead.
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

    execute_program(&program, ctx)
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

/// Get OS-specific remediation guidance for a preconfigured policy.
#[must_use]
pub fn remediation_for_slug(slug: PreconfiguredSlug, os: Option<&str>) -> String {
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
    let os = posture.os.as_ref().map(|o| o.as_str());

    // Evaluate preconfigured policies (using cached compiled programs)
    tracing::debug!(
        preconfigured_count = active_slugs.len(),
        custom_count = active_custom.len(),
        "Evaluating posture policies"
    );
    let compiled = &*COMPILED_PRECONFIGURED;
    for slug_str in &active_slugs {
        if let Some(slug) = PreconfiguredSlug::from_str(slug_str)
            && let Some(policy) = PRECONFIGURED_POLICIES.iter().find(|p| p.slug == slug)
        {
            let passed = compiled
                .get(&slug)
                .is_some_and(|program| execute_program(program, &ctx));
            tracing::debug!(
                policy = policy.name,
                slug = slug.as_str(),
                passed,
                "Preconfigured policy evaluated"
            );
            if !passed {
                let remediation = remediation_for_slug(slug, os);
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
    }

    // Evaluate custom policies
    for policy in &active_custom {
        let passed = evaluate_cel(&policy.cel_expression, &ctx);
        tracing::debug!(
            policy_name = policy.name,
            policy_id = policy.id,
            passed,
            "Custom policy evaluated"
        );
        if !passed {
            return Err(ServiceError::oauth(
                OAuthErrorCode::AccessDenied,
                format!(
                    "Device posture policy '{}' not satisfied. \
                     Check your device settings to meet your \
                     organization's compliance requirements",
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
            let mut posture: DevicePosture =
                serde_json::from_value(entry.clone()).map_err(|e| {
                    tracing::warn!("Failed to deserialize device posture: {e}");
                    ServiceError::oauth(
                        OAuthErrorCode::AccessDenied,
                        format!("Invalid device posture data: {e}"),
                    )
                })?;
            posture.normalize();
            tracing::debug!(
                os = posture.os.as_ref().map(|o| o.as_str()),
                "Extracted device posture from authorization_details"
            );
            return Ok(posture);
        }
    }

    Err(ServiceError::oauth(
        OAuthErrorCode::AccessDenied,
        "Device posture data is required by organization policy",
    ))
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
    use vouch_common::posture::{EdrAgent, MdmAgent, OperatingSystem, PostureTypeTag};

    fn sample_posture() -> DevicePosture {
        DevicePosture {
            detail_type: PostureTypeTag,
            posture_version: 1,
            os: Some(OperatingSystem::MacOs),
            os_version: Some("26.3.1".to_string()),
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
    fn test_evaluate_os_recency_macos_pass() {
        let posture = sample_posture();
        let ctx = build_cel_context(&posture);
        let expr = PRECONFIGURED_POLICIES
            .iter()
            .find(|p| p.slug == PreconfiguredSlug::OsRecency)
            .unwrap()
            .cel_expression;
        assert!(evaluate_cel(expr, &ctx));
    }

    #[test]
    fn test_evaluate_os_recency_old_macos_fail() {
        let mut posture = sample_posture();
        posture.os_version = Some("24.4.0".to_string());
        let ctx = build_cel_context(&posture);
        let expr = PRECONFIGURED_POLICIES
            .iter()
            .find(|p| p.slug == PreconfiguredSlug::OsRecency)
            .unwrap()
            .cel_expression;
        assert!(!evaluate_cel(expr, &ctx));
    }

    #[test]
    fn test_evaluate_os_recency_linux_does_not_pass() {
        let mut posture = minimal_posture();
        posture.os = Some(OperatingSystem::Linux);
        let ctx = build_cel_context(&posture);
        let expr = PRECONFIGURED_POLICIES
            .iter()
            .find(|p| p.slug == PreconfiguredSlug::OsRecency)
            .unwrap()
            .cel_expression;
        // Linux is not covered by the preconfigured os_recency policy;
        // admins should create per-distro custom policies instead.
        assert!(!evaluate_cel(expr, &ctx));
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
            PreconfiguredSlug::from_str("disk_encryption"),
            Some(PreconfiguredSlug::DiskEncryption)
        );
        assert_eq!(
            PreconfiguredSlug::from_str("os_recency"),
            Some(PreconfiguredSlug::OsRecency)
        );
        assert_eq!(PreconfiguredSlug::from_str("custom"), None);
        assert_eq!(
            PreconfiguredSlug::DiskEncryption.as_str(),
            "disk_encryption"
        );
    }

    #[test]
    fn test_semver_comparison() {
        let posture = sample_posture();
        let ctx = build_cel_context(&posture);
        // 26.3.1 >= 25.0.0
        assert!(evaluate_cel(
            "semver(posture.os_version) >= semver(\"25.0.0\")",
            &ctx,
        ));
        // 26.3.1 < 27.0.0
        assert!(evaluate_cel(
            "semver(posture.os_version) < semver(\"27.0.0\")",
            &ctx,
        ));
        // 9.0.0 should NOT be >= 14.0.0 (unlike lexicographic)
        let mut old = minimal_posture();
        old.os_version = Some("9.0.0".to_string());
        let old_ctx = build_cel_context(&old);
        assert!(!evaluate_cel(
            "semver(posture.os_version) >= semver(\"14.0.0\")",
            &old_ctx,
        ));
    }

    #[test]
    fn test_semver_compared_to_int() {
        let posture = sample_posture();
        let ctx = build_cel_context(&posture);
        // semver("26.3.1") = 26_003_001, which is >= 25
        assert!(evaluate_cel("semver(posture.os_version) >= 25", &ctx,));
    }

    #[test]
    fn test_semver_two_components() {
        let mut posture = minimal_posture();
        posture.os_version = Some("10.0".to_string());
        let ctx = build_cel_context(&posture);
        assert!(evaluate_cel(
            "semver(posture.os_version) >= semver(\"10\")",
            &ctx,
        ));
        assert!(!evaluate_cel(
            "semver(posture.os_version) >= semver(\"11\")",
            &ctx,
        ));
    }

    #[test]
    fn test_is_valid_preconfigured_slug() {
        assert!(is_valid_preconfigured_slug("disk_encryption"));
        assert!(is_valid_preconfigured_slug("os_recency"));
        assert!(!is_valid_preconfigured_slug("custom"));
    }

    #[test]
    fn test_extract_device_posture_from_ad() {
        let json = r#"[{"type":"device_posture","posture_version":1,"os":"macos","disk_encryption_enabled":true}]"#;
        let posture = extract_device_posture(Some(json)).unwrap();
        assert_eq!(posture.os, Some(OperatingSystem::MacOs));
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
    fn test_cel_context_field_parity() {
        // Verify every DevicePosture field is accessible in CEL.
        // A full posture ensures all fields serialize; we then check
        // each one evaluates without error.
        let posture = sample_posture();
        let ctx = build_cel_context(&posture);

        let fields = [
            ("os", "posture.os != \"\""),
            ("os_version", "posture.os_version != \"\""),
            (
                "disk_encryption_enabled",
                "posture.disk_encryption_enabled == true",
            ),
            (
                "disk_encryption_technology",
                "posture.disk_encryption_technology != \"\"",
            ),
            ("screen_lock_enabled", "posture.screen_lock_enabled == true"),
            (
                "screen_lock_idle_timeout_secs",
                "posture.screen_lock_idle_timeout_secs > uint(0)",
            ),
            ("firewall_enabled", "posture.firewall_enabled == true"),
            ("firewall_technology", "posture.firewall_technology != \"\""),
            ("secure_boot_enabled", "posture.secure_boot_enabled == true"),
            ("sip_enabled", "posture.sip_enabled == true"),
            ("edr", "size(posture.edr) > 0"),
            ("mdm", "size(posture.mdm) > 0"),
            ("elevated", "posture.elevated == false"),
            ("tty", "posture.tty == true"),
        ];

        for (field, expr) in fields {
            assert!(
                evaluate_cel(expr, &ctx),
                "Field '{field}' not accessible in CEL context (expr: {expr})"
            );
        }
    }
}
