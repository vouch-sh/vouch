// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device posture types for RFC 9396 authorization_details.
//!
//! The CLI collects device posture signals at login time and sends them as
//! a structured `authorization_details` entry with `type: "device_posture"`.
//! All fields are optional — the CLI reports what it can detect, the server
//! policy decides what's required.
//!
//! Field names are intentionally generic and device-agnostic so that server
//! policies can be written without platform-specific logic:
//! - `disk_encryption_enabled` — true on FileVault, BitLocker, LUKS alike
//! - `firewall_enabled` — true for macOS App Firewall, ufw, Windows Firewall
//! - `access_control_enforcing` — true for SELinux enforcing, AppArmor, Gatekeeper

use serde::{Deserialize, Serialize};

/// RFC 9396 authorization_details type for device posture claims.
pub const POSTURE_TYPE: &str = "device_posture";

/// Device posture collected by the CLI at authentication time.
///
/// Serialized as a JSON object within an RFC 9396 `authorization_details`
/// array entry. Every field is `Option<T>` — detection is best-effort and
/// platform-dependent. All field names are flat and device-agnostic.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DevicePosture {
    /// RFC 9396: the authorization detail type.
    #[serde(rename = "type")]
    pub detail_type: String,

    // ── OS info ──────────────────────────────────────────────────────

    /// Operating system identifier (e.g., "macos", "linux", "windows").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,

    /// OS version string (e.g., "15.3.1", "24.04", "10.0.26100").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,

    /// OS distribution or edition (e.g., "Ubuntu", "Fedora", "macOS").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_distribution: Option<String>,

    /// OS build identifier (e.g., macOS build "24D5034f", Windows build "26100").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_build: Option<String>,

    /// CPU architecture (e.g., "aarch64", "x86_64").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,

    /// Client hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    // ── Disk encryption ─────────────────────────────────────────────

    /// Whether disk encryption is enabled on the system volume.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_encryption_enabled: Option<bool>,

    /// Encryption technology (e.g., "FileVault", "LUKS", "BitLocker").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_encryption_technology: Option<String>,

    // ── Screen lock ─────────────────────────────────────────────────

    /// Whether screen lock on idle is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screen_lock_enabled: Option<bool>,

    /// Idle timeout in seconds before lock activates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screen_lock_idle_timeout_secs: Option<u64>,

    // ── Firewall ────────────────────────────────────────────────────

    /// Whether the firewall is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall_enabled: Option<bool>,

    /// Firewall technology (e.g., "Application Firewall", "ufw", "Windows Firewall").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall_technology: Option<String>,

    // ── Secure boot / TPM ───────────────────────────────────────────

    /// Whether secure boot is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_boot_enabled: Option<bool>,

    /// Whether a TPM (or Secure Enclave) is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tpm_present: Option<bool>,

    /// TPM version (e.g., "2.0").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tpm_version: Option<String>,

    // ── OS auto-update ──────────────────────────────────────────────

    /// Whether automatic OS updates are enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_update_enabled: Option<bool>,

    /// Auto-update technology (e.g., "unattended-upgrades", "SoftwareUpdate", "Windows Update").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_update_technology: Option<String>,

    // ── System uptime ───────────────────────────────────────────────

    /// Seconds since last boot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_secs: Option<u64>,

    // ── Mandatory access control ────────────────────────────────────

    /// Whether mandatory access control is enforcing (SELinux, AppArmor, Gatekeeper).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_control_enforcing: Option<bool>,

    /// Access control technology (e.g., "SELinux", "AppArmor", "Gatekeeper").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_control_technology: Option<String>,

    // ── SSH session ─────────────────────────────────────────────────

    /// Whether the CLI is running inside an SSH session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_session_detected: Option<bool>,

    /// Remote client IP address (from SSH_CONNECTION).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_client_ip: Option<String>,

    // ── Execution context ───────────────────────────────────────────

    /// Whether the CLI is running with elevated privileges (root/admin).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elevated: Option<bool>,

    /// Whether the CLI is running from a TTY (interactive terminal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tty: Option<bool>,

    /// Parent process name (e.g., "bash", "zsh", "node").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_process: Option<String>,

    // ── Meta ────────────────────────────────────────────────────────

    /// CLI version that collected this posture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cli_version: Option<String>,

    /// ISO 8601 timestamp when the posture was collected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collected_at: Option<String>,
}

impl DevicePosture {
    /// Create a new `DevicePosture` with the type field pre-filled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            detail_type: POSTURE_TYPE.to_string(),
            ..Default::default()
        }
    }

    /// Wrap this posture in an RFC 9396 `authorization_details` JSON array.
    ///
    /// Returns the JSON string `[{...posture...}]` suitable for the
    /// `authorization_details` form parameter.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_authorization_details_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&[self])
    }

    /// Lowercase all string values for case-insensitive policy evaluation.
    ///
    /// Called after collection to normalize platform-specific casing
    /// (e.g., "FileVault" → "filevault", "Ubuntu" → "ubuntu").
    pub fn normalize(&mut self) {
        fn lower(opt: &mut Option<String>) {
            if let Some(ref mut s) = *opt {
                *s = s.to_lowercase();
            }
        }

        lower(&mut self.os);
        lower(&mut self.os_version);
        lower(&mut self.os_distribution);
        lower(&mut self.os_build);
        lower(&mut self.arch);
        lower(&mut self.hostname);
        lower(&mut self.disk_encryption_technology);
        lower(&mut self.firewall_technology);
        lower(&mut self.tpm_version);
        lower(&mut self.auto_update_technology);
        lower(&mut self.access_control_technology);
        lower(&mut self.ssh_client_ip);
        lower(&mut self.parent_process);
        // cli_version and collected_at are not lowercased — they're metadata
    }
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

    #[test]
    fn test_posture_serializes_as_rar_array() {
        let posture = DevicePosture {
            detail_type: POSTURE_TYPE.to_string(),
            os: Some("macos".to_string()),
            os_version: Some("15.3.1".to_string()),
            ..Default::default()
        };

        let json = posture.to_authorization_details_json().unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["type"], "device_posture");
        assert_eq!(parsed[0]["os"], "macos");
        assert_eq!(parsed[0]["os_version"], "15.3.1");
        // None fields should be absent
        assert!(parsed[0].get("arch").is_none());
    }

    #[test]
    fn test_posture_default_has_type() {
        let posture = DevicePosture::new();
        assert_eq!(posture.detail_type, "device_posture");
    }

    #[test]
    fn test_posture_round_trips() {
        let posture = DevicePosture {
            detail_type: POSTURE_TYPE.to_string(),
            os: Some("linux".to_string()),
            disk_encryption_enabled: Some(true),
            disk_encryption_technology: Some("LUKS".to_string()),
            firewall_enabled: Some(true),
            firewall_technology: Some("ufw".to_string()),
            ssh_session_detected: Some(true),
            ssh_client_ip: Some("192.168.1.100".to_string()),
            elevated: Some(false),
            tty: Some(true),
            parent_process: Some("bash".to_string()),
            secure_boot_enabled: Some(true),
            tpm_present: Some(true),
            tpm_version: Some("2.0".to_string()),
            auto_update_enabled: Some(true),
            auto_update_technology: Some("unattended-upgrades".to_string()),
            uptime_secs: Some(86400),
            access_control_enforcing: Some(true),
            access_control_technology: Some("SELinux".to_string()),
            ..Default::default()
        };

        let json = serde_json::to_string(&posture).unwrap();
        let deserialized: DevicePosture = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.os.as_deref(), Some("linux"));
        assert!(deserialized.disk_encryption_enabled.unwrap());
        assert!(deserialized.auto_update_enabled.unwrap());
        assert_eq!(deserialized.uptime_secs, Some(86400));
        assert!(deserialized.access_control_enforcing.unwrap());
    }

    #[test]
    fn test_flat_fields_serialize_as_top_level_keys() {
        let posture = DevicePosture {
            detail_type: POSTURE_TYPE.to_string(),
            disk_encryption_enabled: Some(true),
            disk_encryption_technology: Some("FileVault".to_string()),
            firewall_enabled: Some(false),
            ..Default::default()
        };

        let json = posture.to_authorization_details_json().unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        // All fields are top-level, no nesting
        assert_eq!(parsed[0]["disk_encryption_enabled"], true);
        assert_eq!(parsed[0]["disk_encryption_technology"], "FileVault");
        assert_eq!(parsed[0]["firewall_enabled"], false);
        // Absent optional fields are not serialized
        assert!(parsed[0].get("screen_lock_enabled").is_none());
    }

    #[test]
    fn test_normalize_lowercases_all_strings() {
        let mut posture = DevicePosture {
            detail_type: POSTURE_TYPE.to_string(),
            os: Some("Linux".to_string()),
            os_distribution: Some("Ubuntu".to_string()),
            hostname: Some("MyHost".to_string()),
            disk_encryption_technology: Some("LUKS".to_string()),
            firewall_technology: Some("UFW".to_string()),
            access_control_technology: Some("SELinux".to_string()),
            auto_update_technology: Some("SoftwareUpdate".to_string()),
            parent_process: Some("Bash".to_string()),
            cli_version: Some("1.0.0".to_string()),
            ..Default::default()
        };

        posture.normalize();

        assert_eq!(posture.os.as_deref(), Some("linux"));
        assert_eq!(posture.os_distribution.as_deref(), Some("ubuntu"));
        assert_eq!(posture.hostname.as_deref(), Some("myhost"));
        assert_eq!(posture.disk_encryption_technology.as_deref(), Some("luks"));
        assert_eq!(posture.firewall_technology.as_deref(), Some("ufw"));
        assert_eq!(posture.access_control_technology.as_deref(), Some("selinux"));
        assert_eq!(posture.auto_update_technology.as_deref(), Some("softwareupdate"));
        assert_eq!(posture.parent_process.as_deref(), Some("bash"));
        // cli_version is NOT lowercased (metadata)
        assert_eq!(posture.cli_version.as_deref(), Some("1.0.0"));
    }
}
