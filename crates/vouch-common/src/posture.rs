// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device posture types for RFC 9396 authorization_details.
//!
//! The CLI collects device posture signals at login time and sends them as
//! a structured `authorization_details` entry with `type: "device_posture"`.
//! All fields are optional — the CLI reports what it can detect, the server
//! policy decides what's required.

use serde::{Deserialize, Serialize};

/// RFC 9396 authorization_details type for device posture claims.
pub const POSTURE_TYPE: &str = "device_posture";

/// Device posture collected by the CLI at authentication time.
///
/// Serialized as a JSON object within an RFC 9396 `authorization_details`
/// array entry. Every field is `Option<T>` — detection is best-effort and
/// platform-dependent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DevicePosture {
    /// RFC 9396: the authorization detail type.
    #[serde(rename = "type")]
    pub detail_type: String,

    /// Operating system identifier (e.g., "macos", "linux", "windows").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,

    /// OS version string (e.g., "15.3.1", "24.04", "10.0.26100").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,

    /// OS distribution or edition (e.g., "Ubuntu", "Fedora", "Windows 11 Pro").
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

    /// Disk encryption status for the system volume.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_encryption: Option<DiskEncryption>,

    /// Screen lock configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screen_lock: Option<ScreenLock>,

    /// Firewall status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall: Option<FirewallStatus>,

    /// Whether the CLI is running inside an SSH session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_session: Option<SshSession>,

    /// Execution context of the CLI binary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_context: Option<ExecutionContext>,

    /// Secure boot / TPM status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_boot: Option<SecureBoot>,

    /// OS automatic update configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_auto_update: Option<OsAutoUpdate>,

    /// System uptime (time since last boot).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_uptime: Option<SystemUptime>,

    /// Mandatory access control policy (SELinux, AppArmor).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_policy: Option<MacPolicy>,

    /// Gatekeeper status (macOS only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gatekeeper: Option<Gatekeeper>,

    /// CLI version that collected this posture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cli_version: Option<String>,

    /// ISO 8601 timestamp when the posture was collected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collected_at: Option<String>,
}

/// Disk encryption status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskEncryption {
    /// Whether disk encryption is enabled.
    pub enabled: bool,
    /// Encryption technology (e.g., "FileVault", "LUKS", "BitLocker").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technology: Option<String>,
}

/// Screen lock configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenLock {
    /// Whether screen lock on idle is enabled.
    pub enabled: bool,
    /// Idle timeout in seconds before lock activates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_timeout_secs: Option<u64>,
}

/// Firewall status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallStatus {
    /// Whether the firewall is enabled.
    pub enabled: bool,
    /// Firewall technology (e.g., "Application Firewall", "ufw", "iptables").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technology: Option<String>,
}

/// SSH session detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshSession {
    /// Whether the CLI is running inside an SSH session.
    pub detected: bool,
    /// Remote client IP address (from SSH_CONNECTION).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
}

/// Execution context of the CLI binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    /// Whether the CLI is running with elevated privileges (root/admin).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elevated: Option<bool>,
    /// Whether the CLI is running from a TTY (interactive terminal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tty: Option<bool>,
    /// Parent process name (e.g., "bash", "zsh", "node").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_process: Option<String>,
}

/// Secure boot and TPM status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureBoot {
    /// Whether secure boot is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Whether a TPM (or Secure Enclave) is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tpm_present: Option<bool>,
    /// TPM version (e.g., "2.0").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tpm_version: Option<String>,
}

/// OS automatic update configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsAutoUpdate {
    /// Whether automatic updates are enabled.
    pub enabled: bool,
    /// Update technology (e.g., "unattended-upgrades", "SoftwareUpdate", "Windows Update").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technology: Option<String>,
}

/// System uptime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemUptime {
    /// Seconds since last boot.
    pub uptime_secs: u64,
}

/// Mandatory access control policy status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacPolicy {
    /// Whether the policy is in enforcing mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcing: Option<bool>,
    /// MAC technology (e.g., "SELinux", "AppArmor").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technology: Option<String>,
}

/// Gatekeeper status (macOS only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gatekeeper {
    /// Whether Gatekeeper is enabled.
    pub enabled: bool,
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
            disk_encryption: Some(DiskEncryption {
                enabled: true,
                technology: Some("LUKS".to_string()),
            }),
            firewall: Some(FirewallStatus {
                enabled: true,
                technology: Some("ufw".to_string()),
            }),
            ssh_session: Some(SshSession {
                detected: true,
                client_ip: Some("192.168.1.100".to_string()),
            }),
            execution_context: Some(ExecutionContext {
                elevated: Some(false),
                tty: Some(true),
                parent_process: Some("bash".to_string()),
            }),
            secure_boot: Some(SecureBoot {
                enabled: Some(true),
                tpm_present: Some(true),
                tpm_version: Some("2.0".to_string()),
            }),
            os_auto_update: Some(OsAutoUpdate {
                enabled: true,
                technology: Some("unattended-upgrades".to_string()),
            }),
            system_uptime: Some(SystemUptime { uptime_secs: 86400 }),
            mac_policy: Some(MacPolicy {
                enforcing: Some(true),
                technology: Some("SELinux".to_string()),
            }),
            gatekeeper: None,
            ..Default::default()
        };

        let json = serde_json::to_string(&posture).unwrap();
        let deserialized: DevicePosture = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.os.as_deref(), Some("linux"));
        assert!(deserialized.disk_encryption.as_ref().unwrap().enabled);
        assert!(deserialized.os_auto_update.as_ref().unwrap().enabled);
        assert_eq!(deserialized.system_uptime.as_ref().unwrap().uptime_secs, 86400);
        assert!(deserialized.mac_policy.as_ref().unwrap().enforcing.unwrap());
    }
}
