// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Linux-specific device posture detection.

use std::process::Command;

use vouch_common::posture::{
    DevicePosture, DiskEncryption, FirewallStatus, ScreenLock, SecureBoot,
};

/// Run all Linux-specific posture detection and populate the struct.
pub fn detect(posture: &mut DevicePosture) {
    detect_os_version(posture);
    posture.disk_encryption = detect_disk_encryption();
    posture.screen_lock = detect_screen_lock();
    posture.firewall = detect_firewall();
    posture.secure_boot = detect_secure_boot();
}

/// Detect Linux distribution and version from `/etc/os-release`.
fn detect_os_version(posture: &mut DevicePosture) {
    let content = match std::fs::read_to_string("/etc/os-release") {
        Ok(c) => c,
        Err(_) => return,
    };

    for line in content.lines() {
        if let Some(val) = line.strip_prefix("VERSION_ID=") {
            posture.os_version = Some(unquote(val));
        } else if let Some(val) = line.strip_prefix("NAME=") {
            posture.os_distribution = Some(unquote(val));
        } else if let Some(val) = line.strip_prefix("BUILD_ID=") {
            posture.os_build = Some(unquote(val));
        }
    }
}

/// Detect LUKS disk encryption without root.
///
/// Checks if the root filesystem is on a device-mapper `crypt` device
/// by inspecting `/sys/block/*/dm/uuid` for `CRYPT-` prefixed entries,
/// and `lsblk` for `crypt` type entries.
fn detect_disk_encryption() -> Option<DiskEncryption> {
    // Method 1: Check for CRYPT- in dm UUIDs via sysfs
    if let Ok(entries) = std::fs::read_dir("/sys/block") {
        for entry in entries.flatten() {
            let uuid_path = entry.path().join("dm").join("uuid");
            if let Ok(uuid) = std::fs::read_to_string(&uuid_path)
                && uuid.trim().starts_with("CRYPT-")
            {
                return Some(DiskEncryption {
                    enabled: true,
                    technology: Some("LUKS".to_string()),
                });
            }
        }
    }

    // Method 2: Use lsblk to check for crypt type
    if let Some(output) = run_command("lsblk", &["-o", "TYPE", "--noheadings"])
        && output.lines().any(|line| line.trim() == "crypt")
    {
        return Some(DiskEncryption {
            enabled: true,
            technology: Some("LUKS".to_string()),
        });
    }

    // If neither method detected encryption, report it as not detected
    // (could be unencrypted, or detection couldn't determine status)
    Some(DiskEncryption {
        enabled: false,
        technology: None,
    })
}

/// Detect GNOME screen lock settings via `gsettings`.
///
/// Only works for GNOME desktop. Returns `None` for other DEs or headless.
fn detect_screen_lock() -> Option<ScreenLock> {
    // Check if we're in a graphical session
    let session_type = std::env::var("XDG_SESSION_TYPE").ok();
    if session_type.as_deref() == Some("tty") {
        return None; // Headless/TTY session — screen lock not applicable
    }

    // Try GNOME settings
    let lock_output = run_command(
        "gsettings",
        &["get", "org.gnome.desktop.screensaver", "lock-enabled"],
    );

    if let Some(output) = lock_output {
        let enabled = output.trim() == "true";

        let delay_output = run_command(
            "gsettings",
            &["get", "org.gnome.desktop.screensaver", "lock-delay"],
        );

        // gsettings returns "uint32 N" format
        let idle_timeout_secs = delay_output.as_deref().and_then(|s| {
            s.trim()
                .strip_prefix("uint32 ")
                .and_then(|n| n.parse::<u64>().ok())
        });

        return Some(ScreenLock {
            enabled,
            idle_timeout_secs,
        });
    }

    None
}

/// Detect firewall status on Linux.
///
/// Checks ufw (via systemd service status) and iptables rules.
fn detect_firewall() -> Option<FirewallStatus> {
    // Check ufw via systemd
    if let Some(output) = run_command("systemctl", &["is-active", "ufw"])
        && output.trim() == "active"
    {
        return Some(FirewallStatus {
            enabled: true,
            technology: Some("ufw".to_string()),
        });
    }

    // Check firewalld via systemd
    if let Some(output) = run_command("systemctl", &["is-active", "firewalld"])
        && output.trim() == "active"
    {
        return Some(FirewallStatus {
            enabled: true,
            technology: Some("firewalld".to_string()),
        });
    }

    // Check nftables via systemd
    if let Some(output) = run_command("systemctl", &["is-active", "nftables"])
        && output.trim() == "active"
    {
        return Some(FirewallStatus {
            enabled: true,
            technology: Some("nftables".to_string()),
        });
    }

    Some(FirewallStatus {
        enabled: false,
        technology: None,
    })
}

/// Detect Secure Boot and TPM status from sysfs (no root required).
fn detect_secure_boot() -> Option<SecureBoot> {
    // Secure Boot: check /sys/firmware/efi/efivars/SecureBoot-*
    let secure_boot_enabled = detect_secure_boot_status();

    // TPM: check /dev/tpm0 or /dev/tpmrm0 and version
    let tpm_present = std::path::Path::new("/dev/tpm0").exists()
        || std::path::Path::new("/dev/tpmrm0").exists();

    let tpm_version = if tpm_present {
        std::fs::read_to_string("/sys/class/tpm/tpm0/tpm_version_major")
            .ok()
            .map(|v| {
                let major = v.trim();
                format!("{major}.0")
            })
    } else {
        None
    };

    Some(SecureBoot {
        enabled: secure_boot_enabled,
        tpm_present: Some(tpm_present),
        tpm_version,
    })
}

/// Check Secure Boot via EFI variables.
fn detect_secure_boot_status() -> Option<bool> {
    // Look for SecureBoot-* in efivars
    let efivars = std::fs::read_dir("/sys/firmware/efi/efivars").ok()?;
    for entry in efivars.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("SecureBoot-") {
            // Read the variable: first 4 bytes are attributes, 5th byte is the value
            if let Ok(data) = std::fs::read(entry.path()) {
                // The value byte (after 4-byte attribute header) is 1 if enabled
                return data.get(4).map(|&b| b == 1);
            }
        }
    }
    None
}

/// Run a command and capture stdout. Returns `None` on any failure.
fn run_command(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Remove surrounding quotes from a value (e.g., `"Ubuntu"` → `Ubuntu`).
fn unquote(s: &str) -> String {
    s.trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}
