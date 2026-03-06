// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Linux-specific device posture detection.

use std::process::Command;

use vouch_common::posture::DevicePosture;

/// Run all Linux-specific posture detection and populate the struct.
pub fn detect(posture: &mut DevicePosture) {
    detect_os_version(posture);
    detect_disk_encryption(posture);
    detect_screen_lock(posture);
    detect_firewall(posture);
    detect_secure_boot(posture);
    detect_os_auto_update(posture);
    detect_uptime(posture);
    detect_access_control(posture);
    detect_edr(posture);
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
fn detect_disk_encryption(posture: &mut DevicePosture) {
    // Method 1: Check for CRYPT- in dm UUIDs via sysfs
    if let Ok(entries) = std::fs::read_dir("/sys/block") {
        for entry in entries.flatten() {
            let uuid_path = entry.path().join("dm").join("uuid");
            if let Ok(uuid) = std::fs::read_to_string(&uuid_path)
                && uuid.trim().starts_with("CRYPT-")
            {
                posture.disk_encryption_enabled = Some(true);
                posture.disk_encryption_technology = Some("LUKS".to_string());
                return;
            }
        }
    }

    // Method 2: Use lsblk to check for crypt type
    if let Some(output) = run_command("lsblk", &["-o", "TYPE", "--noheadings"])
        && output.lines().any(|line| line.trim() == "crypt")
    {
        posture.disk_encryption_enabled = Some(true);
        posture.disk_encryption_technology = Some("LUKS".to_string());
        return;
    }

    // Neither method detected encryption
    posture.disk_encryption_enabled = Some(false);
}

/// Detect GNOME screen lock settings via `gsettings`.
///
/// Only works for GNOME desktop. Skips headless/TTY sessions.
fn detect_screen_lock(posture: &mut DevicePosture) {
    // Check if we're in a graphical session
    let session_type = std::env::var("XDG_SESSION_TYPE").ok();
    if session_type.as_deref() == Some("tty") {
        return; // Headless/TTY session — screen lock not applicable
    }

    // Try GNOME settings
    let lock_output = run_command(
        "gsettings",
        &["get", "org.gnome.desktop.screensaver", "lock-enabled"],
    );

    if let Some(output) = lock_output {
        posture.screen_lock_enabled = Some(output.trim() == "true");

        let delay_output = run_command(
            "gsettings",
            &["get", "org.gnome.desktop.screensaver", "lock-delay"],
        );

        // gsettings returns "uint32 N" format
        posture.screen_lock_idle_timeout_secs = delay_output.as_deref().and_then(|s| {
            s.trim()
                .strip_prefix("uint32 ")
                .and_then(|n| n.parse::<u64>().ok())
        });
    }
}

/// Detect firewall status on Linux.
///
/// Checks ufw, firewalld, and nftables via systemd service status.
fn detect_firewall(posture: &mut DevicePosture) {
    // Check ufw via systemd
    if let Some(output) = run_command("systemctl", &["is-active", "ufw"])
        && output.trim() == "active"
    {
        posture.firewall_enabled = Some(true);
        posture.firewall_technology = Some("ufw".to_string());
        return;
    }

    // Check firewalld via systemd
    if let Some(output) = run_command("systemctl", &["is-active", "firewalld"])
        && output.trim() == "active"
    {
        posture.firewall_enabled = Some(true);
        posture.firewall_technology = Some("firewalld".to_string());
        return;
    }

    // Check nftables via systemd
    if let Some(output) = run_command("systemctl", &["is-active", "nftables"])
        && output.trim() == "active"
    {
        posture.firewall_enabled = Some(true);
        posture.firewall_technology = Some("nftables".to_string());
        return;
    }

    posture.firewall_enabled = Some(false);
}

/// Detect Secure Boot and TPM status from sysfs (no root required).
fn detect_secure_boot(posture: &mut DevicePosture) {
    // Secure Boot: check /sys/firmware/efi/efivars/SecureBoot-*
    posture.secure_boot_enabled = detect_secure_boot_status();

    // TPM: check /dev/tpm0 or /dev/tpmrm0
    let tpm_present = std::path::Path::new("/dev/tpm0").exists()
        || std::path::Path::new("/dev/tpmrm0").exists();
    posture.tpm_present = Some(tpm_present);

    if tpm_present {
        posture.tpm_version = std::fs::read_to_string("/sys/class/tpm/tpm0/tpm_version_major")
            .ok()
            .map(|v| {
                let major = v.trim();
                format!("{major}.0")
            });
    }
}

/// Check Secure Boot via EFI variables.
fn detect_secure_boot_status() -> Option<bool> {
    let efivars = std::fs::read_dir("/sys/firmware/efi/efivars").ok()?;
    for entry in efivars.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("SecureBoot-") {
            // Read the variable: first 4 bytes are attributes, 5th byte is the value
            if let Ok(data) = std::fs::read(entry.path()) {
                return data.get(4).map(|&b| b == 1);
            }
        }
    }
    None
}

/// Detect OS automatic update configuration.
///
/// Checks for `unattended-upgrades` (Debian/Ubuntu) and `dnf-automatic` (Fedora/RHEL).
fn detect_os_auto_update(posture: &mut DevicePosture) {
    // Debian/Ubuntu: unattended-upgrades
    if let Some(output) = run_command("systemctl", &["is-active", "unattended-upgrades"])
        && output.trim() == "active"
    {
        posture.auto_update_enabled = Some(true);
        posture.auto_update_technology = Some("unattended-upgrades".to_string());
        return;
    }

    // Fedora/RHEL: dnf-automatic
    if let Some(output) = run_command("systemctl", &["is-active", "dnf-automatic.timer"])
        && output.trim() == "active"
    {
        posture.auto_update_enabled = Some(true);
        posture.auto_update_technology = Some("dnf-automatic".to_string());
        return;
    }

    posture.auto_update_enabled = Some(false);
}

/// Detect system uptime from `/proc/uptime`.
///
/// The first field is the total seconds since boot (as a float).
fn detect_uptime(posture: &mut DevicePosture) {
    if let Some(secs) = read_proc_uptime() {
        posture.uptime_secs = Some(secs);
    }
}

fn read_proc_uptime() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/uptime").ok()?;
    let secs_str = content.split_whitespace().next()?;
    let secs_f64: f64 = secs_str.parse().ok()?;
    Some(secs_f64 as u64)
}

/// Detect mandatory access control policy (SELinux or AppArmor).
fn detect_access_control(posture: &mut DevicePosture) {
    // SELinux: check /sys/fs/selinux/enforce
    if let Ok(val) = std::fs::read_to_string("/sys/fs/selinux/enforce") {
        posture.access_control_enforcing = Some(val.trim() == "1");
        posture.access_control_technology = Some("SELinux".to_string());
        return;
    }

    // AppArmor: check /sys/module/apparmor/parameters/enabled
    if let Ok(val) = std::fs::read_to_string("/sys/module/apparmor/parameters/enabled") {
        posture.access_control_enforcing = Some(val.trim() == "Y");
        posture.access_control_technology = Some("AppArmor".to_string());
    }
}

/// Detect endpoint detection & response (EDR) agents on Linux.
///
/// Checks for known EDR agent processes by looking for their install paths
/// and systemd service status. No root required.
fn detect_edr(posture: &mut DevicePosture) {
    // CrowdStrike Falcon — check for install directory and service
    if std::path::Path::new("/opt/CrowdStrike").exists()
        || is_service_active("falcon-sensor")
    {
        posture.edr_detected = Some(true);
        posture.edr_technology = Some("CrowdStrike".to_string());
        return;
    }

    // SentinelOne — check for install directory and service
    if std::path::Path::new("/opt/sentinelone").exists()
        || is_service_active("sentineld")
    {
        posture.edr_detected = Some(true);
        posture.edr_technology = Some("SentinelOne".to_string());
        return;
    }

    // Carbon Black (VMware) — check for install directory and service
    if std::path::Path::new("/opt/carbonblack").exists()
        || std::path::Path::new("/var/opt/carbonblack").exists()
        || is_service_active("cbagentd")
    {
        posture.edr_detected = Some(true);
        posture.edr_technology = Some("Carbon Black".to_string());
        return;
    }

    // Microsoft Defender for Endpoint — check for install directory and service
    if std::path::Path::new("/opt/microsoft/mdatp").exists()
        || is_service_active("mdatp")
    {
        posture.edr_detected = Some(true);
        posture.edr_technology = Some("Microsoft Defender".to_string());
        return;
    }

    // Trellix (formerly McAfee) — check for install directory
    if std::path::Path::new("/opt/McAfee").exists()
        || std::path::Path::new("/opt/trellix").exists()
    {
        posture.edr_detected = Some(true);
        posture.edr_technology = Some("Trellix".to_string());
        return;
    }

    // 1Password Device Trust (Kolide) — check for agent binary
    if std::path::Path::new("/usr/local/kolide-k2/bin/launcher").exists()
        || is_service_active("launcher.kolide-k2")
    {
        posture.edr_detected = Some(true);
        posture.edr_technology = Some("1Password Device Trust".to_string());
        return;
    }

    posture.edr_detected = Some(false);
}

/// Check if a systemd service is active.
fn is_service_active(service: &str) -> bool {
    run_command("systemctl", &["is-active", service])
        .as_deref()
        .is_some_and(|s| s.trim() == "active")
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
