// SPDX-License-Identifier: Apache-2.0 OR MIT
//! macOS-specific device posture detection.

use std::process::Command;

use vouch_common::posture::{
    DevicePosture, DiskEncryption, FirewallStatus, Gatekeeper, OsAutoUpdate, ScreenLock,
    SecureBoot, SystemUptime,
};

/// Run all macOS-specific posture detection and populate the struct.
pub fn detect(posture: &mut DevicePosture) {
    detect_os_version(posture);
    posture.disk_encryption = detect_filevault();
    posture.screen_lock = detect_screen_lock();
    posture.firewall = detect_firewall();
    posture.secure_boot = detect_secure_boot();
    posture.os_auto_update = detect_os_auto_update();
    posture.system_uptime = detect_uptime();
    posture.gatekeeper = detect_gatekeeper();
}

/// Detect macOS version using `sw_vers`.
fn detect_os_version(posture: &mut DevicePosture) {
    if let Some(output) = run_command("sw_vers", &["-productVersion"]) {
        let version = output.trim().to_string();
        if !version.is_empty() {
            posture.os_version = Some(version);
        }
    }
    if let Some(output) = run_command("sw_vers", &["-buildVersion"]) {
        let build = output.trim().to_string();
        if !build.is_empty() {
            posture.os_build = Some(build);
        }
    }
    posture.os_distribution = Some("macOS".to_string());
}

/// Detect FileVault status via `fdesetup status`.
///
/// Does not require root. Output is either:
/// - "FileVault is On."
/// - "FileVault is Off."
fn detect_filevault() -> Option<DiskEncryption> {
    let output = run_command("fdesetup", &["status"])?;
    let enabled = output.contains("FileVault is On");
    Some(DiskEncryption {
        enabled,
        technology: Some("FileVault".to_string()),
    })
}

/// Detect screen lock configuration via `defaults read`.
fn detect_screen_lock() -> Option<ScreenLock> {
    let ask_output = run_command(
        "defaults",
        &["read", "com.apple.screensaver", "askForPassword"],
    );

    let enabled = ask_output
        .as_deref()
        .map(|s| s.trim() == "1")
        .unwrap_or(false);

    let idle_output = run_command(
        "defaults",
        &["read", "com.apple.screensaver", "idleTime"],
    );

    let idle_timeout_secs = idle_output
        .as_deref()
        .and_then(|s| s.trim().parse::<u64>().ok());

    Some(ScreenLock {
        enabled,
        idle_timeout_secs,
    })
}

/// Detect macOS Application Firewall status.
///
/// Uses `socketfilterfw --getglobalstate`. No elevation required.
fn detect_firewall() -> Option<FirewallStatus> {
    let output = run_command(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
    )?;

    let enabled = output.contains("enabled");
    Some(FirewallStatus {
        enabled,
        technology: Some("Application Firewall".to_string()),
    })
}

/// Detect Secure Boot on macOS.
///
/// Apple Silicon Macs always have Secure Boot. Check SIP status via `csrutil`.
fn detect_secure_boot() -> Option<SecureBoot> {
    let sip_output = run_command("csrutil", &["status"]);
    let sip_enabled = sip_output
        .as_deref()
        .map(|s| s.contains("enabled"))
        .unwrap_or(false);

    // Apple Silicon always has Secure Enclave (equivalent to TPM)
    let is_arm = std::env::consts::ARCH == "aarch64";

    Some(SecureBoot {
        enabled: Some(sip_enabled),
        tpm_present: Some(is_arm), // Secure Enclave on Apple Silicon
        tpm_version: None,         // Not applicable for Secure Enclave
    })
}

/// Detect macOS automatic software update configuration.
///
/// Reads `com.apple.SoftwareUpdate AutomaticCheckEnabled` via `defaults`.
fn detect_os_auto_update() -> Option<OsAutoUpdate> {
    let output = run_command(
        "defaults",
        &["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"],
    );

    let enabled = output
        .as_deref()
        .map(|s| s.trim() == "1")
        .unwrap_or(false);

    Some(OsAutoUpdate {
        enabled,
        technology: Some("SoftwareUpdate".to_string()),
    })
}

/// Detect system uptime via `sysctl kern.boottime`.
///
/// Output format: `{ sec = 1709123456, usec = 0 } ...`
fn detect_uptime() -> Option<SystemUptime> {
    let output = run_command("sysctl", &["-n", "kern.boottime"])?;

    // Parse "{ sec = NNNN, usec = NNNN } ..."
    let sec_str = output
        .split("sec = ")
        .nth(1)?
        .split(',')
        .next()?
        .trim();

    let boot_secs: i64 = sec_str.parse().ok()?;
    let now_secs = jiff::Timestamp::now().as_second();
    let uptime = now_secs.saturating_sub(boot_secs);

    if uptime >= 0 {
        Some(SystemUptime {
            uptime_secs: uptime as u64,
        })
    } else {
        None
    }
}

/// Detect Gatekeeper status via `spctl --status`.
///
/// Output: "assessments enabled" or "assessments disabled".
fn detect_gatekeeper() -> Option<Gatekeeper> {
    let output = run_command("spctl", &["--status"])?;
    let enabled = output.contains("assessments enabled");
    Some(Gatekeeper { enabled })
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
