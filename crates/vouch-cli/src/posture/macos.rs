// SPDX-License-Identifier: Apache-2.0 OR MIT
//! macOS-specific device posture detection.

use vouch_common::posture::DevicePosture;

use super::common::run_command;

/// Run all macOS-specific posture detection and populate the struct.
pub fn detect(posture: &mut DevicePosture) {
    detect_os_version(posture);
    detect_filevault(posture);
    detect_screen_lock(posture);
    detect_firewall(posture);
    detect_secure_boot(posture);
    detect_os_auto_update(posture);
    detect_uptime(posture);
    detect_gatekeeper(posture);
    detect_edr(posture);
    detect_mdm(posture);
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
    posture.os_distribution = Some(
        run_command("sw_vers", &["-productName"])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "macOS".to_string()),
    );
}

/// Detect FileVault status via `fdesetup status`.
///
/// Does not require root. Output is either:
/// - "FileVault is On."
/// - "FileVault is Off."
fn detect_filevault(posture: &mut DevicePosture) {
    if let Some(output) = run_command("fdesetup", &["status"]) {
        posture.disk_encryption_enabled = Some(output.contains("FileVault is On"));
        posture.disk_encryption_technology = Some("FileVault".to_string());
    }
}

/// Detect screen lock configuration via `defaults read`.
fn detect_screen_lock(posture: &mut DevicePosture) {
    let ask_output = run_command(
        "defaults",
        &["read", "com.apple.screensaver", "askForPassword"],
    );

    posture.screen_lock_enabled = ask_output.as_deref().map(|s| s.trim() == "1");

    let idle_output = run_command("defaults", &["read", "com.apple.screensaver", "idleTime"]);

    posture.screen_lock_idle_timeout_secs = idle_output
        .as_deref()
        .and_then(|s| s.trim().parse::<u64>().ok());
}

/// Detect macOS Application Firewall status.
///
/// Uses `socketfilterfw --getglobalstate`. No elevation required.
fn detect_firewall(posture: &mut DevicePosture) {
    if let Some(output) = run_command(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
    ) {
        posture.firewall_enabled = Some(output.contains("enabled"));
        posture.firewall_technology = Some("Application Firewall".to_string());
    }
}

/// Detect Secure Boot, SIP, and TPM/Secure Enclave on macOS.
///
/// - `secure_boot_enabled`: `Some(true)` for Apple Silicon (always Full
///   Security). `None` for Intel (requires root to query).
/// - `sip_enabled`: parsed from `csrutil status`.
/// - `tpm_present`: true for Apple Silicon (Secure Enclave) or Intel T2
///   (detected via the T2-only `eficheck` binary).
fn detect_secure_boot(posture: &mut DevicePosture) {
    // SIP — separate from Secure Boot
    let sip_output = run_command("csrutil", &["status"]);
    posture.sip_enabled = Some(
        sip_output
            .as_deref()
            .map(|s| s.contains("enabled"))
            .unwrap_or(false),
    );

    let is_arm = std::env::consts::ARCH == "aarch64";

    // Secure Boot: Apple Silicon always runs Full Security.
    // Intel requires root (`bputil`), so we report None.
    posture.secure_boot_enabled = if is_arm { Some(true) } else { None };

    // T2 chip on Intel Macs ships eficheck; Apple Silicon has Secure Enclave
    let has_t2 = std::path::Path::new("/usr/libexec/firmwarecheckers/eficheck/eficheck").exists();
    posture.tpm_present = Some(is_arm || has_t2);
}

/// Detect macOS automatic software update configuration.
///
/// Reads `com.apple.SoftwareUpdate AutomaticCheckEnabled` via `defaults`.
fn detect_os_auto_update(posture: &mut DevicePosture) {
    let output = run_command(
        "defaults",
        &[
            "read",
            "/Library/Preferences/com.apple.SoftwareUpdate",
            "AutomaticCheckEnabled",
        ],
    );

    posture.auto_update_enabled = Some(output.as_deref().map(|s| s.trim() == "1").unwrap_or(false));
    posture.auto_update_technology = Some("SoftwareUpdate".to_string());
}

/// Detect system uptime via `sysctl kern.boottime`.
///
/// Output format: `{ sec = 1709123456, usec = 0 } ...`
fn detect_uptime(posture: &mut DevicePosture) {
    if let Some(secs) = read_boot_uptime() {
        posture.uptime_secs = Some(secs);
    }
}

fn read_boot_uptime() -> Option<u64> {
    let output = run_command("sysctl", &["-n", "kern.boottime"])?;

    // Parse "{ sec = NNNN, usec = NNNN } ..."
    let sec_str = output.split("sec = ").nth(1)?.split(',').next()?.trim();

    let boot_secs: i64 = sec_str.parse().ok()?;
    let now_secs = jiff::Timestamp::now().as_second();
    let uptime = now_secs.saturating_sub(boot_secs);

    if uptime >= 0 {
        Some(uptime as u64)
    } else {
        None
    }
}

/// Detect Gatekeeper status via `spctl --status`.
///
/// Gatekeeper is macOS's code-signing enforcement — reported as
/// `access_control_*` for device-agnostic policy evaluation.
fn detect_gatekeeper(posture: &mut DevicePosture) {
    if let Some(output) = run_command("spctl", &["--status"]) {
        posture.access_control_enforcing = Some(output.contains("assessments enabled"));
        posture.access_control_technology = Some("Gatekeeper".to_string());
    }
}

/// Detect endpoint detection & response (EDR) agents on macOS.
///
/// Checks for known EDR agent install directories and binaries.
/// Reports all detected agents. No elevation required.
fn detect_edr(posture: &mut DevicePosture) {
    // CrowdStrike Falcon (docs behind auth at falcon.crowdstrike.com)
    if std::path::Path::new("/Library/CS").exists()
        || std::path::Path::new("/Applications/Falcon.app").exists()
    {
        posture.edr.push("crowdstrike".to_string());
    }

    // SentinelOne
    if std::path::Path::new("/Library/Sentinel").exists()
        || std::path::Path::new("/Applications/SentinelOne").exists()
    {
        posture.edr.push("sentinelone".to_string());
    }

    // Carbon Black (Broadcom)
    if std::path::Path::new("/Applications/VMware Carbon Black Cloud").exists()
        || std::path::Path::new("/Library/Application Support/com.vmware.carbonblack.cloud")
            .exists()
    {
        posture.edr.push("carbon black".to_string());
    }

    // Microsoft Defender for Endpoint
    // https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-mac
    if std::path::Path::new("/Applications/Microsoft Defender.app").exists()
        || std::path::Path::new("/Library/Application Support/Microsoft/Defender").exists()
    {
        posture.edr.push("microsoft defender".to_string());
    }

    // 1Password Device Trust (Kolide)
    // https://support.1password.com/device-trust/
    if std::path::Path::new("/usr/local/kolide-k2/bin/launcher").exists() {
        posture.edr.push("1password device trust".to_string());
    }
}

/// Detect mobile device management (MDM) agents on macOS.
///
/// Checks for known MDM agent install directories.
/// Reports all detected agents. No elevation required.
fn detect_mdm(posture: &mut DevicePosture) {
    // Jamf Pro
    if std::path::Path::new("/usr/local/jamf/bin/jamf").exists() {
        posture.mdm.push("jamf".to_string());
    }

    // Kandji
    if std::path::Path::new("/Library/Kandji").exists() {
        posture.mdm.push("kandji".to_string());
    }

    // Workspace ONE (Omnissa, formerly VMware)
    if std::path::Path::new("/Library/Application Support/AirWatch").exists()
        || std::path::Path::new("/Applications/Workspace ONE Intelligent Hub.app").exists()
    {
        posture.mdm.push("workspace one".to_string());
    }

    // Mosyle
    if std::path::Path::new("/Library/Application Support/Mosyle").exists() {
        posture.mdm.push("mosyle".to_string());
    }

    // Fleetsmith (Apple Business Essentials)
    if std::path::Path::new("/Library/Fleetsmith").exists() {
        posture.mdm.push("fleetsmith".to_string());
    }
}
