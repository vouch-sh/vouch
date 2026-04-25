// SPDX-License-Identifier: Apache-2.0 OR MIT
//! macOS-specific device posture detection.

use vouch_common::posture::{DevicePosture, EdrAgent, MdmAgent};

use super::common::run_command;

/// Run all macOS-specific posture detection and populate the struct.
pub(super) fn detect(posture: &mut DevicePosture) {
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

/// Detect FileVault status via `fdesetup isactive`.
///
/// Uses exit codes (no text parsing): exit 0 = on, exit 1 = off.
/// Does not require root.
fn detect_filevault(posture: &mut DevicePosture) {
    let result = std::process::Command::new("fdesetup")
        .arg("isactive")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    if let Ok(status) = result {
        posture.disk_encryption_enabled = Some(status.success());
        posture.disk_encryption_technology = Some("FileVault".to_string());
    }
}

/// Detect screen lock configuration.
///
/// Uses `sysadminctl -screenLock status` which works on all modern macOS
/// versions. The legacy `com.apple.screensaver askForPassword` defaults
/// key no longer exists on macOS 15+.
///
/// Note: `sysadminctl` writes to stderr (via NSLog), not stdout.
///
/// Output examples:
/// - `"screenLock delay is immediate"` — enabled, 0 second delay
/// - `"screenLock delay is 300 seconds"` — enabled, 5 minute delay
/// - `"screenLock is off"` — disabled
fn detect_screen_lock(posture: &mut DevicePosture) {
    if let Some(output) = run_command_stderr("sysadminctl", &["-screenLock", "status"]) {
        let line = output.trim().to_lowercase();
        if line.contains("is off") {
            posture.screen_lock_enabled = Some(false);
        } else if line.contains("delay is") {
            posture.screen_lock_enabled = Some(true);
            if line.contains("immediate") {
                posture.screen_lock_idle_timeout_secs = Some(0);
            } else if let Some(secs) = extract_seconds(&line) {
                posture.screen_lock_idle_timeout_secs = Some(secs);
            }
        }
    }
}

/// Extract seconds from sysadminctl output like "delay is 300 seconds".
fn extract_seconds(line: &str) -> Option<u64> {
    let after_is = line.split("delay is ").nth(1)?;
    let num_str = after_is.split_whitespace().next()?;
    num_str.parse::<u64>().ok()
}

/// Run a command and capture stderr. Some macOS tools (sysadminctl)
/// write their output to stderr via NSLog.
fn run_command_stderr(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stderr).into_owned())
}

/// Detect macOS Application Firewall status.
///
/// Uses `socketfilterfw --getglobalstate`. No elevation required.
/// Parses the machine-readable `(State = N)` value from the output:
/// - State 0: disabled
/// - State 1: enabled (allow specific)
/// - State 2: enabled (block all incoming)
fn detect_firewall(posture: &mut DevicePosture) {
    if let Some(output) = run_command(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
    ) {
        let state = output
            .split("State = ")
            .nth(1)
            .and_then(|s| s.split(')').next())
            .and_then(|s| s.trim().parse::<u32>().ok());

        posture.firewall_enabled = state.map(|s| s > 0);
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
    posture.sip_enabled = Some(sip_output.as_deref().is_some_and(|s| s.contains("enabled")));

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
/// The `AutomaticCheckEnabled` key was removed in macOS 15+. Modern
/// macOS uses `AutomaticDownload` (auto-download enabled) and
/// `AutomaticallyInstallMacOSUpdates` (auto-install enabled). We check
/// both, preferring `AutomaticDownload` as the primary signal.
fn detect_os_auto_update(posture: &mut DevicePosture) {
    let plist = "/Library/Preferences/com.apple.SoftwareUpdate";

    // macOS 15+: AutomaticDownload
    let download = run_command("defaults", &["read", plist, "AutomaticDownload"]);
    if let Some(ref val) = download
        && val.trim() == "1"
    {
        posture.auto_update_enabled = Some(true);
        posture.auto_update_technology = Some("SoftwareUpdate".to_string());
        return;
    }

    // macOS 15+: AutomaticallyInstallMacOSUpdates
    let install = run_command(
        "defaults",
        &["read", plist, "AutomaticallyInstallMacOSUpdates"],
    );
    if let Some(ref val) = install
        && val.trim() == "1"
    {
        posture.auto_update_enabled = Some(true);
        posture.auto_update_technology = Some("SoftwareUpdate".to_string());
        return;
    }

    // Legacy: AutomaticCheckEnabled (macOS <= 14)
    let check = run_command("defaults", &["read", plist, "AutomaticCheckEnabled"]);
    if let Some(ref val) = check {
        posture.auto_update_enabled = Some(val.trim() == "1");
        posture.auto_update_technology = Some("SoftwareUpdate".to_string());
        return;
    }

    // If all keys are absent, we can't determine the state
    if download.is_some() || install.is_some() || check.is_some() {
        posture.auto_update_enabled = Some(false);
        posture.auto_update_technology = Some("SoftwareUpdate".to_string());
    }
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
        posture.edr.push(EdrAgent::CrowdStrike);
    }

    // SentinelOne
    if std::path::Path::new("/Library/Sentinel").exists()
        || std::path::Path::new("/Applications/SentinelOne").exists()
    {
        posture.edr.push(EdrAgent::SentinelOne);
    }

    // Carbon Black (Broadcom)
    if std::path::Path::new("/Applications/VMware Carbon Black Cloud").exists()
        || std::path::Path::new("/Library/Application Support/com.vmware.carbonblack.cloud")
            .exists()
    {
        posture.edr.push(EdrAgent::CarbonBlack);
    }

    // Microsoft Defender for Endpoint
    // https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-mac
    if std::path::Path::new("/Applications/Microsoft Defender.app").exists()
        || std::path::Path::new("/Library/Application Support/Microsoft/Defender").exists()
    {
        posture.edr.push(EdrAgent::MicrosoftDefender);
    }

    // 1Password Device Trust (Kolide)
    // https://support.1password.com/device-trust/
    if std::path::Path::new("/usr/local/kolide-k2/bin/launcher").exists() {
        posture.edr.push(EdrAgent::OnePasswordDeviceTrust);
    }
}

/// Detect mobile device management (MDM) agents on macOS.
///
/// Checks for known MDM agent install directories.
/// Reports all detected agents. No elevation required.
fn detect_mdm(posture: &mut DevicePosture) {
    // Jamf Pro
    if std::path::Path::new("/usr/local/jamf/bin/jamf").exists() {
        posture.mdm.push(MdmAgent::Jamf);
    }

    // Kandji
    if std::path::Path::new("/Library/Kandji").exists() {
        posture.mdm.push(MdmAgent::Kandji);
    }

    // Workspace ONE (Omnissa, formerly VMware)
    if std::path::Path::new("/Library/Application Support/AirWatch").exists()
        || std::path::Path::new("/Applications/Workspace ONE Intelligent Hub.app").exists()
    {
        posture.mdm.push(MdmAgent::WorkspaceOne);
    }

    // Mosyle
    if std::path::Path::new("/Library/Application Support/Mosyle").exists() {
        posture.mdm.push(MdmAgent::Mosyle);
    }

    // Fleetsmith (Apple Business Essentials)
    if std::path::Path::new("/Library/Fleetsmith").exists() {
        posture.mdm.push(MdmAgent::Fleetsmith);
    }
}
