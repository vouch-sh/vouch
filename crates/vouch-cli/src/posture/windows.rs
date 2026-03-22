// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Windows-specific device posture detection.

use std::process::Command;

use vouch_common::posture::{DevicePosture, EdrAgent, MdmAgent};

use super::common::run_command;

/// Run all Windows-specific posture detection and populate the struct.
pub(super) fn detect(posture: &mut DevicePosture) {
    detect_os_version(posture);
    detect_bitlocker(posture);
    detect_screen_lock(posture);
    detect_firewall(posture);
    detect_secure_boot(posture);
    detect_os_auto_update(posture);
    detect_uptime(posture);
    detect_edr(posture);
    detect_mdm(posture);
}

/// Detect Windows version from PowerShell / registry.
fn detect_os_version(posture: &mut DevicePosture) {
    if let Some(output) = run_powershell("[System.Environment]::OSVersion.Version.ToString()") {
        let version = output.trim().to_string();
        if !version.is_empty() {
            posture.os_version = Some(version);
        }
    }

    if let Some(output) = run_powershell(
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').DisplayVersion",
    ) {
        let display = output.trim().to_string();
        if !display.is_empty() {
            posture.os_distribution = Some(format!("Windows {display}"));
        }
    }

    if let Some(output) = run_powershell(
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').CurrentBuild",
    ) {
        let build = output.trim().to_string();
        if !build.is_empty() {
            posture.os_build = Some(build);
        }
    }
}

/// Detect BitLocker status via WMI.
fn detect_bitlocker(posture: &mut DevicePosture) {
    let output = run_powershell(
        "(Get-CimInstance -Namespace 'Root\\CIMV2\\Security\\MicrosoftVolumeEncryption' \
         -ClassName Win32_EncryptableVolume -Filter \"DriveLetter='C:'\" \
         -ErrorAction SilentlyContinue).ProtectionStatus",
    );

    if let Some(status) = output.as_deref().map(|s| s.trim()) {
        match status {
            "1" => {
                posture.disk_encryption_enabled = Some(true);
                posture.disk_encryption_technology = Some("BitLocker".to_string());
            }
            "0" => {
                posture.disk_encryption_enabled = Some(false);
                posture.disk_encryption_technology = Some("BitLocker".to_string());
            }
            _ => {}
        }
    }
}

/// Detect screen lock configuration.
///
/// Checks both the modern `MaxInactivityTimeDeviceLock` Group Policy
/// (used by Intune/SCCM) and the legacy screensaver registry keys.
/// The GP value takes precedence since it's the MDM-managed setting.
fn detect_screen_lock(posture: &mut DevicePosture) {
    // Modern: Group Policy / Intune managed lock timeout (in seconds)
    let gp_output = run_powershell(
        "(Get-ItemProperty \
         'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' \
         -ErrorAction SilentlyContinue).InactivityTimeoutSecs",
    );
    if let Some(ref val) = gp_output {
        if let Ok(secs) = val.trim().parse::<u64>() {
            posture.screen_lock_enabled = Some(secs > 0);
            posture.screen_lock_idle_timeout_secs = Some(secs);
            return;
        }
    }

    // Legacy: screensaver-based lock
    let secure_output = run_powershell(
        "(Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' \
         -ErrorAction SilentlyContinue).ScreenSaverIsSecure",
    );

    posture.screen_lock_enabled = secure_output.as_deref().map(|s| s.trim() == "1");

    let timeout_output = run_powershell(
        "(Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' \
         -ErrorAction SilentlyContinue).ScreenSaveTimeOut",
    );

    posture.screen_lock_idle_timeout_secs = timeout_output
        .as_deref()
        .and_then(|s| s.trim().parse::<u64>().ok());
}

/// Detect Windows Firewall status via `netsh`.
fn detect_firewall(posture: &mut DevicePosture) {
    if let Some(output) = run_command("netsh", &["advfirewall", "show", "allprofiles", "state"]) {
        // Check if any profile has "State ON"
        let enabled = output.lines().any(|line| {
            let lower = line.to_lowercase();
            lower.contains("state") && lower.contains("on")
        });

        posture.firewall_enabled = Some(enabled);
        posture.firewall_technology = Some("Windows Firewall".to_string());
    }
}

/// Detect Secure Boot and TPM on Windows.
fn detect_secure_boot(posture: &mut DevicePosture) {
    let sb_output = run_powershell("Confirm-SecureBootUEFI");
    posture.secure_boot_enabled = sb_output
        .as_deref()
        .map(|s| s.trim().eq_ignore_ascii_case("true"));

    let tpm_output = run_powershell(
        "(Get-CimInstance -ClassName Win32_Tpm -Namespace 'Root\\CIMV2\\Security\\MicrosoftTpm' \
         -ErrorAction SilentlyContinue).IsActivated_InitialValue",
    );
    let tpm_present = tpm_output
        .as_deref()
        .is_some_and(|s| s.trim().eq_ignore_ascii_case("true"));
    posture.tpm_present = Some(tpm_present);

    if tpm_present {
        posture.tpm_version = run_powershell(
            "(Get-CimInstance -ClassName Win32_Tpm -Namespace 'Root\\CIMV2\\Security\\MicrosoftTpm' \
             -ErrorAction SilentlyContinue).SpecVersion",
        )
        .map(|s| {
            // SpecVersion returns "2.0, 0, 1.38" — take the first part
            s.trim()
                .split(',')
                .next()
                .unwrap_or(s.trim())
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty());
    }
}

/// Detect Windows Update automatic update configuration.
///
/// Reads the `AUOptions` registry value. Values:
/// - 2: Notify before download
/// - 3: Auto download, notify install
/// - 4: Auto download and install
fn detect_os_auto_update(posture: &mut DevicePosture) {
    let output = run_powershell(
        "(Get-ItemProperty \
         'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update' \
         -ErrorAction SilentlyContinue).AUOptions",
    );

    let enabled = output
        .as_deref()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .is_some_and(|v| v >= 3);

    posture.auto_update_enabled = Some(enabled);
    posture.auto_update_technology = Some("Windows Update".to_string());
}

/// Detect system uptime via WMI `LastBootUpTime`.
fn detect_uptime(posture: &mut DevicePosture) {
    if let Some(output) = run_powershell(
        "((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalSeconds",
    ) {
        if let Ok(secs) = output.trim().parse::<f64>() {
            if secs >= 0.0 {
                posture.uptime_secs = Some(secs as u64);
            }
        }
    }
}

/// Detect endpoint detection & response (EDR) agents on Windows.
///
/// Checks for known EDR services via `sc query`. Reports all detected
/// agents. No elevation required to query service existence.
fn detect_edr(posture: &mut DevicePosture) {
    // CrowdStrike Falcon (docs behind auth at falcon.crowdstrike.com)
    if is_service_running("CSFalconService") {
        posture.edr.push(EdrAgent::CrowdStrike);
    }

    // SentinelOne
    if is_service_running("SentinelAgent") {
        posture.edr.push(EdrAgent::SentinelOne);
    }

    // Carbon Black (Broadcom)
    if is_service_running("CbDefenseService") || is_service_running("CbDefense") {
        posture.edr.push(EdrAgent::CarbonBlack);
    }

    // Microsoft Defender for Endpoint (Sense = EDR component, not basic Defender antivirus)
    // https://learn.microsoft.com/en-us/defender-endpoint/configure-endpoints-script
    if is_service_running("Sense") {
        posture.edr.push(EdrAgent::MicrosoftDefender);
    }

    // Trellix (formerly McAfee)
    if is_service_running("mfemms") || is_service_running("McAfeeFramework") {
        posture.edr.push(EdrAgent::Trellix);
    }

    // 1Password Device Trust (Kolide)
    // https://support.1password.com/device-trust/
    if is_service_running("launcher.kolide-k2") {
        posture.edr.push(EdrAgent::OnePasswordDeviceTrust);
    }
}

/// Detect mobile device management (MDM) on Windows.
///
/// Reports all detected agents.
fn detect_mdm(posture: &mut DevicePosture) {
    // Microsoft Intune
    // https://learn.microsoft.com/en-us/mem/intune/apps/intune-management-extension
    if is_service_running("IntuneManagementExtension") {
        posture.mdm.push(MdmAgent::Intune);
    }

    // Workspace ONE (Omnissa, formerly VMware)
    if is_service_running("AirWatchService") {
        posture.mdm.push(MdmAgent::WorkspaceOne);
    }
}

/// Check if a Windows service is in RUNNING state via `sc query`.
fn is_service_running(service: &str) -> bool {
    run_command("sc", &["query", service])
        .as_deref()
        .is_some_and(|s| s.contains("RUNNING"))
}

/// Run a PowerShell command and capture stdout.
fn run_powershell(script: &str) -> Option<String> {
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if result.is_empty() {
        return None;
    }

    Some(result)
}
