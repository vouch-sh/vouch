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
///
/// The `Win32_EncryptableVolume` WMI class requires administrator privileges;
/// without elevation the query returns `Access denied` (no usable non-admin
/// alternative exists — `manage-bde`, `Get-BitLockerVolume`, and the WMI class
/// all gate on admin). Skip the check entirely when not elevated so the field
/// is correctly reported as "not checked" rather than silently failing.
fn detect_bitlocker(posture: &mut DevicePosture) {
    if !matches!(posture.elevated, Some(true)) {
        return;
    }

    let output = run_powershell(
        "(Get-CimInstance -Namespace 'Root\\CIMV2\\Security\\MicrosoftVolumeEncryption' \
         -ClassName Win32_EncryptableVolume -Filter \"DriveLetter='C:'\" \
         -ErrorAction SilentlyContinue).ProtectionStatus",
    );

    if let Some(status) = output.as_deref().map(str::trim) {
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
///
/// TPM detection uses the `Win32_PnPEntity` security-devices class, which is
/// queryable without elevation. The `Win32_Tpm` WMI class under
/// `Root\CIMV2\Security\MicrosoftTpm` is admin-gated, so we only consult it
/// as an enrichment when running elevated.
fn detect_secure_boot(posture: &mut DevicePosture) {
    let sb_output = run_powershell("Confirm-SecureBootUEFI");
    posture.secure_boot_enabled = sb_output
        .as_deref()
        .map(|s| s.trim().eq_ignore_ascii_case("true"));

    // Primary path: PnP enumeration (no admin required). Returns a literal
    // marker so we can distinguish "TPM present" from "no TPM" from "query failed".
    let pnp_output = run_powershell(
        "$tpm = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue | \
         Where-Object { $_.PNPClass -eq 'SecurityDevices' -and \
         $_.Name -match 'Trusted Platform Module' } | Select-Object -First 1; \
         if ($null -eq $tpm) { 'ABSENT' } else { 'PRESENT:' + $tpm.Name }",
    );

    match pnp_output.as_deref().map(str::trim) {
        Some("ABSENT") => {
            posture.tpm_present = Some(false);
        }
        Some(s) if s.starts_with("PRESENT:") => {
            posture.tpm_present = Some(true);
            let name = s.get("PRESENT:".len()..).unwrap_or("");
            if let Some(ver) = parse_tpm_version_from_pnp_name(name) {
                posture.tpm_version = Some(ver);
            }
        }
        _ => {
            // Leave tpm_present as None — query did not return a usable answer.
        }
    }

    // Enrichment when elevated: prefer the WMI `SpecVersion` if we don't yet
    // have a version. Skipped without admin.
    if matches!(posture.elevated, Some(true))
        && posture.tpm_present == Some(true)
        && posture.tpm_version.is_none()
        && let Some(spec) = run_powershell(
            "(Get-CimInstance -ClassName Win32_Tpm -Namespace 'Root\\CIMV2\\Security\\MicrosoftTpm' \
             -ErrorAction SilentlyContinue).SpecVersion",
        )
        // SpecVersion returns "2.0, 0, 1.38" — take the first part.
        && let Some(first) = spec.trim().split(',').next()
    {
        let trimmed = first.trim();
        if !trimmed.is_empty() {
            posture.tpm_version = Some(trimmed.to_string());
        }
    }
}

/// Extract a TPM version string from a PnP entity friendly name.
///
/// Examples:
/// - `"Trusted Platform Module 2.0"` → `Some("2.0")`
/// - `"Trusted Platform Module 1.2"` → `Some("1.2")`
/// - `"Trusted Platform Module"` → `None`
fn parse_tpm_version_from_pnp_name(name: &str) -> Option<String> {
    let after = name.trim().strip_prefix("Trusted Platform Module")?.trim();
    let token = after.split_whitespace().next()?;
    if token.chars().any(|c| c.is_ascii_digit()) {
        Some(token.to_string())
    } else {
        None
    }
}

/// Detect Windows Update automatic update configuration.
///
/// Signals are consulted in priority order:
///
/// 1. `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate`:
///    if `= 1`, auto-update is explicitly disabled by policy.
/// 2. `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\AUOptions`:
///    legacy value. `>= 2` (notify, auto-download, auto-install) ⇒ enabled;
///    `<= 1` ⇒ disabled. If the value is *absent*, fall through — modern
///    Win10/11 installs do not set this key by default.
/// 3. `Get-Service wuauserv` start type: `Disabled` ⇒ disabled, anything else
///    (including the trigger-started `Manual` default on Win10/11) ⇒ enabled.
fn detect_os_auto_update(posture: &mut DevicePosture) {
    let mark = |p: &mut DevicePosture, enabled: bool| {
        p.auto_update_enabled = Some(enabled);
        p.auto_update_technology = Some("Windows Update".to_string());
    };

    // 1. Explicit policy disable.
    let no_auto = run_powershell(
        "(Get-ItemProperty \
         'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' \
         -ErrorAction SilentlyContinue).NoAutoUpdate",
    );
    if no_auto.as_deref().map(str::trim) == Some("1") {
        mark(posture, false);
        return;
    }

    // 2. Legacy AUOptions, only when explicitly present.
    let au_options = run_powershell(
        "(Get-ItemProperty \
         'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update' \
         -ErrorAction SilentlyContinue).AUOptions",
    );
    if let Some(val) = au_options
        .as_deref()
        .and_then(|s| s.trim().parse::<u32>().ok())
    {
        mark(posture, val >= 2);
        return;
    }

    // 3. Service start type fallback. On default Win10/11 wuauserv is
    //    trigger-started with `Manual` — that is the auto-update-on case.
    let svc =
        run_powershell("(Get-Service -Name wuauserv -ErrorAction SilentlyContinue).StartType");
    if let Some(start_type) = auto_update_from_service_start_type(svc.as_deref()) {
        mark(posture, start_type);
    }
}

/// Map a `Get-Service ... StartType` string to an auto-update enabled flag.
///
/// `Disabled` ⇒ `Some(false)`. Any other recognised start type ⇒ `Some(true)`.
/// Empty or unrecognised ⇒ `None` (treat as "couldn't determine").
fn auto_update_from_service_start_type(start_type: Option<&str>) -> Option<bool> {
    let value = start_type?.trim();
    match value {
        "" => None,
        "Disabled" => Some(false),
        "Automatic" | "AutomaticDelayedStart" | "Manual" | "Boot" | "System" => Some(true),
        _ => None,
    }
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

#[cfg(test)]
mod tests {
    use super::{auto_update_from_service_start_type, parse_tpm_version_from_pnp_name};

    #[test]
    fn tpm_version_from_pnp_name_v2() {
        assert_eq!(
            parse_tpm_version_from_pnp_name("Trusted Platform Module 2.0").as_deref(),
            Some("2.0")
        );
    }

    #[test]
    fn tpm_version_from_pnp_name_v12() {
        assert_eq!(
            parse_tpm_version_from_pnp_name("Trusted Platform Module 1.2").as_deref(),
            Some("1.2")
        );
    }

    #[test]
    fn tpm_version_from_pnp_name_no_version_token() {
        assert_eq!(
            parse_tpm_version_from_pnp_name("Trusted Platform Module"),
            None
        );
    }

    #[test]
    fn tpm_version_from_pnp_name_unrelated() {
        assert_eq!(parse_tpm_version_from_pnp_name("AMD PSP 11.0 Device"), None);
    }

    #[test]
    fn auto_update_start_type_disabled() {
        assert_eq!(
            auto_update_from_service_start_type(Some("Disabled")),
            Some(false)
        );
    }

    #[test]
    fn auto_update_start_type_manual_is_enabled() {
        // Win10/11 default for wuauserv is `Manual` (trigger-started).
        assert_eq!(
            auto_update_from_service_start_type(Some("Manual")),
            Some(true)
        );
    }

    #[test]
    fn auto_update_start_type_automatic_is_enabled() {
        assert_eq!(
            auto_update_from_service_start_type(Some("Automatic")),
            Some(true)
        );
        assert_eq!(
            auto_update_from_service_start_type(Some("AutomaticDelayedStart")),
            Some(true)
        );
    }

    #[test]
    fn auto_update_start_type_missing_or_unknown() {
        assert_eq!(auto_update_from_service_start_type(None), None);
        assert_eq!(auto_update_from_service_start_type(Some("")), None);
        assert_eq!(auto_update_from_service_start_type(Some("Bogus")), None);
    }
}
