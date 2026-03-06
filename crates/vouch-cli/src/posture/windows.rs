// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Windows-specific device posture detection.

use std::process::Command;

use vouch_common::posture::DevicePosture;

/// Run all Windows-specific posture detection and populate the struct.
pub fn detect(posture: &mut DevicePosture) {
    detect_os_version(posture);
    detect_bitlocker(posture);
    detect_screen_lock(posture);
    detect_firewall(posture);
    detect_secure_boot(posture);
    detect_os_auto_update(posture);
    detect_uptime(posture);
}

/// Detect Windows version from PowerShell / registry.
fn detect_os_version(posture: &mut DevicePosture) {
    if let Some(output) = run_powershell(
        "[System.Environment]::OSVersion.Version.ToString()",
    ) {
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

/// Detect screen lock configuration from registry.
fn detect_screen_lock(posture: &mut DevicePosture) {
    let secure_output = run_powershell(
        "(Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' -ErrorAction SilentlyContinue).ScreenSaverIsSecure",
    );

    posture.screen_lock_enabled = Some(
        secure_output
            .as_deref()
            .map(|s| s.trim() == "1")
            .unwrap_or(false),
    );

    let timeout_output = run_powershell(
        "(Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' -ErrorAction SilentlyContinue).ScreenSaveTimeOut",
    );

    posture.screen_lock_idle_timeout_secs = timeout_output
        .as_deref()
        .and_then(|s| s.trim().parse::<u64>().ok());
}

/// Detect Windows Firewall status via `netsh`.
fn detect_firewall(posture: &mut DevicePosture) {
    if let Some(output) = run_command(
        "netsh",
        &["advfirewall", "show", "allprofiles", "state"],
    ) {
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
            posture.uptime_secs = Some(secs as u64);
        }
    }
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
