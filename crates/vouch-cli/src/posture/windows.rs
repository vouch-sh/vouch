// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Windows-specific device posture detection.

use std::process::Command;

use vouch_common::posture::{
    DevicePosture, DiskEncryption, FirewallStatus, OsAutoUpdate, ScreenLock, SecureBoot,
    SystemUptime,
};

/// Run all Windows-specific posture detection and populate the struct.
pub fn detect(posture: &mut DevicePosture) {
    detect_os_version(posture);
    posture.disk_encryption = detect_bitlocker();
    posture.screen_lock = detect_screen_lock();
    posture.firewall = detect_firewall();
    posture.secure_boot = detect_secure_boot();
    posture.os_auto_update = detect_os_auto_update();
    posture.system_uptime = detect_uptime();
}

/// Detect Windows version from `ver` command or registry.
fn detect_os_version(posture: &mut DevicePosture) {
    // Use PowerShell to read from registry — more reliable than `ver`
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

/// Detect BitLocker status via `manage-bde` (which may require elevation)
/// or PowerShell WMI (which may work without elevation).
fn detect_bitlocker() -> Option<DiskEncryption> {
    // Try WMI query for BitLocker — ProtectionStatus is readable without elevation
    // in some configurations
    let output = run_powershell(
        "(Get-CimInstance -Namespace 'Root\\CIMV2\\Security\\MicrosoftVolumeEncryption' \
         -ClassName Win32_EncryptableVolume -Filter \"DriveLetter='C:'\" \
         -ErrorAction SilentlyContinue).ProtectionStatus",
    )?;

    let status = output.trim();
    match status {
        "1" => Some(DiskEncryption {
            enabled: true,
            technology: Some("BitLocker".to_string()),
        }),
        "0" => Some(DiskEncryption {
            enabled: false,
            technology: Some("BitLocker".to_string()),
        }),
        _ => None,
    }
}

/// Detect screen lock configuration from registry.
fn detect_screen_lock() -> Option<ScreenLock> {
    let secure_output = run_powershell(
        "(Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' -ErrorAction SilentlyContinue).ScreenSaverIsSecure",
    );

    let enabled = secure_output
        .as_deref()
        .map(|s| s.trim() == "1")
        .unwrap_or(false);

    let timeout_output = run_powershell(
        "(Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' -ErrorAction SilentlyContinue).ScreenSaveTimeOut",
    );

    let idle_timeout_secs = timeout_output
        .as_deref()
        .and_then(|s| s.trim().parse::<u64>().ok());

    Some(ScreenLock {
        enabled,
        idle_timeout_secs,
    })
}

/// Detect Windows Firewall status via `netsh`.
fn detect_firewall() -> Option<FirewallStatus> {
    let output = run_command(
        "netsh",
        &["advfirewall", "show", "allprofiles", "state"],
    )?;

    // Check if any profile has "State ON"
    let enabled = output.lines().any(|line| {
        let lower = line.to_lowercase();
        lower.contains("state") && lower.contains("on")
    });

    Some(FirewallStatus {
        enabled,
        technology: Some("Windows Firewall".to_string()),
    })
}

/// Detect Secure Boot and TPM on Windows.
fn detect_secure_boot() -> Option<SecureBoot> {
    let sb_output = run_powershell("Confirm-SecureBootUEFI");
    let secure_boot_enabled = sb_output
        .as_deref()
        .map(|s| s.trim().eq_ignore_ascii_case("true"));

    let tpm_output = run_powershell(
        "(Get-CimInstance -ClassName Win32_Tpm -Namespace 'Root\\CIMV2\\Security\\MicrosoftTpm' \
         -ErrorAction SilentlyContinue).IsActivated_InitialValue",
    );
    let tpm_present = tpm_output
        .as_deref()
        .is_some_and(|s| s.trim().eq_ignore_ascii_case("true"));

    let tpm_version = if tpm_present {
        run_powershell(
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
        .filter(|s| !s.is_empty())
    } else {
        None
    };

    Some(SecureBoot {
        enabled: secure_boot_enabled,
        tpm_present: Some(tpm_present),
        tpm_version,
    })
}

/// Detect Windows Update automatic update configuration.
///
/// Reads the `AUOptions` registry value. Values:
/// - 2: Notify before download
/// - 3: Auto download, notify install
/// - 4: Auto download and install
fn detect_os_auto_update() -> Option<OsAutoUpdate> {
    let output = run_powershell(
        "(Get-ItemProperty \
         'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update' \
         -ErrorAction SilentlyContinue).AUOptions",
    );

    let enabled = output
        .as_deref()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .is_some_and(|v| v >= 3);

    Some(OsAutoUpdate {
        enabled,
        technology: Some("Windows Update".to_string()),
    })
}

/// Detect system uptime via WMI `LastBootUpTime`.
fn detect_uptime() -> Option<SystemUptime> {
    let output = run_powershell(
        "((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalSeconds",
    )?;

    let secs: f64 = output.trim().parse().ok()?;
    Some(SystemUptime {
        uptime_secs: secs as u64,
    })
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
