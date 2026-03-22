// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch posture` — inspect device posture signals.
//!
//! Shows what the CLI would send as `authorization_details` at login time.
//! Useful for debugging and verifying posture detection on a given machine.

use anyhow::Result;

/// Output format for the posture command.
#[derive(Debug, Default, Clone, Copy, clap::ValueEnum)]
pub(crate) enum OutputFormat {
    /// Human-readable summary (default).
    #[default]
    Text,
    /// Raw JSON (as sent in authorization_details).
    Json,
}

/// Run the posture inspection command.
pub(crate) fn run(format: OutputFormat) -> Result<()> {
    let posture = vouch_cli::posture::collect();

    match format {
        OutputFormat::Text => print_text(&posture),
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&posture)
                .map_err(|e| anyhow::anyhow!("failed to serialize posture: {e}"))?;
            println!("{json}");
        }
    }

    Ok(())
}

fn print_text(p: &vouch_common::posture::DevicePosture) {
    println!("Device Posture (v{})", p.posture_version);
    println!("{}", "-".repeat(50));

    // OS info
    if let Some(ref os) = p.os {
        let version = p.os_version.as_deref().unwrap_or("unknown");
        let distro = p.os_distribution.as_deref().unwrap_or("");
        if distro.is_empty() {
            println!("  OS:              {os} {version}");
        } else {
            println!("  OS:              {distro} {version} ({os})");
        }
    }
    if let Some(ref build) = p.os_build {
        println!("  Build:           {build}");
    }
    if let Some(ref arch) = p.arch {
        println!("  Architecture:    {arch}");
    }
    println!();

    // Disk encryption
    if let Some(enabled) = p.disk_encryption_enabled {
        let status = if enabled { "enabled" } else { "not detected" };
        let tech = p.disk_encryption_technology.as_deref().unwrap_or("");
        if tech.is_empty() {
            println!("  Disk encryption: {status}");
        } else {
            println!("  Disk encryption: {status} ({tech})");
        }
    } else {
        println!("  Disk encryption: not checked");
    }

    // Screen lock
    if let Some(enabled) = p.screen_lock_enabled {
        let status = if enabled { "enabled" } else { "not detected" };
        if let Some(timeout) = p.screen_lock_idle_timeout_secs {
            println!("  Screen lock:     {status} (idle timeout: {timeout}s)");
        } else {
            println!("  Screen lock:     {status}");
        }
    } else {
        println!("  Screen lock:     not checked");
    }

    // Firewall
    if let Some(enabled) = p.firewall_enabled {
        let status = if enabled { "enabled" } else { "not detected" };
        let tech = p.firewall_technology.as_deref().unwrap_or("");
        if tech.is_empty() {
            println!("  Firewall:        {status}");
        } else {
            println!("  Firewall:        {status} ({tech})");
        }
    } else {
        println!("  Firewall:        not checked");
    }

    // Secure boot / TPM
    if let Some(enabled) = p.secure_boot_enabled {
        let status = if enabled { "enabled" } else { "disabled" };
        println!("  Secure boot:     {status}");
    }
    if let Some(sip) = p.sip_enabled {
        let status = if sip { "enabled" } else { "disabled" };
        println!("  SIP:             {status}");
    }
    if let Some(tpm) = p.tpm_present {
        let status = if tpm { "present" } else { "not detected" };
        if let Some(ref ver) = p.tpm_version {
            println!("  TPM:             {status} (v{ver})");
        } else {
            println!("  TPM:             {status}");
        }
    }

    // Auto-update
    if let Some(enabled) = p.auto_update_enabled {
        let status = if enabled { "enabled" } else { "not detected" };
        let tech = p.auto_update_technology.as_deref().unwrap_or("");
        if tech.is_empty() {
            println!("  Auto-update:     {status}");
        } else {
            println!("  Auto-update:     {status} ({tech})");
        }
    }

    // System uptime
    if let Some(secs) = p.uptime_secs {
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        let mins = (secs % 3600) / 60;
        println!("  Uptime:          {days}d {hours}h {mins}m");
    }

    // Access control (SELinux/AppArmor/Gatekeeper)
    if let Some(enforcing) = p.access_control_enforcing {
        let tech = p.access_control_technology.as_deref().unwrap_or("unknown");
        let status = if enforcing {
            "enforcing"
        } else {
            "permissive/disabled"
        };
        println!("  Access control:  {tech} ({status})");
    }

    // EDR agents
    if p.edr.is_empty() {
        println!("  EDR:             not detected");
    } else {
        let names: Vec<&str> = p.edr.iter().map(|a| a.as_str()).collect();
        println!("  EDR:             {}", names.join(", "));
    }

    // MDM agents
    if p.mdm.is_empty() {
        println!("  MDM:             not detected");
    } else {
        let names: Vec<&str> = p.mdm.iter().map(|a| a.as_str()).collect();
        println!("  MDM:             {}", names.join(", "));
    }

    println!();

    // Execution context
    if let Some(elevated) = p.elevated {
        let status = if elevated { "yes" } else { "no" };
        println!("  Elevated:        {status}");
    }
    if let Some(tty) = p.tty {
        let status = if tty { "yes" } else { "no" };
        println!("  TTY:             {status}");
    }
    if let Some(ref parent) = p.parent_process {
        println!("  Parent process:  {parent}");
    }

    // CLI version
    if let Some(ref ver) = p.cli_version {
        println!("  CLI version:     {ver}");
    }
}
