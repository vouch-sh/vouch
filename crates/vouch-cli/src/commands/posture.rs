// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch posture` — inspect device posture signals.
//!
//! Shows what the CLI would send as `authorization_details` at login time.
//! Useful for debugging and verifying posture detection on a given machine.

use anyhow::Result;

/// Output format for the posture command.
#[derive(Debug, Default, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable summary (default).
    #[default]
    Text,
    /// Raw JSON (as sent in authorization_details).
    Json,
}

/// Run the posture inspection command.
pub fn run(format: OutputFormat) -> Result<()> {
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
    println!("Device Posture");
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
    if let Some(ref hostname) = p.hostname {
        println!("  Hostname:        {hostname}");
    }

    println!();

    // Disk encryption
    if let Some(ref de) = p.disk_encryption {
        let status = if de.enabled { "enabled" } else { "not detected" };
        let tech = de.technology.as_deref().unwrap_or("");
        if tech.is_empty() {
            println!("  Disk encryption: {status}");
        } else {
            println!("  Disk encryption: {status} ({tech})");
        }
    } else {
        println!("  Disk encryption: not checked");
    }

    // Screen lock
    if let Some(ref sl) = p.screen_lock {
        let status = if sl.enabled { "enabled" } else { "not detected" };
        if let Some(timeout) = sl.idle_timeout_secs {
            println!("  Screen lock:     {status} (idle timeout: {timeout}s)");
        } else {
            println!("  Screen lock:     {status}");
        }
    } else {
        println!("  Screen lock:     not checked");
    }

    // Firewall
    if let Some(ref fw) = p.firewall {
        let status = if fw.enabled { "enabled" } else { "not detected" };
        let tech = fw.technology.as_deref().unwrap_or("");
        if tech.is_empty() {
            println!("  Firewall:        {status}");
        } else {
            println!("  Firewall:        {status} ({tech})");
        }
    } else {
        println!("  Firewall:        not checked");
    }

    // Secure boot / TPM
    if let Some(ref sb) = p.secure_boot {
        if let Some(enabled) = sb.enabled {
            let status = if enabled { "enabled" } else { "disabled" };
            println!("  Secure boot:     {status}");
        }
        if let Some(tpm) = sb.tpm_present {
            let status = if tpm { "present" } else { "not detected" };
            if let Some(ref ver) = sb.tpm_version {
                println!("  TPM:             {status} (v{ver})");
            } else {
                println!("  TPM:             {status}");
            }
        }
    }

    // OS auto-update
    if let Some(ref au) = p.os_auto_update {
        let status = if au.enabled { "enabled" } else { "not detected" };
        let tech = au.technology.as_deref().unwrap_or("");
        if tech.is_empty() {
            println!("  Auto-update:     {status}");
        } else {
            println!("  Auto-update:     {status} ({tech})");
        }
    }

    // System uptime
    if let Some(ref up) = p.system_uptime {
        let days = up.uptime_secs / 86400;
        let hours = (up.uptime_secs % 86400) / 3600;
        let mins = (up.uptime_secs % 3600) / 60;
        println!("  Uptime:          {days}d {hours}h {mins}m");
    }

    // MAC policy (SELinux/AppArmor)
    if let Some(ref mac) = p.mac_policy {
        let tech = mac.technology.as_deref().unwrap_or("unknown");
        let status = match mac.enforcing {
            Some(true) => "enforcing",
            Some(false) => "permissive/loaded",
            None => "unknown",
        };
        println!("  MAC policy:      {tech} ({status})");
    }

    // Gatekeeper (macOS)
    if let Some(ref gk) = p.gatekeeper {
        let status = if gk.enabled { "enabled" } else { "disabled" };
        println!("  Gatekeeper:      {status}");
    }

    println!();

    // SSH session
    if let Some(ref ssh) = p.ssh_session {
        if ssh.detected {
            let client = ssh.client_ip.as_deref().unwrap_or("unknown");
            println!("  SSH session:     yes (from {client})");
        } else {
            println!("  SSH session:     no");
        }
    }

    // Execution context
    if let Some(ref ctx) = p.execution_context {
        if let Some(elevated) = ctx.elevated {
            let status = if elevated { "yes" } else { "no" };
            println!("  Elevated:        {status}");
        }
        if let Some(tty) = ctx.tty {
            let status = if tty { "yes" } else { "no" };
            println!("  TTY:             {status}");
        }
        if let Some(ref parent) = ctx.parent_process {
            println!("  Parent process:  {parent}");
        }
    }

    // CLI version
    if let Some(ref ver) = p.cli_version {
        println!("  CLI version:     {ver}");
    }
}
