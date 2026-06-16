// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch posture` — inspect device posture signals.
//!
//! Shows what the CLI would send as `authorization_details` at login time.
//! Useful for debugging and verifying posture detection on a given machine.

use anyhow::Result;
use vouch_cli::{tr, tr_args};

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

#[expect(
    clippy::too_many_lines,
    reason = "linear print of every posture signal — splitting would obscure the column layout"
)]
fn print_text(p: &vouch_common::posture::DevicePosture) {
    println!("{}", tr_args!("posture-title", version = p.posture_version));
    println!("{}", "-".repeat(50));

    // OS info
    if let Some(ref os) = p.os {
        let version = p.os_version.as_deref().unwrap_or("unknown");
        let distro = p.os_distribution.as_deref().unwrap_or("");
        if distro.is_empty() {
            println!("  {:<16} {os} {version}", tr!("posture-label-os"));
        } else {
            println!(
                "  {:<16} {distro} {version} ({os})",
                tr!("posture-label-os")
            );
        }
    }
    if let Some(ref build) = p.os_build {
        println!("  {:<16} {build}", tr!("posture-label-build"));
    }
    if let Some(ref arch) = p.arch {
        println!("  {:<16} {arch}", tr!("posture-label-architecture"));
    }
    println!();

    // Disk encryption
    if let Some(enabled) = p.disk_encryption_enabled {
        let status = tr_args!("posture-val-enabled-or-missing", on = enabled.to_string());
        let tech = p.disk_encryption_technology.as_deref().unwrap_or("");
        if tech.is_empty() {
            println!("  {:<16} {status}", tr!("posture-label-disk-encryption"));
        } else {
            println!(
                "  {:<16} {status} ({tech})",
                tr!("posture-label-disk-encryption")
            );
        }
    } else {
        println!(
            "  {:<16} {}",
            tr!("posture-label-disk-encryption"),
            tr!("posture-val-not-checked")
        );
    }

    // Screen lock
    if let Some(enabled) = p.screen_lock_enabled {
        let status = tr_args!("posture-val-enabled-or-missing", on = enabled.to_string());
        if let Some(timeout) = p.screen_lock_idle_timeout_secs {
            println!(
                "  {:<16} {status} (idle timeout: {timeout}s)",
                tr!("posture-label-screen-lock")
            );
        } else {
            println!("  {:<16} {status}", tr!("posture-label-screen-lock"));
        }
    } else {
        println!(
            "  {:<16} {}",
            tr!("posture-label-screen-lock"),
            tr!("posture-val-not-checked")
        );
    }

    // Firewall
    if let Some(enabled) = p.firewall_enabled {
        let status = tr_args!("posture-val-enabled-or-missing", on = enabled.to_string());
        let tech = p.firewall_technology.as_deref().unwrap_or("");
        if tech.is_empty() {
            println!("  {:<16} {status}", tr!("posture-label-firewall"));
        } else {
            println!("  {:<16} {status} ({tech})", tr!("posture-label-firewall"));
        }
    } else {
        println!(
            "  {:<16} {}",
            tr!("posture-label-firewall"),
            tr!("posture-val-not-checked")
        );
    }

    if let Some(enabled) = p.secure_boot_enabled {
        let status = tr_args!("posture-val-enabled-or-disabled", on = enabled.to_string());
        println!("  {:<16} {status}", tr!("posture-label-secure-boot"));
    }
    if let Some(sip) = p.sip_enabled {
        let status = tr_args!("posture-val-enabled-or-disabled", on = sip.to_string());
        println!("  {:<16} {status}", tr!("posture-label-sip"));
    }
    if let Some(tpm) = p.tpm_present {
        let status = tr_args!("posture-val-present-or-missing", on = tpm.to_string());
        if let Some(ref ver) = p.tpm_version {
            println!("  {:<16} {status} (v{ver})", tr!("posture-label-tpm"));
        } else {
            println!("  {:<16} {status}", tr!("posture-label-tpm"));
        }
    }

    if let Some(enabled) = p.auto_update_enabled {
        let status = tr_args!("posture-val-enabled-or-missing", on = enabled.to_string());
        let tech = p.auto_update_technology.as_deref().unwrap_or("");
        if tech.is_empty() {
            println!("  {:<16} {status}", tr!("posture-label-auto-update"));
        } else {
            println!(
                "  {:<16} {status} ({tech})",
                tr!("posture-label-auto-update")
            );
        }
    }

    if let Some(secs) = p.uptime_secs {
        // 86400, 3600, 60 are non-zero; unwrap_or arms are unreachable.
        let days = secs.checked_div(86400).unwrap_or(0);
        let hours = (secs % 86400).checked_div(3600).unwrap_or(0);
        let mins = (secs % 3600).checked_div(60).unwrap_or(0);
        println!(
            "  {:<16} {days}d {hours}h {mins}m",
            tr!("posture-label-uptime")
        );
    }

    if let Some(enforcing) = p.access_control_enforcing {
        let tech = p.access_control_technology.as_deref().unwrap_or("unknown");
        let status = tr_args!(
            "posture-val-enforcing-or-permissive",
            on = enforcing.to_string()
        );
        println!(
            "  {:<16} {tech} ({status})",
            tr!("posture-label-access-control")
        );
    }

    if p.edr.is_empty() {
        println!(
            "  {:<16} {}",
            tr!("posture-label-edr"),
            tr!("posture-val-not-detected")
        );
    } else {
        let names: Vec<&str> = p.edr.iter().map(|a| a.as_str()).collect();
        println!("  {:<16} {}", tr!("posture-label-edr"), names.join(", "));
    }

    if p.mdm.is_empty() {
        println!(
            "  {:<16} {}",
            tr!("posture-label-mdm"),
            tr!("posture-val-not-detected")
        );
    } else {
        let names: Vec<&str> = p.mdm.iter().map(|a| a.as_str()).collect();
        println!("  {:<16} {}", tr!("posture-label-mdm"), names.join(", "));
    }

    println!();

    if let Some(elevated) = p.elevated {
        let status = tr_args!("posture-val-yes-no", b = elevated.to_string());
        println!("  {:<16} {status}", tr!("posture-label-elevated"));
    }
    if let Some(tty) = p.tty {
        let status = tr_args!("posture-val-yes-no", b = tty.to_string());
        println!("  {:<16} {status}", tr!("posture-label-tty"));
    }
    if let Some(ref parent) = p.parent_process {
        println!("  {:<16} {parent}", tr!("posture-label-parent-process"));
    }

    if let Some(ref ver) = p.cli_version {
        println!("  {:<16} {ver}", tr!("posture-label-cli-version"));
    }
}
