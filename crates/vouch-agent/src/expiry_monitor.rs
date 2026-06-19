// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Session expiry monitor — warns users before their session expires.
//!
//! Runs as a background task in the agent, checking session expiry at regular
//! intervals and sending desktop notifications at configurable thresholds.

use std::sync::Arc;
use tracing::{debug, info};

use crate::state::AgentState;

/// Thresholds (in seconds) at which to send expiry warnings.
/// Notifications are sent at most once per threshold.
const WARN_THRESHOLDS_SECS: &[u64] = &[
    30 * 60, // 30 minutes
    5 * 60,  // 5 minutes
];

/// How often to check session expiry (in seconds).
const CHECK_INTERVAL_SECS: u64 = 60;

/// Run the expiry monitor loop.
///
/// This task checks the session state periodically and sends desktop
/// notifications when the session is about to expire.
pub async fn run(state: Arc<AgentState>) {
    // Track which thresholds have already fired to avoid duplicate notifications
    let mut fired_thresholds: Vec<u64> = Vec::new();

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(CHECK_INTERVAL_SECS)).await;

        // Check if we have an active session
        let remaining_secs = match state.expires_in_seconds().await {
            Some(secs) => secs,
            None => {
                // No session — reset fired thresholds for next login
                if !fired_thresholds.is_empty() {
                    fired_thresholds.clear();
                    debug!("Session cleared, reset expiry notifications");
                }
                continue;
            }
        };

        // Session already expired
        if remaining_secs == 0 {
            if !fired_thresholds.contains(&0) {
                fired_thresholds.push(0);
                info!("Session has expired");
                let email = state.current_user_email().await;
                crate::audit::log_event(crate::audit::AuditEvent::SessionExpired { email });
                send_notification(
                    "Vouch session expired",
                    "Your session has expired. Run 'vouch login' to re-authenticate.",
                );
            }
            continue;
        }

        // Check each threshold
        for &threshold in WARN_THRESHOLDS_SECS {
            if remaining_secs <= threshold && !fired_thresholds.contains(&threshold) {
                fired_thresholds.push(threshold);
                // 60 is non-zero; unwrap_or arm is unreachable.
                let mins = threshold.checked_div(60).unwrap_or(0);
                let message = format!(
                    "Your Vouch session expires in {} minute{}.",
                    mins,
                    if mins == 1 { "" } else { "s" }
                );
                info!("{message}");
                send_notification("Vouch session expiring", &message);
            }
        }
    }
}

/// Send a desktop notification using platform-native commands.
///
/// Best-effort — failures are logged at debug level and never block the monitor.
fn send_notification(title: &str, body: &str) {
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "display notification \"{}\" with title \"{}\"",
            body.replace('"', "\\\""),
            title.replace('"', "\\\"")
        );
        match std::process::Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .output()
        {
            Ok(output) if output.status.success() => {
                debug!("Desktop notification sent via osascript");
            }
            Ok(output) => {
                debug!(
                    "osascript failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(e) => {
                debug!("Failed to run osascript: {e}");
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        match std::process::Command::new("notify-send")
            .arg("--app-name=Vouch")
            .arg(title)
            .arg(body)
            .output()
        {
            Ok(output) if output.status.success() => {
                debug!("Desktop notification sent via notify-send");
            }
            Ok(output) => {
                debug!(
                    "notify-send failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(e) => {
                debug!("Failed to run notify-send: {e}");
            }
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (title, body);
        debug!("Desktop notifications not supported on this platform");
    }
}
