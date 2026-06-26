// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Session expiry monitor — warns users before their session expires.
//!
//! Runs as a background task in the agent, checking session expiry at regular
//! intervals and sending desktop notifications at configurable thresholds.

use jiff::Timestamp;
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
    // Thresholds already fired for the current session, to avoid duplicate
    // notifications.
    let mut fired_thresholds: Vec<u64> = Vec::new();
    // Identity of the session those thresholds were recorded against (its
    // expiry timestamp). A new login changes this — even one that replaces an
    // already-expired session without an intervening logout — so the warnings
    // re-arm for the new session.
    let mut tracked_session: Option<Timestamp> = None;

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(CHECK_INTERVAL_SECS)).await;

        let (session_expiry, remaining_secs) = state.session_expiry_info().await;

        for threshold in thresholds_to_fire(
            &mut tracked_session,
            &mut fired_thresholds,
            session_expiry,
            remaining_secs,
        ) {
            if threshold == 0 {
                info!("Session has expired");
                let email = state.current_user_email().await;
                crate::audit::log_event(crate::audit::AuditEvent::SessionExpired { email });
                send_notification(
                    "Vouch session expired",
                    "Your session has expired. Run 'vouch login' to re-authenticate.",
                );
            } else {
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

/// Compute which expiry thresholds should fire on a single monitor tick.
///
/// Resets `fired_thresholds` whenever the active session changes — keyed on the
/// session's expiry timestamp, so a new login that replaces an already-expired
/// session (without an intervening logout) re-arms the warnings. Returns the
/// thresholds crossed this tick that have not fired yet — `0` means the session
/// has expired — and marks them fired.
fn thresholds_to_fire(
    tracked_session: &mut Option<Timestamp>,
    fired_thresholds: &mut Vec<u64>,
    session_expiry: Option<Timestamp>,
    remaining_secs: Option<u64>,
) -> Vec<u64> {
    if session_expiry != *tracked_session {
        *tracked_session = session_expiry;
        fired_thresholds.clear();
    }

    let Some(remaining) = remaining_secs else {
        return Vec::new();
    };

    let mut fired_now = Vec::new();

    if remaining == 0 {
        if !fired_thresholds.contains(&0) {
            fired_thresholds.push(0);
            fired_now.push(0);
        }
        return fired_now;
    }

    for &threshold in WARN_THRESHOLDS_SECS {
        if remaining <= threshold && !fired_thresholds.contains(&threshold) {
            fired_thresholds.push(threshold);
            fired_now.push(threshold);
        }
    }

    fired_now
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

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> Timestamp {
        Timestamp::from_second(secs).unwrap()
    }

    #[test]
    fn re_login_re_arms_expiry_warnings() {
        let mut tracked = None;
        let mut fired = Vec::new();

        // Session A expires → the expired threshold fires once.
        assert_eq!(
            thresholds_to_fire(&mut tracked, &mut fired, Some(ts(1000)), Some(0)),
            vec![0]
        );
        // Same expired session next tick → no duplicate.
        assert!(thresholds_to_fire(&mut tracked, &mut fired, Some(ts(1000)), Some(0)).is_empty());

        // A new login replaces the still-stored expired session without ever
        // passing through "no session" — thresholds must reset.
        assert!(
            thresholds_to_fire(&mut tracked, &mut fired, Some(ts(40000)), Some(8 * 3600))
                .is_empty()
        );
        assert!(fired.is_empty(), "thresholds reset on session change");

        // When session B expires, the audit/notification must fire again.
        assert_eq!(
            thresholds_to_fire(&mut tracked, &mut fired, Some(ts(40000)), Some(0)),
            vec![0],
            "expiry must fire for the new session"
        );
    }

    #[test]
    fn warn_thresholds_fire_once_each() {
        let mut tracked = None;
        let mut fired = Vec::new();
        let expiry = Some(ts(99999));

        // 25 minutes left crosses the 30-minute threshold.
        assert_eq!(
            thresholds_to_fire(&mut tracked, &mut fired, expiry, Some(25 * 60)),
            vec![30 * 60]
        );
        // Still 25 minutes → no re-fire.
        assert!(thresholds_to_fire(&mut tracked, &mut fired, expiry, Some(25 * 60)).is_empty());
        // 4 minutes left crosses the 5-minute threshold.
        assert_eq!(
            thresholds_to_fire(&mut tracked, &mut fired, expiry, Some(4 * 60)),
            vec![5 * 60]
        );
    }

    #[test]
    fn no_session_clears_tracking() {
        let mut tracked = Some(ts(1000));
        let mut fired = vec![0_u64];

        assert!(thresholds_to_fire(&mut tracked, &mut fired, None, None).is_empty());
        assert_eq!(tracked, None);
        assert!(fired.is_empty());
    }
}
