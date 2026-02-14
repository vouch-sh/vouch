// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Structured audit log for security-relevant agent events.
//!
//! Writes newline-delimited JSON to `~/.vouch/audit.log`. Each line is a
//! self-contained JSON object describing a security-relevant event.
//!
//! This composes with external log aggregation tools (jq, Datadog, Splunk)
//! rather than building an audit UI.

use serde::Serialize;
use std::io::Write;
use tracing::debug;

use crate::socket::vouch_dir;

/// Security-relevant audit event.
#[derive(Debug, Serialize)]
pub struct AuditEvent {
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Event type identifier.
    pub event: &'static str,
    /// Additional event-specific details.
    #[serde(flatten)]
    pub details: serde_json::Value,
}

/// Audit event types.
pub mod events {
    pub const SESSION_STORED: &str = "session_stored";
    pub const SESSION_CLEARED: &str = "session_cleared";
    pub const SESSION_EXPIRED: &str = "session_expired";
    pub const SSH_CERT_PROVISIONED: &str = "ssh_cert_provisioned";
    pub const SSH_SIGNING: &str = "ssh_signing";
    pub const CREDENTIAL_CACHED: &str = "credential_cached";
    pub const CREDENTIAL_CACHE_CLEARED: &str = "credential_cache_cleared";
}

/// Log a security-relevant audit event to `~/.vouch/audit.log`.
///
/// Best-effort: failures are logged at debug level and never block the agent.
pub fn log_event(event: &'static str, details: serde_json::Value) {
    let audit_event = AuditEvent {
        timestamp: jiff::Timestamp::now().to_string(),
        event,
        details,
    };

    if let Err(e) = write_event(&audit_event) {
        debug!("Failed to write audit event: {e}");
    }
}

/// Write a single audit event to the log file.
fn write_event(event: &AuditEvent) -> std::io::Result<()> {
    let dir = vouch_dir()
        .map_err(|e| std::io::Error::other(format!("cannot determine vouch dir: {e}")))?;

    let log_path = dir.join("audit.log");

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;

    let json = serde_json::to_string(event)
        .map_err(|e| std::io::Error::other(format!("cannot serialize audit event: {e}")))?;

    writeln!(file, "{json}")?;

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent {
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            event: events::SESSION_STORED,
            details: serde_json::json!({"email": "user@example.com"}),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event\":\"session_stored\""));
        assert!(json.contains("\"email\":\"user@example.com\""));
        assert!(json.contains("\"timestamp\":\"2024-01-15T10:30:00Z\""));
    }

    #[test]
    fn test_audit_event_empty_details() {
        let event = AuditEvent {
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            event: events::SESSION_CLEARED,
            details: serde_json::json!({}),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event\":\"session_cleared\""));
    }
}
