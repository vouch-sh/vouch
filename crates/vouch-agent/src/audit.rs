// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Structured audit log for security-relevant agent events.
//!
//! Writes newline-delimited JSON to `$XDG_STATE_HOME/vouch/audit.log`
//! (`~/.local/state/vouch/audit.log` by default). Each line is a
//! self-contained JSON object describing a security-relevant event.
//!
//! This composes with external log aggregation tools (jq, Datadog, Splunk)
//! rather than building an audit UI.

use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use tracing::debug;

/// Maximum audit log file size (10 MB). When exceeded, the log is rotated.
const MAX_LOG_SIZE: u64 = 10 * 1024 * 1024;

/// Security-relevant audit event.
///
/// Each variant corresponds to one event type. Fields are included in the
/// serialized JSON alongside the discriminator `"event"` key, e.g.:
///
/// ```json
/// {"timestamp":"2024-01-15T10:30:00Z","event":"session_stored","email":"user@example.com"}
/// ```
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    /// A new session was stored after successful authentication.
    SessionStored {
        /// User's email address.
        email: String,
    },
    /// The session was explicitly cleared (logout).
    SessionCleared,
    /// The session expired naturally.
    SessionExpired {
        /// User's email (if available at expiry time).
        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<String>,
    },
    /// An SSH certificate was provisioned and stored in the agent.
    SshCertProvisioned {
        /// Path to the SSH private key.
        key_path: String,
        /// Path to the SSH certificate.
        cert_path: String,
    },
    /// An SSH signing operation was performed via the agent.
    SshSigning,
    /// A non-SSH credential was cached (AWS, GitHub, etc.).
    CredentialCached {
        /// The credential type key (e.g., "aws:arn:...", "github").
        credential_type: String,
    },
    /// All cached credentials were cleared.
    CredentialCacheCleared,
    /// An IPC connection was rejected due to peer credential mismatch.
    ConnectionRejected {
        /// UID of the rejected peer.
        peer_uid: u32,
        /// PID of the rejected peer (0 if unavailable).
        peer_pid: u32,
        /// Reason for rejection.
        reason: String,
    },
}

/// Wrapper that adds a timestamp to every audit record.
#[derive(Serialize)]
struct AuditRecord {
    /// ISO 8601 timestamp.
    timestamp: String,
    /// The event (flattened so its fields appear at the top level).
    #[serde(flatten)]
    event: AuditEvent,
}

/// Log a security-relevant audit event to the audit log
/// (`$XDG_STATE_HOME/vouch/audit.log`).
///
/// Best-effort: failures are logged at debug level and never block the agent.
pub(crate) fn log_event(event: AuditEvent) {
    let record = AuditRecord {
        timestamp: jiff::Timestamp::now().to_string(),
        event,
    };

    if let Err(e) = write_event(&record) {
        debug!("Failed to write audit event: {e}");
    }
}

/// Resolve the audit log path (`$XDG_STATE_HOME/vouch/audit.log`).
fn audit_log_path() -> std::io::Result<PathBuf> {
    vouch_common::paths::audit_log_file()
        .ok_or_else(|| std::io::Error::other("cannot determine state directory"))
}

/// Write a single audit event to the log file.
fn write_event(record: &AuditRecord) -> std::io::Result<()> {
    let log_path = audit_log_path()?;
    let dir = log_path
        .parent()
        .ok_or_else(|| std::io::Error::other("audit log path has no parent"))?;

    // Ensure the state directory exists with owner-only permissions.
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _chmod = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }

    // Rotate if file exceeds max size
    if let Ok(metadata) = std::fs::metadata(&log_path)
        && metadata.len() > MAX_LOG_SIZE
    {
        let rotated = dir.join("audit.log.1");
        // Best-effort rotation; failure is non-fatal and is shadowed by the next write.
        let _rotated = std::fs::rename(&log_path, &rotated);
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    // Set file permissions to 0600 (owner-only) on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best-effort tightening; if it fails the log still gets written.
        let _chmod = std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o600));
    }

    let json = serde_json::to_string(record)
        .map_err(|e| std::io::Error::other(format!("cannot serialize audit event: {e}")))?;

    writeln!(file, "{json}")?;

    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_session_stored_serialization() {
        let record = AuditRecord {
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            event: AuditEvent::SessionStored {
                email: "user@example.com".to_string(),
            },
        };

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"event\":\"session_stored\""));
        assert!(json.contains("\"email\":\"user@example.com\""));
        assert!(json.contains("\"timestamp\":\"2024-01-15T10:30:00Z\""));
    }

    #[test]
    fn test_audit_event_session_cleared_serialization() {
        let record = AuditRecord {
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            event: AuditEvent::SessionCleared,
        };

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"event\":\"session_cleared\""));
        // No extra fields beyond timestamp and event
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.as_object().unwrap().len(), 2);
    }

    #[test]
    fn test_audit_event_credential_cached_serialization() {
        let record = AuditRecord {
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            event: AuditEvent::CredentialCached {
                credential_type: "aws:arn:aws:iam::123456:role/dev".to_string(),
            },
        };

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"event\":\"credential_cached\""));
        assert!(json.contains("\"credential_type\":\"aws:arn:aws:iam::123456:role/dev\""));
    }

    #[test]
    fn test_audit_event_session_expired_without_email() {
        let record = AuditRecord {
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            event: AuditEvent::SessionExpired { email: None },
        };

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"event\":\"session_expired\""));
        assert!(!json.contains("\"email\""));
    }

    #[test]
    fn test_audit_event_ssh_cert_provisioned_serialization() {
        let record = AuditRecord {
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            event: AuditEvent::SshCertProvisioned {
                key_path: "/home/user/.ssh/id_ed25519_vouch".to_string(),
                cert_path: "/home/user/.ssh/id_ed25519_vouch-cert.pub".to_string(),
            },
        };

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"event\":\"ssh_cert_provisioned\""));
        assert!(json.contains("\"key_path\""));
        assert!(json.contains("\"cert_path\""));
    }
}
