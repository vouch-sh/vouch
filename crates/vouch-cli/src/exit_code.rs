// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Structured exit codes for the Vouch CLI.
//!
//! These exit codes allow scripts and `credential_process` consumers to
//! distinguish between different failure modes without parsing error messages.

use std::process::ExitCode;

/// General or unknown error.
pub const GENERAL: u8 = 1;

/// Not authenticated (session expired or missing).
pub const NOT_AUTHENTICATED: u8 = 2;

/// Hardware key not detected (YubiKey missing or timed out).
pub const HARDWARE_NOT_FOUND: u8 = 3;

/// Network or server unreachable.
pub const NETWORK_ERROR: u8 = 4;

/// Permission denied or unauthorized by server.
pub const PERMISSION_DENIED: u8 = 5;

/// Configuration error (missing or invalid config).
pub const CONFIG_ERROR: u8 = 6;

/// Classify an `anyhow::Error` into an appropriate exit code.
///
/// Inspects the error chain for known types (`AgentError`, `reqwest::Error`)
/// and falls back to message-pattern matching for errors wrapped by `anyhow`.
pub fn classify(err: &anyhow::Error) -> ExitCode {
    // Check for agent-specific error types in the chain
    #[cfg(unix)]
    if let Some(agent_err) = err.downcast_ref::<vouch_agent::AgentError>() {
        return match agent_err {
            vouch_agent::AgentError::SessionExpired | vouch_agent::AgentError::NotAuthenticated => {
                ExitCode::from(NOT_AUTHENTICATED)
            }
            vouch_agent::AgentError::NotRunning | vouch_agent::AgentError::Connection(_) => {
                ExitCode::from(CONFIG_ERROR)
            }
            _ => ExitCode::from(GENERAL),
        };
    }

    // Check for reqwest errors (network / HTTP)
    if let Some(reqwest_err) = err.downcast_ref::<reqwest::Error>() {
        if reqwest_err.is_connect() || reqwest_err.is_timeout() {
            return ExitCode::from(NETWORK_ERROR);
        }
        if let Some(status) = reqwest_err.status()
            && (status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN)
        {
            return ExitCode::from(PERMISSION_DENIED);
        }
    }

    // Fall back to message-based classification for anyhow-wrapped errors
    let msg = format!("{err:#}");
    classify_message(&msg)
}

/// Classify based on the rendered error message string.
fn classify_message(msg: &str) -> ExitCode {
    let lower = msg.to_lowercase();

    // Authentication / session errors
    if lower.contains("not authenticated")
        || lower.contains("session expired")
        || lower.contains("session has expired")
        || lower.contains("run 'vouch login'")
        || lower.contains("run `vouch login`")
        || lower.contains("run: vouch login")
    {
        return ExitCode::from(NOT_AUTHENTICATED);
    }

    // Hardware key errors
    if (lower.contains("yubikey") || lower.contains("fido2") || lower.contains("fido"))
        && (lower.contains("not found")
            || lower.contains("not detected")
            || lower.contains("timed out")
            || lower.contains("insert"))
    {
        return ExitCode::from(HARDWARE_NOT_FOUND);
    }

    // Network errors
    if lower.contains("failed to connect")
        || lower.contains("server unreachable")
        || lower.contains("connection refused")
        || lower.contains("dns error")
        || lower.contains("network")
    {
        return ExitCode::from(NETWORK_ERROR);
    }

    // Permission errors
    if lower.contains("permission denied") || lower.contains("unauthorized") {
        return ExitCode::from(PERMISSION_DENIED);
    }

    // Config errors
    if lower.contains("no config found")
        || lower.contains("invalid server url")
        || lower.contains("configuration error")
    {
        return ExitCode::from(CONFIG_ERROR);
    }

    ExitCode::from(GENERAL)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn code_value(exit: ExitCode) -> u8 {
        // ExitCode doesn't expose its value directly, so extract from Debug repr.
        // Format varies by Rust version, e.g. "ExitCode(unix_exit_status(2))".
        // We extract the last contiguous run of digits from the string.
        let debug = format!("{exit:?}");
        let mut end = debug.len();
        // Skip trailing non-digit chars
        while end > 0
            && !debug
                .as_bytes()
                .get(end - 1)
                .is_some_and(|b| b.is_ascii_digit())
        {
            end -= 1;
        }
        let mut start = end;
        while start > 0
            && debug
                .as_bytes()
                .get(start - 1)
                .is_some_and(|b| b.is_ascii_digit())
        {
            start -= 1;
        }
        debug
            .get(start..end)
            .and_then(|s| s.parse().ok())
            .unwrap_or(255)
    }

    #[test]
    fn test_classify_auth_errors() {
        assert_eq!(
            code_value(classify_message(
                "not authenticated - run 'vouch login' first"
            )),
            NOT_AUTHENTICATED
        );
        assert_eq!(
            code_value(classify_message("Session expired. Run: vouch login")),
            NOT_AUTHENTICATED
        );
    }

    #[test]
    fn test_classify_hardware_errors() {
        assert_eq!(
            code_value(classify_message(
                "Timed out waiting for YubiKey. Insert your key and try again."
            )),
            HARDWARE_NOT_FOUND
        );
        assert_eq!(
            code_value(classify_message(
                "no YubiKey found - please insert your YubiKey"
            )),
            HARDWARE_NOT_FOUND
        );
    }

    #[test]
    fn test_classify_network_errors() {
        assert_eq!(
            code_value(classify_message("failed to connect to https://example.com")),
            NETWORK_ERROR
        );
    }

    #[test]
    fn test_classify_general_errors() {
        assert_eq!(
            code_value(classify_message("some unknown error happened")),
            GENERAL
        );
    }
}
