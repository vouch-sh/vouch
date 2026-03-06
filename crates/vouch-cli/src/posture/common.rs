// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cross-platform posture detection.

use std::process::Command;

use vouch_common::posture::DevicePosture;

/// Detect execution context, setting flat fields directly.
pub fn detect(posture: &mut DevicePosture) {
    posture.elevated = Some(detect_elevated());
    posture.tty = Some(std::io::IsTerminal::is_terminal(&std::io::stdin()));
    posture.parent_process = detect_parent_process();
}

/// Check whether the CLI is running with elevated privileges.
#[cfg(unix)]
fn detect_elevated() -> bool {
    // SAFETY: geteuid() is always safe to call.
    #[allow(unsafe_code)]
    unsafe {
        libc::geteuid() == 0
    }
}

#[cfg(not(unix))]
fn detect_elevated() -> bool {
    false
}

/// Extract PPID from `/proc/self/stat` content.
///
/// Format: `pid (comm) state ppid ...`
/// The comm field may contain spaces and parens, so we find the last `)`.
#[cfg(target_os = "linux")]
fn parse_ppid_from_proc_stat(stat: &str) -> Option<String> {
    let after_comm = stat.rfind(')')?;
    let rest = stat.get(after_comm + 2..)?;
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?;
    let ppid = fields.next()?;
    Some(ppid.to_string())
}

/// Get the name of the parent process.
#[cfg(target_os = "linux")]
fn detect_parent_process() -> Option<String> {
    let ppid = std::env::var("PPID")
        .ok()
        .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
        .or_else(|| {
            let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
            parse_ppid_from_proc_stat(&stat)
        })?;

    // Read /proc/{ppid}/comm
    let comm_path = format!("/proc/{ppid}/comm");
    std::fs::read_to_string(comm_path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "macos")]
fn detect_parent_process() -> Option<String> {
    // On macOS, use ps to get parent process name
    let ppid = std::os::unix::process::parent_id();
    let output = std::process::Command::new("ps")
        .args(["-p", &ppid.to_string(), "-o", "comm="])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
    // ps may return full path; extract basename
    name.rsplit('/')
        .next()
        .map(String::from)
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "windows")]
fn detect_parent_process() -> Option<String> {
    None
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn detect_parent_process() -> Option<String> {
    None
}

/// Run a command and capture stdout. Returns `None` on any failure.
pub fn run_command(program: &str, args: &[&str]) -> Option<String> {
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::parse_ppid_from_proc_stat;

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_ppid_from_proc_stat_normal() {
        let stat = "1234 (bash) S 1111 1234 1234 0 -1 4194304";
        assert_eq!(parse_ppid_from_proc_stat(stat).as_deref(), Some("1111"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_ppid_from_proc_stat_comm_with_spaces() {
        // comm can contain spaces and parens
        let stat = "5678 (Web Content (pid 42)) S 9999 5678 5678 0 -1 0";
        assert_eq!(parse_ppid_from_proc_stat(stat).as_deref(), Some("9999"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_ppid_from_proc_stat_empty() {
        assert_eq!(parse_ppid_from_proc_stat(""), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_ppid_from_proc_stat_no_closing_paren() {
        assert_eq!(parse_ppid_from_proc_stat("1234 (bash"), None);
    }
}
