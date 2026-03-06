// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cross-platform posture detection.

use vouch_common::posture::DevicePosture;

/// Detect SSH session and execution context, setting flat fields directly.
pub fn detect(posture: &mut DevicePosture) {
    // SSH session
    let ssh_connection = std::env::var("SSH_CONNECTION").ok();
    let ssh_client = std::env::var("SSH_CLIENT").ok();
    let ssh_tty = std::env::var("SSH_TTY").ok();

    let detected = ssh_connection.is_some() || ssh_client.is_some() || ssh_tty.is_some();
    posture.ssh_session_detected = Some(detected);

    // SSH_CONNECTION format: "client_ip client_port server_ip server_port"
    posture.ssh_client_ip = ssh_connection
        .as_deref()
        .and_then(|s| s.split_whitespace().next())
        .map(String::from);

    // Execution context
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

/// Get the name of the parent process.
#[cfg(target_os = "linux")]
fn detect_parent_process() -> Option<String> {
    let ppid = std::env::var("PPID").ok().or_else(|| {
        // Read /proc/self/stat to get ppid (field 4)
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        // Format: pid (comm) state ppid ...
        // Find closing paren, then skip state, get ppid
        let after_comm = stat.rfind(')')?;
        let rest = stat.get(after_comm + 2..)?;
        let mut fields = rest.split_whitespace();
        let _state = fields.next()?;
        let ppid = fields.next()?;
        Some(ppid.to_string())
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
    name.rsplit('/').next().map(String::from).filter(|s| !s.is_empty())
}

#[cfg(target_os = "windows")]
fn detect_parent_process() -> Option<String> {
    None
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn detect_parent_process() -> Option<String> {
    None
}
