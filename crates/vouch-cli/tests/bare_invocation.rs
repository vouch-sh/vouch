// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bare `vouch` invocation: help is printed on every platform; the exit code
//! is 0 on Windows (the winget validation pipeline runs the portable exe with
//! no arguments and flags nonzero codes) and clap's usage-error code 2 on Unix.

#![expect(clippy::unwrap_used, reason = "test code")]

#[test]
fn bare_invocation_prints_help_with_platform_exit_code() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vouch"))
        .output()
        .unwrap();

    let expected = if cfg!(windows) { Some(0) } else { Some(2) };
    assert_eq!(output.status.code(), expected);

    let combined = [output.stdout, output.stderr].concat();
    let text = String::from_utf8_lossy(&combined);
    assert!(text.contains("Usage:"), "expected help output, got: {text}");
}
