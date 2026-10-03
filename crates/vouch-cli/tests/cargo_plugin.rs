// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch --cargo-plugin`: the way Cargo launches a credential provider.
//!
//! Cargo runs `<credential-provider[0]> --cargo-plugin` and speaks the JSON
//! protocol on stdin/stdout:
//! https://doc.rust-lang.org/cargo/reference/credential-provider-protocol.html

#![expect(clippy::unwrap_used, reason = "test code")]

use std::io::Write;
use std::process::{Command, Stdio};

/// Run the plugin with an isolated home; `vouch_config` is written as the Vouch
/// `config.json` when given.
fn run_plugin(stdin: &str, vouch_config: Option<&str>) -> std::process::Output {
    let home = tempfile::tempdir().unwrap();
    if let Some(vouch_config) = vouch_config {
        let dir = home.path().join("config").join("vouch");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.json"), vouch_config).unwrap();
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_vouch"))
        .arg("--cargo-plugin")
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_DATA_HOME", home.path().join("data"))
        .env("XDG_CACHE_HOME", home.path().join("cache"))
        .env("XDG_STATE_HOME", home.path().join("state"))
        .env_remove("XDG_RUNTIME_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn crates_io_is_not_supported() {
    let request = concat!(
        r#"{"v":1,"registry":{"index-url":"sparse+https://index.crates.io/","name":"crates-io"},"#,
        r#""kind":"get","operation":"read","args":["credential","cargo","--"]}"#,
        "\n"
    );

    let output = run_plugin(request, None);

    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "{\"v\":[1]}\n{\"Err\":{\"kind\":\"url-not-supported\"}}\n"
    );
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn malformed_request_reports_an_error_to_cargo() {
    let output = run_plugin("not json\n", None);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();
    assert_eq!(lines.next(), Some(r#"{"v":[1]}"#));
    assert!(
        lines
            .next()
            .is_some_and(|l| l.starts_with(r#"{"Err":{"kind":"other","message":""#)),
        "{stdout}"
    );
    // Cargo reads the response line, then waits for the child and replaces the
    // response with "credential process failed with status N" on a nonzero
    // exit (src/cargo/util/credential/process.rs in the Cargo repository), so
    // an `Err` response must come with exit 0.
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn served_registry_without_a_session_reports_not_enrolled() {
    let config =
        r#"{"cargo":{"registries":{"sparse+https://crates.example.com/":"crates-example"}}}"#;
    let request = concat!(
        r#"{"v":1,"registry":{"index-url":"sparse+https://crates.example.com/"},"#,
        r#""kind":"get","operation":"read"}"#,
        "\n"
    );

    let output = run_plugin(request, Some(config));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();
    assert_eq!(lines.next(), Some(r#"{"v":[1]}"#));
    let response = lines.next().unwrap();
    assert!(
        response.starts_with(r#"{"Err":{"kind":"other","message":""#)
            && response.contains("enroll"),
        "{stdout}"
    );
    assert_eq!(output.status.code(), Some(0));
}
