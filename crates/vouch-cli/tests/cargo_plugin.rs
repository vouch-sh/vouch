// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `vouch --cargo-plugin`: the way Cargo launches a credential provider.
//!
//! Cargo runs `<credential-provider[0]> --cargo-plugin` with no other argv,
//! reads the hello line, writes one request line, reads one `Ok`/`Err`
//! response line, and treats a nonzero exit as a failure that replaces the
//! response:
//! <https://doc.rust-lang.org/cargo/reference/credential-provider-protocol.html>
//! (`src/cargo/util/credential/process.rs` in the Cargo source).
//!
//! These tests drive the real binary the same way, with an isolated home so no
//! session, agent, or config exists and nothing touches the network.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use tempfile::TempDir;

const CODEARTIFACT_INDEX: &str =
    "sparse+https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/cargo/my-repo/";

struct PluginRun {
    status_code: Option<i32>,
    stdout_lines: Vec<Value>,
}

impl PluginRun {
    /// The response line after the hello.
    fn response(&self) -> &Value {
        assert_eq!(self.stdout_lines.len(), 2, "{:?}", self.stdout_lines);
        self.stdout_lines.last().unwrap()
    }
}

/// Launch `vouch --cargo-plugin` and feed it one request line, as Cargo does,
/// then parse each stdout line as JSON.
fn run_plugin(request_line: &str) -> PluginRun {
    run_plugin_raw(&format!("{request_line}\n"), None)
}

/// Like [`run_plugin`], with `config_json` written as the Vouch `config.json`.
fn run_plugin_with_config(request_line: &str, config_json: &str) -> PluginRun {
    run_plugin_raw(&format!("{request_line}\n"), Some(config_json))
}

/// What the plugin's stdin is connected to.
enum PluginStdin<'a> {
    /// A pipe that receives these bytes verbatim, then closes.
    Bytes(&'a [u8]),
    /// A directory, so every read fails with an I/O error.
    Unreadable,
}

fn run_plugin_raw(stdin: &str, config_json: Option<&str>) -> PluginRun {
    run_plugin_on(PluginStdin::Bytes(stdin.as_bytes()), config_json)
}

/// Launch `vouch --cargo-plugin` with the given stdin.
fn run_plugin_on(stdin: PluginStdin<'_>, config_json: Option<&str>) -> PluginRun {
    let dir: TempDir = tempfile::tempdir().unwrap();
    if let Some(config_json) = config_json {
        let vouch_dir = dir.path().join("config").join("vouch");
        std::fs::create_dir_all(&vouch_dir).unwrap();
        std::fs::write(vouch_dir.join("config.json"), config_json).unwrap();
    }
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_vouch"))
        .arg("--cargo-plugin")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .env("XDG_CACHE_HOME", dir.path().join("cache"))
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("XDG_RUNTIME_DIR", dir.path().join("run"))
        .env_remove("VOUCH_SERVER")
        .env_remove("VOUCH_ALLOW_INSECURE")
        .env_remove("VOUCH_TOKEN")
        .stdin(match stdin {
            PluginStdin::Bytes(_) => Stdio::piped(),
            PluginStdin::Unreadable => Stdio::from(std::fs::File::open(dir.path()).unwrap()),
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    if let PluginStdin::Bytes(bytes) = stdin {
        let mut child_stdin = child.stdin.take().unwrap();
        child_stdin.write_all(bytes).unwrap();
        // Cargo closes the pipe after reading the response.
        drop(child_stdin);
    }

    let output = child.wait_with_output().unwrap();
    let stdout_lines = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    PluginRun {
        status_code: output.status.code(),
        stdout_lines,
    }
}

fn request(kind_fields: &Value, index_url: &str) -> String {
    let mut request = json!({
        "v": 1,
        "registry": {"index-url": index_url, "name": "my-registry"},
        "args": [],
    });
    request
        .as_object_mut()
        .unwrap()
        .extend(kind_fields.as_object().unwrap().clone());
    request.to_string()
}

// Credential provider protocol, "Credential hello".
#[test]
fn hello_offers_protocol_version_1() {
    let run = run_plugin(&request(
        &json!({"kind": "get", "operation": "read"}),
        "sparse+https://index.crates.io/",
    ));
    assert_eq!(run.stdout_lines.first(), Some(&json!({"v": [1]})));
}

// Credential provider protocol, "Failure response (URL not supported)": a
// registry the provider does not serve gets `url-not-supported` so Cargo tries
// its next provider, and the Vouch session token is never returned.
#[test]
fn non_codeartifact_registry_is_url_not_supported() {
    let run = run_plugin(&request(
        &json!({"kind": "get", "operation": "read"}),
        "sparse+https://registry-url/index/",
    ));
    assert_eq!(
        run.response(),
        &json!({"Err": {"kind": "url-not-supported"}})
    );
    assert_eq!(run.status_code, Some(0));
}

// Credential provider protocol, "Failure response (URL not supported)": a
// provider designed for specific registries answers every action for any other
// registry with `url-not-supported`, so Cargo tries its next provider.
#[test]
fn every_action_on_unserved_registry_is_url_not_supported() {
    for kind_fields in [
        json!({"kind": "get", "operation": "publish", "name": "sample", "vers": "0.1.0", "cksum": "..."}),
        json!({"kind": "login", "token": "<the token value>", "login-url": "http://registry-url/login"}),
        json!({"kind": "logout"}),
        json!({"kind": "unexpected"}),
    ] {
        let run = run_plugin(&request(&kind_fields, "https://example.com/index"));
        assert_eq!(
            run.response(),
            &json!({"Err": {"kind": "url-not-supported"}}),
            "{kind_fields}"
        );
        assert_eq!(run.status_code, Some(0), "{kind_fields}");
    }
}

// Credential provider protocol, "Failure response (operation not supported)".
#[test]
fn login_on_codeartifact_is_operation_not_supported() {
    let run = run_plugin(&request(
        &json!({"kind": "login", "login-url": "http://registry-url/login"}),
        CODEARTIFACT_INDEX,
    ));
    assert_eq!(
        run.response(),
        &json!({"Err": {"kind": "operation-not-supported"}})
    );
    assert_eq!(run.status_code, Some(0));
}

// cargo-credential's `Operation` has `#[serde(other)] Unknown`; Credential
// provider protocol, "Failure response (operation not supported)".
#[test]
fn unknown_operation_on_codeartifact_is_operation_not_supported() {
    let run = run_plugin(&request(
        &json!({"kind": "get", "operation": "frobnicate"}),
        CODEARTIFACT_INDEX,
    ));
    assert_eq!(
        run.response(),
        &json!({"Err": {"kind": "operation-not-supported"}})
    );
    assert_eq!(run.status_code, Some(0));
}

// Credential provider protocol, "Logout success response".
#[test]
fn logout_on_codeartifact_is_wrapped_ok() {
    let run = run_plugin(&request(&json!({"kind": "logout"}), CODEARTIFACT_INDEX));
    assert_eq!(run.response(), &json!({"Ok": {"kind": "logout"}}));
    assert_eq!(run.status_code, Some(0));
}

// Credential provider protocol, "Failure response (other)": each session
// error reaches the user with its own message, since Cargo drops the message of
// `not-found`. Nothing is configured, so the user is told to enroll.
#[test]
fn get_without_config_says_to_enroll() {
    let run = run_plugin(&request(
        &json!({"kind": "get", "operation": "read"}),
        CODEARTIFACT_INDEX,
    ));
    assert_eq!(
        run.response().pointer("/Err/message"),
        Some(&json!("not configured — run 'vouch enroll' first"))
    );
    assert_eq!(run.response().pointer("/Err/kind"), Some(&json!("other")));
    assert_eq!(run.status_code, Some(0));
}

// A configured server with no session token tells the user to log in, not to
// enroll again.
#[test]
fn get_without_a_session_token_says_to_log_in() {
    let run = run_plugin_with_config(
        &request(
            &json!({"kind": "get", "operation": "read"}),
            CODEARTIFACT_INDEX,
        ),
        r#"{"server_url":"https://vouch.example.com"}"#,
    );
    assert_eq!(
        run.response().pointer("/Err/message"),
        Some(&json!(
            "no session token — run 'vouch login' to authenticate"
        ))
    );
    assert_eq!(run.response().pointer("/Err/kind"), Some(&json!("other")));
    assert_eq!(run.status_code, Some(0));
}

// Cargo sends credentials to `sparse+http` registries, and a token minted for
// a plain-HTTP index would travel in the clear, so it is not served.
#[test]
fn plain_http_codeartifact_host_is_url_not_supported() {
    let run = run_plugin(&request(
        &json!({"kind": "get", "operation": "read"}),
        "sparse+http://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/cargo/r/",
    ));
    assert_eq!(
        run.response(),
        &json!({"Err": {"kind": "url-not-supported"}})
    );
    assert_eq!(run.status_code, Some(0));
}

// Cargo reads `https://http://<host>/…` as host `http`, so the token would go
// somewhere other than the CodeArtifact host named in the path. Credential
// provider protocol, "Failure response (URL not supported)".
#[test]
fn double_scheme_codeartifact_url_is_url_not_supported() {
    for index in [
        "sparse+https://http://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/cargo/r/",
        "https://http://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/cargo/r/",
    ] {
        let run = run_plugin(&request(
            &json!({"kind": "get", "operation": "read"}),
            index,
        ));
        assert_eq!(
            run.response(),
            &json!({"Err": {"kind": "url-not-supported"}}),
            "{index}"
        );
        assert_eq!(run.status_code, Some(0), "{index}");
    }
}

// Cargo (`process.rs`) reads exactly one response line per request, so a
// request that never arrives still gets an `Err` line and exit 0.
#[test]
fn stdin_eof_without_a_line_is_other_and_exits_zero() {
    let run = run_plugin_raw("", None);
    let error = &run.response()["Err"];
    assert_eq!(error["kind"], "other");
    assert_eq!(error["message"], "failed to parse credential request");
    assert_eq!(run.status_code, Some(0));
}

// Bytes that are not UTF-8 make the line read fail; that is still answered
// with an `Err` line and exit 0.
#[test]
fn invalid_utf8_on_stdin_is_other_and_exits_zero() {
    let run = run_plugin_on(PluginStdin::Bytes(b"\xff\xfe\n"), None);
    let error = &run.response()["Err"];
    assert_eq!(error["kind"], "other");
    assert_eq!(error["message"], "failed to read from stdin");
    assert_eq!(run.status_code, Some(0));
}

// A stdin that cannot be read is still answered with an `Err` line and exit 0.
#[test]
fn unreadable_stdin_is_other_and_exits_zero() {
    let run = run_plugin_on(PluginStdin::Unreadable, None);
    let error = &run.response()["Err"];
    assert_eq!(error["kind"], "other");
    assert_eq!(error["message"], "failed to read from stdin");
    assert_eq!(run.status_code, Some(0));
}

// An argv that is not UTF-8 must reach clap's error path, not a panic in the
// `--cargo-plugin` check that runs on every invocation.
#[test]
fn non_utf8_first_argument_does_not_panic() {
    use std::os::unix::ffi::OsStrExt;
    let output = Command::new(env!("CARGO_BIN_EXE_vouch"))
        .arg(std::ffi::OsStr::from_bytes(b"\xff"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert_ne!(output.status.code(), Some(101));
}

// A host that only looks like CodeArtifact is not served, so no CodeArtifact
// token is minted for it.
#[test]
fn lookalike_codeartifact_host_is_url_not_supported() {
    let run = run_plugin(&request(
        &json!({"kind": "get", "operation": "read"}),
        "sparse+https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.evil.com/cargo/r/",
    ));
    assert_eq!(
        run.response(),
        &json!({"Err": {"kind": "url-not-supported"}})
    );
    assert_eq!(run.status_code, Some(0));
}

// Cargo's `process.rs` replaces a response with "credential process failed
// with status N" on a nonzero exit, so an unparseable request is still
// answered with an `Err` line and exit 0.
#[test]
fn malformed_request_is_other_and_exits_zero() {
    let run = run_plugin("this is not json");
    let error = &run.response()["Err"];
    assert_eq!(error["kind"], "other");
    assert_eq!(error["message"], "failed to parse credential request");
    assert!(
        error["caused-by"]
            .as_array()
            .is_some_and(|causes| !causes.is_empty()),
        "{error}"
    );
    assert_eq!(run.status_code, Some(0));
}

// cargo-credential's `CredentialRequest` requires `kind` (the flattened
// `Action` tag); a request without it still gets an `Err` line and exit 0,
// since Cargo's `process.rs` drops a response on a nonzero exit.
#[test]
fn request_without_kind_is_other_and_exits_zero() {
    let run = run_plugin(r#"{"v":1,"registry":{"index-url":"url"}}"#);
    assert_eq!(run.response().pointer("/Err/kind"), Some(&json!("other")));
    assert_eq!(run.status_code, Some(0));
}

// cargo-credential's `deserialize_request` rejects other protocol versions;
// the error is still an `Err` line with exit 0 (`process.rs` drops a response
// on a nonzero exit).
#[test]
fn unsupported_protocol_version_is_other_and_exits_zero() {
    let run =
        run_plugin(r#"{"v":999,"registry":{"index-url":"url"},"args":[],"kind":"unexpected"}"#);
    let error = &run.response()["Err"];
    assert_eq!(error["kind"], "other");
    assert_eq!(
        error["message"],
        "unsupported protocol version 999, expected 1"
    );
    assert_eq!(run.status_code, Some(0));
}
