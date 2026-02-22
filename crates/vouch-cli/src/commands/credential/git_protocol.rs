// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Git credential protocol parsing.
//!
//! Shared types and functions for parsing the git credential helper protocol,
//! used by both the GitHub and CodeCommit credential helpers.
//!
//! See: <https://git-scm.com/docs/git-credential#IOFMT>

use anyhow::{Context, Result};
use std::io::{BufRead, Write};

/// Git credential protocol input.
#[derive(Debug, Default)]
pub struct CredentialInput {
    pub protocol: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
}

/// Parse git credential protocol input from stdin.
///
/// Reads key=value pairs until an empty line or EOF.
pub fn read_credential_input() -> Result<CredentialInput> {
    let stdin = std::io::stdin();
    let mut input = CredentialInput::default();

    for line in stdin.lock().lines() {
        let line = line.context("failed to read stdin")?;
        if line.is_empty() {
            break;
        }

        if let Some((key, value)) = line.split_once('=') {
            match key {
                "protocol" => input.protocol = Some(value.to_string()),
                "host" => input.host = Some(value.to_string()),
                "path" => input.path = Some(value.to_string()),
                _ => {} // Ignore other fields
            }
        }
    }

    Ok(input)
}

/// Write git credential protocol output.
///
/// Outputs `key=value` pairs followed by a blank line, as required by
/// the [git credential protocol](https://git-scm.com/docs/git-credential#IOFMT).
pub fn write_credential_output(
    out: &mut impl Write,
    protocol: &str,
    host: &str,
    username: &str,
    password: &str,
) -> Result<()> {
    writeln!(out, "protocol={protocol}")?;
    writeln!(out, "host={host}")?;
    writeln!(out, "username={username}")?;
    writeln!(out, "password={password}")?;
    writeln!(out)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Verify the git credential helper output matches the protocol format.
    /// See: https://git-scm.com/docs/git-credential#IOFMT
    #[test]
    fn test_write_credential_output_format() {
        let mut buf = Vec::new();
        write_credential_output(
            &mut buf,
            "https",
            "github.com",
            "x-access-token",
            "ghu_example",
        )
        .expect("write should succeed");

        let output = String::from_utf8(buf).expect("valid UTF-8");
        // Git credential protocol: key=value lines terminated by a blank line
        assert_eq!(
            output,
            "protocol=https\n\
             host=github.com\n\
             username=x-access-token\n\
             password=ghu_example\n\
             \n"
        );
    }

    /// Verify CodeCommit-style credentials with SigV4-signed values.
    #[test]
    fn test_write_credential_output_codecommit() {
        let mut buf = Vec::new();
        write_credential_output(
            &mut buf,
            "https",
            "git-codecommit.us-east-1.amazonaws.com",
            "AKIAEXAMPLE%FwoGZXIv...",
            "20240114T100000Zabc123def456",
        )
        .expect("write should succeed");

        let output = String::from_utf8(buf).expect("valid UTF-8");
        assert!(output.starts_with("protocol=https\n"));
        assert!(output.contains("host=git-codecommit.us-east-1.amazonaws.com\n"));
        assert!(output.contains("username=AKIAEXAMPLE%FwoGZXIv...\n"));
        assert!(output.contains("password=20240114T100000Zabc123def456\n"));
    }
}
