// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Git credential protocol parsing.
//!
//! Shared types and functions for parsing the git credential helper protocol,
//! used by both the GitHub and CodeCommit credential helpers.
//!
//! See: <https://git-scm.com/docs/git-credential#IOFMT>

use anyhow::{Context, Result};
use std::io::BufRead;

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
