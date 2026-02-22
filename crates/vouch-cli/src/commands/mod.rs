// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CLI command implementations.

pub mod completions;
pub mod credential;
pub mod diag;
pub mod doctor;
pub mod enroll;
pub mod env;
pub mod exec;
pub mod init;
pub mod keys;
pub mod login;
pub mod logout;
pub mod register;
pub mod setup;
pub mod status;

/// Credential type to inject into the subprocess environment.
#[derive(Clone, Debug, clap::ValueEnum)]
pub enum CredentialType {
    /// AWS temporary credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN).
    Aws,
    /// GitHub token (GITHUB_TOKEN, GH_TOKEN).
    Github,
    /// CodeArtifact authorization token (CODEARTIFACT_AUTH_TOKEN).
    Codeartifact,
}
