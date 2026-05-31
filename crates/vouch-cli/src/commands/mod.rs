// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CLI command implementations.

pub(crate) mod aws;
pub(crate) mod completions;
pub(crate) mod credential;
#[cfg(not(target_os = "windows"))]
pub(crate) mod diag;
pub(crate) mod doctor;
pub(crate) mod enroll;
pub(crate) mod env;
pub(crate) mod exec;
pub(crate) mod init;
pub(crate) mod keys;
pub(crate) mod login;
pub(crate) mod logout;
pub(crate) mod posture;
pub(crate) mod register;
pub(crate) mod setup;
pub(crate) mod status;

/// Credential type to inject into the subprocess environment.
#[derive(Clone, Debug, clap::ValueEnum)]
pub(crate) enum CredentialType {
    /// AWS temporary credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN).
    Aws,
    /// GitHub token (GITHUB_TOKEN, GH_TOKEN).
    Github,
    /// CodeArtifact authorization token (CODEARTIFACT_AUTH_TOKEN).
    Codeartifact,
    /// RDS IAM auth token (PGPASSWORD, PGHOST, PGPORT, PGUSER, PGSSLMODE).
    Rds,
    /// Redshift database credentials (PGPASSWORD, PGUSER, PGSSLMODE).
    Redshift,
    /// Anthropic (Claude) federation token (ANTHROPIC_AUTH_TOKEN).
    ///
    /// Workload path: the minted token acts as a service account, intended
    /// for CI/headless automation, not interactive Claude Code sessions.
    Anthropic,
}
