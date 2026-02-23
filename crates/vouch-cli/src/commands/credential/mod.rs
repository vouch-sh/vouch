// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Credential issuance commands.

use clap::Subcommand;

pub mod aws;
pub(crate) mod cache;
pub mod cargo;
pub mod codeartifact;
pub mod codecommit;
pub mod docker;
pub mod git_protocol;
pub mod github;
pub mod pip;

pub mod ssh;

/// Credential subcommands.
#[derive(Subcommand)]
pub enum CredentialCommands {
    /// Obtain temporary AWS credentials.
    Aws {
        /// AWS IAM role ARN to assume.
        #[arg(long)]
        role: String,
        /// Session name for the assumed role.
        #[arg(long)]
        session_name: Option<String>,
    },
    /// Obtain an SSH certificate.
    Ssh {
        /// Path to SSH private key (default: ~/.ssh/id_ed25519_vouch).
        #[arg(long)]
        key: Option<String>,
    },
    /// Git credential helper for GitHub.
    ///
    /// This is used by git as a credential helper. Users should not call this directly.
    /// Instead, use `vouch setup github` to configure git.
    #[command(hide = true)]
    Github {
        /// Git credential operation (get, store, erase).
        operation: String,
    },
    /// Docker credential helper for container registries.
    ///
    /// This is used by Docker as a credential helper. Users should not call this directly.
    /// Instead, use `vouch setup docker` to configure Docker.
    #[command(hide = true)]
    Docker {
        /// Docker credential operation (get, store, erase, list).
        operation: String,
    },
    /// Cargo credential provider for private registries.
    ///
    /// This implements Cargo's credential provider protocol.
    /// Users should not call this directly.
    /// Instead, use `vouch setup cargo` to configure Cargo.
    #[command(hide = true)]
    Cargo {
        /// Cargo plugin marker (always passed by Cargo).
        #[arg(long = "cargo-plugin", hide = true)]
        _cargo_plugin: bool,
    },
    /// Git credential helper for AWS CodeCommit.
    ///
    /// This is used by git as a credential helper. Users should not call this directly.
    /// Instead, use `vouch setup codecommit` to configure git.
    #[command(hide = true)]
    Codecommit {
        /// Git credential operation (get, store, erase).
        operation: String,
    },
    /// pip keyring credential helper for CodeArtifact.
    ///
    /// Implements the keyring CLI protocol (`keyring get/set/del`) so pip can
    /// dynamically fetch fresh CodeArtifact tokens. This command is called by
    /// pip when `keyring-provider = subprocess` is configured.
    ///
    /// Users should not call this directly.
    /// Run `vouch setup codeartifact --tool pip` to configure pip.
    #[command(hide = true)]
    Pip {
        /// Keyring operation (get, set, del).
        operation: String,
        /// Service URL passed by pip (the CodeArtifact index URL).
        service_url: Option<String>,
        /// Username passed by pip (typically "aws").
        username: Option<String>,
    },
    /// Obtain a CodeArtifact authorization token.
    Codeartifact {
        /// CodeArtifact domain name (or use --profile / saved default).
        #[arg(long)]
        domain: Option<String>,
        /// AWS account ID that owns the domain.
        #[arg(long)]
        domain_owner: Option<String>,
        /// AWS region.
        #[arg(long)]
        region: Option<String>,
        /// Named CodeArtifact profile from config.
        #[arg(long)]
        profile: Option<String>,
    },
}
