// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Credential issuance commands.

use clap::Subcommand;

pub(crate) mod anthropic;
pub(crate) mod aws;
pub(crate) mod cache;
pub(crate) mod cargo;
pub(crate) mod codeartifact;
pub(crate) mod codecommit;
pub(crate) mod docker;
pub(crate) mod eks;
pub(crate) mod git_protocol;
pub(crate) mod github;
pub(crate) mod kubernetes;
pub(crate) mod openai;
pub(crate) mod pip;
pub(crate) mod rds;
pub(crate) mod redshift;

pub(crate) mod ssh;
pub(crate) mod token;
pub(crate) mod wif;

/// Credential subcommands.
#[derive(Subcommand)]
pub(crate) enum CredentialCommands {
    /// Obtain temporary AWS credentials.
    ///
    /// Two access patterns:
    ///
    ///   STS role: `--role <full-arn>` — assumes the role directly,
    ///   or chains through the configured management role when the target
    ///   is in another account.
    ///
    ///   Identity Center: `--account <id> --permission-set <name>` —
    ///   exchanges a Vouch RS256 token for an IdC access token, then calls
    ///   `GetRoleCredentials`. Requires Identity Center configured via
    ///   `vouch setup aws`.
    Aws {
        /// AWS IAM role ARN to assume (STS role path).
        #[arg(
            long,
            conflicts_with_all = ["account", "permission_set"],
            required_unless_present_any = ["account", "permission_set"],
        )]
        role: Option<String>,

        /// AWS account ID (Identity Center path).
        #[arg(long, requires = "permission_set", conflicts_with = "role")]
        account: Option<String>,

        /// IAM Identity Center permission-set name.
        #[arg(long, requires = "account", conflicts_with = "role")]
        permission_set: Option<String>,

        /// Management role ARN to chain through when multiple organizations
        /// are configured (STS paths only; not valid with --account/--permission-set).
        #[arg(long, conflicts_with_all = ["idc_application", "account", "permission_set"])]
        via: Option<String>,

        /// Identity Center application ARN to use when multiple IdC instances
        /// are configured (Identity Center path only; omit for single-instance setups).
        #[arg(long, conflicts_with = "via")]
        idc_application: Option<String>,
    },
    /// Obtain an SSH certificate.
    Ssh {
        /// Path to SSH private key (default: ~/.ssh/id_ed25519_vouch).
        #[arg(long)]
        key: Option<String>,
        /// Force re-issuance even if existing certificate is still valid.
        #[arg(long)]
        force: bool,
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
    /// Generate a Kubernetes bearer token for Amazon EKS authentication.
    ///
    /// Outputs a Kubernetes ExecCredential JSON to stdout. Use as a
    /// kubeconfig exec-based credential plugin.
    Eks {
        /// EKS cluster name.
        #[arg(long)]
        cluster_name: String,
        /// AWS region (auto-detected from AWS profile or env if not specified).
        #[arg(long)]
        region: Option<String>,
        /// AWS IAM role ARN to assume (auto-detected from vouch AWS profile if not specified).
        #[arg(long)]
        role: Option<String>,
    },
    /// Generate a Kubernetes OIDC token for generic Kubernetes clusters.
    ///
    /// Outputs a Kubernetes ExecCredential JSON to stdout. Use as a
    /// kubeconfig exec-based credential plugin for clusters configured with
    /// Vouch as the OIDC provider.
    K8s {
        /// Kubernetes cluster name (used as cache key).
        #[arg(long)]
        cluster: String,
        /// OIDC audience (must match --oidc-client-id on the API server).
        /// Defaults to "kubernetes" if not specified.
        #[arg(long)]
        audience: Option<String>,
    },
    /// Generate an RDS IAM authentication token.
    ///
    /// Prints a token to stdout that can be used as the database password
    /// for RDS instances with IAM authentication enabled.
    Rds {
        /// RDS instance hostname.
        #[arg(long)]
        hostname: String,
        /// Database port (default: 5432).
        #[arg(long, default_value = "5432")]
        port: u16,
        /// Database username.
        #[arg(long)]
        username: String,
        /// AWS region (auto-detected from AWS profile or env if not specified).
        #[arg(long)]
        region: Option<String>,
        /// AWS IAM role ARN to assume (auto-detected from vouch AWS profile if not specified).
        #[arg(long)]
        role: Option<String>,
    },
    /// Generate temporary Amazon Redshift database credentials.
    ///
    /// Supports both provisioned clusters (`--cluster-id`) and Redshift
    /// Serverless workgroups (`--workgroup`). Exactly one must be specified.
    /// Outputs JSON with DbUser, DbPassword, and Expiration.
    Redshift {
        /// Redshift provisioned cluster identifier.
        #[arg(
            long,
            conflicts_with = "workgroup",
            required_unless_present = "workgroup"
        )]
        cluster_id: Option<String>,
        /// Redshift Serverless workgroup name.
        #[arg(
            long,
            conflicts_with = "cluster_id",
            required_unless_present = "cluster_id"
        )]
        workgroup: Option<String>,
        /// Database name (optional).
        #[arg(long)]
        db_name: Option<String>,
        /// AWS region (auto-detected from AWS profile or env if not specified).
        #[arg(long)]
        region: Option<String>,
        /// AWS IAM role ARN to assume (auto-detected from vouch AWS profile if not specified).
        #[arg(long)]
        role: Option<String>,
        /// Credential duration in seconds (900-3600, default: 900). Only for provisioned clusters.
        #[arg(long, value_parser = clap::value_parser!(u32).range(900..=3600), conflicts_with = "workgroup")]
        duration: Option<u32>,
    },
    /// Obtain a short-lived Anthropic (Claude) API token via Workload
    /// Identity Federation.
    ///
    /// Requires `vouch setup anthropic` and an active session
    /// (`vouch login`). Prints a bare `sk-ant-oat01-...` token to stdout
    /// with no trailing newline. The token acts as a non-human service
    /// account — intended as a credential source for CI/headless
    /// automation, not for interactive Claude Code sessions.
    Anthropic {},
    /// Obtain a short-lived OpenAI API token via Workload Identity Federation.
    ///
    /// Requires `vouch setup openai`, an active session (`vouch login`),
    /// and that OpenAI has onboarded the Vouch issuer as a workload
    /// identity provider (custom OIDC is not self-service on OpenAI's side).
    /// Prints a bare token to stdout — designed to be invoked by the
    /// OpenAI Codex CLI as a `[model_providers.<id>.auth]` command with
    /// `refresh_interval_ms`.
    Openai {},
    /// Print the current session token for use with curl or other tools.
    Token {},
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
