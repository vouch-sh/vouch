// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Credential issuance commands.

use clap::Subcommand;
use vouch_cli::tr;

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
///
/// Doc comments on this enum are for developers. Every user-visible string is
/// supplied by `about` / `long_about` / `help` so it resolves through Fluent —
/// clap would otherwise derive them from the doc comments and print English in
/// every locale. `long_about` is required wherever a doc comment runs past its
/// first line, because clap derives long help from the whole comment.
#[derive(Subcommand)]
pub(crate) enum CredentialCommands {
    /// Obtain temporary AWS credentials.
    #[command(
        about = tr!("cmd-credential-aws-about"),
        long_about = tr!("cmd-credential-aws-long-about"),
    )]
    Aws {
        /// AWS IAM role ARN to assume (STS role path).
        #[arg(
            long,
            conflicts_with_all = ["account", "permission_set"],
            required_unless_present_any = ["account", "permission_set"],
            help = tr!("arg-credential-aws-role-help"),
        )]
        role: Option<String>,

        /// AWS account ID (Identity Center path).
        #[arg(
            long,
            requires = "permission_set",
            conflicts_with = "role",
            help = tr!("arg-credential-aws-account-help"),
        )]
        account: Option<String>,

        /// IAM Identity Center permission-set name.
        #[arg(
            long,
            requires = "account",
            conflicts_with = "role",
            help = tr!("arg-credential-aws-permission-set-help"),
        )]
        permission_set: Option<String>,

        /// Management role ARN to chain through when multiple organizations
        /// are configured (STS paths only).
        #[arg(
            long,
            conflicts_with_all = ["idc_application", "account", "permission_set"],
            help = tr!("arg-credential-aws-via-help"),
        )]
        via: Option<String>,

        /// Identity Center application ARN to use when multiple IdC instances
        /// are configured (Identity Center path only).
        #[arg(
            long,
            conflicts_with = "via",
            help = tr!("arg-credential-aws-idc-application-help"),
        )]
        idc_application: Option<String>,
    },
    /// Obtain an SSH certificate.
    #[command(about = tr!("cmd-credential-ssh-about"))]
    Ssh {
        /// Path to SSH private key.
        #[arg(long, help = tr!("arg-credential-ssh-key-help"))]
        key: Option<String>,
        /// Force re-issuance even if existing certificate is still valid.
        #[arg(long, help = tr!("arg-credential-ssh-force-help"))]
        force: bool,
    },
    /// Git credential helper for GitHub. Invoked by git, not by users.
    #[command(
        hide = true,
        about = tr!("cmd-credential-github-about"),
        long_about = tr!("cmd-credential-github-long-about"),
    )]
    Github {
        /// Git credential operation (get, store, erase).
        #[arg(help = tr!("arg-credential-github-operation-help"))]
        operation: String,
    },
    /// Docker credential helper. Invoked by Docker, not by users.
    #[command(
        hide = true,
        about = tr!("cmd-credential-docker-about"),
        long_about = tr!("cmd-credential-docker-long-about"),
    )]
    Docker {
        /// Docker credential operation (get, store, erase, list).
        #[arg(help = tr!("arg-credential-docker-operation-help"))]
        operation: String,
        /// AWS profile in ~/.aws/config whose role mints ECR credentials.
        #[arg(long, help = tr!("arg-credential-docker-profile-help"))]
        profile: Option<String>,
    },
    /// Cargo credential provider. Invoked by Cargo, not by users.
    #[command(
        hide = true,
        about = tr!("cmd-credential-cargo-about"),
        long_about = tr!("cmd-credential-cargo-long-about"),
    )]
    Cargo {
        /// Cargo plugin marker (always passed by Cargo). Hidden, so no help text.
        #[arg(long = "cargo-plugin", hide = true)]
        _cargo_plugin: bool,
    },
    /// Git credential helper for CodeCommit. Invoked by git, not by users.
    #[command(
        hide = true,
        about = tr!("cmd-credential-codecommit-about"),
        long_about = tr!("cmd-credential-codecommit-long-about"),
    )]
    Codecommit {
        /// Git credential operation (get, store, erase).
        #[arg(help = tr!("arg-credential-codecommit-operation-help"))]
        operation: String,
        /// AWS profile in ~/.aws/config whose role mints CodeCommit credentials.
        #[arg(long, help = tr!("arg-credential-codecommit-profile-help"))]
        profile: Option<String>,
    },
    /// pip keyring credential helper. Invoked by pip, not by users.
    #[command(
        hide = true,
        about = tr!("cmd-credential-pip-about"),
        long_about = tr!("cmd-credential-pip-long-about"),
    )]
    Pip {
        /// Keyring operation (get, set, del).
        #[arg(help = tr!("arg-credential-pip-operation-help"))]
        operation: String,
        /// Service URL passed by pip (the CodeArtifact index URL).
        #[arg(help = tr!("arg-credential-pip-service-url-help"))]
        service_url: Option<String>,
        /// Username passed by pip (typically "aws").
        #[arg(help = tr!("arg-credential-pip-username-help"))]
        username: Option<String>,
    },
    /// Generate a Kubernetes bearer token for Amazon EKS authentication.
    #[command(
        about = tr!("cmd-credential-eks-about"),
        long_about = tr!("cmd-credential-eks-long-about"),
    )]
    Eks {
        /// EKS cluster name.
        #[arg(long, help = tr!("arg-credential-eks-cluster-name-help"))]
        cluster_name: String,
        /// AWS region.
        #[arg(long, help = tr!("arg-credential-eks-region-help"))]
        region: Option<String>,
        /// AWS IAM role ARN to assume.
        #[arg(long, help = tr!("arg-credential-eks-role-help"))]
        role: Option<String>,
    },
    /// Generate a Kubernetes OIDC token for generic Kubernetes clusters.
    #[command(
        about = tr!("cmd-credential-k8s-about"),
        long_about = tr!("cmd-credential-k8s-long-about"),
    )]
    K8s {
        /// Kubernetes cluster name (used as cache key).
        #[arg(long, help = tr!("arg-credential-k8s-cluster-help"))]
        cluster: String,
        /// OIDC audience.
        #[arg(long, help = tr!("arg-credential-k8s-audience-help"))]
        audience: Option<String>,
    },
    /// Generate an RDS IAM authentication token.
    #[command(
        about = tr!("cmd-credential-rds-about"),
        long_about = tr!("cmd-credential-rds-long-about"),
    )]
    Rds {
        /// RDS instance hostname.
        #[arg(long, help = tr!("arg-credential-rds-hostname-help"))]
        hostname: String,
        /// Database port.
        #[arg(long, default_value = "5432", help = tr!("arg-credential-rds-port-help"))]
        port: u16,
        /// Database username.
        #[arg(long, help = tr!("arg-credential-rds-username-help"))]
        username: String,
        /// AWS region.
        #[arg(long, help = tr!("arg-credential-rds-region-help"))]
        region: Option<String>,
        /// AWS IAM role ARN to assume.
        #[arg(long, help = tr!("arg-credential-rds-role-help"))]
        role: Option<String>,
    },
    /// Generate temporary Amazon Redshift database credentials.
    #[command(
        about = tr!("cmd-credential-redshift-about"),
        long_about = tr!("cmd-credential-redshift-long-about"),
    )]
    Redshift {
        /// Redshift provisioned cluster identifier.
        #[arg(
            long,
            conflicts_with = "workgroup",
            required_unless_present = "workgroup",
            help = tr!("arg-credential-redshift-cluster-id-help"),
        )]
        cluster_id: Option<String>,
        /// Redshift Serverless workgroup name.
        #[arg(
            long,
            conflicts_with = "cluster_id",
            required_unless_present = "cluster_id",
            help = tr!("arg-credential-redshift-workgroup-help"),
        )]
        workgroup: Option<String>,
        /// Database name (optional).
        #[arg(long, help = tr!("arg-credential-redshift-db-name-help"))]
        db_name: Option<String>,
        /// AWS region.
        #[arg(long, help = tr!("arg-credential-redshift-region-help"))]
        region: Option<String>,
        /// AWS IAM role ARN to assume.
        #[arg(long, help = tr!("arg-credential-redshift-role-help"))]
        role: Option<String>,
        /// Credential duration in seconds. Only for provisioned clusters.
        #[arg(
            long,
            value_parser = clap::value_parser!(u32).range(900..=3600),
            conflicts_with = "workgroup",
            help = tr!("arg-credential-redshift-duration-help"),
        )]
        duration: Option<u32>,
    },
    /// Obtain a short-lived Anthropic (Claude) API token via Workload Identity
    /// Federation.
    #[command(
        about = tr!("cmd-credential-anthropic-about"),
        long_about = tr!("cmd-credential-anthropic-long-about"),
    )]
    Anthropic {},
    /// Obtain a short-lived OpenAI API token via Workload Identity Federation.
    #[command(
        about = tr!("cmd-credential-openai-about"),
        long_about = tr!("cmd-credential-openai-long-about"),
    )]
    Openai {},
    /// Print the current session token for use with curl or other tools.
    #[command(about = tr!("cmd-credential-token-about"))]
    Token {},
    /// Obtain a CodeArtifact authorization token.
    #[command(about = tr!("cmd-credential-codeartifact-about"))]
    Codeartifact {
        /// CodeArtifact domain name.
        #[arg(long, help = tr!("arg-credential-codeartifact-domain-help"))]
        domain: Option<String>,
        /// AWS account ID that owns the domain.
        #[arg(long, help = tr!("arg-credential-codeartifact-domain-owner-help"))]
        domain_owner: Option<String>,
        /// AWS region.
        #[arg(long, help = tr!("arg-credential-codeartifact-region-help"))]
        region: Option<String>,
        /// Named CodeArtifact domain profile from config.
        #[arg(long, help = tr!("arg-credential-codeartifact-domain-profile-help"))]
        domain_profile: Option<String>,
        /// AWS profile in ~/.aws/config whose role mints the token.
        #[arg(long, help = tr!("arg-credential-codeartifact-profile-help"))]
        profile: Option<String>,
    },
}
