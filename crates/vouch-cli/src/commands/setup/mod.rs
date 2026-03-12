// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Setup and configuration commands.

use clap::Subcommand;

pub mod aws;
pub mod aws_idc;
pub mod cargo;
pub mod codeartifact;
pub mod codecommit;
pub mod docker;
pub mod eks;
pub mod github;
pub mod ssh;
pub mod ssm;

/// Setup subcommands.
#[derive(Subcommand)]
pub enum SetupCommands {
    /// Configure AWS CLI/SDK to use Vouch credentials.
    Aws {
        /// AWS profile name to configure. Defaults to "vouch" if not specified.
        #[arg(long)]
        profile: Option<String>,
        /// AWS IAM role ARN to assume.
        #[arg(long)]
        role: String,
        /// AWS region to set in the profile.
        #[arg(long)]
        region: Option<String>,
    },
    /// Configure AWS CLI/SDK to use Vouch with IAM Identity Center.
    ///
    /// Creates an AWS profile that obtains credentials through the Identity
    /// Center Trusted Token Issuer flow. The Identity Center configuration
    /// (bootstrap role, application ARN, region) is fetched from the Vouch
    /// server.
    #[command(name = "aws-idc")]
    AwsIdc {
        /// Target AWS account ID. If omitted, discovers all available accounts.
        #[arg(long, requires = "role_name")]
        account_id: Option<String>,
        /// Identity Center permission set role name. Required with --account-id.
        #[arg(long, requires = "account_id")]
        role_name: Option<String>,
        /// AWS profile name to configure.
        #[arg(long)]
        profile: Option<String>,
        /// AWS region to set in the profile (defaults to IdC region from server).
        #[arg(long)]
        region: Option<String>,
    },
    /// Configure SSH to use Vouch certificates.
    Ssh {
        /// Host patterns to trust with this CA (e.g., "*.example.com").
        /// If specified, adds entry to ~/.ssh/known_hosts.
        #[arg(long)]
        hosts: Option<String>,
    },
    /// Configure Git to use Vouch for GitHub credentials.
    Github {
        /// GitHub host to configure (default: github.com).
        #[arg(long, default_value = "github.com")]
        host: String,
        /// Automatically configure git (otherwise just show instructions).
        #[arg(long)]
        configure: bool,
    },
    /// Configure kubectl to use Vouch credentials for Amazon EKS clusters.
    Eks {
        /// EKS cluster name.
        #[arg(long)]
        cluster: String,
        /// AWS region (auto-detected from AWS profile or environment if not specified).
        #[arg(long)]
        region: Option<String>,
        /// AWS profile to use (defaults to auto-detected vouch profile).
        #[arg(long)]
        profile: Option<String>,
        /// Path to kubeconfig file (defaults to ~/.kube/config).
        #[arg(long)]
        kubeconfig: Option<String>,
    },
    /// Configure Docker to use Vouch for container registry authentication.
    Docker {
        /// Container registries to configure (e.g., ghcr.io).
        #[arg(trailing_var_arg = true)]
        registries: Vec<String>,
        /// Automatically configure Docker (otherwise just show instructions).
        #[arg(long)]
        configure: bool,
    },
    /// Configure Cargo to use Vouch for private registry authentication.
    Cargo {
        /// Registry name to configure (if not specified, configures global provider).
        #[arg(long)]
        registry: Option<String>,
        /// Write the configuration (otherwise just show instructions).
        #[arg(long)]
        configure: bool,
    },
    /// Configure Git to use Vouch for AWS CodeCommit credentials.
    Codecommit {
        /// AWS region (default: wildcard matching all regions).
        #[arg(long)]
        region: Option<String>,
        /// AWS profile to use (defaults to auto-detected vouch profile).
        #[arg(long)]
        profile: Option<String>,
        /// Automatically configure git (otherwise just show instructions).
        #[arg(long)]
        configure: bool,
    },
    /// Configure SSH for AWS Systems Manager Session Manager.
    Ssm {
        /// AWS profile to use (defaults to auto-detected vouch profile).
        #[arg(long)]
        profile: Option<String>,
        /// AWS region (auto-detected from AWS profile or environment if not specified).
        #[arg(long)]
        region: Option<String>,
        /// SSH host patterns for SSM proxying (i-* = EC2 instances, mi-* = managed
        /// instances).
        #[arg(long, default_value = ssm::DEFAULT_HOST_PATTERN)]
        hosts: String,
        /// Replace existing Vouch SSM configuration if present.
        #[arg(long)]
        force: bool,
    },
    /// Configure a package manager for AWS CodeArtifact.
    Codeartifact {
        /// Package manager to configure (cargo, pip, npm).
        #[arg(long)]
        tool: codeartifact::Tool,
        /// CodeArtifact domain name (or use --profile / saved default).
        #[arg(long)]
        domain: Option<String>,
        /// AWS account ID that owns the domain.
        #[arg(long)]
        domain_owner: Option<String>,
        /// AWS region.
        #[arg(long)]
        region: Option<String>,
        /// CodeArtifact repository name.
        #[arg(long)]
        repository: String,
        /// Named CodeArtifact profile to use / save.
        #[arg(long)]
        profile: Option<String>,
    },
}
