// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Setup and configuration commands.

use clap::Subcommand;
use vouch_cli::tr;

pub(crate) mod anthropic;
pub(crate) mod aws;
pub(crate) mod cargo;
pub(crate) mod codeartifact;
pub(crate) mod codecommit;
pub(crate) mod docker;
pub(crate) mod eks;
pub(crate) mod github;
pub(crate) mod kubeconfig;
pub(crate) mod kubernetes;
pub(crate) mod openai;
pub(crate) mod ssh;
pub(crate) mod ssm;

/// Setup subcommands.
#[derive(Subcommand)]
pub(crate) enum SetupCommands {
    /// Configure AWS CLI/SDK to use Vouch credentials.
    #[command(about = tr!("cmd-setup-aws-about"))]
    Aws {
        /// AWS profile name to configure. Defaults to "vouch" if not specified.
        #[arg(long, help = tr!("arg-setup-aws-profile-help"))]
        profile: Option<String>,
        /// AWS IAM role ARN to assume. Required unless --discover is set.
        #[arg(long, required_unless_present = "discover", help = tr!("arg-setup-aws-role-help"))]
        role: Option<String>,
        /// AWS region to set in the profile.
        #[arg(long, help = tr!("arg-setup-aws-region-help"))]
        region: Option<String>,
        /// Discover accounts and roles via SSO and generate profiles automatically.
        #[arg(long, conflicts_with = "role", help = tr!("arg-setup-aws-discover-help"))]
        discover: bool,
    },
    /// Configure SSH to use Vouch certificates.
    #[command(about = tr!("cmd-setup-ssh-about"))]
    Ssh {
        /// Host patterns to trust with this CA (e.g., "*.example.com").
        #[arg(long, help = tr!("arg-setup-ssh-hosts-help"))]
        hosts: Option<String>,
    },
    /// Configure Git to use Vouch for GitHub credentials.
    #[command(about = tr!("cmd-setup-github-about"))]
    Github {
        /// GitHub host to configure (default: github.com).
        #[arg(long, default_value = "github.com", help = tr!("arg-setup-github-host-help"))]
        host: String,
        /// Automatically configure git (otherwise just show instructions).
        #[arg(long, help = tr!("arg-setup-github-configure-help"))]
        configure: bool,
    },
    /// Configure kubectl to use Vouch credentials for Amazon EKS clusters.
    #[command(about = tr!("cmd-setup-eks-about"))]
    Eks {
        /// EKS cluster name.
        #[arg(long, help = tr!("arg-setup-eks-cluster-help"))]
        cluster: String,
        /// AWS region (auto-detected from AWS profile or environment if not specified).
        #[arg(long, help = tr!("arg-setup-eks-region-help"))]
        region: Option<String>,
        /// AWS profile to use (defaults to auto-detected vouch profile).
        #[arg(long, help = tr!("arg-setup-eks-profile-help"))]
        profile: Option<String>,
        /// Path to kubeconfig file (defaults to ~/.kube/config).
        #[arg(long, help = tr!("arg-setup-eks-kubeconfig-help"))]
        kubeconfig: Option<String>,
    },
    /// Configure kubectl to use Vouch OIDC credentials for generic Kubernetes clusters.
    #[command(about = tr!("cmd-setup-k8s-about"))]
    K8s {
        /// Kubernetes cluster name.
        #[arg(long, help = tr!("arg-setup-k8s-cluster-help"))]
        cluster: String,
        /// Kubernetes API server URL (e.g., https://k8s.example.com:6443).
        #[arg(long, help = tr!("arg-setup-k8s-server-help"))]
        server: String,
        /// Path to the cluster's certificate authority file (PEM format).
        #[arg(long, help = tr!("arg-setup-k8s-ca-help"))]
        certificate_authority: Option<String>,
        /// OIDC audience.
        #[arg(long, help = tr!("arg-setup-k8s-audience-help"))]
        audience: Option<String>,
        /// Path to kubeconfig file (defaults to ~/.kube/config).
        #[arg(long, help = tr!("arg-setup-k8s-kubeconfig-help"))]
        kubeconfig: Option<String>,
    },
    /// Configure Docker to use Vouch for container registry authentication.
    #[command(about = tr!("cmd-setup-docker-about"))]
    Docker {
        /// Container registries to configure (e.g., ghcr.io).
        #[arg(trailing_var_arg = true, help = tr!("arg-setup-docker-registries-help"))]
        registries: Vec<String>,
        /// Automatically configure Docker (otherwise just show instructions).
        #[arg(long, help = tr!("arg-setup-docker-configure-help"))]
        configure: bool,
    },
    /// Configure Cargo to use Vouch for private registry authentication.
    #[command(about = tr!("cmd-setup-cargo-about"))]
    Cargo {
        /// Registry name to configure (if not specified, configures global provider).
        #[arg(long, help = tr!("arg-setup-cargo-registry-help"))]
        registry: Option<String>,
        /// Write the configuration (otherwise just show instructions).
        #[arg(long, help = tr!("arg-setup-cargo-configure-help"))]
        configure: bool,
    },
    /// Configure Git to use Vouch for AWS CodeCommit credentials.
    #[command(about = tr!("cmd-setup-codecommit-about"))]
    Codecommit {
        /// AWS region (default: wildcard matching all regions).
        #[arg(long, help = tr!("arg-setup-codecommit-region-help"))]
        region: Option<String>,
        /// AWS profile to use (defaults to auto-detected vouch profile).
        #[arg(long, help = tr!("arg-setup-codecommit-profile-help"))]
        profile: Option<String>,
        /// Automatically configure git (otherwise just show instructions).
        #[arg(long, help = tr!("arg-setup-codecommit-configure-help"))]
        configure: bool,
    },
    /// Configure SSH for AWS Systems Manager Session Manager.
    #[command(about = tr!("cmd-setup-ssm-about"))]
    Ssm {
        /// AWS profile to use (defaults to auto-detected vouch profile).
        #[arg(long, help = tr!("arg-setup-ssm-profile-help"))]
        profile: Option<String>,
        /// AWS region.
        #[arg(long, help = tr!("arg-setup-ssm-region-help"))]
        region: Option<String>,
        /// SSH host patterns for SSM proxying.
        #[arg(long, default_value = ssm::DEFAULT_HOST_PATTERN, help = tr!("arg-setup-ssm-hosts-help"))]
        hosts: String,
        /// Replace existing Vouch SSM configuration if present.
        #[arg(long, help = tr!("arg-setup-ssm-force-help"))]
        force: bool,
    },
    /// Configure Anthropic (Claude) Workload Identity Federation.
    #[command(
        about = tr!("cmd-setup-anthropic-about"),
        long_about = tr!("cmd-setup-anthropic-long-about"),
    )]
    Anthropic {
        /// Anthropic federation rule ID (`fdrl_...`).
        #[arg(long, help = tr!("arg-setup-anthropic-federation-rule-id-help"))]
        federation_rule_id: String,
        /// Anthropic organization ID (UUID).
        #[arg(long, help = tr!("arg-setup-anthropic-organization-id-help"))]
        organization_id: String,
        /// Anthropic service account ID (`svac_...`).
        #[arg(long, help = tr!("arg-setup-anthropic-service-account-id-help"))]
        service_account_id: String,
        /// Anthropic workspace ID (`wrkspc_...`).
        #[arg(long, help = tr!("arg-setup-anthropic-workspace-id-help"))]
        workspace_id: String,
        /// `aud` claim to request on the assertion (optional).
        #[arg(long, help = tr!("arg-setup-anthropic-audience-help"))]
        audience: Option<String>,
        /// Token endpoint override (defaults to Anthropic's public endpoint).
        #[arg(long, help = tr!("arg-setup-anthropic-token-endpoint-help"))]
        token_endpoint: Option<String>,
    },
    /// Configure OpenAI Workload Identity Federation.
    #[command(
        about = tr!("cmd-setup-openai-about"),
        long_about = tr!("cmd-setup-openai-long-about"),
    )]
    Openai {
        /// OpenAI Workload Identity Provider ID for the Vouch issuer.
        #[arg(long, help = tr!("arg-setup-openai-identity-provider-id-help"))]
        identity_provider_id: String,
        /// OpenAI service account ID.
        #[arg(long, help = tr!("arg-setup-openai-service-account-id-help"))]
        service_account_id: String,
        /// `aud` claim to request on the assertion.
        #[arg(long, help = tr!("arg-setup-openai-audience-help"))]
        audience: Option<String>,
        /// Token endpoint override (defaults to OpenAI's public endpoint).
        #[arg(long, help = tr!("arg-setup-openai-token-endpoint-help"))]
        token_endpoint: Option<String>,
        /// Overwrite an existing Codex `model_provider` or `vouch` provider block.
        #[arg(long, help = tr!("arg-setup-openai-force-help"))]
        force: bool,
    },
    /// Configure a package manager for AWS CodeArtifact.
    #[command(about = tr!("cmd-setup-codeartifact-about"))]
    Codeartifact {
        /// Package manager to configure (cargo, pip, npm).
        #[arg(long, help = tr!("arg-setup-codeartifact-tool-help"))]
        tool: codeartifact::Tool,
        /// CodeArtifact domain name (or use --profile / saved default).
        #[arg(long, help = tr!("arg-setup-codeartifact-domain-help"))]
        domain: Option<String>,
        /// AWS account ID that owns the domain.
        #[arg(long, help = tr!("arg-setup-codeartifact-domain-owner-help"))]
        domain_owner: Option<String>,
        /// AWS region.
        #[arg(long, help = tr!("arg-setup-codeartifact-region-help"))]
        region: Option<String>,
        /// CodeArtifact repository name.
        #[arg(long, help = tr!("arg-setup-codeartifact-repository-help"))]
        repository: String,
        /// Named CodeArtifact profile to use / save.
        #[arg(long, help = tr!("arg-setup-codeartifact-profile-help"))]
        profile: Option<String>,
    },
}
