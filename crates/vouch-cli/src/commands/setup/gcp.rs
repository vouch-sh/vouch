// SPDX-License-Identifier: Apache-2.0 OR MIT
//! GCP setup command.
//!
//! Configures GCP to use Vouch for credential federation via Workload Identity Federation.
//! Configuration can be provided via CLI args or fetched from the server.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::path::PathBuf;
use vouch_common::{GcpIntegrationConfig, IntegrationConfigResponse};

use crate::client::VouchClient;
use crate::utils::{ensure_secure_dir, write_secure_file};

/// GCP external account credential configuration.
/// See: https://google.aip.dev/auth/4117
#[derive(Debug, Serialize)]
struct ExternalAccountConfig {
    #[serde(rename = "type")]
    config_type: String,
    audience: String,
    subject_token_type: String,
    token_url: String,
    credential_source: CredentialSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_account_impersonation_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct CredentialSource {
    executable: ExecutableConfig,
}

#[derive(Debug, Serialize)]
struct ExecutableConfig {
    command: String,
    timeout_millis: u32,
    output_file: String,
}

/// Get the GCP credential config directory (~/.config/gcloud).
fn gcp_config_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".config").join("gcloud"))
}

/// Get the vouch cache directory (~/.cache/vouch).
fn vouch_cache_dir() -> Result<PathBuf> {
    // Prefer XDG_RUNTIME_DIR if available (more secure on multi-user systems)
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(runtime_dir).join("vouch"));
    }

    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".cache").join("vouch"))
}

/// Build the audience URL from components.
fn build_audience(project_number: &str, pool_id: &str, provider_id: &str) -> String {
    format!(
        "//iam.googleapis.com/projects/{}/locations/global/workloadIdentityPools/{}/providers/{}",
        project_number, pool_id, provider_id
    )
}

/// Build the service account impersonation URL.
fn build_impersonation_url(service_account: &str) -> String {
    format!(
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{}:generateAccessToken",
        service_account
    )
}

/// Fetch GCP configuration from server.
async fn fetch_server_config(server: &str) -> Result<GcpIntegrationConfig> {
    let client = VouchClient::new(server)?;
    let resp: IntegrationConfigResponse<GcpIntegrationConfig> =
        client.get_authenticated("/v1/integrations/gcp").await?;

    resp.config.ok_or_else(|| {
        anyhow::anyhow!(
            "GCP is not configured for your organization.\n\
             Ask your organization admin to configure GCP integration,\n\
             or provide --project-number, --pool-id, and --provider-id manually."
        )
    })
}

/// Run the GCP setup command.
///
/// This command:
/// 1. Fetches config from server if CLI args not provided
/// 2. Shows how to configure GCP to use Vouch
/// 3. Optionally creates the credential configuration file
#[allow(clippy::too_many_arguments)]
pub async fn run(
    server: &str,
    profile: Option<&str>,
    project_number: Option<&str>,
    pool_id: Option<&str>,
    provider_id: Option<&str>,
    service_account: Option<&str>,
    output: Option<&str>,
    configure: bool,
) -> Result<()> {
    // Determine config: either from CLI args or from server
    let config = match (project_number, pool_id, provider_id) {
        (Some(pn), Some(pi), Some(pr)) => {
            // All CLI args provided - use them directly
            GcpIntegrationConfig {
                project_number: pn.to_string(),
                pool_id: pi.to_string(),
                provider_id: pr.to_string(),
                service_account: service_account.map(String::from),
            }
        }
        (None, None, None) => {
            // No CLI args - fetch from server
            println!("Fetching GCP configuration from server...");
            let mut server_config = fetch_server_config(server).await?;
            // Service account can override server config
            if service_account.is_some() {
                server_config.service_account = service_account.map(String::from);
            }
            server_config
        }
        _ => {
            // Partial args - error
            bail!(
                "Provide all of --project-number, --pool-id, --provider-id, or none.\n\
                 When none are provided, configuration is fetched from the server."
            );
        }
    };

    // Get paths
    let vouch_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("vouch"));
    let gcp_config_dir = gcp_config_dir()?;
    let cache_dir = vouch_cache_dir()?;

    // Output file path based on profile name
    let output_path = output.map(PathBuf::from).unwrap_or_else(|| {
        let filename = match profile {
            Some(p) => format!("vouch-credentials-{p}.json"),
            None => "vouch-credentials.json".to_string(),
        };
        gcp_config_dir.join(filename)
    });

    let audience = build_audience(&config.project_number, &config.pool_id, &config.provider_id);
    let cache_file = cache_dir.join("gcp-token.json");

    println!("GCP Workload Identity Federation Setup");
    println!("======================================");
    println!();

    if configure {
        // Create the configuration file
        write_config_file(
            &output_path,
            &vouch_path,
            &audience,
            &cache_file,
            config.service_account.as_deref(),
        )?;
        println!(
            "Created credential configuration: {}",
            output_path.display()
        );
        println!();
    }

    // Show configuration
    println!("Credential configuration file:");
    println!();
    let ext_config = build_config(
        &vouch_path,
        &audience,
        &cache_file,
        config.service_account.as_deref(),
    );
    let json = serde_json::to_string_pretty(&ext_config)?;
    println!("{json}");
    println!();

    // Show usage instructions
    println!("To use Vouch for GCP credentials:");
    println!();
    println!("1. Set the environment variable:");
    println!();
    println!(
        "   export GOOGLE_APPLICATION_CREDENTIALS={}",
        output_path.display()
    );
    println!();
    println!("   Or add to your shell profile (~/.bashrc, ~/.zshrc, etc.)");
    println!();
    if profile.is_some() {
        println!("   Tip: Use direnv for per-directory credentials:");
        println!(
            "   echo 'export GOOGLE_APPLICATION_CREDENTIALS={}' >> .envrc",
            output_path.display()
        );
        println!("   direnv allow");
        println!();
    }
    println!("2. Enable the executable credential source in gcloud:");
    println!();
    println!("   gcloud config set auth/credential_source_command_override true");
    println!();
    println!("3. Log in with Vouch and use GCP tools:");
    println!();
    println!("   vouch login");
    println!("   gcloud projects list");
    println!();

    // Show prerequisites
    println!("Prerequisites:");
    println!();
    println!("  1. You must be logged in to Vouch: vouch login");
    println!("  2. The GCP Workload Identity Pool must trust the Vouch OIDC provider");
    println!();
    if config.service_account.is_none() {
        println!("Note: No service account specified. The token will be used directly");
        println!("      without service account impersonation. For most use cases,");
        println!("      you'll want to specify --service-account.");
        println!();
    }

    println!("To configure GCP Workload Identity Federation:");
    println!();
    println!("  1. Create a Workload Identity Pool:");
    println!(
        "     gcloud iam workload-identity-pools create {} \\",
        config.pool_id
    );
    println!("       --location=global \\");
    println!("       --display-name=\"Vouch Pool\"");
    println!();
    println!("  2. Create an OIDC Provider in the pool:");
    println!(
        "     gcloud iam workload-identity-pools providers create-oidc {} \\",
        config.provider_id
    );
    println!("       --location=global \\");
    println!("       --workload-identity-pool={} \\", config.pool_id);
    println!("       --issuer-uri=\"YOUR_VOUCH_SERVER_URL\" \\");
    println!(
        "       --attribute-mapping=\"google.subject=assertion.sub,attribute.email=assertion.email\""
    );
    println!();
    if let Some(sa) = &config.service_account {
        println!("  3. Grant the service account impersonation permission:");
        println!(
            "     gcloud iam service-accounts add-iam-policy-binding {} \\",
            sa
        );
        println!("       --role=roles/iam.workloadIdentityUser \\");
        println!(
            "       --member=\"principalSet://iam.googleapis.com/projects/{}/locations/global/workloadIdentityPools/{}/attribute.email/YOUR_EMAIL\"",
            config.project_number, config.pool_id
        );
        println!();
    }

    Ok(())
}

/// Build the credential configuration.
fn build_config(
    vouch_path: &std::path::Path,
    audience: &str,
    cache_file: &std::path::Path,
    service_account: Option<&str>,
) -> ExternalAccountConfig {
    let command = format!(
        "{} credential gcp --audience {}",
        vouch_path.display(),
        audience
    );

    ExternalAccountConfig {
        config_type: "external_account".to_string(),
        audience: audience.to_string(),
        subject_token_type: "urn:ietf:params:oauth:token-type:id_token".to_string(),
        token_url: "https://sts.googleapis.com/v1/token".to_string(),
        credential_source: CredentialSource {
            executable: ExecutableConfig {
                command,
                timeout_millis: 30000,
                output_file: cache_file.to_string_lossy().to_string(),
            },
        },
        service_account_impersonation_url: service_account.map(build_impersonation_url),
    }
}

/// Write the credential configuration file.
fn write_config_file(
    output_path: &std::path::Path,
    vouch_path: &std::path::Path,
    audience: &str,
    cache_file: &std::path::Path,
    service_account: Option<&str>,
) -> Result<()> {
    // Ensure cache directory exists with secure permissions
    if let Some(parent) = cache_file.parent() {
        ensure_secure_dir(parent)?;
    }

    let config = build_config(vouch_path, audience, cache_file, service_account);
    let json = serde_json::to_string_pretty(&config)?;

    write_secure_file(output_path, &json)?;

    Ok(())
}
