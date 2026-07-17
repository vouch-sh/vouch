// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Generic Kubernetes OIDC setup command.
//!
//! Configures kubeconfig so kubectl authenticates via `vouch credential k8s`,
//! which fetches a short-lived OIDC token from the Vouch server.

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::path::PathBuf;
use vouch_cli::{tr_args, tr_println};

use super::kubeconfig::{
    ExecConfig, KubeconfigCluster, KubeconfigClusterData, KubeconfigContext, KubeconfigContextData,
    KubeconfigUser, KubeconfigUserData, default_kubeconfig_path, existing_cluster_other,
    existing_context_other, existing_user_other, load_kubeconfig, save_kubeconfig,
};

/// Read and base64-encode a certificate authority file.
fn read_ca_data(ca_path: &str) -> Result<String> {
    let bytes = std::fs::read(ca_path)
        .with_context(|| tr_args!("setup-k8s-err-read-ca", path = ca_path))?;
    Ok(STANDARD.encode(&bytes))
}

/// Run the Kubernetes setup command.
///
/// Configures kubeconfig so kubectl uses `vouch credential k8s` for
/// OIDC token generation against a Vouch-backed Kubernetes cluster.
pub(crate) async fn run(
    server: &str,
    cluster: &str,
    k8s_server: &str,
    ca_path: Option<&str>,
    audience: Option<&str>,
    kubeconfig_path: Option<&str>,
) -> Result<()> {
    let aud = audience.unwrap_or("kubernetes");

    let kubeconfig_path = match kubeconfig_path {
        Some(p) => PathBuf::from(p),
        None => default_kubeconfig_path()?,
    };

    // Read CA data if provided
    let ca_data = ca_path.map(read_ca_data).transpose()?;

    tr_println!("setup-k8s-header");
    println!();
    tr_println!(
        "setup-k8s-summary",
        cluster = cluster,
        server = k8s_server,
        audience = aud,
        vouch = server,
    );
    println!();

    // Naming convention
    let user_name = format!("vouch-k8s-{cluster}");
    let context_name = format!("{cluster}-vouch");

    // Build vouch credential k8s args
    let exec_args = vec![
        "credential".to_string(),
        "k8s".to_string(),
        "--cluster".to_string(),
        cluster.to_string(),
        "--audience".to_string(),
        aud.to_string(),
    ];

    // Load existing kubeconfig
    let mut config = load_kubeconfig(&kubeconfig_path)?;

    // Upsert cluster, preserving any unmodeled fields on an existing entry.
    let cluster_other = existing_cluster_other(&config, cluster);
    config.clusters.retain(|c| c.name != cluster);
    config.clusters.push(KubeconfigCluster {
        name: cluster.to_string(),
        cluster: KubeconfigClusterData {
            server: k8s_server.to_string(),
            certificate_authority_data: ca_data,
            other: cluster_other,
        },
    });

    // Upsert user with vouch credential k8s exec config
    let user_other = existing_user_other(&config, &user_name);
    config.users.retain(|u| u.name != user_name);
    config.users.push(KubeconfigUser {
        name: user_name.clone(),
        user: KubeconfigUserData {
            exec: Some(ExecConfig {
                api_version: "client.authentication.k8s.io/v1".to_string(),
                command: "vouch".to_string(),
                args: exec_args,
                env: None,
                interactive_mode: Some("Never".to_string()),
            }),
            other: user_other,
        },
    });

    // Upsert context
    let context_other = existing_context_other(&config, &context_name);
    config.contexts.retain(|c| c.name != context_name);
    config.contexts.push(KubeconfigContext {
        name: context_name.clone(),
        context: KubeconfigContextData {
            cluster: cluster.to_string(),
            namespace: None,
            user: user_name.clone(),
            other: context_other,
        },
    });

    // Save
    save_kubeconfig(&kubeconfig_path, &config)?;

    // Print summary
    tr_println!(
        "setup-k8s-updated-block",
        kubeconfig = kubeconfig_path.display().to_string(),
        cluster = cluster,
        server = k8s_server,
        user_name = user_name.as_str(),
        context = context_name.as_str(),
    );
    println!();
    tr_println!(
        "setup-k8s-tail-block",
        context = context_name.as_str(),
        vouch = server,
        audience = aud,
    );

    Ok(())
}
