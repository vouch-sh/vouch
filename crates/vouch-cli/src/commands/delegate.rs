//! Manage delegations for AI agents

use anyhow::{Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use vouch_common::{DelegationScope, DelegationSummary, DelegationTarget};

use crate::client::VouchClient;
use crate::config::Config;

// ============================================================================
// Create delegation
// ============================================================================

#[derive(Serialize)]
struct CreateDelegationRequest {
    name: String,
    scope: DelegationScope,
    ttl_seconds: u64,
    max_uses: Option<u64>,
}

#[derive(Deserialize)]
struct CreateDelegationResponse {
    delegation_id: String,
    token: String,
    expires_at: String,
}

pub async fn create(
    client: &VouchClient,
    config: &Config,
    name: String,
    ttl: String,
    max_uses: Option<u64>,
    github_repos: Vec<String>,
    github_branches: Vec<String>,
    aws_roles: Vec<String>,
) -> Result<()> {
    let token = config
        .session_token
        .as_ref()
        .context("not authenticated - run 'vouch login' first")?;

    // Parse TTL
    let ttl_seconds = parse_ttl(&ttl)?;

    // Build scope
    let mut targets = Vec::new();

    if !github_repos.is_empty() {
        targets.push(DelegationTarget::GitHub {
            repositories: github_repos,
            branches: if github_branches.is_empty() {
                None
            } else {
                Some(github_branches)
            },
            permissions: None,
        });
    }

    if !aws_roles.is_empty() {
        targets.push(DelegationTarget::Aws {
            role_arns: aws_roles,
        });
    }

    if targets.is_empty() {
        anyhow::bail!("at least one scope must be specified (--github-repo or --aws-role)");
    }

    let scope = DelegationScope {
        targets,
        operations: None,
    };

    let req = CreateDelegationRequest {
        name: name.clone(),
        scope,
        ttl_seconds,
        max_uses,
    };

    let resp: CreateDelegationResponse = client
        .post("/v1/delegations", &req, Some(token))
        .await
        .context("failed to create delegation")?;

    println!("{}", "✓ Delegation created".green().bold());
    println!();
    println!("  Name:       {}", name);
    println!("  ID:         {}", resp.delegation_id);
    println!("  Expires:    {}", resp.expires_at);
    if let Some(max) = max_uses {
        println!("  Max uses:   {}", max);
    }
    println!();
    println!("{}", "Delegation token (give this to your agent):".yellow());
    println!();
    println!("{}", resp.token);
    println!();
    println!(
        "{}",
        "⚠  This token will not be shown again. Store it securely.".red()
    );

    Ok(())
}

fn parse_ttl(ttl: &str) -> Result<u64> {
    let ttl = ttl.trim().to_lowercase();
    
    if let Some(hours) = ttl.strip_suffix('h') {
        let h: u64 = hours.parse().context("invalid TTL")?;
        return Ok(h * 3600);
    }
    
    if let Some(minutes) = ttl.strip_suffix('m') {
        let m: u64 = minutes.parse().context("invalid TTL")?;
        return Ok(m * 60);
    }
    
    if let Some(days) = ttl.strip_suffix('d') {
        let d: u64 = days.parse().context("invalid TTL")?;
        return Ok(d * 86400);
    }
    
    // Try parsing as seconds
    ttl.parse().context("invalid TTL - use format like '1h', '30m', or '1d'")
}

// ============================================================================
// List delegations
// ============================================================================

#[derive(Deserialize)]
struct ListDelegationsResponse {
    delegations: Vec<DelegationSummary>,
}

pub async fn list(client: &VouchClient, config: &Config) -> Result<()> {
    let token = config
        .session_token
        .as_ref()
        .context("not authenticated - run 'vouch login' first")?;

    let resp: ListDelegationsResponse = client
        .get("/v1/delegations", Some(token))
        .await
        .context("failed to list delegations")?;

    if resp.delegations.is_empty() {
        println!("No active delegations.");
        println!();
        println!(
            "Create one with: {}",
            "vouch delegate create --name my-agent --github-repo 'myorg/*'".cyan()
        );
        return Ok(());
    }

    println!("{}", "Active delegations:".bold());
    println!();

    for d in resp.delegations {
        let status = if d.revoked {
            "revoked".red()
        } else {
            "active".green()
        };

        println!("  {} [{}]", d.name.bold(), status);
        println!("    ID:      {}", d.id);
        println!("    Scope:   {}", d.scope_summary);
        println!("    Uses:    {}", d.use_count);
        println!("    Expires: {}", d.expires_at);
        println!();
    }

    Ok(())
}

// ============================================================================
// Revoke delegation
// ============================================================================

#[derive(Deserialize)]
struct RevokeDelegationResponse {
    revoked: bool,
}

pub async fn revoke(client: &VouchClient, config: &Config, id: String) -> Result<()> {
    let token = config
        .session_token
        .as_ref()
        .context("not authenticated - run 'vouch login' first")?;

    let _resp: RevokeDelegationResponse = client
        .delete(&format!("/v1/delegations/{}", id), Some(token))
        .await
        .context("failed to revoke delegation")?;

    println!("{}", "✓ Delegation revoked".green());

    Ok(())
}

// ============================================================================
// Show delegation details
// ============================================================================

#[derive(Deserialize)]
struct DelegationDetails {
    id: String,
    name: String,
    scope: DelegationScope,
    created_at: String,
    expires_at: String,
    revoked: bool,
    use_count: u64,
    max_uses: Option<u64>,
    recent_uses: Vec<DelegationUse>,
}

#[derive(Deserialize)]
struct DelegationUse {
    timestamp: String,
    action: String,
    target: String,
}

pub async fn show(client: &VouchClient, config: &Config, id: String) -> Result<()> {
    let token = config
        .session_token
        .as_ref()
        .context("not authenticated - run 'vouch login' first")?;

    let d: DelegationDetails = client
        .get(&format!("/v1/delegations/{}", id), Some(token))
        .await
        .context("failed to get delegation")?;

    let status = if d.revoked {
        "revoked".red()
    } else {
        "active".green()
    };

    println!("{} [{}]", d.name.bold(), status);
    println!();
    println!("  ID:         {}", d.id);
    println!("  Created:    {}", d.created_at);
    println!("  Expires:    {}", d.expires_at);
    println!(
        "  Uses:       {} / {}",
        d.use_count,
        d.max_uses.map(|m| m.to_string()).unwrap_or("∞".to_string())
    );
    println!();
    println!("{}", "Scope:".bold());
    for target in &d.scope.targets {
        match target {
            DelegationTarget::GitHub {
                repositories,
                branches,
                ..
            } => {
                println!("  GitHub:");
                println!("    Repos:    {}", repositories.join(", "));
                if let Some(b) = branches {
                    println!("    Branches: {}", b.join(", "));
                }
            }
            DelegationTarget::Aws { role_arns } => {
                println!("  AWS:");
                println!("    Roles:    {}", role_arns.join(", "));
            }
            DelegationTarget::Ssh { principals, hosts } => {
                println!("  SSH:");
                println!("    Principals: {}", principals.join(", "));
                if let Some(h) = hosts {
                    println!("    Hosts:      {}", h.join(", "));
                }
            }
        }
    }

    if !d.recent_uses.is_empty() {
        println!();
        println!("{}", "Recent uses:".bold());
        for u in d.recent_uses.iter().take(10) {
            println!("  {} - {} ({})", u.timestamp, u.action, u.target);
        }
    }

    Ok(())
}
