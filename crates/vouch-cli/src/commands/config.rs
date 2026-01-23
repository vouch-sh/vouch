//! Configuration helpers for git and AWS integration

use anyhow::{Context, Result};
use colored::Colorize;
use std::process::Command;

pub async fn git_config(global: bool) -> Result<()> {
    let vouch_path = std::env::current_exe()
        .context("failed to get vouch executable path")?;
    
    let vouch_path = vouch_path.to_string_lossy();
    let credential_helper = format!("!{} git-credential", vouch_path);

    let scope = if global { "--global" } else { "--local" };

    // Configure git to use vouch as credential helper
    let status = Command::new("git")
        .args(["config", scope, "credential.helper", &credential_helper])
        .status()
        .context("failed to run git config")?;

    if !status.success() {
        anyhow::bail!("git config failed");
    }

    println!("{}", "✓ Git credential helper configured".green());
    println!();
    
    if global {
        println!("  Scope: global (~/.gitconfig)");
    } else {
        println!("  Scope: local (.git/config)");
    }
    
    println!();
    println!("Git will now use vouch for authentication.");
    println!("Make sure the vouch agent is running: {}", "vouch agent start".cyan());

    Ok(())
}

pub async fn aws_config(profile: String, role_arn: String) -> Result<()> {
    let vouch_path = std::env::current_exe()
        .context("failed to get vouch executable path")?;
    
    let vouch_path = vouch_path.to_string_lossy();
    let credential_process = format!("{} get aws --role {} --format json", vouch_path, role_arn);

    // Get AWS config path
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let config_path = format!("{}/.aws/config", home);

    println!("{}", "AWS credential_process configuration:".bold());
    println!();
    println!("Add the following to {}:", config_path.cyan());
    println!();
    println!("[profile {}]", profile);
    println!("credential_process = {}", credential_process);
    println!();
    println!("{}", "Note:".yellow());
    println!("  This requires AWS CLI v2 or boto3 >= 1.14.0");
    println!();
    println!("Test with: {}", format!("aws --profile {} sts get-caller-identity", profile).cyan());

    Ok(())
}
