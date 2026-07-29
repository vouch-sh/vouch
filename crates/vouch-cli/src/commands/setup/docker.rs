// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Docker setup command.
//!
//! Configures Docker to use Vouch for container registry authentication.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vouch_cli::{tr, tr_args, tr_println};

use crate::config::Config;
use crate::install_path::resolve_install_path;
use crate::integrations::aws::{ProfileOverride, resolve_vouch_profile};

/// Docker config.json structure (partial).
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct DockerConfig {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    cred_helpers: HashMap<String, String>,
    #[serde(flatten)]
    other: serde_json::Map<String, serde_json::Value>,
}

/// Run the Docker setup command.
///
/// This command:
/// 1. Checks if the user is logged in
/// 2. Creates symlink for docker-credential-vouch
/// 3. Optionally configures ~/.docker/config.json
///
/// # Arguments
/// * `registries` - Registry URLs to configure (e.g., "ghcr.io", "123456789012.dkr.ecr.us-east-1.amazonaws.com")
/// * `configure` - If true, automatically configure Docker; if false, just show instructions
/// * `profile` - AWS profile whose role mints ECR credentials for these registries
pub(crate) async fn run(
    registries: &[String],
    configure: bool,
    profile: Option<&str>,
) -> Result<()> {
    // Load config to verify enrollment
    let config = Config::load().with_context(|| tr!("setup-err-load-config"))?;
    let _server = config
        .server_url()
        .with_context(|| tr!("setup-err-not-configured"))?;

    tr_println!("setup-docker-header");
    println!();

    // Get vouch binary path
    let vouch_path = resolve_install_path();

    // Determine where to create the symlink
    let symlink_path = crate::utils::vouch_helper_path("docker-credential-vouch")?;

    // The anchor lives in Vouch's own config, so record it on both paths —
    // the manual-instructions path still ends with Docker calling the helper,
    // which has no other way to learn which account a registry belongs to.
    anchor_registries_to_profile(registries, profile)?;

    if configure {
        // Create symlink
        create_credential_helper_symlink(&vouch_path, &symlink_path)?;

        // Configure Docker if registries provided
        if !registries.is_empty() {
            configure_docker_config(registries)?;
        }

        tr_println!("setup-docker-configured");
        println!();

        if registries.is_empty() {
            tr_println!("setup-docker-no-registries-add");
            print_example_config();
        } else {
            tr_println!("setup-docker-configured-registries-header");
            for registry in registries {
                tr_println!(
                    "setup-docker-registry-line",
                    indent = "  ",
                    registry = registry
                );
            }
        }
    } else {
        // Show manual instructions
        tr_println!(
            "setup-docker-step1-block",
            vouch_path = vouch_path.display().to_string(),
            symlink_path = symlink_path.display().to_string(),
        );
        println!();

        tr_println!("setup-docker-step2-header");
        print_example_config();

        println!();
        tr_println!("setup-docker-tail-block");
    }

    println!();
    tr_println!("setup-docker-supported-block");

    Ok(())
}

/// Record which AWS profile mints credentials for each ECR registry.
///
/// Docker execs `docker-credential-vouch` with no arguments, so this anchor is
/// the only way the helper can tell which account a registry belongs to when
/// more than one Vouch profile exists. Non-ECR registries (ghcr.io) need no
/// anchor and are skipped.
fn anchor_registries_to_profile(registries: &[String], profile: Option<&str>) -> Result<()> {
    let Some(profile) = profile else {
        return Ok(());
    };

    // Fail before writing if the profile is not usable, rather than leaving an
    // anchor that every later `docker push` would trip over.
    let resolved = resolve_vouch_profile(Some(profile), ProfileOverride::Profile)?;

    let ecr_registries: Vec<&String> = registries
        .iter()
        .filter(|r| {
            matches!(
                crate::commands::credential::docker::detect_registry_type(r),
                crate::commands::credential::docker::RegistryType::AwsEcr { .. }
            )
        })
        .collect();

    if ecr_registries.is_empty() {
        return Ok(());
    }

    // Config::modify performs both a load and a save; its internal context
    // already distinguishes the two (load errors via Config::load, save errors
    // via Config::save). Wrapping it with a load-focused message would be
    // misleading — the config already loaded successfully at the top of `run`,
    // so a failure here is far more likely to come from the save phase (e.g.
    // disk full, permissions) than from re-loading a file that just loaded.
    Config::modify(|config| {
        for registry in &ecr_registries {
            config.set_docker_registry_profile(registry, &resolved.name);
        }
    })?;

    for registry in ecr_registries {
        tr_println!(
            "setup-docker-anchored-profile",
            registry = registry.as_str(),
            profile = resolved.name.as_str(),
        );
    }

    Ok(())
}

/// Create the docker-credential-vouch symlink or wrapper script.
fn create_credential_helper_symlink(
    vouch_path: &std::path::Path,
    symlink_path: &std::path::Path,
) -> Result<()> {
    let batch_content = format!(
        "@echo off\r\n\"{}\" credential docker %1\r\n",
        vouch_path.display()
    );
    crate::utils::create_symlink_with_fallback(vouch_path, symlink_path, &batch_content)
}

/// Configure ~/.docker/config.json with the credential helper.
fn configure_docker_config(registries: &[String]) -> Result<()> {
    let home = dirs::home_dir().with_context(|| tr!("setup-err-no-home"))?;
    let docker_config_path = home.join(".docker/config.json");

    // Load existing config or create new
    let mut config: DockerConfig = if docker_config_path.exists() {
        let content = std::fs::read_to_string(&docker_config_path).with_context(|| {
            tr_args!(
                "setup-docker-err-read",
                path = docker_config_path.display().to_string()
            )
        })?;
        serde_json::from_str(&content).with_context(|| {
            tr_args!(
                "setup-docker-err-parse",
                path = docker_config_path.display().to_string()
            )
        })?
    } else {
        DockerConfig::default()
    };

    // Add registries
    for registry in registries {
        config
            .cred_helpers
            .insert(registry.clone(), "vouch".to_string());
    }

    // Ensure .docker directory exists
    if let Some(parent) = docker_config_path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent).with_context(|| {
            tr_args!(
                "setup-docker-err-create-dir",
                path = parent.display().to_string()
            )
        })?;
    }

    // Write config atomically to avoid corruption if interrupted
    let json =
        serde_json::to_string_pretty(&config).with_context(|| tr!("setup-docker-err-serialize"))?;
    vouch_common::fs::atomic_write(&docker_config_path, json.as_bytes()).with_context(|| {
        tr_args!(
            "setup-docker-err-write",
            path = docker_config_path.display().to_string()
        )
    })?;

    tr_println!(
        "setup-docker-updated-file",
        path = docker_config_path.display().to_string()
    );

    Ok(())
}

/// Print example Docker config.json.
///
/// JSON snippet: machine-readable, stays English so users can paste it
/// verbatim into `~/.docker/config.json`.
fn print_example_config() {
    println!("  {{");
    println!("    \"credHelpers\": {{");
    println!("      \"ghcr.io\": \"vouch\",");
    println!("      \"123456789012.dkr.ecr.us-east-1.amazonaws.com\": \"vouch\"");
    println!("    }}");
    println!("  }}");
}

/// Check if Docker credential helper is configured.
pub(crate) fn check_docker_config() -> DockerSetupStatus {
    // Check for symlink or batch file
    let symlink_exists =
        crate::utils::vouch_helper_path("docker-credential-vouch").is_ok_and(|p| {
            #[cfg(unix)]
            {
                p.exists() || p.is_symlink()
            }
            #[cfg(windows)]
            {
                // On Windows, check for the .bat file
                p.with_extension("bat").exists()
            }
        });

    // Check Docker config
    let configured_registries = get_configured_registries().unwrap_or_default();

    DockerSetupStatus {
        symlink_exists,
        configured_registries,
    }
}

/// Docker setup status.
pub(crate) struct DockerSetupStatus {
    pub symlink_exists: bool,
    pub configured_registries: Vec<String>,
}

/// Get registries configured to use vouch in Docker config.
fn get_configured_registries() -> Result<Vec<String>> {
    let home = dirs::home_dir().context(tr!("err-could-not-determine-home-directory"))?;
    let docker_config_path = home.join(".docker/config.json");

    if !docker_config_path.exists() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(&docker_config_path)?;
    let config: DockerConfig = serde_json::from_str(&content)?;

    let registries: Vec<String> = config
        .cred_helpers
        .iter()
        .filter(|(_, helper)| *helper == "vouch")
        .map(|(registry, _)| registry.clone())
        .collect();

    Ok(registries)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    /// Serialize tests that mutate `XDG_CONFIG_HOME` (process-wide env) so
    /// parallel test threads cannot observe each other's config-path
    /// redirection. `Mutex<()>` is permitted by the `mutex_atomic` lint
    /// (which only flags `Mutex<bool>`/`Mutex<integer>`).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The config dir that `Config::modify` creates under `XDG_CONFIG_HOME`.
    fn vouch_config_dir(tmp: &tempfile::TempDir) -> std::path::PathBuf {
        tmp.path().join("vouch")
    }

    /// Config::modify performs both a load AND a save. When the save phase
    /// fails (e.g. disk full, read-only filesystem), the error must surface a
    /// save-appropriate message — NOT the load-focused "failed to load config
    /// \- run 'vouch enroll' first" wrapper that `anchor_registries_to_profile`
    /// previously applied (and which this fix removed).
    ///
    /// This test calls `Config::modify` directly with the same mutation that
    /// `anchor_registries_to_profile` uses, and forces the save to fail by
    /// replacing the config directory with a regular file inside the closure
    /// (after load succeeds, before save runs). Replacing the directory with a
    /// file (rather than chmod 0o555) ensures the failure is deterministic
    /// even when the test runs as root, which bypasses permission checks. The
    /// resulting error chain is identical to what
    /// `anchor_registries_to_profile` propagates (it uses `?` with no extra
    /// wrapping).
    #[test]
    #[cfg(unix)]
    #[expect(
        unsafe_code,
        reason = "XDG_CONFIG_HOME mutation to isolate the config path; restored before assertion"
    )]
    fn save_failure_does_not_report_failed_to_load_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg_dir = vouch_config_dir(&tmp);

        // SAFETY: XDG_CONFIG_HOME is removed before the test returns,
        // regardless of assertion outcome.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", tmp.path());
        }

        // The closure replaces the vouch/ directory with a regular file so
        // that config.save() → atomic_write_secure → create_dir_all(parent)
        // fails with "Not a directory". Load has already succeeded by the
        // time the closure runs, so this deterministically isolates a
        // SAVE-phase failure.
        let result = Config::modify(|cfg| {
            cfg.set_docker_registry_profile(
                "123456789012.dkr.ecr.us-east-1.amazonaws.com",
                "vouch-demo",
            );
            let _removed: Result<(), std::io::Error> = std::fs::remove_dir_all(&cfg_dir);
            let _written: Result<(), std::io::Error> = std::fs::write(&cfg_dir, b"not a directory");
        });

        // SAFETY: env restored.
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }

        let err = result.expect_err("save should fail when config dir is a file");
        let msg = format!("{err:#}");
        assert!(
            !msg.contains("failed to load config"),
            "save-phase error must not say 'failed to load config': {msg}"
        );
        assert!(
            !msg.contains("enroll' first"),
            "save-phase error must not suggest enrolling: {msg}"
        );
        assert!(
            msg.contains("failed to write config"),
            "expected save-phase error ('failed to write config'), got: {msg}"
        );
    }

    /// When `Config::modify` fails during the LOAD phase (e.g. corrupt config
    /// file), the error must surface a load-appropriate message from
    /// `Config::load`'s own internal context — NOT the removed
    /// `setup-err-load-config` wrapper. This confirms the removal didn't
    /// discard useful load-error context.
    #[test]
    #[cfg(unix)]
    #[expect(
        unsafe_code,
        reason = "XDG_CONFIG_HOME mutation to isolate the config path; restored before assertion"
    )]
    fn load_failure_surfaces_parse_error_without_load_wrapper() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg_dir = vouch_config_dir(&tmp);
        std::fs::create_dir_all(&cfg_dir).expect("create vouch dir");
        // Write invalid JSON so Config::load's parse step fails.
        std::fs::write(cfg_dir.join("config.json"), "{ not valid json")
            .expect("write corrupt config");

        // SAFETY: XDG_CONFIG_HOME is removed before the test returns.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", tmp.path());
        }

        let result = Config::modify(|cfg| {
            cfg.set_docker_registry_profile("ghcr.io", "vouch-demo");
        });

        // SAFETY: env restored.
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }

        let err = result.expect_err("load should fail on corrupt config");
        let msg = format!("{err:#}");
        assert!(
            !msg.contains("enroll' first"),
            "load-phase error must not carry the old enroll-remediation wrapper: {msg}"
        );
        // Config::load wraps parse failures with err-failed-parse-config.
        assert!(
            msg.contains("failed to parse config"),
            "expected parse-related load error, got: {msg}"
        );
    }
}
