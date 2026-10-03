// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cargo setup command.
//!
//! Configures Cargo to use Vouch for one private registry. The registry's index URL
//! and ID token audience are recorded in the Vouch config, because Cargo passes the
//! credential provider only the index URL.

use anyhow::{Result, bail};
use vouch_cli::{tr, tr_args, tr_println};

use crate::config::{CargoRegistriesConfig, Config};
use crate::install_path::resolve_install_path;
use crate::integrations::cargo::CargoConfig;

/// Clap value parser for `--audience`: an empty audience would make the server
/// default the token's `aud` to its own issuer.
pub(crate) fn parse_audience(value: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        return Err(tr!("arg-setup-cargo-audience-blank"));
    }
    Ok(value.to_string())
}

/// What `apply` did to the in-memory configs.
#[derive(Debug, PartialEq, Eq)]
enum Applied {
    /// Both configs already held this registry, index and audience.
    AlreadyConfigured,
    /// The provider and audience were written to the in-memory configs.
    Configured,
}

/// Run the Cargo setup command.
///
/// This command:
/// 1. Resolves the registry's index URL (`--index`, else the Cargo config)
/// 2. Shows the per-registry credential provider setting, or with `--configure`
///    writes it and records the index URL → audience pair in the Vouch config
///
/// # Arguments
/// * `registry` - Registry name in the Cargo config
/// * `audience` - `aud` the registry requires in the Vouch ID token
/// * `index` - Index URL, exactly as Cargo sends it; defaults to the Cargo config's `index`
/// * `configure` - If true, write the configuration; if false, just show instructions
pub(crate) async fn run(
    registry: &str,
    audience: &str,
    index: Option<&str>,
    configure: bool,
) -> Result<()> {
    tr_println!("setup-cargo-header");
    println!();

    let mut cargo_config = CargoConfig::load()?;
    let index_url = resolve_index(&cargo_config, registry, index)?;

    let vouch_path = resolve_install_path();
    let vouch_path_str = vouch_path.display().to_string();
    let command = [vouch_path_str.as_str()];

    if configure {
        // No context wrapper: Config::modify saves as well as loads, and each phase
        // already carries an accurate message.
        let mut applied = Applied::AlreadyConfigured;
        Config::modify(|vouch_config| {
            applied = apply(
                &mut cargo_config,
                vouch_config,
                registry,
                audience,
                &index_url,
                &command,
            );
        })?;
        match applied {
            Applied::AlreadyConfigured => {
                tr_println!(
                    "setup-cargo-already-registry",
                    name = registry,
                    audience = audience
                );
                println!();
                tr_println!(
                    "setup-cargo-config-file",
                    path = cargo_config.path().display().to_string()
                );
            }
            Applied::Configured => {
                cargo_config.save()?;
                tr_println!(
                    "setup-cargo-audience-recorded",
                    audience = audience,
                    index = index_url.as_str()
                );
                tr_println!("setup-cargo-configured-registry", name = registry);
                println!();
                tr_println!(
                    "setup-cargo-config-added",
                    path = cargo_config.path().display().to_string()
                );
            }
        }
    } else {
        tr_println!(
            "setup-cargo-instructions-specific",
            registry = registry,
            index = index_url.as_str(),
            audience = audience,
            command = CargoConfig::command_to_array(&command).to_string(),
        );
    }

    println!();
    tr_println!("setup-cargo-more-info");

    Ok(())
}

/// Resolve the registry's normalized index URL from `--index`, else the Cargo config.
///
/// `--index` must not replace a different index already set for the registry.
fn resolve_index(
    cargo_config: &CargoConfig,
    registry: &str,
    index: Option<&str>,
) -> Result<String> {
    let existing = cargo_config.get_registry_index(registry);
    let normalize = |url: &str| {
        CargoRegistriesConfig::normalize_index(url)
            .ok_or_else(|| anyhow::anyhow!(tr_args!("setup-cargo-invalid-index", index = url)))
    };

    match (index, existing) {
        (Some(given), Some(existing)) => {
            let given_url = normalize(given)?;
            if given_url != normalize(&existing)? {
                bail!(tr_args!(
                    "setup-cargo-index-conflict",
                    registry = registry,
                    existing = existing.as_str(),
                    given = given,
                ));
            }
            Ok(given_url)
        }
        (Some(url), None) => normalize(url),
        (None, Some(url)) => normalize(&url),
        (None, None) => bail!(tr_args!(
            "setup-cargo-no-index",
            registry = registry,
            path = cargo_config.path().display().to_string(),
        )),
    }
}

/// Record the audience and provider in the in-memory configs.
///
/// Writes nothing when the Cargo registry already names exactly this provider and
/// index and the Vouch config holds this audience; otherwise it rewrites, which
/// repairs a stale binary path or a missing index. The caller saves the Cargo
/// config; the Vouch config is saved by `Config::modify`.
fn apply(
    cargo_config: &mut CargoConfig,
    vouch_config: &mut Config,
    registry: &str,
    audience: &str,
    index_url: &str,
    command: &[&str],
) -> Applied {
    let index_present = cargo_config
        .get_registry_index(registry)
        .and_then(|index| CargoRegistriesConfig::normalize_index(&index))
        .is_some_and(|index| index == index_url);
    if vouch_config.cargo_registry_audience(index_url) == Some(audience)
        && cargo_config.has_registry_provider(registry, command)
        && index_present
    {
        return Applied::AlreadyConfigured;
    }

    vouch_config.set_cargo_registry_audience(index_url, audience);
    if !index_present {
        cargo_config.set_registry_index(registry, index_url);
    }
    cargo_config.set_registry_provider(registry, command);
    Applied::Configured
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    const INDEX: &str = "sparse+https://crates.example.com/";
    const COMMAND: &[&str] = &["/usr/local/bin/vouch"];

    fn cargo_config(content: &str) -> (tempfile::TempDir, CargoConfig) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, content).unwrap();
        let config = CargoConfig::load_from(path).unwrap();
        (dir, config)
    }

    fn with_index() -> (tempfile::TempDir, CargoConfig) {
        cargo_config(&format!("[registries.my-reg]\nindex = \"{INDEX}\"\n"))
    }

    #[test]
    fn test_parse_audience() {
        assert_eq!(parse_audience("crates-example").unwrap(), "crates-example");
        assert!(parse_audience("").is_err());
        assert!(parse_audience("  \t").is_err());
    }

    #[test]
    fn test_index_comes_from_cargo_config() {
        let (_dir, config) = with_index();
        assert_eq!(resolve_index(&config, "my-reg", None).unwrap(), INDEX);
    }

    #[test]
    fn test_index_flag_wins_when_the_config_has_none() {
        let (_dir, config) = cargo_config("");
        assert_eq!(
            resolve_index(&config, "my-reg", Some("sparse+https://Other.example.com")).unwrap(),
            "sparse+https://other.example.com/"
        );
    }

    #[test]
    fn test_index_flag_may_repeat_the_existing_index_in_another_spelling() {
        let (_dir, config) = with_index();
        let resolved = resolve_index(&config, "my-reg", Some("sparse+https://CRATES.example.com"));
        assert_eq!(resolved.unwrap(), INDEX);
    }

    #[test]
    fn test_missing_index_is_an_error() {
        let (_dir, config) = cargo_config("");
        let error = resolve_index(&config, "my-reg", None).unwrap_err();
        assert!(error.to_string().contains("--index"), "{error}");
    }

    #[test]
    fn test_conflicting_index_is_an_error_naming_both() {
        let (_dir, config) = with_index();
        let error = resolve_index(&config, "my-reg", Some("sparse+https://other.example.com/"))
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains(INDEX), "{message}");
        assert!(message.contains("https://other.example.com/"), "{message}");
    }

    #[test]
    fn test_invalid_index_is_an_error() {
        let (_dir, config) = cargo_config("");
        assert!(resolve_index(&config, "my-reg", Some("not a url")).is_err());
    }

    #[test]
    fn test_git_index_keeps_its_scheme() {
        let (_dir, config) = cargo_config("");
        let git = "https://github.com/example/index";
        assert_eq!(resolve_index(&config, "my-reg", Some(git)).unwrap(), git);
    }

    #[test]
    fn test_apply_writes_both_configs_and_is_idempotent() {
        let (dir, mut cargo) = with_index();
        let mut vouch = Config::default();

        let first = apply(&mut cargo, &mut vouch, "my-reg", "aud", INDEX, COMMAND);
        assert_eq!(first, Applied::Configured);
        cargo.save().unwrap();

        assert_eq!(vouch.cargo_registry_audience(INDEX), Some("aud"));
        let reloaded = CargoConfig::load_from(dir.path().join("config.toml")).unwrap();
        assert!(reloaded.has_registry_vouch("my-reg"));
        assert_eq!(
            reloaded.get_registry_index("my-reg").as_deref(),
            Some(INDEX)
        );

        let second = apply(&mut cargo, &mut vouch, "my-reg", "aud", INDEX, COMMAND);
        assert_eq!(second, Applied::AlreadyConfigured);
    }

    #[test]
    fn test_apply_records_a_new_index_for_a_registry_without_one() {
        let (_dir, mut cargo) = cargo_config("");
        let mut vouch = Config::default();

        apply(&mut cargo, &mut vouch, "my-reg", "aud", INDEX, COMMAND);

        assert_eq!(cargo.get_registry_index("my-reg").as_deref(), Some(INDEX));
    }

    #[test]
    fn test_apply_rewrites_when_the_audience_changed() {
        let (_dir, mut cargo) = with_index();
        let mut vouch = Config::default();
        apply(&mut cargo, &mut vouch, "my-reg", "old", INDEX, COMMAND);

        let outcome = apply(&mut cargo, &mut vouch, "my-reg", "new", INDEX, COMMAND);

        assert_eq!(outcome, Applied::Configured);
        assert_eq!(vouch.cargo_registry_audience(INDEX), Some("new"));
    }

    #[test]
    fn test_apply_adds_the_provider_when_missing() {
        let (_dir, mut cargo) = with_index();
        let mut vouch = Config::default();
        vouch.set_cargo_registry_audience(INDEX, "aud");
        assert!(!cargo.has_registry_vouch("my-reg"));

        let outcome = apply(&mut cargo, &mut vouch, "my-reg", "aud", INDEX, COMMAND);

        assert_eq!(outcome, Applied::Configured);
        assert!(cargo.has_registry_vouch("my-reg"));
    }

    #[test]
    fn test_apply_rewrites_a_stale_binary_path() {
        let (_dir, mut cargo) = with_index();
        let mut vouch = Config::default();
        apply(
            &mut cargo,
            &mut vouch,
            "my-reg",
            "aud",
            INDEX,
            &["/old/vouch"],
        );

        let outcome = apply(&mut cargo, &mut vouch, "my-reg", "aud", INDEX, COMMAND);

        assert_eq!(outcome, Applied::Configured);
        assert!(cargo.has_registry_provider("my-reg", COMMAND));
    }

    #[test]
    fn test_apply_rewrites_a_missing_index() {
        let (_dir, mut cargo) =
            cargo_config("[registries.my-reg]\ncredential-provider = [\"/usr/local/bin/vouch\"]\n");
        let mut vouch = Config::default();
        vouch.set_cargo_registry_audience(INDEX, "aud");

        let outcome = apply(&mut cargo, &mut vouch, "my-reg", "aud", INDEX, COMMAND);

        assert_eq!(outcome, Applied::Configured);
        assert_eq!(cargo.get_registry_index("my-reg").as_deref(), Some(INDEX));
    }

    #[test]
    fn test_apply_records_the_audience_when_a_legacy_provider_is_already_set() {
        let (_dir, mut cargo) = cargo_config(&format!(
            "[registries.my-reg]\nindex = \"{INDEX}\"\ncredential-provider = [\"/usr/local/bin/vouch\", \"credential\", \"cargo\", \"--\"]\n"
        ));
        let mut vouch = Config::default();

        let outcome = apply(&mut cargo, &mut vouch, "my-reg", "aud", INDEX, COMMAND);

        assert_eq!(outcome, Applied::Configured);
        assert_eq!(vouch.cargo_registry_audience(INDEX), Some("aud"));
    }
}
