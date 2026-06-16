// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Locale-agnostic Fluent i18n core for the Vouch workspace.
//!
//! Three helpers shared by the server, CLI, and agent:
//!
//! - [`build_loader`] constructs a [`FluentLanguageLoader`] with isolation
//!   disabled (LTR catalogs only until an RTL language ships).
//! - [`select_loader`] picks a sub-loader for a list of requested languages,
//!   falling back to the loader's fallback language when none match.
//! - [`validate_startup`] refuses to launch if the embedded fallback catalog
//!   is missing or yields raw message ids for required keys.
//!
//! Each binary owns its own `Localizations` `RustEmbed` struct (one
//! `i18n/<lang>/<domain>.ftl` per shipped language), its own process-wide
//! `LOADER`, and its own request-scoped or process-scoped context wrapper.
//! This crate intentionally has no Axum, no HTTP, and no global state — it
//! plugs into whatever ambient-access pattern the binary uses (task-local,
//! `OnceLock`, threaded parameter).

use i18n_embed::I18nAssets;
use i18n_embed::LanguageLoader;
use i18n_embed::fluent::{FluentLanguageLoader, NegotiationStrategy};
use unic_langid::{LanguageIdentifier, langid};

pub use i18n_embed;
pub use unic_langid;

/// Build a process-wide [`FluentLanguageLoader`] for the given Fluent
/// `domain`, loading every available catalog from `assets`.
///
/// Isolation is disabled: Fluent's default behavior wraps every interpolated
/// value in invisible U+2068/U+2069 bidi marks, which leak into copy-paste
/// and version strings for LTR-only catalogs. Re-enable when an RTL language
/// ships and add BiDi-aware tests.
///
/// Catalog load failures are logged and the loader is returned with whatever
/// catalogs did parse — startup health is verified separately by
/// [`validate_startup`].
pub fn build_loader(
    domain: &'static str,
    fallback: LanguageIdentifier,
    assets: &dyn I18nAssets,
) -> FluentLanguageLoader {
    let loader = FluentLanguageLoader::new(domain, fallback);
    if let Err(error) = loader.load_available_languages(assets) {
        tracing::error!(%error, domain, "failed to load i18n catalogs");
    }
    loader.set_use_isolating(false);
    loader
}

/// Derive a sub-loader for the requested languages from the process-wide
/// `loader`. If `requested` is empty, the loader's fallback language is
/// selected so callers always get a usable [`FluentLanguageLoader`].
///
/// The returned loader shares catalog data with `loader` via `Arc`; selecting
/// is cheap.
pub fn select_loader(
    loader: &FluentLanguageLoader,
    requested: &[LanguageIdentifier],
) -> FluentLanguageLoader {
    if requested.is_empty() {
        loader.select_languages(&[loader.fallback_language().clone()])
    } else {
        loader.select_languages_negotiate(requested, NegotiationStrategy::Filtering)
    }
}

/// Verify the embedded catalogs are healthy and refuse to start otherwise.
///
/// Catches three packaging mistakes that would otherwise let a binary boot
/// with broken localization and render raw Fluent message ids in user-facing
/// output:
///
/// 1. The fallback `en-US` catalog is missing from `assets`.
/// 2. The fallback catalog failed to parse, so every lookup echoes the id.
/// 3. A required message id is missing from the catalog.
///
/// Call this once during startup, **before** any user-facing output. Binaries
/// pair it with their own bundle-warm-up or task-local install as needed.
///
/// # Errors
///
/// Returns `Err` when any of the conditions above are detected.
pub fn validate_startup(
    loader: &FluentLanguageLoader,
    assets: &dyn I18nAssets,
    required_ids: &[&str],
) -> anyhow::Result<()> {
    use anyhow::Context;
    let available = loader
        .available_languages(assets)
        .context("failed to enumerate embedded i18n catalogs")?;
    anyhow::ensure!(
        available.contains(&langid!("en-US")),
        "embedded i18n catalog en-US is missing; refusing to start"
    );
    let fallback = select_loader(loader, &[]);
    for id in required_ids {
        let probe = fallback.get(id);
        // `FluentLanguageLoader::get` returns `"No localization for id:
        // \"{id}\""` when the key is absent from every bundle and echoes the
        // raw id when the bundle is empty — guard both.
        anyhow::ensure!(
            !probe.starts_with("No localization for id") && probe != *id,
            "i18n catalog missing required key `{id}`; refusing to start"
        );
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code may panic on setup failure"
)]
mod tests {
    use super::*;

    #[derive(rust_embed::RustEmbed)]
    #[folder = "test-i18n/"]
    struct TestAssets;

    fn test_loader() -> FluentLanguageLoader {
        build_loader("vouch_i18n", langid!("en-US"), &TestAssets)
    }

    #[test]
    fn build_loader_loads_available_catalogs() {
        let loader = test_loader();
        let langs = loader.available_languages(&TestAssets).unwrap();
        assert!(langs.contains(&langid!("en-US")));
    }

    #[test]
    fn select_loader_with_empty_request_picks_fallback() {
        let loader = test_loader();
        let selected = select_loader(&loader, &[]);
        assert_eq!(selected.current_language(), langid!("en-US"));
    }

    #[test]
    fn select_loader_with_unknown_request_falls_back() {
        let loader = test_loader();
        let selected = select_loader(&loader, &[langid!("zz-ZZ")]);
        assert_eq!(selected.current_language(), langid!("en-US"));
    }

    #[test]
    fn validate_startup_passes_with_known_key() {
        let loader = test_loader();
        validate_startup(&loader, &TestAssets, &["probe-key"]).unwrap();
    }

    #[test]
    fn validate_startup_fails_when_required_key_missing() {
        let loader = test_loader();
        let err = validate_startup(&loader, &TestAssets, &["does-not-exist"]).unwrap_err();
        assert!(
            err.to_string().contains("does-not-exist"),
            "error should name the missing key: {err}"
        );
    }
}
