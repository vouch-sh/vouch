// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Internationalization (i18n) for the agent daemon.
//!
//! Mirrors the CLI's shape (`OnceLock<I18nContext>`, `tr!()` /
//! `tr_args!()` / `tr_println!()` / `tr_eprintln!()` macros), scoped down
//! to the small set of operator-visible strings the agent emits when
//! invoked directly (`--status`, `--stop`, `--foreground` errors).
//!
//! Background daemon `tracing` logs stay English — they target operators
//! and developers, not end users.

use std::sync::OnceLock;

use i18n_embed::fluent::FluentLanguageLoader;
use unic_langid::{LanguageIdentifier, langid};

/// Embedded Fluent catalogs, one `i18n/<lang>/vouch-agent.ftl` per language.
#[derive(rust_embed::RustEmbed)]
#[folder = "i18n/"]
struct Localizations;

/// Process-wide loader holding every embedded catalog. Built once.
pub(crate) static LOADER: std::sync::LazyLock<FluentLanguageLoader> =
    std::sync::LazyLock::new(|| {
        vouch_i18n::build_loader("vouch-agent", langid!("en-US"), &Localizations)
    });

/// Process-wide negotiated context. Installed exactly once by [`init`].
static I18N: OnceLock<I18nContext> = OnceLock::new();

/// Required message ids that must resolve at startup — packaging guard.
const REQUIRED_IDS: &[&str] = &["agent-running", "agent-not-running"];

/// Agent translation context. Wraps a selected [`FluentLanguageLoader`] and
/// caches the negotiated BCP-47 tag.
#[derive(Clone)]
pub struct I18nContext {
    loader: std::sync::Arc<FluentLanguageLoader>,
}

impl I18nContext {
    fn from_loader(loader: FluentLanguageLoader) -> Self {
        Self {
            loader: std::sync::Arc::new(loader),
        }
    }

    /// Borrow the underlying loader; used by the `tr!` / `tr_args!`
    /// macros via [`i18n_embed_fl::fl!`]. Not a stable consumer API.
    #[doc(hidden)]
    pub fn loader(&self) -> &FluentLanguageLoader {
        &self.loader
    }
}

/// Resolve the user's preferred locale once and install it.
///
/// # Errors
///
/// Returns the underlying [`vouch_i18n::validate_startup`] error if the
/// embedded `en-US` catalog is missing or any [`REQUIRED_IDS`] key fails to
/// resolve.
pub fn init() -> anyhow::Result<()> {
    vouch_i18n::validate_startup(&LOADER, &Localizations, REQUIRED_IDS)?;
    let lang = negotiate();
    let langs: Vec<LanguageIdentifier> = lang.into_iter().collect();
    let loader = vouch_i18n::select_loader(&LOADER, &langs);
    let ctx = I18nContext::from_loader(loader);
    if I18N.set(ctx).is_err() {
        tracing::debug!("vouch_agent::i18n::init called more than once; ignoring later call");
    }
    Ok(())
}

/// Borrow the process-wide [`I18nContext`], falling back to en-US if
/// [`init`] hasn't run yet (so panic-path `tr!()` never crashes).
pub fn ctx() -> I18nContext {
    if let Some(ctx) = I18N.get() {
        return ctx.clone();
    }
    let loader = vouch_i18n::select_loader(&LOADER, &[]);
    I18nContext::from_loader(loader)
}

/// Negotiate the preferred locale from environment + OS default.
fn negotiate() -> Option<LanguageIdentifier> {
    let env = |key: &str| std::env::var(key).ok();
    let candidates = [
        env("VOUCH_LANG"),
        env("LC_ALL"),
        env("LC_MESSAGES"),
        env("LANG"),
        sys_locale::get_locale(),
    ];
    for raw in candidates.into_iter().flatten() {
        let trimmed = raw
            .split(['.', '@'])
            .next()
            .unwrap_or(&raw)
            .replace('_', "-");
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(lang) = trimmed.parse::<LanguageIdentifier>() {
            return Some(lang);
        }
    }
    None
}

/// Translate a message id with no arguments.
#[macro_export]
macro_rules! tr {
    ($id:literal) => {{
        let __ctx = $crate::i18n::ctx();
        ::i18n_embed_fl::fl!(__ctx.loader(), $id)
    }};
}

/// Translate a message id with Fluent placeable arguments. Values are
/// forwarded to Fluent via `Into<FluentValue>`: integer/float primitives
/// become `FluentValue::Number` (engaging CLDR plural arms), string types
/// (`&str`, `String`, `&String`, `Cow<str>`) become `FluentValue::String`.
/// Anything else (`bool`, `Path::Display`, `anyhow::Error`, raw identifiers
/// like a PID that should not be locale-grouped, …) must be stringified at
/// the call site with `.to_string()` or `format!()`.
#[macro_export]
macro_rules! tr_args {
    ($id:literal, $($name:ident = $value:expr),+ $(,)?) => {{
        let __ctx = $crate::i18n::ctx();
        ::i18n_embed_fl::fl!(__ctx.loader(), $id, $($name = $value),+)
    }};
}

/// Print a translated message to stdout.
#[macro_export]
macro_rules! tr_println {
    ($id:literal) => { println!("{}", $crate::tr!($id)) };
    ($id:literal, $($name:ident = $value:expr),+ $(,)?) => {
        println!("{}", $crate::tr_args!($id, $($name = $value),+))
    };
}

/// Print a translated message to stderr.
#[macro_export]
macro_rules! tr_eprintln {
    ($id:literal) => { eprintln!("{}", $crate::tr!($id)) };
    ($id:literal, $($name:ident = $value:expr),+ $(,)?) => {
        eprintln!("{}", $crate::tr_args!($id, $($name = $value),+))
    };
}
