// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Internationalization (i18n) for the CLI.
//!
//! All `i18n-embed` / Fluent usage is confined to this module behind the
//! [`tr!`] / [`tr_args!`] / [`tr_println!`] / [`tr_eprintln!`] macros. Call
//! sites never reference `i18n-embed` types — keeping the translation backend
//! swappable in one place.
//!
//! Locale is resolved exactly once at process start in [`init`] (which calls
//! [`validate_startup`]) and cached in [`I18N`]. Resolution order:
//!
//! 1. `--lang <BCP-47>` global CLI flag
//! 2. `VOUCH_LANG` environment variable
//! 3. `LC_ALL` → `LC_MESSAGES` → `LANG`
//! 4. OS default via [`sys_locale::get_locale`]
//! 5. `en-US` fallback
//!
//! Because [`tr!`] expressions are embedded directly in clap derive
//! attributes (`#[command(about = tr!(...))]`), [`init`] must run *before*
//! `Cli::parse()`. A small [`preresolve_lang_from_argv_and_env`] pre-scan
//! reads `--lang` straight from `argv` so the locale is known before clap
//! does any work.

use std::ffi::OsStr;
use std::sync::OnceLock;

use i18n_embed::LanguageLoader;
use i18n_embed::fluent::FluentLanguageLoader;
use unic_langid::{LanguageIdentifier, langid};

/// Embedded Fluent catalogs, one `i18n/<lang>/vouch_cli.ftl` per language.
#[derive(rust_embed::RustEmbed)]
#[folder = "i18n/"]
struct Localizations;

/// Process-wide loader holding every embedded catalog. Built once; never
/// mutated after [`init`] runs.
pub(crate) static LOADER: std::sync::LazyLock<FluentLanguageLoader> =
    std::sync::LazyLock::new(|| {
        vouch_i18n::build_loader("vouch-cli", langid!("en-US"), &Localizations)
    });

/// Process-wide negotiated context. Installed exactly once by [`init`].
static I18N: OnceLock<I18nContext> = OnceLock::new();

/// Required message ids that must resolve at startup — packaging guard. Add
/// new entries here when a new code path depends on a catalog key being
/// present.
const REQUIRED_IDS: &[&str] = &[
    "cli-about",
    "cli-long-about",
    "cli-after-help",
    "cli-lang-help",
    "cli-verbose-help",
    "cli-server-help",
    "cli-color-help",
];

/// CLI translation context. Wraps a selected [`FluentLanguageLoader`] and
/// caches the negotiated BCP-47 tag.
#[derive(Clone)]
pub struct I18nContext {
    loader: std::sync::Arc<FluentLanguageLoader>,
    lang: String,
}

impl I18nContext {
    fn from_loader(loader: FluentLanguageLoader) -> Self {
        let lang = loader.current_language().to_string();
        Self {
            loader: std::sync::Arc::new(loader),
            lang,
        }
    }

    /// BCP-47 tag of the negotiated language.
    pub fn lang(&self) -> &str {
        &self.lang
    }

    /// Borrow the underlying loader. Used by the [`crate::tr!`] /
    /// [`crate::tr_args!`] macros to call [`i18n_embed_fl::fl!`] against the
    /// negotiated locale; not a stable consumer API.
    #[doc(hidden)]
    pub fn loader(&self) -> &FluentLanguageLoader {
        &self.loader
    }
}

/// Resolve the user's preferred locale once and install it as the
/// process-wide [`I18nContext`].
///
/// # Errors
///
/// Returns the underlying [`vouch_i18n::validate_startup`] error if the
/// embedded `en-US` catalog is missing or any [`REQUIRED_IDS`] key fails to
/// resolve. Safe to call only once; later calls are no-ops.
pub fn init(requested: Option<LanguageIdentifier>) -> anyhow::Result<()> {
    vouch_i18n::validate_startup(&LOADER, &Localizations, REQUIRED_IDS)?;
    let langs: Vec<LanguageIdentifier> = requested.into_iter().collect();
    let loader = vouch_i18n::select_loader(&LOADER, &langs);
    let ctx = I18nContext::from_loader(loader);
    // Setting the OnceLock can only fail if `init` was called twice; a benign
    // double-init is a no-op rather than an error, so the second call drops
    // its built context and the first context wins.
    if I18N.set(ctx).is_err() {
        tracing::debug!("vouch_cli::i18n::init called more than once; ignoring later call");
    }
    Ok(())
}

/// Borrow the process-wide [`I18nContext`], falling back to a fresh
/// en-US-only context if [`init`] hasn't run. The fallback exists so a
/// `tr!()` call from a panic handler or early-init path never crashes — code
/// paths that depend on the user's negotiated locale must run after
/// [`init`].
pub fn ctx() -> I18nContext {
    if let Some(ctx) = I18N.get() {
        return ctx.clone();
    }
    let loader = vouch_i18n::select_loader(&LOADER, &[]);
    I18nContext::from_loader(loader)
}

/// Negotiate the preferred locale from CLI args (the value of `--lang`) and
/// the process environment. Pure: takes only borrowed inputs, touches no
/// globals.
///
/// Resolution order matches the module-level doc comment. Returns `None`
/// only when every source is empty or unparseable; callers fall back to the
/// loader's `en-US` default in that case.
pub fn negotiate(
    cli_lang: Option<&str>,
    env: impl Fn(&str) -> Option<String>,
    os_locale: impl Fn() -> Option<String>,
) -> Option<LanguageIdentifier> {
    let candidates = [
        cli_lang.map(str::to_owned),
        env("VOUCH_LANG"),
        env("LC_ALL"),
        env("LC_MESSAGES"),
        env("LANG"),
        os_locale(),
    ];
    for raw in candidates.into_iter().flatten() {
        // POSIX locale strings often carry `.UTF-8` or `@modifier` suffixes;
        // strip them so `en_US.UTF-8` parses as `en-US`.
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

/// Pre-scan `argv` for `--lang <value>` / `--lang=<value>` and fold in the
/// environment-based negotiation. This runs *before* `Cli::parse()` so the
/// locale is known when clap evaluates the `tr!()` expressions inside derive
/// attributes.
///
/// Only the `--lang` flag is recognized — any other argument is ignored.
/// `--` halts scanning so `vouch -- --lang foo` (for a passthrough command)
/// does not pick up `--lang` from the trailing args.
pub fn preresolve_lang_from_argv_and_env() -> Option<LanguageIdentifier> {
    let cli_lang = preresolve_cli_lang(std::env::args_os());
    negotiate(
        cli_lang.as_deref(),
        |key| std::env::var(key).ok(),
        sys_locale::get_locale,
    )
}

fn preresolve_cli_lang<I, S>(args: I) -> Option<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut iter = args.into_iter();
    // Skip the program name.
    let _ = iter.next();
    while let Some(raw) = iter.next() {
        let arg = raw.as_ref().to_str()?;
        if arg == "--" {
            return None;
        }
        if let Some(value) = arg.strip_prefix("--lang=") {
            return Some(value.to_owned());
        }
        if arg == "--lang" {
            return iter
                .next()
                .and_then(|next| next.as_ref().to_str().map(str::to_owned));
        }
    }
    None
}

/// Translate a message id with no arguments. Returns the locale-resolved
/// `String`; safe to embed directly in `clap` derive attributes (`about =
/// tr!("cli-about")`) because clap's `Arg::help` / `Command::about` accept
/// `impl IntoResettable<StyledStr>`, which is implemented for `String`.
///
/// The id is checked at *compile time* against the `en-US` catalog
/// (`crates/vouch-cli/i18n/en-US/vouch_cli.ftl`) via the
/// [`i18n_embed_fl::fl!`] macro — a typo or missing key fails the build, not
/// a startup probe. The runtime call uses the negotiated [`I18nContext`] so
/// the user's locale is honored.
#[macro_export]
macro_rules! tr {
    ($id:literal) => {{
        let __ctx = $crate::i18n::ctx();
        ::i18n_embed_fl::fl!(__ctx.loader(), $id)
    }};
}

/// Translate a message id with Fluent placeable arguments. `name = value`
/// pairs; each value is forwarded to Fluent via `Into<FluentValue>`, so the
/// dispatch matches `i18n-embed-fl`'s native contract:
///
/// - integer and float primitives become `FluentValue::Number`, engaging CLDR
///   plural categories so `{ $count -> [one] 1 account *[other] N accounts }`
///   selects the singular arm when `count = 1`.
/// - `&str`, `String`, `&String`, and `Cow<'_, str>` become
///   `FluentValue::String`, matched by exact variant-key equality (e.g. the
///   `[true]` / `[false]` arms used for boolean selectors).
/// - anything else (`bool`, `Path::Display`, `anyhow::Error`,
///   `reqwest::StatusCode`, jiff timestamps, identifiers like a PID that
///   should not be locale-grouped) must be stringified at the call site with
///   `.to_string()` or `format!()` — the compiler will tell you.
///
/// Same compile-time-check guarantee as [`tr!`] for both message id and
/// argument names.
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code may panic on setup failure"
)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }
    fn no_os_locale() -> Option<String> {
        None
    }

    #[test]
    fn cli_lang_wins_over_env() {
        let lang = negotiate(
            Some("fr-FR"),
            |k| (k == "VOUCH_LANG").then(|| "ja-JP".to_owned()),
            no_os_locale,
        )
        .unwrap();
        assert_eq!(lang.to_string(), "fr-FR");
    }

    #[test]
    fn vouch_lang_wins_over_lc_all() {
        let lang = negotiate(
            None,
            |k| match k {
                "VOUCH_LANG" => Some("ja-JP".to_owned()),
                "LC_ALL" => Some("fr-FR".to_owned()),
                _ => None,
            },
            no_os_locale,
        )
        .unwrap();
        assert_eq!(lang.to_string(), "ja-JP");
    }

    #[test]
    fn lc_all_wins_over_lc_messages_and_lang() {
        let lang = negotiate(
            None,
            |k| match k {
                "LC_ALL" => Some("fr-FR".to_owned()),
                "LC_MESSAGES" => Some("ja-JP".to_owned()),
                "LANG" => Some("de-DE".to_owned()),
                _ => None,
            },
            no_os_locale,
        )
        .unwrap();
        assert_eq!(lang.to_string(), "fr-FR");
    }

    #[test]
    fn lc_messages_wins_over_lang() {
        let lang = negotiate(
            None,
            |k| match k {
                "LC_MESSAGES" => Some("ja-JP".to_owned()),
                "LANG" => Some("de-DE".to_owned()),
                _ => None,
            },
            no_os_locale,
        )
        .unwrap();
        assert_eq!(lang.to_string(), "ja-JP");
    }

    #[test]
    fn lang_wins_over_os_locale() {
        let lang = negotiate(
            None,
            |k| (k == "LANG").then(|| "ja-JP".to_owned()),
            || Some("de-DE".to_owned()),
        )
        .unwrap();
        assert_eq!(lang.to_string(), "ja-JP");
    }

    #[test]
    fn os_locale_used_when_env_empty() {
        let lang = negotiate(None, no_env, || Some("ja-JP".to_owned())).unwrap();
        assert_eq!(lang.to_string(), "ja-JP");
    }

    #[test]
    fn posix_locale_suffix_stripped() {
        let lang = negotiate(None, |_| Some("en_US.UTF-8".to_owned()), no_os_locale).unwrap();
        assert_eq!(lang.to_string(), "en-US");
    }

    #[test]
    fn posix_locale_modifier_stripped() {
        let lang = negotiate(None, |_| Some("ca_ES@valencia".to_owned()), no_os_locale).unwrap();
        // unic-langid accepts ca-ES; modifier was dropped.
        assert!(lang.to_string().starts_with("ca-ES"));
    }

    #[test]
    fn unparseable_falls_through() {
        let lang = negotiate(Some("not-a-locale!!!"), no_env, || Some("ja-JP".to_owned())).unwrap();
        assert_eq!(lang.to_string(), "ja-JP");
    }

    #[test]
    fn empty_everywhere_returns_none() {
        assert!(negotiate(None, no_env, no_os_locale).is_none());
    }

    #[test]
    fn preresolve_cli_lang_space_form() {
        let argv: Vec<&OsStr> = ["vouch", "--lang", "fr-FR", "enroll"]
            .iter()
            .map(OsStr::new)
            .collect();
        assert_eq!(preresolve_cli_lang(argv), Some("fr-FR".to_owned()));
    }

    #[test]
    fn preresolve_cli_lang_equals_form() {
        let argv: Vec<&OsStr> = ["vouch", "--lang=fr-FR", "enroll"]
            .iter()
            .map(OsStr::new)
            .collect();
        assert_eq!(preresolve_cli_lang(argv), Some("fr-FR".to_owned()));
    }

    #[test]
    fn preresolve_cli_lang_stops_at_double_dash() {
        let argv: Vec<&OsStr> = ["vouch", "--", "--lang", "fr-FR"]
            .iter()
            .map(OsStr::new)
            .collect();
        assert_eq!(preresolve_cli_lang(argv), None);
    }

    #[test]
    fn preresolve_cli_lang_absent_returns_none() {
        let argv: Vec<&OsStr> = ["vouch", "enroll"].iter().map(OsStr::new).collect();
        assert_eq!(preresolve_cli_lang(argv), None);
    }

    #[test]
    fn validate_startup_passes_with_embedded_catalog() {
        vouch_i18n::validate_startup(&LOADER, &Localizations, REQUIRED_IDS).unwrap();
    }

    #[test]
    fn cli_about_resolves() {
        let loader = vouch_i18n::select_loader(&LOADER, &[]);
        let about = loader.get("cli-about");
        assert!(
            !about.starts_with("No localization") && about != "cli-about",
            "cli-about should resolve to a string, got {about:?}"
        );
    }

    /// Walk the catalog: every multi-segment lowercase kebab-case key parsed
    /// from `vouch-cli.ftl` must resolve at startup. Mirrors the server's
    /// `every_template_key_is_defined` test and catches typos that
    /// [`REQUIRED_IDS`] doesn't cover. The cost is one runtime probe per id;
    /// when the catalog grows past a thousand keys, switch this to a
    /// compile-time check via `fl!()` only.
    #[test]
    fn every_catalog_key_resolves() {
        let ftl = std::fs::read_to_string(format!(
            "{}/i18n/en-US/vouch-cli.ftl",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let loader = vouch_i18n::select_loader(&LOADER, &[]);
        for line in ftl.lines() {
            if line.trim_start() != line {
                continue;
            }
            let Some((left, _)) = line.split_once('=') else {
                continue;
            };
            let id = left.trim();
            if id.is_empty() {
                continue;
            }
            // Fluent terms (e.g. `-yubikey`) start with `-` and are only
            // reachable via `{ -term }` references inside other messages —
            // never via `loader.get()`. Skip them.
            if id.starts_with('-') {
                continue;
            }
            if !id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                continue;
            }
            if !id.contains('-') {
                continue;
            }
            let resolved = loader.get(id);
            assert!(
                !resolved.starts_with("No localization for id"),
                "catalog id `{id}` does not resolve",
            );
        }
    }

    /// Locks in the contract that numeric arg values flow through
    /// `FluentValue::Number`, so CLDR plural rules pick `[one]` for count = 1
    /// and `*[other]` for count = 2. The bug this guards against: a previous
    /// `tr_args!` macro stringified every value, so `[one]` never matched and
    /// summary lines always read "1 accounts".
    #[test]
    fn aws_accounts_summary_singular_plural() {
        let singular = crate::tr_args!("aws-accounts-summary", count = 1_usize);
        assert!(
            singular.contains("1 account") && !singular.contains("accounts"),
            "count = 1 should pick the [one] arm, got {singular:?}"
        );
        let plural = crate::tr_args!("aws-accounts-summary", count = 2_usize);
        assert!(
            plural.contains("2 accounts"),
            "count = 2 should pick the [other] arm, got {plural:?}"
        );
    }

    /// Locks in the contract that `bool.to_string()` produces strings that
    /// match the FTL's explicit `[true]` / `[false]` variant arms.
    #[test]
    fn github_app_configured_boolean_arms() {
        let yes = crate::tr_args!("setup-github-app-configured", configured = true.to_string());
        assert!(yes.contains("Yes"), "true should pick [true], got {yes:?}");
        let no = crate::tr_args!(
            "setup-github-app-configured",
            configured = false.to_string()
        );
        assert!(no.contains("No"), "false should pick [false], got {no:?}");
    }
}
