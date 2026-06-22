// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Internationalization (i18n) for the server UI.
//!
//! All `i18n-embed` / Fluent usage is confined to this module, behind
//! [`I18nContext`]. Templates, handlers, and JS string injection only ever call
//! the [`I18nContext`] methods — they never reference `i18n-embed` types. This
//! keeps the translation backend swappable in one place.
//!
//! Locale is negotiated per request from the `Accept-Language` header against
//! the embedded catalogs, falling back to `en-US`. The global [`struct@LOADER`]
//! is built once; each request derives a cheap, resource-sharing loader via
//! `select_languages_negotiate`, so there is no shared mutable locale state.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, LazyLock};

use axum::extract::FromRequestParts;
use axum::response::{IntoResponse, Response};
use http::request::Parts;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use i18n_embed::LanguageLoader;
use i18n_embed::fluent::FluentLanguageLoader;
use unic_langid::{LanguageIdentifier, langid};
use vouch_i18n::FluentValue;

/// Embedded Fluent catalogs, one `i18n/<lang>/vouch-server.ftl` per language.
#[derive(rust_embed::RustEmbed)]
#[folder = "i18n/"]
struct Localizations;

/// Process-wide loader holding every embedded catalog. Built once; never mutated
/// after load. Per-request locale selection happens on cheap derived loaders.
static LOADER: LazyLock<FluentLanguageLoader> =
    LazyLock::new(|| vouch_i18n::build_loader("vouch-server", langid!("en-US"), &Localizations));

/// Request-scoped translation handle passed into every UI template.
///
/// Cloneable and cheap (the inner loader shares catalog data via `Arc`).
#[derive(Clone)]
pub struct I18nContext {
    loader: Arc<FluentLanguageLoader>,
    lang: String,
}

impl I18nContext {
    /// Build the fallback (`en-US`) context, for template constructors deep in
    /// error paths where threading the request-scoped context would be
    /// invasive. With a single shipped language this is identical to any
    /// negotiated context; once a second language ships, callers should prefer
    /// the [`FromRequestParts`] extractor so the user's locale is honored.
    pub fn fallback() -> Self {
        negotiate(None)
    }

    /// Translate a no-argument message id. Bypasses the [`Tr`] builder for
    /// the common case where a string lookup is all the caller needs — used
    /// by the `/i18n.js` bundle builder and unit tests. Template call sites
    /// go through the unified [`Tr`] entry point via `self.tr("id")`.
    pub fn t(&self, id: &str) -> String {
        self.loader.get(id)
    }

    /// Render a [`Tr`] against this context. Handles all four shapes
    /// (`id`, `id` + args, `id.attr`, `id.attr` + args) in one place so the
    /// builder can stay small.
    pub fn render(&self, tr: &Tr<'_>) -> String {
        let no_args = tr.args.is_empty();
        match (tr.attr, no_args) {
            (None, true) => self.loader.get(tr.id),
            (None, false) => {
                let map = build_arg_map(&tr.args);
                self.loader.get_args_concrete(tr.id, map)
            }
            (Some(attr), true) => self.loader.get_attr(tr.id, attr),
            (Some(attr), false) => {
                let map = build_arg_map(&tr.args);
                self.loader.get_attr_args_concrete(tr.id, attr, map)
            }
        }
    }

    /// BCP-47 tag of the negotiated language, for `<html lang="...">`.
    pub fn lang(&self) -> &str {
        &self.lang
    }

    /// Text direction for the negotiated language (`ltr` until an RTL language
    /// is added).
    pub fn dir(&self) -> &'static str {
        "ltr"
    }
}

tokio::task_local! {
    /// Request-scoped translation context, installed by [`i18n_layer`] for
    /// every request. The [`Tr`] builder reads it inside its [`fmt::Display`]
    /// impl — handlers don't thread the context and templates don't carry
    /// any extra field.
    static REQUEST_I18N: I18nContext;
}

/// Lazy translation builder.
///
/// Constructed by `self.tr("id")` in templates (and `Tr::new("id")` in Rust
/// code), then chained with `.arg(name, value)` and/or `.attr(attr_name)`.
/// Rendering happens through [`fmt::Display`] (so `{{ self.tr("id") }}` in
/// Askama just works) and resolves against the request-scoped task-local —
/// falling back to en-US outside any request scope.
///
/// Why a single builder instead of six methods (`tr` / `tr1` / `tr1_num` /
/// `tr2` / `tr_attr` / `tr_attr1`): Askama can only call methods on `self`
/// in `{{ … }}` expressions, so the historical method-per-arity API had to
/// fan out. A method that returns a builder collapses every shape (no-arg,
/// one arg, many args, with or without attribute, string or numeric value)
/// into one call site shape, and `arg<V: Into<FluentValue<'_>>>` engages
/// CLDR plural rules automatically when the value is numeric.
pub struct Tr<'a> {
    id: &'a str,
    attr: Option<&'a str>,
    args: Vec<(&'a str, FluentValue<'a>)>,
}

impl<'a> Tr<'a> {
    /// Build a no-arg, no-attribute lookup. Chain `.arg` / `.attr` to refine.
    pub fn new(id: &'a str) -> Self {
        Self {
            id,
            attr: None,
            args: Vec::new(),
        }
    }

    /// Select a message attribute (Fluent's `id .attr = value` form). Pairs
    /// with `.arg` for attributes that take placeables.
    #[must_use]
    pub fn attr(mut self, attr: &'a str) -> Self {
        self.attr = Some(attr);
        self
    }

    /// Add a Fluent placeable. Numeric `V` (`i64`, `usize`, …) flows through
    /// `FluentValue::Number` so CLDR plural arms (`[one]` / `*[other]`) match
    /// correctly; string `V` (`&str`, `String`, `&String`, `Cow<str>`) flows
    /// through `FluentValue::String`. Anything else is not supported — the
    /// compiler will tell the caller to stringify explicitly.
    #[must_use]
    pub fn arg<V>(mut self, name: &'a str, value: V) -> Self
    where
        V: Into<FluentValue<'a>>,
    {
        self.args.push((name, value.into()));
        self
    }
}

impl fmt::Display for Tr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rendered = REQUEST_I18N
            .try_with(|ctx| ctx.render(self))
            .unwrap_or_else(|_| I18nContext::fallback().render(self));
        f.write_str(&rendered)
    }
}

/// Materialize the builder's arg list as the loader's expected map. Cheap
/// for the typical 0-3 args; the FluentValues are cloned because the
/// loader's `_concrete` entry points take ownership of the map.
fn build_arg_map<'a>(args: &'a [(&'a str, FluentValue<'a>)]) -> HashMap<&'a str, FluentValue<'a>> {
    args.iter().map(|(k, v)| (*k, v.clone())).collect()
}

/// BCP-47 tag of the negotiated language for `<html lang="...">`. Returns
/// `"en-US"` outside any request scope.
pub(crate) fn lang() -> String {
    REQUEST_I18N
        .try_with(|i| i.lang().to_owned())
        .unwrap_or_else(|_| "en-US".to_owned())
}

/// Text direction for `<html dir="...">` — `"ltr"` until an RTL language
/// ships.
pub(crate) fn dir() -> &'static str {
    REQUEST_I18N.try_with(I18nContext::dir).unwrap_or("ltr")
}

/// Shared `en-US` context used to build the static `/i18n.js` bundle.
///
/// Template rendering goes through the task-local installed by [`i18n_layer`]
/// (via [`t`], [`t1`], [`lang`]), so this static is reached only by the JS
/// bundle builder and [`validate_startup`].
static DEFAULT_CONTEXT: LazyLock<I18nContext> = LazyLock::new(|| negotiate(None));

/// Borrow the process-wide static (`en-US`) translation context. Internal
/// helper for the JS-bundle builder and the startup health check.
fn default_context() -> &'static I18nContext {
    &DEFAULT_CONTEXT
}

/// Verify the embedded i18n catalogs are healthy and refuse to start otherwise.
///
/// Without this guard, a packaging mistake that ships a corrupt or missing
/// `i18n/en-US/vouch-server.ftl` would let the server boot and render the UI with raw
/// Fluent message ids — a silent break an operator could miss until a user
/// complained.
///
/// **Ordering requirement:** call this exactly once during server
/// initialization, **before** the listener starts accepting requests. It is
/// what eagerly drives the `JS_BUNDLES` and `DEFAULT_CONTEXT` `LazyLock`
/// initializers — if a request reaches the handlers before this runs and
/// `build_js_bundles` panics, that `LazyLock` poisons and every later request
/// panics on access. The current call site in `main::run_server` upholds this;
/// a future refactor that reorders startup must preserve it.
///
/// # Errors
///
/// Returns an error if the embedded `en-US` catalog cannot be enumerated, is
/// missing, fails to resolve a well-known key, or yields no JS bundle entry.
pub fn validate_startup() -> anyhow::Result<()> {
    vouch_i18n::validate_startup(&LOADER, &Localizations, &["common-app-name"])?;
    // Eagerly force the JS bundle map to build now so any render failure
    // surfaces here (not on the first `/i18n.js` request), and confirm en-US
    // is present — the handler's fallback path depends on it.
    LazyLock::force(&JS_BUNDLES);
    anyhow::ensure!(
        JS_BUNDLES.contains_key("en-US"),
        "i18n JS bundle for en-US was not built; refusing to start"
    );
    Ok(())
}

/// Negotiate an [`I18nContext`] giving precedence to `ui_locales` (RP-Initiated Logout 1.0
/// Section 3, space-separated BCP-47 tags) over `Accept-Language`.
///
/// If `ui_locales` is `Some` and non-empty, its tags are tried first. If none match an
/// installed locale, fall back to `accept_language` as normal.
pub(crate) fn negotiate_ui_locales(
    ui_locales: Option<&str>,
    accept_language: Option<&str>,
) -> I18nContext {
    if let Some(raw) = ui_locales {
        let mut requested: Vec<LanguageIdentifier> = raw
            .split_whitespace()
            .filter_map(|tag| tag.parse::<LanguageIdentifier>().ok())
            .collect();
        if !requested.is_empty() {
            // Append Accept-Language languages as lower-priority fallbacks.
            if let Some(al) = accept_language {
                requested.extend(parse_accept_language(al));
            }
            let loader = vouch_i18n::select_loader(&LOADER, &requested);
            let lang = loader.current_language().to_string();
            return I18nContext {
                loader: Arc::new(loader),
                lang,
            };
        }
    }
    negotiate(accept_language)
}

/// Run `f` inside the [`REQUEST_I18N`] scope of `ctx`.
///
/// Used by the logout handler to honour `ui_locales` for page rendering without
/// changing the handler signature — templates pick up the locale via the
/// task-local just as they do under [`i18n_layer`].
pub(crate) fn sync_scope_locale<R>(ctx: I18nContext, f: impl FnOnce() -> R) -> R {
    REQUEST_I18N.sync_scope(ctx, f)
}

/// Negotiate an [`I18nContext`] from an optional `Accept-Language` header value.
pub(crate) fn negotiate(accept_language: Option<&str>) -> I18nContext {
    let requested = accept_language
        .map(parse_accept_language)
        .unwrap_or_default();
    let loader = vouch_i18n::select_loader(&LOADER, &requested);
    let lang = loader.current_language().to_string();
    I18nContext {
        loader: Arc::new(loader),
        lang,
    }
}

/// Parse an `Accept-Language` header into language identifiers, highest quality
/// first. Malformed entries and the `*` wildcard are skipped.
fn parse_accept_language(header: &str) -> Vec<LanguageIdentifier> {
    // Browsers typically send a handful of languages; preallocate to skip the
    // early reallocations.
    let mut weighted: Vec<(f32, LanguageIdentifier)> = Vec::with_capacity(4);
    for entry in header.split(',') {
        let mut segments = entry.trim().split(';');
        let Some(tag) = segments.next() else {
            continue;
        };
        let tag = tag.trim();
        if tag.is_empty() || tag == "*" {
            continue;
        }
        let Ok(lang) = tag.parse::<LanguageIdentifier>() else {
            continue;
        };
        let mut quality = 1.0_f32;
        let mut valid = true;
        for segment in segments {
            let Some(value) = segment.trim().strip_prefix("q=") else {
                continue;
            };
            let Ok(parsed) = value.trim().parse::<f32>() else {
                continue;
            };
            // RFC 9110 §12.4.2: q-values are bounded to `[0, 1]`. Reject
            // anything else — `q=5` or `q=-1` would otherwise mis-rank.
            if !(0.0..=1.0).contains(&parsed) {
                valid = false;
                break;
            }
            quality = parsed;
        }
        // RFC 9110 §12.4.2: `q=0` means "not acceptable" — drop the entry.
        // NaN can't reach this point: the range check above uses
        // `Range::contains`, which returns `false` for NaN and sets `valid`
        // to `false`. So `quality` here is either the default `1.0` or a
        // value that already passed `[0, 1]`.
        if !valid || quality <= 0.0 {
            continue;
        }
        weighted.push((quality, lang));
    }
    weighted.sort_by(|a, b| b.0.total_cmp(&a.0));
    weighted.into_iter().map(|(_, lang)| lang).collect()
}

impl<S> FromRequestParts<S> for I18nContext
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(http::header::ACCEPT_LANGUAGE)
            .and_then(|value| value.to_str().ok());
        Ok(negotiate(header))
    }
}

/// Axum middleware that negotiates the request locale and installs it in the
/// [`REQUEST_I18N`] task-local for the duration of the request. Templates
/// constructed by handlers downstream pick it up via [`PageContext::current`].
///
/// Apply this once at the top of every router that renders UI templates.
pub async fn i18n_layer(
    i18n: I18nContext,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    REQUEST_I18N.scope(i18n, next.run(request)).await
}

/// Translation keys exposed to client-side JavaScript via [`i18n_js_handler`].
///
/// The single authoritative list of strings the browser needs. The completeness
/// test asserts this is a superset of every `t("…")` referenced under
/// `static/js/` and a subset of the catalog, so a missing entry fails the build
/// instead of silently rendering the raw key at runtime.
pub(crate) const JS_I18N_KEYS: &[&str] = &[
    "admin-js-cel-fails",
    "admin-js-cel-invalid",
    "admin-js-cel-passes",
    "admin-js-edit-policy-title",
    "admin-policies-playground-title",
    "appcreate-js-fapi-required",
    "appcreate-js-jwks-json",
    "appcreate-js-postlogout-invalid",
    "appcreate-js-jwks-keys",
    "appcreate-js-jwksuri-https",
    "appcreate-js-jwksuri-invalid",
    "appcreate-js-redirect-invalid",
    "appcreate-js-redirect-required",
    "appcreate-js-resource-fragment-uri",
    "appcreate-js-resource-invalid",
    "appcreate-js-resource-scheme-uri",
    "appcreate-js-resource-toolong-uri",
    "common-copy",
    "common-js-copied",
    "keys-js-delete",
    "keys-js-delete-failed",
    "keys-js-delete-failed-message",
    "keys-js-delete-failed-reauth",
    "keys-js-reauth-complete-failed",
    "keys-js-reauth-start-failed",
    "keys-js-reg-complete-failed",
    "keys-js-reg-completing",
    "keys-js-reg-start-failed",
    "keys-js-reg-starting",
    "keys-js-reg-touch",
    "keys-js-stepup",
    "login-js-complete-failed",
    "login-js-error",
    "login-js-signed-in",
    "login-js-start-failed",
    "login-js-success-redirect",
    "login-js-touch",
    "login-js-waiting",
    "webauthn-err-abort",
    "webauthn-err-invalidstate",
    "webauthn-err-notallowed",
    "webauthn-err-notsupported",
    "webauthn-err-pin",
    "webauthn-err-security",
];

/// Tiny client-side translation runtime, appended to every bundle.
///
/// `t(key)` returns the translation (or the key itself if absent). `t(key, args)`
/// additionally substitutes Fluent-style `{ $name }` placeables — variable names
/// here are Fluent identifiers (ASCII alphanumeric plus `-`/`_`), so the regex
/// composed from them is always safe.
const T_RUNTIME_JS: &str = r"window.t=function(k,a){var s=Object.prototype.hasOwnProperty.call(window.VOUCH_I18N,k)?window.VOUCH_I18N[k]:k;if(a)for(var n in a)if(Object.prototype.hasOwnProperty.call(a,n))s=s.replace(new RegExp('\\{\\s*\\$'+n+'\\s*\\}','g'),String(a[n]));return s;};";

/// Build the locale's client-side translation bundle as JavaScript source.
///
/// Emits `window.VOUCH_I18N` (a `key → string` map) and the global `t` runtime
/// defined above. Catalog values keep Fluent placeables unresolved (e.g. the
/// literal `{$name}`) so the browser can substitute runtime values via `t(key,
/// args)`.
///
/// Note on Unicode line separators: `serde_json` does not escape U+2028 or
/// U+2029. That is safe here because `/i18n.js` is served as an external script
/// (CSP `script-src 'self'`), where those code points are valid in string
/// literals. If a future change ever inlines this output into HTML, switch to
/// an escaping serializer — inline `<script>` parsing treats U+2028/2029 as
/// line terminators.
fn render_i18n_js(ctx: &I18nContext) -> String {
    let mut map = serde_json::Map::with_capacity(JS_I18N_KEYS.len());
    for key in JS_I18N_KEYS {
        map.insert((*key).to_owned(), serde_json::Value::String(ctx.t(key)));
    }
    let json = serde_json::Value::Object(map).to_string();
    format!("window.VOUCH_I18N={json};\n{T_RUNTIME_JS}\n")
}

/// Strong ETag (quoted SHA-256 hex) over the rendered bundle, so an unchanged
/// locale validates with a 304 across page loads.
fn etag_for(body: &str) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, body.as_bytes());
    format!("\"{}\"", hex::encode(digest.as_ref()))
}

/// Pre-rendered `(body, etag)` for each shipped client bundle, keyed by BCP-47
/// tag. Built once at first access; serving `/i18n.js` is then a HashMap lookup
/// instead of a fresh JSON serialization plus SHA-256 per page navigation.
/// `en-US` is the guaranteed fallback (verified by [`validate_startup`]); new
/// languages are added inside [`build_js_bundles`] as their catalogs land.
/// A pre-rendered client bundle: the JS body, its ETag string (for comparing
/// against `If-None-Match`), and that ETag pre-parsed as a `HeaderValue` so the
/// response path neither re-parses nor heap-allocates it per request.
type Bundle = (String, String, HeaderValue);

static JS_BUNDLES: LazyLock<HashMap<String, Bundle>> = LazyLock::new(build_js_bundles);

fn build_js_bundles() -> HashMap<String, Bundle> {
    let mut bundles = HashMap::new();
    let body = render_i18n_js(default_context());
    let etag = etag_for(&body);
    // `etag_for` emits `"<hex>"`, always a valid header value; the fallback only
    // keeps this panic-free.
    let etag_value =
        HeaderValue::from_str(&etag).unwrap_or_else(|_| HeaderValue::from_static("\"i18n\""));
    bundles.insert("en-US".to_owned(), (body, etag, etag_value));
    // Additional language bundles land here as their catalogs ship: build an
    // `I18nContext` for the tag via `negotiate(Some(tag))` and insert.
    bundles
}

const I18N_JS_CONTENT_TYPE: HeaderValue =
    HeaderValue::from_static("text/javascript; charset=utf-8");
const I18N_JS_CACHE_CONTROL: HeaderValue = HeaderValue::from_static("no-cache");
const I18N_JS_VARY: HeaderValue = HeaderValue::from_static("Accept-Language");

/// Serve the negotiated locale's client-side translation bundle.
///
/// A single external script (allowed by the `script-src 'self'` CSP) loaded
/// before page scripts, replacing per-page inline injection. `no-cache` + ETag
/// lets the body be reused across navigations via cheap 304s while staying fresh
/// on deploy; `Vary: Accept-Language` keeps per-locale responses distinct.
pub(crate) async fn i18n_js_handler(ctx: I18nContext, headers: HeaderMap) -> Response {
    // Look up the negotiated language; fall back to en-US, which startup
    // validation guarantees is present. The final empty-map branch is a
    // degenerate "should never happen" case kept panic-free.
    let bundle = JS_BUNDLES
        .get(ctx.lang())
        .or_else(|| JS_BUNDLES.get("en-US"));
    let Some((body, etag, etag_value)) = bundle else {
        tracing::error!("i18n bundle map is empty; serving 500");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let if_none_match = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok());
    if if_none_match == Some(etag.as_str()) {
        return (
            StatusCode::NOT_MODIFIED,
            [
                (header::ETAG, etag_value.clone()),
                (header::CACHE_CONTROL, I18N_JS_CACHE_CONTROL),
                (header::VARY, I18N_JS_VARY),
            ],
        )
            .into_response();
    }

    (
        [
            (header::CONTENT_TYPE, I18N_JS_CONTENT_TYPE),
            (header::CACHE_CONTROL, I18N_JS_CACHE_CONTROL),
            (header::VARY, I18N_JS_VARY),
            (header::ETAG, etag_value.clone()),
        ],
        body.clone(),
    )
        .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]
mod tests {
    use super::*;

    #[test]
    fn en_us_catalog_loads() {
        let available = LOADER.available_languages(&Localizations).unwrap();
        assert!(available.contains(&langid!("en-US")));
    }

    #[test]
    fn known_key_resolves() {
        let ctx = negotiate(None);
        let rendered = ctx.t("footer-install");
        assert_eq!(rendered, "Install");
    }

    #[test]
    fn placeable_substitution() {
        let ctx = negotiate(None);
        let rendered = ctx.render(&Tr::new("footer-copyright").arg("year", "2026"));
        assert!(rendered.contains("2026"));
    }

    #[test]
    fn attribute_resolves() {
        // Fluent attribute pattern, per the docs at
        // <https://projectfluent.org/fluent/guide/attributes.html>.
        // `admin-members-demote` carries a `.title` for the button tooltip.
        let ctx = negotiate(None);
        assert_eq!(ctx.t("admin-members-demote"), "Demote");
        assert_eq!(
            ctx.render(&Tr::new("admin-members-demote").attr("title")),
            "Demote to member"
        );
    }

    #[test]
    fn term_substitution_renders_product_name() {
        // Terms (`-product`, `-yubikey`, …) defined at the top of vouch-server.ftl
        // expand inside referencing messages. A change to the term name
        // propagates everywhere; this test pins one representative call site.
        let ctx = negotiate(None);
        let rendered = ctx.t("home-welcome");
        assert!(
            rendered.contains("Vouch"),
            "{{ -product }} should expand to Vouch, got: {rendered}"
        );
    }

    /// Display impl resolves via the request-scoped task-local — and falls
    /// back to en-US when called outside any scope. This is the path Askama
    /// takes when rendering `{{ self.tr(...) }}`; the templates never call
    /// `I18nContext::render` directly.
    #[test]
    fn tr_display_falls_back_to_en_us_outside_scope() {
        let rendered = Tr::new("footer-install").to_string();
        assert_eq!(rendered, "Install");
        let with_attr = Tr::new("admin-members-demote").attr("title").to_string();
        assert_eq!(with_attr, "Demote to member");
        // Numeric arg → CLDR plural dispatch through the Display path.
        let one_arm = Tr::new("admin-members-confirm-revoke")
            .arg("count", 1_i64)
            .to_string();
        assert!(
            one_arm.contains("key ") && !one_arm.contains("keys "),
            "Display path should engage [one] arm for count=1, got: {one_arm}"
        );
    }

    #[test]
    fn plural_selector_one_vs_other() {
        // CLDR plural selector on `admin-members-confirm-revoke`. The
        // selector picks `[one]` vs `*[other]` from a `FluentValue::Number`,
        // so the value must be passed as a numeric type — the `Tr` builder's
        // `arg<V: Into<FluentValue>>` dispatches `i64` (and friends) through
        // the Number arm automatically.
        let ctx = negotiate(None);
        let one = ctx.render(&Tr::new("admin-members-confirm-revoke").arg("count", 1_i64));
        let many = ctx.render(&Tr::new("admin-members-confirm-revoke").arg("count", 3_i64));
        assert!(one.contains("key "), "one-arm should say 'key', got: {one}");
        assert!(
            many.contains("keys "),
            "other-arm should say 'keys', got: {many}"
        );
    }

    #[test]
    fn validate_startup_passes_with_embedded_catalog() {
        validate_startup().expect("embedded en-US catalog should validate");
    }

    #[test]
    fn cached_bundle_matches_freshly_rendered() {
        let fresh = render_i18n_js(default_context());
        let cached = JS_BUNDLES
            .get("en-US")
            .map(|(body, ..)| body.clone())
            .expect("en-US bundle should be present");
        assert_eq!(
            cached, fresh,
            "cache should hold the same body as a fresh render"
        );
    }

    #[test]
    fn js_bundle_carries_placeable_runtime() {
        let ctx = negotiate(None);
        let bundle = render_i18n_js(&ctx);
        assert!(
            bundle.contains("window.t=function(k,a)"),
            "runtime should accept an args object"
        );
        assert!(
            bundle.contains("new RegExp"),
            "runtime should substitute Fluent placeables via regex"
        );
        // Catalog values that take a placeable must ship with the placeable
        // unresolved, so the browser can substitute the runtime value.
        let raw = ctx.t("appcreate-js-redirect-invalid");
        assert!(
            raw.contains("$uris"),
            "expected unresolved $uris placeable, got {raw}"
        );
    }

    #[test]
    fn js_bundle_exposes_every_declared_key() {
        let ctx = negotiate(None);
        let bundle = render_i18n_js(&ctx);
        assert!(bundle.contains("window.VOUCH_I18N="));
        assert!(bundle.contains("window.t=function"));
        for key in JS_I18N_KEYS {
            assert!(bundle.contains(key), "bundle missing key {key}");
        }
        // A representative translation is present, not just the key name.
        assert!(bundle.contains(&ctx.t("common-copy")));
    }

    #[test]
    fn etag_is_stable_and_content_addressed() {
        let ctx = negotiate(None);
        let body = render_i18n_js(&ctx);
        assert_eq!(etag_for(&body), etag_for(&body));
        assert_ne!(etag_for(&body), etag_for("window.VOUCH_I18N={};"));
        assert!(etag_for(&body).starts_with('"') && etag_for(&body).ends_with('"'));
    }

    #[test]
    fn absent_header_falls_back_to_en_us() {
        assert_eq!(negotiate(None).lang(), "en-US");
    }

    #[test]
    fn unsupported_language_falls_back_to_en_us() {
        assert_eq!(negotiate(Some("zz,xx;q=0.5")).lang(), "en-US");
    }

    #[test]
    fn quality_values_are_ordered() {
        let parsed = parse_accept_language("fr;q=0.5, de, en;q=0.9");
        let tags: Vec<String> = parsed.iter().map(ToString::to_string).collect();
        assert_eq!(tags, vec!["de", "en", "fr"]);
    }

    #[test]
    fn malformed_header_does_not_panic() {
        let _ = parse_accept_language(";;;,,q=,=,*;q=x");
        let _ = negotiate(Some(""));
    }

    #[test]
    fn empty_accept_language_resolves_to_en_us() {
        assert_eq!(negotiate(Some("")).lang(), "en-US");
    }

    #[test]
    fn out_of_range_quality_is_dropped() {
        // q=5 and q=-1 are outside RFC 9110's [0,1] band and must not mis-rank.
        let parsed = parse_accept_language("fr;q=5, de;q=-1, en;q=0.7");
        let tags: Vec<String> = parsed.iter().map(ToString::to_string).collect();
        assert_eq!(tags, vec!["en"]);
    }

    #[test]
    fn zero_quality_is_dropped() {
        // RFC 9110 §12.4.2: q=0 means "not acceptable".
        let parsed = parse_accept_language("fr;q=0, en;q=0.5");
        let tags: Vec<String> = parsed.iter().map(ToString::to_string).collect();
        assert_eq!(tags, vec!["en"]);
    }

    #[test]
    fn test_negotiate_ui_locales_prefers_ui_locales_over_accept_language() {
        // When `ui_locales` is present, it takes precedence over `Accept-Language`.
        // Both use en-US in this catalog so we verify the lang tag, not a
        // translated string (we only ship en-US in the test binary).
        let ctx = negotiate_ui_locales(Some("en-US"), Some("zz"));
        assert_eq!(
            ctx.lang(),
            "en-US",
            "ui_locales=en-US must win over Accept-Language=zz"
        );
    }

    #[test]
    fn test_negotiate_ui_locales_falls_back_to_accept_language_when_empty() {
        // An empty ui_locales string must fall through to Accept-Language.
        let ctx_empty = negotiate_ui_locales(Some(""), Some("en;q=0.9"));
        assert_eq!(ctx_empty.lang(), "en-US");
        // A None ui_locales also falls through.
        let ctx_none = negotiate_ui_locales(None, Some("en;q=0.8"));
        assert_eq!(ctx_none.lang(), "en-US");
    }

    #[test]
    fn test_negotiate_ui_locales_preserves_order() {
        // Tags in ui_locales appear before Accept-Language fallbacks.
        // We can only verify this indirectly (single catalog), but we confirm
        // that multiple space-separated tags are accepted without panicking.
        let ctx = negotiate_ui_locales(Some("en-US fr-FR"), None);
        // Must resolve to en-US (the only installed locale) without panicking.
        assert_eq!(ctx.lang(), "en-US");
    }

    #[tokio::test]
    async fn js_handler_returns_etag_and_serves_304_on_match() {
        // No If-None-Match → 200 with body and ETag.
        let response = i18n_js_handler(negotiate(None), HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .expect("response should carry an ETag")
            .to_owned();
        assert!(etag.starts_with('"') && etag.ends_with('"'));
        assert_eq!(
            response
                .headers()
                .get(header::VARY)
                .and_then(|v| v.to_str().ok()),
            Some("Accept-Language")
        );

        // Matching If-None-Match → 304 with no body.
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, etag.parse().unwrap());
        let response = i18n_js_handler(negotiate(None), headers).await;
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            response
                .headers()
                .get(header::ETAG)
                .and_then(|v| v.to_str().ok()),
            Some(etag.as_str())
        );

        // Mismatched If-None-Match → 200 again.
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, "\"deadbeef\"".parse().unwrap());
        let response = i18n_js_handler(negotiate(None), headers).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Every `self.tr*("id")` / `page.tr*("id")` key referenced by a template,
    /// JS bundle, or `Tr::new("id")` Rust call site must be defined in the
    /// `en-US` catalog. This is the runtime-resolution guard that mirrors the
    /// CLI/agent's compile-time `fl!` checks (Askama needs runtime-string
    /// ids, so a true compile-time check isn't available).
    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "single cohesive completeness check (FTL parsing + template + JS + Rust scans); \
                  splitting would obscure the catalog-vs-references diff at the end"
    )]
    fn every_template_key_is_defined() {
        use std::collections::HashSet;
        use std::fs;
        use std::path::{Path, PathBuf};

        fn collect_ftl_ids(content: &str) -> HashSet<String> {
            // Collect both top-level message ids (`my-msg = …`) and attribute
            // refs (`my-msg.title`, indented under their owning message as
            // `    .title = …`). Attribute references in templates use the
            // `id.attr` form (e.g. `self.tr_attr("admin-members-demote",
            // "title")`), so we register them as `my-msg.title` here.
            let mut ids = HashSet::new();
            let mut current_owner: Option<String> = None;
            for line in content.lines() {
                let trimmed = line.trim_start();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let indented = trimmed.len() < line.len();
                if indented {
                    // Attribute line: `    .attr-name = …`. Anything else
                    // indented (raw continuation, selector arm, etc.) is
                    // skipped — those don't introduce new ids.
                    if !trimmed.starts_with('.') {
                        continue;
                    }
                    let Some((left, _)) = trimmed.split_once('=') else {
                        continue;
                    };
                    let attr = left.trim().trim_start_matches('.');
                    if attr.is_empty()
                        || !attr
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                    {
                        continue;
                    }
                    if let Some(owner) = current_owner.as_deref() {
                        ids.insert(format!("{owner}.{attr}"));
                    }
                    continue;
                }
                // Top-level line: `my-msg = …`. Reset attribute ownership.
                let Some((left, _)) = line.split_once('=') else {
                    current_owner = None;
                    continue;
                };
                let id = left.trim();
                // Skip Fluent terms (`-foo = …`) — they're not callable from
                // templates, only referenced from other messages via
                // `{ -foo }`. Their syntax doesn't fit our kebab-case check
                // either (leading `-`).
                if id.starts_with('-') {
                    current_owner = None;
                    continue;
                }
                if !id.is_empty()
                    && id
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                {
                    ids.insert(id.to_owned());
                    current_owner = Some(id.to_owned());
                } else {
                    current_owner = None;
                }
            }
            ids
        }

        fn collect_keys_with_marker(text: &str, marker: &str, keys: &mut HashSet<String>) {
            // Call sites have the shape `<marker>id")` or
            // `<marker>id").attr("attr-name")` (plus optional `.arg(...)`
            // chains that don't affect catalog identity). Capture the id,
            // then peek at the immediately-following bytes for a
            // `.attr("attr-name")` segment so attribute references are
            // recorded as `id.attr` — matching what `collect_ftl_ids`
            // produces.
            //
            // We filter to kebab-case ids (`looks_like_key`) so doc-comment
            // placeholders like `Tr::new("id")` and the test/example
            // strings in this very file don't pollute the `used` set.
            for part in text.split(marker).skip(1) {
                let Some(id) = part.split('"').next() else {
                    continue;
                };
                if !looks_like_key(id) {
                    continue;
                }
                // The rest of the slice starts at the byte after the
                // closing quote of the id. Look for an immediate
                // `).attr("…")` to attach.
                let rest_start = id.len() + 1; // +1 for the closing `"`
                let rest = part.get(rest_start..).unwrap_or("");
                let attr_marker = ").attr(\"";
                if let Some(after) = rest.strip_prefix(attr_marker)
                    && let Some(attr) = after.split('"').next()
                    && !attr.is_empty()
                {
                    keys.insert(format!("{id}.{attr}"));
                } else {
                    keys.insert(id.to_owned());
                }
            }
        }

        fn collect_keys(text: &str, keys: &mut HashSet<String>) {
            // Template call sites: `self.tr("id")` / `page.tr("id")` etc.
            collect_keys_with_marker(text, ".tr(\"", keys);
        }

        fn collect_rust_tr_keys(text: &str, keys: &mut HashSet<String>) {
            // Rust call sites: `Tr::new("id")`. Optional `.attr("…")` is
            // picked up the same way as template `.tr().attr()` chains.
            collect_keys_with_marker(text, "Tr::new(\"", keys);
        }

        // A translation key in our convention: kebab-case with at least one
        // hyphen. Filters out incidental `t('...')` matches in JS such as
        // `split('\n')` or `closest('.foo')`.
        fn looks_like_key(s: &str) -> bool {
            s.contains('-')
                && s.starts_with(|c: char| c.is_ascii_lowercase())
                && s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        }

        fn collect_js_keys(text: &str, keys: &mut HashSet<String>) {
            for marker in ["t(\"", "t('"] {
                let quote = if marker.ends_with('"') { '"' } else { '\'' };
                for part in text.split(marker).skip(1) {
                    if let Some(candidate) = part.split(quote).next()
                        && looks_like_key(candidate)
                    {
                        keys.insert(candidate.to_owned());
                    }
                }
            }
        }

        fn files_with_ext(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    files_with_ext(&path, ext, out);
                } else if path.extension().is_some_and(|e| e == ext) {
                    out.push(path);
                }
            }
        }

        let root = env!("CARGO_MANIFEST_DIR");
        let ftl = fs::read_to_string(format!("{root}/i18n/en-US/vouch-server.ftl")).unwrap();
        let defined = collect_ftl_ids(&ftl);

        let mut used = HashSet::new();

        let mut templates = Vec::new();
        files_with_ext(
            Path::new(&format!("{root}/templates")),
            "html",
            &mut templates,
        );
        assert!(!templates.is_empty(), "no templates found");
        for path in templates {
            let text = fs::read_to_string(&path).unwrap();
            collect_keys(&text, &mut used);
        }

        let mut js_used = HashSet::new();
        let mut scripts = Vec::new();
        files_with_ext(Path::new(&format!("{root}/static/js")), "js", &mut scripts);
        assert!(!scripts.is_empty(), "no JS files found");
        for path in scripts {
            let text = fs::read_to_string(&path).unwrap();
            collect_js_keys(&text, &mut js_used);
        }

        // Rust call sites: any `Tr::new("id")` in src/**/*.rs (handlers,
        // services, infra). The infra/i18n.rs module itself contains
        // `Tr::new(...)` examples inside doc comments and unit tests; those
        // still need to resolve, so we don't filter them out — a typo in a
        // doc-comment example would also fail this test, which is fine.
        let mut rust_used = HashSet::new();
        let mut rust_files = Vec::new();
        files_with_ext(Path::new(&format!("{root}/src")), "rs", &mut rust_files);
        assert!(!rust_files.is_empty(), "no Rust source files found");
        for path in rust_files {
            let text = fs::read_to_string(&path).unwrap();
            collect_rust_tr_keys(&text, &mut rust_used);
        }
        used.extend(rust_used);

        // Every key the JS calls must be declared in the bundle the /i18n.js
        // route ships; otherwise t() would silently return the raw key.
        let declared: HashSet<String> = JS_I18N_KEYS.iter().map(|key| (*key).to_owned()).collect();
        let mut undeclared: Vec<&String> = js_used.difference(&declared).collect();
        undeclared.sort();
        assert!(
            undeclared.is_empty(),
            "JS t() keys missing from JS_I18N_KEYS: {undeclared:?}"
        );

        // Everything referenced (template keys plus the shipped JS bundle) must
        // exist in the catalog.
        used.extend(declared);
        let mut missing: Vec<&String> = used.difference(&defined).collect();
        missing.sort();
        assert!(
            missing.is_empty(),
            "i18n keys missing from catalog: {missing:?}"
        );

        // Reverse direction: every catalog id should be referenced by some
        // template/JS/Rust call site, otherwise it is dead weight. A message
        // whose attribute is referenced (e.g. used only via `.attr("title")`)
        // counts as live. Terms (`-foo`) are already excluded from `defined`.
        //
        // A few ids are intentionally present without a `tr()` render site:
        // `common-app-name` is the canary `validate_startup` probes (passed as a
        // required-id literal) to confirm the catalog resolves terms.
        const NON_RENDERED_IDS: &[&str] = &["common-app-name"];
        let used_roots: HashSet<&str> = used
            .iter()
            .map(|key| key.split('.').next().unwrap_or(key))
            .collect();
        let is_dead = |id: &String| {
            if used.contains(id) || NON_RENDERED_IDS.contains(&id.as_str()) {
                return false;
            }
            // Attribute entries (`id.attr`) must be referenced directly.
            if id.contains('.') {
                return true;
            }
            // A bare message id is live if any of its attributes is used.
            !used_roots.contains(&id.as_str())
        };
        let mut dead: Vec<&String> = defined.iter().filter(|id| is_dead(id)).collect();
        dead.sort();
        assert!(
            dead.is_empty(),
            "i18n catalog ids defined but never referenced by any call site: {dead:?}"
        );
    }
}
