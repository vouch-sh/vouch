// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cookie-based flash messages for server-rendered form-POST pages.
//!
//! Carries one-shot success/error messages across a POST → redirect → GET
//! cycle without putting the text in a query string. Each page that wants
//! flash messages reads them at the top of its GET handler (clearing them in
//! the response) and sets them in its POST handlers' redirects.

use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use time::Duration;

const FLASH_OK: &str = "vouch_flash_ok";
const FLASH_ERR: &str = "vouch_flash_err";

/// Cookie path scope. Root-scoped so the same utility is reusable across the
/// admin pages (`members`, `policies`, `scim_tokens`, …) and the enrollment
/// key-management page. A flash is set by a POST handler and immediately
/// consumed by the GET it redirects to, so the broad scope does not cause
/// messages to leak between unrelated pages in practice.
const PATH: &str = "/";

/// Short TTL so a flash that the user navigates away from (instead of
/// loading the page that would clear it) doesn't linger and reappear later.
const TTL_SECONDS: i64 = 60;

/// Values read from the flash cookies on the GET side of a PRG cycle.
#[derive(Debug, Default)]
pub(crate) struct Flash {
    pub(crate) ok: Option<String>,
    pub(crate) err: Option<String>,
}

/// Read whatever flash values are present on the incoming jar. Always call
/// [`clear`] on the response jar so the cookies don't survive past this
/// render.
pub(crate) fn read(jar: &CookieJar) -> Flash {
    Flash {
        ok: jar.get(FLASH_OK).map(|c| c.value().to_string()),
        err: jar.get(FLASH_ERR).map(|c| c.value().to_string()),
    }
}

/// Add expiring cookies that clear the flash on the user's browser.
pub(crate) fn clear(jar: CookieJar) -> CookieJar {
    jar.add(expire(FLASH_OK)).add(expire(FLASH_ERR))
}

/// Set a success flash to be displayed on the next render.
pub(crate) fn set_ok(jar: CookieJar, msg: impl Into<String>) -> CookieJar {
    jar.add(build(FLASH_OK, msg.into()))
}

/// Set an error flash to be displayed on the next render.
pub(crate) fn set_err(jar: CookieJar, msg: impl Into<String>) -> CookieJar {
    jar.add(build(FLASH_ERR, msg.into()))
}

fn build(name: &'static str, value: String) -> Cookie<'static> {
    Cookie::build((name, value))
        .path(PATH)
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(TTL_SECONDS))
        .build()
}

fn expire(name: &'static str) -> Cookie<'static> {
    Cookie::build((name, ""))
        .path(PATH)
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::ZERO)
        .build()
}
