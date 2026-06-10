// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cookie-based flash messages for server-rendered form-POST pages.
//!
//! Carries one-shot success/error messages across a POST → redirect → GET
//! cycle without putting the text in a query string. Each page that wants
//! flash messages reads them at the top of its GET handler (clearing them in
//! the response) and sets them in its POST handlers' redirects.
//!
//! Flashes are **path-scoped** to the area that uses them (the admin pages vs.
//! the enrollment key page). The cookie name is shared, but because the
//! browser only returns a cookie for requests under its path, a flash set for
//! one area is never read — or one-shot-cleared — on an unrelated page.

use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use time::Duration;

const FLASH_OK: &str = "vouch_flash_ok";
const FLASH_ERR: &str = "vouch_flash_err";

/// Cookie path scope for the admin pages (`members`, `policies`, …).
const ADMIN_PATH: &str = "/admin";

/// Cookie path scope for the enrollment key-management page.
pub(crate) const KEYS_PATH: &str = "/enroll/keys";

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
/// [`clear`]/[`clear_at`] on the response jar so the cookies don't survive
/// past this render.
pub(crate) fn read(jar: &CookieJar) -> Flash {
    Flash {
        ok: jar.get(FLASH_OK).map(|c| c.value().to_string()),
        err: jar.get(FLASH_ERR).map(|c| c.value().to_string()),
    }
}

/// Add expiring cookies that clear the admin-scoped flash.
pub(crate) fn clear(jar: CookieJar) -> CookieJar {
    clear_at(jar, ADMIN_PATH)
}

/// Set an admin-scoped success flash for the next render.
pub(crate) fn set_ok(jar: CookieJar, msg: impl Into<String>) -> CookieJar {
    set_ok_at(jar, msg, ADMIN_PATH)
}

/// Set an admin-scoped error flash for the next render.
pub(crate) fn set_err(jar: CookieJar, msg: impl Into<String>) -> CookieJar {
    set_err_at(jar, msg, ADMIN_PATH)
}

/// Clear the flash for a specific cookie path scope.
pub(crate) fn clear_at(jar: CookieJar, path: &'static str) -> CookieJar {
    jar.add(expire(FLASH_OK, path)).add(expire(FLASH_ERR, path))
}

/// Set a success flash scoped to `path`.
pub(crate) fn set_ok_at(jar: CookieJar, msg: impl Into<String>, path: &'static str) -> CookieJar {
    jar.add(build(FLASH_OK, msg.into(), path))
}

/// Set an error flash scoped to `path`.
pub(crate) fn set_err_at(jar: CookieJar, msg: impl Into<String>, path: &'static str) -> CookieJar {
    jar.add(build(FLASH_ERR, msg.into(), path))
}

fn build(name: &'static str, value: String, path: &'static str) -> Cookie<'static> {
    Cookie::build((name, value))
        .path(path)
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(TTL_SECONDS))
        .build()
}

fn expire(name: &'static str, path: &'static str) -> Cookie<'static> {
    Cookie::build((name, ""))
        .path(path)
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::ZERO)
        .build()
}
