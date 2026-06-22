// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Custom Askama template filters shared across all templates.
//!
//! To use these filters in a template, add `use crate::filters;` to the
//! module that defines the template struct.

/// Format a `jiff::Timestamp` as "Mar 1, 2026, 17:43 UTC" (24-hour, UTC).
///
/// Used as the no-JS fallback inside `<time data-localize-time>` elements;
/// client-side JS (`static/js/common.js`) upgrades it to the viewer's locale
/// and timezone. The `UTC` label keeps the server-rendered time unambiguous.
#[askama::filter_fn]
pub fn humandatetime(ts: &jiff::Timestamp, _env: &dyn askama::Values) -> askama::Result<String> {
    Ok(ts.strftime("%b %-d, %Y, %H:%M UTC").to_string())
}
