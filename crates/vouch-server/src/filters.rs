// SPDX-License-Identifier: BUSL-1.1
//! Custom Askama template filters shared across all templates.
//!
//! To use these filters in a template, add `use crate::filters;` to the
//! module that defines the template struct.

/// Format a `jiff::Timestamp` as "Mar 1, 2026" (English, UTC).
#[askama::filter_fn]
pub fn humandate(ts: &jiff::Timestamp, _env: &dyn askama::Values) -> askama::Result<String> {
    Ok(ts.strftime("%b %-d, %Y").to_string())
}
