// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM 2.0 handler tests, one file per topic.
//!
//! No fixtures are defined here — shared helpers come from
//! `crate::test_utils` through the module-root globs below, which every
//! submodule re-imports with `use super::*`. New tests go in the file
//! whose scope matches; add a new file (and list it here) when none does:
//!
//! - [`filters`] — SCIM filter operators (eq, co, sw) on the list endpoints.
//! - [`groups`] — Group resource CRUD, PATCH, membership, and schema validation.
//! - [`meta`] — `meta.created` / `meta.lastModified` timestamp semantics.
//! - [`protocol`] — Service-provider config, authentication, and error format/classification.
//! - [`users`] — User resource CRUD and PATCH semantics.
//! - [`validation`] — Input bounds, validation-before-auth ordering, NUL-byte rejection.

use super::*;
use crate::test_utils::*;

mod filters;
mod groups;
mod meta;
mod protocol;
mod users;
mod validation;
