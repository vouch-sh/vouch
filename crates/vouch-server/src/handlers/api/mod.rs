// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JSON API handlers, distinct from the Askama-rendered browser UI in
//! [`crate::handlers::admin`]. Not exclusively for non-browser callers — see
//! `org`'s module doc for which entry points a browser actually calls.

pub(crate) mod org;
