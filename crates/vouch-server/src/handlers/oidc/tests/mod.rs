// SPDX-License-Identifier: BUSL-1.1
//! Tests for OIDC handlers — organized by RFC/specification.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod helpers;

mod e2e;
mod fapi2;
mod oidc_core;
mod oidc_discovery;
mod oidc_userinfo;
mod rfc6749_authorize;
mod rfc6749_token;
mod rfc7009;
mod rfc7523;
mod rfc7636;
mod rfc7662;
mod rfc8176;
mod rfc8414;
mod rfc8628;
mod rfc8693;
mod rfc8707;
mod rfc8725;
mod rfc9068;
mod rfc9101;
mod rfc9126;
mod rfc9207;
mod rfc9449;
mod rfc9470;
mod rfc9700;
