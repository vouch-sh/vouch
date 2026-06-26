// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared error type for single-use claim primitives.
//!
//! The codebase has several "consume-once" database operations — auth codes,
//! device codes, DPoP JTIs, JWT-assertion JTIs, PAR records, challenge states,
//! pending OAuth records — whose security property is the same: only one
//! caller can succeed, the rest are replays. Their per-module witness types
//! (`AuthCodeClaim`, `DpopJtiClaim`, etc.) all surface failures through this
//! shared error, which each call site translates to its layer-specific
//! HTTP/OAuth error at the boundary.

use std::fmt;

/// Outcome of a failed single-use claim attempt.
///
/// Every primitive deliberately collapses its "lost" cases (not found,
/// expired, already consumed, concurrent race loser) into the single
/// `AlreadyConsumed` variant — the cases are indistinguishable from the
/// caller's perspective and each is rejected the same way (invalid_grant
/// / invalid_client). `InvalidInput` is a client-input validation
/// failure (e.g., oversized JTI) — callers should map it to a 4xx so
/// the client fixes its request rather than retrying. `Database` wraps
/// an unexpected backend failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClaimError {
    /// A prior caller already claimed this token, OR the token never
    /// existed, OR has expired. Deliberately indistinguishable — callers
    /// must not be able to probe state existence via response timing or
    /// error messages.
    AlreadyConsumed,
    /// Caller-supplied input violated a validation bound (length, format,
    /// etc.). Not a database failure — the client must fix its request.
    InvalidInput(String),
    /// Backend database failure unrelated to claim semantics.
    Database(String),
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyConsumed => write!(f, "already consumed (replay detected)"),
            Self::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            Self::Database(msg) => write!(f, "database error: {msg}"),
        }
    }
}

impl std::error::Error for ClaimError {}
