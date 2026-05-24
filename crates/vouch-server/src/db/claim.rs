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
/// `AlreadyConsumed` is the security-relevant case (replay detected).
/// `Expired` and `NotFound` are operational cases — the claim was never
/// valid or has aged out. `Database` wraps an unexpected backend failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClaimError {
    /// A prior caller already claimed this token. Replay detected.
    AlreadyConsumed,
    /// The claim TTL has elapsed.
    Expired,
    /// No record exists for the supplied key.
    NotFound,
    /// Backend database failure unrelated to claim semantics.
    Database(String),
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyConsumed => write!(f, "already consumed (replay detected)"),
            Self::Expired => write!(f, "claim expired"),
            Self::NotFound => write!(f, "claim not found"),
            Self::Database(msg) => write!(f, "database error: {msg}"),
        }
    }
}

impl std::error::Error for ClaimError {}

impl From<anyhow::Error> for ClaimError {
    fn from(err: anyhow::Error) -> Self {
        Self::Database(err.to_string())
    }
}
