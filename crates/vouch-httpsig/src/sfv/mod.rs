// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 8941 Structured Field Values implementation.
//!
//! Supports all six bare item types (Integer, Decimal, String, Token,
//! Byte Sequence, Boolean) and all three top-level structures (List,
//! Dictionary, Item) including Inner Lists and Parameters.

pub mod parse;
pub mod serialize;
pub mod types;
