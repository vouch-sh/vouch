// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Service layer for business logic.
//!
//! This module contains business logic services that are called by HTTP handlers.
//! Services encapsulate domain logic and RFC-compliant protocol implementations,
//! while handlers focus on HTTP concerns (extraction, response formatting).
//!
//! # Architecture
//!
//! ```text
//! HTTP Request
//!     │
//!     ▼
//! ┌─────────────────┐
//! │    Handler      │  ← Extract HTTP-specific data (headers, cookies, form)
//! │  (thin layer)   │
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │    Service      │  ← Business logic, RFC compliance, validation
//! │ (domain logic)  │
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │   Database      │  ← Persistence operations
//! │   (db module)   │
//! └─────────────────┘
//! ```
//!
//! # Module Organization
//!
//! ## Protocols (standards we implement as a provider)
//!
//! - [`oidc`] - OpenID Connect provider (RFC 6749, 7636, 8628, 8693, 9449)
//!
//! ## Integrations (external systems we connect to)
//!
//! - [`integrations::github`] - GitHub App, OAuth, webhooks
//!
//! # Error Handling
//!
//! Services return [`ServiceError`] which can be converted to protocol-appropriate
//! responses (OAuth, SCIM, or standard HTTP errors).

pub(crate) mod auth;
pub(crate) mod idp;
pub(crate) mod integrations;
pub(crate) mod keys;
pub mod oidc;
pub(crate) mod policy;

// Protocol modules will be added here as they are implemented:
// pub mod scim;
