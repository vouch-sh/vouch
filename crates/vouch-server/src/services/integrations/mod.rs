// SPDX-License-Identifier: BUSL-1.1
//! External integration services.
//!
//! This module contains services for connecting to external systems where Vouch
//! acts as a **client/consumer**. These are vendor-specific integrations that
//! call external APIs.
//!
//! # Available Integrations
//!
//! - [`github`] - GitHub App installation, OAuth, and webhook handling
//!
//! # Distinction from Protocols
//!
//! **Integrations** (this module): External systems we connect TO
//! - GitHub API, AWS STS, GCP token exchange
//! - Vouch is the client, calling external APIs
//!
//! **Protocols** (`services/oidc`, future `protocols/`): Standards we IMPLEMENT
//! - OIDC provider, SCIM server, JWKS endpoint
//! - Vouch is the server, responding to external clients

pub mod github;

pub use github::GitHubService;
