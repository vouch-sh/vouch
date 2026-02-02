// SPDX-License-Identifier: BUSL-1.1
//! External integration services.
//!
//! This module contains services for connecting to external systems where Vouch
//! acts as a **client/consumer**. These are vendor-specific integrations that
//! call external APIs or issue tokens for external consumption.
//!
//! # Available Integrations
//!
//! - [`aws`] - AWS STS token issuance (OIDC for `AssumeRoleWithWebIdentity`)
//! - [`gcp`] - GCP Workload Identity Federation token issuance
//! - [`github`] - GitHub App installation, OAuth, and webhook handling
//!
//! # Distinction from Protocols
//!
//! **Integrations** (this module): External systems we connect TO
//! - GitHub API, AWS STS, GCP token exchange
//! - Vouch issues tokens that external systems consume
//!
//! **Protocols** (`services/oidc`, future `protocols/`): Standards we IMPLEMENT
//! - OIDC provider, SCIM server, JWKS endpoint
//! - Vouch is the server, responding to external clients

pub mod aws;
pub mod gcp;
pub mod github;

pub use aws::{AwsError, AwsResult, AwsService, AwsTokenResult};
pub use gcp::{GcpError, GcpResult, GcpService, GcpTokenResult, validate_gcp_audience};
pub use github::GitHubService;
