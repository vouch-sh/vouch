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
//! - [`github`] - GitHub App installation, OAuth, and webhook handling
//! - [`k8s`] - Kubernetes OIDC token issuance
//!
//! # Distinction from Protocols
//!
//! **Integrations** (this module): External systems we connect TO
//! - GitHub API, AWS STS, Kubernetes OIDC
//! - Vouch issues tokens that external systems consume
//!
//! **Protocols** (`services/oidc`, future `protocols/`): Standards we IMPLEMENT
//! - OIDC provider, SCIM server, JWKS endpoint
//! - Vouch is the server, responding to external clients

pub mod aws;
pub mod github;
pub mod k8s;

pub use aws::{AwsError, AwsResult, AwsService, AwsTokenResult};
pub use github::GitHubService;
pub use k8s::{K8sError, K8sResult, K8sTokenResult, KubernetesService, validate_k8s_audience};
