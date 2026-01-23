//! Delegation types for agent authorization
//!
//! Delegations allow humans to grant scoped, time-limited credentials to
//! automated agents (AI coding assistants, CI/CD, scripts).

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A delegation grants an agent permission to act on behalf of a human
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    /// Unique delegation ID
    pub id: Uuid,
    /// User who created the delegation
    pub user_id: Uuid,
    /// Human-readable name for this delegation
    pub name: String,
    /// What the agent is allowed to do
    pub scope: DelegationScope,
    /// When the delegation was created
    pub created_at: Timestamp,
    /// When the delegation expires
    pub expires_at: Timestamp,
    /// Has this delegation been revoked?
    pub revoked: bool,
    /// When it was revoked (if applicable)
    pub revoked_at: Option<Timestamp>,
    /// How many times this delegation has been used
    pub use_count: u64,
    /// Maximum uses allowed (None = unlimited)
    pub max_uses: Option<u64>,
}

/// What an agent is allowed to do
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationScope {
    /// Which credential targets are allowed
    pub targets: Vec<DelegationTarget>,
    /// Optional: restrict to specific operations
    pub operations: Option<Vec<String>>,
}

/// A scoped credential target for delegation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum DelegationTarget {
    /// GitHub with optional repo/branch restrictions
    GitHub {
        /// Allowed repositories (glob patterns)
        /// e.g., ["myorg/frontend", "myorg/api-*"]
        repositories: Vec<String>,
        /// Allowed branch patterns for push
        /// e.g., ["feature/*", "fix/*"]
        branches: Option<Vec<String>>,
        /// Restricted permissions (must be subset of user's)
        permissions: Option<crate::credentials::GitHubPermissions>,
    },
    /// AWS with role restriction
    Aws {
        /// Allowed role ARNs (exact match)
        role_arns: Vec<String>,
    },
    /// SSH with principal/host restrictions  
    Ssh {
        /// Allowed principals
        principals: Vec<String>,
        /// Allowed hosts (glob patterns)
        hosts: Option<Vec<String>>,
    },
}

/// Request to create a new delegation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDelegationRequest {
    /// Human-readable name
    pub name: String,
    /// What the agent can do
    pub scope: DelegationScope,
    /// How long until expiration (seconds)
    pub ttl_seconds: u64,
    /// Maximum uses (None = unlimited)
    pub max_uses: Option<u64>,
}

/// Response with delegation token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationResponse {
    /// The created delegation
    pub delegation: Delegation,
    /// Token for agent to use (JWT)
    pub token: String,
}

/// Summary of a delegation for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationSummary {
    pub id: Uuid,
    pub name: String,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub revoked: bool,
    pub use_count: u64,
    pub scope_summary: String, // e.g., "GitHub: myorg/* (read/write)"
}
