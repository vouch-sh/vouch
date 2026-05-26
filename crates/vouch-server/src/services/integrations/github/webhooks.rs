// SPDX-License-Identifier: Apache-2.0 OR MIT
//! GitHub webhook handling.
//!
//! This module handles:
//! - Webhook signature verification (HMAC-SHA256)
//! - Installation lifecycle events (created, deleted, suspend, unsuspend)
//! - Repository change events (added, removed)

use aws_lc_rs::hmac;
use serde::Deserialize;
use subtle::ConstantTimeEq;

use super::{GitHubError, GitHubResult, GitHubService};
use crate::db;

// ============================================================================
// Webhook Event Types
// ============================================================================

/// Installation webhook events with typed actions.
#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
#[allow(
    dead_code,
    reason = "GitHub webhook payload fields deserialized for completeness"
)]
pub(crate) enum InstallationEvent {
    Created {
        installation: WebhookInstallation,
        #[serde(default)]
        repositories: Vec<WebhookRepository>,
        sender: Option<WebhookSender>,
    },
    Deleted {
        installation: WebhookInstallation,
        #[serde(default)]
        repositories: Vec<WebhookRepository>,
    },
    Suspend {
        installation: WebhookInstallation,
    },
    Unsuspend {
        installation: WebhookInstallation,
    },
    /// Catch-all for unhandled actions (e.g., new_permissions_accepted).
    #[serde(other)]
    Unknown,
}

/// Installation repositories webhook events.
/// Note: Both arrays are always present in GitHub payloads (one may be empty).
#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub(crate) enum InstallationRepositoriesEvent {
    Added {
        installation: WebhookInstallation,
        #[serde(default)]
        repositories_added: Vec<WebhookRepository>,
        #[serde(default)]
        repositories_removed: Vec<WebhookRepository>,
    },
    Removed {
        installation: WebhookInstallation,
        #[serde(default)]
        repositories_added: Vec<WebhookRepository>,
        #[serde(default)]
        repositories_removed: Vec<WebhookRepository>,
    },
    /// Catch-all for unhandled actions.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize)]
pub(crate) struct WebhookInstallation {
    pub id: u64,
    pub account: WebhookAccount,
}

#[derive(Debug, Deserialize)]
#[allow(
    dead_code,
    reason = "GitHub webhook payload fields deserialized for completeness"
)]
pub(crate) struct WebhookAccount {
    pub login: String,
    #[serde(rename = "type")]
    pub account_type: String,
}

#[derive(Debug, Deserialize)]
#[allow(
    dead_code,
    reason = "GitHub webhook payload fields deserialized for completeness"
)]
pub(crate) struct WebhookRepository {
    pub name: String,
    pub full_name: String,
    pub private: bool,
}

#[derive(Debug, Deserialize)]
#[allow(
    dead_code,
    reason = "GitHub webhook payload fields deserialized for completeness"
)]
pub(crate) struct WebhookSender {
    pub login: String,
}

// ============================================================================
// Webhook Processing Types
// ============================================================================

/// Supported webhook event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebhookEvent {
    Installation,
    InstallationRepositories,
    Unknown,
}

impl From<&str> for WebhookEvent {
    fn from(header: &str) -> Self {
        match header {
            "installation" => Self::Installation,
            "installation_repositories" => Self::InstallationRepositories,
            _ => Self::Unknown,
        }
    }
}

/// Result of processing a webhook.
#[derive(Debug)]
pub(crate) enum WebhookResult {
    /// Event was processed successfully.
    Processed,
    /// Event type is not handled (ignored).
    Ignored,
}

// ============================================================================
// Webhook Processing Implementation
// ============================================================================

impl GitHubService<'_> {
    /// Verify webhook signature using HMAC-SHA256.
    ///
    /// # Arguments
    /// * `signature` - The signature from X-Hub-Signature-256 header (without "sha256=" prefix)
    /// * `body` - The raw request body
    pub(crate) fn verify_webhook_signature(
        &self,
        signature: &str,
        body: &[u8],
    ) -> GitHubResult<()> {
        let secret = self.webhook_secret()?;

        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let computed = hmac::sign(&key, body);
        let computed_hex = hex::encode(computed.as_ref());

        if computed_hex.as_bytes().ct_eq(signature.as_bytes()).into() {
            Ok(())
        } else {
            Err(GitHubError::InvalidSignature)
        }
    }

    /// Handle a webhook event.
    ///
    /// # Arguments
    /// * `event_type` - The event type from X-GitHub-Event header
    /// * `body` - The raw request body (already signature-verified)
    pub(crate) async fn handle_webhook_event(
        &self,
        event_type: WebhookEvent,
        body: &[u8],
    ) -> GitHubResult<WebhookResult> {
        match event_type {
            WebhookEvent::Installation => {
                self.handle_installation_event(body).await?;
                Ok(WebhookResult::Processed)
            }
            WebhookEvent::InstallationRepositories => {
                self.handle_installation_repositories_event(body).await?;
                Ok(WebhookResult::Processed)
            }
            WebhookEvent::Unknown => {
                tracing::debug!("Ignoring unknown webhook event type");
                Ok(WebhookResult::Ignored)
            }
        }
    }

    /// Handle installation webhook events (created, deleted, suspend, unsuspend).
    async fn handle_installation_event(&self, body: &[u8]) -> GitHubResult<()> {
        let event: InstallationEvent = serde_json::from_slice(body).map_err(|e| {
            tracing::warn!("Failed to parse installation payload: {}", e);
            GitHubError::Internal(format!("Invalid webhook payload: {e}"))
        })?;

        match event {
            InstallationEvent::Created {
                installation,
                repositories,
                ..
            } => {
                let installation_id = installation.id.cast_signed();
                let repo_names: Vec<String> = repositories.iter().map(|r| r.name.clone()).collect();

                if repo_names.is_empty() {
                    tracing::info!(
                        "GitHub installation created: {} ({}) with all repositories",
                        installation_id,
                        installation.account.login
                    );
                } else {
                    tracing::info!(
                        "GitHub installation created: {} ({}) with {} repositories",
                        installation_id,
                        installation.account.login,
                        repo_names.len()
                    );
                    if let Err(e) = db::update_github_installation_repos(
                        self.store,
                        installation_id,
                        &repo_names,
                    )
                    .await
                    {
                        tracing::error!(
                            "Failed to update repos for installation {}: {}",
                            installation_id,
                            e
                        );
                    }
                }
            }
            InstallationEvent::Deleted { installation, .. } => {
                let installation_id = installation.id.cast_signed();
                tracing::info!(
                    "GitHub installation deleted: {} ({})",
                    installation_id,
                    installation.account.login
                );
                if let Err(e) =
                    db::delete_github_installation_by_installation_id(self.store, installation_id)
                        .await
                {
                    tracing::error!("Failed to delete installation {}: {}", installation_id, e);
                }
            }
            InstallationEvent::Suspend { installation } => {
                let installation_id = installation.id.cast_signed();
                tracing::info!(
                    "GitHub installation suspended: {} ({})",
                    installation_id,
                    installation.account.login
                );
                if let Err(e) = db::suspend_github_installation(self.store, installation_id).await {
                    tracing::error!("Failed to suspend installation {}: {}", installation_id, e);
                }
            }
            InstallationEvent::Unsuspend { installation } => {
                let installation_id = installation.id.cast_signed();
                tracing::info!(
                    "GitHub installation unsuspended: {} ({})",
                    installation_id,
                    installation.account.login
                );
                if let Err(e) = db::unsuspend_github_installation(self.store, installation_id).await
                {
                    tracing::error!(
                        "Failed to unsuspend installation {}: {}",
                        installation_id,
                        e
                    );
                }
            }
            InstallationEvent::Unknown => {
                tracing::debug!("Ignoring unknown installation action");
            }
        }

        Ok(())
    }

    /// Handle installation_repositories webhook events (added/removed repos).
    async fn handle_installation_repositories_event(&self, body: &[u8]) -> GitHubResult<()> {
        let event: InstallationRepositoriesEvent = serde_json::from_slice(body).map_err(|e| {
            tracing::warn!("Failed to parse installation_repositories payload: {}", e);
            GitHubError::Internal(format!("Invalid webhook payload: {e}"))
        })?;

        let (installation, added, removed, action) = match event {
            InstallationRepositoriesEvent::Added {
                installation,
                repositories_added,
                repositories_removed,
            } => (
                installation,
                repositories_added,
                repositories_removed,
                "added",
            ),
            InstallationRepositoriesEvent::Removed {
                installation,
                repositories_added,
                repositories_removed,
            } => (
                installation,
                repositories_added,
                repositories_removed,
                "removed",
            ),
            InstallationRepositoriesEvent::Unknown => {
                tracing::debug!("Ignoring unknown installation_repositories action");
                return Ok(());
            }
        };

        let installation_id = installation.id.cast_signed();
        let added_names: Vec<String> = added.iter().map(|r| r.name.clone()).collect();
        let removed_names: Vec<String> = removed.iter().map(|r| r.name.clone()).collect();

        tracing::info!(
            "GitHub installation {} repositories updated: +{} -{} ({})",
            installation_id,
            added_names.len(),
            removed_names.len(),
            action
        );

        if let Err(e) = db::update_github_installation_repos_delta(
            self.store,
            installation_id,
            &added_names,
            &removed_names,
        )
        .await
        {
            tracing::error!(
                "Failed to update repos delta for installation {}: {}",
                installation_id,
                e
            );
        }

        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_installation_created() {
        let payload = r#"{
            "action": "created",
            "installation": { "id": 957387, "account": { "login": "Codertocat", "type": "User" } },
            "repositories": [{ "name": "Hello-World", "full_name": "Codertocat/Hello-World", "private": false }],
            "sender": { "login": "Codertocat" }
        }"#;
        let event: InstallationEvent = serde_json::from_str(payload).unwrap();
        assert!(
            matches!(event, InstallationEvent::Created { .. }),
            "Expected Created event"
        );
        let InstallationEvent::Created {
            installation,
            repositories,
            ..
        } = event
        else {
            return;
        };
        assert_eq!(installation.id, 957387);
        assert_eq!(installation.account.login, "Codertocat");
        assert_eq!(repositories.len(), 1);
        assert_eq!(repositories[0].name, "Hello-World");
    }

    #[test]
    fn test_parse_installation_created_without_repos() {
        let payload = r#"{
            "action": "created",
            "installation": { "id": 123, "account": { "login": "test-org", "type": "Organization" } },
            "sender": { "login": "admin" }
        }"#;
        let event: InstallationEvent = serde_json::from_str(payload).unwrap();
        assert!(
            matches!(event, InstallationEvent::Created { .. }),
            "Expected Created event"
        );
        let InstallationEvent::Created { repositories, .. } = event else {
            return;
        };
        assert!(repositories.is_empty());
    }

    #[test]
    fn test_parse_installation_deleted() {
        let payload = r#"{
            "action": "deleted",
            "installation": { "id": 957387, "account": { "login": "Codertocat", "type": "User" } },
            "repositories": []
        }"#;
        let event: InstallationEvent = serde_json::from_str(payload).unwrap();
        assert!(matches!(event, InstallationEvent::Deleted { .. }));
    }

    #[test]
    fn test_parse_installation_suspend() {
        let payload = r#"{
            "action": "suspend",
            "installation": { "id": 957387, "account": { "login": "Codertocat", "type": "User" } }
        }"#;
        let event: InstallationEvent = serde_json::from_str(payload).unwrap();
        assert!(matches!(event, InstallationEvent::Suspend { .. }));
    }

    #[test]
    fn test_parse_installation_unsuspend() {
        let payload = r#"{
            "action": "unsuspend",
            "installation": { "id": 957387, "account": { "login": "Codertocat", "type": "User" } }
        }"#;
        let event: InstallationEvent = serde_json::from_str(payload).unwrap();
        assert!(matches!(event, InstallationEvent::Unsuspend { .. }));
    }

    #[test]
    fn test_parse_installation_unknown_action() {
        let payload = r#"{
            "action": "new_permissions_accepted",
            "installation": { "id": 1, "account": { "login": "x", "type": "User" } }
        }"#;
        let event: InstallationEvent = serde_json::from_str(payload).unwrap();
        assert!(matches!(event, InstallationEvent::Unknown));
    }

    #[test]
    fn test_parse_installation_repositories_added() {
        let payload = r#"{
            "action": "added",
            "installation": { "id": 957387, "account": { "login": "Codertocat", "type": "User" } },
            "repositories_added": [{ "name": "Space", "full_name": "Codertocat/Space", "private": false }],
            "repositories_removed": []
        }"#;
        let event: InstallationRepositoriesEvent = serde_json::from_str(payload).unwrap();
        assert!(
            matches!(event, InstallationRepositoriesEvent::Added { .. }),
            "Expected Added event"
        );
        let InstallationRepositoriesEvent::Added {
            installation,
            repositories_added,
            repositories_removed,
        } = event
        else {
            return;
        };
        assert_eq!(installation.id, 957387);
        assert_eq!(repositories_added.len(), 1);
        assert_eq!(repositories_added[0].name, "Space");
        assert!(repositories_removed.is_empty());
    }

    #[test]
    fn test_parse_installation_repositories_removed() {
        let payload = r#"{
            "action": "removed",
            "installation": { "id": 957387, "account": { "login": "Codertocat", "type": "User" } },
            "repositories_added": [],
            "repositories_removed": [{ "name": "OldRepo", "full_name": "Codertocat/OldRepo", "private": true }]
        }"#;
        let event: InstallationRepositoriesEvent = serde_json::from_str(payload).unwrap();
        assert!(
            matches!(event, InstallationRepositoriesEvent::Removed { .. }),
            "Expected Removed event"
        );
        let InstallationRepositoriesEvent::Removed {
            repositories_added,
            repositories_removed,
            ..
        } = event
        else {
            return;
        };
        assert!(repositories_added.is_empty());
        assert_eq!(repositories_removed.len(), 1);
        assert_eq!(repositories_removed[0].name, "OldRepo");
    }

    #[test]
    fn test_parse_installation_repositories_unknown_action() {
        let payload = r#"{
            "action": "future_action",
            "installation": { "id": 1, "account": { "login": "x", "type": "User" } }
        }"#;
        let event: InstallationRepositoriesEvent = serde_json::from_str(payload).unwrap();
        assert!(matches!(event, InstallationRepositoriesEvent::Unknown));
    }

    #[test]
    fn test_webhook_event_from_header() {
        assert_eq!(
            WebhookEvent::from("installation"),
            WebhookEvent::Installation
        );
        assert_eq!(
            WebhookEvent::from("installation_repositories"),
            WebhookEvent::InstallationRepositories
        );
        assert_eq!(WebhookEvent::from("push"), WebhookEvent::Unknown);
        assert_eq!(WebhookEvent::from(""), WebhookEvent::Unknown);
    }
}
