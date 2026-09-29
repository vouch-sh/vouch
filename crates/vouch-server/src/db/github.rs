// SPDX-License-Identifier: Apache-2.0 OR MIT
//! GitHub App installation database operations.

use std::collections::HashMap;

use super::document_type::Document;
use super::documents::github::GitHubInstallationDoc;
use super::store::DocumentStore;
use anyhow::Result;
use jiff::Timestamp;

// ============================================================================
// GitHub App Installations
// ============================================================================

/// GitHub App installation record.
#[derive(Debug)]
pub struct GitHubInstallation {
    pub id: String,
    pub org_id: String,
    pub installation_id: i64,
    pub github_account_login: String,
    pub github_account_type: String,
    pub permissions: HashMap<String, String>,
    pub repository_selection: String,
    pub installed_at: Timestamp,
    pub installed_by_user_id: Option<String>,
    pub suspended_at: Option<Timestamp>,
    pub repositories: Option<Vec<String>>,
}

impl From<Document<GitHubInstallationDoc>> for GitHubInstallation {
    fn from(doc: Document<GitHubInstallationDoc>) -> Self {
        Self {
            id: doc.id,
            org_id: doc.data.org_id,
            installation_id: doc.data.installation_id,
            github_account_login: doc.data.github_account_login,
            github_account_type: doc.data.github_account_type,
            permissions: doc.data.permissions,
            repository_selection: doc.data.repository_selection,
            installed_at: doc.data.installed_at,
            installed_by_user_id: doc.data.installed_by_user_id,
            suspended_at: doc.data.suspended_at,
            repositories: doc.data.repositories,
        }
    }
}

/// Parameters for creating a new GitHub App installation.
pub struct CreateGitHubInstallationParams<'a> {
    pub org_id: &'a str,
    pub installation_id: i64,
    pub github_account_login: &'a str,
    pub github_account_type: &'a str,
    pub permissions: &'a HashMap<String, String>,
    pub repository_selection: &'a str,
    pub installed_by_user_id: Option<&'a str>,
}

/// Errors returned by [`create_github_installation`].
///
/// `Duplicate` is terminal (not retried): a replayed install callback or a
/// concurrent connect for the same `installation_id` collided on the
/// deterministic primary key. The service layer maps it to
/// `GitHubError::InstallationAlreadyConnected`. `Other` is surfaced from the
/// document store.
#[derive(Debug, thiserror::Error)]
pub enum CreateGitHubInstallationError {
    /// An installation with the same `installation_id` is already linked to an
    /// organization (GitHub installations are globally unique across all orgs).
    #[error("GitHub installation already connected for this organization")]
    Duplicate,
    /// Database or unexpected infrastructure failure.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Derive a deterministic document ID from `installation_id` alone so that
/// two concurrent connect/replay attempts for the same GitHub installation
/// collide on the primary key of the `documents` table instead of producing
/// duplicate rows.
///
/// The ID is scoped to `installation_id` — not `(org_id, installation_id)` —
/// to match the service layer's global-uniqueness invariant: a GitHub
/// installation can be linked to at most one Vouch organization. Scoping to
/// `(org_id, installation_id)` left a TOCTOU window where two concurrent
/// cross-org `connect_installation` calls both passed the global guard (the
/// `installation_id` index lookup) and produced distinct primary keys, so
/// neither insert collided and both committed, linking one installation to
/// two organizations. Dropping `org_id` from the hash makes cross-org
/// connects collide exactly like same-org connects do.
///
/// The unique constraint on `(document_id, index_field, index_value)` does
/// NOT enforce uniqueness across documents on `(index_field, index_value)`
/// (see `db/enrollment.rs`), so a `create_github_installation` call that
/// generated random IDs could not be made race-safe at the SQL level. Hashing
/// `installation_id` into a stable primary key closes the TOCTOU window,
/// mirroring `deterministic_challenge_state_id` and `deterministic_org_id`.
/// The `"github_installation\0"` domain separator prevents cross-type ID
/// collisions. Output is hex-encoded SHA-256.
fn deterministic_installation_id(installation_id: i64) -> String {
    use aws_lc_rs::digest::{self, SHA256};

    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(b"github_installation\0");
    ctx.update(&installation_id.to_le_bytes());
    hex::encode(ctx.finish().as_ref())
}

/// Create a new GitHub App installation for an organization.
///
/// Uses a deterministic document ID derived from `installation_id` alone so a
/// replayed install callback (or two concurrent connects — including cross-org)
/// collide on the primary key and return [`CreateGitHubInstallationError::Duplicate`]
/// instead of creating a duplicate row. The collision is race-safe: the document
/// store reports a unique/primary-key violation that this function maps to
/// `Duplicate`, so exactly one of N concurrent calls commits. See
/// `db/challenge_states.rs` for the same pattern.
///
/// GitHub installations are globally unique: a given `installation_id` may be
/// linked to at most one Vouch organization. This matches the service-layer
/// guard in `connect_installation`/`reconnect_installation`, which rejects any
/// second connect for the same `installation_id` regardless of org. The
/// webhook helpers still act on every row for an `installation_id`, since a
/// row written before this ID scheme can sit beside another.
#[expect(clippy::disallowed_methods, reason = "stamps the row's installed_at")]
pub async fn create_github_installation(
    store: &DocumentStore,
    params: &CreateGitHubInstallationParams<'_>,
) -> Result<String, CreateGitHubInstallationError> {
    let id = deterministic_installation_id(params.installation_id);
    let doc = GitHubInstallationDoc {
        org_id: params.org_id.to_string(),
        installation_id: params.installation_id,
        github_account_login: params.github_account_login.to_string(),
        github_account_type: params.github_account_type.to_string(),
        permissions: params.permissions.clone(),
        repository_selection: params.repository_selection.to_string(),
        installed_at: Timestamp::now(),
        installed_by_user_id: params.installed_by_user_id.map(String::from),
        suspended_at: None,
        repositories: None,
    };

    match store.insert_with_id(&id, &doc).await {
        Ok(result) => Ok(result.id),
        Err(e) if super::pool::is_unique_violation(&e) => {
            Err(CreateGitHubInstallationError::Duplicate)
        }
        Err(e) => Err(CreateGitHubInstallationError::Other(e)),
    }
}

/// Get all GitHub installations for an organization.
pub async fn get_github_installations_by_org(
    store: &DocumentStore,
    org_id: &str,
) -> Result<Vec<GitHubInstallation>> {
    let docs = store
        .find_all::<GitHubInstallationDoc>("org_id", org_id)
        .await?;

    let mut installations: Vec<GitHubInstallation> =
        docs.into_iter().map(GitHubInstallation::from).collect();

    installations.sort_by(|a, b| a.github_account_login.cmp(&b.github_account_login));

    Ok(installations)
}

/// Get GitHub installation by organization ID and
/// GitHub account login (case-insensitive).
pub async fn get_github_installation_by_org_and_account(
    store: &DocumentStore,
    org_id: &str,
    github_account: &str,
) -> Result<Option<GitHubInstallation>> {
    let docs = store
        .find_all::<GitHubInstallationDoc>("org_id", org_id)
        .await?;

    let account_lower = github_account.to_lowercase();
    let found = docs
        .into_iter()
        .find(|d| d.data.github_account_login.to_lowercase() == account_lower);

    Ok(found.map(GitHubInstallation::from))
}

/// Get GitHub installation by installation ID.
pub async fn get_github_installation_by_installation_id(
    store: &DocumentStore,
    installation_id: i64,
) -> Result<Option<GitHubInstallation>> {
    let doc = store
        .find_one::<GitHubInstallationDoc>("installation_id", &installation_id.to_string())
        .await?;

    Ok(doc.map(GitHubInstallation::from))
}

/// Delete every row recorded for an installation ID, in one transaction.
///
/// [`create_github_installation`] writes one row per `installation_id`, but a
/// row written before its document ID was derived from `installation_id` can
/// sit beside another for the same installation. An `installation.deleted`
/// webhook removes all of them.
pub async fn delete_github_installation_by_installation_id(
    store: &DocumentStore,
    installation_id: i64,
) -> Result<bool> {
    let deleted = store
        .delete_by_index::<GitHubInstallationDoc>("installation_id", &installation_id.to_string())
        .await?;
    Ok(deleted > 0)
}

/// Apply `modifier` to every row recorded for an installation ID, each through
/// optimistic concurrency (`store.modify`), so concurrent webhook events never
/// lose an update. Every modifier here is idempotent, so a failure part way
/// through converges when GitHub redelivers the webhook.
///
/// Returns `true` if any row was modified, `false` if none exists (including
/// one deleted between the lookup and its modify).
async fn modify_installation_rows<F>(
    store: &DocumentStore,
    installation_id: i64,
    modifier: F,
) -> Result<bool>
where
    F: Fn(&mut GitHubInstallationDoc),
{
    let docs = store
        .find_all::<GitHubInstallationDoc>("installation_id", &installation_id.to_string())
        .await?;
    let mut modified = false;
    for doc in docs {
        if store
            .modify::<GitHubInstallationDoc, _>(&doc.id, &modifier)
            .await?
        {
            modified = true;
        }
    }
    Ok(modified)
}

/// Suspend every row for a GitHub installation (used by webhook handler).
/// See [`modify_installation_rows`].
#[expect(clippy::disallowed_methods, reason = "stamps the row's suspended_at")]
pub async fn suspend_github_installation(
    store: &DocumentStore,
    installation_id: i64,
) -> Result<bool> {
    let suspended_at = Timestamp::now();
    modify_installation_rows(store, installation_id, |data| {
        data.suspended_at = Some(suspended_at);
    })
    .await
}

/// Unsuspend every row for a GitHub installation (used by webhook handler).
/// See [`modify_installation_rows`].
pub async fn unsuspend_github_installation(
    store: &DocumentStore,
    installation_id: i64,
) -> Result<bool> {
    modify_installation_rows(store, installation_id, |data| {
        data.suspended_at = None;
    })
    .await
}

/// Replace the repositories of every row for a GitHub installation.
/// See [`modify_installation_rows`].
pub async fn update_github_installation_repos(
    store: &DocumentStore,
    installation_id: i64,
    repos: &[String],
) -> Result<bool> {
    modify_installation_rows(store, installation_id, |data| {
        data.repositories = Some(repos.to_vec());
    })
    .await
}

/// Update repositories for a GitHub installation by
/// adding/removing repos (used by webhook handler).
///
/// The delta merge runs inside the `store.modify` closure, so every
/// optimistic-concurrency retry re-reads the current repo list and re-applies
/// the delta to fresh state: two concurrent delta webhooks for the same
/// installation both land. The merge is idempotent (adds are deduplicated,
/// removals filter by name, the result is sorted). It is applied to every row
/// for the installation; see [`modify_installation_rows`].
pub async fn update_github_installation_repos_delta(
    store: &DocumentStore,
    installation_id: i64,
    added: &[String],
    removed: &[String],
) -> Result<bool> {
    modify_installation_rows(store, installation_id, |data| {
        let repos = data.repositories.get_or_insert_default();
        for repo in added {
            if !repos.contains(repo) {
                repos.push(repo.clone());
            }
        }
        repos.retain(|r| !removed.contains(r));
        repos.sort();
    })
    .await
}

/// Get all linked GitHub installation IDs (across all orgs).
///
/// Useful for finding "orphaned" installations on GitHub
/// that aren't in the database.
pub async fn get_all_linked_installation_ids(store: &DocumentStore) -> Result<Vec<i64>> {
    let docs = store.list_all::<GitHubInstallationDoc>().await?;
    Ok(docs.into_iter().map(|d| d.data.installation_id).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- deterministic_installation_id ----

    /// Same `installation_id` input must always produce the same document ID.
    /// This is what makes a replay (or a concurrent cross-org connect) collide
    /// on the primary key instead of creating a duplicate row.
    #[test]
    fn deterministic_installation_id_is_stable() {
        let a = deterministic_installation_id(42);
        let b = deterministic_installation_id(42);
        assert_eq!(a, b, "same installation_id must produce the same ID");
        // Hex-encoded SHA-256 is 64 chars.
        assert_eq!(a.len(), 64, "ID must be hex-encoded SHA-256");
        assert!(
            a.chars().all(|c| c.is_ascii_hexdigit()),
            "ID must be lowercase hex"
        );
    }

    /// Different `installation_id` values must produce different IDs (so a
    /// multi-account org linking several distinct installations doesn't
    /// collide).
    #[test]
    fn deterministic_installation_id_differs_by_installation_id() {
        let a = deterministic_installation_id(1);
        let b = deterministic_installation_id(2);
        assert_ne!(a, b, "different installation_id must differ");
    }

    /// The deterministic ID is a pure function of `installation_id` alone — it
    /// does not mix in `org_id` — so two concurrent connects of the same
    /// `installation_id` in different orgs produce the *same* primary key and
    /// collide on `insert_with_id`. This is the global-uniqueness property the
    /// service-layer guard already assumes, and the fix that closes the
    /// cross-org TOCTOU window the previous `(org_id, installation_id)`
    /// scoping left open.
    #[test]
    fn deterministic_installation_id_is_globally_scoped_to_installation_id() {
        // The function takes only `installation_id`; there is no org dimension
        // to vary, so the same installation_id always maps to one primary key.
        let a = deterministic_installation_id(42);
        let b = deterministic_installation_id(42);
        assert_eq!(
            a, b,
            "same installation_id must collide on the primary key regardless of org"
        );

        // A different installation_id must not accidentally collide.
        let c = deterministic_installation_id(43);
        assert_ne!(a, c, "distinct installation_id must not collide");
    }

    /// The domain separator (`b"github_installation\0"`) must keep the
    /// installation ID distinct from a raw digest of the same input bytes
    /// (i.e. the prefix is actually mixed in). This is what keeps the ID
    /// domains apart: the `deterministic_challenge_state_id` and
    /// `deterministic_org_id` helpers use different prefixes
    /// (`b"challenge_state\0"`, `b"organization_domain\0"`), so they can never
    /// produce a `documents`-primary-key collision with an installation ID
    /// built from identical trailing bytes.
    #[test]
    fn deterministic_installation_id_is_domain_separated() {
        use aws_lc_rs::digest::{self, SHA256};

        let id = deterministic_installation_id(42);

        // A digest of the raw inputs WITHOUT the domain prefix.
        let mut raw = digest::Context::new(&SHA256);
        raw.update(&42i64.to_le_bytes());
        let raw_id = hex::encode(raw.finish().as_ref());

        assert_ne!(
            id, raw_id,
            "domain separator must change the digest, preventing cross-type ID collisions"
        );
    }
}
