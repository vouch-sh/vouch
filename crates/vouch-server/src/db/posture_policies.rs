// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device posture policy database operations.
//!
//! Manages per-org activation of preconfigured policies (stored as a
//! `PostureConfigDoc`) and custom CEL-based policies (stored as
//! `CustomPosturePolicyDoc` documents).

use super::document_type::Document;
use super::documents::posture_policy::{CustomPosturePolicyDoc, PostureConfigDoc};
use super::store::DocumentStore;
use anyhow::Result;
use jiff::Timestamp;

// ============================================================
// Custom Posture Policy
// ============================================================

/// A custom posture policy record (public API type).
#[derive(Debug, Clone)]
pub struct CustomPosturePolicy {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub policy_text: String,
    pub active: bool,
    pub org_id: String,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl From<Document<CustomPosturePolicyDoc>> for CustomPosturePolicy {
    fn from(doc: Document<CustomPosturePolicyDoc>) -> Self {
        Self {
            id: doc.id,
            name: doc.data.name,
            description: doc.data.description,
            policy_text: doc.data.policy_text,
            active: doc.data.active,
            org_id: doc.data.org_id,
            created_at: doc.created_at,
            updated_at: doc.updated_at,
        }
    }
}

// ============================================================
// Posture Config (preconfigured policy activation)
// ============================================================

/// Get the posture config for an org (which preconfigured slugs are active).
///
/// Returns `None` if no config exists yet (no preconfigured policies activated).
pub(super) async fn get_posture_config(
    store: &DocumentStore,
    org_id: &str,
) -> Result<Option<Document<PostureConfigDoc>>> {
    store.find_one::<PostureConfigDoc>("org_id", org_id).await
}

/// Set which preconfigured policy slugs are active for an org.
///
/// Creates the config document if it doesn't exist, or updates it.
pub async fn set_preconfigured_active(
    store: &DocumentStore,
    org_id: &str,
    active_slugs: Vec<String>,
) -> Result<()> {
    let existing = get_posture_config(store, org_id).await?;

    match existing {
        Some(doc) => {
            let updated = PostureConfigDoc {
                org_id: org_id.to_string(),
                active_slugs,
            };
            store.update(&doc.id, &updated).await?;
        }
        None => {
            let doc = PostureConfigDoc {
                org_id: org_id.to_string(),
                active_slugs,
            };
            store.insert(&doc).await?;
        }
    }

    Ok(())
}

/// Get the list of active preconfigured slugs for an org.
pub async fn get_active_preconfigured_slugs(
    store: &DocumentStore,
    org_id: &str,
) -> Result<Vec<String>> {
    match get_posture_config(store, org_id).await? {
        Some(doc) => Ok(doc.data.active_slugs),
        None => Ok(Vec::new()),
    }
}

// ============================================================
// Custom Posture Policies
// ============================================================

/// Parameters for creating a custom posture policy.
pub struct CreateCustomPolicyParams<'a> {
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub policy_text: &'a str,
    pub org_id: &'a str,
}

/// Create a new custom posture policy (defaults to inactive).
pub async fn create_custom_policy(
    store: &DocumentStore,
    params: CreateCustomPolicyParams<'_>,
) -> Result<CustomPosturePolicy> {
    let doc = CustomPosturePolicyDoc {
        name: params.name.to_string(),
        description: params.description.map(String::from),
        policy_text: params.policy_text.to_string(),
        active: false,
        org_id: params.org_id.to_string(),
    };
    let result = store.insert(&doc).await?;
    Ok(CustomPosturePolicy::from(result))
}

/// List all custom posture policies for an org.
pub async fn list_custom_policies(
    store: &DocumentStore,
    org_id: &str,
) -> Result<Vec<CustomPosturePolicy>> {
    let docs = store
        .find_all::<CustomPosturePolicyDoc>("org_id", org_id)
        .await?;
    Ok(docs.into_iter().map(CustomPosturePolicy::from).collect())
}

/// Get active custom posture policies for an org.
///
/// Filters at the DB level using indexed `org_id` + `active` fields.
pub async fn get_active_custom_policies(
    store: &DocumentStore,
    org_id: &str,
) -> Result<Vec<CustomPosturePolicy>> {
    let docs = store
        .find_by_indexes::<CustomPosturePolicyDoc>(&[("org_id", org_id), ("active", "true")])
        .await?;
    Ok(docs.into_iter().map(CustomPosturePolicy::from).collect())
}

/// Get a custom posture policy by ID.
pub async fn get_custom_policy(
    store: &DocumentStore,
    id: &str,
) -> Result<Option<CustomPosturePolicy>> {
    let doc = store.get::<CustomPosturePolicyDoc>(id).await?;
    Ok(doc.map(CustomPosturePolicy::from))
}

/// Intent for an optional field in a PATCH-style update.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FieldUpdate<'a> {
    /// Leave the stored value unchanged.
    #[default]
    Keep,
    /// Clear the stored value.
    Clear,
    /// Replace the stored value.
    Set(&'a str),
}

/// Parameters for updating a custom posture policy.
pub struct UpdateCustomPolicyParams<'a> {
    pub name: Option<&'a str>,
    pub description: FieldUpdate<'a>,
    pub policy_text: Option<&'a str>,
    pub active: Option<bool>,
}

/// Update a custom posture policy.
///
/// Uses optimistic concurrency (`store.modify`) so concurrent mutations to the
/// same policy (e.g. a concurrent activation toggle) do not silently overwrite
/// each other. The org-scope check is re-evaluated inside the closure on each
/// OCC retry. Re-fetches the document after the write to capture updated timestamps.
pub async fn update_custom_policy(
    store: &DocumentStore,
    id: &str,
    org_id: &str,
    params: UpdateCustomPolicyParams<'_>,
) -> Result<Option<CustomPosturePolicy>> {
    // Pre-check: return not-found quickly without entering the modify loop
    // if the policy is absent or belongs to a different org.
    let Some(doc) = store.get::<CustomPosturePolicyDoc>(id).await? else {
        return Ok(None);
    };
    if doc.data.org_id != org_id {
        return Ok(None);
    }

    // Owned copies for the Fn closure (params borrows from caller stack).
    let name_owned = params.name.map(String::from);
    let description_owned = match params.description {
        FieldUpdate::Keep => None,
        FieldUpdate::Clear => Some(None::<String>),
        FieldUpdate::Set(d) => Some(Some(d.to_string())),
    };
    let cel_owned = params.policy_text.map(String::from);
    let active_owned = params.active;

    let applied = std::sync::atomic::AtomicBool::new(false);
    let found = store
        .modify::<CustomPosturePolicyDoc, _>(id, |data| {
            // Reset at the top of every attempt: if an earlier OCC retry set
            // this flag but then lost the version race, the closure runs again
            // and org ownership must be re-evaluated from scratch.
            applied.store(false, std::sync::atomic::Ordering::Relaxed);
            // Re-check org ownership inside the closure so a concurrent
            // org migration cannot smuggle a cross-org write through a version win.
            if data.org_id != org_id {
                return;
            }
            if let Some(ref n) = name_owned {
                data.name = n.clone();
            }
            // description is a 3-way FieldUpdate: None means Keep (no-op).
            if let Some(ref desc_opt) = description_owned {
                data.description = desc_opt.clone();
            }
            if let Some(ref cel) = cel_owned {
                data.policy_text = cel.clone();
            }
            if let Some(active) = active_owned {
                data.active = active;
            }
            applied.store(true, std::sync::atomic::Ordering::Relaxed);
        })
        .await?;

    if !found || !applied.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(None);
    }

    // Re-fetch to get updated timestamps.
    let refreshed = store.get::<CustomPosturePolicyDoc>(id).await?;
    Ok(refreshed.map(CustomPosturePolicy::from))
}

/// Delete a custom posture policy.
///
/// Returns `true` if the policy was found and deleted, `false` if not found.
pub async fn delete_custom_policy(store: &DocumentStore, id: &str, org_id: &str) -> Result<bool> {
    let doc = store.get::<CustomPosturePolicyDoc>(id).await?;
    let Some(doc) = doc else {
        return Ok(false);
    };

    // Verify org ownership
    if doc.data.org_id != org_id {
        return Ok(false);
    }

    store.delete(id).await?;
    Ok(true)
}
