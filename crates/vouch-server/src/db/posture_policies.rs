// SPDX-License-Identifier: BUSL-1.1
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
    pub cel_expression: String,
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
            cel_expression: doc.data.cel_expression,
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
pub async fn get_posture_config(
    store: &DocumentStore,
    org_id: &str,
) -> Result<Option<Document<PostureConfigDoc>>> {
    store
        .find_one::<PostureConfigDoc>("org_id", org_id)
        .await
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
    pub cel_expression: &'a str,
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
        cel_expression: params.cel_expression.to_string(),
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
pub async fn get_active_custom_policies(
    store: &DocumentStore,
    org_id: &str,
) -> Result<Vec<CustomPosturePolicy>> {
    let all = list_custom_policies(store, org_id).await?;
    Ok(all.into_iter().filter(|p| p.active).collect())
}

/// Get a custom posture policy by ID.
pub async fn get_custom_policy(
    store: &DocumentStore,
    id: &str,
) -> Result<Option<CustomPosturePolicy>> {
    let doc = store.get::<CustomPosturePolicyDoc>(id).await?;
    Ok(doc.map(CustomPosturePolicy::from))
}

/// Parameters for updating a custom posture policy.
pub struct UpdateCustomPolicyParams<'a> {
    pub name: Option<&'a str>,
    pub description: Option<Option<&'a str>>,
    pub cel_expression: Option<&'a str>,
    pub active: Option<bool>,
}

/// Update a custom posture policy.
pub async fn update_custom_policy(
    store: &DocumentStore,
    id: &str,
    org_id: &str,
    params: UpdateCustomPolicyParams<'_>,
) -> Result<Option<CustomPosturePolicy>> {
    let doc = store.get::<CustomPosturePolicyDoc>(id).await?;
    let Some(doc) = doc else {
        return Ok(None);
    };

    // Verify org ownership
    if doc.data.org_id != org_id {
        return Ok(None);
    }

    let updated = CustomPosturePolicyDoc {
        name: params
            .name
            .map(String::from)
            .unwrap_or(doc.data.name),
        description: match params.description {
            Some(d) => d.map(String::from),
            None => doc.data.description,
        },
        cel_expression: params
            .cel_expression
            .map(String::from)
            .unwrap_or(doc.data.cel_expression),
        active: params.active.unwrap_or(doc.data.active),
        org_id: doc.data.org_id,
    };

    store.update(id, &updated).await?;

    // Re-fetch to get updated timestamps
    let refreshed = store.get::<CustomPosturePolicyDoc>(id).await?;
    Ok(refreshed.map(CustomPosturePolicy::from))
}

/// Delete a custom posture policy.
///
/// Returns `true` if the policy was found and deleted, `false` if not found.
pub async fn delete_custom_policy(
    store: &DocumentStore,
    id: &str,
    org_id: &str,
) -> Result<bool> {
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

/// Count total active policies for an org (preconfigured + custom).
pub async fn count_active_policies(
    store: &DocumentStore,
    org_id: &str,
) -> Result<usize> {
    let preconfigured_count = get_active_preconfigured_slugs(store, org_id)
        .await?
        .len();
    let custom_active = get_active_custom_policies(store, org_id)
        .await?
        .len();
    Ok(preconfigured_count + custom_active)
}
