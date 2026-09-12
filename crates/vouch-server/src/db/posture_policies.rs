// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device posture policy database operations.
//!
//! Manages per-org activation of preconfigured policies (stored as a
//! `PostureConfigDoc`) and admin-authored policies (stored as
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
    /// Serialized builder `RuleSpec` the text was generated from, absent
    /// for hand-written policies. Advisory: never read by the engine.
    pub builder_spec: Option<String>,
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
            builder_spec: doc.data.builder_spec,
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

/// Document ID of an org's posture config, derived from the org ID.
///
/// `PostureConfigDoc` is "at most one per org", but `org_id` is an ordinary
/// index rather than a unique one, so two concurrent first activations both
/// read no config and both insert. Deriving the primary key from `org_id`
/// makes that collide: exactly one insert commits and the other observes a
/// unique violation, on every backend. Same construction as
/// `deterministic_challenge_state_id` and `deterministic_domain_claim_id`.
fn deterministic_posture_config_id(org_id: &str) -> String {
    use aws_lc_rs::digest::{self, SHA256};

    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(b"posture_config\0");
    ctx.update(org_id.as_bytes());
    hex::encode(ctx.finish().as_ref())
}

/// Set which preconfigured policy slugs are active for an org.
///
/// Creates the config document if it doesn't exist, or updates it.
///
/// This is an unconditional full-replace: the caller is authoritative for the
/// entire `active_slugs` list (it does *not* derive the list from a prior
/// read). Use it for authoritative writes such as test setup. Callers that
/// perform a read-modify-write — e.g. the toggle handler, which reads the
/// current slugs, mutates one entry, and writes the list back — must use
/// [`compare_and_set_preconfigured_active`] instead: this blind helper writes
/// the full list with no version guard, so two concurrent toggles each derive
/// from a stale read and the later write silently clobbers the earlier one.
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
            store
                .insert_with_id(&deterministic_posture_config_id(org_id), &doc)
                .await?;
        }
    }

    Ok(())
}

/// The identity, version, and active slugs of an org's posture config document.
///
/// Returned by [`get_preconfigured_active_with_version`] for callers that need
/// to perform an optimistic-concurrency update (e.g. the admin toggle handler,
/// which reads the slugs, mutates one, and writes the list back guarded by the
/// version captured here).
#[derive(Debug, Clone)]
pub struct ActivePreconfiguredConfig {
    /// UUID v7 of the `PostureConfigDoc` row — the CAS target.
    pub doc_id: String,
    /// Optimistic-concurrency version at the time of the read.
    pub version: i32,
    /// Active preconfigured slugs at the time of the read.
    pub active_slugs: Vec<String>,
}

/// Read the posture config for an org, returning the document id and version
/// alongside the active slugs so callers can issue an OCC-protected write.
///
/// Returns `None` if no config document exists yet (no preconfigured policy has
/// ever been activated for the org).
pub async fn get_preconfigured_active_with_version(
    store: &DocumentStore,
    org_id: &str,
) -> Result<Option<ActivePreconfiguredConfig>> {
    match get_posture_config(store, org_id).await? {
        Some(doc) => Ok(Some(ActivePreconfiguredConfig {
            doc_id: doc.id,
            version: doc.version,
            active_slugs: doc.data.active_slugs,
        })),
        None => Ok(None),
    }
}

/// Conditionally replace the active preconfigured slugs for an org, guarded by
/// optimistic concurrency.
///
/// Like [`set_preconfigured_active`], this is a full-replace: the caller is
/// authoritative for the entire `active_slugs` list and the stored value is
/// overwritten outright (no merge). Unlike the blind helper, the write only
/// commits when the document's version still equals `expected_version`, so a
/// concurrent toggle cannot silently overwrite this one — it surfaces as
/// `Ok(false)` and the caller re-reads and recomputes.
///
/// Returns `Ok(true)` if the update was applied; `Ok(false)` if a concurrent
/// modification bumped the version first (or, equivalently, the row was
/// removed). The handler turns the `false` into a `409 Conflict` so the admin
/// re-reads the page and re-issues the toggle against the current state.
pub async fn compare_and_set_preconfigured_active(
    store: &DocumentStore,
    doc_id: &str,
    expected_version: i32,
    org_id: &str,
    active_slugs: Vec<String>,
) -> Result<bool> {
    let updated = PostureConfigDoc {
        org_id: org_id.to_string(),
        active_slugs,
    };
    store
        .compare_and_update(doc_id, expected_version, &updated)
        .await
}

/// Create the posture config document for an org (first activation).
///
/// Inserts a new `PostureConfigDoc` with `active_slugs`. Use
/// [`compare_and_set_preconfigured_active`] once a config already exists.
///
/// Returns `Ok(true)` when this call created the document, and `Ok(false)`
/// when a concurrent first activation created it first. The ID is derived
/// from `org_id`, so the loser collides on the primary key rather than
/// inserting a second config for the same org — the version guard on the
/// update path cannot help here, there being no version to read yet. The
/// caller treats `false` exactly like a lost compare-and-update: re-read and
/// re-issue against the config that now exists.
pub async fn create_preconfigured_active(
    store: &DocumentStore,
    org_id: &str,
    active_slugs: Vec<String>,
) -> Result<bool> {
    let doc = PostureConfigDoc {
        org_id: org_id.to_string(),
        active_slugs,
    };
    match store
        .insert_with_id(&deterministic_posture_config_id(org_id), &doc)
        .await
    {
        Ok(_) => Ok(true),
        Err(e) if super::pool::is_unique_violation(&e) => Ok(false),
        Err(e) => Err(e),
    }
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
    pub builder_spec: Option<&'a str>,
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
        builder_spec: params.builder_spec.map(String::from),
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
    /// Follows `policy_text`: set when the new text came from the builder,
    /// cleared when it was hand-edited, kept for toggles.
    pub builder_spec: FieldUpdate<'a>,
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
    let builder_spec_owned = match params.builder_spec {
        FieldUpdate::Keep => None,
        FieldUpdate::Clear => Some(None::<String>),
        FieldUpdate::Set(s) => Some(Some(s.to_string())),
    };

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
            if let Some(ref spec_opt) = builder_spec_owned {
                data.builder_spec = spec_opt.clone();
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
