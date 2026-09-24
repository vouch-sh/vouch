// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Database module tests, one file per domain.
//!
//! Shared fixtures (`test_db`, `seed_test_org`, `test_org_doc`, the
//! `update_scim_group` edits, the `TEST_ORG_*` constants) live here in the module root. New tests go in
//! the file whose scope matches; add a new file (and list it here) when
//! none does:
//!
//! - [`arrival_anchored_expiry`] — Request-deciding expiry comparisons read the caller's instant, not an ambient clock.
//! - [`audit_events`] — Auth/key/device audit event logging and expiry.
//! - [`authenticators`] — Authenticator (security key) CRUD and counting.
//! - [`cascade_delete`] — Cascade deletion of users and OAuth clients with their dependent rows, and the transfer of org-scoped applications when their creator is deleted or deactivated.
//! - [`challenge_states`] — FIDO2 challenge state single-use enforcement.
//! - [`concurrency`] — Concurrent-replay and CAS regressions for single-use primitives and state-transition helpers.
//! - [`device_auth`] — Device authorization grant (RFC 8628): request lifecycle, polling, atomic consumption, single-use semantics.
//! - [`email_normalization`] — Email canonicalization across SCIM provisioning and OIDC enrollment.
//! - [`identity_binding`] — Upstream (issuer, subject) identity binding and account matching.
//! - [`jti_replay`] — JWT-assertion and DPoP JTI replay prevention and expiry cleanup.
//! - [`jwks_cache`] — Client JWKS cache behavioral invariants.
//! - [`oauth_clients`] — OAuth client application CRUD, client types, secret validity.
//! - [`oauth_secrets`] — OAuth client secret cap/floor OCC invariants.
//! - [`occ_modify`] — OCC read-modify-write conversions: every mutation path uses `store.modify`, not blind get+update.
//! - [`oidc_state`] — Upstream OIDC login state: lifecycle plus atomic consume / concurrent-replay coverage.
//! - [`org_domain`] — `UserDoc.org_domain`: populated by both production writers, resolved and lazily backfilled by `get_user_org_domain`.
//! - [`scim_filters`] — SCIM list filter types (which attributes and operators are evaluated) and application-side co/sw matching.
//! - [`scim_groups`] — SCIM group lifecycle and membership.
//! - [`scim_provisioning`] — SCIM user creation: duplicate/uniqueness handling, in-transaction domain-ownership validation, deterministic IDs, cross-backend races.
//! - [`scim_tokens`] — Org API (SCIM) tokens: cap enforcement, expiry, scopes.
//! - [`scim_users`] — SCIM user CRUD, list/filter behavior, deactivation, and SCIM audit records.
//! - [`store_gaps`] — DocumentStore behaviors not covered by `db/store.rs` unit tests.
//! - [`users_and_sessions`] — User CRUD (`db::users`) and browser-session lifecycle (`db::sessions`).

#![expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use std::sync::Arc;

use super::*;
use crate::crypto::document_crypto::PlaintextDocumentCrypto;
use crate::db::audit::AuditStore;
use crate::db::store::DocumentStore;
use crate::test_utils::{TestClientSpec, create_test_client};

/// Create an in-memory SQLite database for testing.
///
/// Returns a `(DocumentStore, AuditStore)` pair backed by the same
/// in-memory pool with migrations applied.
async fn test_db() -> (DocumentStore, AuditStore) {
    let pool = Pool::connect("sqlite::memory:", &pool::PoolConfig::default())
        .await
        .expect("Failed to create test database");

    // Run migrations based on database type
    match &pool {
        Pool::Sqlite(p) => sqlx::migrate!("./migrations/sqlite")
            .run(p)
            .await
            .expect("Failed to run migrations"),
        Pool::Postgres(p) => sqlx::migrate!("./migrations/postgres")
            .run(p)
            .await
            .expect("Failed to run migrations"),
    }

    let crypto: Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
        Arc::new(PlaintextDocumentCrypto);
    let store = DocumentStore::new(pool.clone(), crypto.clone());
    let audit = AuditStore::new(pool, crypto);
    (store, audit)
}

/// An [`update_scim_group`] edit that sets a group's attributes and keeps
/// its members.
fn set_group_attributes(
    display_name: &str,
    external_id: Option<&str>,
) -> impl Fn(&mut ScimGroupState) -> Result<(), std::convert::Infallible> {
    let display_name = display_name.to_string();
    let external_id = external_id.map(String::from);
    move |group| {
        group.display_name.clone_from(&display_name);
        group.external_id.clone_from(&external_id);
        Ok(())
    }
}

/// An [`update_scim_group`] edit that replaces a group's members.
fn set_group_members(
    user_ids: &[&str],
) -> impl Fn(&mut ScimGroupState) -> Result<(), std::convert::Infallible> {
    let user_ids: std::collections::BTreeSet<String> =
        user_ids.iter().map(|id| (*id).to_string()).collect();
    move |group| {
        group.members.clone_from(&user_ids);
        Ok(())
    }
}

/// An [`update_scim_group`] edit that adds one member.
fn add_group_member(
    user_id: &str,
) -> impl Fn(&mut ScimGroupState) -> Result<(), std::convert::Infallible> {
    let user_id = user_id.to_string();
    move |group| {
        group.members.insert(user_id.clone());
        Ok(())
    }
}

/// A Users list filter, parsed the way the SCIM handler parses `filter`.
fn user_filter(filter: &str) -> crate::db::UserListFilter {
    crate::scim_filter::parse(filter, "urn:ietf:params:scim:schemas:core:2.0:User")
        .and_then(crate::db::UserListFilter::try_from)
        .expect("valid Users filter")
}

/// A Groups list filter, parsed the way the SCIM handler parses `filter`.
fn group_filter(filter: &str) -> crate::db::GroupListFilter {
    crate::scim_filter::parse(filter, "urn:ietf:params:scim:schemas:core:2.0:Group")
        .and_then(crate::db::GroupListFilter::try_from)
        .expect("valid Groups filter")
}

const TEST_ORG_ID: &str = "test-org";
const TEST_ORG_DOMAIN: &str = "example.com";

/// Create the `TEST_ORG_ID` organization with `example.com` as its primary
/// domain, so `create_scim_user`'s in-transaction domain-ownership check
/// passes for the `*@example.com` emails used throughout the SCIM tests.
///
/// `create_scim_user` validates domain ownership inside the transaction that
/// inserts the user (closing the TOCTOU race with `remove_additional_domain`),
/// so every test that provisions a `*@example.com` user against `TEST_ORG_ID`
/// must seed this org first.
async fn seed_test_org(store: &DocumentStore) {
    store
        .insert_with_id(TEST_ORG_ID, &test_org_doc(TEST_ORG_DOMAIN))
        .await
        .expect("seed test org");
}

/// A minimal org document owning `domain` — no name, creator, additional
/// domains, or subdomain. The shape every org fixture in this file needs;
/// construct through here instead of inlining the literal.
fn test_org_doc(domain: &str) -> crate::db::documents::organization::OrganizationDoc {
    crate::db::documents::organization::OrganizationDoc {
        domain: domain.to_string(),
        name: None,
        created_by_user_id: None,
        additional_domains: Vec::new(),
        subdomain: None,
    }
}

mod arrival_anchored_expiry;
mod audit_events;
mod authenticators;
mod cascade_delete;
mod challenge_states;
mod concurrency;
mod device_auth;
mod email_normalization;
mod identity_binding;
mod jti_replay;
mod jwks_cache;
mod oauth_clients;
mod oauth_secrets;
mod occ_modify;
mod oidc_state;
mod org_domain;
mod scim_filters;
mod scim_groups;
mod scim_provisioning;
mod scim_tokens;
mod scim_users;
mod store_gaps;
mod users_and_sessions;
