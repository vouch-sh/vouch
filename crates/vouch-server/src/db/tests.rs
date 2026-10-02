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
//! - [`aws_audit`] — AWS credential audit events (`AuditStore::log_credential_event` with AWS details): round trip.
//! - [`cascade_delete`] — Cascade deletion of users and OAuth clients with their dependent rows, and the transfer of org-scoped applications when their creator is deleted or deactivated.
//! - [`challenge_states`] — FIDO2 challenge state single-use enforcement.
//! - [`concurrency`] — Concurrent-replay and CAS regressions for single-use primitives and state-transition helpers.
//! - [`credential_audit`] — SSH certificate and RFC 8693 token exchange audit events: round trip.
//! - [`device_auth`] — Device authorization grant (RFC 8628): request lifecycle, polling, atomic consumption, single-use semantics.
//! - [`email_normalization`] — Email canonicalization across SCIM provisioning and OIDC enrollment.
//! - [`github`] — GitHub App installations (`db::github`): create, lookups, suspend and delete.
//! - [`identity_binding`] — Upstream (issuer, subject) identity binding and account matching.
//! - [`jti_replay`] — JWT-assertion and DPoP JTI replay prevention and expiry cleanup.
//! - [`jwks_cache`] — Client JWKS cache behavioral invariants.
//! - [`oauth_clients`] — OAuth client application CRUD, client types, secret validity.
//! - [`oauth_secrets`] — OAuth client secret cap/floor OCC invariants.
//! - [`occ_modify`] — OCC read-modify-write conversions: every mutation path uses `store.modify`, not blind get+update.
//! - [`oidc_state`] — Upstream OIDC login state: lifecycle plus atomic consume / concurrent-replay coverage.
//! - [`org_domain`] — `UserDoc.org_domain`: populated by both production writers, resolved and lazily backfilled by `get_user_org_domain`.
//! - [`posture_policies`] — Posture policies (`db::posture_policies`): preconfigured activation and custom policy CRUD.
//! - [`scim_filters`] — SCIM list filter types (which attributes and operators are evaluated) and application-side co/sw matching.
//! - [`scim_groups`] — SCIM group lifecycle and membership.
//! - [`scim_provisioning`] — SCIM user creation: duplicate/uniqueness handling, in-transaction domain-ownership validation, deterministic IDs, cross-backend races.
//! - [`scim_tokens`] — Org API (SCIM) tokens: cap enforcement, expiry, scopes.
//! - [`scim_users`] — SCIM user CRUD, list/filter behavior, deactivation, and SCIM audit records.
//! - [`store_gaps`] — DocumentStore behaviors not covered by `db/store.rs` unit tests.
//! - [`users_and_sessions`] — User CRUD (`db::users`) and browser-session lifecycle (`db::sessions`).

#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use std::sync::Arc;

use super::sessions::{
    delete_session_by_token_hash, delete_sessions_for_code_replay,
    delete_sessions_for_oauth_client, delete_sessions_for_user,
};
use super::*;
use crate::crypto::document_crypto::{DocumentCrypto, PlaintextDocumentCrypto};
use crate::db::audit::AuditStore;
use crate::db::documents::organization::OrganizationDoc;
use crate::db::store::DocumentStore;
use crate::db::{GroupListFilter, UserListFilter};
use crate::scim_filter;
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

    let crypto: Arc<dyn DocumentCrypto> = Arc::new(PlaintextDocumentCrypto);
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
fn user_filter(filter: &str) -> UserListFilter {
    scim_filter::parse(filter, "urn:ietf:params:scim:schemas:core:2.0:User")
        .and_then(UserListFilter::try_from)
        .expect("valid Users filter")
}

/// A Groups list filter, parsed the way the SCIM handler parses `filter`.
fn group_filter(filter: &str) -> GroupListFilter {
    scim_filter::parse(filter, "urn:ietf:params:scim:schemas:core:2.0:Group")
        .and_then(GroupListFilter::try_from)
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
fn test_org_doc(domain: &str) -> OrganizationDoc {
    OrganizationDoc {
        domain: domain.to_string(),
        name: None,
        created_by_user_id: None,
        additional_domains: Vec::new(),
        subdomain: None,
    }
}

/// Move `doc_id`'s `documents` row and every `document_indexes` row to the end
/// of SQLite's rowid order (delete and re-insert verbatim). Without an
/// `ORDER BY`, SQLite returns rows in the rowid order of whichever table drives
/// the join, so bumping the smaller id makes an unordered query return
/// reverse-id order. Tests use it to prove `find_by_indexes` orders by id.
async fn bump_document_to_end(store: &DocumentStore, doc_id: &str) {
    use crate::db::pool::Pool;

    let Pool::Sqlite(pool) = store.pool() else {
        panic!("in-memory test DB must be SQLite");
    };

    // Round-trip the documents row verbatim; delete + re-insert hands it a
    // fresh, higher rowid so a documents-driven plan returns it last.
    let row = sqlx::query_as::<_, RawDocumentsRowForBump>(
        "SELECT id, doc_type, schema_version, encapped_key, data, \
                expires_at, created_at, updated_at, version, last_used_at \
         FROM documents WHERE id = ?",
    )
    .bind(doc_id)
    .fetch_one(pool)
    .await
    .expect("fetch documents row to bump");
    sqlx::query("DELETE FROM documents WHERE id = ?")
        .bind(doc_id)
        .execute(pool)
        .await
        .expect("delete documents row before re-insert");
    sqlx::query(
        "INSERT INTO documents (id, doc_type, schema_version, encapped_key, data, \
                expires_at, created_at, updated_at, version, last_used_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&row.id)
    .bind(&row.doc_type)
    .bind(row.schema_version)
    .bind(&row.encapped_key)
    .bind(&row.data)
    .bind(&row.expires_at)
    .bind(&row.created_at)
    .bind(&row.updated_at)
    .bind(row.version)
    .bind(&row.last_used_at)
    .execute(pool)
    .await
    .expect("re-insert documents row with a higher rowid");

    // Move every document_indexes row for this document to the end of that
    // table's rowid order, one at a time (fresh rowid per re-insert).
    let idx_rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT id, document_id, index_field, index_value \
         FROM document_indexes WHERE document_id = ?",
    )
    .bind(doc_id)
    .fetch_all(pool)
    .await
    .expect("fetch index rows to bump");
    for (idx_id, document_id, field, value) in &idx_rows {
        sqlx::query("DELETE FROM document_indexes WHERE id = ?")
            .bind(idx_id)
            .execute(pool)
            .await
            .expect("delete index row before re-insert");
        let new_id = uuid::Uuid::now_v7().to_string();
        sqlx::query(
            "INSERT INTO document_indexes (id, document_id, index_field, index_value) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(&new_id)
        .bind(document_id)
        .bind(field)
        .bind(value)
        .execute(pool)
        .await
        .expect("re-insert index row with a higher rowid");
    }
}

/// Raw `documents` row shape, for [`bump_document_to_end`] to round-trip a row
/// verbatim with a fresh rowid.
#[derive(sqlx::FromRow)]
struct RawDocumentsRowForBump {
    id: String,
    doc_type: String,
    schema_version: i32,
    encapped_key: Option<String>,
    data: String,
    expires_at: Option<String>,
    created_at: String,
    updated_at: String,
    version: i32,
    last_used_at: Option<String>,
}

mod arrival_anchored_expiry;
mod audit_events;
mod authenticators;
mod aws_audit;
mod cascade_delete;
mod challenge_states;
mod concurrency;
mod credential_audit;
mod device_auth;
mod email_normalization;
mod github;
mod identity_binding;
mod jti_replay;
mod jwks_cache;
mod oauth_clients;
mod oauth_secrets;
mod occ_modify;
mod oidc_state;
mod org_domain;
mod posture_policies;
mod scim_filters;
mod scim_groups;
mod scim_provisioning;
mod scim_tokens;
mod scim_users;
mod store_gaps;
mod users_and_sessions;
