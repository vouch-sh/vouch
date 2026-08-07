// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Database module tests, one file per domain.
//!
//! Shared fixtures (`test_db`, `seed_test_org`, `test_org_doc`, the
//! `TEST_ORG_*` constants) live here in the module root. New tests go in
//! the file whose scope matches; add a new file (and list it here) when
//! none does:
//!
//! - [`audit_events`] — Auth/key/device audit event logging and expiry.
//! - [`authenticators`] — Authenticator (security key) CRUD and counting.
//! - [`cascade_delete`] — Cascade deletion of users and OAuth clients with their dependent rows.
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
//! - [`scim_filters`] — SCIM filter parsing and application-side co/sw matching, including multibyte input.
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
mod scim_filters;
mod scim_groups;
mod scim_provisioning;
mod scim_tokens;
mod scim_users;
mod store_gaps;
mod users_and_sessions;
