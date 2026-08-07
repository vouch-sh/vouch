// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Org API (SCIM) tokens: cap enforcement, expiry, scopes.
#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

// ========================================================================
// SCIM Token Tests
// ========================================================================

#[tokio::test]
async fn test_scim_token_management() {
    let (store, _audit) = test_db().await;

    // Create org for SCIM token (new signature: domain, name, created_by_user_id)
    let org = create_organization(&store, "test.com", Some("Test Org"), None)
        .await
        .expect("Failed to create org");
    let org_id = &org.id;

    // Create SCIM token with org
    let token_hash = "hashed_scim_token";
    let token_id = create_scim_token(
        &store,
        &CreateScimTokenParams {
            org_id,
            token_hash,
            description: Some("Admin token"),
            expires_at: None,
            scope: ScimScopeSet::default(),
        },
    )
    .await
    .expect("Failed to create SCIM token");

    assert!(!token_id.is_empty());

    // Get by hash
    let token = get_scim_token_by_hash(&store, token_hash)
        .await
        .expect("Failed to get token")
        .expect("Token should exist");

    assert_eq!(token.description, Some("Admin token".to_string()));
    assert!(token.last_used_at.is_none());

    // Update last used
    update_scim_token_last_used(&store, &token.id)
        .await
        .expect("Failed to update last used");

    let token = get_scim_token_by_hash(&store, token_hash)
        .await
        .expect("Failed to get token")
        .expect("Token should exist");

    assert!(token.last_used_at.is_some());

    // List tokens
    let tokens = list_scim_tokens(&store, None)
        .await
        .expect("Failed to list tokens");

    assert_eq!(tokens.len(), 1);

    // Attempt delete with wrong org (should not delete)
    let deleted = delete_scim_token(&store, &token_id, "wrong-org")
        .await
        .expect("Query should succeed");
    assert!(
        !deleted,
        "Should not delete token belonging to different org"
    );

    // Verify token still exists
    let token = get_scim_token_by_hash(&store, token_hash)
        .await
        .expect("Query should succeed");
    assert!(
        token.is_some(),
        "Token should still exist after wrong-org delete"
    );

    // Delete token with correct org
    let deleted = delete_scim_token(&store, &token_id, org_id)
        .await
        .expect("Failed to delete token");
    assert!(deleted, "Should delete token belonging to correct org");

    let token = get_scim_token_by_hash(&store, token_hash)
        .await
        .expect("Query should succeed");

    assert!(token.is_none());
}

/// Expired SCIM tokens cannot authenticate, so they must not count
/// toward the per-org creation limit, and cleanup must purge them (#715).
#[tokio::test]
async fn test_expired_scim_tokens_excluded_from_active_count() {
    let (store, _audit) = test_db().await;

    let org = create_organization(&store, "test.com", Some("Test Org"), None)
        .await
        .expect("Failed to create org");
    let org_id = &org.id;

    let past = jiff::Timestamp::now() - jiff::Span::new().hours(1);
    let future = jiff::Timestamp::now() + jiff::Span::new().hours(1);

    // Two expired tokens and one active token
    for (hash, expiry) in [
        ("expired-1", Some(past)),
        ("expired-2", Some(past)),
        ("active-1", Some(future)),
    ] {
        create_scim_token(
            &store,
            &CreateScimTokenParams {
                org_id,
                token_hash: hash,
                description: None,
                expires_at: expiry,
                scope: ScimScopeSet::default(),
            },
        )
        .await
        .expect("Failed to create SCIM token");
    }

    // list returns everything, expired rows included
    let all = list_scim_tokens(&store, Some(org_id))
        .await
        .expect("Failed to list tokens");
    assert_eq!(all.len(), 3);

    // An expired token cannot authenticate...
    assert!(
        get_scim_token_by_hash(&store, "expired-1")
            .await
            .expect("lookup expired token")
            .is_none(),
        "an expired token must not authenticate"
    );
    assert!(
        get_scim_token_by_hash(&store, "active-1")
            .await
            .expect("lookup active token")
            .is_some(),
        "an unexpired token must authenticate"
    );

    // ...so it must not consume a slot either. Only `active-1` counts against
    // the cap of 2, leaving room for one more. A token with no expiration is
    // always active, so the one after that is refused.
    create_scim_token(
        &store,
        &CreateScimTokenParams {
            org_id,
            token_hash: "no-expiry",
            description: None,
            expires_at: None,
            scope: ScimScopeSet::default(),
        },
    )
    .await
    .expect("a second active token must be allowed alongside 2 expired ones");

    match create_scim_token(
        &store,
        &CreateScimTokenParams {
            org_id,
            token_hash: "third-active",
            description: None,
            expires_at: Some(future),
            scope: ScimScopeSet::default(),
        },
    )
    .await
    {
        Err(crate::error::ServiceError::Api { ref code, .. }) if code == "token_limit_reached" => {}
        other => panic!("a third active token must hit the cap; got {other:?}"),
    }

    // Cleanup purges only the expired tokens
    let deleted = delete_expired_scim_tokens(&store)
        .await
        .expect("Failed to delete expired tokens");
    assert_eq!(deleted, 2);
    let remaining = list_scim_tokens(&store, Some(org_id))
        .await
        .expect("Failed to list tokens");
    assert_eq!(remaining.len(), 2);
}

// ========================================================================
// SCIM Scope Tests
// ========================================================================

#[test]
fn test_scim_scope_round_trip() {
    for scope in [
        ScimScope::UsersRead,
        ScimScope::UsersWrite,
        ScimScope::GroupsRead,
        ScimScope::GroupsWrite,
    ] {
        let s = scope.as_str();
        let parsed = ScimScope::parse(s).expect("Should parse valid scope");
        assert_eq!(parsed, scope);
    }
}

#[test]
fn test_scim_scope_parse_invalid() {
    assert!(ScimScope::parse("invalid").is_none());
    assert!(ScimScope::parse("").is_none());
    assert!(ScimScope::parse("users:admin").is_none());
    assert!(ScimScope::parse("Users:Read").is_none());
}

#[test]
fn test_scim_scope_set_round_trip() {
    let set = ScimScopeSet::all();
    let db_string = set.as_db_string();
    let parsed = ScimScopeSet::parse(&db_string).expect("Should parse valid scope set");
    assert_eq!(parsed, set);
}

#[test]
fn test_scim_scope_set_parse_subset() {
    let parsed = ScimScopeSet::parse("users:read,groups:write").expect("Should parse valid subset");
    assert!(parsed.contains(ScimScope::UsersRead));
    assert!(!parsed.contains(ScimScope::UsersWrite));
    assert!(!parsed.contains(ScimScope::GroupsRead));
    assert!(parsed.contains(ScimScope::GroupsWrite));
}

#[test]
fn test_scim_scope_set_parse_rejects_invalid() {
    assert!(ScimScopeSet::parse("users:read,invalid").is_none());
    assert!(ScimScopeSet::parse("bad").is_none());
    assert!(ScimScopeSet::parse("").is_none());
}

#[test]
fn test_scim_scope_set_contains() {
    let all = ScimScopeSet::all();
    assert!(all.contains(ScimScope::UsersRead));
    assert!(all.contains(ScimScope::UsersWrite));
    assert!(all.contains(ScimScope::GroupsRead));
    assert!(all.contains(ScimScope::GroupsWrite));

    let partial = ScimScopeSet::parse("users:read").expect("valid");
    assert!(partial.contains(ScimScope::UsersRead));
    assert!(!partial.contains(ScimScope::UsersWrite));
}

#[test]
fn test_scim_scope_set_default_is_all() {
    assert_eq!(ScimScopeSet::default(), ScimScopeSet::all());
}
