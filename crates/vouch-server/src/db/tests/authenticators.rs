// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authenticator (security key) CRUD and counting.
#![expect(
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

// ========================================================================
// Authenticator Tests
// ========================================================================

#[tokio::test]
async fn test_authenticator_crud() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "auth@example.com", None)
        .await
        .expect("Failed to create user");

    // Create authenticator (with user_email parameter)
    let credential_id = vec![1u8, 2, 3, 4, 5];
    let public_key = vec![10u8; 65];
    let user_handle = vec![20u8; 32];

    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "auth@example.com",
            name: "YubiKey 5C",
            credential_id: &credential_id,
            public_key: &public_key,
            aaguid: Some("2fc0579f-8113-47ea-b116-bb5a8db9202a"),
            user_handle: Some(&user_handle),
            attestation_verified: false,
        },
    )
    .await
    .expect("Failed to create authenticator");

    assert!(!auth_id.is_empty());

    // Get by ID
    let auth = get_authenticator_by_id(&store, &auth_id)
        .await
        .expect("Failed to get authenticator")
        .expect("Authenticator should exist");

    assert_eq!(auth.name, "YubiKey 5C");
    assert_eq!(auth.credential_id, credential_id);
    assert_eq!(auth.counter, 0);

    // Get by credential ID
    let auth = get_authenticator_by_credential_id(&store, &credential_id)
        .await
        .expect("Failed to get authenticator")
        .expect("Authenticator should exist");

    assert_eq!(auth.id, auth_id);

    // Get all for user
    let auths = get_authenticators_for_user(&store, &user_id)
        .await
        .expect("Failed to get authenticators");

    assert_eq!(auths.len(), 1);

    // Update counter
    update_authenticator_counter(&store, &auth_id, 42)
        .await
        .expect("Failed to update counter");

    let auth = get_authenticator_by_id(&store, &auth_id)
        .await
        .expect("Failed to get authenticator")
        .expect("Authenticator should exist");

    assert_eq!(auth.counter, 42);

    // Delete authenticator
    crate::test_utils::remove_test_authenticator(&store, &auth_id).await;

    // Verify deleted
    let auth = get_authenticator_by_id(&store, &auth_id)
        .await
        .expect("Query should succeed");

    assert!(auth.is_none());
}

#[tokio::test]
async fn test_authenticator_count() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "count@example.com", None)
        .await
        .expect("Failed to create user");

    // Initially 0 authenticators
    let count = count_authenticators_for_user(&store, &user_id)
        .await
        .expect("Failed to count");
    assert_eq!(count, 0);

    // Add authenticators (with user_email parameter)
    for i in 0..3 {
        create_authenticator(
            &store,
            &CreateAuthenticatorParams {
                user_id: &user_id,
                user_email: "count@example.com",
                name: &format!("Key {}", i),
                credential_id: &[i as u8; 10],
                public_key: &[0u8; 32],
                aaguid: None,
                user_handle: None,
                attestation_verified: false,
            },
        )
        .await
        .expect("Failed to create authenticator");
    }

    let count = count_authenticators_for_user(&store, &user_id)
        .await
        .expect("Failed to count");
    assert_eq!(count, 3);
}
