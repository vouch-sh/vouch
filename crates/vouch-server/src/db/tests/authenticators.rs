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
            counter: 0,
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
                counter: 0,
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

// ========================================================================
// Registration counter persistence (WebAuthn L2 §7.1 step 23)
// ========================================================================

// WebAuthn L2 §7.1 step 23: "Associate the credentialId with a new stored
// signature counter value initialized to the value of authData.signCount."
// `create_authenticator` persists `CreateAuthenticatorParams::counter` (via
// `cast_signed`) rather than a hardcoded `0`, so a global-counter
// authenticator that reports a non-zero signCount at registration is stored
// with that value.
#[tokio::test]
async fn test_create_authenticator_persists_nonzero_registration_counter() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "reg-counter@example.com", None)
        .await
        .expect("Failed to create user");

    // Simulate a global-counter authenticator that has performed prior
    // operations and reports signCount = 42 at makeCredential (WebAuthn L2
    // §6.3.2 step 10 first branch).
    let credential_id = vec![1u8, 2, 3, 4, 5];
    let public_key = vec![10u8; 65];
    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "reg-counter@example.com",
            name: "YubiKey 5C",
            credential_id: &credential_id,
            public_key: &public_key,
            aaguid: Some("2fc0579f-8113-47ea-b116-bb5a8db9202a"),
            user_handle: None,
            attestation_verified: true,
            counter: 42,
        },
    )
    .await
    .expect("Failed to create authenticator");

    let auth = get_authenticator_by_id(&store, &auth_id)
        .await
        .expect("Failed to get authenticator")
        .expect("Authenticator should exist");

    // The stored counter must equal the registration signCount, not 0.
    assert_eq!(
        auth.counter, 42,
        "stored counter must initialize to the registration authData.signCount"
    );

    crate::test_utils::remove_test_authenticator(&store, &auth_id).await;
}

// `cast_signed` reinterprets the u32 registration counter bit-identically as
// i32 (the column type). A registration signCount above i32::MAX, while
// unrealistic for a personal hardware key (the §6.1.1 counter increments by
// one per credential operation), must round-trip bit-identically so
// `update_authenticator_counter`'s max-based monotonicity comparison stays
// consistent on the same bit pattern written here.
#[tokio::test]
async fn test_create_authenticator_preserves_high_bit_counter_via_cast_signed() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "highbit@example.com", None)
        .await
        .expect("Failed to create user");

    // 0x8000_0001u32 has the high bit set. `cast_signed` reinterprets to
    // i32::MIN + 1, preserving the bit pattern for monotonic comparisons.
    let high_bit_counter: u32 = 0x8000_0001;
    let credential_id = vec![9u8, 8, 7, 6, 5];
    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "highbit@example.com",
            name: "YubiKey",
            credential_id: &credential_id,
            public_key: &[10u8; 65],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
            counter: high_bit_counter,
        },
    )
    .await
    .expect("Failed to create authenticator");

    let auth = get_authenticator_by_id(&store, &auth_id)
        .await
        .expect("Failed to get authenticator")
        .expect("Authenticator should exist");

    assert_eq!(
        auth.counter,
        high_bit_counter.cast_signed(),
        "high-bit-set u32 counter must round-trip bit-identically as i32"
    );
    assert_eq!(auth.counter, i32::MIN.wrapping_add(1));

    crate::test_utils::remove_test_authenticator(&store, &auth_id).await;
}
