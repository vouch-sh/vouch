// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Client JWKS cache behavioral invariants.
#![expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;
use crate::crypto::alg::JwsAlgorithm;

// ========================================================================
// JWKS cache — behavioral invariants
// ========================================================================

#[tokio::test]
async fn test_update_oauth_client_jwks_uri_clears_cache() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "jwks-uri-clear@example.com", None)
        .await
        .expect("upsert_user failed");

    let (client, _) = create_oauth_client(
        &store,
        &CreateOAuthClientParams {
            user_id: Some(&user_id),
            name: "JWKS URI Clear Test",
            description: None,
            application_type: OAuthClientType::Web,
            redirect_uris: &[],
            access_scope: AccessScope::default(),
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            keys: Some(&crate::db::ClientKeys::Uri(
                "https://original.example.com/jwks".to_string(),
            )),
            fapi_profile: None,
            dpop_bound_access_tokens: None,
            grant_types: None,
            response_types: None,
            software_id: None,
            software_version: None,
            registration_source: RegistrationSource::Manual,
            registration_access_token_hash: None,
            registration_metadata: None,
            id_token_signed_response_alg: JwsAlgorithm::Rs256,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,
            tls_client_certificate_bound_access_tokens: None,
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: None,
            userinfo_signed_response_alg: None,
            request_uris: None,
            post_logout_redirect_uris: None,
        },
    )
    .await
    .expect("create_oauth_client failed");

    let jwks = serde_json::json!({"keys": [{"kty": "EC", "kid": "k1"}]});
    upsert_jwks_cache(&store, &client.id, &jwks)
        .await
        .expect("upsert_jwks_cache failed");

    assert!(
        get_jwks_cache(&store, &client.id)
            .await
            .expect("get_jwks_cache failed")
            .is_some(),
        "cache should be populated before URI change"
    );

    update_oauth_client_registration(
        &store,
        &client.id,
        &UpdateClientRegistrationParams {
            redirect_uris: &[],
            grant_types: None,
            response_types: None,
            keys: Some(&crate::db::ClientKeys::Uri(
                "https://rotated.example.com/jwks".to_string(),
            )),
            registration_access_token_hash: "hash",
            registration_metadata: None,
            userinfo_signed_response_alg: None,
            request_uris: None,
            post_logout_redirect_uris: None,
            client_name: None,
            software_id: None,
            software_version: None,
            id_token_signed_response_alg: JwsAlgorithm::Es256,
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: None,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,
        },
    )
    .await
    .expect("update_oauth_client_registration failed");

    let cache = get_jwks_cache(&store, &client.id)
        .await
        .expect("get_jwks_cache failed");
    assert!(
        cache.is_none(),
        "cache must be cleared when jwks_uri changes"
    );
}

#[tokio::test]
async fn test_admin_update_oauth_client_jwks_uri_clears_cache() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "admin-jwks-uri-clear@example.com", None)
        .await
        .expect("upsert_user failed");

    let (client, _) = create_oauth_client(
        &store,
        &CreateOAuthClientParams {
            user_id: Some(&user_id),
            name: "Admin JWKS URI Clear Test",
            description: None,
            application_type: OAuthClientType::Web,
            redirect_uris: &[],
            access_scope: AccessScope::default(),
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            keys: Some(&crate::db::ClientKeys::Uri(
                "https://original.example.com/jwks".to_string(),
            )),
            fapi_profile: None,
            dpop_bound_access_tokens: None,
            grant_types: None,
            response_types: None,
            software_id: None,
            software_version: None,
            registration_source: RegistrationSource::Manual,
            registration_access_token_hash: None,
            registration_metadata: None,
            id_token_signed_response_alg: JwsAlgorithm::Rs256,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,
            tls_client_certificate_bound_access_tokens: None,
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: None,
            userinfo_signed_response_alg: None,
            request_uris: None,
            post_logout_redirect_uris: None,
        },
    )
    .await
    .expect("create_oauth_client failed");

    let jwks = serde_json::json!({"keys": [{"kty": "EC", "kid": "k1"}]});
    upsert_jwks_cache(&store, &client.id, &jwks)
        .await
        .expect("upsert_jwks_cache failed");

    assert!(
        get_jwks_cache(&store, &client.id)
            .await
            .expect("get_jwks_cache failed")
            .is_some(),
        "cache should be populated before URI change"
    );

    update_oauth_client(
        &store,
        &UpdateOAuthClientParams {
            id: &client.id,
            name: "Admin JWKS URI Clear Test",
            description: None,
            redirect_uris: &[],
            access_scope: None,
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            keys: Some(&crate::db::ClientKeys::Uri(
                "https://rotated.example.com/jwks".to_string(),
            )),
            fapi_profile: FapiProfile::None,
            dpop_bound_access_tokens: false,
            post_logout_redirect_uris: None,
        },
    )
    .await
    .expect("update_oauth_client failed");

    let cache = get_jwks_cache(&store, &client.id)
        .await
        .expect("get_jwks_cache failed");
    assert!(
        cache.is_none(),
        "cache must be cleared when the admin path changes jwks_uri"
    );
}

#[tokio::test]
async fn test_admin_update_oauth_client_preserves_cache_when_jwks_uri_unchanged() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "admin-jwks-uri-unchanged@example.com", None)
        .await
        .expect("upsert_user failed");

    let (client, _) = create_oauth_client(
        &store,
        &CreateOAuthClientParams {
            user_id: Some(&user_id),
            name: "Admin JWKS URI Unchanged Test",
            description: None,
            application_type: OAuthClientType::Web,
            redirect_uris: &[],
            access_scope: AccessScope::default(),
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            keys: Some(&crate::db::ClientKeys::Uri(
                "https://unchanged.example.com/jwks".to_string(),
            )),
            fapi_profile: None,
            dpop_bound_access_tokens: None,
            grant_types: None,
            response_types: None,
            software_id: None,
            software_version: None,
            registration_source: RegistrationSource::Manual,
            registration_access_token_hash: None,
            registration_metadata: None,
            id_token_signed_response_alg: JwsAlgorithm::Rs256,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,
            tls_client_certificate_bound_access_tokens: None,
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: None,
            userinfo_signed_response_alg: None,
            request_uris: None,
            post_logout_redirect_uris: None,
        },
    )
    .await
    .expect("create_oauth_client failed");

    let jwks = serde_json::json!({"keys": [{"kty": "EC", "kid": "k1"}]});
    upsert_jwks_cache(&store, &client.id, &jwks)
        .await
        .expect("upsert_jwks_cache failed");

    update_oauth_client(
        &store,
        &UpdateOAuthClientParams {
            id: &client.id,
            name: "Renamed, Same URI",
            description: None,
            redirect_uris: &[],
            access_scope: None,
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            keys: Some(&crate::db::ClientKeys::Uri(
                "https://unchanged.example.com/jwks".to_string(),
            )),
            fapi_profile: FapiProfile::None,
            dpop_bound_access_tokens: false,
            post_logout_redirect_uris: None,
        },
    )
    .await
    .expect("update_oauth_client failed");

    let cache = get_jwks_cache(&store, &client.id)
        .await
        .expect("get_jwks_cache failed");
    assert!(
        cache.is_some(),
        "cache must survive an update that doesn't change jwks_uri"
    );
}

#[tokio::test]
async fn test_jwks_refresh_does_not_modify_oauth_client_doc() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "jwks-parent-immutable@example.com", None)
        .await
        .expect("upsert_user failed");

    let (client, _) = create_oauth_client(
        &store,
        &CreateOAuthClientParams {
            user_id: Some(&user_id),
            name: "Parent Immutable Test",
            description: None,
            application_type: OAuthClientType::Web,
            redirect_uris: &[],
            access_scope: AccessScope::default(),
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            keys: Some(&crate::db::ClientKeys::Uri(
                "https://immutable.example.com/jwks".to_string(),
            )),
            fapi_profile: None,
            dpop_bound_access_tokens: None,
            grant_types: None,
            response_types: None,
            software_id: None,
            software_version: None,
            registration_source: RegistrationSource::Manual,
            registration_access_token_hash: None,
            registration_metadata: None,
            id_token_signed_response_alg: JwsAlgorithm::Rs256,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,
            tls_client_certificate_bound_access_tokens: None,
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: None,
            userinfo_signed_response_alg: None,
            request_uris: None,
            post_logout_redirect_uris: None,
        },
    )
    .await
    .expect("create_oauth_client failed");

    let snapshot_updated_at = client.updated_at;

    let jwks = serde_json::json!({"keys": [{"kty": "EC", "kid": "p1"}]});
    upsert_jwks_cache(&store, &client.id, &jwks)
        .await
        .expect("upsert_jwks_cache failed");

    let after = get_oauth_client_by_id(&store, &client.id)
        .await
        .expect("get_oauth_client_by_id failed")
        .expect("client must still exist");

    assert_eq!(
        after.updated_at, snapshot_updated_at,
        "upsert_jwks_cache must not change parent updated_at"
    );
}
