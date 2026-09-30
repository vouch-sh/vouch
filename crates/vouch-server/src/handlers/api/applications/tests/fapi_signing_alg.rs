// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A FAPI 2.0 application holds no RS256 JWT signing algorithm, however it
//! became FAPI: console create, console upgrade, or RFC 7591 registration.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panicking on an assertion failure is the point"
)]

use crate::crypto::alg::JwsAlgorithm;
use crate::db;
use crate::db::TokenEndpointAuthMethod;
use crate::test_utils::TestHarness;
use crate::test_utils::{TestClientSpec, TestJwks, create_test_client};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn es256_jwk() -> serde_json::Value {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
    let pk = kp.public_key().as_ref();
    serde_json::json!({
        "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "k1",
        "x": URL_SAFE_NO_PAD.encode(&pk[1..33]),
        "y": URL_SAFE_NO_PAD.encode(&pk[33..65]),
    })
}

fn jwks_string() -> String {
    serde_json::json!({ "keys": [es256_jwk()] }).to_string()
}

async fn stored_alg(h: &TestHarness, id: &str) -> JwsAlgorithm {
    db::get_oauth_client_by_id(&h.state.store, id)
        .await
        .unwrap()
        .expect("client stored")
        .id_token_signed_response_alg
}

// FAPI 2.0 Security Profile §5.4.1 (specs/openid/fapi-security-profile-2_0-final.txt,
// CONVERTED cache, source https://openid.net/specs/fapi-security-profile-2_0-final.html):
// "Authorization servers, clients, and resource servers when creating or processing JWTs
//  shall ... use PS256, ES256, or EdDSA (using the Ed25519 variant) algorithms"
// FAPI "shall" is mandatory; RS256 is not in the list, so an ID token for a FAPI client
// must not be signed RS256.
#[tokio::test]
async fn console_created_fapi_app_does_not_store_rs256_id_token_alg() {
    let h = TestHarness::new().await;
    let (_u, _a, token) = h
        .create_authenticated_user("fapi-alg@example.com")
        .await
        .unwrap();
    let body = serde_json::json!({
        "name": "FAPI App",
        "application_type": "web",
        "redirect_uris": ["https://rp.example.com/cb"],
        "fapi_profile": "fapi2_security",
        "jwks": jwks_string(),
    });
    let resp = h
        .post_json_authenticated("/api/v1/applications", &body, &token)
        .await
        .unwrap();
    assert_eq!(resp.status, 200, "create failed: {}", resp.body.clone());
    let json: serde_json::Value = resp.json().unwrap();
    assert_eq!(
        json["fapi_profile"], "fapi2_security",
        "setup: app must be FAPI: {json}"
    );
    let id = json["id"].as_str().unwrap();
    let alg = stored_alg(&h, id).await;
    assert_ne!(
        alg,
        JwsAlgorithm::Rs256,
        "POST /api/v1/applications with fapi_profile=fapi2_security must not store \
         id_token_signed_response_alg=RS256; FAPI 2.0 §5.4.1 requires PS256/ES256/EdDSA"
    );
}

// Same FAPI 2.0 §5.4.1 requirement, reached through the console upgrade path:
// create a Standard web app, then PATCH it to fapi2_security.
#[tokio::test]
async fn console_upgraded_fapi_app_does_not_keep_rs256_id_token_alg() {
    let h = TestHarness::new().await;
    let (_u, _a, token) = h
        .create_authenticated_user("fapi-upg@example.com")
        .await
        .unwrap();
    let body = serde_json::json!({
        "name": "Std App",
        "application_type": "web",
        "redirect_uris": ["https://rp.example.com/cb"],
    });
    let resp = h
        .post_json_authenticated("/api/v1/applications", &body, &token)
        .await
        .unwrap();
    assert_eq!(resp.status, 200, "create failed: {}", resp.body.clone());
    let json: serde_json::Value = resp.json().unwrap();
    let id = json["id"].as_str().unwrap().to_string();
    assert_eq!(
        stored_alg(&h, &id).await,
        JwsAlgorithm::Rs256,
        "setup: standard app is RS256"
    );

    let patch = serde_json::json!({ "fapi_profile": "fapi2_security", "jwks": jwks_string() });
    let resp = h
        .patch_json_authenticated(&format!("/api/v1/applications/{id}"), &patch, &token)
        .await
        .unwrap();
    assert_eq!(resp.status, 200, "upgrade failed: {}", resp.body.clone());
    let client = db::get_oauth_client_by_id(&h.state.store, &id)
        .await
        .unwrap()
        .unwrap();
    assert!(client.is_fapi(), "setup: client must now be FAPI");
    assert_ne!(
        client.id_token_signed_response_alg,
        JwsAlgorithm::Rs256,
        "PATCH /api/v1/applications/{{id}} upgrading to fapi2_security must not leave \
         id_token_signed_response_alg=RS256; FAPI 2.0 §5.4.1 requires PS256/ES256/EdDSA"
    );
}

// Positive control: RFC 7591 dynamic registration of a FAPI (DPoP-bound) client
// resolves the ID-token alg to ES256 (resolve_id_token_alg).
#[tokio::test]
async fn control_dcr_fapi_client_gets_es256() {
    let h = TestHarness::new().await;
    let body = serde_json::json!({
        "client_name": "DCR FAPI",
        "application_type": "web",
        "redirect_uris": ["https://rp.example.com/cb"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "private_key_jwt",
        "dpop_bound_access_tokens": true,
        "jwks": { "keys": [es256_jwk()] },
    });
    let resp = h.post_json("/oauth/register", &body).await.unwrap();
    assert_eq!(resp.status, 201, "register failed: {}", resp.body.clone());
    let json: serde_json::Value = resp.json().unwrap();
    let client_id = json["client_id"].as_str().unwrap();
    let client = db::get_oauth_client_by_client_id(&h.state.store, client_id)
        .await
        .unwrap()
        .unwrap();
    assert!(client.is_fapi(), "setup: DCR client must be FAPI");
    assert_eq!(client.id_token_signed_response_alg, JwsAlgorithm::Es256);
}

// FAPI 2.0 §5.4.1 again, for every algorithm the client stores: a standard
// client holding RS256 ID token, JARM, userinfo and request object signing
// (as RFC 7591 registration allows) holds no RS256 once upgraded to FAPI in
// the console.
#[tokio::test]
async fn console_upgrade_moves_every_stored_signing_alg_off_rs256() {
    let h = TestHarness::new().await;
    let (user, _a, token) = h
        .create_authenticated_user("fapi-rs256-upg@example.com")
        .await
        .unwrap();
    let client = create_test_client(
        &h.state.store,
        &user.id,
        TestClientSpec {
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
            jwks: TestJwks::Custom(serde_json::json!({ "keys": [es256_jwk()] })),
            id_token_signed_response_alg: JwsAlgorithm::Rs256,
            authorization_signed_response_alg: Some(JwsAlgorithm::Rs256),
            userinfo_signed_response_alg: Some(JwsAlgorithm::Rs256),
            request_object_signing_alg: Some(JwsAlgorithm::Rs256),
            ..Default::default()
        },
    )
    .await;

    let patch = serde_json::json!({ "fapi_profile": "fapi2_security" });
    let resp = h
        .patch_json_authenticated(
            &format!("/api/v1/applications/{}", client.app_id),
            &patch,
            &token,
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 200, "upgrade failed: {}", resp.body.clone());

    let client = db::get_oauth_client_by_id(&h.state.store, &client.app_id)
        .await
        .unwrap()
        .unwrap();
    assert!(client.is_fapi(), "setup: client must now be FAPI");
    assert_eq!(client.id_token_signed_response_alg, JwsAlgorithm::Es256);
    assert_eq!(
        client.authorization_signed_response_alg,
        Some(JwsAlgorithm::Es256)
    );
    assert_eq!(
        client.userinfo_signed_response_alg,
        Some(JwsAlgorithm::Es256)
    );
    assert_eq!(client.request_object_signing_alg, Some(JwsAlgorithm::Es256));
}
