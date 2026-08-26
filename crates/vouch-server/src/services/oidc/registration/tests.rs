// SPDX-License-Identifier: Apache-2.0 OR MIT
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]

use super::*;

fn assert_oauth_error<T: std::fmt::Debug>(
    result: Result<T, ServiceError>,
    expected: OAuthErrorCode,
) {
    let err = result.unwrap_err();
    assert!(
        matches!(&err, ServiceError::OAuth { code, .. } if *code == expected),
        "Expected {expected:?}",
    );
}

/// The shared redirect-URI rule as it applies to a native client, which is the
/// client kind these cases describe: `https`, loopback `http`, and a custom
/// scheme are all registrable, and a fragment is not.
fn validate_redirect_uri_for_native(uri: &str) -> Result<(), crate::error::ServiceError> {
    crate::db::validate_redirect_uri(uri, crate::db::OAuthClientType::Native).map_err(|e| {
        crate::error::ServiceError::oauth(
            OAuthErrorCode::InvalidRedirectUri,
            format!("Invalid redirect URI '{uri}': {e}"),
        )
    })
}

// =========================================================================
// Redirect URI Validation Tests
// =========================================================================

#[test]
fn test_accepts_https_redirect_uri() {
    let result = validate_redirect_uri_for_native("https://example.com/callback");
    assert!(result.is_ok());
}

#[test]
fn test_accepts_http_localhost_redirect_uri() {
    let result = validate_redirect_uri_for_native("http://127.0.0.1:8080/callback");
    assert!(result.is_ok());
}

#[test]
fn test_accepts_http_localhost_hostname() {
    let result = validate_redirect_uri_for_native("http://localhost:8080/callback");
    assert!(result.is_ok());
}

#[test]
fn test_accepts_custom_scheme_redirect_uri() {
    let result = validate_redirect_uri_for_native("myapp://auth");
    assert!(result.is_ok());
}

#[test]
fn test_rejects_http_non_loopback() {
    let result = validate_redirect_uri_for_native("http://example.com/callback");
    assert!(result.is_err());
    assert_oauth_error(result, OAuthErrorCode::InvalidRedirectUri);
}

#[test]
fn test_rejects_redirect_uri_with_fragment() {
    let result = validate_redirect_uri_for_native("https://example.com/callback#anchor");
    assert!(result.is_err());
    assert_oauth_error(result, OAuthErrorCode::InvalidRedirectUri);
}

#[test]
fn test_rejects_invalid_redirect_uri() {
    let result = validate_redirect_uri_for_native("not a valid uri !!!");
    assert!(result.is_err());
    assert_oauth_error(result, OAuthErrorCode::InvalidRedirectUri);
}

// =========================================================================
// Redirect URI Validation — Additional Edge Cases
// =========================================================================

/// RFC 8252 Section 7.3: IPv6 loopback [::1] must be accepted over HTTP.
#[test]
fn test_accepts_http_ipv6_loopback_redirect_uri() {
    let result = validate_redirect_uri_for_native("http://[::1]:7777/callback");
    assert!(
        result.is_ok(),
        "IPv6 loopback [::1] must be accepted: {result:?}"
    );
}

/// HTTP redirect URIs with a path component at loopback must be accepted.
#[test]
fn test_accepts_http_loopback_with_path() {
    let result = validate_redirect_uri_for_native("http://127.0.0.1/callback/deep/path");
    assert!(result.is_ok());
}

/// HTTPS URIs with query strings must be accepted (query is not a fragment).
#[test]
fn test_accepts_https_redirect_uri_with_query() {
    let result = validate_redirect_uri_for_native("https://example.com/cb?foo=bar");
    assert!(result.is_ok());
}

/// The fragment check is string-based and must catch '#' before URL parsing.
#[test]
fn test_rejects_redirect_uri_with_fragment_before_parse() {
    // A URI that would otherwise be valid https but contains '#'
    let err = validate_redirect_uri_for_native("https://example.com/cb#").unwrap_err();
    assert!(
        matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidRedirectUri)
    );
    assert!(
        matches!(&err, ServiceError::OAuth { description, .. } if description.contains("fragment"))
    );
}

/// HTTP to a non-loopback private IP (e.g., 192.168.x.x) must be rejected.
#[test]
fn test_rejects_http_private_ip_redirect_uri() {
    let result = validate_redirect_uri_for_native("http://192.168.1.1/callback");
    assert!(result.is_err());
    assert_oauth_error(result, OAuthErrorCode::InvalidRedirectUri);
}

/// An empty string is not a valid redirect URI.
#[test]
fn test_rejects_empty_redirect_uri() {
    let result = validate_redirect_uri_for_native("");
    assert!(result.is_err());
    assert_oauth_error(result, OAuthErrorCode::InvalidRedirectUri);
}

// =========================================================================
// HTTPS URI Validation Tests
// =========================================================================

#[test]
fn test_accepts_https_uri() {
    let result = validate_https_uri("client_uri", Some("https://example.com"));
    assert!(result.is_ok());
}

#[test]
fn test_rejects_http_uri() {
    let result = validate_https_uri("client_uri", Some("http://example.com"));
    assert!(result.is_err());
    assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
}

#[test]
fn test_accepts_none_uri() {
    let result = validate_https_uri("client_uri", None);
    assert!(result.is_ok());
}

#[test]
fn test_rejects_invalid_uri() {
    let result = validate_https_uri("client_uri", Some("not a url"));
    assert!(result.is_err());
    assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
}

// =========================================================================
// HTTPS URI Validation — Additional Cases
// =========================================================================

/// The error message must include the field name for debuggability.
#[test]
fn test_https_uri_error_includes_field_name() {
    let err = validate_https_uri("logo_uri", Some("http://example.com/logo.png")).unwrap_err();
    assert!(
        matches!(&err, ServiceError::OAuth { description, .. } if description.contains("logo_uri"))
    );
}

/// Custom (non-http/https) schemes must be rejected for URI fields.
#[test]
fn test_https_uri_rejects_custom_scheme() {
    let result = validate_https_uri("tos_uri", Some("ftp://example.com/tos"));
    assert!(result.is_err());
    assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
}

/// An empty string for a URI field must be rejected (invalid URL).
#[test]
fn test_https_uri_rejects_empty_string() {
    let result = validate_https_uri("policy_uri", Some(""));
    assert!(result.is_err());
}

// =========================================================================
// Registration Metadata Tests
// =========================================================================

#[test]
fn test_build_metadata_includes_all_fields() {
    let request = RegistrationRequest {
        redirect_uris: None,
        token_endpoint_auth_method: None,
        grant_types: None,
        response_types: None,
        client_name: Some("My App".to_string()),
        client_uri: Some("https://example.com".to_string()),
        logo_uri: Some("https://example.com/logo.png".to_string()),
        tos_uri: Some("https://example.com/tos".to_string()),
        policy_uri: Some("https://example.com/privacy".to_string()),
        scope: Some("openid profile".to_string()),
        contacts: Some(vec!["admin@example.com".to_string()]),
        jwks: None,
        jwks_uri: None,
        software_id: None,
        software_version: None,
        dpop_bound_access_tokens: None,
        id_token_signed_response_alg: None,
        ..Default::default()
    };

    let metadata = request.registration_metadata();

    assert!(metadata.is_object());
    let obj = metadata.as_object().unwrap();
    assert_eq!(obj.get("client_uri").unwrap(), "https://example.com");
    assert_eq!(obj.get("logo_uri").unwrap(), "https://example.com/logo.png");
    assert_eq!(obj.get("tos_uri").unwrap(), "https://example.com/tos");
    assert_eq!(
        obj.get("policy_uri").unwrap(),
        "https://example.com/privacy"
    );
    assert_eq!(obj.get("scope").unwrap(), "openid profile");
    let contacts = obj.get("contacts").unwrap().as_array().unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0], "admin@example.com");
}

#[test]
fn test_build_metadata_empty_request() {
    let request = RegistrationRequest {
        redirect_uris: None,
        token_endpoint_auth_method: None,
        grant_types: None,
        response_types: None,
        client_name: None,
        client_uri: None,
        logo_uri: None,
        tos_uri: None,
        policy_uri: None,
        scope: None,
        contacts: None,
        jwks: None,
        jwks_uri: None,
        software_id: None,
        software_version: None,
        dpop_bound_access_tokens: None,
        id_token_signed_response_alg: None,
        ..Default::default()
    };

    let metadata = request.registration_metadata();

    assert!(metadata.is_object());
    let obj = metadata.as_object().unwrap();
    assert!(
        obj.is_empty(),
        "Expected empty metadata object, got: {obj:?}"
    );
}

// =========================================================================
// Registration Metadata — Additional Cases
// =========================================================================

/// `client_name` is NOT stored in the metadata blob (it has its own column).
#[test]
fn test_build_metadata_excludes_client_name() {
    let request = RegistrationRequest {
        redirect_uris: None,
        token_endpoint_auth_method: None,
        grant_types: None,
        response_types: None,
        client_name: Some("Should Not Appear".to_string()),
        client_uri: None,
        logo_uri: None,
        tos_uri: None,
        policy_uri: None,
        scope: None,
        contacts: None,
        jwks: None,
        jwks_uri: None,
        software_id: None,
        software_version: None,
        dpop_bound_access_tokens: None,
        id_token_signed_response_alg: None,
        ..Default::default()
    };

    let metadata = request.registration_metadata();
    let obj = metadata.as_object().unwrap();
    assert!(
        !obj.contains_key("client_name"),
        "client_name must not be in the metadata blob"
    );
}

/// Multiple contacts must all appear in the metadata array.
#[test]
fn test_build_metadata_multiple_contacts() {
    let request = RegistrationRequest {
        redirect_uris: None,
        token_endpoint_auth_method: None,
        grant_types: None,
        response_types: None,
        client_name: None,
        client_uri: None,
        logo_uri: None,
        tos_uri: None,
        policy_uri: None,
        scope: None,
        contacts: Some(vec![
            "a@example.com".to_string(),
            "b@example.com".to_string(),
            "c@example.com".to_string(),
        ]),
        jwks: None,
        jwks_uri: None,
        software_id: None,
        software_version: None,
        dpop_bound_access_tokens: None,
        id_token_signed_response_alg: None,
        ..Default::default()
    };

    let metadata = request.registration_metadata();
    let obj = metadata.as_object().unwrap();
    let contacts = obj.get("contacts").unwrap().as_array().unwrap();
    assert_eq!(contacts.len(), 3);
    assert_eq!(contacts[0], "a@example.com");
    assert_eq!(contacts[1], "b@example.com");
    assert_eq!(contacts[2], "c@example.com");
}

/// Partial metadata — only scope present — produces a single-key object.
#[test]
fn test_build_metadata_scope_only() {
    let request = RegistrationRequest {
        redirect_uris: None,
        token_endpoint_auth_method: None,
        grant_types: None,
        response_types: None,
        client_name: None,
        client_uri: None,
        logo_uri: None,
        tos_uri: None,
        policy_uri: None,
        scope: Some("openid".to_string()),
        contacts: None,
        jwks: None,
        jwks_uri: None,
        software_id: None,
        software_version: None,
        dpop_bound_access_tokens: None,
        id_token_signed_response_alg: None,
        ..Default::default()
    };

    let metadata = request.registration_metadata();
    let obj = metadata.as_object().unwrap();
    assert_eq!(obj.len(), 1);
    assert_eq!(obj.get("scope").unwrap(), "openid");
}

// =========================================================================
// Request Deserialization Tests
// =========================================================================

#[test]
fn test_request_deserialize_minimal() {
    let json = "{}";
    let result: Result<RegistrationRequest, _> = serde_json::from_str(json);
    assert!(result.is_ok(), "Empty JSON should deserialize successfully");
    let req = result.unwrap();
    assert!(req.redirect_uris.is_none());
    assert!(req.grant_types.is_none());
    assert!(req.client_name.is_none());
}

#[test]
fn test_request_deserialize_with_unknown_fields() {
    // RFC 7591 Section 2: "The authorization server MUST ignore any metadata it does not
    // understand" — unknown fields must not cause deserialization to fail.
    let json = r#"{
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "My App",
        "unknown_field_from_future_spec": "should be ignored",
        "another_unknown": 42,
        "nested_unknown": {"key": "value"}
    }"#;

    let result: Result<RegistrationRequest, _> = serde_json::from_str(json);
    assert!(
        result.is_ok(),
        "Unknown fields must be ignored per RFC 7591: {result:?}"
    );
    let req = result.unwrap();
    assert_eq!(
        req.redirect_uris,
        Some(vec!["https://example.com/callback".to_string()])
    );
    assert_eq!(req.client_name, Some("My App".to_string()));
}

#[test]
fn test_request_deserialize_full() {
    let json = r#"{
        "redirect_uris": ["https://example.com/callback", "https://example.com/callback2"],
        "token_endpoint_auth_method": "client_secret_basic",
        "grant_types": ["authorization_code", "client_credentials"],
        "response_types": ["code"],
        "client_name": "Full Example App",
        "client_uri": "https://example.com",
        "logo_uri": "https://example.com/logo.png",
        "tos_uri": "https://example.com/tos",
        "policy_uri": "https://example.com/privacy",
        "scope": "openid profile email",
        "contacts": ["admin@example.com", "security@example.com"],
        "software_id": "4NRB1-0XZABZI9E6-5SM3R",
        "software_version": "2.1",
        "dpop_bound_access_tokens": false
    }"#;

    let result: Result<RegistrationRequest, _> = serde_json::from_str(json);
    assert!(
        result.is_ok(),
        "Full request should deserialize: {result:?}"
    );
    let req = result.unwrap();

    assert_eq!(
        req.redirect_uris,
        Some(vec![
            "https://example.com/callback".to_string(),
            "https://example.com/callback2".to_string(),
        ])
    );
    assert_eq!(
        req.token_endpoint_auth_method,
        Some("client_secret_basic".to_string())
    );
    assert_eq!(
        req.grant_types,
        Some(vec![
            "authorization_code".to_string(),
            "client_credentials".to_string(),
        ])
    );
    assert_eq!(req.response_types, Some(vec!["code".to_string()]));
    assert_eq!(req.client_name, Some("Full Example App".to_string()));
    assert_eq!(req.client_uri, Some("https://example.com".to_string()));
    assert_eq!(
        req.logo_uri,
        Some("https://example.com/logo.png".to_string())
    );
    assert_eq!(req.tos_uri, Some("https://example.com/tos".to_string()));
    assert_eq!(
        req.policy_uri,
        Some("https://example.com/privacy".to_string())
    );
    assert_eq!(req.scope, Some("openid profile email".to_string()));
    assert_eq!(
        req.contacts,
        Some(vec![
            "admin@example.com".to_string(),
            "security@example.com".to_string(),
        ])
    );
    assert_eq!(req.software_id, Some("4NRB1-0XZABZI9E6-5SM3R".to_string()));
    assert_eq!(req.software_version, Some("2.1".to_string()));
    assert_eq!(req.dpop_bound_access_tokens, Some(false));
}

// =========================================================================
// Request Deserialization — Additional Edge Cases
// =========================================================================

/// `dpop_bound_access_tokens: true` must deserialize correctly.
#[test]
fn test_request_deserialize_dpop_true() {
    let json = r#"{"dpop_bound_access_tokens": true}"#;
    let req: RegistrationRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.dpop_bound_access_tokens, Some(true));
}

/// Inline JWKS must deserialize as a JSON object.
#[test]
fn test_request_deserialize_jwks_inline() {
    let json = r#"{
        "jwks": {
            "keys": [
                {"kty": "RSA", "n": "abc", "e": "AQAB"}
            ]
        }
    }"#;
    let req: RegistrationRequest = serde_json::from_str(json).unwrap();
    assert!(req.jwks.is_some());
    let jwks = req.jwks.unwrap();
    assert!(jwks.get("keys").is_some());
    assert!(jwks.get("keys").unwrap().is_array());
}

/// `jwks_uri` must deserialize as a plain string.
#[test]
fn test_request_deserialize_jwks_uri() {
    let json = r#"{"jwks_uri": "https://example.com/.well-known/jwks.json"}"#;
    let req: RegistrationRequest = serde_json::from_str(json).unwrap();
    assert_eq!(
        req.jwks_uri,
        Some("https://example.com/.well-known/jwks.json".to_string())
    );
    assert!(req.jwks.is_none());
}

/// An empty contacts array is a valid (though unusual) value.
#[test]
fn test_request_deserialize_empty_contacts() {
    let json = r#"{"contacts": []}"#;
    let req: RegistrationRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.contacts, Some(vec![]));
}

// =========================================================================
// Registration Response Serialization Tests
// =========================================================================

/// Optional fields marked `skip_serializing_if = "Option::is_none"` must be
/// absent from the JSON when `None`, not serialized as `null`.
#[test]
fn test_response_serialization_omits_none_fields() {
    let response = RegistrationResponse {
        client_id: "test-client-id".to_string(),
        client_secret: None,
        client_secret_expires_at: None,
        client_id_issued_at: Some(1_700_000_000),
        registration_access_token: Some("vouch_reg_abc123".into()),
        registration_client_uri: Some(
            "https://example.com/oauth/register/test-client-id".to_string(),
        ),
        redirect_uris: None,
        token_endpoint_auth_method: "none".to_string(),
        grant_types: vec!["authorization_code".to_string()],
        response_types: vec!["code".to_string()],
        client_name: Some("Test App".to_string()),
        client_uri: None,
        logo_uri: None,
        tos_uri: None,
        policy_uri: None,
        scope: None,
        contacts: None,
        jwks: None,
        jwks_uri: None,
        software_id: None,
        software_version: None,
        dpop_bound_access_tokens: None,
        id_token_signed_response_alg: "ES256".to_string(),
        authorization_signed_response_alg: None,
        introspection_signed_response_alg: None,
        request_object_signing_alg: None,
        require_signed_request_object: None,
        userinfo_signed_response_alg: None,
        request_uris: None,
        post_logout_redirect_uris: None,
    };

    let json = serde_json::to_string(&response).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Required fields must be present
    assert!(value.get("client_id").is_some());
    assert!(value.get("token_endpoint_auth_method").is_some());
    assert!(value.get("grant_types").is_some());
    assert!(value.get("response_types").is_some());
    assert_eq!(value["id_token_signed_response_alg"], "ES256");

    // Optional None fields must be absent
    assert!(
        value.get("client_secret").is_none(),
        "client_secret must be absent when None"
    );
    assert!(value.get("client_secret_expires_at").is_none());
    assert!(value.get("redirect_uris").is_none());
    assert!(value.get("client_uri").is_none());
    assert!(value.get("logo_uri").is_none());
    assert!(value.get("tos_uri").is_none());
    assert!(value.get("policy_uri").is_none());
    assert!(value.get("scope").is_none());
    assert!(value.get("contacts").is_none());
    assert!(value.get("jwks").is_none());
    assert!(value.get("jwks_uri").is_none());
    assert!(value.get("software_id").is_none());
    assert!(value.get("software_version").is_none());
    assert!(value.get("dpop_bound_access_tokens").is_none());
}

/// When `client_secret` is present, `client_secret_expires_at` must also be present
/// (RFC 7591 Section 3.2.1 requires it when a secret is issued).
#[test]
fn test_response_serialization_includes_secret_fields_when_present() {
    let response = RegistrationResponse {
        client_id: "test-client".to_string(),
        client_secret: Some("s3cr3t".into()),
        client_secret_expires_at: Some(0),
        client_id_issued_at: Some(1_700_000_000),
        registration_access_token: None,
        registration_client_uri: None,
        redirect_uris: Some(vec!["https://example.com/cb".to_string()]),
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        grant_types: vec!["authorization_code".to_string()],
        response_types: vec!["code".to_string()],
        client_name: None,
        client_uri: None,
        logo_uri: None,
        tos_uri: None,
        policy_uri: None,
        scope: None,
        contacts: None,
        jwks: None,
        jwks_uri: None,
        software_id: None,
        software_version: None,
        dpop_bound_access_tokens: None,
        id_token_signed_response_alg: "ES256".to_string(),
        authorization_signed_response_alg: None,
        introspection_signed_response_alg: None,
        request_object_signing_alg: None,
        require_signed_request_object: None,
        userinfo_signed_response_alg: None,
        request_uris: None,
        post_logout_redirect_uris: None,
    };

    let json = serde_json::to_string(&response).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(value["client_secret"], "s3cr3t");
    assert_eq!(value["client_secret_expires_at"], 0);
    assert_eq!(value["redirect_uris"].as_array().unwrap().len(), 1);
}

// =========================================================================
// Constants Tests
// =========================================================================

#[test]
fn test_allowed_grant_types_includes_expected() {
    let allowed = allowed_grant_types();
    assert!(
        allowed.contains(&"authorization_code"),
        "authorization_code must be an allowed grant type"
    );
    assert!(
        allowed.contains(&"client_credentials"),
        "client_credentials must be an allowed grant type"
    );
    assert!(
        allowed.contains(&"urn:ietf:params:oauth:grant-type:device_code"),
        "device_code URN must be an allowed grant type"
    );
    assert!(
        allowed.contains(&"refresh_token"),
        "refresh_token must be accepted in registration (though never issued)"
    );
}

/// The registration-only delta must stay disjoint from the token
/// endpoint's dispatch set. Every dispatchable grant being registrable is
/// guaranteed by construction (`allowed_grant_types` is the union); this
/// guards the other direction — if a delta entry ever becomes
/// dispatchable, it must be removed from the delta.
#[test]
fn registration_only_grants_are_not_dispatchable() {
    for grant in REGISTRATION_ONLY_GRANT_TYPES {
        assert!(
            grant
                .parse::<crate::services::oidc::grant_type::OAuthGrantType>()
                .is_err(),
            "{grant} is dispatched by the token endpoint; \
             remove it from REGISTRATION_ONLY_GRANT_TYPES"
        );
    }
}

#[test]
fn test_allowed_response_types_includes_code() {
    assert!(
        crate::services::oidc::SUPPORTED_RESPONSE_TYPES.contains(&"code"),
        "'code' must be in the supported response types set"
    );
}

// =========================================================================
// Constants — Additional Checks
// =========================================================================

/// `implicit` must NOT be in the allowed grant types list.
#[test]
fn test_implicit_grant_not_allowed() {
    assert!(
        !allowed_grant_types().contains(&"implicit"),
        "The implicit grant type must not be allowed (deprecated by RFC 9700)"
    );
}

/// `token` response type must NOT be in the allowed set.
#[test]
fn test_token_response_type_not_allowed() {
    assert!(
        !crate::services::oidc::SUPPORTED_RESPONSE_TYPES.contains(&"token"),
        "'token' response type must not be allowed (implicit flow)"
    );
}

/// `id_token` response type must NOT be in the allowed set.
#[test]
fn test_id_token_response_type_not_allowed() {
    assert!(
        !crate::services::oidc::SUPPORTED_RESPONSE_TYPES.contains(&"id_token"),
        "'id_token' response type must not be allowed (implicit flow)"
    );
}

/// MAX_REDIRECT_URIS must be a positive non-trivial limit.
#[test]
fn test_max_redirect_uris_is_reasonable() {
    const {
        assert!(MAX_REDIRECT_URIS >= 5, "should allow at least 5 URIs");
        assert!(MAX_REDIRECT_URIS <= 100, "should not be excessively large");
    }
}

/// MAX_CONTACTS must be a positive non-trivial limit.
#[test]
fn test_max_contacts_is_reasonable() {
    const {
        assert!(MAX_CONTACTS >= 2, "should allow at least 2 contacts");
    }
}

// =========================================================================
// generate_registration_token Tests
// =========================================================================

/// Token must start with the "vouch_reg_" prefix.
#[test]
fn test_generate_registration_token_has_prefix() {
    let token = generate_registration_token().unwrap();
    assert!(
        token.starts_with("vouch_reg_"),
        "Registration token must start with 'vouch_reg_': got '{token}'"
    );
}

/// Tokens must be sufficiently long for security (prefix + 32 bytes base64url ≈ 53 chars).
#[test]
fn test_generate_registration_token_length() {
    let token = generate_registration_token().unwrap();
    // "vouch_reg_" = 10 chars; base64url(32 bytes) = 43 chars → total ≥ 50
    assert!(
        token.len() >= 50,
        "Registration token too short: {} chars",
        token.len()
    );
}

/// Two generated tokens must not be identical (random generation).
#[test]
fn test_generate_registration_token_is_unique() {
    let t1 = generate_registration_token().unwrap();
    let t2 = generate_registration_token().unwrap();
    assert_ne!(t1, t2, "Registration tokens must be unique");
}

/// Token suffix must be valid base64url (no '+', '/', '=' padding).
#[test]
fn test_generate_registration_token_suffix_is_base64url() {
    let token = generate_registration_token().unwrap();
    let suffix = token.strip_prefix("vouch_reg_").unwrap();
    assert!(
        !suffix.contains('+') && !suffix.contains('/') && !suffix.contains('='),
        "Token suffix must be base64url-encoded (no +, /, =): '{suffix}'"
    );
}

// =========================================================================
// RegistrationSource Tests
// =========================================================================

/// `RegistrationSource::Manual` must serialize to "manual".
#[test]
fn test_registration_source_manual_as_str() {
    assert_eq!(RegistrationSource::Manual.as_str(), "manual");
}

/// `RegistrationSource::Dynamic` must serialize to "dynamic".
#[test]
fn test_registration_source_dynamic_as_str() {
    assert_eq!(RegistrationSource::Dynamic.as_str(), "dynamic");
}

/// Default registration source must be Manual (for backward-compatibility).
#[test]
fn test_registration_source_default_is_manual() {
    let default = RegistrationSource::default();
    assert_eq!(default.as_str(), "manual");
}

// =========================================================================
// validate_grant_and_response_types
// =========================================================================

fn make_request_with_grant_response(
    grant_types: Option<Vec<&str>>,
    response_types: Option<Vec<&str>>,
) -> RegistrationRequest {
    RegistrationRequest {
        redirect_uris: None,
        token_endpoint_auth_method: None,
        grant_types: grant_types.map(|v| v.iter().map(|s| s.to_string()).collect()),
        response_types: response_types.map(|v| v.iter().map(|s| s.to_string()).collect()),
        client_name: None,
        client_uri: None,
        logo_uri: None,
        tos_uri: None,
        policy_uri: None,
        scope: None,
        contacts: None,
        jwks: None,
        jwks_uri: None,
        software_id: None,
        software_version: None,
        dpop_bound_access_tokens: None,
        id_token_signed_response_alg: None,
        ..Default::default()
    }
}

#[test]
fn test_validate_grant_and_response_types_defaults() {
    let mut req = make_request_with_grant_response(None, None);
    let result = validate_grant_and_response_types(&mut req);
    let validated = result.expect("Defaults must be accepted");
    assert!(
        validated
            .grant_types
            .contains(&"authorization_code".to_string())
    );
    assert!(validated.response_types.contains(&"code".to_string()));
    assert_eq!(validated.auth_method_str, "client_secret_basic");
    assert_eq!(validated.auth_code_grant, AuthorizationCodeGrant::Present);
}

#[test]
fn test_validate_grant_and_response_types_implicit_grant_rejected() {
    let mut req = make_request_with_grant_response(Some(vec!["implicit"]), None);
    let result = validate_grant_and_response_types(&mut req);
    assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
}

#[test]
fn test_validate_grant_and_response_types_implicit_response_token_rejected() {
    let mut req = make_request_with_grant_response(None, Some(vec!["token"]));
    let result = validate_grant_and_response_types(&mut req);
    assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
}

#[test]
fn test_validate_grant_and_response_types_implicit_response_id_token_rejected() {
    let mut req = make_request_with_grant_response(None, Some(vec!["id_token"]));
    let result = validate_grant_and_response_types(&mut req);
    assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
}

#[test]
fn test_validate_grant_and_response_types_unknown_grant_rejected() {
    let mut req = make_request_with_grant_response(Some(vec!["magic_grant"]), None);
    let err = validate_grant_and_response_types(&mut req).unwrap_err();
    assert!(
        matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClientMetadata)
    );
    assert!(
        matches!(&err, ServiceError::OAuth { description, .. } if description.contains("magic_grant"))
    );
}

#[test]
fn test_validate_grant_and_response_types_unknown_response_type_rejected() {
    let mut req = make_request_with_grant_response(None, Some(vec!["magic_response"]));
    let err = validate_grant_and_response_types(&mut req).unwrap_err();
    assert!(
        matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClientMetadata)
    );
    assert!(
        matches!(&err, ServiceError::OAuth { description, .. } if description.contains("magic_response"))
    );
}

#[test]
fn test_validate_grant_and_response_types_auth_code_without_code_response() {
    // authorization_code grant requires "code" response type.
    let mut req =
        make_request_with_grant_response(Some(vec!["authorization_code"]), Some(vec!["code"]));
    // Deliberately overwrite response_types to omit "code" after construction
    req.response_types = Some(vec!["token".to_string()]); // will fail earlier for "token"
    // Use a minimal non-implicit, non-code type — but those are all rejected.
    // Instead, craft a request where the authorization_code grant is present but response_types != ["code"].
    // The only allowed response type is "code", so we must test via a two-step approach:
    // Force grant_types to include authorization_code while response_types is empty.
    let mut req2 = RegistrationRequest {
        redirect_uris: None,
        token_endpoint_auth_method: None,
        grant_types: Some(vec!["authorization_code".to_string()]),
        response_types: Some(vec![]), // empty but won't hit implicit check
        client_name: None,
        client_uri: None,
        logo_uri: None,
        tos_uri: None,
        policy_uri: None,
        scope: None,
        contacts: None,
        jwks: None,
        jwks_uri: None,
        software_id: None,
        software_version: None,
        dpop_bound_access_tokens: None,
        id_token_signed_response_alg: None,
        ..Default::default()
    };
    let result = validate_grant_and_response_types(&mut req2);
    assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
}

#[test]
fn test_validate_grant_and_response_types_client_credentials_valid() {
    let mut req =
        make_request_with_grant_response(Some(vec!["client_credentials"]), Some(vec!["code"]));
    let result = validate_grant_and_response_types(&mut req);
    let validated = result.expect("client_credentials + code must be valid");
    assert_eq!(validated.auth_code_grant, AuthorizationCodeGrant::Absent);
    assert!(
        validated
            .grant_types
            .contains(&"client_credentials".to_string())
    );
}

#[test]
fn test_validate_grant_and_response_types_auth_method_extracted() {
    let mut req = make_request_with_grant_response(None, None);
    req.token_endpoint_auth_method = Some("private_key_jwt".to_string());
    let validated = validate_grant_and_response_types(&mut req).unwrap();
    assert_eq!(validated.auth_method_str, "private_key_jwt");
}

// =========================================================================
// validate_redirect_uris
// =========================================================================

fn make_request_with_redirect_uris(uris: Option<Vec<&str>>) -> RegistrationRequest {
    RegistrationRequest {
        redirect_uris: uris.map(|v| v.iter().map(|s| s.to_string()).collect()),
        token_endpoint_auth_method: None,
        grant_types: None,
        response_types: None,
        client_name: None,
        client_uri: None,
        logo_uri: None,
        tos_uri: None,
        policy_uri: None,
        scope: None,
        contacts: None,
        jwks: None,
        jwks_uri: None,
        software_id: None,
        software_version: None,
        dpop_bound_access_tokens: None,
        id_token_signed_response_alg: None,
        ..Default::default()
    }
}

#[test]
fn test_validate_redirect_uris_required_for_auth_code_empty() {
    let mut req = make_request_with_redirect_uris(None);
    let result = validate_redirect_uris(
        &mut req,
        AuthorizationCodeGrant::Present,
        crate::db::OAuthClientType::Web,
    );
    assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
}

#[test]
fn test_validate_redirect_uris_not_required_without_auth_code() {
    let mut req = make_request_with_redirect_uris(None);
    let result = validate_redirect_uris(
        &mut req,
        AuthorizationCodeGrant::Absent,
        crate::db::OAuthClientType::Web,
    );
    let uris = result.expect("Empty redirect_uris allowed without the authorization_code grant");
    assert!(uris.is_empty());
}

#[test]
fn test_validate_redirect_uris_too_many() {
    let many: Vec<&str> = (0..=MAX_REDIRECT_URIS)
        .map(|_| "https://example.com/callback")
        .collect();
    let mut req = make_request_with_redirect_uris(Some(many));
    let result = validate_redirect_uris(
        &mut req,
        AuthorizationCodeGrant::Absent,
        crate::db::OAuthClientType::Web,
    );
    assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
}

#[test]
fn test_validate_redirect_uris_valid_uris_pass_through() {
    let mut req = make_request_with_redirect_uris(Some(vec![
        "https://example.com/callback",
        "http://localhost:8080/callback",
    ]));
    let result = validate_redirect_uris(
        &mut req,
        AuthorizationCodeGrant::Present,
        crate::db::OAuthClientType::Web,
    );
    let uris = result.expect("Valid URIs must pass");
    assert_eq!(uris.len(), 2);
}

#[test]
fn test_validate_redirect_uris_invalid_uri_rejected() {
    let mut req = make_request_with_redirect_uris(Some(vec!["not a uri !!"]));
    let result = validate_redirect_uris(
        &mut req,
        AuthorizationCodeGrant::Absent,
        crate::db::OAuthClientType::Web,
    );
    assert_oauth_error(result, OAuthErrorCode::InvalidRedirectUri);
}

// =========================================================================
// validate_jwks_and_auth_method
// =========================================================================

fn make_request_with_jwks(
    jwks: Option<serde_json::Value>,
    jwks_uri: Option<&str>,
) -> RegistrationRequest {
    RegistrationRequest {
        redirect_uris: None,
        token_endpoint_auth_method: None,
        grant_types: None,
        response_types: None,
        client_name: None,
        client_uri: None,
        logo_uri: None,
        tos_uri: None,
        policy_uri: None,
        scope: None,
        contacts: None,
        jwks,
        jwks_uri: jwks_uri.map(String::from),
        software_id: None,
        software_version: None,
        dpop_bound_access_tokens: None,
        id_token_signed_response_alg: None,
        ..Default::default()
    }
}

#[test]
fn test_validate_jwks_and_auth_method_mutual_exclusivity() {
    let jwks = serde_json::json!({"keys": [{"kty": "EC"}]});
    let mut req = make_request_with_jwks(Some(jwks), Some("https://example.com/jwks"));
    let err = validate_jwks_and_auth_method(&mut req, "client_secret_basic").unwrap_err();
    assert!(
        matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClientMetadata)
    );
    assert!(
        matches!(&err, ServiceError::OAuth { description, .. } if description.contains("mutually exclusive"))
    );
}

#[test]
fn test_validate_jwks_and_auth_method_empty_keys_rejected() {
    let jwks = serde_json::json!({"keys": []});
    let mut req = make_request_with_jwks(Some(jwks), None);
    let result = validate_jwks_and_auth_method(&mut req, "client_secret_basic");
    assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
}

#[test]
fn test_validate_jwks_and_auth_method_jwks_uri_not_https() {
    let mut req = make_request_with_jwks(None, Some("http://example.com/jwks"));
    let err = validate_jwks_and_auth_method(&mut req, "client_secret_basic").unwrap_err();
    assert!(
        matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClientMetadata)
    );
    assert!(
        matches!(&err, ServiceError::OAuth { description, .. } if description.contains("https"))
    );
}

#[test]
fn test_validate_jwks_and_auth_method_private_key_jwt_without_jwks() {
    let mut req = make_request_with_jwks(None, None);
    let result = validate_jwks_and_auth_method(&mut req, "private_key_jwt");
    assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
}

#[test]
fn test_validate_jwks_and_auth_method_private_key_jwt_with_jwks_uri_valid() {
    let mut req = make_request_with_jwks(None, Some("https://example.com/jwks.json"));
    let result = validate_jwks_and_auth_method(&mut req, "private_key_jwt");
    let validated = result.expect("private_key_jwt + jwks_uri must succeed");
    assert_eq!(
        validated.auth_method,
        TokenEndpointAuthMethod::PrivateKeyJwt
    );
    assert_eq!(
        validated.keys,
        Some(crate::db::ClientKeys::Uri(
            "https://example.com/jwks.json".to_string()
        ))
    );
}

#[test]
fn test_validate_jwks_and_auth_method_private_key_jwt_with_inline_jwks_valid() {
    let jwks = serde_json::json!({"keys": [{"kty": "EC", "crv": "P-256"}]});
    let mut req = make_request_with_jwks(Some(jwks.clone()), None);
    let result = validate_jwks_and_auth_method(&mut req, "private_key_jwt");
    let validated = result.expect("private_key_jwt + inline jwks must succeed");
    assert_eq!(
        validated.auth_method,
        TokenEndpointAuthMethod::PrivateKeyJwt
    );
    assert!(matches!(
        validated.keys,
        Some(crate::db::ClientKeys::Inline(_))
    ));
}

#[test]
fn test_validate_jwks_and_auth_method_none_auth_method() {
    let mut req = make_request_with_jwks(None, None);
    let result = validate_jwks_and_auth_method(&mut req, "none");
    let validated = result.expect("none auth method must be accepted");
    assert_eq!(validated.auth_method, TokenEndpointAuthMethod::None);
}

#[test]
fn test_validate_jwks_and_auth_method_unknown_auth_method_rejected() {
    let mut req = make_request_with_jwks(None, None);
    let result = validate_jwks_and_auth_method(&mut req, "unknown_method");
    assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
}

// =========================================================================
// validate_jwks_and_auth_method — tls_client_auth (RFC 8705 Section 2.1.1)
// =========================================================================

/// tls_client_auth with a subject_dn identity field is accepted.
#[test]
fn test_validate_tls_client_auth_accepted() {
    let mut req = RegistrationRequest {
        tls_client_auth_subject_dn: Some("CN=test-client".to_string()),
        ..Default::default()
    };
    let result = validate_jwks_and_auth_method(&mut req, "tls_client_auth");
    let validated = result.expect("tls_client_auth + subject_dn must succeed");
    assert_eq!(
        validated.auth_method,
        TokenEndpointAuthMethod::TlsClientAuth
    );
}

/// tls_client_auth without any identity field must be rejected with invalid_client_metadata.
#[test]
fn test_validate_tls_client_auth_requires_identity_field() {
    let mut req = RegistrationRequest {
        // No tls_client_auth_* identity fields set
        ..Default::default()
    };
    let result = validate_jwks_and_auth_method(&mut req, "tls_client_auth");
    assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
}

/// tls_client_auth with san_dns identity field is accepted.
#[test]
fn test_validate_tls_client_auth_with_san_dns_accepted() {
    let mut req = RegistrationRequest {
        tls_client_auth_san_dns: Some("client.example.com".to_string()),
        ..Default::default()
    };
    let result = validate_jwks_and_auth_method(&mut req, "tls_client_auth");
    assert!(
        result.is_ok(),
        "tls_client_auth + san_dns must succeed, got: {result:?}"
    );
}

/// tls_client_auth with san_email identity field is accepted (RFC 8705 Section 2.1.1).
#[test]
fn test_validate_tls_client_auth_with_san_email() {
    let mut req = RegistrationRequest {
        tls_client_auth_san_email: Some("client@example.com".to_string()),
        ..Default::default()
    };
    let result = validate_jwks_and_auth_method(&mut req, "tls_client_auth");
    let validated = result.expect("tls_client_auth + san_email must succeed");
    assert_eq!(
        validated.auth_method,
        TokenEndpointAuthMethod::TlsClientAuth
    );
}

/// tls_client_auth with san_uri identity field is accepted (RFC 8705 Section 2.1.1).
#[test]
fn test_validate_tls_client_auth_with_san_uri() {
    let mut req = RegistrationRequest {
        tls_client_auth_san_uri: Some("https://client.example.com/".to_string()),
        ..Default::default()
    };
    let result = validate_jwks_and_auth_method(&mut req, "tls_client_auth");
    let validated = result.expect("tls_client_auth + san_uri must succeed");
    assert_eq!(
        validated.auth_method,
        TokenEndpointAuthMethod::TlsClientAuth
    );
}

/// tls_client_auth with san_ip identity field is accepted (RFC 8705 Section 2.1.1).
#[test]
fn test_validate_tls_client_auth_with_san_ip() {
    let mut req = RegistrationRequest {
        tls_client_auth_san_ip: Some("192.0.2.1".to_string()),
        ..Default::default()
    };
    let result = validate_jwks_and_auth_method(&mut req, "tls_client_auth");
    let validated = result.expect("tls_client_auth + san_ip must succeed");
    assert_eq!(
        validated.auth_method,
        TokenEndpointAuthMethod::TlsClientAuth
    );
}

/// self_signed_tls_client_auth does not require identity fields — accepted without them.
/// It does require a jwks or jwks_uri (its certificate carrier, RFC 8705
/// §2.2.2), supplied here so this test isolates the identity-fields concern.
#[test]
fn test_validate_self_signed_tls_client_auth_accepted_without_identity() {
    let mut req = make_request_with_jwks(None, Some("https://example.com/jwks.json"));
    let result = validate_jwks_and_auth_method(&mut req, "self_signed_tls_client_auth");
    let validated = result.expect("self_signed_tls_client_auth must succeed without identity");
    assert_eq!(
        validated.auth_method,
        TokenEndpointAuthMethod::SelfSignedTlsClientAuth
    );
}

// =========================================================================
// validate_contacts_and_uris
// =========================================================================

fn make_request_with_uris(
    client_uri: Option<&str>,
    logo_uri: Option<&str>,
    tos_uri: Option<&str>,
    policy_uri: Option<&str>,
    contacts: Option<Vec<&str>>,
) -> RegistrationRequest {
    RegistrationRequest {
        redirect_uris: None,
        token_endpoint_auth_method: None,
        grant_types: None,
        response_types: None,
        client_name: None,
        client_uri: client_uri.map(String::from),
        logo_uri: logo_uri.map(String::from),
        tos_uri: tos_uri.map(String::from),
        policy_uri: policy_uri.map(String::from),
        scope: None,
        contacts: contacts.map(|v| v.iter().map(|s| s.to_string()).collect()),
        jwks: None,
        jwks_uri: None,
        software_id: None,
        software_version: None,
        dpop_bound_access_tokens: None,
        id_token_signed_response_alg: None,
        ..Default::default()
    }
}

#[test]
fn test_validate_contacts_and_uris_all_none_valid() {
    let req = make_request_with_uris(None, None, None, None, None);
    let result = validate_contacts_and_uris(&req);
    assert!(result.is_ok());
}

#[test]
fn test_validate_contacts_and_uris_all_https_valid() {
    let req = make_request_with_uris(
        Some("https://example.com"),
        Some("https://example.com/logo.png"),
        Some("https://example.com/tos"),
        Some("https://example.com/privacy"),
        Some(vec!["admin@example.com"]),
    );
    let result = validate_contacts_and_uris(&req);
    assert!(result.is_ok());
}

#[test]
fn test_validate_contacts_and_uris_http_client_uri_rejected() {
    let req = make_request_with_uris(Some("http://example.com"), None, None, None, None);
    let result = validate_contacts_and_uris(&req);
    assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
}

#[test]
fn test_validate_contacts_and_uris_http_logo_uri_rejected() {
    let req = make_request_with_uris(None, Some("http://example.com/logo.png"), None, None, None);
    let result = validate_contacts_and_uris(&req);
    assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
}

#[test]
fn test_validate_contacts_and_uris_http_tos_uri_rejected() {
    let req = make_request_with_uris(None, None, Some("http://example.com/tos"), None, None);
    let result = validate_contacts_and_uris(&req);
    assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
}

#[test]
fn test_validate_contacts_and_uris_http_policy_uri_rejected() {
    let req = make_request_with_uris(None, None, None, Some("http://example.com/privacy"), None);
    let result = validate_contacts_and_uris(&req);
    assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
}

#[test]
fn test_validate_contacts_and_uris_too_many_contacts() {
    let contacts: Vec<&str> = (0..=MAX_CONTACTS).map(|_| "user@example.com").collect();
    let req = make_request_with_uris(None, None, None, None, Some(contacts));
    let result = validate_contacts_and_uris(&req);
    assert_oauth_error(result, OAuthErrorCode::InvalidClientMetadata);
}

#[test]
fn test_validate_contacts_and_uris_invalid_email_format() {
    let req = make_request_with_uris(None, None, None, None, Some(vec!["notanemail"]));
    let err = validate_contacts_and_uris(&req).unwrap_err();
    assert!(
        matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClientMetadata)
    );
    assert!(
        matches!(&err, ServiceError::OAuth { description, .. } if description.contains("notanemail"))
    );
}

// =========================================================================
// determine_client_type
// =========================================================================

#[test]
fn test_determine_client_type_client_credentials_only_is_service() {
    let grant_types = vec!["client_credentials".to_string()];
    let result = determine_client_type(
        &grant_types,
        TokenEndpointAuthMethod::ClientSecretBasic,
        &[],
    );
    assert_eq!(result, OAuthClientType::Service);
}

#[test]
fn test_determine_client_type_public_with_loopback_is_native() {
    let grant_types = vec!["authorization_code".to_string()];
    let redirect_uris = vec!["http://localhost:7777/callback".to_string()];
    let result = determine_client_type(&grant_types, TokenEndpointAuthMethod::None, &redirect_uris);
    assert_eq!(result, OAuthClientType::Native);
}

#[test]
fn test_determine_client_type_public_with_127_0_0_1_is_native() {
    let grant_types = vec!["authorization_code".to_string()];
    let redirect_uris = vec!["http://127.0.0.1:3000/callback".to_string()];
    let result = determine_client_type(&grant_types, TokenEndpointAuthMethod::None, &redirect_uris);
    assert_eq!(result, OAuthClientType::Native);
}

#[test]
fn test_determine_client_type_public_no_loopback_is_spa() {
    let grant_types = vec!["authorization_code".to_string()];
    let redirect_uris = vec!["https://app.example.com/callback".to_string()];
    let result = determine_client_type(&grant_types, TokenEndpointAuthMethod::None, &redirect_uris);
    assert_eq!(result, OAuthClientType::Spa);
}

#[test]
fn test_determine_client_type_public_no_redirect_uris_is_spa() {
    let grant_types = vec!["authorization_code".to_string()];
    let result = determine_client_type(&grant_types, TokenEndpointAuthMethod::None, &[]);
    assert_eq!(result, OAuthClientType::Spa);
}

#[test]
fn test_determine_client_type_confidential_is_web() {
    let grant_types = vec!["authorization_code".to_string()];
    let redirect_uris = vec!["https://app.example.com/callback".to_string()];
    let result = determine_client_type(
        &grant_types,
        TokenEndpointAuthMethod::ClientSecretBasic,
        &redirect_uris,
    );
    assert_eq!(result, OAuthClientType::Web);
}

#[test]
fn test_determine_client_type_private_key_jwt_is_web() {
    let grant_types = vec!["authorization_code".to_string()];
    let redirect_uris = vec!["https://app.example.com/callback".to_string()];
    let result = determine_client_type(
        &grant_types,
        TokenEndpointAuthMethod::PrivateKeyJwt,
        &redirect_uris,
    );
    assert_eq!(result, OAuthClientType::Web);
}

#[test]
fn test_determine_client_type_client_credentials_with_multiple_grants_not_service() {
    // Only single-grant client_credentials → Service. Multiple grants → Web.
    let grant_types = vec![
        "client_credentials".to_string(),
        "authorization_code".to_string(),
    ];
    let redirect_uris = vec!["https://app.example.com/callback".to_string()];
    let result = determine_client_type(
        &grant_types,
        TokenEndpointAuthMethod::ClientSecretBasic,
        &redirect_uris,
    );
    assert_eq!(result, OAuthClientType::Web);
}

// =========================================================================
// FAPI 2.0 Section 5.4: RS256 rejection across all client-configurable
// signing algorithm fields (issue #393).
//
// Each test asserts the specific field name appears in the error message
// so future refactors that drop the field-specific message would break the
// test, not just the helper.
// =========================================================================

fn assert_rs256_fapi_error(result: Result<(), ServiceError>, field: &str) {
    let err = result.expect_err("RS256 + FAPI must be rejected");
    assert!(
        matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClientMetadata),
        "Expected InvalidClientMetadata OAuth error, got {err:?}"
    );
    assert!(
        matches!(&err, ServiceError::OAuth { description, .. } if description.contains(field)),
        "Error description must name the field '{field}': {err:?}"
    );
    assert!(
        matches!(&err, ServiceError::OAuth { description, .. } if description.contains("RS256")),
        "Error description must mention RS256: {err:?}"
    );
}

#[test]
fn test_reject_rs256_for_fapi_rejects_jarm() {
    let result = reject_rs256_for_fapi(
        JwsAlgorithm::Rs256,
        FapiProfile::Fapi2Security,
        "authorization_signed_response_alg",
    );
    assert_rs256_fapi_error(result, "authorization_signed_response_alg");
}

#[test]
fn test_reject_rs256_for_fapi_rejects_userinfo() {
    let result = reject_rs256_for_fapi(
        JwsAlgorithm::Rs256,
        FapiProfile::Fapi2Security,
        "userinfo_signed_response_alg",
    );
    assert_rs256_fapi_error(result, "userinfo_signed_response_alg");
}

#[test]
fn test_reject_rs256_for_fapi_rejects_id_token() {
    let result = reject_rs256_for_fapi(
        JwsAlgorithm::Rs256,
        FapiProfile::Fapi2Security,
        "id_token_signed_response_alg",
    );
    assert_rs256_fapi_error(result, "id_token_signed_response_alg");
}

#[test]
fn test_reject_rs256_for_fapi_rejects_request_object() {
    let result = reject_rs256_for_fapi(
        JwsAlgorithm::Rs256,
        FapiProfile::Fapi2Security,
        "request_object_signing_alg",
    );
    assert_rs256_fapi_error(result, "request_object_signing_alg");
}

#[test]
fn test_reject_rs256_for_fapi_allows_rs256_for_non_fapi() {
    // Non-FAPI clients are permitted to use RS256 (subject to other checks
    // like RSA key availability handled by the calling block).
    let result = reject_rs256_for_fapi(
        JwsAlgorithm::Rs256,
        FapiProfile::None,
        "authorization_signed_response_alg",
    );
    assert!(result.is_ok(), "Non-FAPI + RS256 must be allowed");
}

#[test]
fn test_reject_rs256_for_fapi_allows_es256_for_fapi() {
    // ES256 is the canonical FAPI-permitted algorithm.
    let result = reject_rs256_for_fapi(
        JwsAlgorithm::Es256,
        FapiProfile::Fapi2Security,
        "authorization_signed_response_alg",
    );
    assert!(result.is_ok(), "FAPI + ES256 must be allowed");
}

#[test]
fn test_validate_userinfo_signed_response_alg_rejects_rs256_for_fapi() {
    // Integration of reject_rs256_for_fapi into the userinfo validator.
    // Passing has_rsa_key=true isolates the FAPI rejection from the
    // "no RSA key configured" path.
    let result = validate_userinfo_signed_response_alg(
        Some("RS256"),
        RsaSigningKey::Available,
        FapiProfile::Fapi2Security,
    );
    assert_rs256_fapi_error(result.map(|_| ()), "userinfo_signed_response_alg");
}

#[test]
fn test_validate_userinfo_signed_response_alg_allows_es256_for_fapi() {
    // ES256 is allowed for FAPI clients regardless of RSA key availability.
    let result = validate_userinfo_signed_response_alg(
        Some("ES256"),
        RsaSigningKey::Unavailable,
        FapiProfile::Fapi2Security,
    );
    let alg = result.expect("ES256 must be accepted for FAPI userinfo");
    assert_eq!(alg, Some(JwsAlgorithm::Es256));
}
