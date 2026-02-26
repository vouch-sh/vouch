// SPDX-License-Identifier: BUSL-1.1
//! FAPI 2.0 Security Profile validation.
//!
//! Centralized validation logic for Financial-grade API (FAPI) 2.0 Security Profile
//! constraints. All FAPI-specific checks are in this module for auditability.
//!
//! Reference: <https://openid.net/specs/fapi-security-profile-2_0-final.html>

use crate::db::{OAuthClient, TokenEndpointAuthMethod};
use crate::services::{OAuthErrorCode, ServiceError, ServiceResult};

/// FAPI 2.0 authorization code lifetime in seconds (shorter than standard).
pub const FAPI_AUTH_CODE_LIFETIME_SECONDS: i64 = 60;

/// Standard (non-FAPI) authorization code lifetime in seconds.
///
/// 60 seconds is sufficient for the client to exchange the code after redirect.
/// Matches the FAPI 2.0 recommendation — no reason for standard clients to be laxer.
pub const STANDARD_AUTH_CODE_LIFETIME_SECONDS: i64 = 60;

/// FAPI 2.0 PAR request lifetime in seconds.
pub const FAPI_PAR_EXPIRES_IN: i64 = 60;

/// Algorithms allowed for FAPI 2.0 clients.
///
/// RS256 is explicitly excluded per FAPI 2.0 Section 5.2.2 due to known weaknesses.
pub const FAPI_ALLOWED_ALGORITHMS: &[&str] = &["PS256", "ES256", "EdDSA"];

/// FAPI 2.0 clock skew tolerance for acceptance (tighter than standard).
pub const FAPI_CLOCK_SKEW_ACCEPT_SECONDS: i64 = 10;

/// FAPI 2.0 clock skew tolerance for rejection (beyond this, always reject).
pub const FAPI_CLOCK_SKEW_REJECT_SECONDS: i64 = 60;

/// Standard (non-FAPI) clock skew tolerance in seconds.
///
/// 10 seconds matches the FAPI 2.0 recommendation. Modern NTP-synced systems
/// should not drift beyond this. Tighter tolerance reduces replay attack windows.
pub const STANDARD_CLOCK_SKEW_SECONDS: i64 = 10;

/// Validate that a client's registration is compatible with FAPI 2.0.
///
/// FAPI 2.0 Section 5.2.2 requires:
/// - Confidential client (not public/SPA/native)
/// - `private_key_jwt` authentication method
/// - JWKS or JWKS URI configured
///
/// Non-FAPI clients pass validation unconditionally.
///
/// # Errors
///
/// Returns `ServiceError::OAuth` with `invalid_client` if the client
/// does not meet FAPI 2.0 registration requirements.
pub fn validate_fapi_client_registration(client: &OAuthClient) -> ServiceResult<()> {
    if !client.is_fapi() {
        return Ok(());
    }

    // FAPI 2.0 Section 5.2.2: Confidential clients only
    if !client.application_type.requires_secret() {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "FAPI 2.0 requires confidential clients",
        ));
    }

    // FAPI 2.0 Section 5.2.2: Must use private_key_jwt
    if client.token_endpoint_auth_method != TokenEndpointAuthMethod::PrivateKeyJwt {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "FAPI 2.0 requires private_key_jwt authentication",
        ));
    }

    // FAPI 2.0: Must have JWKS configured for private_key_jwt
    if client.jwks.is_none() && client.jwks_uri.is_none() {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "FAPI 2.0 requires JWKS or JWKS URI for private_key_jwt",
        ));
    }

    Ok(())
}

/// Validate FAPI 2.0 constraints on an authorization request.
///
/// FAPI 2.0 Section 5.2.2 requires Pushed Authorization Requests (PAR).
/// The `request_uri` must be present, obtained from a prior PAR endpoint call.
///
/// Non-FAPI clients pass validation unconditionally.
///
/// # Arguments
///
/// * `client` - The OAuth client making the authorization request
/// * `has_par` - Whether the request arrived via PAR (`request_uri` present)
///
/// # Errors
///
/// Returns `ServiceError::OAuth` with `invalid_request` if constraints are violated.
pub fn validate_fapi_authorization_request(
    client: &OAuthClient,
    has_par: bool,
) -> ServiceResult<()> {
    if !client.is_fapi() {
        return Ok(());
    }

    // FAPI 2.0 Section 5.2.2: PAR is required
    if !has_par {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequest,
            "FAPI 2.0 requires Pushed Authorization Requests (PAR)",
        ));
    }

    Ok(())
}

/// Validate FAPI 2.0 constraints on a token request.
///
/// FAPI 2.0 Section 5.2.2 requires sender-constrained access tokens.
/// Since we use DPoP (not mTLS), a DPoP proof is required for FAPI clients.
///
/// Non-FAPI clients pass validation unconditionally.
///
/// # Arguments
///
/// * `client` - The OAuth client making the token request
/// * `has_dpop` - Whether a valid DPoP proof was provided in the request
///
/// # Errors
///
/// Returns `ServiceError::OAuth` with `invalid_request` if constraints are violated.
pub fn validate_fapi_token_request(client: &OAuthClient, has_dpop: bool) -> ServiceResult<()> {
    if !client.is_fapi() {
        return Ok(());
    }

    // FAPI 2.0 Section 5.2.2: Sender-constrained tokens required (DPoP or mTLS)
    if !has_dpop {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequest,
            "FAPI 2.0 requires sender-constrained access tokens (DPoP proof required)",
        ));
    }

    Ok(())
}

/// Validate that an algorithm is allowed for a FAPI 2.0 client.
///
/// FAPI 2.0 Section 5.2.2 prohibits RS256 due to known weaknesses.
/// Only PS256, ES256, and EdDSA are permitted.
///
/// Non-FAPI clients pass validation unconditionally.
///
/// # Arguments
///
/// * `client` - The OAuth client
/// * `algorithm` - The algorithm identifier being used (e.g., "RS256", "ES256")
///
/// # Errors
///
/// Returns `ServiceError::OAuth` with `invalid_request` if the algorithm
/// is not in the FAPI 2.0 allowlist.
pub fn validate_fapi_algorithm(client: &OAuthClient, algorithm: &str) -> ServiceResult<()> {
    if !client.is_fapi() {
        return Ok(());
    }

    if !FAPI_ALLOWED_ALGORITHMS.contains(&algorithm) {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequest,
            format!(
                "FAPI 2.0 does not allow algorithm '{}'. Allowed: PS256, ES256, EdDSA",
                algorithm
            ),
        ));
    }

    Ok(())
}

/// Validate that the client authentication method is allowed for FAPI 2.0.
///
/// FAPI 2.0 Section 5.2.2 requires `private_key_jwt` (mTLS support is deferred).
///
/// Non-FAPI clients pass validation unconditionally.
///
/// # Arguments
///
/// * `client` - The OAuth client
/// * `auth_method` - The authentication method used in this request
///
/// # Errors
///
/// Returns `ServiceError::OAuth` with `invalid_client` if the method is not
/// `private_key_jwt`.
pub fn validate_fapi_client_auth_method(
    client: &OAuthClient,
    auth_method: TokenEndpointAuthMethod,
) -> ServiceResult<()> {
    if !client.is_fapi() {
        return Ok(());
    }

    match auth_method {
        TokenEndpointAuthMethod::PrivateKeyJwt => Ok(()),
        _ => Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            format!(
                "FAPI 2.0 requires private_key_jwt authentication, got '{}'",
                auth_method.as_str()
            ),
        )),
    }
}

/// Return the clock skew tolerance for a client.
///
/// FAPI 2.0 clients use a tighter 10-second acceptance window.
/// Standard clients use 30 seconds.
///
/// This is used when validating JWT timestamps (`iat`, `exp`, `nbf`).
pub fn clock_skew_seconds(client: &OAuthClient) -> i64 {
    if client.is_fapi() {
        FAPI_CLOCK_SKEW_ACCEPT_SECONDS
    } else {
        STANDARD_CLOCK_SKEW_SECONDS
    }
}

/// Return the authorization code lifetime for a client.
///
/// FAPI 2.0 clients receive a 60-second code lifetime.
/// Standard clients receive a 300-second lifetime.
pub fn auth_code_lifetime_seconds(client: &OAuthClient) -> i64 {
    if client.is_fapi() {
        FAPI_AUTH_CODE_LIFETIME_SECONDS
    } else {
        STANDARD_AUTH_CODE_LIFETIME_SECONDS
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::db::{AccessScope, FapiProfile, OAuthClientType};

    /// Create a minimal FAPI 2.0 confidential client for testing.
    fn fapi_client() -> OAuthClient {
        let now = jiff::Timestamp::now();
        OAuthClient {
            id: "test-fapi-id".to_string(),
            user_id: Some("test-user".to_string()),
            client_id: "fapi-client-id".to_string(),
            name: "FAPI Test Client".to_string(),
            description: None,
            application_type: OAuthClientType::Service,
            redirect_uris: r#"["https://example.com/callback"]"#.to_string(),
            active: true,
            created_at: now,
            updated_at: now,
            last_used_at: None,
            access_scope: AccessScope::Organization,
            org_id: None,
            resource_uris: "[]".to_string(),
            jwks: Some(r#"{"keys":[]}"#.to_string()),
            jwks_uri: None,
            jwks_uri_cached_at: None,
            jwks_uri_cache: None,
            token_endpoint_auth_method: TokenEndpointAuthMethod::PrivateKeyJwt,
            request_object_signing_alg: None,
            require_signed_request_object: None,
            fapi_profile: FapiProfile::Fapi2Security,
            dpop_bound_access_tokens: true,
            grant_types: None,
            response_types: None,
            software_id: None,
            software_version: None,
            registration_source: None,
            registration_access_token_hash: None,
            registration_metadata: None,
        }
    }

    /// Create a minimal standard (non-FAPI) client for testing.
    fn standard_client() -> OAuthClient {
        let now = jiff::Timestamp::now();
        OAuthClient {
            id: "test-standard-id".to_string(),
            user_id: Some("test-user".to_string()),
            client_id: "standard-client-id".to_string(),
            name: "Standard Test Client".to_string(),
            description: None,
            application_type: OAuthClientType::Web,
            redirect_uris: r#"["https://example.com/callback"]"#.to_string(),
            active: true,
            created_at: now,
            updated_at: now,
            last_used_at: None,
            access_scope: AccessScope::Organization,
            org_id: None,
            resource_uris: "[]".to_string(),
            jwks: None,
            jwks_uri: None,
            jwks_uri_cached_at: None,
            jwks_uri_cache: None,
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            request_object_signing_alg: None,
            require_signed_request_object: None,
            fapi_profile: FapiProfile::None,
            dpop_bound_access_tokens: false,
            grant_types: None,
            response_types: None,
            software_id: None,
            software_version: None,
            registration_source: None,
            registration_access_token_hash: None,
            registration_metadata: None,
        }
    }

    // =========================================================================
    // Client Registration Tests
    // =========================================================================

    #[test]
    fn test_validate_fapi_client_registration_valid() {
        let client = fapi_client();
        assert!(validate_fapi_client_registration(&client).is_ok());
    }

    #[test]
    fn test_validate_fapi_client_registration_rejects_public_client() {
        let mut client = fapi_client();
        client.application_type = OAuthClientType::Spa;
        assert!(validate_fapi_client_registration(&client).is_err());
    }

    #[test]
    fn test_validate_fapi_client_registration_rejects_native_client() {
        let mut client = fapi_client();
        client.application_type = OAuthClientType::Native;
        assert!(validate_fapi_client_registration(&client).is_err());
    }

    #[test]
    fn test_validate_fapi_client_registration_rejects_client_secret() {
        let mut client = fapi_client();
        client.token_endpoint_auth_method = TokenEndpointAuthMethod::ClientSecretBasic;
        assert!(validate_fapi_client_registration(&client).is_err());
    }

    #[test]
    fn test_validate_fapi_client_registration_rejects_no_jwks() {
        let mut client = fapi_client();
        client.jwks = None;
        client.jwks_uri = None;
        assert!(validate_fapi_client_registration(&client).is_err());
    }

    #[test]
    fn test_validate_fapi_client_registration_accepts_jwks_uri() {
        let mut client = fapi_client();
        client.jwks = None;
        client.jwks_uri = Some("https://example.com/.well-known/jwks.json".to_string());
        assert!(validate_fapi_client_registration(&client).is_ok());
    }

    #[test]
    fn test_validate_fapi_client_registration_skips_non_fapi() {
        let client = standard_client();
        assert!(validate_fapi_client_registration(&client).is_ok());
    }

    // =========================================================================
    // Authorization Request Tests
    // =========================================================================

    #[test]
    fn test_validate_fapi_authorization_request_requires_par() {
        let client = fapi_client();
        assert!(validate_fapi_authorization_request(&client, false).is_err());
    }

    #[test]
    fn test_validate_fapi_authorization_request_accepts_par() {
        let client = fapi_client();
        assert!(validate_fapi_authorization_request(&client, true).is_ok());
    }

    #[test]
    fn test_validate_fapi_authorization_request_skips_non_fapi() {
        let client = standard_client();
        // Non-FAPI clients don't need PAR
        assert!(validate_fapi_authorization_request(&client, false).is_ok());
        assert!(validate_fapi_authorization_request(&client, true).is_ok());
    }

    // =========================================================================
    // Token Request Tests
    // =========================================================================

    #[test]
    fn test_validate_fapi_token_request_requires_dpop() {
        let client = fapi_client();
        assert!(validate_fapi_token_request(&client, false).is_err());
    }

    #[test]
    fn test_validate_fapi_token_request_accepts_dpop() {
        let client = fapi_client();
        assert!(validate_fapi_token_request(&client, true).is_ok());
    }

    #[test]
    fn test_validate_fapi_token_request_skips_non_fapi() {
        let client = standard_client();
        assert!(validate_fapi_token_request(&client, false).is_ok());
        assert!(validate_fapi_token_request(&client, true).is_ok());
    }

    // =========================================================================
    // Algorithm Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_fapi_algorithm_rejects_rs256() {
        let client = fapi_client();
        assert!(validate_fapi_algorithm(&client, "RS256").is_err());
    }

    #[test]
    fn test_validate_fapi_algorithm_allows_es256() {
        let client = fapi_client();
        assert!(validate_fapi_algorithm(&client, "ES256").is_ok());
    }

    #[test]
    fn test_validate_fapi_algorithm_allows_ps256() {
        let client = fapi_client();
        assert!(validate_fapi_algorithm(&client, "PS256").is_ok());
    }

    #[test]
    fn test_validate_fapi_algorithm_allows_eddsa() {
        let client = fapi_client();
        assert!(validate_fapi_algorithm(&client, "EdDSA").is_ok());
    }

    #[test]
    fn test_validate_fapi_algorithm_rejects_rs384() {
        let client = fapi_client();
        assert!(validate_fapi_algorithm(&client, "RS384").is_err());
    }

    #[test]
    fn test_validate_fapi_algorithm_skips_non_fapi() {
        let client = standard_client();
        // Non-FAPI clients are not restricted
        assert!(validate_fapi_algorithm(&client, "RS256").is_ok());
        assert!(validate_fapi_algorithm(&client, "ES256").is_ok());
    }

    // =========================================================================
    // Client Auth Method Tests
    // =========================================================================

    #[test]
    fn test_validate_fapi_client_auth_method_accepts_private_key_jwt() {
        let client = fapi_client();
        assert!(
            validate_fapi_client_auth_method(&client, TokenEndpointAuthMethod::PrivateKeyJwt)
                .is_ok()
        );
    }

    #[test]
    fn test_validate_fapi_client_auth_method_rejects_client_secret_basic() {
        let client = fapi_client();
        assert!(
            validate_fapi_client_auth_method(&client, TokenEndpointAuthMethod::ClientSecretBasic)
                .is_err()
        );
    }

    #[test]
    fn test_validate_fapi_client_auth_method_rejects_client_secret_post() {
        let client = fapi_client();
        assert!(
            validate_fapi_client_auth_method(&client, TokenEndpointAuthMethod::ClientSecretPost)
                .is_err()
        );
    }

    #[test]
    fn test_validate_fapi_client_auth_method_rejects_none() {
        let client = fapi_client();
        assert!(validate_fapi_client_auth_method(&client, TokenEndpointAuthMethod::None).is_err());
    }

    #[test]
    fn test_validate_fapi_client_auth_method_skips_non_fapi() {
        let client = standard_client();
        assert!(
            validate_fapi_client_auth_method(&client, TokenEndpointAuthMethod::ClientSecretBasic)
                .is_ok()
        );
        assert!(validate_fapi_client_auth_method(&client, TokenEndpointAuthMethod::None).is_ok());
    }

    // =========================================================================
    // Clock Skew Tests
    // =========================================================================

    #[test]
    fn test_clock_skew_seconds_fapi_client() {
        let client = fapi_client();
        assert_eq!(clock_skew_seconds(&client), FAPI_CLOCK_SKEW_ACCEPT_SECONDS);
        assert_eq!(clock_skew_seconds(&client), 10);
    }

    #[test]
    fn test_clock_skew_seconds_standard_client() {
        let client = standard_client();
        assert_eq!(clock_skew_seconds(&client), STANDARD_CLOCK_SKEW_SECONDS);
        assert_eq!(clock_skew_seconds(&client), 10);
    }

    // =========================================================================
    // Auth Code Lifetime Tests
    // =========================================================================

    #[test]
    fn test_auth_code_lifetime_seconds_fapi_client() {
        let client = fapi_client();
        assert_eq!(
            auth_code_lifetime_seconds(&client),
            FAPI_AUTH_CODE_LIFETIME_SECONDS
        );
        assert_eq!(auth_code_lifetime_seconds(&client), 60);
    }

    #[test]
    fn test_auth_code_lifetime_seconds_standard_client() {
        let client = standard_client();
        assert_eq!(
            auth_code_lifetime_seconds(&client),
            STANDARD_AUTH_CODE_LIFETIME_SECONDS
        );
        assert_eq!(auth_code_lifetime_seconds(&client), 60);
    }

    // =========================================================================
    // Constants Sanity Tests
    // =========================================================================

    #[test]
    fn test_fapi_and_standard_auth_code_lifetime_aligned() {
        // Both FAPI and standard use 60s — FAPI best practice adopted as default.
        let fapi = FAPI_AUTH_CODE_LIFETIME_SECONDS;
        let standard = STANDARD_AUTH_CODE_LIFETIME_SECONDS;
        assert_eq!(fapi, standard);
        assert_eq!(fapi, 60);
    }

    #[test]
    fn test_fapi_and_standard_clock_skew_aligned() {
        // Both FAPI and standard use 10s — FAPI best practice adopted as default.
        let fapi = FAPI_CLOCK_SKEW_ACCEPT_SECONDS;
        let standard = STANDARD_CLOCK_SKEW_SECONDS;
        assert_eq!(fapi, standard);
        assert_eq!(fapi, 10);
    }

    #[test]
    fn test_fapi_reject_clock_skew_is_beyond_accept() {
        let reject = FAPI_CLOCK_SKEW_REJECT_SECONDS;
        let accept = FAPI_CLOCK_SKEW_ACCEPT_SECONDS;
        assert!(reject > accept);
    }

    #[test]
    fn test_fapi_allowed_algorithms_excludes_rs256() {
        assert!(!FAPI_ALLOWED_ALGORITHMS.contains(&"RS256"));
    }

    #[test]
    fn test_fapi_allowed_algorithms_includes_required() {
        assert!(FAPI_ALLOWED_ALGORITHMS.contains(&"PS256"));
        assert!(FAPI_ALLOWED_ALGORITHMS.contains(&"ES256"));
        assert!(FAPI_ALLOWED_ALGORITHMS.contains(&"EdDSA"));
    }
}
