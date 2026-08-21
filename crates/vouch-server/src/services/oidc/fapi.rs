// SPDX-License-Identifier: Apache-2.0 OR MIT
//! FAPI 2.0 Security Profile validation.
//!
//! Centralized validation logic for Financial-grade API (FAPI) 2.0 Security Profile
//! constraints. All FAPI-specific checks are in this module for auditability.
//!
//! Reference: <https://openid.net/specs/fapi-security-profile-2_0-final.html>

use crate::db::{JwsAlgorithm, OAuthClient, TokenEndpointAuthMethod};
use crate::error::{OAuthErrorCode, ServiceError, ServiceResult};

/// FAPI 2.0 authorization code lifetime in seconds (shorter than standard).
pub const FAPI_AUTH_CODE_LIFETIME_SECONDS: i64 = 60;

/// Standard (non-FAPI) authorization code lifetime in seconds.
///
/// 60 seconds is sufficient for the client to exchange the code after redirect.
/// Matches the FAPI 2.0 recommendation — no reason for standard clients to be laxer.
pub const STANDARD_AUTH_CODE_LIFETIME_SECONDS: i64 = 60;

/// FAPI 2.0 clock skew tolerance for acceptance (tighter than standard).
pub const FAPI_CLOCK_SKEW_ACCEPT_SECONDS: i64 = 10;

/// Standard (non-FAPI) clock skew tolerance in seconds.
///
/// 10 seconds matches the FAPI 2.0 recommendation. Modern NTP-synced systems
/// should not drift beyond this. Tighter tolerance reduces replay attack windows.
pub const STANDARD_CLOCK_SKEW_SECONDS: i64 = 10;

/// Validate FAPI 2.0 constraints on an authorization request.
///
/// FAPI 2.0 Section 5.3.2.2 requires Pushed Authorization Requests (PAR).
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

    // FAPI 2.0 Section 5.3.2.2: PAR is required
    if !has_par {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequest,
            "FAPI 2.0 requires Pushed Authorization Requests (PAR)",
        ));
    }

    Ok(())
}

/// Sender-constraint mechanisms present on a token request.
///
/// FAPI 2.0 Section 5.3.2.1 requires at least one of these for FAPI clients.
#[derive(Debug, Clone, Copy)]
pub struct SenderConstraints {
    /// A valid DPoP proof was provided in the request.
    pub dpop: bool,
    /// A client mTLS certificate was presented on the connection.
    pub mtls_cert: bool,
}

/// Validate FAPI 2.0 constraints on a token request.
///
/// FAPI 2.0 Section 5.3.2.1 requires sender-constrained access tokens,
/// so FAPI clients must present at least one mechanism in `constraints`.
///
/// Non-FAPI clients pass validation unconditionally.
///
/// # Errors
///
/// Returns `ServiceError::OAuth` with `invalid_request` if constraints are violated.
pub(crate) fn validate_fapi_token_request(
    client: &OAuthClient,
    constraints: SenderConstraints,
) -> ServiceResult<()> {
    if !client.is_fapi() {
        return Ok(());
    }

    // FAPI 2.0 Section 5.3.2.1: Sender-constrained tokens required (DPoP or mTLS)
    if !constraints.dpop && !constraints.mtls_cert {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequest,
            "FAPI 2.0 requires sender-constrained access tokens (DPoP or mTLS required)",
        ));
    }

    Ok(())
}

/// Validate that an algorithm is allowed for a FAPI 2.0 client.
///
/// See [`JwsAlgorithm::FAPI_ALLOWED`] for the FAPI 2.0 citation excluding RS256.
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

    let allowed = algorithm
        .parse::<JwsAlgorithm>()
        .is_ok_and(|alg| JwsAlgorithm::FAPI_ALLOWED.contains(&alg));
    if !allowed {
        let allowed_list = JwsAlgorithm::FAPI_ALLOWED
            .iter()
            .map(JwsAlgorithm::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequest,
            format!("FAPI 2.0 does not allow algorithm '{algorithm}'. Allowed: {allowed_list}"),
        ));
    }

    Ok(())
}

/// Validate that the client authentication method is allowed for FAPI 2.0.
///
/// FAPI 2.0 Section 5.3.2.1 requires `private_key_jwt` (mTLS support is deferred).
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
        TokenEndpointAuthMethod::PrivateKeyJwt
        | TokenEndpointAuthMethod::TlsClientAuth
        | TokenEndpointAuthMethod::SelfSignedTlsClientAuth => Ok(()),
        _ => Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            format!(
                "FAPI 2.0 requires private_key_jwt or mTLS authentication, got '{}'",
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
mod tests {
    use super::*;
    use crate::db::{AccessScope, FapiProfile, JwsAlgorithm, OAuthClientType};

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
            redirect_uris: vec!["https://example.com/callback".to_string()],
            active: true,
            created_at: now,
            updated_at: now,
            last_used_at: None,
            access_scope: AccessScope::Organization,
            org_id: None,
            resource_uris: vec![],
            jwks: Some(serde_json::json!({"keys":[]})),
            jwks_uri: None,
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
            id_token_signed_response_alg: JwsAlgorithm::Rs256,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,
            tls_client_certificate_bound_access_tokens: false,
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: None,
            userinfo_signed_response_alg: None,
            request_uris: None,
            post_logout_redirect_uris: None,
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
            redirect_uris: vec!["https://example.com/callback".to_string()],
            active: true,
            created_at: now,
            updated_at: now,
            last_used_at: None,
            access_scope: AccessScope::Organization,
            org_id: None,
            resource_uris: vec![],
            jwks: None,
            jwks_uri: None,
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
            id_token_signed_response_alg: JwsAlgorithm::Rs256,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,
            tls_client_certificate_bound_access_tokens: false,
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: None,
            userinfo_signed_response_alg: None,
            request_uris: None,
            post_logout_redirect_uris: None,
        }
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

    const NO_CONSTRAINTS: SenderConstraints = SenderConstraints {
        dpop: false,
        mtls_cert: false,
    };
    const DPOP_ONLY: SenderConstraints = SenderConstraints {
        dpop: true,
        mtls_cert: false,
    };
    const MTLS_ONLY: SenderConstraints = SenderConstraints {
        dpop: false,
        mtls_cert: true,
    };

    #[test]
    fn test_validate_fapi_token_request_requires_sender_constraint() {
        let client = fapi_client();
        assert!(validate_fapi_token_request(&client, NO_CONSTRAINTS).is_err());
    }

    #[test]
    fn test_validate_fapi_token_request_accepts_dpop() {
        let client = fapi_client();
        assert!(validate_fapi_token_request(&client, DPOP_ONLY).is_ok());
    }

    #[test]
    fn test_validate_fapi_token_request_accepts_mtls() {
        // mTLS certificate is a valid sender-constraint mechanism for FAPI 2.0.
        let client = fapi_client();
        assert!(
            validate_fapi_token_request(&client, MTLS_ONLY).is_ok(),
            "mTLS cert must be accepted as sender-constraint for FAPI token request"
        );
    }

    #[test]
    fn test_validate_fapi_token_request_skips_non_fapi() {
        let client = standard_client();
        assert!(validate_fapi_token_request(&client, NO_CONSTRAINTS).is_ok());
        assert!(validate_fapi_token_request(&client, DPOP_ONLY).is_ok());
    }

    // =========================================================================
    // Algorithm Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_fapi_algorithm_rejects_rs256() {
        let client = fapi_client();
        let result = validate_fapi_algorithm(&client, "RS256");
        assert!(result.is_err(), "RS256 must be rejected");
        if let Err(err) = result {
            let message = err.oauth_description();
            assert!(
                message.contains("Allowed: ES256, PS256, EdDSA"),
                "error message must pin the FAPI_ALLOWED wire order, got: {message}"
            );
        }
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
    fn test_validate_fapi_client_auth_method_accepts_tls_client_auth() {
        let client = fapi_client();
        assert!(
            validate_fapi_client_auth_method(&client, TokenEndpointAuthMethod::TlsClientAuth)
                .is_ok(),
            "TlsClientAuth must be accepted for FAPI clients"
        );
    }

    #[test]
    fn test_validate_fapi_client_auth_method_accepts_self_signed_tls() {
        let client = fapi_client();
        assert!(
            validate_fapi_client_auth_method(
                &client,
                TokenEndpointAuthMethod::SelfSignedTlsClientAuth
            )
            .is_ok(),
            "SelfSignedTlsClientAuth must be accepted for FAPI clients"
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
    fn test_fapi_allowed_algorithms_excludes_rs256() {
        assert!(!JwsAlgorithm::FAPI_ALLOWED.contains(&JwsAlgorithm::Rs256));
    }

    #[test]
    fn test_fapi_allowed_algorithms_includes_required() {
        assert!(JwsAlgorithm::FAPI_ALLOWED.contains(&JwsAlgorithm::Ps256));
        assert!(JwsAlgorithm::FAPI_ALLOWED.contains(&JwsAlgorithm::Es256));
        assert!(JwsAlgorithm::FAPI_ALLOWED.contains(&JwsAlgorithm::EdDsa));
    }
}
