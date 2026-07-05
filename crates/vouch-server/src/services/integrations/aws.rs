// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS integration service.
//!
//! This module provides OIDC token issuance for AWS STS `AssumeRoleWithWebIdentity`.
//!
//! # How it works
//!
//! 1. User authenticates with Vouch using FIDO2/WebAuthn
//! 2. User requests an AWS token via `/v1/credentials/aws/token`
//! 3. Vouch issues an OIDC ID token with the user's identity
//! 4. User exchanges the token with AWS STS for temporary credentials
//!
//! # AWS Configuration
//!
//! The AWS IAM role must be configured to trust the Vouch OIDC provider.
//!
//! When the organization has claimed an issuer subdomain (e.g. `acme` →
//! `https://acme.us.vouch.sh`), that issuer host has its **own** signing keys,
//! served only at its own JWKS. A token minted for another org is signed with a
//! different key and will not verify against this issuer, so the provider ARN
//! alone scopes trust — no `Condition` block is needed:
//!
//! ```json
//! {
//!   "Version": "2012-10-17",
//!   "Statement": [{
//!     "Effect": "Allow",
//!     "Principal": {"Federated": "arn:aws:iam::ACCOUNT:oidc-provider/acme.us.vouch.sh"},
//!     "Action": "sts:AssumeRoleWithWebIdentity"
//!   }]
//! }
//! ```
//!
//! Two caveats:
//!
//! - **Releasing a subdomain does not revoke AWS-side trust.** Delete the
//!   corresponding IAM OIDC identity provider when you release a label —
//!   otherwise a later claimant of the same label gets fresh keys served at that
//!   host and could mint tokens the role still accepts.
//! - **Per-org keys require a KMS-backed deployment.** Without at-rest
//!   encryption the issuer subdomain falls back to the shared signing key, so
//!   the host is not a tenant boundary; there, scope the trust policy by
//!   audience and the `vouch:Domain` session tag instead of the ARN alone.
//!
//! Without a claimed subdomain the issuer is the shared server base URL, and
//! the trust policy must scope by audience (and typically `sub` or session
//! tags) because every org shares that provider host:
//!
//! ```json
//! {
//!   "Version": "2012-10-17",
//!   "Statement": [{
//!     "Effect": "Allow",
//!     "Principal": {"Federated": "arn:aws:iam::ACCOUNT:oidc-provider/vouch.example.com"},
//!     "Action": "sts:AssumeRoleWithWebIdentity",
//!     "Condition": {
//!       "StringEquals": {
//!         "vouch.example.com:aud": "https://vouch.example.com"
//!       }
//!     }
//!   }]
//! }
//! ```

use crate::handlers::session::ValidatedResourceToken;
use crate::redact_email;
use crate::services::oidc::{
    AwsSessionTags, OidcIdTokenClaimsBuilder, OidcRsaSigningKey, OidcSigningKey,
};

/// Error types for AWS integration operations.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AwsError {
    /// Failed to build OIDC claims.
    #[error("Failed to build claims: {0}")]
    ClaimsBuild(String),

    /// Failed to sign the token.
    #[error("Failed to sign token: {0}")]
    TokenSign(String),
}

/// Result type for AWS integration operations.
pub(crate) type AwsResult<T> = Result<T, AwsError>;

/// Result of issuing an AWS OIDC token.
#[derive(Debug)]
pub(crate) struct AwsTokenResult {
    /// The signed OIDC ID token.
    pub id_token: String,
    /// Token validity in seconds.
    pub expires_in: u64,
}

/// Build the AWS session tags embedded in the `https://aws.amazon.com/tags`
/// claim for ABAC and CloudTrail attribution.
///
/// `vouch:Email` is always present (and transitive). `vouch:Domain` is added
/// when the org domain (`hd`) is known. When an AI coding agent is detected
/// (`source`, set by the CLI via env-var sniffing and carried tamperproof in
/// the DPoP proof), `vouch:AccessType=ai` and `vouch:Agent=<source>` are added.
/// All tags are transitive so they propagate through role chains.
fn build_aws_session_tags(
    user_email: &str,
    hd: Option<&str>,
    source: Option<&str>,
) -> AwsSessionTags {
    let mut principal_tags = std::collections::HashMap::new();
    let mut transitive_tag_keys = Vec::new();

    principal_tags.insert("vouch:Email".to_string(), vec![user_email.to_string()]);
    transitive_tag_keys.push("vouch:Email".to_string());

    if let Some(domain) = hd {
        principal_tags.insert("vouch:Domain".to_string(), vec![domain.to_string()]);
        transitive_tag_keys.push("vouch:Domain".to_string());
    }

    if let Some(agent) = source {
        principal_tags.insert("vouch:AccessType".to_string(), vec!["ai".to_string()]);
        transitive_tag_keys.push("vouch:AccessType".to_string());
        principal_tags.insert("vouch:Agent".to_string(), vec![agent.to_string()]);
        transitive_tag_keys.push("vouch:Agent".to_string());
    }

    AwsSessionTags {
        principal_tags,
        transitive_tag_keys,
    }
}

/// Issue an OIDC ID token for AWS STS.
///
/// The token can be used with `AssumeRoleWithWebIdentity` to get temporary
/// AWS credentials. The token includes:
/// - `sub`: User email
/// - `aud`: Vouch issuer URL (AWS matches against the OIDC provider)
/// - `iss`: Vouch issuer URL
/// - `hardware_aaguid`: FIDO2 authenticator AAGUID (for hardware key verification)
/// - `hd`: Google Workspace hosted domain (for domain-based access control)
///
/// # Arguments
/// * `issuer` - Issuer URL (`iss` and `aud`): the org's claimed issuer
///   subdomain when one exists, otherwise the server base URL
/// * `session_hours` - Session duration in hours
/// * `oidc_key` - OIDC signing key
/// * `user_email` - The authenticated user's email (resolved with a DB fallback,
///   so it is passed explicitly rather than read from the token)
/// * `token` - The validated resource token; supplies the session-snapshot
///   `hardware_aaguid`, `org_domain` (`hd`), and `dpop_source` federation claims
pub(crate) async fn issue_aws_token(
    issuer: &str,
    session_hours: u64,
    oidc_key: &OidcSigningKey,
    user_email: &str,
    token: &ValidatedResourceToken,
) -> AwsResult<AwsTokenResult> {
    // Token validity matches session duration
    let expires_in = session_hours.saturating_mul(3600);

    let aws_tags = build_aws_session_tags(
        user_email,
        token.org_domain.as_deref(),
        token.dpop_source.as_deref(),
    );

    // Build OIDC claims
    // For AWS, the audience is the issuer URL (AWS matches against the OIDC provider)
    let id_claims = OidcIdTokenClaimsBuilder::for_aws(issuer, user_email)
        .hardware_aaguid(token.hardware_aaguid.clone())
        .hd(token.org_domain.clone())
        .aws_tags(aws_tags)
        .valid_for_seconds(expires_in)
        .build()
        .map_err(|e| AwsError::ClaimsBuild(e.to_string()))?;

    // Sign the token with ES256
    let id_token = oidc_key
        .sign_jwt(&id_claims)
        .await
        .map_err(|e| AwsError::TokenSign(e.to_string()))?;

    tracing::info!("Issued AWS OIDC token for {}", redact_email(user_email));

    Ok(AwsTokenResult {
        id_token,
        expires_in,
    })
}

/// Issue an **RS256**-signed OIDC ID token for AWS IAM Identity Center trusted
/// identity propagation.
///
/// This token is the subject (`assertion`) for the IAM Identity Center
/// `sso-oidc:CreateTokenWithIAM` call (`jwt-bearer` grant), which exchanges it
/// for an Identity Center token. That token then drives the SSO Portal
/// (`ListAccounts`/`ListAccountRoles`/`GetRoleCredentials`) to reach every
/// account+permission-set the user is assigned to — without role chaining.
///
/// AWS's trusted-token-issuer contract **requires RS256** (the
/// `AssumeRoleWithWebIdentity` path uses ES256 via [`issue_aws_token`]; this
/// path is distinct and signs with [`OidcRsaSigningKey`]). The token's `iss`
/// matches the Vouch OIDC discovery document and its public key is published in
/// the JWKS, so Identity Center can verify the signature.
///
/// The `aud` claim is set to the issuer, matching the STS token
/// ([`issue_aws_token`]); the customer-managed application's Aud claim
/// must be configured to that same URL. This path therefore differs from
/// [`issue_aws_token`] only by signing algorithm.
///
/// # Arguments
/// * `issuer` - Issuer URL (`iss` and `aud`; must match the registered TTI):
///   the org's claimed issuer subdomain when one exists, otherwise the
///   server base URL
/// * `session_hours` - Session duration in hours
/// * `oidc_rsa_key` - OIDC RSA (RS256) signing key
/// * `user_email` - Authenticated user's email (maps to the Identity Store user;
///   resolved with a DB fallback, so it is passed explicitly rather than read
///   from the token)
/// * `token` - The validated resource token; supplies the session-snapshot
///   `hardware_aaguid`, `org_domain` (`hd`), and `dpop_source` federation claims
pub(crate) async fn issue_sso_jwt(
    issuer: &str,
    session_hours: u64,
    oidc_rsa_key: &OidcRsaSigningKey,
    user_email: &str,
    token: &ValidatedResourceToken,
) -> AwsResult<AwsTokenResult> {
    let expires_in = session_hours.saturating_mul(3600);

    // Reuse the same AWS session tags as the web-identity path for consistent
    // ABAC/CloudTrail attribution.
    let aws_tags = build_aws_session_tags(
        user_email,
        token.org_domain.as_deref(),
        token.dpop_source.as_deref(),
    );

    // aud = issuer, same as the STS token.
    let id_claims = OidcIdTokenClaimsBuilder::for_aws(issuer, user_email)
        .hardware_aaguid(token.hardware_aaguid.clone())
        .hd(token.org_domain.clone())
        .aws_tags(aws_tags)
        .valid_for_seconds(expires_in)
        .build()
        .map_err(|e| AwsError::ClaimsBuild(e.to_string()))?;

    // Sign with RS256 — required by the AWS IAM Identity Center trusted token
    // issuer contract.
    let id_token = oidc_rsa_key
        .sign_jwt(&id_claims)
        .await
        .map_err(|e| AwsError::TokenSign(e.to_string()))?;

    tracing::info!(
        "Issued AWS Identity Center JWT (RS256) for {}",
        redact_email(user_email)
    );

    Ok(AwsTokenResult {
        id_token,
        expires_in,
    })
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::services::oidc::{OidcRsaSigningKey, OidcSigningKey};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    /// Decode a JWT payload (middle part) into a `serde_json::Value` without
    /// signature verification. Used only in tests to inspect claims.
    fn decode_jwt_payload(token: &str) -> serde_json::Value {
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have exactly 3 parts");
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("Failed to base64url-decode JWT payload");
        serde_json::from_slice(&payload_bytes).expect("Failed to parse JWT payload as JSON")
    }

    /// Decode a JWT header (first part) into a `serde_json::Value`.
    fn decode_jwt_header(token: &str) -> serde_json::Value {
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have exactly 3 parts");
        let header_bytes = URL_SAFE_NO_PAD
            .decode(parts[0])
            .expect("Failed to base64url-decode JWT header");
        serde_json::from_slice(&header_bytes).expect("Failed to parse JWT header as JSON")
    }

    const BASE_URL: &str = "https://vouch.example.com";
    const SESSION_HOURS: u64 = 8;
    const USER_EMAIL: &str = "user@example.com";
    const TEST_AAGUID: &str = "ee882879-721c-4913-9775-3dfcce97072a";

    /// Build a `ValidatedResourceToken` carrying only the federation-snapshot
    /// fields the `issue_*` functions read (`hardware_aaguid`, `org_domain`,
    /// `dpop_source`). The remaining fields are placeholders; a hardware-verified
    /// session is assumed since these functions run only after that gate.
    fn test_token(
        hardware_aaguid: Option<String>,
        org_domain: Option<String>,
        dpop_source: Option<String>,
    ) -> super::ValidatedResourceToken {
        super::ValidatedResourceToken {
            sub: "user-id".to_string(),
            email: None,
            client_id: "test-client".to_string(),
            scope: None,
            authenticator_id: None,
            hardware_verified: true,
            auth_time: None,
            token_hash: String::new(),
            dpop_source,
            hardware_aaguid,
            org_domain,
        }
    }

    /// The Identity Center JWT must be signed with RS256 (AWS TTI requirement),
    /// unlike the ES256 `AssumeRoleWithWebIdentity` token.
    #[tokio::test]
    async fn test_sso_jwt_is_rs256_signed() {
        let rsa_key = OidcRsaSigningKey::generate().expect("Failed to generate RSA key");

        let result = issue_sso_jwt(
            BASE_URL,
            SESSION_HOURS,
            &rsa_key,
            USER_EMAIL,
            &test_token(Some(TEST_AAGUID.to_string()), None, None),
        )
        .await
        .expect("issue_sso_jwt should succeed");

        let header = decode_jwt_header(&result.id_token);
        assert_eq!(header["alg"], "RS256", "Identity Center JWT must use RS256");
    }

    /// The JWT carries `iss` = issuer, `aud` = issuer (server base URL), `sub` =
    /// the user email, and the same AWS session tags as the web-identity path.
    #[tokio::test]
    async fn test_sso_jwt_claims_and_tags() {
        let rsa_key = OidcRsaSigningKey::generate().expect("Failed to generate RSA key");

        let result = issue_sso_jwt(
            BASE_URL,
            SESSION_HOURS,
            &rsa_key,
            USER_EMAIL,
            &test_token(
                None,
                Some("example.com".to_string()),
                Some("claude-code".to_string()),
            ),
        )
        .await
        .expect("issue_sso_jwt should succeed");

        let claims = decode_jwt_payload(&result.id_token);
        assert_eq!(claims["iss"], BASE_URL, "iss must match the issuer URL");
        assert_eq!(claims["aud"], BASE_URL, "aud must be the issuer URL");
        assert_eq!(claims["sub"], USER_EMAIL, "sub must be the user email");

        let principal_tags = &claims["https://aws.amazon.com/tags"]["principal_tags"];
        assert_eq!(
            principal_tags["vouch:Email"],
            serde_json::json!([USER_EMAIL])
        );
        assert_eq!(
            principal_tags["vouch:Domain"],
            serde_json::json!(["example.com"])
        );
        assert_eq!(
            principal_tags["vouch:Agent"],
            serde_json::json!(["claude-code"])
        );
    }

    /// Default tags present: `vouch:Email` is always included; `vouch:AccessType`
    /// and `vouch:Agent` must NOT be present when `source` is `None`.
    #[tokio::test]
    async fn test_default_tags_present_without_source() {
        let key = OidcSigningKey::generate().expect("Failed to generate OIDC key");

        let result = issue_aws_token(
            BASE_URL,
            SESSION_HOURS,
            &key,
            USER_EMAIL,
            &test_token(Some(TEST_AAGUID.to_string()), None, None),
        )
        .await
        .expect("issue_aws_token should succeed");

        let claims = decode_jwt_payload(&result.id_token);
        let tags = &claims["https://aws.amazon.com/tags"];
        assert!(tags.is_object(), "aws tags claim must be present");

        let principal_tags = &tags["principal_tags"];
        assert_eq!(
            principal_tags["vouch:Email"],
            serde_json::json!([USER_EMAIL]),
            "vouch:Email tag must contain the user email"
        );
        assert!(
            principal_tags.get("vouch:AccessType").is_none(),
            "vouch:AccessType must not be present when source is None"
        );
        assert!(
            principal_tags.get("vouch:Agent").is_none(),
            "vouch:Agent must not be present when source is None"
        );
    }

    /// Domain tag: when `hd` is `Some`, `vouch:Domain` must be included.
    #[tokio::test]
    async fn test_domain_tag_included_when_hd_present() {
        let key = OidcSigningKey::generate().expect("Failed to generate OIDC key");

        let result = issue_aws_token(
            BASE_URL,
            SESSION_HOURS,
            &key,
            USER_EMAIL,
            &test_token(
                Some(TEST_AAGUID.to_string()),
                Some("example.com".to_string()),
                None,
            ),
        )
        .await
        .expect("issue_aws_token should succeed");

        let claims = decode_jwt_payload(&result.id_token);
        let tags = &claims["https://aws.amazon.com/tags"];
        let principal_tags = &tags["principal_tags"];

        assert_eq!(
            principal_tags["vouch:Domain"],
            serde_json::json!(["example.com"]),
            "vouch:Domain tag must contain the hosted domain"
        );
        assert_eq!(
            principal_tags["vouch:Email"],
            serde_json::json!([USER_EMAIL]),
            "vouch:Email must also be present alongside vouch:Domain"
        );
    }

    /// Agent tags added: when `source` is `Some`, both `vouch:AccessType=ai`
    /// and `vouch:Agent=<source>` must appear in `principal_tags`.
    #[tokio::test]
    async fn test_agent_tags_added_when_source_present() {
        let key = OidcSigningKey::generate().expect("Failed to generate OIDC key");

        let result = issue_aws_token(
            BASE_URL,
            SESSION_HOURS,
            &key,
            USER_EMAIL,
            &test_token(
                Some(TEST_AAGUID.to_string()),
                None,
                Some("claude-code".to_string()),
            ),
        )
        .await
        .expect("issue_aws_token should succeed");

        let claims = decode_jwt_payload(&result.id_token);
        let tags = &claims["https://aws.amazon.com/tags"];
        let principal_tags = &tags["principal_tags"];

        assert_eq!(
            principal_tags["vouch:AccessType"],
            serde_json::json!(["ai"]),
            "vouch:AccessType must be 'ai' when source is present"
        );
        assert_eq!(
            principal_tags["vouch:Agent"],
            serde_json::json!(["claude-code"]),
            "vouch:Agent must contain the source identifier"
        );
        assert_eq!(
            principal_tags["vouch:Email"],
            serde_json::json!([USER_EMAIL]),
            "vouch:Email must still be present alongside agent tags"
        );
    }

    /// Agent tags absent without source: when `source` is `None`, neither
    /// `vouch:AccessType` nor `vouch:Agent` may appear.
    #[tokio::test]
    async fn test_agent_tags_absent_without_source() {
        let key = OidcSigningKey::generate().expect("Failed to generate OIDC key");

        let result = issue_aws_token(
            BASE_URL,
            SESSION_HOURS,
            &key,
            USER_EMAIL,
            &test_token(
                Some(TEST_AAGUID.to_string()),
                Some("example.com".to_string()),
                None,
            ),
        )
        .await
        .expect("issue_aws_token should succeed");

        let claims = decode_jwt_payload(&result.id_token);
        let tags = &claims["https://aws.amazon.com/tags"];
        let principal_tags = &tags["principal_tags"];

        assert!(
            principal_tags.get("vouch:AccessType").is_none(),
            "vouch:AccessType must be absent when source is None (even with hd present)"
        );
        assert!(
            principal_tags.get("vouch:Agent").is_none(),
            "vouch:Agent must be absent when source is None"
        );
    }

    /// All tags are transitive: `transitive_tag_keys` must include every key
    /// present in `principal_tags`.
    #[tokio::test]
    async fn test_all_tags_are_transitive() {
        let key = OidcSigningKey::generate().expect("Failed to generate OIDC key");

        let result = issue_aws_token(
            BASE_URL,
            SESSION_HOURS,
            &key,
            USER_EMAIL,
            &test_token(
                Some(TEST_AAGUID.to_string()),
                Some("example.com".to_string()),
                Some("cursor".to_string()),
            ),
        )
        .await
        .expect("issue_aws_token should succeed");

        let claims = decode_jwt_payload(&result.id_token);
        let tags = &claims["https://aws.amazon.com/tags"];
        let principal_tags = &tags["principal_tags"];
        let transitive_keys: Vec<&str> = tags["transitive_tag_keys"]
            .as_array()
            .expect("transitive_tag_keys must be an array")
            .iter()
            .map(|v| v.as_str().expect("key must be a string"))
            .collect();

        let tag_keys: Vec<&str> = principal_tags
            .as_object()
            .expect("principal_tags must be an object")
            .keys()
            .map(String::as_str)
            .collect();

        for key_name in &tag_keys {
            assert!(
                transitive_keys.contains(key_name),
                "tag key '{key_name}' must appear in transitive_tag_keys"
            );
        }

        // Verify the specific expected keys are all transitive
        for expected in &[
            "vouch:Email",
            "vouch:Domain",
            "vouch:AccessType",
            "vouch:Agent",
        ] {
            assert!(
                transitive_keys.contains(expected),
                "'{expected}' must be in transitive_tag_keys"
            );
        }
    }

    /// A per-org issuer subdomain flows through to both `iss` and `aud`.
    #[tokio::test]
    async fn test_org_issuer_sets_iss_and_aud() {
        let key = OidcSigningKey::generate().expect("Failed to generate OIDC key");
        let org_issuer = "https://acme.us.vouch.sh";

        let result = issue_aws_token(
            org_issuer,
            SESSION_HOURS,
            &key,
            USER_EMAIL,
            &test_token(Some(TEST_AAGUID.to_string()), None, None),
        )
        .await
        .expect("issue_aws_token should succeed");

        let claims = decode_jwt_payload(&result.id_token);
        assert_eq!(claims["iss"], org_issuer, "iss must be the org issuer");
        assert_eq!(claims["aud"], org_issuer, "aud must equal the org issuer");
    }

    /// `expires_in` matches `session_hours * 3600`.
    #[tokio::test]
    async fn test_expires_in_matches_session_hours() {
        let key = OidcSigningKey::generate().expect("Failed to generate OIDC key");

        let result = issue_aws_token(
            BASE_URL,
            4, // 4 hours
            &key,
            USER_EMAIL,
            &test_token(Some(TEST_AAGUID.to_string()), None, None),
        )
        .await
        .expect("issue_aws_token should succeed");

        assert_eq!(
            result.expires_in,
            4 * 3600,
            "expires_in must be session_hours * 3600"
        );
    }

    /// AAGUID claim is present in the issued token when supplied.
    #[tokio::test]
    async fn test_hardware_aaguid_claim_is_emitted() {
        let key = OidcSigningKey::generate().expect("Failed to generate OIDC key");

        let result = issue_aws_token(
            BASE_URL,
            SESSION_HOURS,
            &key,
            USER_EMAIL,
            &test_token(Some(TEST_AAGUID.to_string()), None, None),
        )
        .await
        .expect("issue_aws_token should succeed");

        let claims = decode_jwt_payload(&result.id_token);
        assert_eq!(
            claims["hardware_aaguid"], TEST_AAGUID,
            "hardware_aaguid claim must reflect the supplied snapshot"
        );
    }
}
