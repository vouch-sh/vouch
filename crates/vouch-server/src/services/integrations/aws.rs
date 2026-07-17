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
//! When the organization has claimed an issuer subdomain (e.g. `acme-com` →
//! `https://acme-com.us.vouch.sh`, derived from its verified `acme.com`), that
//! issuer host has its **own** signing keys, served only at its own JWKS. A
//! token minted for another org is signed with a different key and will not
//! verify against this issuer, so the provider ARN alone scopes trust — no
//! `Condition` block is needed:
//!
//! ```json
//! {
//!   "Version": "2012-10-17",
//!   "Statement": [{
//!     "Effect": "Allow",
//!     "Principal": {"Federated": "arn:aws:iam::ACCOUNT:oidc-provider/acme-com.us.vouch.sh"},
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
//!
//! # Requiring role pinning
//!
//! The CLI requests tokens pinned to the role it is about to assume
//! (`?role_arn=` on `/v1/credentials/aws/token`), which Vouch embeds as the
//! `https://aws.amazon.com/roles` claim, so a leaked token cannot be
//! exchanged for a role it was not minted for.
//!
//! The [AWS Service Authorization Reference for STS] defines the Bool
//! condition key `sts:RoleAuthorizedByIdp` on `AssumeRoleWithWebIdentity`
//! (and only that action): "Filters access based on whether the identity
//! provider authorized the role via the roles claim in the OIDC token".
//! A web-identity trust statement can use it to require a pinned token:
//!
//! ```json
//! "Condition": {
//!   "Bool": {"sts:RoleAuthorizedByIdp": "true"}
//! }
//! ```
//!
//! The claim's matching behavior — exact role ARN, string or array value,
//! no wildcards or bare role names, rejection with `InvalidIdentityToken`
//! when the target role is absent — is not yet described in the
//! `AssumeRoleWithWebIdentity` API reference; it is based on third-party
//! testing ([awsteele.com, 2026-07-13]).
//!
//! Caveats before requiring the condition key:
//!
//! - **Older CLIs do not request pinning.** Their tokens carry no roles
//!   claim and fail the condition; roll the CLI out first.
//! - **Only use it on web-identity trust statements.** The key is defined
//!   for `AssumeRoleWithWebIdentity` only; a role assumed by SigV4
//!   `sts:AssumeRole` (e.g. the second hop of a management-role chain) has
//!   no OIDC token in the request, so a Bool-`true` condition there can
//!   never match.
//!
//! The Identity Center path (`vouch credential aws --account/--permission-set`,
//! `vouch setup aws --discover`) pins its token to the management role — the
//! role its `AssumeRoleWithWebIdentity` hop assumes — so IdC management roles
//! can require the condition key like any other web-identity role. The same
//! token doubles as the `jwt-bearer` assertion for
//! `sso-oidc:CreateTokenWithIAM`; AWS does not document how that operation
//! treats the roles claim, but it already accepts this token carrying the
//! other AWS-namespaced claims it does not consume (`tags`,
//! `source_identity`) — observed behavior, not a documented contract.
//!
//! [AWS Service Authorization Reference for STS]: https://docs.aws.amazon.com/service-authorization/latest/reference/list_sts.html
//! [awsteele.com, 2026-07-13]: https://awsteele.com/blog/2026/07/13/oidc-tokens-can-restrict-which-aws-roles-they-assume.html

use crate::crypto::keys::OidcRsaSigningKey;
use crate::redact_email;
use crate::services::auth::ValidatedResourceToken;
use crate::services::oidc::{AwsSessionTags, OidcIdTokenClaimsBuilder};

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
pub(crate) struct AwsTokenResult {
    /// The signed OIDC ID token.
    pub id_token: String,
    /// Token validity in seconds.
    pub expires_in: u64,
}

// Custom Debug that redacts id_token to prevent accidental log exposure.
impl std::fmt::Debug for AwsTokenResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsTokenResult")
            .field("id_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .finish()
    }
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

/// Issue an OIDC ID token for AWS.
///
/// The token serves two AWS consumers: STS `AssumeRoleWithWebIdentity` (for
/// temporary credentials) and IAM Identity Center `sso-oidc:CreateTokenWithIAM`
/// (as the `jwt-bearer` assertion for trusted identity propagation). It is
/// signed with **RS256** because the Identity Center trusted-token-issuer
/// contract rejects ES256, while STS accepts both. The token's `iss` matches
/// the Vouch OIDC discovery document and its public key is published in the
/// JWKS, so both consumers can verify the signature. The token includes:
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
/// * `oidc_rsa_key` - OIDC RSA (RS256) signing key
/// * `user_email` - The authenticated user's email (resolved with a DB fallback,
///   so it is passed explicitly rather than read from the token)
/// * `token` - The validated resource token; supplies the session-snapshot
///   `hardware_aaguid`, `org_domain` (`hd`), and `dpop_source` federation claims
/// * `pinned_role` - Role ARN to pin the token to via the
///   `https://aws.amazon.com/roles` claim; `None` omits the claim (STS then
///   accepts the token for any role trusting this issuer)
pub(crate) async fn issue_aws_token(
    issuer: &str,
    session_hours: u64,
    oidc_rsa_key: &OidcRsaSigningKey,
    user_email: &str,
    token: &ValidatedResourceToken,
    pinned_role: Option<&str>,
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
        .aws_role(pinned_role)
        .valid_for_seconds(expires_in)
        .build()
        .map_err(|e| AwsError::ClaimsBuild(e.to_string()))?;

    // Sign with RS256 — required by the AWS IAM Identity Center trusted token
    // issuer contract; STS accepts it for AssumeRoleWithWebIdentity as well.
    let id_token = oidc_rsa_key
        .sign_jwt(&id_claims)
        .await
        .map_err(|e| AwsError::TokenSign(e.to_string()))?;

    match pinned_role {
        Some(role) => tracing::info!(
            pinned_role_arn = %role,
            "Issued AWS OIDC token for {} pinned to role",
            redact_email(user_email)
        ),
        None => tracing::info!("Issued AWS OIDC token for {}", redact_email(user_email)),
    }

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
    use crate::crypto::keys::OidcRsaSigningKey;

    /// The signed OIDC ID token is a bearer credential for AWS STS and
    /// must never appear in `{:?}` output.
    #[test]
    fn test_aws_token_result_debug_redacts_id_token() {
        let result = AwsTokenResult {
            id_token: "eyJhbGciOiJSUzI1NiJ9.secret-token".to_string(),
            expires_in: 28_800,
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("[REDACTED]"), "{debug}");
        assert!(!debug.contains("secret-token"), "{debug}");
    }
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    /// Shared RSA-3072 signing key — generated once because RSA key
    /// generation is slow enough to dominate per-test runtime.
    fn test_rsa_key() -> &'static OidcRsaSigningKey {
        static KEY: std::sync::OnceLock<OidcRsaSigningKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| OidcRsaSigningKey::generate().expect("Failed to generate RSA key"))
    }

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
            aud: "test-client".to_string(),
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

    /// The AWS token must be signed with RS256: the IAM Identity Center
    /// trusted-token-issuer contract rejects ES256, and STS accepts RS256
    /// for `AssumeRoleWithWebIdentity`.
    #[tokio::test]
    async fn test_aws_token_is_rs256_signed() {
        let result = issue_aws_token(
            BASE_URL,
            SESSION_HOURS,
            test_rsa_key(),
            USER_EMAIL,
            &test_token(Some(TEST_AAGUID.to_string()), None, None),
            None,
        )
        .await
        .expect("issue_aws_token should succeed");

        let header = decode_jwt_header(&result.id_token);
        assert_eq!(header["alg"], "RS256", "AWS token must use RS256");

        let claims = decode_jwt_payload(&result.id_token);
        assert_eq!(claims["iss"], BASE_URL, "iss must match the issuer URL");
        assert_eq!(claims["aud"], BASE_URL, "aud must be the issuer URL");
        assert_eq!(claims["sub"], USER_EMAIL, "sub must be the user email");
    }

    /// Default tags present: `vouch:Email` is always included; `vouch:AccessType`
    /// and `vouch:Agent` must NOT be present when `source` is `None`.
    #[tokio::test]
    async fn test_default_tags_present_without_source() {
        let result = issue_aws_token(
            BASE_URL,
            SESSION_HOURS,
            test_rsa_key(),
            USER_EMAIL,
            &test_token(Some(TEST_AAGUID.to_string()), None, None),
            None,
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
        let result = issue_aws_token(
            BASE_URL,
            SESSION_HOURS,
            test_rsa_key(),
            USER_EMAIL,
            &test_token(
                Some(TEST_AAGUID.to_string()),
                Some("example.com".to_string()),
                None,
            ),
            None,
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
        let result = issue_aws_token(
            BASE_URL,
            SESSION_HOURS,
            test_rsa_key(),
            USER_EMAIL,
            &test_token(
                Some(TEST_AAGUID.to_string()),
                None,
                Some("claude-code".to_string()),
            ),
            None,
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
        let result = issue_aws_token(
            BASE_URL,
            SESSION_HOURS,
            test_rsa_key(),
            USER_EMAIL,
            &test_token(
                Some(TEST_AAGUID.to_string()),
                Some("example.com".to_string()),
                None,
            ),
            None,
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
        let result = issue_aws_token(
            BASE_URL,
            SESSION_HOURS,
            test_rsa_key(),
            USER_EMAIL,
            &test_token(
                Some(TEST_AAGUID.to_string()),
                Some("example.com".to_string()),
                Some("cursor".to_string()),
            ),
            None,
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
        let org_issuer = "https://acme.us.vouch.sh";

        let result = issue_aws_token(
            org_issuer,
            SESSION_HOURS,
            test_rsa_key(),
            USER_EMAIL,
            &test_token(Some(TEST_AAGUID.to_string()), None, None),
            None,
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
        let result = issue_aws_token(
            BASE_URL,
            4, // 4 hours
            test_rsa_key(),
            USER_EMAIL,
            &test_token(Some(TEST_AAGUID.to_string()), None, None),
            None,
        )
        .await
        .expect("issue_aws_token should succeed");

        assert_eq!(
            result.expires_in,
            4 * 3600,
            "expires_in must be session_hours * 3600"
        );
    }

    /// A requested pin appears as a single-element array in the
    /// `https://aws.amazon.com/roles` claim.
    #[tokio::test]
    async fn test_pinned_role_emitted_in_roles_claim() {
        let role = "arn:aws:iam::123456789012:role/ExampleRole";
        let result = issue_aws_token(
            BASE_URL,
            SESSION_HOURS,
            test_rsa_key(),
            USER_EMAIL,
            &test_token(Some(TEST_AAGUID.to_string()), None, None),
            Some(role),
        )
        .await
        .expect("issue_aws_token should succeed");

        let claims = decode_jwt_payload(&result.id_token);
        assert_eq!(
            claims["https://aws.amazon.com/roles"],
            serde_json::json!([role]),
            "roles claim must be a single-element array with the pinned ARN"
        );
    }

    /// Without a requested pin the roles claim is absent, preserving the
    /// pre-pinning token shape for older CLIs.
    #[tokio::test]
    async fn test_roles_claim_absent_without_pin() {
        let result = issue_aws_token(
            BASE_URL,
            SESSION_HOURS,
            test_rsa_key(),
            USER_EMAIL,
            &test_token(Some(TEST_AAGUID.to_string()), None, None),
            None,
        )
        .await
        .expect("issue_aws_token should succeed");

        let claims = decode_jwt_payload(&result.id_token);
        assert!(
            claims.get("https://aws.amazon.com/roles").is_none(),
            "roles claim must be absent when no pin is requested"
        );
    }

    /// AAGUID claim is present in the issued token when supplied.
    #[tokio::test]
    async fn test_hardware_aaguid_claim_is_emitted() {
        let result = issue_aws_token(
            BASE_URL,
            SESSION_HOURS,
            test_rsa_key(),
            USER_EMAIL,
            &test_token(Some(TEST_AAGUID.to_string()), None, None),
            None,
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
