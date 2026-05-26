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
//! The AWS IAM role must be configured to trust the Vouch OIDC provider:
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

use crate::db::{self, Authenticator, store::DocumentStore};
use crate::redact_email;
use crate::services::oidc::{AwsSessionTags, OidcIdTokenClaimsBuilder, OidcSigningKey};

/// Error types for AWS integration operations.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AwsError {
    /// User session does not have an associated authenticator.
    #[error("Session does not have a security key - please register one first")]
    NoAuthenticator,

    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] anyhow::Error),

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
/// * `db` - Database pool
/// * `base_url` - Server base URL (issuer)
/// * `session_hours` - Session duration in hours
/// * `oidc_key` - OIDC signing key
/// * `user_email` - The authenticated user's email
/// * `authenticator_id` - The authenticator ID from the session (for AAGUID lookup)
/// * `hd` - The user's organization domain (Google Workspace hosted domain)
/// * `source` - AI coding agent identifier (e.g., "claude-code", "cursor")
#[expect(
    clippy::too_many_arguments,
    reason = "AWS STS AssumeRoleWithWebIdentity issuance requires full session context"
)]
pub(crate) async fn issue_aws_token(
    store: &DocumentStore,
    base_url: &str,
    session_hours: u64,
    oidc_key: &OidcSigningKey,
    user_email: &str,
    authenticator_id: Option<&str>,
    hd: Option<String>,
    source: Option<&str>,
) -> AwsResult<AwsTokenResult> {
    // Get authenticator info for AAGUID
    let authenticator = get_authenticator(store, authenticator_id).await?;

    // Token validity matches session duration
    let expires_in = session_hours.saturating_mul(3600);

    // Build AWS session tags for ABAC and CloudTrail attribution.
    // Tags are embedded in the JWT so AWS extracts them during
    // AssumeRoleWithWebIdentity and logs them as principalTags in CloudTrail.
    let mut principal_tags = std::collections::HashMap::new();
    let mut transitive_tag_keys = Vec::new();

    principal_tags.insert("vouch:Email".to_string(), vec![user_email.to_string()]);
    transitive_tag_keys.push("vouch:Email".to_string());

    if let Some(ref domain) = hd {
        principal_tags.insert("vouch:Domain".to_string(), vec![domain.clone()]);
        transitive_tag_keys.push("vouch:Domain".to_string());
    }

    // Add AI-specific tags when a coding agent is detected.
    // The `source` claim is set by the CLI via env-var sniffing (CLAUDECODE,
    // CURSOR_AGENT, etc.) and carried tamperproof in the DPoP proof JWT.
    // These tags enable IAM condition keys (aws:PrincipalTag/vouch:access-type)
    // and CloudTrail filtering for agent-initiated API calls.
    if let Some(agent) = source {
        principal_tags.insert("vouch:AccessType".to_string(), vec!["ai".to_string()]);
        transitive_tag_keys.push("vouch:AccessType".to_string());
        principal_tags.insert("vouch:Agent".to_string(), vec![agent.to_string()]);
        transitive_tag_keys.push("vouch:Agent".to_string());
    }

    let aws_tags = AwsSessionTags {
        principal_tags,
        transitive_tag_keys,
    };

    // Build OIDC claims
    // For AWS, the audience is the issuer URL (AWS matches against the OIDC provider)
    let id_claims = OidcIdTokenClaimsBuilder::for_aws(base_url, user_email)
        .hardware_aaguid(authenticator.and_then(|a| a.aaguid))
        .hd(hd)
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

/// Get authenticator info for AAGUID lookup.
async fn get_authenticator(
    store: &DocumentStore,
    authenticator_id: Option<&str>,
) -> AwsResult<Option<Authenticator>> {
    let Some(id) = authenticator_id else {
        return Err(AwsError::NoAuthenticator);
    };

    db::get_authenticator_by_id(store, id)
        .await
        .map_err(AwsError::Database)
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::crypto::document_crypto::PlaintextDocumentCrypto;
    use crate::db::{Pool, pool::PoolConfig, store::DocumentStore};
    use crate::services::oidc::OidcSigningKey;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use std::sync::Arc;

    /// Create an in-memory SQLite store with migrations for testing.
    async fn test_store() -> DocumentStore {
        let pool = Pool::connect("sqlite::memory:", &PoolConfig::default())
            .await
            .expect("Failed to create test database");

        match &pool {
            Pool::Sqlite(p) => sqlx::migrate!("./migrations/sqlite")
                .run(p)
                .await
                .expect("Failed to run migrations"),
            Pool::Postgres(p) => sqlx::migrate!("./migrations/postgres")
                .run(p)
                .await
                .expect("Failed to run migrations"),
        }

        let crypto: Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
            Arc::new(PlaintextDocumentCrypto);
        DocumentStore::new(pool, crypto)
    }

    /// Create a user and authenticator in the store, returning the authenticator ID.
    async fn create_test_user_and_authenticator(store: &DocumentStore, email: &str) -> String {
        let (user_id, _) = db::upsert_user(store, email, None)
            .await
            .expect("Failed to create test user");

        db::create_authenticator(
            store,
            &user_id,
            email,
            "Test Key",
            b"test-credential-id",
            &[0u8; 32],
            None,
            Some(user_id.as_bytes()),
            false,
        )
        .await
        .expect("Failed to create test authenticator")
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

    // ── test helpers ──────────────────────────────────────────────────────────

    const BASE_URL: &str = "https://vouch.example.com";
    const SESSION_HOURS: u64 = 8;
    const USER_EMAIL: &str = "user@example.com";

    // ── tests ─────────────────────────────────────────────────────────────────

    /// Default tags present: `vouch:Email` is always included; `vouch:AccessType`
    /// and `vouch:Agent` must NOT be present when `source` is `None`.
    #[tokio::test]
    async fn test_default_tags_present_without_source() {
        let store = test_store().await;
        let auth_id = create_test_user_and_authenticator(&store, USER_EMAIL).await;
        let key = OidcSigningKey::generate().expect("Failed to generate OIDC key");

        let result = issue_aws_token(
            &store,
            BASE_URL,
            SESSION_HOURS,
            &key,
            USER_EMAIL,
            Some(&auth_id),
            None,
            None, // no source
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
        let store = test_store().await;
        let auth_id = create_test_user_and_authenticator(&store, USER_EMAIL).await;
        let key = OidcSigningKey::generate().expect("Failed to generate OIDC key");

        let result = issue_aws_token(
            &store,
            BASE_URL,
            SESSION_HOURS,
            &key,
            USER_EMAIL,
            Some(&auth_id),
            Some("example.com".to_string()),
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
        let store = test_store().await;
        let auth_id = create_test_user_and_authenticator(&store, USER_EMAIL).await;
        let key = OidcSigningKey::generate().expect("Failed to generate OIDC key");

        let result = issue_aws_token(
            &store,
            BASE_URL,
            SESSION_HOURS,
            &key,
            USER_EMAIL,
            Some(&auth_id),
            None,
            Some("claude-code"),
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
        let store = test_store().await;
        let auth_id = create_test_user_and_authenticator(&store, USER_EMAIL).await;
        let key = OidcSigningKey::generate().expect("Failed to generate OIDC key");

        let result = issue_aws_token(
            &store,
            BASE_URL,
            SESSION_HOURS,
            &key,
            USER_EMAIL,
            Some(&auth_id),
            Some("example.com".to_string()), // hd present, but no source
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
        let store = test_store().await;
        let auth_id = create_test_user_and_authenticator(&store, USER_EMAIL).await;
        let key = OidcSigningKey::generate().expect("Failed to generate OIDC key");

        let result = issue_aws_token(
            &store,
            BASE_URL,
            SESSION_HOURS,
            &key,
            USER_EMAIL,
            Some(&auth_id),
            Some("example.com".to_string()),
            Some("cursor"),
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

    /// No-authenticator error: passing `authenticator_id = None` returns
    /// `AwsError::NoAuthenticator` without touching the database.
    #[tokio::test]
    async fn test_no_authenticator_returns_error() {
        let store = test_store().await;
        let key = OidcSigningKey::generate().expect("Failed to generate OIDC key");

        let result = issue_aws_token(
            &store,
            BASE_URL,
            SESSION_HOURS,
            &key,
            USER_EMAIL,
            None, // no authenticator
            None,
            None,
        )
        .await;

        assert!(
            matches!(result, Err(AwsError::NoAuthenticator)),
            "expected NoAuthenticator error when authenticator_id is None, got: {result:?}"
        );
    }

    /// `expires_in` matches `session_hours * 3600`.
    #[tokio::test]
    async fn test_expires_in_matches_session_hours() {
        let store = test_store().await;
        let auth_id = create_test_user_and_authenticator(&store, USER_EMAIL).await;
        let key = OidcSigningKey::generate().expect("Failed to generate OIDC key");

        let result = issue_aws_token(
            &store,
            BASE_URL,
            4, // 4 hours
            &key,
            USER_EMAIL,
            Some(&auth_id),
            None,
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
}
