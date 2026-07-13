// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OIDC token claims for cloud provider identity federation.

use serde::{Deserialize, Serialize};

/// Confirmation claim for sender-constrained token binding.
///
/// Used in access tokens to bind them to a client's cryptographic key:
/// - `jkt`: JWK thumbprint for DPoP (RFC 9449 Section 6)
/// - `x5t#S256`: Certificate thumbprint for mTLS (RFC 8705 Section 3.1)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnfClaim {
    /// JWK thumbprint of the sender's key (DPoP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
    /// Certificate thumbprint (mTLS).
    #[serde(default, rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
}

/// Standard OIDC ID token claims with Vouch extensions.
/// Used by credential endpoints (AWS, Kubernetes).
#[derive(Debug, Serialize)]
pub struct OidcIdTokenClaims {
    /// Issuer (Vouch server URL).
    pub iss: String,
    /// Subject (user email).
    pub sub: String,
    /// Audience (varies by provider).
    pub aud: String,
    /// Expiration time (Unix timestamp).
    pub exp: i64,
    /// Issued at time (Unix timestamp).
    pub iat: i64,
    /// JWT ID (unique identifier for replay prevention, required by AWS IAM
    /// Identity Center Trusted Token Issuer).
    pub jti: String,
    /// User's email address.
    pub email: String,
    /// Email verified flag.
    pub email_verified: bool,
    /// Hardware verification flag (always true for Vouch).
    pub hardware_verified: bool,
    /// Hardware AAGUID (YubiKey model identifier).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_aaguid: Option<String>,
    /// Google Workspace hosted domain (e.g., "acme.com").
    /// Only present for users from Google Workspace organizations.
    /// Can be used in AWS IAM trust policy conditions to restrict access by domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hd: Option<String>,
    /// AWS STS source identity for role chaining audit trails.
    ///
    /// When present in the OIDC token, AWS STS extracts this as the
    /// `SourceIdentity` during `AssumeRoleWithWebIdentity`. The value
    /// persists immutably through role chains and appears in CloudTrail,
    /// enabling end-to-end user attribution across chained role
    /// assumptions.
    ///
    /// Uses the AWS-defined claim namespace per:
    /// <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html#id_credentials_temp_control-access_monitor-assume-role-web-id>
    ///
    /// Only set for AWS tokens (via `for_aws()`), not Kubernetes or
    /// other providers. This is a provider-defined claim permitted by
    /// OIDC Core Section 5.1.2 (additional claims using
    /// collision-resistant names).
    #[serde(
        rename = "https://aws.amazon.com/source_identity",
        skip_serializing_if = "Option::is_none"
    )]
    pub source_identity: Option<String>,
    /// AWS session tags for ABAC and CloudTrail attribution.
    ///
    /// Uses the nested claim format per:
    /// <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html>
    ///
    /// Tags passed via JWT claims appear as `principalTags` in CloudTrail
    /// `requestParameters`. Tags passed via STS API parameters do NOT
    /// appear in CloudTrail for `AssumeRoleWithWebIdentity`.
    ///
    /// **Important:** Tags must be in either the JWT OR the STS API call,
    /// never both — AWS rejects requests that include both.
    #[serde(
        rename = "https://aws.amazon.com/tags",
        skip_serializing_if = "Option::is_none"
    )]
    pub aws_tags: Option<AwsSessionTags>,
    /// AWS role ARNs this token is authorized to assume (role pinning).
    ///
    /// When present, AWS STS rejects `AssumeRoleWithWebIdentity` for any
    /// role whose ARN is not an exact match of an entry in this claim —
    /// enforcement happens at the STS layer, before the role's trust
    /// policy is evaluated. Trust policies can additionally require the
    /// claim with the `sts:RoleAuthorizedByIdp` condition key.
    ///
    /// Serialized as an array of ARN strings (STS accepts a bare string
    /// too, but the array form is forward-compatible with pinning more
    /// than one role). Exact-match only — no wildcards or role names.
    ///
    /// Only set for AWS STS tokens when the client requests pinning;
    /// never set for Kubernetes/WIF tokens or the Identity Center path
    /// (`CreateTokenWithIAM` does not define semantics for this claim).
    #[serde(
        rename = "https://aws.amazon.com/roles",
        skip_serializing_if = "Option::is_none"
    )]
    pub aws_roles: Option<Vec<String>>,
}

/// AWS session tags claim structure (nested format).
///
/// Per the AWS docs, tag values are arrays of strings and transitive
/// tag keys is an array of key names.
#[derive(Debug, Clone, Serialize)]
pub struct AwsSessionTags {
    /// Tag key-value pairs. Values are single-element arrays per AWS spec.
    pub principal_tags: std::collections::HashMap<String, Vec<String>>,
    /// Tag keys that propagate through role chains.
    pub transitive_tag_keys: Vec<String>,
}

/// Errors from building OIDC ID token claims.
#[derive(Debug, thiserror::Error)]
pub enum ClaimsBuildError {
    /// A required field was not set.
    #[error("Missing required claim: {0}")]
    MissingField(&'static str),
}

/// Builder for constructing OIDC ID token claims.
pub struct OidcIdTokenClaimsBuilder {
    issuer: Option<String>,
    subject: Option<String>,
    audience: Option<String>,
    email: Option<String>,
    hardware_aaguid: Option<String>,
    hd: Option<String>,
    source_identity: Option<String>,
    aws_tags: Option<AwsSessionTags>,
    aws_roles: Option<Vec<String>>,
    valid_for_seconds: u64,
}

impl OidcIdTokenClaimsBuilder {
    /// Create a new builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self {
            issuer: None,
            subject: None,
            audience: None,
            email: None,
            hardware_aaguid: None,
            hd: None,
            source_identity: None,
            aws_tags: None,
            aws_roles: None,
            valid_for_seconds: 28800, // 8 hours default
        }
    }

    /// Create a builder pre-configured for AWS.
    ///
    /// AWS uses the issuer URL as the audience (AWS matches against the OIDC provider).
    /// The subject and email are both set to the user's email.
    /// Includes `https://aws.amazon.com/source_identity` claim set to the
    /// user's email for role chaining audit trails.
    #[must_use]
    pub fn for_aws(issuer: &str, email: &str) -> Self {
        Self::new()
            .issuer(issuer)
            .subject(email)
            .audience(issuer) // AWS uses issuer as audience
            .email(email)
            .source_identity(email)
    }

    /// Create a builder pre-configured for an external relying party that
    /// validates a specific `aud` claim.
    ///
    /// Generic shape: `iss = issuer`, `sub = email`, `aud = audience`,
    /// `email = email`. Used by every non-AWS issuance path — Kubernetes
    /// (audience = `--oidc-client-id` on the API server) and Workload
    /// Identity Federation with Claude/OpenAI (audience = the value the
    /// relying party expects).
    #[must_use]
    pub fn for_audience(issuer: &str, email: &str, audience: &str) -> Self {
        Self::new()
            .issuer(issuer)
            .subject(email)
            .audience(audience)
            .email(email)
    }

    /// Set the token issuer (Vouch server URL).
    #[must_use]
    pub fn issuer(mut self, issuer: &str) -> Self {
        self.issuer = Some(issuer.to_string());
        self
    }

    /// Set the token subject (user identifier, typically email).
    #[must_use]
    pub fn subject(mut self, subject: &str) -> Self {
        self.subject = Some(subject.to_string());
        self
    }

    /// Set the token audience (cloud provider specific).
    #[must_use]
    pub fn audience(mut self, audience: &str) -> Self {
        self.audience = Some(audience.to_string());
        self
    }

    /// Set the user's email address.
    #[must_use]
    pub fn email(mut self, email: &str) -> Self {
        self.email = Some(email.to_string());
        self
    }

    /// Set the hardware AAGUID (authenticator model identifier).
    #[must_use]
    pub fn hardware_aaguid(mut self, aaguid: Option<String>) -> Self {
        self.hardware_aaguid = aaguid;
        self
    }

    /// Set the Google Workspace hosted domain (e.g., "acme.com").
    ///
    /// This is the `hd` claim from Google's OIDC tokens, indicating the user's
    /// Google Workspace domain. Can be used in AWS IAM trust policy conditions
    /// to restrict access to users from specific domains.
    #[must_use]
    pub fn hd(mut self, hd: Option<String>) -> Self {
        self.hd = hd;
        self
    }

    /// Set the AWS STS source identity for role chaining.
    ///
    /// Only relevant for AWS tokens. The value appears in CloudTrail
    /// and persists immutably through role chains.
    #[must_use]
    pub fn source_identity(mut self, identity: &str) -> Self {
        self.source_identity = Some(identity.to_string());
        self
    }

    /// Set AWS session tags for ABAC and CloudTrail attribution.
    ///
    /// Tags are embedded in the JWT using the nested `https://aws.amazon.com/tags`
    /// claim format. AWS extracts them during `AssumeRoleWithWebIdentity` and
    /// logs them as `principalTags` in CloudTrail.
    #[must_use]
    pub fn aws_tags(mut self, tags: AwsSessionTags) -> Self {
        self.aws_tags = Some(tags);
        self
    }

    /// Pin the token to a single AWS role ARN (`https://aws.amazon.com/roles`).
    ///
    /// When set, AWS STS rejects `AssumeRoleWithWebIdentity` for any other
    /// role, so a leaked token cannot be exchanged outside the intended role.
    /// Takes an `Option` (mirroring [`hd`](Self::hd)) so callers can chain it
    /// unconditionally; `None` leaves the claim absent.
    #[must_use]
    pub fn aws_role(mut self, role_arn: Option<&str>) -> Self {
        self.aws_roles = role_arn.map(|arn| vec![arn.to_string()]);
        self
    }

    /// Set the token validity period in seconds.
    #[must_use]
    pub fn valid_for_seconds(mut self, seconds: u64) -> Self {
        self.valid_for_seconds = seconds;
        self
    }

    /// Build the OIDC ID token claims.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields (issuer, subject, audience) are missing.
    pub fn build(self) -> Result<OidcIdTokenClaims, ClaimsBuildError> {
        let now = jiff::Timestamp::now();
        let exp = now
            .as_second()
            .saturating_add(i64::try_from(self.valid_for_seconds).unwrap_or(28800));

        Ok(OidcIdTokenClaims {
            iss: self
                .issuer
                .ok_or(ClaimsBuildError::MissingField("issuer"))?,
            sub: self
                .subject
                .clone()
                .ok_or(ClaimsBuildError::MissingField("subject"))?,
            aud: self
                .audience
                .ok_or(ClaimsBuildError::MissingField("audience"))?,
            exp,
            iat: now.as_second(),
            jti: uuid::Uuid::now_v7().to_string(),
            email: self
                .email
                .or(self.subject)
                .ok_or(ClaimsBuildError::MissingField("email"))?,
            email_verified: true,
            hardware_verified: true,
            hardware_aaguid: self.hardware_aaguid,
            hd: self.hd,
            source_identity: self.source_identity,
            aws_tags: self.aws_tags,
            aws_roles: self.aws_roles,
        })
    }
}

impl Default for OidcIdTokenClaimsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_creates_valid_claims() {
        let result = OidcIdTokenClaimsBuilder::new()
            .issuer("https://vouch.example.com")
            .subject("user@example.com")
            .audience("https://vouch.example.com")
            .email("user@example.com")
            .hardware_aaguid(Some("ee882879-721c-4913-9775-3dfcce97072a".to_string()))
            .valid_for_seconds(3600)
            .build();

        assert!(result.is_ok());
        if let Ok(claims) = result {
            assert_eq!(claims.iss, "https://vouch.example.com");
            assert_eq!(claims.sub, "user@example.com");
            assert_eq!(claims.aud, "https://vouch.example.com");
            assert_eq!(claims.email, "user@example.com");
            assert!(claims.email_verified);
            assert!(claims.hardware_verified);
            assert!(claims.hardware_aaguid.is_some());
            assert!(!claims.jti.is_empty());
            // Verify jti is a valid UUID
            assert!(uuid::Uuid::parse_str(&claims.jti).is_ok());
        }
    }

    #[test]
    fn test_builder_requires_issuer() {
        let result = OidcIdTokenClaimsBuilder::new()
            .subject("user@example.com")
            .audience("test")
            .build();

        assert!(result.is_err());
        assert!(matches!(
            result.err(),
            Some(ClaimsBuildError::MissingField("issuer"))
        ));
    }

    #[test]
    fn test_builder_requires_subject() {
        let result = OidcIdTokenClaimsBuilder::new()
            .issuer("https://vouch.example.com")
            .audience("test")
            .build();

        assert!(result.is_err());
        assert!(matches!(
            result.err(),
            Some(ClaimsBuildError::MissingField("subject"))
        ));
    }

    #[test]
    fn test_builder_requires_audience() {
        let result = OidcIdTokenClaimsBuilder::new()
            .issuer("https://vouch.example.com")
            .subject("user@example.com")
            .build();

        assert!(result.is_err());
        assert!(matches!(
            result.err(),
            Some(ClaimsBuildError::MissingField("audience"))
        ));
    }

    #[test]
    fn test_email_defaults_to_subject() {
        let result = OidcIdTokenClaimsBuilder::new()
            .issuer("https://vouch.example.com")
            .subject("user@example.com")
            .audience("test")
            .build();

        assert!(result.is_ok());
        if let Ok(claims) = result {
            assert_eq!(claims.email, "user@example.com");
        }
    }

    #[test]
    fn test_for_aws_uses_issuer_as_audience() {
        let result =
            OidcIdTokenClaimsBuilder::for_aws("https://vouch.example.com", "user@example.com")
                .build();

        assert!(result.is_ok());
        if let Ok(claims) = result {
            assert_eq!(claims.iss, "https://vouch.example.com");
            assert_eq!(claims.sub, "user@example.com");
            assert_eq!(claims.aud, "https://vouch.example.com"); // issuer == audience for AWS
            assert_eq!(claims.email, "user@example.com");
            assert!(!claims.jti.is_empty());
        }
    }

    #[test]
    fn test_jti_is_unique_per_build() {
        let claims1 =
            OidcIdTokenClaimsBuilder::for_aws("https://vouch.example.com", "user@example.com")
                .build()
                .unwrap();
        let claims2 =
            OidcIdTokenClaimsBuilder::for_aws("https://vouch.example.com", "user@example.com")
                .build()
                .unwrap();
        assert_ne!(claims1.jti, claims2.jti);
    }

    #[test]
    fn test_for_audience_uses_provided_audience() {
        let result = OidcIdTokenClaimsBuilder::for_audience(
            "https://vouch.example.com",
            "user@example.com",
            "kubernetes",
        )
        .build();

        assert!(result.is_ok());
        if let Ok(claims) = result {
            assert_eq!(claims.iss, "https://vouch.example.com");
            assert_eq!(claims.sub, "user@example.com");
            assert_eq!(claims.aud, "kubernetes");
            assert_eq!(claims.email, "user@example.com");
            assert!(claims.email_verified);
            assert!(claims.hardware_verified);
            assert!(!claims.jti.is_empty());
        }
    }

    #[test]
    fn test_for_audience_custom_value() {
        let result = OidcIdTokenClaimsBuilder::for_audience(
            "https://vouch.example.com",
            "user@example.com",
            "my-cluster",
        )
        .build();

        assert!(result.is_ok());
        if let Ok(claims) = result {
            assert_eq!(claims.aud, "my-cluster");
        }
    }

    #[test]
    fn test_aws_tags_serialized_in_jwt() {
        let mut principal_tags = std::collections::HashMap::new();
        principal_tags.insert("email".to_string(), vec!["user@example.com".to_string()]);
        principal_tags.insert("domain".to_string(), vec!["example.com".to_string()]);

        let aws_tags = AwsSessionTags {
            principal_tags,
            transitive_tag_keys: vec!["email".to_string(), "domain".to_string()],
        };

        let claims =
            OidcIdTokenClaimsBuilder::for_aws("https://vouch.example.com", "user@example.com")
                .hd(Some("example.com".to_string()))
                .aws_tags(aws_tags)
                .build()
                .unwrap();

        let json = serde_json::to_value(&claims).unwrap();

        // Verify the nested claim structure
        let tags = &json["https://aws.amazon.com/tags"];
        assert!(tags.is_object(), "aws tags claim should be present");

        let ptags = &tags["principal_tags"];
        assert_eq!(ptags["email"], serde_json::json!(["user@example.com"]));
        assert_eq!(ptags["domain"], serde_json::json!(["example.com"]));

        let transitive = &tags["transitive_tag_keys"];
        assert!(
            transitive
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("email"))
        );
        assert!(
            transitive
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("domain"))
        );
    }

    #[test]
    fn test_aws_tags_omitted_when_none() {
        let claims =
            OidcIdTokenClaimsBuilder::for_aws("https://vouch.example.com", "user@example.com")
                .build()
                .unwrap();

        let json = serde_json::to_value(&claims).unwrap();
        assert!(
            json.get("https://aws.amazon.com/tags").is_none(),
            "aws tags claim should be absent when not set"
        );
    }

    #[test]
    fn test_aws_role_serialized_as_single_element_array() {
        let claims =
            OidcIdTokenClaimsBuilder::for_aws("https://vouch.example.com", "user@example.com")
                .aws_role(Some("arn:aws:iam::123456789012:role/MyRole"))
                .build()
                .unwrap();

        let json = serde_json::to_value(&claims).unwrap();
        assert_eq!(
            json["https://aws.amazon.com/roles"],
            serde_json::json!(["arn:aws:iam::123456789012:role/MyRole"])
        );
    }

    #[test]
    fn test_aws_roles_omitted_when_none() {
        let claims =
            OidcIdTokenClaimsBuilder::for_aws("https://vouch.example.com", "user@example.com")
                .aws_role(None)
                .build()
                .unwrap();

        let json = serde_json::to_value(&claims).unwrap();
        assert!(
            json.get("https://aws.amazon.com/roles").is_none(),
            "aws roles claim should be absent when no pin is requested"
        );
    }
}
