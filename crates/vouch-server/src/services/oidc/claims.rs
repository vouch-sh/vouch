// SPDX-License-Identifier: BUSL-1.1
//! OIDC token claims for cloud provider identity federation.

use serde::Serialize;

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
            valid_for_seconds: 28800, // 8 hours default
        }
    }

    /// Create a builder pre-configured for AWS.
    ///
    /// AWS uses the issuer URL as the audience (AWS matches against the OIDC provider).
    /// The subject and email are both set to the user's email.
    #[must_use]
    pub fn for_aws(issuer: &str, email: &str) -> Self {
        Self::new()
            .issuer(issuer)
            .subject(email)
            .audience(issuer) // AWS uses issuer as audience
            .email(email)
    }

    /// Create a builder pre-configured for Kubernetes.
    ///
    /// The audience must match the `--oidc-client-id` configured on the Kubernetes
    /// API server. The subject and email are both set to the user's email.
    #[must_use]
    pub fn for_k8s(issuer: &str, email: &str, audience: &str) -> Self {
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
        let exp = now.as_second() + i64::try_from(self.valid_for_seconds).unwrap_or(28800);

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
        })
    }
}

impl Default for OidcIdTokenClaimsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
    fn test_for_k8s_uses_provided_audience() {
        let result = OidcIdTokenClaimsBuilder::for_k8s(
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
    fn test_for_k8s_custom_audience() {
        let result = OidcIdTokenClaimsBuilder::for_k8s(
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
}
