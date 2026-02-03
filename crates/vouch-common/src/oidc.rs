// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared OIDC token claims for cloud provider identity federation.

use serde::Serialize;

/// Standard OIDC ID token claims with Vouch extensions.
/// Used by both AWS and GCP credential endpoints.
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

    /// Create a builder pre-configured for GCP.
    ///
    /// GCP uses a custom audience (Workload Identity Pool provider resource name).
    /// The subject and email are both set to the user's email.
    #[must_use]
    pub fn for_gcp(issuer: &str, email: &str, audience: &str) -> Self {
        Self::new()
            .issuer(issuer)
            .subject(email)
            .audience(audience) // GCP uses WIF provider audience
            .email(email)
    }

    /// Create a builder pre-configured for Kubernetes.
    ///
    /// Kubernetes uses a custom audience (typically cluster name or API server URL).
    /// The subject and email are both set to the user's email.
    #[must_use]
    pub fn for_k8s(issuer: &str, email: &str, audience: &str) -> Self {
        Self::new()
            .issuer(issuer)
            .subject(email)
            .audience(audience) // K8s uses --oidc-client-id as audience
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
    pub fn build(self) -> Result<OidcIdTokenClaims, &'static str> {
        let now = jiff::Timestamp::now();
        let exp = now.as_second() + i64::try_from(self.valid_for_seconds).unwrap_or(28800);

        Ok(OidcIdTokenClaims {
            iss: self.issuer.ok_or("issuer is required")?,
            sub: self.subject.clone().ok_or("subject is required")?,
            aud: self.audience.ok_or("audience is required")?,
            exp,
            iat: now.as_second(),
            email: self.email.or(self.subject).ok_or("email is required")?,
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
        }
    }

    #[test]
    fn test_builder_requires_issuer() {
        let result = OidcIdTokenClaimsBuilder::new()
            .subject("user@example.com")
            .audience("test")
            .build();

        assert!(result.is_err());
        assert_eq!(result.err(), Some("issuer is required"));
    }

    #[test]
    fn test_builder_requires_subject() {
        let result = OidcIdTokenClaimsBuilder::new()
            .issuer("https://vouch.example.com")
            .audience("test")
            .build();

        assert!(result.is_err());
        assert_eq!(result.err(), Some("subject is required"));
    }

    #[test]
    fn test_builder_requires_audience() {
        let result = OidcIdTokenClaimsBuilder::new()
            .issuer("https://vouch.example.com")
            .subject("user@example.com")
            .build();

        assert!(result.is_err());
        assert_eq!(result.err(), Some("audience is required"));
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
        }
    }

    #[test]
    fn test_for_gcp_uses_custom_audience() {
        let audience = "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/my-pool/providers/my-provider";
        let result = OidcIdTokenClaimsBuilder::for_gcp(
            "https://vouch.example.com",
            "user@example.com",
            audience,
        )
        .build();

        assert!(result.is_ok());
        if let Ok(claims) = result {
            assert_eq!(claims.iss, "https://vouch.example.com");
            assert_eq!(claims.sub, "user@example.com");
            assert_eq!(claims.aud, audience); // custom audience for GCP
            assert_eq!(claims.email, "user@example.com");
        }
    }

    #[test]
    fn test_for_k8s_uses_custom_audience() {
        let audience = "my-kubernetes-cluster";
        let result = OidcIdTokenClaimsBuilder::for_k8s(
            "https://vouch.example.com",
            "user@example.com",
            audience,
        )
        .build();

        assert!(result.is_ok());
        if let Ok(claims) = result {
            assert_eq!(claims.iss, "https://vouch.example.com");
            assert_eq!(claims.sub, "user@example.com");
            assert_eq!(claims.aud, audience); // custom audience for K8s
            assert_eq!(claims.email, "user@example.com");
            assert!(claims.hardware_verified);
        }
    }
}
