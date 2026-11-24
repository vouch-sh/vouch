// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OIDC token claims for cloud provider identity federation.

use crate::error::{OAuthErrorCode, ServiceError};
use crate::services::auth::TokenBinding;
use crate::services::oidc::dpop::ValidatedDpopProof;
use crate::services::oidc::fapi::SenderConstraints;
use crate::services::oidc::mtls::CertThumbprint;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use vouch_common::protocol;

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

impl CnfClaim {
    /// The `token_type` a token carrying this confirmation is advertised with.
    ///
    /// RFC 9449 §5: "A token_type of DPoP MUST be included in the access token
    /// response to signal to the client that the access token was bound to its
    /// DPoP key". A certificate-bound token has no such signal — RFC 8705 §3.1
    /// defines the `x5t#S256` confirmation without changing the token type — so
    /// it stays `Bearer`.
    ///
    /// Issuance derives the advertised type from the binding it is about to
    /// stamp in, and introspection derives it from the claim it reads back
    /// (RFC 7662 §2.2 `token_type`). Both go through here, so the two answers
    /// cannot disagree about the same token.
    #[must_use]
    pub fn token_type(&self) -> &'static str {
        if self.jkt.is_some() {
            protocol::ACCESS_TOKEN_TYPE_DPOP
        } else {
            protocol::ACCESS_TOKEN_TYPE_BEARER
        }
    }

    /// Whether `proof` was signed by the key this claim confirms.
    ///
    /// RFC 9449 §7.1: a resource server MUST "check that the public key of
    /// the DPoP proof matches the public key to which the access token is
    /// bound".
    #[must_use]
    pub(crate) fn confirms_dpop(&self, proof: &ValidatedDpopProof) -> bool {
        self.jkt
            .as_deref()
            .is_some_and(|jkt| proof.jkt.as_bytes().ct_eq(jkt.as_bytes()).into())
    }

    /// Whether `cert` is the client certificate this claim confirms
    /// (RFC 8705 §3).
    #[must_use]
    pub(crate) fn confirms_certificate(&self, cert: &CertThumbprint) -> bool {
        self.x5t_s256
            .as_deref()
            .is_some_and(|x5t| cert.as_str().as_bytes().ct_eq(x5t.as_bytes()).into())
    }

    /// The binding this claim confirms, proven by the keys a request
    /// presented, or `None` when the claim names no key.
    ///
    /// A token derived from a sender-constrained token must stay bound to the
    /// same key, and only its holder may derive it. The returned binding
    /// borrows the presented proof, so it cannot name a key the request did
    /// not prove. DPoP takes precedence over mTLS, matching
    /// [`TokenBinding::new`] and resource access.
    ///
    /// # Errors
    ///
    /// [`PossessionError`] when the request lacks the confirmed key or proves
    /// a different one.
    pub(crate) fn confirmed_binding<'a>(
        &self,
        presented: SenderConstraints<'a>,
    ) -> Result<Option<TokenBinding<'a>>, PossessionError> {
        if self.jkt.is_some() {
            let proof = presented.dpop.ok_or(PossessionError::MissingDpopProof)?;
            if !self.confirms_dpop(proof) {
                return Err(PossessionError::DpopKeyMismatch);
            }
            return Ok(Some(TokenBinding::Dpop(proof)));
        }
        if self.x5t_s256.is_some() {
            let cert = presented
                .mtls_cert
                .ok_or(PossessionError::MissingClientCertificate)?;
            if !self.confirms_certificate(cert) {
                return Err(PossessionError::ClientCertificateMismatch);
            }
            return Ok(Some(TokenBinding::MutualTls(cert)));
        }
        Ok(None)
    }
}

/// Why a request failed to prove possession of the key a `cnf` claim names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PossessionError {
    /// The token is DPoP-bound and the request carried no DPoP proof.
    MissingDpopProof,
    /// The DPoP proof was signed by a key other than `cnf.jkt`.
    DpopKeyMismatch,
    /// The token is certificate-bound and the request presented no
    /// certificate.
    MissingClientCertificate,
    /// The presented certificate is not the one `cnf.x5t#S256` names.
    ClientCertificateMismatch,
    /// The token is certificate-bound and the requesting client registered
    /// for DPoP-bound tokens only.
    DpopRequired,
    /// The request used the `DPoP` authorization scheme for a token that is
    /// not DPoP-bound.
    NotDpopBound,
}

impl PossessionError {
    /// The error description, ASCII per RFC 6749 §5.2.
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::MissingDpopProof => "Missing DPoP proof header for sender-constrained token",
            Self::DpopKeyMismatch => "DPoP proof key does not match token binding",
            Self::MissingClientCertificate => {
                "mTLS certificate required for certificate-bound token"
            }
            Self::ClientCertificateMismatch => "Client certificate does not match token binding",
            Self::DpopRequired => {
                "client requires DPoP-bound access tokens, but the token is certificate-bound"
            }
            Self::NotDpopBound => "DPoP scheme used but token is not DPoP-bound",
        }
    }

    /// The token-exchange error for the `parameter` whose token failed.
    ///
    /// RFC 8693 §2.2.2: a subject or actor token that is "unacceptable based
    /// on policy" MUST be reported with the `invalid_request` error code.
    #[must_use]
    pub(crate) fn for_exchange(self, parameter: &str) -> ServiceError {
        ServiceError::oauth(
            OAuthErrorCode::InvalidRequest,
            format!("{parameter}: {}", self.as_str()),
        )
    }
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
    /// When present, AWS STS only allows `AssumeRoleWithWebIdentity` for
    /// a role listed in this claim. Trust policies can require the claim
    /// via the Bool condition key `sts:RoleAuthorizedByIdp`, defined in
    /// the AWS Service Authorization Reference for STS as "Filters access
    /// based on whether the identity provider authorized the role via the
    /// roles claim in the OIDC token":
    /// <https://docs.aws.amazon.com/service-authorization/latest/reference/list_sts.html>
    ///
    /// Serialized as an array of full role ARNs. Matching is reported to
    /// be by exact ARN — no wildcards or bare role names (third-party
    /// testing; not yet in the `AssumeRoleWithWebIdentity` API reference):
    /// <https://awsteele.com/blog/2026/07/13/oidc-tokens-can-restrict-which-aws-roles-they-assume.html>
    ///
    /// Only set for AWS tokens when the client requests pinning; never
    /// set for Kubernetes/WIF tokens. The Identity Center token is pinned
    /// to the management role its `AssumeRoleWithWebIdentity` hop assumes;
    /// `CreateTokenWithIAM` also receives it and, in observed behavior
    /// (undocumented), ignores the claim as it does the other
    /// AWS-namespaced claims it does not consume.
    #[serde(
        rename = "https://aws.amazon.com/roles",
        skip_serializing_if = "Option::is_none"
    )]
    pub aws_roles: Option<Vec<String>>,
    /// OIDC Core §2: "Time when the End-User authentication occurred",
    /// in seconds since the epoch. Only set for AWS tokens, so an IAM OIDC
    /// provider can map it as a trusted identity propagation runtime claim.
    /// A target key ending in `IssueTime` requires an integer and also
    /// yields the derived `Age` key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    /// Vouch session context for AWS trusted identity propagation. Only set
    /// for AWS tokens. See [`VouchSessionContext`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vouch: Option<VouchSessionContext>,
}

/// The `vouch` claim on AWS tokens: one object nested one level, so an IAM
/// OIDC provider can map its members with trusted identity propagation
/// (TIP). IAM documents the shape: "To map a member of an object claim
/// nested one level, use ` / ` as the source key. Arrays and deeper nesting
/// are not supported."
/// (<https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_tip_federation_configure_oidc.html>).
/// A customer maps `vouch/subject_type` with `SubjectTypeSourceKey` and
/// `vouch/agent` as a runtime claim.
///
/// Both members come from the client's DPoP `source` claim, like the
/// `vouch:AccessType` and `vouch:Agent` session tags. `workload` narrows
/// the caller; `user` proves nothing. Policies deny on `workload` and never
/// grant on `user`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VouchSessionContext {
    /// Always present: STS rejects a federation request whose mapped
    /// Subject type source is absent.
    pub subject_type: TipSubjectType,
    /// The agent the client named. Absent for a human session or a blank
    /// name; STS omits an absent optional runtime claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<TipClaimValue>,
}

impl VouchSessionContext {
    /// Build the context from the DPoP proof's `source` claim. A claimed
    /// source, even a blank one, makes the session a `workload`, matching
    /// the `vouch:AccessType=ai` tag and the agent session policy.
    ///
    /// # Errors
    ///
    /// Returns [`AwsClaimError::TipValue`] when the agent name is one STS
    /// would refuse as a TIP value.
    pub fn from_dpop_source(source: Option<&str>) -> Result<Self, AwsClaimError> {
        let agent = source
            .filter(|s| !s.trim().is_empty())
            .map(|s| TipClaimValue::parse("vouch/agent", s))
            .transpose()?;
        let subject_type = if source.is_some() {
            TipSubjectType::Workload
        } else {
            TipSubjectType::User
        };
        Ok(Self {
            subject_type,
            agent,
        })
    }
}

/// `aws:OriginIdentity/SubjectType`: "The value must be `user` or
/// `workload`." (IAM, Configure TIP for an OIDC provider).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TipSubjectType {
    /// A person at the keyboard.
    User,
    /// An AI agent acting for the person.
    Workload,
}

/// A value STS accepts as a mapped trusted identity propagation source.
///
/// IAM, "Meet source-value requirements": each mapped value "must contain
/// one value of no more than 128 characters" and "can contain letters,
/// numbers, spaces, and the characters `_ . : / = + - @`". A present mapped
/// value that breaks a rule fails the whole federation request with
/// `InvalidIdentityToken`, so Vouch refuses it at issuance instead.
/// "Letters" is read as ASCII, the narrower reading.
/// (<https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_tip_federation_context_keys.html>)
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct TipClaimValue(String);

impl TipClaimValue {
    const MAX_LEN: usize = 128;

    /// Accept `value`, with surrounding whitespace trimmed, for the claim
    /// `key` if STS will accept it as a TIP value.
    ///
    /// # Errors
    ///
    /// Returns [`AwsClaimError::TipValue`] naming the claim when the value
    /// is empty, longer than 128 characters, or has a character STS refuses.
    pub fn parse(key: &'static str, value: &str) -> Result<Self, AwsClaimError> {
        let value = value.trim();
        let allowed = |c: char| c.is_ascii_alphanumeric() || c == ' ' || "_.:/=+-@".contains(c);
        let len = value.chars().count();
        if (1..=Self::MAX_LEN).contains(&len) && value.chars().all(allowed) {
            Ok(Self(value.to_owned()))
        } else {
            Err(AwsClaimError::TipValue {
                key,
                value: value.to_owned(),
            })
        }
    }
}

/// AWS session tags claim structure (nested format).
///
/// Per the AWS docs, tag values are arrays of strings and transitive
/// tag keys is an array of key names.
#[derive(Debug, Clone, Serialize)]
pub struct AwsSessionTags {
    /// Tag key-value pairs. Values are single-element arrays per AWS spec.
    pub principal_tags: std::collections::HashMap<String, Vec<AwsTagValue>>,
    /// Tag keys that propagate through role chains.
    pub transitive_tag_keys: Vec<String>,
}

/// A value AWS STS accepts as a session's source identity.
///
/// STS `SourceIdentity`: "Length Constraints: Minimum length of 2. Maximum
/// length of 64. Pattern: [\w+=,.@-]*" (AssumeRole API reference). Measured
/// against STS on 2026-10-09, `\w` is ASCII-only (`jürgen@example.com` is
/// refused) and the enforced maximum is 256, matching the IAM User Guide's
/// "between 2 and 256 characters", not the 64 in the API reference. A value
/// outside this set makes STS refuse the whole credential request, so it is
/// refused here instead, before a token is minted. Surrounding whitespace is
/// trimmed; nothing inside the value is rewritten or removed, because the
/// source identity is the audit identity that trust policies match on, and
/// `o'malley@example.com` must not become another user's
/// `omalley@example.com`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsSourceIdentity(String);

impl AwsSourceIdentity {
    const MIN_LEN: usize = 2;
    const MAX_LEN: usize = 256;

    /// Accept `value`, with surrounding whitespace trimmed, if STS will.
    ///
    /// # Errors
    ///
    /// Returns [`AwsClaimError`] naming the value when STS would refuse it.
    pub fn parse(value: &str) -> Result<Self, AwsClaimError> {
        let value = value.trim();
        let allowed = |c: char| c.is_ascii_alphanumeric() || "_+=,.@-".contains(c);
        let len = value.chars().count();
        if (Self::MIN_LEN..=Self::MAX_LEN).contains(&len) && value.chars().all(allowed) {
            Ok(Self(value.to_owned()))
        } else {
            Err(AwsClaimError::SourceIdentity(value.to_owned()))
        }
    }
}

/// A value AWS STS accepts as a session tag value.
///
/// STS `Tag.Value`: "Length Constraints: Minimum length of 0. Maximum length
/// of 256. Pattern: [\p{L}\p{Z}\p{N}_.:/=+\-@]*" (Tag API reference),
/// confirmed against STS on 2026-10-09: `o'malley@example.com` is refused,
/// `jürgen@example.com` and a value with a space are accepted. `\p{N}` is
/// `char::is_numeric` and `\p{Z}` is non-control whitespace;
/// `char::is_alphabetic` admits a few combining marks beyond `\p{L}`, which
/// STS still refuses at assume time.
///
/// STS accepts an empty value, but a tag that states nothing is never set:
/// an empty value is refused, and an optional tag with no value is omitted
/// ([`Self::parse_optional`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct AwsTagValue(String);

impl AwsTagValue {
    const MAX_LEN: usize = 256;

    /// Accept `value`, with surrounding whitespace trimmed, for the tag `key`
    /// if it is not empty and STS will accept it. Nothing inside the value is
    /// rewritten or removed.
    ///
    /// # Errors
    ///
    /// Returns [`AwsClaimError`] naming the tag when the value is empty or
    /// STS would refuse it.
    pub fn parse(key: &'static str, value: &str) -> Result<Self, AwsClaimError> {
        let value = value.trim();
        let allowed = |c: char| {
            c.is_alphabetic()
                || c.is_numeric()
                || (c.is_whitespace() && !c.is_control())
                || "_.:/=+-@".contains(c)
        };
        let len = value.chars().count();
        if (1..=Self::MAX_LEN).contains(&len) && value.chars().all(allowed) {
            Ok(Self(value.to_owned()))
        } else {
            Err(AwsClaimError::TagValue {
                key,
                value: value.to_owned(),
            })
        }
    }

    /// Like [`Self::parse`] for an optional tag: an absent value, or one that
    /// is empty after trimming, yields `None`, so the tag is not set.
    ///
    /// # Errors
    ///
    /// Returns [`AwsClaimError`] naming the tag when STS would refuse a
    /// non-empty value.
    pub fn parse_optional(
        key: &'static str,
        value: Option<&str>,
    ) -> Result<Option<Self>, AwsClaimError> {
        value
            .filter(|v| !v.trim().is_empty())
            .map(|v| Self::parse(key, v))
            .transpose()
    }
}

/// A claim value AWS STS would refuse.
#[derive(Debug, thiserror::Error)]
pub enum AwsClaimError {
    /// The source identity is outside STS's `[\w+=,.@-]`, 2 to 256 characters.
    #[error(
        "'{0}' cannot be an AWS source identity: AWS allows only ASCII letters, digits, \
         and _+=,.@- (2 to 256 characters)"
    )]
    SourceIdentity(String),
    /// A session tag value is outside STS's tag value pattern.
    #[error(
        "'{value}' cannot be the AWS session tag {key}: AWS allows only letters, digits, \
         spaces, and _.:/=+-@ (1 to 256 characters)"
    )]
    TagValue {
        /// The tag key.
        key: &'static str,
        /// The refused value.
        value: String,
    },
    /// A trusted identity propagation claim value is outside what STS maps.
    #[error(
        "'{value}' cannot be the AWS token claim {key}: AWS allows only ASCII letters, \
         digits, spaces, and _.:/=+-@ (1 to 128 characters)"
    )]
    TipValue {
        /// The claim's TIP source key.
        key: &'static str,
        /// The refused value.
        value: String,
    },
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
    auth_time: Option<Timestamp>,
    vouch: Option<VouchSessionContext>,
    valid_for_seconds: u64,
    /// Reference instant stamped onto `iat` and `exp`. Production callers
    /// pass the request's [`crate::arrival::ArrivalTime`] instant (via
    /// [`crate::arrival::ArrivalTime::timestamp`]) so this token's
    /// `exp`/`iat` share one instant with every other credential in the
    /// same response — required by `arrival.rs` for request-scoped
    /// temporal claims. Defaulting this to `Timestamp::now()` here would
    /// reintroduce the two-clock drift the `disallowed-methods` lint guards
    /// against, so [`build`](Self::build) rejects an unset `issued_at`.
    issued_at: Option<Timestamp>,
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
            auth_time: None,
            vouch: None,
            valid_for_seconds: 28800, // 8 hours default
            issued_at: None,
        }
    }

    /// Create a builder pre-configured for AWS.
    ///
    /// AWS uses the issuer URL as the audience (AWS matches against the OIDC provider).
    /// The subject and email are both set to the user's email.
    /// Includes `https://aws.amazon.com/source_identity` claim set to the
    /// user's email for role chaining audit trails.
    #[must_use]
    pub fn for_aws(issuer: &str, email: &str, source_identity: AwsSourceIdentity) -> Self {
        Self::new()
            .issuer(issuer)
            .subject(email)
            .audience(issuer) // AWS uses issuer as audience
            .email(email)
            .source_identity(source_identity)
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
    pub fn source_identity(mut self, identity: AwsSourceIdentity) -> Self {
        self.source_identity = Some(identity.0);
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

    /// Set the `auth_time` claim; `None` leaves it absent.
    #[must_use]
    pub fn auth_time(mut self, auth_time: Option<Timestamp>) -> Self {
        self.auth_time = auth_time;
        self
    }

    /// Set the `vouch` session-context claim for AWS trusted identity
    /// propagation.
    #[must_use]
    pub fn vouch_context(mut self, context: VouchSessionContext) -> Self {
        self.vouch = Some(context);
        self
    }

    /// Set the token validity period in seconds.
    #[must_use]
    pub fn valid_for_seconds(mut self, seconds: u64) -> Self {
        self.valid_for_seconds = seconds;
        self
    }

    /// Anchor the token's `iat`/`exp` to a specific instant.
    ///
    /// Production callers pass the request's `ArrivalTime` instant (via
    /// [`crate::arrival::ArrivalTime::timestamp`]) so this token's
    /// `exp`/`iat` share one instant with every other credential in the same
    /// response — the contract [`crate::arrival`] establishes for
    /// request-scoped temporal claims. Leaving `issued_at` unset fails
    /// [`build`](Self::build): the build cannot fall back to an ambient
    /// `Timestamp::now()` because that reopens the gap the
    /// `disallowed-methods` lint guards against.
    #[must_use]
    pub fn issued_at(mut self, now: Timestamp) -> Self {
        self.issued_at = Some(now);
        self
    }

    /// Build the OIDC ID token claims.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields (issuer, subject, audience, or
    /// `issued_at`) are missing. `issued_at` is required because a caller
    /// that has no reference instant is a request the
    /// [`crate::arrival`] middleware never stamped, not a relaxed default
    /// the builder should paper over. The `issuer`/`subject`/`audience`
    /// checks run before the `issued_at` check so a test asserting
    /// `MissingField("issuer")` (etc.) is not preempted by the new required
    /// field.
    pub fn build(self) -> Result<OidcIdTokenClaims, ClaimsBuildError> {
        let iss = self
            .issuer
            .ok_or(ClaimsBuildError::MissingField("issuer"))?;
        let sub = self
            .subject
            .clone()
            .ok_or(ClaimsBuildError::MissingField("subject"))?;
        let aud = self
            .audience
            .ok_or(ClaimsBuildError::MissingField("audience"))?;
        let email = self
            .email
            .or(self.subject)
            .ok_or(ClaimsBuildError::MissingField("email"))?;
        let now = self
            .issued_at
            .ok_or(ClaimsBuildError::MissingField("issued_at"))?;
        let exp = now
            .as_second()
            .saturating_add(i64::try_from(self.valid_for_seconds).unwrap_or(28800));

        Ok(OidcIdTokenClaims {
            iss,
            sub,
            aud,
            exp,
            iat: now.as_second(),
            jti: uuid::Uuid::now_v7().to_string(),
            email,
            email_verified: true,
            hardware_verified: true,
            hardware_aaguid: self.hardware_aaguid,
            hd: self.hd,
            source_identity: self.source_identity,
            aws_tags: self.aws_tags,
            aws_roles: self.aws_roles,
            auth_time: self.auth_time.map(Timestamp::as_second),
            vouch: self.vouch,
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

    // STS `SourceIdentity` (AssumeRole API reference): "Pattern:
    // [\w+=,.@-]*". Each case below was sent to STS on 2026-10-09: the
    // accepted ones drew AccessDenied, the refused ones ValidationError.
    #[test]
    fn test_aws_source_identity_matches_sts() {
        let at_limit = format!("{}@example.com", "a".repeat(244));
        let over_limit = format!("{}@example.com", "a".repeat(245));
        for ok in [
            "omalley@example.com",
            "ab",
            "first.last+tag@example.com",
            &at_limit,
        ] {
            assert!(AwsSourceIdentity::parse(ok).is_ok(), "{ok}");
        }
        for refused in [
            "o'malley@example.com",
            "jürgen@example.com",
            "first last@example.com",
            "a",
            " a ",
            &over_limit,
        ] {
            assert!(AwsSourceIdentity::parse(refused).is_err(), "{refused}");
        }
        assert_eq!(
            AwsSourceIdentity::parse("  omalley@example.com\n").unwrap(),
            AwsSourceIdentity::parse("omalley@example.com").unwrap(),
            "surrounding whitespace is trimmed"
        );
    }

    #[test]
    fn test_aws_tag_value_trims_surrounding_whitespace() {
        assert_eq!(
            AwsTagValue::parse("vouch:Agent", "\tclaude-code ").unwrap(),
            AwsTagValue::parse("vouch:Agent", "claude-code").unwrap(),
        );
        assert_eq!(
            AwsTagValue::parse("vouch:Email", " first last@example.com ").unwrap(),
            AwsTagValue::parse("vouch:Email", "first last@example.com").unwrap(),
            "an interior space is kept"
        );
    }

    // A tag that states nothing is never set: an absent or blank optional
    // value yields no tag, and a value STS refuses is still an error.
    #[test]
    fn test_aws_tag_value_parse_optional() {
        assert_eq!(
            AwsTagValue::parse_optional("vouch:Domain", None).unwrap(),
            None
        );
        assert_eq!(
            AwsTagValue::parse_optional("vouch:Domain", Some("")).unwrap(),
            None
        );
        assert_eq!(
            AwsTagValue::parse_optional("vouch:Domain", Some(" \t")).unwrap(),
            None
        );
        assert_eq!(
            AwsTagValue::parse_optional("vouch:Domain", Some(" example.com ")).unwrap(),
            Some(AwsTagValue::parse("vouch:Domain", "example.com").unwrap()),
        );
        assert!(AwsTagValue::parse_optional("vouch:Agent", Some("agent'name")).is_err());
    }

    // STS `Tag.Value` (Tag API reference): "Maximum length of 256. Pattern:
    // [\p{L}\p{Z}\p{N}_.:/=+\-@]*". Cases sent to STS on 2026-10-09 as
    // above.
    #[test]
    fn test_aws_tag_value_matches_sts() {
        let at_limit = format!("{}@example.com", "a".repeat(244));
        let over_limit = format!("{}@example.com", "a".repeat(245));
        for ok in [
            "omalley@example.com",
            "jürgen@example.com",
            "first last@example.com",
            "claude-code/1.0",
            &at_limit,
        ] {
            assert!(AwsTagValue::parse("vouch:Email", ok).is_ok(), "{ok}");
        }
        for refused in ["o'malley@example.com", "tab\there", "", "   ", &over_limit] {
            assert!(
                AwsTagValue::parse("vouch:Email", refused).is_err(),
                "{refused}"
            );
        }
    }

    // IAM, Meet source-value requirements: a mapped value "must contain one
    // value of no more than 128 characters" and "can contain letters,
    // numbers, spaces, and the characters `_ . : / = + - @`".
    // https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_tip_federation_context_keys.html
    #[test]
    fn test_tip_claim_value_matches_iam_source_value_requirements() {
        let at_limit = "a".repeat(128);
        let over_limit = "a".repeat(129);
        for ok in [
            "claude-code",
            "claude-code/1.0",
            "agent name",
            "a_b.c:d/e=f+g-h@i",
            &at_limit,
        ] {
            assert!(TipClaimValue::parse("vouch/agent", ok).is_ok(), "{ok}");
        }
        // A comma and `#` pass other STS fields but not a TIP value; `ü` is
        // refused under the ASCII reading of "letters".
        for refused in [
            "",
            "   ",
            "a,b",
            "a#b",
            "o'malley",
            "tab\there",
            "jürgen",
            &over_limit,
        ] {
            assert!(
                matches!(
                    TipClaimValue::parse("vouch/agent", refused),
                    Err(AwsClaimError::TipValue {
                        key: "vouch/agent",
                        ..
                    })
                ),
                "{refused}"
            );
        }
    }

    #[test]
    fn test_tip_claim_value_trims_surrounding_whitespace() {
        assert_eq!(
            TipClaimValue::parse("vouch/agent", " claude-code\t").unwrap(),
            TipClaimValue::parse("vouch/agent", "claude-code").unwrap(),
        );
    }

    // IAM, Configure TIP for an OIDC provider: the Subject type "value must
    // be `user` or `workload`".
    #[test]
    fn test_vouch_session_context_subject_type() {
        let cases = [
            (None, serde_json::json!({ "subject_type": "user" })),
            (
                Some("claude-code"),
                serde_json::json!({ "subject_type": "workload", "agent": "claude-code" }),
            ),
            // A claimed but blank source still attaches the agent session
            // policy, so the session is a workload with no agent name.
            (
                Some("  "),
                serde_json::json!({ "subject_type": "workload" }),
            ),
        ];
        for (source, expected) in cases {
            let context = VouchSessionContext::from_dpop_source(source).unwrap();
            assert_eq!(
                serde_json::to_value(&context).unwrap(),
                expected,
                "{source:?}"
            );
        }
    }

    #[test]
    fn test_vouch_session_context_refuses_unmappable_agent() {
        assert!(matches!(
            VouchSessionContext::from_dpop_source(Some("agent,with,commas")),
            Err(AwsClaimError::TipValue {
                key: "vouch/agent",
                ..
            })
        ));
    }

    /// A deterministic reference instant used by [`issued_at`](OidcIdTokenClaimsBuilder::issued_at)
    /// so tests can assert exact `iat`/`exp` values rather than a window
    /// around `Timestamp::now()`. Matches the convention in `arrival.rs`'s
    /// `for_test_second` boundary tests.
    fn test_now() -> Timestamp {
        Timestamp::from_second(1_700_000_000).unwrap()
    }

    #[test]
    fn test_builder_creates_valid_claims() {
        let result = OidcIdTokenClaimsBuilder::new()
            .issuer("https://vouch.example.com")
            .subject("user@example.com")
            .audience("https://vouch.example.com")
            .email("user@example.com")
            .hardware_aaguid(Some("ee882879-721c-4913-9775-3dfcce97072a".to_string()))
            .valid_for_seconds(3600)
            .issued_at(test_now())
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
            .issued_at(test_now())
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
            .issued_at(test_now())
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
            .issued_at(test_now())
            .build();

        assert!(result.is_err());
        assert!(matches!(
            result.err(),
            Some(ClaimsBuildError::MissingField("audience"))
        ));
    }

    #[test]
    fn test_builder_requires_issued_at() {
        // `issued_at` is required: a caller that has no reference instant is a
        // request the `arrival` middleware never stamped, not a relaxed default
        // the builder should paper over — see the build() doc comment.
        let result = OidcIdTokenClaimsBuilder::new()
            .issuer("https://vouch.example.com")
            .subject("user@example.com")
            .audience("test")
            .build();

        assert!(result.is_err());
        assert!(matches!(
            result.err(),
            Some(ClaimsBuildError::MissingField("issued_at"))
        ));
    }

    #[test]
    fn test_builder_issued_at_anchors_iat_and_exp() {
        // The `issued_at` reference instant is the value stamped onto `iat`
        // and (shifted by `valid_for_seconds`) onto `exp`. Asserting the exact
        // integers prevents a regression where `build()` falls back to an
        // ambient `Timestamp::now()` and ignores the supplied instant.
        let claims = OidcIdTokenClaimsBuilder::new()
            .issuer("https://vouch.example.com")
            .subject("user@example.com")
            .audience("test")
            .valid_for_seconds(3600)
            .issued_at(test_now())
            .build()
            .unwrap();

        assert_eq!(
            claims.iat, 1_700_000_000,
            "iat must be stamped from `issued_at`, not an ambient clock"
        );
        assert_eq!(
            claims.exp,
            1_700_000_000 + 3600,
            "exp must be `issued_at.as_second() + valid_for_seconds`"
        );
    }

    #[test]
    fn test_email_defaults_to_subject() {
        let result = OidcIdTokenClaimsBuilder::new()
            .issuer("https://vouch.example.com")
            .subject("user@example.com")
            .audience("test")
            .issued_at(test_now())
            .build();

        assert!(result.is_ok());
        if let Ok(claims) = result {
            assert_eq!(claims.email, "user@example.com");
        }
    }

    #[test]
    fn test_for_aws_uses_issuer_as_audience() {
        let result = OidcIdTokenClaimsBuilder::for_aws(
            "https://vouch.example.com",
            "user@example.com",
            AwsSourceIdentity::parse("user@example.com").unwrap(),
        )
        .issued_at(test_now())
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
        let claims1 = OidcIdTokenClaimsBuilder::for_aws(
            "https://vouch.example.com",
            "user@example.com",
            AwsSourceIdentity::parse("user@example.com").unwrap(),
        )
        .issued_at(test_now())
        .build()
        .unwrap();
        let claims2 = OidcIdTokenClaimsBuilder::for_aws(
            "https://vouch.example.com",
            "user@example.com",
            AwsSourceIdentity::parse("user@example.com").unwrap(),
        )
        .issued_at(test_now())
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
        .issued_at(test_now())
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
        .issued_at(test_now())
        .build();

        assert!(result.is_ok());
        if let Ok(claims) = result {
            assert_eq!(claims.aud, "my-cluster");
        }
    }

    #[test]
    fn test_aws_tags_serialized_in_jwt() {
        let mut principal_tags = std::collections::HashMap::new();
        principal_tags.insert(
            "email".to_string(),
            vec![AwsTagValue::parse("email", "user@example.com").unwrap()],
        );
        principal_tags.insert(
            "domain".to_string(),
            vec![AwsTagValue::parse("domain", "example.com").unwrap()],
        );

        let aws_tags = AwsSessionTags {
            principal_tags,
            transitive_tag_keys: vec!["email".to_string(), "domain".to_string()],
        };

        let claims = OidcIdTokenClaimsBuilder::for_aws(
            "https://vouch.example.com",
            "user@example.com",
            AwsSourceIdentity::parse("user@example.com").unwrap(),
        )
        .hd(Some("example.com".to_string()))
        .aws_tags(aws_tags)
        .issued_at(test_now())
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
        let claims = OidcIdTokenClaimsBuilder::for_aws(
            "https://vouch.example.com",
            "user@example.com",
            AwsSourceIdentity::parse("user@example.com").unwrap(),
        )
        .issued_at(test_now())
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
        let claims = OidcIdTokenClaimsBuilder::for_aws(
            "https://vouch.example.com",
            "user@example.com",
            AwsSourceIdentity::parse("user@example.com").unwrap(),
        )
        .aws_role(Some("arn:aws:iam::123456789012:role/MyRole"))
        .issued_at(test_now())
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
        let claims = OidcIdTokenClaimsBuilder::for_aws(
            "https://vouch.example.com",
            "user@example.com",
            AwsSourceIdentity::parse("user@example.com").unwrap(),
        )
        .aws_role(None)
        .issued_at(test_now())
        .build()
        .unwrap();

        let json = serde_json::to_value(&claims).unwrap();
        assert!(
            json.get("https://aws.amazon.com/roles").is_none(),
            "aws roles claim should be absent when no pin is requested"
        );
    }
}
