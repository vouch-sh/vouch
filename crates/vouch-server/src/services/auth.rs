// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authentication service for FIDO2/WebAuthn login.
//!
//! Implements:
//! - WebAuthn Level 2 Section 7.2 — Verifying an Authentication Assertion
//! - RFC 8176 — Authentication Method Reference Values
//! - RFC 9068 Section 2.2 — JWT Access Token claims (`amr`, `acr`)
//!
//! This module provides business logic for authenticating users via WebAuthn
//! discoverable credentials. It handles:
//! - Authentication method references (AMR) and assurance levels (ACR)
//! - Authenticator lookup and ownership verification
//! - WebAuthn assertion verification
//! - OAuth access token creation and storage
//!
//! The handlers remain thin, focusing on HTTP concerns.

use crate::AppState;
use crate::crypto::hash_token;
use crate::crypto::keys::OidcSigningKey;
use crate::crypto::webauthn_verify::{self, OriginPolicy};
use crate::db::{self, Authenticator, SessionPurpose, User};
use crate::services::oidc::mtls::CertThumbprint;
use crate::services::oidc::{CnfClaim, ScopeSet, ValidatedDpopProof};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};
use secrecy::SecretString;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use uuid::Uuid;

use crate::error::{OAuthErrorCode, ServiceError, ServiceResult};
use vouch_common::protocol;

// ============================================================================
// Authentication Method References (RFC 8176)
// ============================================================================

/// Authentication method reference value (RFC 8176).
///
/// Represents a single authentication method used during user authentication.
/// Vouch always uses FIDO2 hardware keys with PIN and user presence, so all
/// three methods are present in every authentication event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// RFC 8176: Proof-of-possession of a hardware-secured key.
    HardwareKey,
    /// RFC 8176: Personal Identification Number or pattern verified on device.
    Pin,
    /// RFC 8176: User presence test (physical interaction with authenticator).
    UserPresence,
}

impl AuthMethod {
    /// Return the wire-format string per RFC 8176.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::HardwareKey => "hwk",
            Self::Pin => "pin",
            Self::UserPresence => "user",
        }
    }

    /// All authentication methods used in a FIDO2 hardware key flow.
    ///
    /// Vouch always requires hardware key + PIN + user presence, so this
    /// returns all three methods.
    #[must_use]
    pub const fn all_fido2() -> &'static [Self] {
        &[Self::HardwareKey, Self::Pin, Self::UserPresence]
    }
}

impl fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for AuthMethod {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AuthMethod {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "hwk" => Ok(Self::HardwareKey),
            "pin" => Ok(Self::Pin),
            "user" => Ok(Self::UserPresence),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["hwk", "pin", "user"],
            )),
        }
    }
}

/// NIST SP 800-63B AAL3: Hardware-based multi-factor authentication.
///
/// FIDO2 hardware key + PIN + user presence meets AAL3 per NIST SP 800-63B.
pub(crate) const ACR_AAL3: &str = "urn:nist:authentication:assurance-level:aal3";

/// Authentication assurance level for an issued token.
///
/// Bundles `hardware_verified`, `auth_time`, `amr`, and `acr` into a single
/// type to prevent inconsistent combinations (e.g., `hardware_verified: true`
/// with `amr: None`).
///
/// `auth_time` lives inside [`Self::Verified`] rather than beside this enum
/// because it records *when the FIDO2 assertion happened*. A token that ran no
/// assertion has no such instant, and [`Self::NotVerified`] has nowhere to put
/// one — so an enrollment bootstrap or M2M token cannot carry an `auth_time`
/// that a freshness gate would read as proof of recent FIDO2 (issue #1114).
#[derive(Debug, Clone)]
pub(crate) enum HardwareVerification {
    /// FIDO2 hardware key verified by Vouch (UP + UV).
    /// Sets `hardware_verified: true`, `amr: [hwk, pin, user]`,
    /// `acr: urn:nist:...:aal3`.
    Verified {
        /// When the assertion happened (Unix seconds), for the `auth_time`
        /// claim. `None` when verification is inherited from another token
        /// rather than observed here — RFC 8693 token exchange runs no
        /// ceremony of its own.
        auth_time: Option<i64>,
    },
    /// No hardware verification performed (M2M, JWT bearer, etc.).
    /// Sets `hardware_verified: false`, `auth_time: None`, `amr: None`,
    /// `acr: None`.
    NotVerified,
}

impl HardwareVerification {
    /// Whether FIDO2 hardware verification was performed.
    #[must_use]
    pub(crate) fn hardware_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// RFC 9068 Section 2.2 / OIDC Core Section 2: when the End-User
    /// authentication occurred. Absent unless FIDO2 ran.
    #[must_use]
    pub(crate) fn auth_time(&self) -> Option<i64> {
        match self {
            Self::Verified { auth_time } => *auth_time,
            Self::NotVerified => None,
        }
    }

    /// RFC 8176 authentication methods reference.
    #[must_use]
    pub(crate) fn amr(&self) -> Option<Vec<AuthMethod>> {
        match self {
            Self::Verified { .. } => Some(AuthMethod::all_fido2().to_vec()),
            Self::NotVerified => None,
        }
    }

    /// RFC 9068 authentication context class reference.
    #[must_use]
    pub(crate) fn acr(&self) -> Option<String> {
        match self {
            Self::Verified { .. } => Some(ACR_AAL3.to_string()),
            Self::NotVerified => None,
        }
    }
}

/// Parameters for verifying authenticator ownership.
pub(crate) struct AuthenticatorLookupParams<'a> {
    /// The credential ID from the WebAuthn assertion.
    pub credential_id: &'a [u8],
    /// The user ID from the user handle.
    pub user_id: Uuid,
}

/// Result of authenticator lookup and ownership verification.
pub(crate) struct AuthenticatorLookupResult {
    /// The verified authenticator.
    pub authenticator: Authenticator,
    /// The user who owns the authenticator.
    pub user: User,
}

/// Look up an authenticator and verify it belongs to the specified user.
///
/// Uses a single JOIN query to fetch both the authenticator and user,
/// eliminating a sequential DB round-trip.
///
/// # Errors
///
/// Returns `ServiceError::NotFound` if the credential or user is not found.
/// Returns `ServiceError::Forbidden` if the credential doesn't belong to the user.
pub(crate) async fn lookup_and_verify_authenticator(
    state: &AppState,
    params: AuthenticatorLookupParams<'_>,
) -> ServiceResult<AuthenticatorLookupResult> {
    // Get the authenticator and user in a single JOIN query
    let row = db::get_authenticator_with_user_by_credential_id(&state.store, params.credential_id)
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))?
        .ok_or(ServiceError::NotFound("credential"))?;

    let (authenticator, user) = (row.authenticator, row.user);

    // Verify authenticator belongs to this user (from user_handle)
    if authenticator.user_id != params.user_id.to_string() {
        return Err(ServiceError::Forbidden("user_mismatch"));
    }

    if !user.active {
        return Err(ServiceError::Forbidden("user_deactivated"));
    }

    Ok(AuthenticatorLookupResult {
        authenticator,
        user,
    })
}

/// Parameters for verifying a WebAuthn login assertion.
pub(crate) struct LoginAssertionParams {
    /// Authenticator data from the assertion.
    pub authenticator_data: Vec<u8>,
    /// Client data JSON from the assertion.
    pub client_data_json: Vec<u8>,
    /// Signature from the assertion.
    pub signature: Vec<u8>,
    /// Public key of the authenticator.
    pub public_key: Vec<u8>,
    /// Relying party ID.
    pub rp_id: String,
    /// Expected `clientDataJSON.origin`. Browsers set this to the calling
    /// page's origin (the server's `base_url`); CLI flows construct it as
    /// `https://{rp_id}`. Deriving it from `rp_id` here would reject valid
    /// browser logins when `base_url`'s host is a subdomain of `rp_id`
    /// (a configuration `webauthn-rs` accepts at startup).
    pub expected_origin: String,
    /// Expected challenge (raw bytes).
    pub challenge: Vec<u8>,
    /// Current counter value from the database.
    pub stored_counter: u32,
    /// Whether to tolerate loopback origin variations (development only).
    /// Set to `false` whenever TLS is configured so a production deployment
    /// never weakens origin binding, even with a loopback `rp_id`.
    pub origin_policy: OriginPolicy,
}

/// Result of WebAuthn assertion verification.
pub(crate) struct LoginAssertionResult {
    /// New counter value to store.
    pub new_counter: u32,
    /// Whether user verification was performed.
    pub user_verified: bool,
}

/// Verify a WebAuthn login assertion (WebAuthn Level 2 Section 7.2).
///
/// Runs signature verification on a blocking thread as a fairness
/// optimization: on small (1-vCPU) instances, ECDSA/Ed25519
/// verification (~0.5-2 ms) would monopolize the single worker thread,
/// stalling all other I/O. Unlike the KMS SSH-CA path (which would
/// deadlock without `spawn_blocking`), this is purely about runtime
/// fairness — local crypto doesn't block on async I/O.
///
/// # Errors
///
/// Returns `ServiceError::OAuth` with `InvalidGrant` if verification fails.
pub(crate) async fn verify_login_assertion(
    params: LoginAssertionParams,
) -> ServiceResult<LoginAssertionResult> {
    tokio::task::spawn_blocking(move || {
        let expected_challenge = URL_SAFE_NO_PAD.encode(&params.challenge);

        let result = webauthn_verify::verify_assertion(&webauthn_verify::AssertionParams {
            authenticator_data: &params.authenticator_data,
            client_data_json: &params.client_data_json,
            signature: &params.signature,
            public_key_cose: &params.public_key,
            expected_rp_id: &params.rp_id,
            expected_challenge: &expected_challenge,
            expected_origin: &params.expected_origin,
            stored_counter: params.stored_counter,
            require_user_verification: true,
            origin_policy: params.origin_policy,
        })
        .map_err(|e| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                format!("WebAuthn verification failed: {e}"),
            )
        })?;

        Ok(LoginAssertionResult {
            new_counter: result.counter,
            user_verified: result.user_verified,
        })
    })
    .await
    .map_err(|e| {
        tracing::error!("WebAuthn verification task failed: {e}");
        ServiceError::Internal("WebAuthn verification failed".to_string())
    })?
}

/// Actor claim for delegation chains (RFC 8693 Section 4.1).
///
/// Used in both token exchange responses and access token JWTs to
/// represent the acting party in a delegation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ActorClaim {
    /// RFC 8693 Section 4.1: Subject identifier of the actor.
    pub sub: String,
    /// RFC 8693 Section 4.1: Nested actor (for multi-hop delegation).
    #[serde(rename = "act", skip_serializing_if = "Option::is_none")]
    pub actor: Option<Box<ActorClaim>>,
}

impl ActorClaim {
    /// Count the delegation depth of this actor chain.
    ///
    /// Returns 1 for a single actor, 2 for a nested actor, etc.
    /// Uses iterative traversal to prevent stack overflow from
    /// deeply nested (potentially malicious) actor chains.
    #[must_use]
    pub(crate) fn depth(&self) -> usize {
        let mut depth: usize = 1;
        let mut current = &self.actor;
        while let Some(inner) = current {
            depth = depth.saturating_add(1);
            current = &inner.actor;
        }
        depth
    }
}

/// Maximum allowed delegation depth for actor chains.
///
/// Prevents unbounded nesting in token exchange delegation chains.
pub(crate) const MAX_DELEGATION_DEPTH: usize = 5;

// ============================================================================
// Token Issuance Proof (single-use witness chokepoint)
// ============================================================================

/// Proof that a token-issuance request has consumed its replay-prevention
/// primitives. Required parameter to [`create_oauth_access_token`].
///
/// The presence of a `TokenIssuanceProof` value is compile-time evidence that
/// the caller has consumed the relevant grant-level and client-authentication
/// replay primitives, in the correct order, before invoking the chokepoint.
/// The proof is constructed only at call sites that have already executed
/// those consume-once operations.
///
/// `TokenIssuanceProof` is not `Clone` — the proof represents a one-shot
/// authorization to issue a token and cannot be duplicated.
///
/// Every issuance must also supply a
/// [`SenderConstraintProof`], so minting an
/// unbound access token for a FAPI client is a compile error rather than a
/// per-grant check that a new grant can forget to call.
#[must_use = "the proof was constructed to authorize a single token issuance; \
              dropping it without calling create_oauth_access_token is a bug"]
#[derive(Debug)]
pub(crate) struct TokenIssuanceProof {
    pub(crate) grant: GrantProof,
    pub(crate) client_auth: ClientAuthProof,
    pub(crate) sender_constraint: SenderConstraintProof,
}

/// Witness for the grant-level replay primitive consumed during token issuance.
///
/// Every variant either carries a sealed claim witness produced by an
/// atomic consume-once operation, or is explicitly a no-replay-primitive
/// variant (`ClientCredentials`, `TokenExchange` — protected via
/// `ClientAuthProof`; `CertificationBypass` — gated by env-var; and
/// `TestingOnly` — `cfg`-gated to test builds).
#[derive(Debug)]
pub(crate) enum GrantProof {
    /// `authorization_code` grant. Carries a [`crate::db::AuthCodeClaim`]
    /// witness — proof that the authorization code was atomically consumed
    /// before this token issuance.
    AuthorizationCode(crate::db::AuthCodeClaim),

    /// `client_credentials` grant — no grant-level replay primitive; the
    /// single-use guarantee is enforced entirely via [`ClientAuthProof`].
    ClientCredentials,

    /// `urn:ietf:params:oauth:grant-type:token-exchange` — RFC 8693 does not
    /// require single-use of the subject token; replay protection is via
    /// [`ClientAuthProof`].
    TokenExchange,

    /// FIDO2 assertion grant. Carries a [`crate::db::ChallengeStateClaim`]
    /// witness — proof that the challenge state JWT was atomically marked
    /// consumed before this token issuance.
    Fido2Assertion(crate::db::ChallengeStateClaim),

    /// Device authorization grant (RFC 8628). Carries a [`crate::db::DeviceCodeClaim`]
    /// witness — proof that the device code was atomically transitioned to
    /// `Consumed` before this token issuance.
    DeviceCode(crate::db::DeviceCodeClaim),

    /// Enrollment bootstrap session — issued post-IdP authentication and
    /// pre-FIDO2 registration. `hardware_verified` is false here. Carries
    /// an [`crate::db::OidcStateClaim`] witness — proof that the OIDC
    /// state record was atomically transitioned to `consumed_at = Some(_)`
    /// before this token issuance, closing the read-vs-consume TOCTOU
    /// window that existed when callers used `get_oidc_state` +
    /// `delete_oidc_state` as separate steps.
    EnrollmentBootstrap(crate::db::OidcStateClaim),

    /// Enrollment complete session — issued after WebAuthn registration.
    /// Carries a [`crate::db::ChallengeStateClaim`] witness — proof that
    /// the registration state JWT was atomically marked consumed before
    /// this token issuance.
    EnrollmentComplete(crate::db::ChallengeStateClaim),

    /// Browser WebAuthn login. Carries a [`crate::db::ChallengeStateClaim`]
    /// witness — proof that the authentication state JWT was atomically
    /// marked consumed before this token issuance.
    BrowserLogin(crate::db::ChallengeStateClaim),

    /// Certification test bypass (only available when
    /// `VOUCH_CERTIFICATION_TEST_TOKEN` is configured). Deliberately does
    /// not consume the pending authorization — the authorize endpoint
    /// handles consumption on the subsequent redirect.
    CertificationBypass,

    /// Test-only variant used by `test_utils` session helpers. Gated by
    /// the same `cfg` as the `test_utils` module so it cannot appear in
    /// production builds.
    #[cfg(any(test, feature = "test-utils"))]
    TestingOnly,
}

/// Witness bundle for a `private_key_jwt` (RFC 7523) client authentication.
///
/// Composes the two independent invariants:
/// - **auth** — RFC 7523 §3 validation passed (signature, audience, timing,
///   `iss == sub == client_id`, client configured for `private_key_jwt`).
///   Constructible only by
///   [`crate::services::oidc::jwt_bearer::client_auth::authenticate_client_jwt`].
/// - **jti** — present when the assertion carried a `jti` claim and the atomic
///   replay-prevention insert succeeded. `None` is valid for non-FAPI clients
///   (RFC 7523 §3 makes `jti` OPTIONAL); FAPI 2.0 §5.3.2.1 enforces presence
///   upstream so a FAPI client reaching this struct cannot have `jti: None`.
///
/// Fields are private; construction goes through [`Self::new`] so callers
/// must supply both witnesses. Witnesses are consumed by drop.
#[derive(Debug)]
pub(crate) struct JwtClientAuthProof {
    _auth: crate::services::oidc::jwt_bearer::client_auth::JwtAuthSucceeded,
    _jti: Option<crate::db::JwtAssertionJtiClaim>,
}

impl JwtClientAuthProof {
    pub(crate) fn new(
        auth: crate::services::oidc::jwt_bearer::client_auth::JwtAuthSucceeded,
        jti: Option<crate::db::JwtAssertionJtiClaim>,
    ) -> Self {
        Self {
            _auth: auth,
            _jti: jti,
        }
    }
}

/// Witness that every sender-constraint requirement applying to an issuance
/// was checked.
///
/// Requiring this on [`TokenIssuanceProof`] means a grant cannot mint a token
/// without deciding which case it is in — the enforcement is not a call a new
/// grant can forget. Both constructors are named for the case they assert, so
/// the choice is visible at the call site and in review.
#[derive(Debug)]
pub(crate) struct SenderConstraintProof {
    _private: (),
}

impl SenderConstraintProof {
    /// Check every sender-constraint requirement registered for `client`.
    ///
    /// Three independent requirements, all enforced here so that no grant
    /// enforces a different subset:
    /// - FAPI 2.0 Section 5.3.2.1 — a FAPI client's tokens must be
    ///   sender-constrained by DPoP or mTLS.
    /// - RFC 9449 Section 5 — a client that registered
    ///   `dpop_bound_access_tokens` must present a DPoP proof. mTLS does not
    ///   substitute: the client asked for a `cnf.jkt` binding specifically.
    /// - RFC 8705 Section 3 — a client that registered
    ///   `tls_client_certificate_bound_access_tokens` must present a
    ///   certificate, with DPoP accepted as an alternative constraint.
    ///
    /// # Errors
    ///
    /// Returns `ServiceError::OAuth` with `invalid_request` if a registered
    /// requirement is unmet.
    pub(crate) fn validate(
        client: &db::OAuthClient,
        constraints: crate::services::oidc::fapi::SenderConstraints,
    ) -> ServiceResult<Self> {
        crate::services::oidc::fapi::validate_fapi_token_request(client, constraints)?;

        if client.dpop_bound_access_tokens && !constraints.dpop {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequest,
                "Client requires DPoP-bound access tokens \
                 but no DPoP proof was provided",
            ));
        }

        if client.tls_client_certificate_bound_access_tokens
            && !constraints.mtls_cert
            && !constraints.dpop
        {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequest,
                "Client requires certificate-bound access tokens \
                 but no client certificate was presented",
            ));
        }

        Ok(Self { _private: () })
    }

    /// There is no registered OAuth client whose registration could constrain
    /// this issuance.
    ///
    /// Browser sessions, enrollment bootstrap/completion, and the
    /// certification-test bypass mint tokens for a user rather than for a
    /// client. The device grant's built-in CLI flow (no `client_id`) is the
    /// same case.
    pub(crate) fn no_registered_client() -> Self {
        Self { _private: () }
    }
}

/// Witness for the client-authentication replay primitive consumed during
/// token issuance.
#[derive(Debug)]
pub(crate) enum ClientAuthProof {
    /// `private_key_jwt` (RFC 7523). Carries the auth-succeeded witness plus
    /// an optional JTI replay-prevention claim — see [`JwtClientAuthProof`].
    #[expect(
        dead_code,
        reason = "witness payload is consumed by drop, not by field access"
    )]
    PrivateKeyJwt(JwtClientAuthProof),

    /// `client_secret_basic` / `client_secret_post` (RFC 6749 §2.3.1).
    /// Carries the verification witness from
    /// [`crate::services::oidc::token::authenticate_client`].
    ClientSecret(crate::services::oidc::token::ClientSecretVerification),

    /// `tls_client_auth` / `self_signed_tls_client_auth` (RFC 8705 §2).
    /// Carries the verification witness from
    /// [`crate::services::oidc::token::authenticate_client_mtls`].
    MutualTls(crate::services::oidc::token::MtlsCertVerification),

    /// No external client authentication was performed. Carries a
    /// [`NoClientAuth`] witness whose two named constructors document
    /// why client auth is absent — either the client is a registered
    /// public OAuth client (RFC 6749 §2.1), or the request originates
    /// from an internal flow where the server is both issuer and client
    /// (browser login, enrollment, device polling).
    NoAuth(NoClientAuth),
}

/// Witness justifying a [`ClientAuthProof::NoAuth`] variant. The two
/// named constructors split the legitimate cases:
///
/// - [`Self::for_public_client`] — the request carries a `client_id`
///   for a registered OAuth client whose `token_endpoint_auth_method`
///   is `None` (public client, RFC 6749 §2.1).
/// - [`Self::internal_endpoint`] — the request originates from a
///   server-internal endpoint (browser login, enrollment callbacks,
///   device-code polling) where there is no external OAuth client and
///   the server itself is the client.
///
/// A confidential client's grant arm cannot accidentally satisfy the
/// chokepoint with this witness — `for_public_client` rejects clients
/// registered with a non-`None` auth method, and `internal_endpoint`
/// is a grep-auditable explicit choice. Future grant arms for
/// confidential clients must construct `PrivateKeyJwt`, `ClientSecret`,
/// or `MutualTls` instead.
#[derive(Debug)]
pub(crate) struct NoClientAuth {
    _private: (),
}

impl NoClientAuth {
    /// Construct evidence that the request is for a public OAuth client
    /// (RFC 6749 §2.1 — `token_endpoint_auth_method = None`). Returns
    /// `Err` if the client is registered as confidential; in that case
    /// the caller must produce a real verification witness instead.
    pub(crate) fn for_public_client(
        client: &crate::db::OAuthClient,
    ) -> Result<Self, crate::error::ServiceError> {
        if client.token_endpoint_auth_method == crate::db::TokenEndpointAuthMethod::None {
            Ok(Self { _private: () })
        } else {
            Err(crate::error::ServiceError::oauth(
                crate::error::OAuthErrorCode::InvalidClient,
                "client authentication required",
            ))
        }
    }

    /// Construct evidence that the request originates from a
    /// server-internal endpoint where there is no external OAuth client.
    ///
    /// Use **only** for endpoints where the server is acting as both
    /// issuer and client — browser login, enrollment callbacks, device
    /// polling, certification test bypass. Adding new call sites is an
    /// audit-relevant decision: grep for this constructor before merging
    /// any change that introduces a new caller.
    pub(crate) fn internal_endpoint() -> Self {
        Self { _private: () }
    }
}

/// Proof that a PAR (RFC 9126) creation request has consumed its
/// client-authentication replay primitive. Required parameter to
/// [`crate::db::create_pushed_authorization_request`].
///
/// PAR does not issue an access token, so the [`TokenIssuanceProof`]
/// chokepoint does not fit. `ParCreationProof` is the analog for the
/// PAR-storage chokepoint: a caller must construct one before persisting
/// a PAR record, and the only path to a `ClientAuthProof::PrivateKeyJwt`
/// is via a committed [`crate::db::JwtAssertionJtiClaim`].
#[must_use = "the proof was constructed to authorize a single PAR creation; \
              dropping it without calling create_pushed_authorization_request \
              is a bug"]
#[derive(Debug)]
pub(crate) struct ParCreationProof {
    pub(crate) client_auth: ClientAuthProof,
}

/// JWT Access Token claims per RFC 9068 Section 2.2.
///
/// These claims are included in OAuth 2.0 access tokens signed with ES256.
/// The JWT header MUST have `typ: "at+jwt"` (RFC 9068 Section 2.1).
///
/// Note: `authenticator_id` is intentionally excluded from the JWT to
/// prevent information leakage. It is stored server-side in the sessions
/// table and looked up via the token hash.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AccessTokenClaims {
    /// RFC 9068 Section 2.2: REQUIRED. Issuer identifier (base_url).
    pub iss: String,
    /// RFC 9068 Section 2.2: REQUIRED. Subject identifier (user ID).
    pub sub: String,
    /// RFC 9068 Section 2.2: REQUIRED. Audience (client_id or target resource).
    pub aud: String,
    /// RFC 9068 Section 2.2: REQUIRED. Expiration time (Unix timestamp).
    pub exp: i64,
    /// RFC 9068 Section 2.2: REQUIRED. Issued at time (Unix timestamp).
    pub iat: i64,
    /// RFC 8725 §3.4: Not before time (set to iat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// RFC 9068 Section 2.2: REQUIRED. Unique token identifier.
    pub jti: String,
    /// RFC 9068 Section 2.2: REQUIRED. OAuth client that requested this token.
    pub client_id: String,
    /// RFC 6749 Section 3.3: Granted scope (space-separated in JWT).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeSet>,
    /// OIDC Core Section 5.1: User email (included when email scope is granted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// OIDC Core Section 5.1: Whether email has been verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Custom claim: FIDO2 hardware verification proof.
    #[serde(default)]
    pub hardware_verified: bool,
    /// RFC 9449 Section 6: DPoP confirmation (sender-constrained token binding).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<CnfClaim>,
    /// RFC 9068 Section 2.2: Time when the End-User authentication occurred.
    /// RECOMMENDED per OIDC Core Section 2. Reflects FIDO2 session creation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    /// RFC 8693 Section 4.1: Actor claim for delegation chains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<ActorClaim>,
    /// RFC 9068 Section 2.2 / RFC 8176: Authentication methods used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<AuthMethod>>,
    /// RFC 9068 Section 2.2: Authentication context class reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
}

/// Parameters for creating an OAuth access token (RFC 9068).
pub(crate) struct CreateOAuthTokenParams<'a> {
    /// User ID (stored as `sub` claim).
    pub user_id: &'a str,
    /// User email (included when email scope is granted).
    pub email: &'a str,
    /// Authenticator ID (stored server-side in session, NOT in the JWT).
    pub authenticator_id: Option<&'a str>,
    /// OAuth client_id that requested this token.
    pub client_id: &'a str,
    /// Granted OAuth scope.
    pub scope: Option<ScopeSet>,
    /// How this token is bound to its holder (RFC 9449 §6 / RFC 8705 §3).
    /// Taking the DPoP witness rather than a bare thumbprint means a
    /// sender-constrained token cannot be minted from a string that never
    /// passed signature, `htm`/`htu`, nonce, and replay validation.
    pub binding: TokenBinding<'a>,
    /// Actor claim for delegation chains (token exchange).
    pub act: Option<ActorClaim>,
    /// Optional audience override (for token exchange with explicit audience).
    /// When `None`, defaults to `client_id`.
    pub audience: Option<&'a str>,
    /// Authentication assurance level — bundles `hardware_verified`,
    /// `auth_time`, `amr`, and `acr` to prevent inconsistent combinations.
    /// The `auth_time` claim is derived from this field, so a token issued
    /// without a FIDO2 assertion cannot claim one.
    pub hardware_verification: HardwareVerification,
    /// Session purpose for the database record.
    pub session_purpose: SessionPurpose,
    /// RFC 9396: Rich authorization details (JSON array, stored in session).
    pub authorization_details: Option<&'a serde_json::Value>,
    /// AAGUID of the authenticator establishing this session (snapshot for
    /// federation claims). `None` for M2M and pre-FIDO2 enrollment sessions.
    pub hardware_aaguid: Option<&'a str>,
    /// Organization domain (`hd` claim) at session creation time.
    pub org_domain: Option<&'a str>,
    /// Hash of the single-use grant code that sourced this token. `None` for
    /// grants with no single-use code (FIDO2, client_credentials, token
    /// exchange, browser login, enrollment); `Some` for the authorization-code
    /// and device-code grants. Recorded on the session so that replay
    /// detection (RFC 6749 §10.5) can revoke only the tokens issued from the
    /// replayed code rather than every session for the user.
    pub source_code_hash: Option<&'a str>,
}

/// How an issued token is bound to the party that may present it.
///
/// One value decides both halves of sender-constraining: the `cnf` claim
/// stamped into the token and the `token_type` advertised for it. Deriving
/// them separately is what let the two disagree — six call sites each spelled
/// `if dpop.is_some() { DPoP } else { Bearer }` while `cnf` was built from a
/// different pair of options a layer away.
///
/// DPoP wins when a request carries both: the proof is per-request evidence of
/// possession, so it is the stronger statement about who holds this token, and
/// `cnf` has room for only one confirmation method (RFC 7800 §3.1).
#[derive(Debug, Clone, Copy)]
pub enum TokenBinding<'a> {
    /// RFC 9449 §6: bound to the DPoP proof's key, confirmed by `cnf.jkt`.
    Dpop(&'a ValidatedDpopProof),
    /// RFC 8705 §3: bound to the client certificate, confirmed by
    /// `cnf.x5t#S256`.
    MutualTls(&'a CertThumbprint),
    /// A bearer token: whoever holds it may present it.
    Bearer,
}

impl<'a> TokenBinding<'a> {
    /// Resolve the binding from the two things a request can carry. Both
    /// absent is a bearer token; both present is DPoP.
    #[must_use]
    pub fn new(
        dpop_proof: Option<&'a ValidatedDpopProof>,
        mtls_cert_thumbprint: Option<&'a CertThumbprint>,
    ) -> Self {
        match (dpop_proof, mtls_cert_thumbprint) {
            (Some(proof), _) => Self::Dpop(proof),
            (None, Some(thumbprint)) => Self::MutualTls(thumbprint),
            (None, None) => Self::Bearer,
        }
    }

    /// The confirmation claim this binding stamps into the token.
    #[must_use]
    pub fn cnf(self) -> Option<CnfClaim> {
        match self {
            Self::Dpop(proof) => Some(CnfClaim {
                jkt: Some(proof.jkt.clone()),
                x5t_s256: None,
            }),
            Self::MutualTls(thumbprint) => Some(CnfClaim {
                jkt: None,
                x5t_s256: Some(thumbprint.as_str().to_string()),
            }),
            Self::Bearer => None,
        }
    }

    /// The `token_type` advertised for a token carrying this binding, derived
    /// from the same `cnf` the token will carry.
    #[must_use]
    pub fn token_type(self) -> &'static str {
        self.cnf()
            .as_ref()
            .map_or(protocol::ACCESS_TOKEN_TYPE_BEARER, CnfClaim::token_type)
    }

    /// The DPoP proof, when this binding is one. Callers that record the
    /// binding server-side (session rows, introspection) need the thumbprint
    /// rather than the claim.
    #[must_use]
    pub fn dpop_proof(self) -> Option<&'a ValidatedDpopProof> {
        match self {
            Self::Dpop(proof) => Some(proof),
            Self::MutualTls(_) | Self::Bearer => None,
        }
    }
}

/// Result of creating a session token.
pub(crate) struct CreateSessionResult {
    /// The JWT token.
    pub token: SecretString,
    /// Token lifetime in seconds.
    pub expires_in: u64,
    /// RFC 6749 §5.1 `token_type`, derived from the binding stamped into the
    /// token so the advertisement cannot contradict the `cnf` claim.
    pub token_type: &'static str,
}

/// Create an OAuth 2.0 access token per RFC 9068.
///
/// Signs the token with ES256 using the OIDC signing key, making it
/// verifiable via the JWKS endpoint by third-party resource servers.
/// The `authenticator_id` is stored server-side in the session record
/// and NOT included in the JWT to prevent information leakage.
///
/// The `proof` parameter is a compile-time witness that the caller has
/// consumed the relevant single-use replay-prevention primitives in the
/// correct order. It is dropped immediately on entry — its only purpose
/// is to make the chokepoint unforgeable from outside the crate.
///
/// # Errors
///
/// Returns `ServiceError::Internal` if token signing or database operations fail.
pub(crate) async fn create_oauth_access_token(
    state: &AppState,
    params: CreateOAuthTokenParams<'_>,
    proof: TokenIssuanceProof,
) -> ServiceResult<CreateSessionResult> {
    // Consume the witness. Its presence is the structural guarantee that the
    // caller has consumed the required replay primitives — once consumed
    // here, the proof cannot be reused for another token issuance.
    //
    // `JwtAssertionJtiClaim` holds only `_private: ()` — the JTI string is
    // not retained in the witness, so the Debug log cannot leak it.
    let TokenIssuanceProof {
        grant,
        client_auth,
        sender_constraint,
    } = proof;
    tracing::debug!(
        ?grant,
        ?client_auth,
        ?sender_constraint,
        "token issuance proof consumed"
    );

    let now = Timestamp::now();
    let session_hours = i64::try_from(state.config().session_hours)
        .map_err(|_| ServiceError::Internal("Invalid session hours".to_string()))?;
    let duration = Span::new().hours(session_hours);
    let expires = now
        .checked_add(duration)
        .map_err(|_| ServiceError::Internal("Time overflow".to_string()))?;

    // RFC 9068 Section 2.2: jti MUST be a unique identifier
    let jti = Uuid::now_v7().to_string();

    // Determine audience: explicit audience (token exchange) or client_id
    let aud = params.audience.unwrap_or(params.client_id).to_string();

    // Include email claims when email scope is granted
    let has_email_scope = params
        .scope
        .as_ref()
        .is_some_and(|s| s.contains(crate::services::oidc::OAuthScope::Email));

    // RFC 9449 / RFC 8705: the binding decides the confirmation claim and the
    // advertised token type together.
    let cnf = params.binding.cnf();

    let claims = AccessTokenClaims {
        iss: state.config().base_url.to_string(),
        sub: params.user_id.to_string(),
        aud,
        exp: expires.as_second(),
        iat: now.as_second(),
        nbf: Some(now.as_second()),
        jti,
        client_id: params.client_id.to_string(),
        scope: params.scope.clone(),
        email: if has_email_scope {
            Some(params.email.to_string())
        } else {
            None
        },
        email_verified: if has_email_scope { Some(true) } else { None },
        hardware_verified: params.hardware_verification.hardware_verified(),
        cnf,
        auth_time: params.hardware_verification.auth_time(),
        act: params.act,
        amr: params.hardware_verification.amr(),
        acr: params.hardware_verification.acr(),
    };

    let token = state
        .oidc_key
        .sign_access_token_jwt(&claims)
        .await
        .map_err(|e| ServiceError::Internal(format!("Access token signing failed: {e}")))?;

    // Store session in database (authenticator_id is server-side only)
    let token_hash = hash_token(&token);
    db::create_session(
        &state.store,
        &db::CreateSessionParams {
            user_id: params.user_id,
            user_email: params.email,
            token_hash: &token_hash,
            authenticator_id: params.authenticator_id,
            expires_at: expires,
            session_type: params.session_purpose,
            authorization_details: params.authorization_details,
            hardware_aaguid: params.hardware_aaguid,
            org_domain: params.org_domain,
            source_code_hash: params.source_code_hash,
        },
    )
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to store session: {e}")))?;

    let expires_in = state.config().session_hours.saturating_mul(3600);

    Ok(CreateSessionResult {
        token_type: params.binding.token_type(),
        token: SecretString::from(token),
        expires_in,
    })
}

/// Decoded JWT token — an RFC 9068 OAuth access token (ES256, `at+jwt`).
pub(crate) enum DecodedToken {
    /// OAuth 2.0 access token (ES256, RFC 9068).
    AccessToken(AccessTokenClaims),
}

impl DecodedToken {
    /// RFC 7519 Section 4.1.2: Subject claim.
    #[must_use]
    pub(crate) fn sub(&self) -> &str {
        match self {
            Self::AccessToken(c) => &c.sub,
        }
    }

    /// User email. Returns `None` for access tokens without email scope.
    #[must_use]
    pub(crate) fn email(&self) -> Option<&str> {
        match self {
            Self::AccessToken(c) => c.email.as_deref(),
        }
    }

    /// RFC 6749 Section 3.3: Granted scope.
    #[must_use]
    pub(crate) fn scope(&self) -> Option<&ScopeSet> {
        match self {
            Self::AccessToken(c) => c.scope.as_ref(),
        }
    }

    /// DPoP confirmation claim (None for non-DPoP tokens).
    #[must_use]
    pub(crate) fn cnf(&self) -> Option<&CnfClaim> {
        match self {
            Self::AccessToken(c) => c.cnf.as_ref(),
        }
    }

    /// RFC 7519 Section 4.1.4: Expiration time (Unix timestamp).
    #[must_use]
    pub(crate) fn exp(&self) -> Option<i64> {
        match self {
            Self::AccessToken(c) => Some(c.exp),
        }
    }

    /// RFC 8693 Section 4.1: Actor claim for delegation chains.
    /// Only present in access tokens that resulted from token exchange.
    #[must_use]
    pub(crate) fn act(&self) -> Option<&ActorClaim> {
        match self {
            Self::AccessToken(c) => c.act.as_ref(),
        }
    }

    /// Reconstruct the hardware verification level from token claims.
    ///
    /// `auth_time` is deliberately not carried over: the reconstruction
    /// describes a token being minted *from* this one, and that token runs no
    /// assertion of its own. Inheriting the instant would let a derived token
    /// satisfy a freshness gate on a ceremony it never performed.
    #[must_use]
    pub(crate) fn hardware_verification(&self) -> HardwareVerification {
        match self {
            Self::AccessToken(c) if c.hardware_verified => {
                HardwareVerification::Verified { auth_time: None }
            }
            Self::AccessToken(_) => HardwareVerification::NotVerified,
        }
    }
}

/// Validated OAuth resource token information.
///
/// Produced by the HTTP-side extractors in `handlers::session`
/// (`extract_resource_token` and friends) after ES256 `at+jwt` decoding,
/// session lookup, and DPoP validation; consumed by handlers and by
/// integrations that read the federation snapshot (e.g. AWS WIF).
#[derive(Debug)]
#[allow(dead_code, reason = "fields populated for diagnostic / future use")]
pub(crate) struct ValidatedResourceToken {
    /// User ID (`sub` claim from the access token).
    pub sub: String,
    /// User email (from `email` claim if present, or DB lookup).
    pub email: Option<String>,
    /// OAuth client_id from the access token.
    pub client_id: String,
    /// Audience (`aud` claim) from the access token. Equals `client_id`
    /// for un-narrowed tokens; a resource URI for tokens narrowed via
    /// RFC 8707 `resource` or RFC 8693 `audience`. Audience coverage has
    /// already been enforced by `extract_resource_token`.
    pub aud: String,
    /// Granted OAuth scope.
    pub scope: Option<crate::services::oidc::ScopeSet>,
    /// Authenticator ID from the server-side session record (not in JWT).
    ///
    /// Presence merely means a key is registered to the user — it does
    /// **not** prove the current session was hardware-verified. For that,
    /// gate on [`Self::hardware_verified`] instead.
    pub authenticator_id: Option<String>,
    /// FIDO2 hardware-verification claim from the access token. `true`
    /// only when the session was minted via the FIDO2 grant; `false` for
    /// bootstrap/enrollment sessions. Used to gate credential issuance
    /// that asserts hardware verification downstream (e.g. AWS WIF).
    pub hardware_verified: bool,
    /// Authentication time (`auth_time` claim).
    pub auth_time: Option<i64>,
    /// SHA-256 hash of the access token (for DB lookups/revocation).
    pub token_hash: String,
    /// AI coding agent identifier from DPoP proof custom claim (e.g., "claude-code").
    pub dpop_source: Option<String>,
    /// AAGUID snapshot from the session record (federation claim).
    pub hardware_aaguid: Option<String>,
    /// Organization domain snapshot from the session record (`hd` claim).
    pub org_domain: Option<String>,
}

/// Decode a JWT as an RFC 9068 ES256 access token.
///
/// This is a convenience wrapper around
/// [`crate::crypto::jwt::decode_es256_token`] that constructs a
/// [`TokenValidationContext`] and instantiates the [`AccessTokenClaims`]
/// schema.
///
/// Validates `typ` and `iss` per RFC 8725.
///
/// Returns `None` for invalid, expired, or unsupported tokens.
pub(crate) fn decode_token(
    token: &str,
    oidc_key: &OidcSigningKey,
    expected_issuer: &str,
) -> Option<DecodedToken> {
    let ctx = crate::crypto::jwt::TokenValidationContext::new(oidc_key, expected_issuer);
    let claims: AccessTokenClaims = crate::crypto::jwt::decode_es256_token(token, &ctx)?;
    Some(DecodedToken::AccessToken(claims))
}

/// Revoke every credential that lets a user keep acting after their access is
/// withdrawn: active sessions, issued SSH certificates, and the stored GitHub
/// refresh token.
///
/// Every write propagates. A caller that reports the withdrawal as successful
/// while one of these failed tells the operator (or the IdP) that access is
/// gone when it is not: an unrevoked certificate appears on no KRL, and
/// `revoke_all_ssh_certificates_for_user` is the only server-side lever there
/// is. Returning an error lets the caller surface a 5xx so the request is
/// retried.
///
/// `reason` and `revoked_by` are recorded on the revocation records.
///
/// # Errors
///
/// Returns [`ServiceError`] if any of the three writes fails. Earlier writes
/// are not rolled back; each is individually idempotent, so retrying the whole
/// operation converges.
pub(crate) async fn revoke_user_access(
    state: &AppState,
    user_id: &str,
    reason: &str,
    revoked_by: &str,
) -> Result<(), ServiceError> {
    db::delete_sessions_for_user(&state.store, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete sessions for {user_id}: {e}");
            ServiceError::Internal("failed to delete sessions".to_string())
        })?;
    state.session_cache.invalidate_for_user(user_id);

    db::revoke_user_credentials(&state.store, user_id, Some(reason), Some(revoked_by))
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke credentials for {user_id}: {e}");
            ServiceError::Internal("failed to revoke user credentials".to_string())
        })?;

    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::test_utils::{TEST_ISSUER, make_test_access_token, make_test_oidc_key};

    #[tokio::test]
    async fn test_decode_token_routes_es256_to_access_token() {
        let key = make_test_oidc_key();
        let token = make_test_access_token(&key).await;

        let decoded = decode_token(&token, &key, TEST_ISSUER);
        assert!(decoded.is_some());
        match decoded.unwrap() {
            DecodedToken::AccessToken(c) => {
                assert_eq!(c.sub, "user-123");
                assert_eq!(c.client_id, "client-abc");
                assert_eq!(c.email.as_deref(), Some("test@example.com"));
            }
        }
    }

    #[tokio::test]
    async fn test_decode_token_rejects_id_token_without_at_jwt_typ() {
        // An ES256 JWT signed with the OIDC key but with typ: "JWT" (ID token)
        // should NOT be decoded as an access token.
        let key = make_test_oidc_key();

        let claims = AccessTokenClaims {
            iss: TEST_ISSUER.to_string(),
            sub: "user-123".to_string(),
            aud: "client-abc".to_string(),
            exp: 9_999_999_999,
            iat: 1_000_000_000,
            nbf: None,
            jti: "jti-1".to_string(),
            client_id: "client-abc".to_string(),
            scope: None,
            email: None,
            email_verified: None,
            hardware_verified: false,
            cnf: None,
            auth_time: None,
            act: None,
            amr: None,
            acr: None,
        };

        // Sign as ID token (typ: "JWT", no "at+jwt")
        let token = key.sign_jwt(&claims).await.expect("sign");

        let decoded = decode_token(&token, &key, TEST_ISSUER);
        assert!(decoded.is_none(), "ID token should be rejected");
    }

    #[test]
    fn test_decode_token_rejects_garbage() {
        let key = make_test_oidc_key();
        assert!(decode_token("not.a.jwt", &key, TEST_ISSUER).is_none());
        assert!(decode_token("", &key, TEST_ISSUER).is_none());
        assert!(decode_token("abc123", &key, TEST_ISSUER).is_none());
    }

    #[tokio::test]
    async fn test_decode_token_rejects_expired_access_token() {
        let key = make_test_oidc_key();

        let claims = AccessTokenClaims {
            iss: TEST_ISSUER.to_string(),
            sub: "user-123".to_string(),
            aud: "client-abc".to_string(),
            exp: 1, // Expired in 1970
            iat: 0,
            nbf: None,
            jti: "jti-1".to_string(),
            client_id: "client-abc".to_string(),
            scope: None,
            email: None,
            email_verified: None,
            hardware_verified: false,
            cnf: None,
            auth_time: None,
            act: None,
            amr: None,
            acr: None,
        };

        let token = key.sign_access_token_jwt(&claims).await.expect("sign");
        let decoded = decode_token(&token, &key, TEST_ISSUER);
        assert!(decoded.is_none(), "Expired token should be rejected");
    }

    #[tokio::test]
    async fn test_decoded_token_accessors() {
        let key = make_test_oidc_key();
        let token = make_test_access_token(&key).await;
        let decoded = decode_token(&token, &key, TEST_ISSUER).unwrap();

        assert_eq!(decoded.sub(), "user-123");
        assert_eq!(decoded.email(), Some("test@example.com"));
        assert!(decoded.scope().is_some());
        assert!(decoded.cnf().is_none());
        assert!(decoded.act().is_none());
    }

    #[test]
    fn test_actor_claim_depth() {
        let single = ActorClaim {
            sub: "a@example.com".to_string(),
            actor: None,
        };
        assert_eq!(single.depth(), 1);

        let nested = ActorClaim {
            sub: "b@example.com".to_string(),
            actor: Some(Box::new(ActorClaim {
                sub: "a@example.com".to_string(),
                actor: None,
            })),
        };
        assert_eq!(nested.depth(), 2);

        let deep = ActorClaim {
            sub: "c@example.com".to_string(),
            actor: Some(Box::new(ActorClaim {
                sub: "b@example.com".to_string(),
                actor: Some(Box::new(ActorClaim {
                    sub: "a@example.com".to_string(),
                    actor: None,
                })),
            })),
        };
        assert_eq!(deep.depth(), 3);
    }

    #[test]
    fn test_actor_claim_depth_exceeds_max() {
        // Build a chain of MAX_DELEGATION_DEPTH + 1
        let mut actor = ActorClaim {
            sub: "leaf@example.com".to_string(),
            actor: None,
        };
        for i in 0..MAX_DELEGATION_DEPTH {
            actor = ActorClaim {
                sub: format!("actor-{i}@example.com"),
                actor: Some(Box::new(actor)),
            };
        }
        assert!(actor.depth() > MAX_DELEGATION_DEPTH);
    }

    // AMR tests (RFC 8176)

    #[test]
    fn test_auth_method_wire_format() {
        assert_eq!(AuthMethod::HardwareKey.as_str(), "hwk");
        assert_eq!(AuthMethod::Pin.as_str(), "pin");
        assert_eq!(AuthMethod::UserPresence.as_str(), "user");
    }

    #[test]
    fn test_all_fido2() {
        let methods = AuthMethod::all_fido2();
        assert_eq!(methods.len(), 3);
        assert_eq!(methods[0], AuthMethod::HardwareKey);
        assert_eq!(methods[1], AuthMethod::Pin);
        assert_eq!(methods[2], AuthMethod::UserPresence);
    }

    #[test]
    fn test_auth_method_serde_roundtrip() {
        let methods: Vec<AuthMethod> = AuthMethod::all_fido2().to_vec();
        let json = serde_json::to_string(&methods).unwrap();
        assert_eq!(json, r#"["hwk","pin","user"]"#);

        let deserialized: Vec<AuthMethod> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, methods);
    }

    #[test]
    fn test_auth_method_deserialize_rejects_unknown() {
        let result: Result<AuthMethod, _> = serde_json::from_str(r#""mfa""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_auth_method_display() {
        assert_eq!(format!("{}", AuthMethod::HardwareKey), "hwk");
        assert_eq!(format!("{}", AuthMethod::Pin), "pin");
        assert_eq!(format!("{}", AuthMethod::UserPresence), "user");
    }

    /// The claim mapping the browser-enrollment regression test from #1124
    /// used to assert end to end. Registration now requires an attestation
    /// chain no test can mint, so the mapping is pinned here instead.
    #[test]
    fn test_verified_hardware_sets_amr_acr_and_flag() {
        let verified = HardwareVerification::Verified {
            auth_time: Some(42),
        };
        assert!(verified.hardware_verified());
        assert_eq!(verified.acr().as_deref(), Some(ACR_AAL3));
        let amr = verified.amr().expect("Verified must set amr");
        for expected in AuthMethod::all_fido2() {
            assert!(
                amr.contains(expected),
                "amr must include {expected:?}, got {amr:?}"
            );
        }

        // The negative half: without a FIDO2 ceremony none of the three are
        // asserted, so a machine token cannot look like a hardware login.
        let not_verified = HardwareVerification::NotVerified;
        assert!(!not_verified.hardware_verified());
        assert!(not_verified.amr().is_none());
        assert!(not_verified.acr().is_none());
    }

    #[test]
    fn test_acr_aal3_constant() {
        assert!(ACR_AAL3.starts_with("urn:nist:"));
        assert!(ACR_AAL3.contains("aal3"));
    }

    #[test]
    fn test_access_token_claims_optional_fields_omitted() {
        let claims = AccessTokenClaims {
            iss: "https://example.com".to_string(),
            sub: "user-123".to_string(),
            aud: "client-abc".to_string(),
            exp: 9_999_999_999,
            iat: 1_000_000_000,
            nbf: None,
            jti: "jti-1".to_string(),
            client_id: "client-abc".to_string(),
            scope: None,
            email: None,
            email_verified: None,
            hardware_verified: false,
            cnf: None,
            auth_time: None,
            act: None,
            amr: None,
            acr: None,
        };

        let json = serde_json::to_string(&claims).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");

        // Optional None fields should not be present
        assert!(parsed.get("scope").is_none());
        assert!(parsed.get("email").is_none());
        assert!(parsed.get("email_verified").is_none());
        assert!(parsed.get("cnf").is_none());
        assert!(parsed.get("auth_time").is_none());
        assert!(parsed.get("act").is_none());
        assert!(parsed.get("amr").is_none());
        assert!(parsed.get("acr").is_none());
        // Required fields should be present
        assert_eq!(parsed["iss"], "https://example.com");
        assert_eq!(parsed["sub"], "user-123");
    }

    // Regression for #392: `verify_login_assertion` must honor the
    // caller-supplied `expected_origin` rather than deriving it from
    // `rp_id`. This matters when `base_url` is a subdomain of `rp_id`
    // (e.g. `https://idp.example.com` for `rp_id=example.com`), a
    // configuration `webauthn-rs` accepts and browsers report as the
    // page origin in `clientDataJSON.origin`.
    #[tokio::test]
    async fn test_verify_login_assertion_honors_expected_origin_subdomain() {
        use aws_lc_rs::digest::{SHA256, digest};

        let rp_id = "example.com";
        let expected_origin = "https://idp.example.com";
        let challenge: Vec<u8> = b"regression-test-challenge".to_vec();

        // Minimal valid authData: rpIdHash || flags(UP|UV) || counter
        let rp_id_hash = digest(&SHA256, rp_id.as_bytes());
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(rp_id_hash.as_ref());
        auth_data.push(0x05); // UP + UV
        auth_data.extend_from_slice(&[0, 0, 0, 1]); // counter = 1

        let challenge_b64 = URL_SAFE_NO_PAD.encode(&challenge);
        let client_data_json = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge_b64,
            "origin": expected_origin,
        })
        .to_string()
        .into_bytes();

        let params = LoginAssertionParams {
            authenticator_data: auth_data,
            client_data_json,
            signature: vec![0u8; 64],
            // Bogus 32-byte COSE key — signature verification will fail,
            // but only AFTER the origin check, which is what we're testing.
            public_key: vec![0u8; 32],
            rp_id: rp_id.to_string(),
            expected_origin: expected_origin.to_string(),
            challenge,
            stored_counter: 0,
            // Exact-match origins here; relaxation is irrelevant to this test.
            origin_policy: OriginPolicy::Strict,
        };

        let err = verify_login_assertion(params)
            .await
            .err()
            .expect("expected error — signature is bogus");
        let description = match &err {
            ServiceError::OAuth { description, .. } => description.clone(),
            other => format!("unexpected error variant: {other}"),
        };
        assert!(
            !description.contains("Invalid origin"),
            "origin must not be rejected for valid subdomain config; got: {description}"
        );
    }
}
