// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authorization code flow operations.
//!
//! Implements:
//! - RFC 6749 Section 4.1 - Authorization Code Grant
//! - RFC 7636 - PKCE (Proof Key for Code Exchange)

use crate::AppState;
use crate::crypto::jwt::JwtType;
use crate::db::{
    AccessScope, Authenticator, OAuthClient, ParConsumptionProof, ResponseMode, Session,
    TokenEndpointAuthMethod, User,
};
use crate::error::{OAuthErrorCode, ServiceError, ServiceResult};
use crate::services::oidc::ScopeSet;
use jiff::{Span, Timestamp};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;

use super::token::validate_session_token;

/// PKCE code challenge method (RFC 7636 Section 4.2).
///
/// Only `S256` is supported per RFC 9700 Section 2.1.1: "Clients MUST use
/// `code_challenge_method` value `S256`." The `plain` method is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeChallengeMethod {
    /// SHA-256 transformation: `BASE64URL(SHA256(code_verifier))`.
    /// RFC 7636 Section 4.2.
    #[serde(rename = "S256")]
    S256,
}

impl CodeChallengeMethod {
    /// Every accepted `code_challenge_method`, in the order advertised in
    /// discovery metadata (`code_challenge_methods_supported`).
    /// [`parse`](Self::parse) reads this table, so an advertised method
    /// cannot be unparseable.
    pub const SUPPORTED: &'static [Self] = &[Self::S256];

    /// Parse a code challenge method from a string value.
    ///
    /// Only `S256` is accepted per RFC 9700. Returns `None` for `plain`
    /// and all other unsupported methods.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::SUPPORTED.iter().copied().find(|m| m.as_str() == s)
    }

    /// Return the string representation used in OAuth parameters.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::S256 => "S256",
        }
    }
}

impl fmt::Display for CodeChallengeMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// OIDC Core Section 3.1.2.1: Prompt parameter values.
///
/// Controls whether the authorization server prompts the user for re-authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Prompt {
    /// Force the user to re-authenticate even if they have a valid session.
    #[serde(rename = "login")]
    Login,
    /// Do not display any authentication UI. Return an error if the user
    /// is not already authenticated.
    ///
    /// Named `Silent` (not `None`) to avoid ambiguity with `Option::None`.
    #[serde(rename = "none")]
    Silent,
    /// Request user consent. Vouch has no consent screen, so this is
    /// treated as a normal authentication flow (no-op).
    #[serde(rename = "consent")]
    Consent,
}

impl Prompt {
    /// Every value OIDC Core Section 3.1.2.1 defines, paired with the
    /// behavior Vouch offers for it.
    ///
    /// `select_account` is defined by the specification but has no `Prompt`
    /// variant: Vouch authenticates a single identity per session and has no
    /// account chooser, so it can never obtain the account selection the
    /// value asks for. Section 3.1.2.1 covers exactly that case — "If it
    /// cannot obtain an account selection choice made by the End-User, it
    /// MUST return an error, typically `account_selection_required`" — which
    /// is why it is listed here as defined-but-unhonored rather than left out
    /// to be reported as an unrecognized value.
    ///
    /// [`PromptSet::parse`] and [`supported_values`](Self::supported_values)
    /// both read this table, so an honored value cannot be missing from the
    /// error message that lists them and a listed value cannot be
    /// unparseable. Keeping them as separate literals is how the message came
    /// to advertise fewer values than the parser accepted.
    const DEFINED: &'static [(&'static str, Option<Self>)] = &[
        ("login", Some(Self::Login)),
        ("none", Some(Self::Silent)),
        ("consent", Some(Self::Consent)),
        ("select_account", None),
    ];

    /// Comma-separated list of the honored values, for error messages.
    #[must_use]
    pub fn supported_values() -> String {
        Self::DEFINED
            .iter()
            .filter(|(_, prompt)| prompt.is_some())
            .map(|(value, _)| *value)
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Return the string representation used in OAuth parameters.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Silent => "none",
            Self::Consent => "consent",
        }
    }
}

impl fmt::Display for Prompt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The set of values carried by one `prompt` parameter.
///
/// OIDC Core Section 3.1.2.1 defines `prompt` as a "Space-delimited,
/// case-sensitive list of ASCII string values", so `prompt=login consent` is
/// a single request for two behaviors rather than an unrecognized value. The
/// set is the parsed form of that list; [`parse`](Self::parse) is the only
/// way to build one, so a `PromptSet` in hand has already been checked
/// against every rule the section states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PromptSet {
    login: bool,
    silent: bool,
    consent: bool,
}

impl PromptSet {
    /// Parse the `prompt` request parameter.
    ///
    /// # Errors
    ///
    /// - `account_selection_required` when `select_account` is requested, per
    ///   the OIDC Core Section 3.1.2.1 sentence quoted on [`Prompt::DEFINED`].
    ///   Callers that cannot return a user-interaction error code — the PAR
    ///   endpoint, per RFC 9126 Section 2.3 — translate it at their boundary.
    /// - `invalid_request` when `none` appears alongside another value:
    ///   "If this parameter contains `none` with any other value, an error is
    ///   returned."
    /// - `invalid_request` for a value outside the defined set. The same
    ///   section permits either answer — "it MAY return an error or it MAY
    ///   ignore it" — and Vouch returns one so that a client learns its
    ///   request was not understood.
    pub fn parse(raw: &str) -> ServiceResult<Self> {
        let mut set = Self::default();
        let mut others = false;

        for token in raw.split_whitespace() {
            match Prompt::DEFINED.iter().find(|(value, _)| *value == token) {
                Some((_, Some(Prompt::Login))) => {
                    set.login = true;
                    others = true;
                }
                Some((_, Some(Prompt::Silent))) => set.silent = true,
                Some((_, Some(Prompt::Consent))) => {
                    set.consent = true;
                    others = true;
                }
                Some((_, None)) => {
                    return Err(ServiceError::oauth(
                        OAuthErrorCode::AccountSelectionRequired,
                        "prompt=select_account is not supported: this authorization server \
                         authenticates a single account per session",
                    ));
                }
                None => {
                    return Err(ServiceError::oauth(
                        OAuthErrorCode::InvalidRequest,
                        format!(
                            "Unsupported prompt value. Supported values: {}",
                            Prompt::supported_values()
                        ),
                    ));
                }
            }
        }

        if set.silent && others {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequest,
                "prompt=none must not be combined with other prompt values",
            ));
        }

        Ok(set)
    }

    /// A set holding exactly one value.
    #[must_use]
    pub fn of(prompt: Prompt) -> Self {
        let mut set = Self::default();
        match prompt {
            Prompt::Login => set.login = true,
            Prompt::Silent => set.silent = true,
            Prompt::Consent => set.consent = true,
        }
        set
    }

    /// Whether the request asked for this behavior.
    #[must_use]
    pub fn contains(self, prompt: Prompt) -> bool {
        match prompt {
            Prompt::Login => self.login,
            Prompt::Silent => self.silent,
            Prompt::Consent => self.consent,
        }
    }

    /// Whether the parameter carried no values at all.
    #[must_use]
    pub fn is_empty(self) -> bool {
        !self.login && !self.silent && !self.consent
    }

    /// The set in the wire form `prompt` uses, for storage and re-parsing.
    #[must_use]
    pub fn to_space_separated(self) -> String {
        let mut values = Vec::new();
        for (value, prompt) in Prompt::DEFINED {
            if prompt.is_some_and(|p| self.contains(p)) {
                values.push(*value);
            }
        }
        values.join(" ")
    }
}

impl fmt::Display for PromptSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_space_separated())
    }
}

/// Resolve the `response_mode` request parameter into the mode the
/// authorization response will use.
///
/// An absent parameter yields the default for the `code` response type
/// (OAuth 2.0 Multiple Response Type Encoding Practices Section 2.1: "For
/// purposes of this specification, the default Response Mode for the OAuth
/// 2.0 `code` Response Type is the `query` encoding").
///
/// Every entry point that turns a client-supplied `response_mode` into a
/// [`ResponseMode`] goes through here, because the alternative — reading
/// [`ResponseMode::parse`] and substituting the default when it returns
/// `None` — silently answers a `form_post` or `jwt` request with a bare query
/// redirect, delivering the authorization code by a mechanism the client is
/// not listening on. The specification says nothing about unrecognized
/// values, so rejecting one is our decision rather than a requirement; it is
/// the one answer that cannot hand a client a response it will not see.
///
/// # Errors
///
/// Returns `invalid_request` when the value is not a supported mode.
pub fn parse_response_mode(value: Option<&str>) -> ServiceResult<ResponseMode> {
    let Some(value) = value else {
        return Ok(ResponseMode::Query);
    };
    ResponseMode::parse(value).ok_or_else(|| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidRequest,
            format!(
                "Unsupported response_mode. Supported values: {}",
                ResponseMode::supported_values()
            ),
        )
    })
}

/// Parameters for creating an authorization code.
#[derive(Debug)]
pub struct AuthorizationCodeParams<'a> {
    /// The client ID requesting authorization.
    pub client_id: &'a str,
    /// The redirect URI for the response.
    pub redirect_uri: &'a str,
    /// User ID to authorize.
    pub user_id: &'a str,
    /// User email.
    pub email: &'a str,
    /// Authenticator ID used for authentication.
    pub authenticator_id: &'a str,
    /// Authenticator AAGUID.
    pub aaguid: Option<&'a str>,
    /// Requested scope.
    pub scope: &'a ScopeSet,
    /// OIDC nonce.
    pub nonce: Option<&'a str>,
    /// PKCE code challenge (RFC 7636 Section 4.2).
    pub code_challenge: Option<&'a str>,
    /// PKCE code challenge method (RFC 7636 Section 4.2).
    pub code_challenge_method: Option<CodeChallengeMethod>,
    /// RFC 8707: Target resource indicator.
    pub resource: Option<&'a str>,
    /// RFC 9470: Requested ACR values.
    pub acr_values: Option<&'a str>,
    /// RFC 9449 / FAPI 2.0: DPoP key thumbprint bound at PAR time.
    ///
    /// When present, the same DPoP key must be used at the token endpoint
    /// (verified in `exchange_authorization_code`).
    pub dpop_jkt: Option<&'a str>,
    /// Authorization code lifetime in seconds.
    ///
    /// FAPI 2.0 clients use 60s; standard clients use 300s.
    /// Use `fapi::auth_code_lifetime_seconds(&client)` to compute the correct value.
    pub auth_code_lifetime_seconds: i64,
    /// RFC 9396: Rich authorization details (JSON value for server-side storage).
    pub authorization_details: Option<&'a serde_json::Value>,
    /// OIDC Core Section 2: Time when the End-User authentication occurred.
    ///
    /// This should be the session's `created_at` timestamp so that `auth_time`
    /// in the id_token reflects the actual authentication event, not code issuance.
    /// When `None`, falls back to the code's `iat`.
    pub auth_time: Option<i64>,
    /// RFC 9126: proof that the pushed authorization request backing this
    /// authorization was consumed, or that the request was never pushed.
    ///
    /// Naming it here means every code-issuing flow has to say which case it
    /// is in: a flow holding a `request_uri` can only obtain the proof from
    /// [`ParConsumptionProof::consume`], so it cannot issue a code and leave
    /// the `request_uri` replayable for the rest of its lifetime.
    pub par: ParConsumptionProof,
}

/// Authorization request parameters (from query string).
#[derive(Debug)]
pub struct AuthorizeRequestParams {
    /// Response type (must be "code") — RFC 6749 Section 4.1.1.
    pub response_type: String,
    /// Client ID — RFC 6749 Section 4.1.1.
    pub client_id: String,
    /// Redirect URI — RFC 6749 Section 4.1.1.
    pub redirect_uri: String,
    /// Requested scope — RFC 6749 Section 3.3.
    pub scope: Option<String>,
    /// State parameter (opaque to server) — RFC 6749 Section 4.1.1.
    pub state: Option<String>,
    /// OIDC nonce — OIDC Core Section 3.1.2.1.
    pub nonce: Option<String>,
    /// PKCE code challenge — RFC 7636 Section 4.2.
    pub code_challenge: Option<String>,
    /// PKCE code challenge method (raw string from request, validated into enum).
    /// RFC 7636 Section 4.3.
    pub code_challenge_method: Option<String>,
    /// RFC 8707 Section 2: Target resource indicator.
    pub resource: Option<String>,
    /// RFC 9470: Requested authentication context class references.
    pub acr_values: Option<String>,
    /// RFC 9470 / OIDC Core Section 3.1.2.1: Maximum authentication age in seconds.
    pub max_age: Option<u64>,
    /// OIDC Core Section 3.1.2.1: Requested prompt behavior (raw
    /// space-delimited string from the request, validated into a
    /// [`PromptSet`]).
    pub prompt: Option<String>,
    /// RFC 9449 Section 10: DPoP JWK thumbprint for authorization code binding.
    pub dpop_jkt: Option<String>,
    /// RFC 9396: Rich authorization details (raw JSON string from request).
    pub authorization_details: Option<String>,
    /// JARM (oauth-v2-jarm): Requested authorization response mode.
    pub response_mode: Option<String>,
}

/// Validated authorization request ready for code issuance.
///
/// Fields are private to ensure this struct can only be constructed via
/// [`validate_authorize_request()`], guaranteeing all invariants are met.
#[derive(Debug)]
pub struct ValidatedAuthRequest {
    client_id: String,
    redirect_uri: String,
    scope: ScopeSet,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<CodeChallengeMethod>,
    /// RFC 8707: Validated resource indicator.
    resource: Option<String>,
    /// RFC 9470: Requested ACR values.
    acr_values: Option<String>,
    /// RFC 9470: Maximum authentication age in seconds.
    max_age: Option<u64>,
    /// OIDC Core: Requested prompt behavior.
    prompt: Option<PromptSet>,
    /// RFC 9449 Section 10: DPoP JWK thumbprint for authorization code binding.
    dpop_jkt: Option<String>,
    /// RFC 9396: Validated authorization details.
    authorization_details: Option<super::authorization_details::AuthorizationDetails>,
}

impl ValidatedAuthRequest {
    /// Client ID.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Redirect URI.
    #[must_use]
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Requested scope.
    #[must_use]
    pub fn scope(&self) -> &ScopeSet {
        &self.scope
    }

    /// State parameter.
    #[must_use]
    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    /// OIDC nonce.
    #[must_use]
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    /// PKCE code challenge (RFC 7636 Section 4.2).
    #[must_use]
    pub fn code_challenge(&self) -> Option<&str> {
        self.code_challenge.as_deref()
    }

    /// PKCE code challenge method (RFC 7636 Section 4.2).
    #[must_use]
    pub fn code_challenge_method(&self) -> Option<CodeChallengeMethod> {
        self.code_challenge_method
    }

    /// RFC 8707: Resource indicator.
    #[must_use]
    pub fn resource(&self) -> Option<&str> {
        self.resource.as_deref()
    }

    /// RFC 9470: Requested ACR values.
    #[must_use]
    pub fn acr_values(&self) -> Option<&str> {
        self.acr_values.as_deref()
    }

    /// RFC 9470: Maximum authentication age in seconds.
    #[must_use]
    pub fn max_age(&self) -> Option<u64> {
        self.max_age
    }

    /// OIDC Core: Requested prompt behavior.
    #[must_use]
    pub fn prompt(&self) -> Option<PromptSet> {
        self.prompt
    }

    /// Whether the request asked for a particular prompt behavior.
    ///
    /// `prompt` is a list, so asking whether it *equals* one value is the
    /// wrong question: `prompt=login consent` asks for `login` just as much
    /// as `prompt=login` does.
    #[must_use]
    pub fn has_prompt(&self, prompt: Prompt) -> bool {
        self.prompt.is_some_and(|set| set.contains(prompt))
    }

    /// RFC 9449 Section 10: DPoP JWK thumbprint.
    #[must_use]
    pub fn dpop_jkt(&self) -> Option<&str> {
        self.dpop_jkt.as_deref()
    }

    /// RFC 9396: Validated authorization details.
    #[must_use]
    pub fn authorization_details(
        &self,
    ) -> Option<&super::authorization_details::AuthorizationDetails> {
        self.authorization_details.as_ref()
    }

    /// RFC 9396: Validated authorization details as a JSON value.
    #[must_use]
    pub fn authorization_details_value(&self) -> Option<serde_json::Value> {
        self.authorization_details
            .as_ref()
            .map(serde_json::Value::from)
    }
}

/// Result of checking session state for authorization.
pub enum AuthorizationSessionState {
    /// User is authenticated with valid session.
    Authenticated {
        /// The authenticated user.
        user: Box<User>,
        /// The session.
        session: Box<Session>,
        /// The authenticator used.
        authenticator: Box<Authenticator>,
        /// When the session's FIDO2 ceremony happened, from the access
        /// token's `auth_time` claim — the value the issued code reports as
        /// `auth_time` and the `max_age` decision measures from.
        ///
        /// `None` for a session whose verification was inherited rather than
        /// observed (RFC 8693 token exchange) or issued before the instant
        /// was recorded. It stays `None` all the way to the claim: row
        /// creation and code issuance are not authentication.
        auth_time: Option<i64>,
    },
    /// User needs to authenticate.
    NeedsAuth,
}

/// Authorization code stored temporarily (JWT-encoded).
///
/// Encodes all parameters from the authorization request so they can be
/// verified at the token endpoint (RFC 6749 Section 4.1.3).
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationCode {
    /// RFC 8725 §3.8: Issuer (base_url).
    pub iss: String,
    /// RFC 8725 §3.9: Audience (client_id).
    pub aud: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub user_id: String,
    pub email: String,
    pub authenticator_id: String,
    pub aaguid: Option<String>,
    pub scope: ScopeSet,
    /// OIDC nonce — OIDC Core Section 3.1.2.1.
    pub nonce: Option<String>,
    /// PKCE code challenge — RFC 7636 Section 4.2.
    pub code_challenge: Option<String>,
    /// PKCE code challenge method — RFC 7636 Section 4.2.
    pub code_challenge_method: Option<CodeChallengeMethod>,
    /// RFC 8707: Resource indicator from authorization request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// RFC 9470: Requested ACR values from authorization request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_values: Option<String>,
    /// RFC 9449 / FAPI 2.0: DPoP key thumbprint bound at PAR time.
    ///
    /// When present, the token endpoint MUST verify that the DPoP proof
    /// presented at token exchange uses the same key (RFC 9449 Section 10).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_jkt: Option<String>,
    pub iat: i64,
    pub exp: i64,
    /// OIDC Core Section 2: Time when the End-User authentication occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
}

impl AuthorizationCode {
    /// Encode the authorization code as a JWT (RFC 8725 §3.11: explicit typ).
    pub async fn encode(
        &self,
        signer: &crate::crypto::jwt::StateTokenSigner,
    ) -> Result<String, crate::crypto::jwt::StateTokenError> {
        signer
            .encode_state_token(self, JwtType::AuthorizationCode)
            .await
    }

    /// Decode an authorization code from a JWT.
    ///
    /// Validates `typ`, `iss`, and `aud` per RFC 8725.
    pub async fn decode(
        token: &str,
        signer: &crate::crypto::jwt::StateTokenSigner,
        expected_issuer: &str,
        expected_client_id: &str,
    ) -> Result<Self, crate::crypto::jwt::StateTokenError> {
        let claims: Self = signer
            .decode_state_token(token, JwtType::AuthorizationCode)
            .await?;

        // RFC 8725 §3.8: Validate issuer
        if claims.iss != expected_issuer {
            return Err(crate::crypto::jwt::StateTokenError::Validation(
                "Issuer mismatch".to_string(),
            ));
        }

        // RFC 8725 §3.9: Validate audience (client_id)
        if claims.aud != expected_client_id {
            return Err(crate::crypto::jwt::StateTokenError::Validation(
                "Audience mismatch".to_string(),
            ));
        }

        Ok(claims)
    }
}

// Maximum lengths for OAuth authorization request parameters.
// These prevent oversized inputs from consuming memory or being stored in the database.
const MAX_CLIENT_ID_LEN: usize = 256;
const MAX_REDIRECT_URI_LEN: usize = 2048;
const MAX_RESOURCE_LEN: usize = 2048;
const MAX_STATE_LEN: usize = 512;
const MAX_SCOPE_LEN: usize = 512;
const MAX_NONCE_LEN: usize = 256;
const MAX_CODE_CHALLENGE_LEN: usize = 128;
const MAX_ACR_VALUES_LEN: usize = 512;
/// Maximum allowed value for the `max_age` parameter (1 year in seconds).
/// Prevents unreasonable values and ensures safe u64→i64 conversion for storage.
const MAX_MAX_AGE: u64 = 31_536_000;

/// Validate an authorization request.
///
/// # Arguments
/// * `params` - The authorization request parameters
///
/// # Returns
/// A validated request ready for code issuance, or an error.
///
/// # Errors
/// Returns `ServiceError::OAuth` for invalid requests.
pub fn validate_authorize_request(
    params: AuthorizeRequestParams,
) -> ServiceResult<ValidatedAuthRequest> {
    // RFC 6749 Section 4.1.1: response_type must be "code"
    if !super::SUPPORTED_RESPONSE_TYPES.contains(&params.response_type.as_str()) {
        return Err(ServiceError::oauth(
            OAuthErrorCode::UnsupportedResponseType,
            "Only 'code' response type is supported",
        ));
    }

    // Validate redirect_uri is present
    if params.redirect_uri.is_empty() {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequest,
            "redirect_uri is required",
        ));
    }

    // Validate client_id is present
    if params.client_id.is_empty() {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequest,
            "client_id is required",
        ));
    }

    // Input length validation — reject oversized parameters early.
    validate_param_length("client_id", &params.client_id, MAX_CLIENT_ID_LEN)?;
    validate_param_length("redirect_uri", &params.redirect_uri, MAX_REDIRECT_URI_LEN)?;
    if let Some(ref state) = params.state {
        validate_param_length("state", state, MAX_STATE_LEN)?;
    }
    if let Some(ref scope) = params.scope {
        validate_param_length("scope", scope, MAX_SCOPE_LEN)?;
    }
    if let Some(ref nonce) = params.nonce {
        validate_param_length("nonce", nonce, MAX_NONCE_LEN)?;
    }
    if let Some(ref challenge) = params.code_challenge {
        validate_param_length("code_challenge", challenge, MAX_CODE_CHALLENGE_LEN)?;
    }
    if let Some(ref resource) = params.resource {
        validate_param_length("resource", resource, MAX_RESOURCE_LEN)?;
    }
    if let Some(ref acr_values) = params.acr_values {
        validate_param_length("acr_values", acr_values, MAX_ACR_VALUES_LEN)?;
        // Reject characters that could break WWW-Authenticate header quoted-string
        // syntax (RFC 9470 Section 3): double quotes, backslashes, and control chars.
        if acr_values
            .bytes()
            .any(|b| b == b'"' || b == b'\\' || b < 0x20)
        {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequest,
                "acr_values contains invalid characters",
            ));
        }
    }
    if let Some(max_age) = params.max_age
        && max_age > MAX_MAX_AGE
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequest,
            format!("max_age exceeds maximum allowed value of {MAX_MAX_AGE}"),
        ));
    }

    // OIDC Core Section 3.1.2.1: validate `prompt` here rather than at each
    // handler. RFC 9101 Section 6.3 has a Request Object's parameters
    // "validated ... as specified in OAuth 2.0", i.e. the same way a plain
    // request's are, so a plain body, a pushed request, and a signed Request
    // Object all reach this one check and answer alike. An empty list is the
    // same as no parameter at all.
    let prompt = match params.prompt.as_deref() {
        Some(raw) => {
            let set = PromptSet::parse(raw)?;
            (!set.is_empty()).then_some(set)
        }
        None => None,
    };

    // RFC 9700 Section 2.1.1: PKCE with S256 is required for all clients.
    let parsed_method = if let Some(ref method_str) = params.code_challenge_method {
        let method = CodeChallengeMethod::parse(method_str).ok_or_else(|| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidRequest,
                "Unsupported code_challenge_method. Only S256 is supported",
            )
        })?;
        // code_challenge_method without code_challenge is invalid
        if params.code_challenge.is_none() {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequest,
                "code_challenge is required when code_challenge_method is provided",
            ));
        }
        Some(method)
    } else if params.code_challenge.is_some() {
        // code_challenge without method defaults to S256
        Some(CodeChallengeMethod::S256)
    } else {
        // PKCE not provided — allowed for confidential clients.
        // Public clients are checked after client lookup in the handler.
        None
    };

    // RFC 9396: Parse and validate authorization_details if present
    let parsed_authorization_details = if let Some(ref raw) = params.authorization_details {
        Some(super::authorization_details::AuthorizationDetails::parse(
            raw,
        )?)
    } else {
        None
    };

    let scope = ScopeSet::parse(&params.scope.unwrap_or_else(|| "openid".to_string()));

    // RFC 8707 Section 2: Validate resource parameter if present
    if let Some(ref resource) = params.resource {
        use super::resource::ResourceUri;
        if ResourceUri::parse(resource).is_err() {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidTarget,
                "Invalid resource parameter: must be an absolute URI without a fragment",
            ));
        }
    }

    Ok(ValidatedAuthRequest {
        client_id: params.client_id,
        redirect_uri: params.redirect_uri,
        scope,
        state: params.state,
        nonce: params.nonce,
        code_challenge: params.code_challenge,
        code_challenge_method: parsed_method,
        resource: params.resource,
        acr_values: params.acr_values,
        max_age: params.max_age,
        prompt,
        dpop_jkt: params.dpop_jkt,
        authorization_details: parsed_authorization_details,
    })
}

/// Enforce PKCE for public clients and application types that require it.
///
/// Confidential clients (e.g., `client_secret_basic`, `private_key_jwt`) using
/// the `Web` application type are exempt from the PKCE requirement per the OIDF
/// conformance expectations. Public clients and Native/SPA types always require PKCE.
///
/// Call this after `validate_authorize_request` and client lookup.
///
/// # Errors
///
/// Returns `ServiceError::OAuth` with `InvalidRequest` if PKCE is required but missing.
pub fn require_pkce_for_client(
    validated: &ValidatedAuthRequest,
    client: &OAuthClient,
) -> ServiceResult<()> {
    let is_public = client.token_endpoint_auth_method == TokenEndpointAuthMethod::None;
    // FAPI 2.0 Section 5.3.2.1: PKCE is required for all FAPI clients.
    let pkce_required = is_public || client.application_type.requires_pkce() || client.is_fapi();
    if pkce_required && validated.code_challenge().is_none() {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequest,
            "PKCE is required: code_challenge and code_challenge_method=S256 must be provided",
        ));
    }
    Ok(())
}

/// Validate that a parameter does not exceed the maximum allowed length.
fn validate_param_length(name: &str, value: &str, max_len: usize) -> ServiceResult<()> {
    if value.len() > max_len {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequest,
            format!("{name} exceeds maximum length of {max_len}"),
        ));
    }
    Ok(())
}

/// Check if the user has a valid session for authorization.
///
/// # Arguments
/// * `state` - Application state
/// * `session_token` - The session token from cookie
///
/// # Returns
/// The session state (authenticated or needs auth).
pub async fn check_session_for_authorization(
    state: &Arc<AppState>,
    session_token: Option<&str>,
) -> ServiceResult<AuthorizationSessionState> {
    let Some(token) = session_token else {
        return Ok(AuthorizationSessionState::NeedsAuth);
    };

    match validate_session_token(state, token).await? {
        Some(validated) => {
            // Two separate facts, and the authorization flow needs both.
            //
            // `authenticator` says the user has a key on record. That alone
            // used to gate this path, but an enrollment bootstrap session —
            // upstream IdP sign-in, no ceremony — carries an authenticator for
            // any returning user while `hardware_verified` is false. Issuing a
            // code from one produced tokens claiming `acr: aal3` and
            // `amr: [hwk, pin, user]` to the relying party for an
            // authentication where no key was touched, because
            // `exchange_authorization_code` stamps the grant as `Verified`
            // unconditionally.
            //
            // This is the same unsound inference as issue #1114, which read a
            // fresh `auth_time` as evidence of a ceremony. Ask directly.
            // Sending the user to `/login` to assert is what PAR/FAPI clients
            // already get from `ReauthPolicy::Always`; this extends it to the
            // flows that use `ReauthPolicy::OnDemand`.
            if !validated.hardware_verified {
                tracing::info!(
                    target: "security",
                    user_id = %validated.user.id,
                    "authorization requires an assertion: session is not hardware-verified"
                );
                return Ok(AuthorizationSessionState::NeedsAuth);
            }
            let Some(authenticator) = validated.authenticator else {
                return Ok(AuthorizationSessionState::NeedsAuth);
            };
            Ok(AuthorizationSessionState::Authenticated {
                user: Box::new(validated.user),
                session: Box::new(validated.session),
                authenticator: Box::new(authenticator),
                auth_time: validated.auth_time,
            })
        }
        None => Ok(AuthorizationSessionState::NeedsAuth),
    }
}

/// Issue an authorization code for a validated request.
///
/// Stores the code hash in the database for single-use enforcement
/// per RFC 6749 Section 10.5.
///
/// `params.par` is the RFC 9126 chokepoint: the caller must supply a
/// [`ParConsumptionProof`], so a pushed request reaches this function only
/// after its `request_uri` has been consumed.
///
/// # Arguments
/// * `state` - Application state
/// * `params` - Parameters for the authorization code
///
/// # Returns
/// The encoded authorization code (JWT).
///
/// # Errors
/// Returns `ServiceError` if encoding fails or database storage fails.
pub async fn issue_authorization_code(
    state: &Arc<AppState>,
    params: AuthorizationCodeParams<'_>,
) -> ServiceResult<String> {
    tracing::debug!(par = ?params.par, "PAR consumption proof consumed");

    let now = Timestamp::now();
    // Use the caller-supplied lifetime (FAPI 2.0 uses 60s, standard uses 300s).
    // Fallback to the supplied value if Span arithmetic overflows (shouldn't happen
    // for reasonable lifetime values).
    let lifetime_secs = params.auth_code_lifetime_seconds;
    let exp = now
        .checked_add(Span::new().seconds(lifetime_secs))
        .map_or_else(
            |_| now.as_second().saturating_add(lifetime_secs),
            |t| t.as_second(),
        );

    let auth_code = AuthorizationCode {
        iss: state.config().base_url.to_string(),
        aud: params.client_id.to_string(),
        client_id: params.client_id.to_string(),
        redirect_uri: params.redirect_uri.to_string(),
        user_id: params.user_id.to_string(),
        email: params.email.to_string(),
        authenticator_id: params.authenticator_id.to_string(),
        aaguid: params.aaguid.map(String::from),
        scope: params.scope.clone(),
        nonce: params.nonce.map(String::from),
        code_challenge: params.code_challenge.map(String::from),
        code_challenge_method: params.code_challenge_method,
        resource: params.resource.map(String::from),
        acr_values: params.acr_values.map(String::from),
        dpop_jkt: params.dpop_jkt.map(String::from),
        iat: now.as_second(),
        exp,
        auth_time: params.auth_time,
    };

    let code = auth_code.encode(&state.state_signer).await.map_err(|e| {
        tracing::error!("Failed to encode authorization code: {}", e);
        ServiceError::Internal("Failed to generate authorization code".to_string())
    })?;

    // RFC 6749 Section 10.5: Store code hash for single-use enforcement.
    let code_hash = crate::crypto::hash_token(&code);
    let expires_at = Timestamp::from_second(exp).unwrap_or(now);

    if let Err(e) = crate::db::store_authorization_code(
        &state.store,
        &code_hash,
        params.client_id,
        params.user_id,
        expires_at,
        params.authorization_details,
    )
    .await
    {
        tracing::error!("Failed to store authorization code hash: {}", e);
        return Err(ServiceError::Internal(
            "Failed to generate authorization code".to_string(),
        ));
    }

    Ok(code)
}

/// Decode and validate an authorization code.
///
/// # Arguments
/// * `state` - Application state
/// * `code` - The encoded authorization code
/// * `client_id` - Expected client_id (RFC 8725 §3.9: audience validation)
///
/// # Returns
/// The decoded authorization code.
///
/// # Errors
/// Returns `ServiceError::OAuth` with `invalid_grant` if the code is invalid or expired.
pub async fn decode_authorization_code(
    state: &Arc<AppState>,
    code: &str,
    client_id: &str,
) -> ServiceResult<AuthorizationCode> {
    let auth_code = AuthorizationCode::decode(
        code,
        &state.state_signer,
        &state.config().base_url,
        client_id,
    )
    .await
    .map_err(|_| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidGrant,
            "Invalid or expired authorization code",
        )
    })?;

    // Check expiration
    let now = Timestamp::now().as_second();
    if auth_code.exp < now {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidGrant,
            "Authorization code has expired",
        ));
    }

    Ok(auth_code)
}

// ============================================================================
// Access Control
// ============================================================================

/// Check if a user has access to an OAuth client based on its access scope.
///
/// # Arguments
/// * `client` - The OAuth client to check access for
/// * `user` - The user attempting to access the client
///
/// # Returns
/// `Ok(())` if the user has access, or an appropriate error.
///
/// # Access Rules
/// - **Public**: Any authenticated Vouch user can access
/// - **Personal**: Only the application creator can access
/// - **Organization**: Only users in the same organization can access
pub fn check_client_access(client: &OAuthClient, user: &User) -> ServiceResult<()> {
    let access_scope = client.access_scope;

    match access_scope {
        AccessScope::Public => {
            // Any authenticated user can access public apps
            Ok(())
        }
        AccessScope::Personal => {
            // Only the creator can access personal apps
            if client.user_id.as_deref() == Some(user.id.as_str()) {
                Ok(())
            } else {
                Err(ServiceError::oauth(
                    OAuthErrorCode::AccessDenied,
                    "You don't have access to this application",
                ))
            }
        }
        AccessScope::Organization => {
            // User must be in the same organization as the app
            match (&client.org_id, &user.org_id) {
                (Some(app_org), Some(user_org)) if app_org == user_org => Ok(()),
                (Some(_), Some(_)) => {
                    // Different organizations
                    Err(ServiceError::oauth(
                        OAuthErrorCode::AccessDenied,
                        "This application is only available to members of a different organization",
                    ))
                }
                (Some(_), None) => {
                    // User has no organization
                    Err(ServiceError::oauth(
                        OAuthErrorCode::AccessDenied,
                        "This application requires organization membership",
                    ))
                }
                (None, _) => {
                    // App has no org_id (shouldn't happen for org-scoped apps, but handle gracefully)
                    // Fall back to personal scope behavior
                    if client.user_id.as_deref() == Some(user.id.as_str()) {
                        Ok(())
                    } else {
                        Err(ServiceError::oauth(
                            OAuthErrorCode::AccessDenied,
                            "You don't have access to this application",
                        ))
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::crypto::alg::JwsAlgorithm;
    use crate::db::{FapiProfile, OAuthClientType, TokenEndpointAuthMethod};

    fn assert_oauth_error<T: std::fmt::Debug>(
        result: Result<T, ServiceError>,
        expected: OAuthErrorCode,
    ) {
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == expected),
            "Expected {expected:?}",
        );
    }

    // Helper to create a test OAuthClient
    fn test_client(user_id: &str, access_scope: AccessScope, org_id: Option<&str>) -> OAuthClient {
        let now = jiff::Timestamp::now();
        OAuthClient {
            id: "client-1".to_string(),
            user_id: Some(user_id.to_string()),
            client_id: "test-client-id".to_string(),
            name: "Test App".to_string(),
            description: None,
            application_type: OAuthClientType::Web,
            redirect_uris: vec![],
            active: true,
            created_at: now,
            updated_at: now,
            last_used_at: None,
            access_scope,
            org_id: org_id.map(String::from),
            resource_uris: vec![],
            keys: None,
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

    fn make_validated_request(
        code_challenge: Option<String>,
        code_challenge_method: Option<CodeChallengeMethod>,
    ) -> ValidatedAuthRequest {
        ValidatedAuthRequest {
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: ScopeSet::parse("openid"),
            state: None,
            nonce: None,
            code_challenge,
            code_challenge_method,
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: None,
            dpop_jkt: None,
            authorization_details: None,
        }
    }

    fn make_test_oauth_client(
        auth_method: TokenEndpointAuthMethod,
        app_type: OAuthClientType,
    ) -> OAuthClient {
        let now = jiff::Timestamp::now();
        OAuthClient {
            id: "client-1".to_string(),
            user_id: None,
            client_id: "test-client".to_string(),
            name: "Test App".to_string(),
            description: None,
            application_type: app_type,
            redirect_uris: vec!["https://example.com/callback".to_string()],
            active: true,
            created_at: now,
            updated_at: now,
            last_used_at: None,
            access_scope: AccessScope::Personal,
            org_id: None,
            resource_uris: vec![],
            keys: None,
            token_endpoint_auth_method: auth_method,
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

    // Helper to create a test User
    fn test_user(id: &str, org_id: Option<&str>) -> User {
        User {
            id: id.to_string(),
            email: format!("{}@example.com", id),
            name: Some("Test User".to_string()),
            org_id: org_id.map(String::from),
            is_org_admin: false,
            active: true,
            external_id: None,
            github_id: None,
            github_login: None,
            github_refresh_token: None,
        }
    }

    // =========================================================================
    // AuthorizationCode encode/decode tests (RFC 8725 §3.8/§3.9)
    // =========================================================================

    fn test_auth_code(iss: &str, aud: &str) -> AuthorizationCode {
        AuthorizationCode {
            iss: iss.to_string(),
            aud: aud.to_string(),
            client_id: aud.to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            user_id: "user-1".to_string(),
            email: "test@example.com".to_string(),
            authenticator_id: "auth-1".to_string(),
            aaguid: None,
            scope: ScopeSet::parse("openid"),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            dpop_jkt: None,
            iat: 1_000_000_000,
            exp: 9_999_999_999,
            auth_time: None,
        }
    }

    #[tokio::test]
    async fn test_authorization_code_roundtrip() {
        let signer = crate::crypto::jwt::StateTokenSigner::local(
            crate::test_utils::TEST_JWT_SECRET.to_vec(),
        );
        let code = test_auth_code("https://example.com", "client-a");

        let token = code.encode(&signer).await.unwrap();
        let decoded = AuthorizationCode::decode(&token, &signer, "https://example.com", "client-a")
            .await
            .unwrap();

        assert_eq!(decoded.iss, "https://example.com");
        assert_eq!(decoded.aud, "client-a");
        assert_eq!(decoded.user_id, "user-1");
        assert_eq!(decoded.email, "test@example.com");
    }

    #[tokio::test]
    async fn test_authorization_code_decode_wrong_issuer() {
        let signer = crate::crypto::jwt::StateTokenSigner::local(
            crate::test_utils::TEST_JWT_SECRET.to_vec(),
        );
        let code = test_auth_code("https://attacker.com", "client-a");

        let token = code.encode(&signer).await.unwrap();
        let result =
            AuthorizationCode::decode(&token, &signer, "https://example.com", "client-a").await;

        assert!(result.is_err(), "Wrong issuer must be rejected");
        let err = result.unwrap_err();
        assert!(
            matches!(&err, crate::crypto::jwt::StateTokenError::Validation(_)),
            "Expected Validation error, got: {err}",
        );
        if let crate::crypto::jwt::StateTokenError::Validation(msg) = err {
            assert!(msg.contains("Issuer"), "Error should mention issuer: {msg}");
        }
    }

    #[tokio::test]
    async fn test_authorization_code_decode_wrong_audience() {
        let signer = crate::crypto::jwt::StateTokenSigner::local(
            crate::test_utils::TEST_JWT_SECRET.to_vec(),
        );
        let code = test_auth_code("https://example.com", "client-a");

        let token = code.encode(&signer).await.unwrap();
        let result = AuthorizationCode::decode(
            &token,
            &signer,
            "https://example.com",
            "client-b", // Different client_id
        )
        .await;

        assert!(result.is_err(), "Wrong audience must be rejected");
        let err = result.unwrap_err();
        assert!(
            matches!(&err, crate::crypto::jwt::StateTokenError::Validation(_)),
            "Expected Validation error, got: {err}",
        );
        if let crate::crypto::jwt::StateTokenError::Validation(msg) = err {
            assert!(
                msg.contains("Audience"),
                "Error should mention audience: {msg}"
            );
        }
    }

    #[tokio::test]
    async fn test_authorization_code_decode_wrong_secret() {
        let signer_a = crate::crypto::jwt::StateTokenSigner::local(
            crate::test_utils::TEST_JWT_SECRET.to_vec(),
        );
        let signer_b = crate::crypto::jwt::StateTokenSigner::local(
            b"different_secret_at_least_32chars_long!!".to_vec(),
        );
        let code = test_auth_code("https://example.com", "client-a");

        let token = code.encode(&signer_a).await.unwrap();
        let result =
            AuthorizationCode::decode(&token, &signer_b, "https://example.com", "client-a").await;

        assert!(result.is_err(), "Wrong secret must be rejected");
    }

    // =========================================================================
    // Validate authorize request tests
    // =========================================================================

    // OIDC Core §3.1.2.1: a conformant authentication request is accepted.
    #[test]
    fn test_validate_authorize_request_valid() {
        let params = AuthorizeRequestParams {
            response_type: "code".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("openid email".to_string()),
            state: Some("abc123".to_string()),
            nonce: Some("nonce123".to_string()),
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: None,
            dpop_jkt: None,
            authorization_details: None,
            response_mode: None,
        };

        let result = validate_authorize_request(params);
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert_eq!(validated.client_id(), "test-client");
        assert_eq!(*validated.scope(), ScopeSet::parse("openid email"));
    }

    // OIDC Core §3.1.2.1: an unsupported response_type is rejected.
    #[test]
    fn test_validate_authorize_request_invalid_response_type() {
        let params = AuthorizeRequestParams {
            response_type: "token".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: None,
            state: None,
            nonce: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: None,
            dpop_jkt: None,
            authorization_details: None,
            response_mode: None,
        };

        let result = validate_authorize_request(params);
        assert!(result.is_err());
        assert_oauth_error(result, OAuthErrorCode::UnsupportedResponseType);
    }

    // OIDC Core §3.1.2.1: client_id is required.
    #[test]
    fn test_validate_authorize_request_missing_client_id() {
        let params = AuthorizeRequestParams {
            response_type: "code".to_string(),
            client_id: "".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: None,
            state: None,
            nonce: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: None,
            dpop_jkt: None,
            authorization_details: None,
            response_mode: None,
        };

        let result = validate_authorize_request(params);
        assert!(result.is_err());
    }

    // OIDC Core §3.1.2.1: scope defaults when the request omits it.
    #[test]
    fn test_validate_authorize_request_default_scope() {
        let params = AuthorizeRequestParams {
            response_type: "code".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: None, // No scope provided
            state: None,
            nonce: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: None,
            dpop_jkt: None,
            authorization_details: None,
            response_mode: None,
        };

        let result = validate_authorize_request(params);
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert_eq!(*validated.scope(), ScopeSet::parse("openid")); // Default scope
    }

    // OIDC Core §3.1.2.1: PKCE parameters are not required of every client.
    #[test]
    fn test_validate_authorize_request_allows_missing_pkce() {
        // PKCE enforcement is deferred to handler after client lookup.
        // validate_authorize_request should accept missing PKCE.
        let params = AuthorizeRequestParams {
            response_type: "code".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: None,
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: None,
            dpop_jkt: None,
            authorization_details: None,
            response_mode: None,
        };

        let result = validate_authorize_request(params);
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert!(validated.code_challenge().is_none());
        assert!(validated.code_challenge_method().is_none());
    }

    // RFC 9700 §2.1.1: a public client uses PKCE.
    #[test]
    fn test_require_pkce_for_public_client() {
        use crate::db::{OAuthClientType, TokenEndpointAuthMethod};

        let validated = make_validated_request(None, None);
        let client = make_test_oauth_client(TokenEndpointAuthMethod::None, OAuthClientType::Spa);

        let result = require_pkce_for_client(&validated, &client);
        assert!(result.is_err());
        assert_oauth_error(result, OAuthErrorCode::InvalidRequest);
    }

    // RFC 8252 §8.1: a native app protects the authorization code with PKCE.
    #[test]
    fn test_require_pkce_for_native_client() {
        use crate::db::{OAuthClientType, TokenEndpointAuthMethod};

        let validated = make_validated_request(None, None);
        let client = make_test_oauth_client(
            TokenEndpointAuthMethod::ClientSecretBasic,
            OAuthClientType::Native,
        );

        let result = require_pkce_for_client(&validated, &client);
        assert!(result.is_err());
    }

    // RFC 9700 §2.1.1: a confidential client may rely on client authentication instead.
    #[test]
    fn test_require_pkce_not_required_for_confidential_web_client() {
        use crate::db::{OAuthClientType, TokenEndpointAuthMethod};

        let validated = make_validated_request(None, None);
        let client = make_test_oauth_client(
            TokenEndpointAuthMethod::ClientSecretBasic,
            OAuthClientType::Web,
        );

        let result = require_pkce_for_client(&validated, &client);
        assert!(result.is_ok());
    }

    // RFC 9700 §2.1.1: a confidential client may also use PKCE.
    #[test]
    fn test_require_pkce_confidential_with_pkce_succeeds() {
        use crate::db::{OAuthClientType, TokenEndpointAuthMethod};

        let validated = make_validated_request(
            Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
            Some(CodeChallengeMethod::S256),
        );
        let client = make_test_oauth_client(TokenEndpointAuthMethod::None, OAuthClientType::Spa);

        let result = require_pkce_for_client(&validated, &client);
        assert!(result.is_ok());
    }

    // RFC 7636 §4.2: S256 is used when the client can support it.
    #[test]
    fn test_validate_authorize_request_rejects_plain_pkce() {
        // RFC 9700: Only S256 is supported
        let params = AuthorizeRequestParams {
            response_type: "code".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: None,
            state: None,
            nonce: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("plain".to_string()),
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: None,
            dpop_jkt: None,
            authorization_details: None,
            response_mode: None,
        };

        let result = validate_authorize_request(params);
        assert!(result.is_err());
        assert_oauth_error(result, OAuthErrorCode::InvalidRequest);
    }

    // =========================================================================
    // Access Control Tests
    // =========================================================================

    #[test]
    fn test_access_check_public_allows_anyone() {
        let client = test_client("user-1", AccessScope::Public, None);
        let user = test_user("user-2", None); // Different user

        let result = check_client_access(&client, &user);
        assert!(result.is_ok());
    }

    #[test]
    fn test_access_check_personal_allows_only_creator() {
        let client = test_client("user-1", AccessScope::Personal, None);
        let creator = test_user("user-1", None);

        let result = check_client_access(&client, &creator);
        assert!(result.is_ok());
    }

    #[test]
    fn test_access_check_personal_denies_others() {
        let client = test_client("user-1", AccessScope::Personal, None);
        let other_user = test_user("user-2", None);

        let result = check_client_access(&client, &other_user);
        assert!(result.is_err());
        assert_oauth_error(result, OAuthErrorCode::AccessDenied);
    }

    #[test]
    fn test_access_check_organization_allows_same_org() {
        let client = test_client("user-1", AccessScope::Organization, Some("org-1"));
        let same_org_user = test_user("user-2", Some("org-1"));

        let result = check_client_access(&client, &same_org_user);
        assert!(result.is_ok());
    }

    #[test]
    fn test_access_check_organization_denies_different_org() {
        let client = test_client("user-1", AccessScope::Organization, Some("org-1"));
        let diff_org_user = test_user("user-2", Some("org-2"));

        let result = check_client_access(&client, &diff_org_user);
        assert!(result.is_err());
        assert_oauth_error(result, OAuthErrorCode::AccessDenied);
    }

    #[test]
    fn test_access_check_organization_denies_no_org_user() {
        let client = test_client("user-1", AccessScope::Organization, Some("org-1"));
        let no_org_user = test_user("user-2", None);

        let result = check_client_access(&client, &no_org_user);
        assert!(result.is_err());
        assert_oauth_error(result, OAuthErrorCode::AccessDenied);
    }

    #[test]
    fn test_access_check_organization_creator_in_same_org() {
        // Creator should also have access if they're in the same org
        let client = test_client("user-1", AccessScope::Organization, Some("org-1"));
        let creator = test_user("user-1", Some("org-1"));

        let result = check_client_access(&client, &creator);
        assert!(result.is_ok());
    }

    // =========================================================================
    // RFC 9470 Step-Up Authentication Tests
    // =========================================================================

    // RFC 9470 §4: acr_values requests an authentication strength.
    #[test]
    fn test_validate_authorize_request_with_acr_values() {
        let params = AuthorizeRequestParams {
            response_type: "code".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("openid".to_string()),
            state: None,
            nonce: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            resource: None,
            acr_values: Some("urn:nist:authentication:assurance-level:aal3".to_string()),
            max_age: None,
            prompt: None,
            dpop_jkt: None,
            authorization_details: None,
            response_mode: None,
        };

        let result = validate_authorize_request(params);
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert_eq!(
            validated.acr_values(),
            Some("urn:nist:authentication:assurance-level:aal3")
        );
    }

    // OIDC Core §3.1.2.1: max_age bounds the age of the authentication.
    #[test]
    fn test_validate_authorize_request_with_max_age() {
        let params = AuthorizeRequestParams {
            response_type: "code".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("openid".to_string()),
            state: None,
            nonce: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            resource: None,
            acr_values: None,
            max_age: Some(300),
            prompt: None,
            dpop_jkt: None,
            authorization_details: None,
            response_mode: None,
        };

        let result = validate_authorize_request(params);
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert_eq!(validated.max_age(), Some(300));
    }

    // OIDC Core §3.1.2.1: prompt=login asks for reauthentication.
    #[test]
    fn test_validate_authorize_request_with_prompt_login() {
        let params = AuthorizeRequestParams {
            response_type: "code".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("openid".to_string()),
            state: None,
            nonce: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: Some("login".to_string()),
            dpop_jkt: None,
            authorization_details: None,
            response_mode: None,
        };

        let result = validate_authorize_request(params);
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert_eq!(validated.prompt(), Some(PromptSet::of(Prompt::Login)));
    }

    // OIDC Core §3.1.2.1: prompt=none forbids any user interaction.
    #[test]
    fn test_validate_authorize_request_with_prompt_none() {
        let params = AuthorizeRequestParams {
            response_type: "code".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("openid".to_string()),
            state: None,
            nonce: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: Some("none".to_string()),
            dpop_jkt: None,
            authorization_details: None,
            response_mode: None,
        };

        let result = validate_authorize_request(params);
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert_eq!(validated.prompt(), Some(PromptSet::of(Prompt::Silent)));
    }

    // RFC 9470 §4: the acr_values parameter is bounded.
    #[test]
    fn test_validate_authorize_request_rejects_long_acr_values() {
        let params = AuthorizeRequestParams {
            response_type: "code".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: None,
            state: None,
            nonce: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            resource: None,
            acr_values: Some("a".repeat(513)),
            max_age: None,
            prompt: None,
            dpop_jkt: None,
            authorization_details: None,
            response_mode: None,
        };

        let result = validate_authorize_request(params);
        assert!(result.is_err());
    }

    /// Extract the OAuth error code from a failed [`PromptSet::parse`].
    fn prompt_error(raw: &str) -> OAuthErrorCode {
        match PromptSet::parse(raw) {
            Ok(set) => panic!("{raw:?} should have been rejected, parsed as {set}"),
            Err(ServiceError::OAuth { code, .. }) => code,
            Err(e) => panic!("expected an OAuth error for {raw:?}, got {e:?}"),
        }
    }

    // OIDC Core §3.1.2.1: each honored value parses on its own.
    #[test]
    fn test_prompt_parse_single_values() {
        for (raw, prompt) in [
            ("login", Prompt::Login),
            ("none", Prompt::Silent),
            ("consent", Prompt::Consent),
        ] {
            assert_eq!(
                PromptSet::parse(raw).unwrap(),
                PromptSet::of(prompt),
                "{raw:?} should parse as the {prompt} behavior"
            );
        }
    }

    // OIDC Core §3.1.2.1: prompt is a "Space-delimited, case-sensitive list of
    // ASCII string values", so more than one value in one parameter is a
    // request for both behaviors, not an unrecognized value.
    #[test]
    fn test_prompt_parse_accepts_multiple_values() {
        let set = PromptSet::parse("login consent").unwrap();
        assert!(set.contains(Prompt::Login), "login must be honored");
        assert!(set.contains(Prompt::Consent), "consent must be honored");
        assert!(!set.contains(Prompt::Silent));

        // Order is the client's choice; the parsed set is the same either way.
        assert_eq!(set, PromptSet::parse("consent login").unwrap());
    }

    // OIDC Core §3.1.2.1: "If this parameter contains none with any other
    // value, an error is returned."
    #[test]
    fn test_prompt_parse_rejects_none_with_other_values() {
        assert_eq!(prompt_error("none login"), OAuthErrorCode::InvalidRequest);
        assert_eq!(prompt_error("consent none"), OAuthErrorCode::InvalidRequest);
    }

    // OIDC Core §3.1.2.1: for select_account, "If it cannot obtain an account
    // selection choice made by the End-User, it MUST return an error,
    // typically account_selection_required." Vouch authenticates one account
    // per session, so it never can.
    #[test]
    fn test_prompt_parse_rejects_select_account() {
        assert_eq!(
            prompt_error("select_account"),
            OAuthErrorCode::AccountSelectionRequired
        );
        assert_eq!(
            prompt_error("login select_account"),
            OAuthErrorCode::AccountSelectionRequired
        );
    }

    // OIDC Core §3.1.2.1 permits either answer for a value outside the defined
    // set — "it MAY return an error or it MAY ignore it". Vouch returns one.
    #[test]
    fn test_prompt_parse_rejects_undefined_values() {
        assert_eq!(prompt_error("x_vendor_ext"), OAuthErrorCode::InvalidRequest);
        assert_eq!(
            prompt_error("login x_vendor_ext"),
            OAuthErrorCode::InvalidRequest
        );
        // Case-sensitive: "Login" is not "login".
        assert_eq!(prompt_error("Login"), OAuthErrorCode::InvalidRequest);
    }

    // RFC 6749 §3.1: "Parameters sent without a value MUST be treated as if
    // they were omitted from the request." An empty list carries no values.
    #[test]
    fn test_prompt_parse_empty_is_no_values() {
        assert!(PromptSet::parse("").unwrap().is_empty());
        assert!(PromptSet::parse("   ").unwrap().is_empty());
    }

    // The stored form has to survive a round trip: a PAR record's prompt is
    // re-parsed when the request_uri is redeemed at the authorize endpoint.
    #[test]
    fn test_prompt_set_round_trips_through_its_wire_form() {
        for raw in ["login", "none", "consent", "login consent"] {
            let set = PromptSet::parse(raw).unwrap();
            assert_eq!(
                PromptSet::parse(&set.to_space_separated()).unwrap(),
                set,
                "{raw:?} did not survive a round trip"
            );
        }
    }

    /// Every value the error message advertises must actually parse. This is
    /// the invariant that broke when the message and the parser were separate
    /// literals: the message listed fewer values than the parser accepted.
    // OIDC Core §3.1.2.1: every advertised prompt value is one the server accepts.
    #[test]
    fn every_advertised_prompt_value_parses() {
        let advertised = Prompt::supported_values();
        assert!(!advertised.is_empty(), "message must list something");
        for value in advertised.split(", ") {
            assert!(
                PromptSet::parse(value).is_ok(),
                "advertised prompt {value:?} does not parse"
            );
        }
        // And every honored value is advertised. `select_account` is defined
        // but not honored, so it is deliberately absent from the list.
        for (value, prompt) in Prompt::DEFINED {
            assert_eq!(
                advertised.contains(value),
                prompt.is_some(),
                "advertised list disagrees with the parser about {value:?}"
            );
        }
    }

    // OIDC Core §3.1.2.1: prompt values are the strings the specification names.
    #[test]
    fn test_prompt_as_str() {
        assert_eq!(Prompt::Login.as_str(), "login");
        assert_eq!(Prompt::Silent.as_str(), "none");
    }

    // OIDC Core §3.1.2.1: prompt values are the strings the specification names.
    #[test]
    fn test_prompt_display() {
        assert_eq!(format!("{}", Prompt::Login), "login");
        assert_eq!(format!("{}", Prompt::Silent), "none");
    }

    // OIDC Core §3.1.2.1: prompt values round-trip through their wire form.
    #[test]
    fn test_prompt_serde_roundtrip() {
        let login = Prompt::Login;
        let json = serde_json::to_string(&login).unwrap();
        assert_eq!(json, "\"login\"");

        let deserialized: Prompt = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, Prompt::Login);
    }

    // RFC 9470 §4: acr values are space-delimited strings, not quoted ones.
    #[test]
    fn test_validate_authorize_request_rejects_acr_values_with_quotes() {
        let params = AuthorizeRequestParams {
            response_type: "code".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: None,
            state: None,
            nonce: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            resource: None,
            acr_values: Some("aal3\", injected=\"bad".to_string()),
            max_age: None,
            prompt: None,
            dpop_jkt: None,
            authorization_details: None,
            response_mode: None,
        };

        let result = validate_authorize_request(params);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, description }
                if *code == OAuthErrorCode::InvalidRequest && description.contains("invalid characters")),
            "Expected OAuth InvalidRequest with 'invalid characters', got: {err:?}",
        );
    }

    // RFC 9470 §4: acr values carry no control characters.
    #[test]
    fn test_validate_authorize_request_rejects_acr_values_with_control_chars() {
        let params = AuthorizeRequestParams {
            response_type: "code".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: None,
            state: None,
            nonce: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            resource: None,
            acr_values: Some("aal3\rnewline".to_string()),
            max_age: None,
            prompt: None,
            dpop_jkt: None,
            authorization_details: None,
            response_mode: None,
        };

        let result = validate_authorize_request(params);
        assert!(result.is_err());
    }

    // OIDC Core §3.1.2.1: max_age is a number of seconds.
    #[test]
    fn test_validate_authorize_request_rejects_excessive_max_age() {
        let params = AuthorizeRequestParams {
            response_type: "code".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: None,
            state: None,
            nonce: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            resource: None,
            acr_values: None,
            max_age: Some(31_536_001), // 1 year + 1 second
            prompt: None,
            dpop_jkt: None,
            authorization_details: None,
            response_mode: None,
        };

        let result = validate_authorize_request(params);
        assert!(result.is_err());
        assert_oauth_error(result, OAuthErrorCode::InvalidRequest);
    }

    // OIDC Core §3.1.2.1: the max_age boundary is exact.
    #[test]
    fn test_validate_authorize_request_accepts_max_max_age() {
        // Exactly 1 year should be accepted
        let params = AuthorizeRequestParams {
            response_type: "code".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: None,
            state: None,
            nonce: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            resource: None,
            acr_values: None,
            max_age: Some(31_536_000),
            prompt: None,
            dpop_jkt: None,
            authorization_details: None,
            response_mode: None,
        };

        let result = validate_authorize_request(params);
        assert!(result.is_ok());
    }
}
