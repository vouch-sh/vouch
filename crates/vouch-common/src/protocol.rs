// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Wire literals shared by the Vouch server and CLI.
//!
//! These are the exact bytes that cross the wire between the two crates:
//! `grant_type` and `client_assertion_type` values sent by the CLI and
//! dispatched by the server, RFC 8693 token type URNs, the error codes the
//! CLI string-matches on to drive retries, the DPoP and Bearer header and
//! scheme names, the WebAuthn client-data types the CLI produces and the
//! server verifies, and the JWS algorithm both sides sign with. Spelling
//! them once means a typo is a compile error on both sides instead of a
//! runtime mismatch.
//!
//! Every constant carries the verbatim normative text that fixes its value,
//! with the section number and the URL it was fetched from.
//!
//! # Scope
//!
//! What belongs here is the CLI↔server contract, not every wire string the
//! workspace types. Four neighbours are deliberately absent:
//!
//! - `urn:ietf:params:oauth:grant-type:jwt-bearer` (RFC 7523 §2.1) is used
//!   by the CLI against AWS IAM Identity Center, Anthropic, and OpenAI,
//!   never against vouch-server — which rejects it. Those call sites keep
//!   their own literals: they answer to the provider's contract, not ours.
//! - The PAR `request_uri` URN prefix (RFC 9126 §2.2) is server-only; it
//!   lives in `vouch_server::db::par`.
//! - The `application/x-www-form-urlencoded` content type sent to AWS STS
//!   and IAM Identity Center (`vouch_cli::integrations::aws`) keeps its own
//!   literal for the same reason the `jwt-bearer` grant does, even though
//!   [`CONTENT_TYPE_FORM_URLENCODED`] holds the identical bytes.
//! - The `Bearer` scheme the server sends to the GitHub API
//!   (`vouch_server::services::integrations::github`) likewise stays put: it
//!   answers to GitHub's contract, not to what Vouch's own clients send.
//!
//! [`TOKEN_TYPE_JWT`] is the one constant here that vouch-server alone
//! sends. It is admitted because RFC 8693 §3 defines the three token type
//! identifiers as one group and the server matches on all three; splitting
//! the group across two crates would be worse than carrying it.
//!
//! Behavior stays where it is: `OAuthGrantType`, `OAuthErrorCode`, and
//! `JwsAlgorithm` remain server-side enums, and their `as_str()` arms
//! return these constants. The enums own dispatch; this module owns bytes.
//!
//! # `DPoP` is three contracts, not one
//!
//! RFC 9449 spells `DPoP` in three independent places — the proof header
//! field ([`HEADER_DPOP`]), the `Authorization` scheme
//! ([`AUTH_SCHEME_DPOP`]), and the `token_type` response value
//! ([`ACCESS_TOKEN_TYPE_DPOP`]). Each has its own constant so a call site
//! names the contract it is in and cites the section that fixes it. The
//! same split applies to Bearer, whose scheme (RFC 6750 §2.1) and access
//! token type (RFC 6750 §6.1.1) are registered separately.
//!
//! # Header-name case
//!
//! [`HEADER_DPOP`] and [`HEADER_DPOP_NONCE`] are lowercase. RFC 9449 §4.1
//! is explicit that this does not change the wire:
//!
//! > Note that per \[RFC9110\], header field names are case insensitive;
//! > thus, DPoP, DPOP, dpop, etc., are all valid and equivalent header
//! > field names.  However, case is significant in the header field value.
//!
//! <https://www.rfc-editor.org/rfc/rfc9449#section-4.1>
//!
//! Lowercase is the spelling `http::HeaderName` normalizes to on
//! construction, so it is what already goes out on the wire regardless of
//! how a call site spells it, and it is the only spelling
//! `HeaderName::from_static` accepts.

/// RFC 8628 §3.4 (Device Access Token Request) — device authorization grant.
///
/// > grant_type
/// >    REQUIRED.  Value MUST be set to
/// >    "urn:ietf:params:oauth:grant-type:device_code".
///
/// <https://www.rfc-editor.org/rfc/rfc8628#section-3.4>
pub const GRANT_TYPE_DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// RFC 8693 §2.1 (Request) — token exchange grant.
///
/// > grant_type
/// >    REQUIRED.  The value "urn:ietf:params:oauth:grant-type:token-
/// >    exchange" indicates that a token exchange is being performed.
///
/// <https://www.rfc-editor.org/rfc/rfc8693#section-2.1>
pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// Vouch's FIDO2 assertion grant — an extension grant, not IETF-registered.
///
/// RFC 6749 §4.5 (Extension Grants) is the authority for minting it:
///
/// > The client uses an extension grant type by specifying the grant type
/// > using an absolute URI (defined by the authorization server) as the
/// > value of the "grant_type" parameter of the token endpoint, and by
/// > adding any additional parameters necessary.
///
/// <https://www.rfc-editor.org/rfc/rfc6749#section-4.5>
///
/// Because no registry fixes this value, the CLI and server agreeing on it
/// is entirely on us — which is the strongest reason for it to live here.
pub const GRANT_TYPE_FIDO2_ASSERTION: &str = "urn:ietf:params:oauth:grant-type:fido2-assertion";

/// RFC 7523 §2.2 (Using JWTs for Client Authentication) — `private_key_jwt`.
///
/// > The value of the "client_assertion_type" is
/// > "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".
///
/// <https://www.rfc-editor.org/rfc/rfc7523#section-2.2>
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// RFC 8693 §3 (Token Type Identifiers) — OAuth 2.0 access token.
///
/// > urn:ietf:params:oauth:token-type:access_token
/// >    Indicates that the token is an OAuth 2.0 access token issued by
/// >    the given authorization server.
///
/// <https://www.rfc-editor.org/rfc/rfc8693#section-3>
pub const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";

/// RFC 8693 §3 (Token Type Identifiers) — OIDC ID Token.
///
/// > urn:ietf:params:oauth:token-type:id_token
/// >    Indicates that the token is an ID Token as defined in Section 2 of
/// >    [OpenID.Core].
///
/// <https://www.rfc-editor.org/rfc/rfc8693#section-3>
pub const TOKEN_TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";

/// RFC 8693 §3 (Token Type Identifiers) — bare JWT.
///
/// > The value "urn:ietf:params:oauth:token-type:jwt", which is defined in
/// > Section 9 of \[JWT\], indicates that the token is a JWT.
///
/// <https://www.rfc-editor.org/rfc/rfc8693#section-3>
///
/// Distinct from [`TOKEN_TYPE_ACCESS_TOKEN`]: the same RFC 8693 §3 notes
/// that an access token "represents a delegated authorization decision,
/// whereas JWT is a token format".
pub const TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

/// RFC 9449 §8 (Authorization Server-Provided Nonce) — retry with a nonce.
///
/// > An authorization server MAY supply a nonce value to be included by
/// > the client in DPoP proofs sent.  In this case, the authorization
/// > server responds to requests that do not include a nonce with an HTTP
/// > 400 (Bad Request) error response per Section 5.2 of \[RFC6749\] using
/// > use_dpop_nonce as the error code value.
///
/// <https://www.rfc-editor.org/rfc/rfc9449#section-8>
///
/// Resource servers use the same code in a `WWW-Authenticate: DPoP`
/// challenge, per RFC 9449 §7.1 (The DPoP Authentication Scheme):
///
/// > The value use_dpop_nonce can be used as described in Section 9 to
/// > signal that a nonce is needed in the DPoP proof of a subsequent
/// > request(s).
///
/// <https://www.rfc-editor.org/rfc/rfc9449#section-7.1>
pub const ERROR_USE_DPOP_NONCE: &str = "use_dpop_nonce";

/// RFC 8628 §3.5 (Device Access Token Response) — keep polling.
///
/// > authorization_pending
/// >    The authorization request is still pending as the end user hasn't
/// >    yet completed the user-interaction steps (Section 3.3).
///
/// <https://www.rfc-editor.org/rfc/rfc8628#section-3.5>
pub const ERROR_AUTHORIZATION_PENDING: &str = "authorization_pending";

/// RFC 8628 §3.5 (Device Access Token Response) — poll less often.
///
/// > slow_down
/// >    A variant of "authorization_pending", the authorization request is
/// >    still pending and polling should continue, but the interval MUST
/// >    be increased by 5 seconds for this and all subsequent requests.
///
/// <https://www.rfc-editor.org/rfc/rfc8628#section-3.5>
pub const ERROR_SLOW_DOWN: &str = "slow_down";

/// RFC 8628 §3.5 (Device Access Token Response) — the user said no.
///
/// > access_denied
/// >    The authorization request was denied.
///
/// <https://www.rfc-editor.org/rfc/rfc8628#section-3.5>
pub const ERROR_ACCESS_DENIED: &str = "access_denied";

/// RFC 8628 §3.5 (Device Access Token Response) — the device code is dead.
///
/// > expired_token
/// >    The "device_code" has expired, and the device authorization
/// >    session has concluded.
///
/// <https://www.rfc-editor.org/rfc/rfc8628#section-3.5>
pub const ERROR_EXPIRED_TOKEN: &str = "expired_token";

/// RFC 9449 §4.1 (The DPoP HTTP Header) — carries the DPoP proof JWT.
///
/// > A DPoP proof is included in an HTTP request using the following
/// > request header field.
/// >
/// > DPoP:  A JWT that adheres to the structure and syntax of Section 4.2.
///
/// <https://www.rfc-editor.org/rfc/rfc9449#section-4.1>
///
/// Registered permanently as an HTTP field name in RFC 9449 §12.8.
/// Lowercase per the module's header-name note.
pub const HEADER_DPOP: &str = "dpop";

/// RFC 9449 §8 (Authorization Server-Provided Nonce) — carries the nonce.
///
/// > The authorization server includes a DPoP-Nonce HTTP header in the
/// > response supplying a nonce value to be used when sending the
/// > subsequent request.  Nonce values MUST be unpredictable.
///
/// <https://www.rfc-editor.org/rfc/rfc9449#section-8>
///
/// The same section requires browsers be able to read it, which is why the
/// server lists it in `Access-Control-Expose-Headers`:
///
/// > In order for the application to obtain and use the DPoP-Nonce HTTP
/// > response header value, the server needs to make it available to the
/// > application by including DPoP-Nonce in the Access-Control-Expose-
/// > Headers response header list value.
///
/// Registered permanently as an HTTP field name in RFC 9449 §12.8.
/// Lowercase per the module's header-name note.
pub const HEADER_DPOP_NONCE: &str = "dpop-nonce";

/// RFC 6750 §2.1 (Authorization Request Header Field) — the Bearer scheme.
///
/// > When sending the access token in the "Authorization" request header
/// > field defined by HTTP/1.1 \[RFC2617\], the client uses the "Bearer"
/// > authentication scheme to transmit the access token.
///
/// The section's ABNF fixes the spelling:
///
/// > credentials = "Bearer" 1*SP b64token
///
/// <https://www.rfc-editor.org/rfc/rfc6750#section-2.1>
pub const AUTH_SCHEME_BEARER: &str = "Bearer";

/// RFC 9449 §7.1 (The DPoP Authentication Scheme) — the DPoP scheme.
///
/// > A DPoP-bound access token is sent using the Authorization request
/// > header field per Section 11.6.2 of \[RFC9110\] with an authentication
/// > scheme of DPoP.
///
/// The section's ABNF fixes the spelling:
///
/// > credentials = "DPoP" 1*SP token68
///
/// <https://www.rfc-editor.org/rfc/rfc9449#section-7.1>
///
/// Distinct from [`HEADER_DPOP`]: this is the `Authorization` scheme that
/// carries the access token, not the field that carries the proof. RFC 9449
/// §7.1 requires both on the same request.
pub const AUTH_SCHEME_DPOP: &str = "DPoP";

/// RFC 6750 §6.1.1 (The "Bearer" OAuth Access Token Type) — `token_type`.
///
/// > Type name:
/// >    Bearer
/// >
/// > Additional Token Endpoint Response Parameters:
/// >    (none)
/// >
/// > HTTP Authentication Scheme(s):
/// >    Bearer
///
/// <https://www.rfc-editor.org/rfc/rfc6750#section-6.1.1>
///
/// RFC 6749 §5.1 says of the response parameter this value fills: "The type
/// of the token issued as described in Section 7.1.  Value is case
/// insensitive." Vouch emits the registered spelling.
///
/// <https://www.rfc-editor.org/rfc/rfc6749#section-5.1>
pub const ACCESS_TOKEN_TYPE_BEARER: &str = "Bearer";

/// RFC 9449 §5 (DPoP Access Token Request) — `token_type` when bound.
///
/// > A token_type of DPoP MUST be included in the access token response to
/// > signal to the client that the access token was bound to its DPoP key
/// > and can be used as described in Section 7.1.
///
/// <https://www.rfc-editor.org/rfc/rfc9449#section-5>
pub const ACCESS_TOKEN_TYPE_DPOP: &str = "DPoP";

/// WebAuthn Level 2 §5.1.3 (Create a New Credential) — registration.
///
/// The client sets `CollectedClientData.type` when building the credential:
///
/// > Let collectedClientData be a new CollectedClientData instance whose
/// > fields are:
/// >
/// > type
/// >    The string "webauthn.create".
///
/// <https://www.w3.org/TR/webauthn-2/#sctn-createCredential>
///
/// §7.1 (Registering a New Credential) step 7 is the matching check the
/// server performs: "Verify that the value of C.type is webauthn.create."
///
/// <https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential>
pub const CLIENT_DATA_TYPE_CREATE: &str = "webauthn.create";

/// WebAuthn Level 2 §5.1.4.1 (`[[DiscoverFromExternalSource]]`) — assertion.
///
/// The client sets `CollectedClientData.type` when building the assertion:
///
/// > Let collectedClientData be a new CollectedClientData instance whose
/// > fields are:
/// >
/// > type
/// >    The string "webauthn.get".
///
/// <https://www.w3.org/TR/webauthn-2/#sctn-discover-from-external-source>
///
/// §7.2 (Verifying an Authentication Assertion) step 11 is the matching
/// check: "Verify that the value of C.type is the string webauthn.get."
///
/// <https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion>
///
/// §5.8.1 states why the two values must never be interchanged: the member
/// exists "to prevent certain types of signature confusion attacks (where
/// an attacker substitutes one legitimate signature for another)".
///
/// <https://www.w3.org/TR/webauthn-2/#dictionary-client-data>
pub const CLIENT_DATA_TYPE_GET: &str = "webauthn.get";

/// RFC 7518 §3.1 (`"alg"` Header Parameter Values for JWS) — P-256 ECDSA.
///
/// The registry table gives the identifier and what it denotes:
///
/// > | ES256        | ECDSA using P-256 and SHA-256 | Recommended+       |
///
/// <https://www.rfc-editor.org/rfc/rfc7518#section-3.1>
///
/// This is the algorithm FAPI 2.0 permits and Vouch signs every
/// FAPI-scoped JWT with — DPoP proofs, client assertions, access and ID
/// tokens. `vouch_server::db::JwsAlgorithm` owns the enum; this is the
/// spelling its `Es256` arm serializes to.
pub const JWS_ALG_ES256: &str = "ES256";

/// RFC 6749 §4.1.3 (Access Token Request) — token endpoint request body.
///
/// > The client makes a request to the token endpoint by sending the
/// > following parameters using the "application/x-www-form-urlencoded"
/// > format per Appendix B with a character encoding of UTF-8 in the HTTP
/// > request entity-body:
///
/// <https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3>
pub const CONTENT_TYPE_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";

#[cfg(test)]
mod tests {
    use super::*;

    // Each constant is asserted against its literal spelled out a second
    // time. The duplication is the point: centralizing these values makes a
    // single typo change a URN everywhere at once, so an edit has to touch
    // both the constant and the RFC-named test that pins it.

    #[test]
    fn rfc8628_device_code_grant_type_urn() {
        assert_eq!(
            GRANT_TYPE_DEVICE_CODE,
            "urn:ietf:params:oauth:grant-type:device_code"
        );
    }

    #[test]
    fn rfc8693_token_exchange_grant_type_urn() {
        assert_eq!(
            GRANT_TYPE_TOKEN_EXCHANGE,
            "urn:ietf:params:oauth:grant-type:token-exchange"
        );
    }

    #[test]
    fn vouch_fido2_assertion_grant_type_urn() {
        assert_eq!(
            GRANT_TYPE_FIDO2_ASSERTION,
            "urn:ietf:params:oauth:grant-type:fido2-assertion"
        );
    }

    #[test]
    fn rfc7523_client_assertion_type_urn() {
        assert_eq!(
            CLIENT_ASSERTION_TYPE_JWT_BEARER,
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        );
    }

    #[test]
    fn rfc8693_access_token_type_urn() {
        assert_eq!(
            TOKEN_TYPE_ACCESS_TOKEN,
            "urn:ietf:params:oauth:token-type:access_token"
        );
    }

    #[test]
    fn rfc8693_id_token_type_urn() {
        assert_eq!(
            TOKEN_TYPE_ID_TOKEN,
            "urn:ietf:params:oauth:token-type:id_token"
        );
    }

    #[test]
    fn rfc8693_jwt_token_type_urn() {
        assert_eq!(TOKEN_TYPE_JWT, "urn:ietf:params:oauth:token-type:jwt");
    }

    #[test]
    fn rfc9449_use_dpop_nonce_error_code() {
        assert_eq!(ERROR_USE_DPOP_NONCE, "use_dpop_nonce");
    }

    #[test]
    fn rfc8628_authorization_pending_error_code() {
        assert_eq!(ERROR_AUTHORIZATION_PENDING, "authorization_pending");
    }

    #[test]
    fn rfc8628_slow_down_error_code() {
        assert_eq!(ERROR_SLOW_DOWN, "slow_down");
    }

    #[test]
    fn rfc8628_access_denied_error_code() {
        assert_eq!(ERROR_ACCESS_DENIED, "access_denied");
    }

    #[test]
    fn rfc8628_expired_token_error_code() {
        assert_eq!(ERROR_EXPIRED_TOKEN, "expired_token");
    }

    #[test]
    fn rfc9449_dpop_proof_header_name() {
        assert_eq!(HEADER_DPOP, "dpop");
    }

    #[test]
    fn rfc9449_dpop_nonce_header_name() {
        assert_eq!(HEADER_DPOP_NONCE, "dpop-nonce");
    }

    #[test]
    fn rfc6750_bearer_auth_scheme() {
        assert_eq!(AUTH_SCHEME_BEARER, "Bearer");
    }

    #[test]
    fn rfc9449_dpop_auth_scheme() {
        assert_eq!(AUTH_SCHEME_DPOP, "DPoP");
    }

    #[test]
    fn rfc6750_bearer_access_token_type() {
        assert_eq!(ACCESS_TOKEN_TYPE_BEARER, "Bearer");
    }

    #[test]
    fn rfc9449_dpop_access_token_type() {
        assert_eq!(ACCESS_TOKEN_TYPE_DPOP, "DPoP");
    }

    #[test]
    fn webauthn2_create_client_data_type() {
        assert_eq!(CLIENT_DATA_TYPE_CREATE, "webauthn.create");
    }

    #[test]
    fn webauthn2_get_client_data_type() {
        assert_eq!(CLIENT_DATA_TYPE_GET, "webauthn.get");
    }

    #[test]
    fn rfc7518_es256_jws_algorithm() {
        assert_eq!(JWS_ALG_ES256, "ES256");
    }

    #[test]
    fn rfc6749_form_urlencoded_content_type() {
        assert_eq!(
            CONTENT_TYPE_FORM_URLENCODED,
            "application/x-www-form-urlencoded"
        );
    }

    // The header-name constants are lowercase while the scheme and token
    // type constants that share their bytes are not. RFC 9449 §4.1 makes
    // field names case-insensitive and §7.1 fixes the scheme spelling, so
    // the two must not be collapsed into one constant.
    #[test]
    fn dpop_header_and_scheme_spellings_are_independent() {
        assert_ne!(HEADER_DPOP, AUTH_SCHEME_DPOP);
        assert_eq!(HEADER_DPOP, AUTH_SCHEME_DPOP.to_ascii_lowercase());
    }
}
