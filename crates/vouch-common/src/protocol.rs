// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OAuth 2.0 wire literals shared by the Vouch server and CLI.
//!
//! These are the exact bytes that cross the wire between the two crates:
//! `grant_type` and `client_assertion_type` values sent by the CLI and
//! dispatched by the server, RFC 8693 token type URNs, and the error codes
//! the CLI string-matches on to drive retries. Spelling them once means a
//! typo is a compile error on both sides instead of a runtime mismatch.
//!
//! Every constant carries the verbatim normative text that fixes its value,
//! with the section number and the URL it was fetched from.
//!
//! # Scope
//!
//! What belongs here is the CLI↔server contract, not every OAuth string the
//! workspace types. Two neighbours are deliberately absent:
//!
//! - `urn:ietf:params:oauth:grant-type:jwt-bearer` (RFC 7523 §2.1) is used
//!   by the CLI against AWS IAM Identity Center, Anthropic, and OpenAI,
//!   never against vouch-server — which rejects it. Those call sites keep
//!   their own literals: they answer to the provider's contract, not ours.
//! - The PAR `request_uri` URN prefix (RFC 9126 §2.2) is server-only; it
//!   lives in `vouch_server::db::par`.
//!
//! [`TOKEN_TYPE_JWT`] is the one constant here that vouch-server alone
//! sends. It is admitted because RFC 8693 §3 defines the three token type
//! identifiers as one group and the server matches on all three; splitting
//! the group across two crates would be worse than carrying it.
//!
//! Behavior stays where it is: `OAuthGrantType` and `OAuthErrorCode` remain
//! server-side enums, and their `as_str()` arms return these constants. The
//! enums own dispatch; this module owns bytes.

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
/// > Section 9 of [JWT], indicates that the token is a JWT.
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
/// > 400 (Bad Request) error response per Section 5.2 of [RFC6749] using
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
}
