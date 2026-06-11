// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared types for vouch CLI and server.

pub mod aaguid;
pub(crate) mod api;
pub mod aws;
pub(crate) mod cookie;
pub mod dns;
pub mod encoding;
pub(crate) mod error;
pub mod fido2_types;
pub mod fixtures;
pub mod fs;
pub mod http;
pub mod posture;
pub(crate) mod url;

#[cfg(test)]
mod api_tests;
#[cfg(test)]
mod encoding_tests;

pub use encoding::{Base64Url, ConvertEncoding, Encoded, Encoding, Raw};
pub use fido2_types::{
    AttestationObject, AttestationObjectData, AuthData, AuthenticatorDataMarker,
    Base64UrlChallenge, Base64UrlCredentialId, Challenge, ChallengeData, ClientDataJson,
    ClientDataJsonData, CoseKey, CoseKeyData, CredentialId, CredentialIdData, RawAttestationObject,
    RawAuthData, RawChallenge, RawClientDataJson, RawCoseKey, RawCredentialId, RawSignature,
    RawUserHandle, Signature, SignatureData, UserHandle, UserHandleData,
};

pub use aaguid::{
    AaguidPolicy, extract_aaguid_from_auth_data, extract_public_key_from_attestation,
    extract_public_key_from_auth_data, is_fips, is_yubikey_5, lookup_device_model,
};
pub use api::{
    AwsTokenResponse, BrowserLoginCompleteRequest, BrowserLoginCompleteResponse,
    BrowserLoginStartRequest, BrowserLoginStartResponse, BrowserRegisterCompleteRequest,
    BrowserRegisterStartRequest, BrowserRegisterStartResponse, CloudTokenResponse,
    DeleteKeyResponse, DeviceCodeRequest, DeviceCodeResponse, DeviceTokenRequest,
    DeviceTokenResponse, Fido2ChallengeResponse, GitHubAccountStatus, GitHubStatusResponse,
    GitHubTokenRequest, GitHubTokenResponse, KeyInfo, ListKeysResponse, OAuthError,
    RegisterCompleteRequest, RegisterCompleteResponse, RegisterStartRequest, RegisterStartResponse,
    RenameKeyRequest, RenameKeyResponse, SessionStatus, SshCaPublicKeyResponse,
    SshCertificateRequest, SshCertificateResponse, serialize_secret_string,
};
pub use cookie::{SessionCookie, clear_cookie, cookie_path, read_cookie, write_cookie};
pub use error::{ApiError, VouchError};
pub use url::{UrlSecurity, check_url_security, is_loopback_host};

/// Session cookie name with `__Host-` prefix (RFC 6265bis).
///
/// The `__Host-` prefix provides browser-enforced guarantees:
/// - Cookie must be set with `Secure` flag
/// - Cookie must be set from a secure origin
/// - Cookie must not include a `Domain` attribute
/// - Cookie must have `Path=/`
pub const SESSION_COOKIE_NAME: &str = "__Host-vouch_session";

/// SSH certificate refresh/reissue threshold in seconds (1 hour).
///
/// Used by both the CLI (skip re-issuance if cert has more remaining)
/// and the agent (trigger background refresh when cert has less remaining).
pub const SSH_CERT_REFRESH_THRESHOLD_SECS: i64 = 60 * 60;
