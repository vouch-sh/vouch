//! Shared types for vouch CLI and server.

pub mod aaguid;
pub mod api;
pub mod attestation;
pub mod clock;
pub mod contracts;
pub mod cookie;
pub mod encoding;
pub mod error;
pub mod fido2_types;
pub mod fixtures;

#[cfg(test)]
mod api_tests;
#[cfg(test)]
mod encoding_tests;

pub use encoding::{Base64Url, ConvertEncoding, Encoded, Encoding, Raw};
pub use fido2_types::*;

pub use aaguid::{
    extract_aaguid_from_auth_data, extract_public_key_from_attestation,
    extract_public_key_from_auth_data, lookup_device_model,
};
pub use api::*;
pub use attestation::{
    AttestationFormat, AttestationValidation, extract_aaguid_from_attestation,
    extract_attestation_format, validate_hardware_attestation,
};
#[cfg(any(test, feature = "test-utils"))]
pub use clock::TestClock;
pub use clock::{Clock, SystemClock};
pub use cookie::{
    SessionCookie, clear_cookie, cookie_path, is_cookie_expired, read_cookie, write_cookie,
};
pub use error::*;
