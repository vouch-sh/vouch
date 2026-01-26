//! Shared types for vouch CLI and server.

pub mod aaguid;
pub mod api;
pub mod attestation;
pub mod clock;
pub mod cookie;
pub mod error;

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
