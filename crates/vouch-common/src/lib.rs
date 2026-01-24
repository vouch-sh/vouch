//! Shared types for vouch CLI and server.

pub mod aaguid;
pub mod api;
pub mod error;

pub use aaguid::{extract_aaguid_from_auth_data, lookup_device_model};
pub use api::*;
pub use error::*;
