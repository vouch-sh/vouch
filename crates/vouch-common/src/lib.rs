//! Shared types for vouch CLI and server.

pub mod aaguid;
pub mod api;
pub mod cookie;
pub mod error;

pub use aaguid::{extract_aaguid_from_auth_data, lookup_device_model};
pub use api::*;
pub use cookie::{
    SessionCookie, clear_cookie, cookie_path, is_cookie_expired, read_cookie, write_cookie,
};
pub use error::*;
