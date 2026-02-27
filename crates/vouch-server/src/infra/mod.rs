// SPDX-License-Identifier: BUSL-1.1
//! Server infrastructure: TLS, background cleanup, S3 config polling, config encryption,
//! route construction, security headers, static assets, and server lifecycle.
//!
//! These modules handle operational concerns for running the server binary.
//! They are not part of the business logic or HTTP handler layers.

pub mod cleanup;
pub mod decrypt_config;
pub mod encrypt_config;
pub mod generate_document_key;
pub mod rate_limit;
pub mod request_id;
pub mod router;
pub mod s3_config;
pub mod security_headers;
pub mod serve;
pub mod startup;
pub mod static_assets;
pub mod tls;
