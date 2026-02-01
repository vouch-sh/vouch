// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS integration utilities.
//!
//! - `config` - AWS config file (~/.aws/config) parsing
//! - `sts` - AWS STS (Security Token Service) utilities

pub mod config;
pub mod sts;

// Re-export commonly used types
pub use config::{AwsConfig, AwsProfile, extract_role_from_credential_process};
