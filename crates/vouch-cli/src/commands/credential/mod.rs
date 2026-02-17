// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Credential issuance commands.

pub mod aws;
pub(crate) mod cache;
pub mod cargo;
pub mod codeartifact;
pub mod codecommit;
pub mod docker;
pub mod git_protocol;
pub mod github;

pub mod ssh;
