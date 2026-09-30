// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cross-crate tests: the CLI's HTTP client and FIDO2 device driving the
//! server, agent and HTTP-signature interplay, the WebAuthn contract
//! validators, and repository-wide scans. One binary, so the workspace is
//! linked once. A test that exercises a single crate belongs in that crate.

mod dogwood_temporal_e2e;
mod fido2_cross_client_e2e;
mod fido2_posture_e2e;
mod golden_files;
mod i18n_brand_terms;
mod integration;
mod pq_tls;
mod properties;
mod registration_counter_e2e;
mod sig_policy;
mod spec_coverage;
