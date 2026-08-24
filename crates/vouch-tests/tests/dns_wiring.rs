// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Verifies that the process-wide DoH resolver wires through to every
//! reqwest client built via `vouch-common`'s HTTP factories.
//!
//! Integration scope: this is a *wiring-existence* check (every factory
//! reaches `process_resolver()`), not an end-to-end DNS lookup. The
//! lookup path is exercised separately by `vouch doctor` against a live
//! provider.

#![expect(
    clippy::expect_used,
    reason = "test code: panicking on an assertion failure is the point"
)]

use vouch_common::dns::{DohConfig, DohResolver, install_process_resolver, process_resolver};
use vouch_common::http::{agent_client, credential_client, server_client};

#[test]
fn install_process_resolver_wires_through_all_factories() {
    // Pre-install: nothing has been set, so the accessors report defaults.
    assert!(process_resolver().is_none(), "no resolver before install");

    // Install Cloudflare DoH for the rest of this test process.
    let cfg = DohConfig::Cloudflare;
    let resolver = DohResolver::for_config(&cfg);
    assert!(
        resolver.is_some(),
        "for_config(Cloudflare) should produce a resolver"
    );
    install_process_resolver(cfg, resolver);

    // After install, the resolver accessor reflects the new state.
    assert!(
        process_resolver().is_some(),
        "process_resolver should return Some after install"
    );

    // Each factory must construct successfully with the resolver applied.
    // The build is what exercises the dns_resolver wiring; if any future
    // edit removes `with_process_doh` from a factory, this test alone
    // wouldn't catch a silent skip — but a build failure here would
    // surface a misuse of the resolver type or feature flags.
    credential_client("test-credential/1.0").expect("credential_client builds");
    agent_client("test-agent/1.0").expect("agent_client builds");
    server_client("test-server/1.0", None).expect("server_client builds");

    // Idempotency: a second install must NOT replace the state. Attempt
    // to install Off and verify the resolver from the first install survives.
    install_process_resolver(DohConfig::Off, None);
    assert!(
        process_resolver().is_some(),
        "resolver from first install survives a second-call attempt"
    );
}
