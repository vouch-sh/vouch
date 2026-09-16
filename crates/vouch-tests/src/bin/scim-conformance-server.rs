// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Serves the SCIM API over TCP for an external conformance suite.
//!
//! Usage: `scim-conformance-server <listen-addr> <token-file>`
//!
//! Builds the server's router over an in-memory test state, seeds an
//! organization for `example.com` with three users and a group, writes a
//! SCIM bearer token for that organization to `<token-file>`, and serves
//! until killed. The suite's own create tests use `example.com` addresses,
//! which the organization's domain check requires.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use serde_json::json;
use vouch_tests::TestHarness;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let (Some(listen), Some(token_file), None) = (args.next(), args.next(), args.next()) else {
        bail!("usage: scim-conformance-server <listen-addr> <token-file>");
    };
    let listen: SocketAddr = listen.parse().context("parse listen address")?;

    let state = vouch_server::test_utils::test_app_state().await;
    // The rate limiters are skipped only when a certification token is
    // configured; a conformance run sends a burst the general limiter would
    // refuse. The token affects the certification routes, not SCIM.
    let mut config = state.config().as_ref().clone();
    config.certification_test_token = Some("scim-conformance".to_string().into());
    state.config.store(Arc::new(config));
    let harness = TestHarness::from_state(state);

    let org = harness.create_org("example.com").await?;
    let token = harness
        .create_scim_token("scim conformance", &org.id)
        .await?;
    for name in ["alice", "bob", "carol"] {
        let resp = harness
            .post_json_authenticated(
                "/scim/v2/Users",
                &json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "userName": format!("{name}@example.com"),
                    "active": true,
                }),
                &token,
            )
            .await?;
        ensure!(
            resp.status == 201,
            "seeding user {name}: status {}",
            resp.status
        );
    }
    let resp = harness
        .post_json_authenticated(
            "/scim/v2/Groups",
            &json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": "Seed Group",
            }),
            &token,
        )
        .await?;
    ensure!(resp.status == 201, "seeding group: status {}", resp.status);

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind {listen}"))?;
    std::fs::write(&token_file, &token).with_context(|| format!("write {token_file}"))?;
    axum::serve(
        listener,
        harness
            .router
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("serve")
}
