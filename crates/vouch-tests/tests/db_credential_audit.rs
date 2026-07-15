// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Round-trip tests for SSH certificate and RFC 8693 token exchange audit
//! events (`AuditStore::log_credential_event` with the per-kind details).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use vouch_server::db::{
    self, AuditEventFilter, CredentialAuditEnvelope, SshCredentialDetails, TokenExchangeDetails,
};
use vouch_tests::TestHarness;

async fn query_events(harness: &TestHarness, event_type: &str) -> Vec<db::AuditEvent> {
    harness
        .state
        .audit
        .query_events(&AuditEventFilter {
            event_types: Some(vec![event_type.to_string()]),
            ..AuditEventFilter::default()
        })
        .await
        .expect("query audit events")
}

#[tokio::test]
async fn ssh_credential_event_persists_serial_and_principals() {
    let harness = TestHarness::new().await;
    harness
        .state
        .audit
        .log_credential_event(
            "user-123",
            "user@example.com",
            CredentialAuditEnvelope {
                event_type: "certificate_issued".to_string(),
                agent: Some("claude-code".to_string()),
                success: true,
                ..Default::default()
            },
            &SshCredentialDetails {
                serial: 42,
                principals: vec!["dev".to_string()],
                cert_expires_at: None,
            },
        )
        .await;

    let events = query_events(&harness, "ssh_credential").await;
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].email_domain.as_deref(),
        Some("example.com"),
        "email must be masked to domain-only"
    );
    let data: serde_json::Value = serde_json::from_str(&events[0].data).expect("parse data");
    assert_eq!(data["event_type"], "certificate_issued");
    assert_eq!(data["serial"], 42);
    assert_eq!(data["principals"], serde_json::json!(["dev"]));
    assert_eq!(data["agent"], "claude-code");
}

#[tokio::test]
async fn retention_sweep_removes_ssh_credential_events() {
    let harness = TestHarness::new().await;
    harness
        .state
        .audit
        .log_credential_event(
            "user-123",
            "user@example.com",
            CredentialAuditEnvelope {
                event_type: "certificate_issued".to_string(),
                success: true,
                ..Default::default()
            },
            &SshCredentialDetails::default(),
        )
        .await;

    let cutoff = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(1))
        .unwrap();
    let deleted = harness
        .state
        .audit
        .delete_expired_events(None, Some(cutoff))
        .await
        .expect("delete events");
    assert_eq!(deleted, 1);
    assert!(query_events(&harness, "ssh_credential").await.is_empty());
}

#[tokio::test]
async fn token_exchange_event_persists_audience_and_scope() {
    let harness = TestHarness::new().await;
    harness
        .state
        .audit
        .log_credential_event(
            "user-123",
            "user@example.com",
            CredentialAuditEnvelope {
                event_type: "token_issued".to_string(),
                success: true,
                ..Default::default()
            },
            &TokenExchangeDetails {
                client_id: "cli-client".to_string(),
                audience: Some("https://api.anthropic.com".to_string()),
                scope: Some("openid".to_string()),
                issued_token_type: "access_token".to_string(),
                token_expires_at: Some("2026-07-14T00:00:00Z".to_string()),
            },
        )
        .await;

    let events = query_events(&harness, "token_exchange").await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].email_domain.as_deref(), Some("example.com"));
    let data: serde_json::Value = serde_json::from_str(&events[0].data).expect("parse data");
    assert_eq!(data["client_id"], "cli-client");
    assert_eq!(data["audience"], "https://api.anthropic.com");
    assert_eq!(data["issued_token_type"], "access_token");
}

#[tokio::test]
async fn retention_sweep_removes_token_exchange_events() {
    let harness = TestHarness::new().await;
    harness
        .state
        .audit
        .log_credential_event(
            "user-123",
            "user@example.com",
            CredentialAuditEnvelope {
                event_type: "token_issued".to_string(),
                success: true,
                ..Default::default()
            },
            &TokenExchangeDetails {
                client_id: "cli-client".to_string(),
                issued_token_type: "access_token".to_string(),
                ..Default::default()
            },
        )
        .await;

    let cutoff = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(1))
        .unwrap();
    let deleted = harness
        .state
        .audit
        .delete_expired_events(None, Some(cutoff))
        .await
        .expect("delete events");
    assert_eq!(deleted, 1);
    assert!(query_events(&harness, "token_exchange").await.is_empty());
}
