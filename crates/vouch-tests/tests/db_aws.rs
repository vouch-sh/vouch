// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Round-trip tests for AWS credential audit events
//! (`AuditStore::log_credential_event` with [`AwsCredentialDetails`]).

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panicking on an assertion failure is the point"
)]

use vouch_server::db::{self, AuditEventFilter, AwsCredentialDetails, CredentialAuditEnvelope};
use vouch_tests::TestHarness;

async fn query_aws_events(harness: &TestHarness) -> Vec<db::AuditEvent> {
    harness
        .state
        .audit
        .query_events(&AuditEventFilter {
            event_types: Some(vec!["aws_credential".to_string()]),
            ..AuditEventFilter::default()
        })
        .await
        .expect("query audit events")
}

#[tokio::test]
async fn aws_credential_event_persists_pinned_role() {
    let harness = TestHarness::new().await;
    harness
        .state
        .audit
        .log_credential_event(
            "user-123",
            "user@example.com",
            CredentialAuditEnvelope {
                event_type: "token_issued".to_string(),
                org_id: Some("test-org".to_string()),
                agent: Some("claude-code".to_string()),
                success: true,
                ..Default::default()
            },
            &AwsCredentialDetails {
                role_arn: Some("arn:aws:iam::111122223333:role/Example".to_string()),
                token_expires_at: None,
            },
        )
        .await;

    let events = query_aws_events(&harness).await;
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.event_type, "aws_credential");
    assert_eq!(
        event.email_domain.as_deref(),
        Some("example.com"),
        "email must be masked to domain-only"
    );

    let data: serde_json::Value = serde_json::from_str(&event.data).expect("parse data");
    assert_eq!(data["event_type"], "token_issued");
    assert_eq!(data["role_arn"], "arn:aws:iam::111122223333:role/Example");
    assert_eq!(data["agent"], "claude-code");
    assert_eq!(data["success"], true);
}

#[tokio::test]
async fn aws_credential_event_unpinned_has_null_role() {
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
            &AwsCredentialDetails::default(),
        )
        .await;

    let events = query_aws_events(&harness).await;
    assert_eq!(events.len(), 1);
    let data: serde_json::Value = serde_json::from_str(&events[0].data).expect("parse data");
    assert!(
        data["role_arn"].is_null(),
        "unpinned token records a null role_arn"
    );
}

#[tokio::test]
async fn retention_sweep_removes_aws_credential_events() {
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
            &AwsCredentialDetails::default(),
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
    assert!(query_aws_events(&harness).await.is_empty());
}
