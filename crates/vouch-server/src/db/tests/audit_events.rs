// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Auth/key/device audit event logging and expiry.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

// ========================================================================
// Authentication Event Tests
// ========================================================================

#[tokio::test]
async fn test_auth_event_logging() {
    let (store, audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "events@example.com", None)
        .await
        .expect("Failed to create user");

    // Log successful login (record_auth_event writes via AuditStore)
    config::record_auth_event(
        &audit,
        AuthEventParams {
            user_id: user_id.clone(),
            event_type: AuthEventType::LoginSuccess,
            authenticator_id: Some("auth-123".to_string()),
            client: ClientInfo {
                client_ip: Some("192.168.1.1".parse().unwrap()),
                user_agent: Some("Mozilla/5.0".to_string()),
                ..Default::default()
            },
            success: true,
            ..Default::default()
        },
        Some("events@example.com".to_string()),
    )
    .await;

    // Log failed login
    config::record_auth_event(
        &audit,
        AuthEventParams {
            user_id: user_id.clone(),
            event_type: AuthEventType::LoginFailed,
            client: ClientInfo {
                client_ip: Some("192.168.1.1".parse().unwrap()),
                ..Default::default()
            },
            success: false,
            failure_reason: Some("Invalid credential".to_string()),
            ..Default::default()
        },
        Some("events@example.com".to_string()),
    )
    .await;

    // The write is best-effort (failures are swallowed), so assert both
    // rows landed by querying them back.
    for expected in ["login_success", "login_failed"] {
        let events = audit
            .query_events(&AuditEventFilter {
                event_types: Some(vec![expected.to_string()]),
                user_id: Some(user_id.clone()),
                ..AuditEventFilter::default()
            })
            .await
            .expect("query events");
        assert_eq!(events.len(), 1, "expected one {expected} event");
    }
}

#[tokio::test]
async fn test_key_and_device_auth_events_round_trip_and_expire() {
    let (store, audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "key-events@example.com", None)
        .await
        .expect("Failed to create user");

    // Insert one event per key/device-auth lifecycle variant.
    let variants = [
        AuthEventType::KeyRegistered,
        AuthEventType::KeyRemoved,
        AuthEventType::DeviceAuthApproved,
    ];
    for event_type in variants {
        config::record_auth_event(
            &audit,
            AuthEventParams {
                user_id: user_id.clone(),
                event_type,
                authenticator_id: Some("auth-123".to_string()),
                success: true,
                ..Default::default()
            },
            Some("key-events@example.com".to_string()),
        )
        .await;
    }

    // Each variant is queryable under its expected event_type string.
    for expected in ["key_registered", "key_removed", "device_auth_approved"] {
        let events = audit
            .query_events(&AuditEventFilter {
                event_types: Some(vec![expected.to_string()]),
                ..AuditEventFilter::default()
            })
            .await
            .expect("query events");
        assert_eq!(events.len(), 1, "expected one {expected} event");
        assert_eq!(
            events[0].email_domain.as_deref(),
            Some("example.com"),
            "email must be masked to domain-only"
        );
    }

    // Retention must cover the new variants: the sweep derives coverage from
    // each variant's registry kind, so this fails if a kind loses its
    // AuthEvents retention class.
    let cutoff = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(1))
        .unwrap();
    let deleted = audit
        .delete_expired_events(Some(cutoff), None)
        .await
        .expect("delete old auth events");
    assert!(
        deleted >= 3,
        "expected the 3 lifecycle events to be deleted, got {deleted}"
    );
}
