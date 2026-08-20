// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Background cleanup tasks for expired data.
//!
//! This module handles periodic cleanup of:
//! - Expired sessions
//! - Expired device authorization requests
//! - Expired OIDC states
//! - Old audit events (retention per `AuditEventKind` registry class)
//! - Old token exchange records
//! - DPoP nonces and JTI cache

use crate::db;
use crate::db::audit::AuditStore;
use crate::db::documents::audit::{OrgDomainCleanupData, OrgSubdomainCleanupData};
use crate::db::store::DocumentStore;
use crate::infra::dns;
use aws_lc_rs::rand as aws_rand;
use jiff::{Span, Timestamp};
use secrecy::ExposeSecret;
use tokio::task::JoinHandle;

/// Minimum gap between consecutive DNS re-checks for the same domain.
///
/// Re-verification is best-effort drift detection, not real-time enforcement —
/// 24 hours is enough to notice a missing TXT well before it matters, while
/// keeping DNS load proportional to the number of verified domains.
const DOMAIN_RECHECK_MIN_INTERVAL_HOURS: i64 = 24;

/// Maximum number of DNS re-verification queries in flight at once.
///
/// Each task does a 5s-bounded TXT lookup plus a short DB write, so a small
/// fan-out keeps a single cleanup tick from stalling on the long tail of
/// slow recursive resolvers without overloading the resolver or DB.
const DOMAIN_RECHECK_CONCURRENCY: usize = 8;

/// Total budget for one re-verification pass. Any domains not yet processed
/// when this elapses are skipped and retried on the next cleanup tick.
const DOMAIN_RECHECK_PASS_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(5);

/// Pending additional-domain claims older than this are deleted by the
/// cleanup task. Prevents squatting — admins can't pre-claim domains they
/// never intend to verify and tie up their org's 10-domain cap.
const PENDING_DOMAIN_TTL_DAYS: i64 = 7;

/// Auto-unverified additional-domain entries older than this are deleted by
/// the cleanup task. Gives the admin a grace window to fix DNS after a
/// re-verification flip before the entry is removed entirely.
const UNVERIFIED_DOMAIN_TTL_DAYS: i64 = 14;

/// Build a [`Span`] of `days` worth of hours.
///
/// Day-unit arithmetic on a bare `Timestamp` would require a time zone (DST
/// can change a calendar day's duration), so we express day-scale retention
/// windows as fixed-length hour spans. Centralizing the conversion keeps the
/// `_TTL_DAYS` constants readable and prevents drift between call sites.
fn days_to_span(days: i64) -> Span {
    Span::new().hours(days.saturating_mul(24))
}

/// Compute a retention cutoff timestamp by subtracting days from now.
fn retention_cutoff(now: Timestamp, days: i64) -> Option<Timestamp> {
    now.checked_sub(days_to_span(days)).ok()
}

/// Log cleanup results: info on deletions, warn on errors, silent on zero.
macro_rules! cleanup_and_log {
    ($op:expr, $desc:expr) => {
        match $op.await {
            Ok(count) if count > 0 => {
                tracing::info!("Cleaned up {count} {}", $desc);
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("Failed to clean up {}: {e}", $desc);
            }
        }
    };
}

/// Generate a random jitter duration up to `max_jitter_secs` seconds.
///
/// Returns `Duration::ZERO` if `max_jitter_secs` is 0 or the RNG fails.
fn random_jitter(max_jitter_secs: u64) -> std::time::Duration {
    if max_jitter_secs == 0 {
        return std::time::Duration::ZERO;
    }
    let mut buf = [0u8; 8];
    if aws_rand::fill(&mut buf).is_ok() {
        // checked_rem returns None only if max_jitter_secs is 0; guarded above.
        let value = u64::from_le_bytes(buf)
            .checked_rem(max_jitter_secs)
            .unwrap_or(0);
        std::time::Duration::from_secs(value)
    } else {
        std::time::Duration::ZERO
    }
}

/// Start the background cleanup task.
///
/// Returns a handle to the spawned task for graceful shutdown.
///
/// Each iteration sleeps for the base interval plus a random jitter of up to
/// 20% of the interval. This staggers cleanup across multiple server instances
/// to avoid thundering-herd database pressure.
pub fn start_cleanup_task(
    store: DocumentStore,
    audit: AuditStore,
    interval_minutes: u64,
    auth_events_retention_days: i64,
    oauth_events_retention_days: i64,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let base_secs = interval_minutes.saturating_mul(60);
        // Jitter of up to 20% of the base interval
        // 5 is non-zero; unwrap_or arm is unreachable.
        let max_jitter_secs = base_secs.checked_div(5).unwrap_or(0);

        // Initial delay with jitter so instances started simultaneously don't
        // all fire their first cleanup at the same time.
        let initial_jitter = random_jitter(max_jitter_secs);
        let initial_delay =
            std::time::Duration::from_secs(base_secs).saturating_add(initial_jitter);
        tracing::debug!(
            "First cleanup in {}s (base {}s + jitter {}s)",
            initial_delay.as_secs(),
            base_secs,
            initial_jitter.as_secs(),
        );
        tokio::time::sleep(initial_delay).await;

        loop {
            tracing::debug!("Running background cleanup tasks");

            // Run all cleanup tasks
            run_cleanup(
                &store,
                &audit,
                auth_events_retention_days,
                oauth_events_retention_days,
            )
            .await;

            // Sleep with jitter before the next run
            let jitter = random_jitter(max_jitter_secs);
            let sleep_duration = std::time::Duration::from_secs(base_secs).saturating_add(jitter);
            tracing::debug!(
                "Next cleanup in {}s (base {}s + jitter {}s)",
                sleep_duration.as_secs(),
                base_secs,
                jitter.as_secs(),
            );
            tokio::time::sleep(sleep_duration).await;
        }
    })
}

/// Run all cleanup tasks once.
pub async fn run_cleanup(
    store: &DocumentStore,
    audit: &AuditStore,
    auth_events_retention_days: i64,
    oauth_events_retention_days: i64,
) {
    let now = Timestamp::now();
    let now_str = now.to_string();

    // Clean up expired data (DocumentStore)
    cleanup_and_log!(
        db::delete_expired_sessions(store, &now_str),
        "expired sessions"
    );
    cleanup_and_log!(
        db::delete_expired_device_auth_requests(store, &now_str),
        "expired device auth requests"
    );
    cleanup_and_log!(
        db::delete_expired_oidc_states(store, &now_str),
        "expired OIDC states"
    );
    cleanup_and_log!(
        db::delete_expired_pending_oauth_authorizations(store, &now_str),
        "expired pending OAuth authorizations"
    );
    cleanup_and_log!(
        db::delete_expired_pushed_authorization_requests(store, &now_str),
        "expired pushed authorization requests"
    );
    cleanup_and_log!(
        db::delete_expired_authorization_codes(store),
        "expired authorization codes"
    );
    cleanup_and_log!(
        db::delete_expired_challenge_states(store),
        "expired FIDO2 challenge states"
    );
    cleanup_and_log!(
        db::delete_expired_enrollment_sessions(store),
        "expired enrollment sessions"
    );

    // Clean up old audit events. Retention per event kind comes from the
    // AuditEventKind registry — a new kind cannot be added without declaring
    // its retention class.
    cleanup_and_log!(
        audit.delete_expired_events(
            retention_cutoff(now, auth_events_retention_days),
            retention_cutoff(now, oauth_events_retention_days),
        ),
        "expired audit events"
    );

    // Clean up old token exchanges (DocumentStore)
    cleanup_and_log!(
        db::delete_old_token_exchanges(store),
        "old token exchange records"
    );

    // Clean up expired JWT assertion JTIs (RFC 7523)
    cleanup_and_log!(
        db::delete_expired_jwt_assertion_jtis(store),
        "expired JWT assertion JTIs"
    );

    // Clean up expired DPoP nonces and JTIs (RFC 9449)
    cleanup_and_log!(
        db::delete_expired_dpop_nonces(store, &now_str),
        "expired DPoP nonces"
    );
    cleanup_and_log!(
        db::delete_expired_dpop_jtis(store, &now_str),
        "expired DPoP JTIs"
    );

    // Clean up expired SSH certificate revocations
    cleanup_and_log!(
        db::delete_expired_ssh_revocations(store),
        "expired SSH certificate revocations"
    );

    // Clean up expired SSH issued certificate records
    cleanup_and_log!(
        db::delete_expired_ssh_issued_certs(store),
        "expired SSH issued certificate records"
    );

    // Clean up expired JWKS cache entries (standalone cache docs)
    cleanup_and_log!(db::delete_expired_jwks_caches(store), "expired JWKS caches");

    // Clean up expired SCIM tokens (they cannot authenticate and would
    // otherwise accumulate against the per-org token limit)
    cleanup_and_log!(db::delete_expired_scim_tokens(store), "expired SCIM tokens");

    // Re-verify organization additional domains.
    if let Err(e) = recheck_additional_domains(store, audit, now).await {
        tracing::warn!(error = %e, "Additional-domain re-verification pass failed");
    }

    // Garbage-collect pending and auto-unverified additional domains.
    if let Err(e) = gc_stale_additional_domains(store, audit, now).await {
        tracing::warn!(error = %e, "Additional-domain GC pass failed");
    }

    tracing::debug!("Background cleanup tasks complete");
}

/// Delete additional-domain entries whose TTL has elapsed.
///
/// See [`PENDING_DOMAIN_TTL_DAYS`] and [`UNVERIFIED_DOMAIN_TTL_DAYS`]. Emits
/// an `org_domain_expired` audit event for each removal so admins can see
/// what disappeared and why.
async fn gc_stale_additional_domains(
    store: &DocumentStore,
    audit: &AuditStore,
    now: Timestamp,
) -> anyhow::Result<()> {
    let pending_ttl = days_to_span(PENDING_DOMAIN_TTL_DAYS);
    let unverified_ttl = days_to_span(UNVERIFIED_DOMAIN_TTL_DAYS);

    let removed =
        db::cleanup_stale_additional_domains(store, now, pending_ttl, unverified_ttl).await?;

    for r in removed {
        let reason = if r.never_verified {
            "pending_ttl_expired"
        } else {
            "unverified_ttl_expired"
        };
        tracing::info!(
            domain = %r.domain,
            org_id = %r.org_id,
            reason,
            "Removed stale additional-domain entry"
        );
        let data = OrgDomainCleanupData {
            action: "expire_org_domain",
            domain: &r.domain,
            org_id: &r.org_id,
            reason,
        };
        // Stamp the org's primary domain into `email_domain` — this event
        // has no user/email of its own, and without a domain it would be
        // invisible to org-scoped audit reads.
        let org_domain = match db::get_organization_domain(store, &r.org_id).await {
            Ok(domain) => domain,
            Err(e) => {
                tracing::warn!(error = %e, org_id = %r.org_id, "failed to look up org domain for org_domain_expired audit stamping");
                None
            }
        };
        if let Err(e) = audit
            .insert_event_with_domain(
                db::AuditEventKind::OrgDomainExpired,
                None,
                org_domain.as_deref(),
                &data,
            )
            .await
        {
            tracing::warn!(error = %e, "failed to write org_domain_expired audit event");
        }
    }
    Ok(())
}

/// Re-verify the DNS TXT ownership of every verified additional domain.
///
/// Skips domains that were checked within the last
/// [`DOMAIN_RECHECK_MIN_INTERVAL_HOURS`]. After
/// [`db::UNVERIFY_FAILURE_THRESHOLD`] consecutive failures the entry is
/// flipped to unverified, which immediately drops it from the document's
/// index entries so new logins from that domain no longer attach to the org.
///
/// Existing users keep their `org_id`; only future logins stop matching.
///
/// Up to [`DOMAIN_RECHECK_CONCURRENCY`] domains are checked in parallel and
/// the whole pass is bounded by [`DOMAIN_RECHECK_PASS_TIMEOUT`]; remaining
/// domains roll over to the next cleanup tick.
async fn recheck_additional_domains(
    store: &DocumentStore,
    audit: &AuditStore,
    now: Timestamp,
) -> anyhow::Result<()> {
    let records = db::list_all_verified_additional_domains(store).await?;
    if records.is_empty() {
        return Ok(());
    }

    let cutoff = now
        .checked_sub(Span::new().hours(DOMAIN_RECHECK_MIN_INTERVAL_HOURS))
        .map_err(|e| anyhow::anyhow!("recheck cutoff overflow: {e}"))?;

    let due: Vec<db::VerifiedDomainRecord> = records
        .into_iter()
        .filter(|rec| rec.last_checked_at.is_none_or(|ts| ts <= cutoff))
        .collect();
    if due.is_empty() {
        return Ok(());
    }

    let total = due.len();
    let pass = async {
        let mut iter = due.into_iter();
        let mut set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        // Seed initial batch up to the concurrency cap.
        while set.len() < DOMAIN_RECHECK_CONCURRENCY {
            let Some(rec) = iter.next() else { break };
            let store = store.clone();
            let audit = audit.clone();
            set.spawn(async move { recheck_one(&store, &audit, rec).await });
        }
        // Top up as tasks complete so at most CONCURRENCY are in flight.
        while set.join_next().await.is_some() {
            if let Some(rec) = iter.next() {
                let store = store.clone();
                let audit = audit.clone();
                set.spawn(async move { recheck_one(&store, &audit, rec).await });
            }
        }
    };

    if tokio::time::timeout(DOMAIN_RECHECK_PASS_TIMEOUT, pass)
        .await
        .is_err()
    {
        tracing::warn!(
            total,
            timeout_secs = DOMAIN_RECHECK_PASS_TIMEOUT.as_secs(),
            "Re-verification pass timed out; remaining domains will retry on next tick"
        );
    }
    Ok(())
}

/// Re-verify a single domain and persist the result. Errors are logged and
/// swallowed so one bad record never aborts the surrounding pass.
async fn recheck_one(store: &DocumentStore, audit: &AuditStore, rec: db::VerifiedDomainRecord) {
    let outcome =
        match dns::verify_txt_record(&rec.domain, rec.verification_token.expose_secret()).await {
            Ok(true) => db::RecheckOutcome::Success,
            Ok(false) => db::RecheckOutcome::Failure,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    domain = %rec.domain,
                    org_id = %rec.org_id,
                    "DNS re-verification lookup failed; treating as failure"
                );
                db::RecheckOutcome::Failure
            }
        };

    match db::record_recheck_result(store, &rec.org_id, &rec.domain, outcome).await {
        Ok(db::RecheckEffect::FlippedToUnverified { released_subdomain }) => {
            tracing::warn!(
                domain = %rec.domain,
                org_id = %rec.org_id,
                "Additional domain flipped to unverified after repeated DNS failures"
            );
            // Stamp the org's primary domain into `email_domain` for both
            // writes below — neither event has a user/email of its own,
            // and without a domain they'd be invisible to org-scoped
            // audit reads.
            let org_domain = match db::get_organization_domain(store, &rec.org_id).await {
                Ok(domain) => domain,
                Err(e) => {
                    tracing::warn!(error = %e, org_id = %rec.org_id, "failed to look up org domain for domain-unverify audit stamping");
                    None
                }
            };
            let data = OrgDomainCleanupData {
                action: "auto_unverify_org_domain",
                domain: &rec.domain,
                org_id: &rec.org_id,
                reason: "consecutive_dns_recheck_failures",
            };
            if let Err(e) = audit
                .insert_event_with_domain(
                    db::AuditEventKind::OrgDomainUnverified,
                    None,
                    org_domain.as_deref(),
                    &data,
                )
                .await
            {
                tracing::warn!(error = %e, "failed to write org_domain_unverified audit event");
            }
            if let Some(label) = released_subdomain {
                let data = OrgSubdomainCleanupData {
                    action: "release_subdomain",
                    label: &label,
                    org_id: &rec.org_id,
                    reason: "backing_domain_unverified",
                };
                if let Err(e) = audit
                    .insert_event_with_domain(
                        db::AuditEventKind::OrgSubdomainReleased,
                        None,
                        org_domain.as_deref(),
                        &data,
                    )
                    .await
                {
                    tracing::warn!(
                        error = %e,
                        "failed to write org_subdomain_released audit event"
                    );
                }
            }
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(
                error = %e,
                domain = %rec.domain,
                org_id = %rec.org_id,
                "Failed to record domain re-verification result"
            );
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    /// Regression test for the NULL-`email_domain` bug: `gc_stale_additional_domains`
    /// writes `org_domain_expired` with no user/email of its own, so without
    /// stamping the org's primary domain, the event would be invisible to
    /// org-scoped audit reads (`/admin/audit`, the audit events API).
    #[tokio::test]
    async fn gc_stale_additional_domains_stamps_org_primary_domain() {
        use crate::crypto::document_crypto::PlaintextDocumentCrypto;
        use crate::db::documents::organization::{
            AdditionalDomain, AdditionalDomainState, OrganizationDoc,
        };
        use std::sync::Arc;

        let pool = crate::test_utils::test_db().await;
        let crypto: Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
            Arc::new(PlaintextDocumentCrypto);
        let store = DocumentStore::new(pool.clone(), crypto.clone());
        let audit = AuditStore::new(pool, crypto);

        let org = db::create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();

        // A pending additional domain added 10 days ago (past the 7-day
        // pending TTL) so the cleanup pass removes it.
        let stale_added = Timestamp::now()
            .checked_sub(Span::new().hours(10 * 24))
            .unwrap();
        let mut doc = store
            .get::<OrganizationDoc>(&org.id)
            .await
            .unwrap()
            .unwrap();
        doc.data.additional_domains.push(AdditionalDomain {
            domain: "squatted.example.com".to_string(),
            verification_token: "tok".into(),
            added_at: stale_added,
            added_by_user_id: "u1".to_string(),
            added_by_email: "u1@acme.com".to_string(),
            consecutive_failures: 0,
            state: AdditionalDomainState::Pending,
        });
        store.update(&org.id, &doc.data).await.unwrap();

        gc_stale_additional_domains(&store, &audit, Timestamp::now())
            .await
            .expect("cleanup pass must succeed");

        let events = audit
            .query_events(&db::AuditEventFilter {
                event_types: Some(vec!["org_domain_expired".to_string()]),
                ..db::AuditEventFilter::default()
            })
            .await
            .expect("query audit events");
        assert_eq!(
            events.len(),
            1,
            "one org_domain_expired event must be written"
        );
        assert_eq!(
            events[0].email_domain.as_deref(),
            Some("acme.com"),
            "event must carry the org's primary domain, not NULL"
        );
    }

    /// Regression test for the NULL-`email_domain` bug at `recheck_one`'s
    /// two write sites (`org_domain_unverified`, `org_subdomain_released`)
    /// — the sibling fix to `gc_stale_additional_domains_stamps_org_primary_domain`
    /// above, for the other cleanup entry point that stamps an org domain.
    ///
    /// Drives `recheck_one` through real DNS resolution against a domain
    /// with no `_vouch-verification` TXT record: `verify_txt_record`
    /// converges to `RecheckOutcome::Failure` whether that lookup returns
    /// "no records found" or errors outright (e.g. no network egress in a
    /// sandboxed test run) — `recheck_one` maps both to `Failure` — so this
    /// is deterministic regardless of network availability.
    #[tokio::test]
    async fn recheck_one_stamps_org_primary_domain_on_unverify_and_subdomain_release() {
        use crate::crypto::document_crypto::PlaintextDocumentCrypto;
        use std::sync::Arc;

        let pool = crate::test_utils::test_db().await;
        let crypto: Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
            Arc::new(PlaintextDocumentCrypto);
        let store = DocumentStore::new(pool.clone(), crypto.clone());
        let audit = AuditStore::new(pool, crypto);

        let org = db::create_organization(&store, "acme.com", None, None)
            .await
            .unwrap();
        db::add_additional_domain(&store, &org.id, "widgets.io", "u1", "u1@acme.com")
            .await
            .unwrap();
        db::mark_additional_domain_verified(&store, &org.id, "widgets.io")
            .await
            .unwrap();
        db::claim_subdomain(&store, &org.id, "widgets-io")
            .await
            .unwrap();

        let rec = db::VerifiedDomainRecord {
            org_id: org.id.clone(),
            domain: "widgets.io".to_string(),
            verification_token: "tok".into(),
            last_checked_at: None,
            consecutive_failures: 0,
        };
        for _ in 0..db::UNVERIFY_FAILURE_THRESHOLD {
            recheck_one(&store, &audit, rec.clone()).await;
        }

        let unverified_events = audit
            .query_events(&db::AuditEventFilter {
                event_types: Some(vec!["org_domain_unverified".to_string()]),
                ..db::AuditEventFilter::default()
            })
            .await
            .expect("query audit events");
        assert_eq!(
            unverified_events.len(),
            1,
            "one org_domain_unverified event must be written"
        );
        assert_eq!(
            unverified_events[0].email_domain.as_deref(),
            Some("acme.com"),
            "org_domain_unverified event must carry the org's primary domain, not NULL"
        );

        let released_events = audit
            .query_events(&db::AuditEventFilter {
                event_types: Some(vec!["org_subdomain_released".to_string()]),
                ..db::AuditEventFilter::default()
            })
            .await
            .expect("query audit events");
        assert_eq!(
            released_events.len(),
            1,
            "one org_subdomain_released event must be written"
        );
        assert_eq!(
            released_events[0].email_domain.as_deref(),
            Some("acme.com"),
            "org_subdomain_released event must carry the org's primary domain, not NULL"
        );
    }

    #[test]
    fn test_retention_cutoff_30_days() {
        let now = Timestamp::now();
        let cutoff = retention_cutoff(now, 30).expect("30 days should not overflow");
        let diff_secs = now.duration_since(cutoff).as_secs();
        let expected_secs: i64 = 30 * 24 * 3600;
        assert!(
            (expected_secs - 5..=expected_secs + 5).contains(&diff_secs),
            "30-day cutoff should be ~{expected_secs}s ago, got {diff_secs}s"
        );
    }

    #[test]
    fn test_retention_cutoff_one_day() {
        let now = Timestamp::now();
        let cutoff = retention_cutoff(now, 1).expect("1 day should not overflow");
        let diff_secs = now.duration_since(cutoff).as_secs();
        let expected_secs: i64 = 24 * 3600;
        assert!(
            (expected_secs - 5..=expected_secs + 5).contains(&diff_secs),
            "1-day cutoff should be ~{expected_secs}s ago, got {diff_secs}s"
        );
    }

    #[test]
    fn test_retention_cutoff_is_in_the_past() {
        let now = Timestamp::now();
        let cutoff = retention_cutoff(now, 90).expect("90 days should not overflow");
        assert!(cutoff < now, "cutoff must be before now");
    }

    #[test]
    fn test_retention_cutoff_zero_days_returns_now() {
        let now = Timestamp::now();
        let cutoff = retention_cutoff(now, 0).expect("0 days should not overflow");
        let diff_secs = now.duration_since(cutoff).as_secs().abs();
        assert!(diff_secs <= 1, "0-day cutoff should be ~now");
    }

    // -----------------------------------------------------------------
    // random_jitter
    // -----------------------------------------------------------------

    #[test]
    fn random_jitter_zero_returns_zero() {
        let jitter = random_jitter(0);
        assert_eq!(jitter, std::time::Duration::ZERO);
    }

    #[test]
    fn random_jitter_is_bounded_above_by_input() {
        // The function returns `value % max_jitter_secs` seconds, so the result
        // must be strictly less than the cap. Sample several draws so a single
        // unlucky zero doesn't pass the bound check by accident.
        let cap_secs = 30u64;
        for _ in 0..32 {
            let jitter = random_jitter(cap_secs);
            assert!(
                jitter < std::time::Duration::from_secs(cap_secs),
                "jitter {:?} exceeds cap {cap_secs}s",
                jitter
            );
        }
    }
}
