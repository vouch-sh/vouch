// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Admin-page view-model for the signing-key panel.

use anyhow::{Context, Result};
use jiff::Timestamp;

use super::rotation::{RevokeOutcome, RotateOutcome, publish_ready_at, revoke_ready_at};
use super::state_priority;
use crate::AppState;
use crate::db;
use crate::db::documents::oauth::JwsAlgorithm;
use crate::db::documents::organization::SigningKeyState;

// ---------------------------------------------------------------------------
// Admin page panel
// ---------------------------------------------------------------------------

/// One key row for the admin page's signing-key panel.
pub(crate) struct OrgKeyPanelRow {
    pub alg: JwsAlgorithm,
    pub state: SigningKeyState,
    pub kid: String,
    /// `staged_at` for Next keys, `demoted_at` for Previous keys.
    pub since: Option<Timestamp>,
}

/// The admin page's view of an org's key set and what the two buttons may do.
///
/// Blocked reasons reuse the operation outcome types so the page and the POST
/// handlers derive their messages from the same source.
pub(crate) struct OrgKeyPanel {
    /// RS256 rows first, Current → Next → Previous within each algorithm.
    pub rows: Vec<OrgKeyPanelRow>,
    /// Why rotate would be rejected right now; `None` when it may proceed.
    pub rotate_blocked: Option<RotateOutcome>,
    /// Why revoke would be rejected right now; `None` when it may proceed.
    pub revoke_blocked: Option<RevokeOutcome>,
}

/// Build the signing-key panel for the admin subdomain page.
///
/// Read-only: unlike the operations themselves this never stages or heals
/// anything, so rendering the page has no side effects.
///
/// # Errors
/// Returns an error if the key list cannot be loaded or a stored key is
/// missing its state timestamp.
pub(crate) async fn org_key_panel(state: &AppState, org_id: &str) -> Result<OrgKeyPanel> {
    let now = Timestamp::now();
    let mut docs = db::list_org_signing_keys(&state.store, org_id).await?;
    docs.sort_by_key(|d| {
        (
            d.data.alg != JwsAlgorithm::Rs256,
            state_priority(d.data.state),
        )
    });

    let mut has_previous = false;
    let mut missing_current_or_next = false;
    let mut latest_next_ready: Option<Timestamp> = None;
    let mut latest_revoke_ready: Option<Timestamp> = None;

    for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
        let find = |state: SigningKeyState| {
            docs.iter()
                .find(|d| d.data.alg == alg && d.data.state == state)
        };
        if let Some(prev) = find(SigningKeyState::Previous) {
            has_previous = true;
            let demoted_at = prev
                .data
                .demoted_at
                .context("previous key is missing its demoted_at timestamp")?;
            let ready_at = revoke_ready_at(demoted_at, state.config().session_hours)?;
            if latest_revoke_ready.is_none_or(|cur| ready_at > cur) {
                latest_revoke_ready = Some(ready_at);
            }
        }
        match (find(SigningKeyState::Current), find(SigningKeyState::Next)) {
            (Some(_), Some(next)) => {
                let staged_at = next
                    .data
                    .staged_at
                    .context("next key is missing its staged_at timestamp")?;
                let ready_at = publish_ready_at(staged_at)?;
                if latest_next_ready.is_none_or(|cur| ready_at > cur) {
                    latest_next_ready = Some(ready_at);
                }
            }
            // Legacy rows: a rotate attempt heals the missing Next and starts
            // its publish window, so report the state a rotate would produce.
            (Some(_), None) => {
                let ready_at = publish_ready_at(now)?;
                if latest_next_ready.is_none_or(|cur| ready_at > cur) {
                    latest_next_ready = Some(ready_at);
                }
            }
            // Keys are created on first use; until then nothing can rotate.
            (None, _) => missing_current_or_next = true,
        }
    }

    let rotate_blocked = if has_previous {
        Some(RotateOutcome::PreviousUnrevoked)
    } else if missing_current_or_next {
        Some(RotateOutcome::NotBootstrapped)
    } else {
        match latest_next_ready {
            Some(ready_at) if ready_at > now => Some(RotateOutcome::NextNotReady { ready_at }),
            _ => None,
        }
    };
    let revoke_blocked = if has_previous {
        match latest_revoke_ready {
            Some(ready_at) if ready_at > now => Some(RevokeOutcome::NotReady { ready_at }),
            _ => None,
        }
    } else {
        Some(RevokeOutcome::NothingToRevoke)
    };

    let rows = docs
        .into_iter()
        .map(|d| OrgKeyPanelRow {
            alg: d.data.alg,
            state: d.data.state,
            kid: d.data.kid,
            since: d.data.staged_at.or(d.data.demoted_at),
        })
        .collect();
    Ok(OrgKeyPanel {
        rows,
        rotate_blocked,
        revoke_blocked,
    })
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::super::test_support::{NO_OPERATOR, backdate, setup};
    use super::*;
    use crate::db::JwsAlgorithm;
    use crate::services::oidc::{resolve_org_keys, rotate_org_keys};

    #[tokio::test]
    async fn panel_gates_follow_the_key_set_state() {
        let (state, org_id, org) = setup().await;

        // Before first use: nothing to rotate or revoke.
        let panel = super::org_key_panel(&state, &org_id).await.unwrap();
        assert!(panel.rows.is_empty());
        assert_eq!(panel.rotate_blocked, Some(RotateOutcome::NotBootstrapped));
        assert_eq!(panel.revoke_blocked, Some(RevokeOutcome::NothingToRevoke));

        // Bootstrapped, next keys fresh: rotate gated by the publish window.
        resolve_org_keys(&state, Some(&org)).await.unwrap();
        let panel = super::org_key_panel(&state, &org_id).await.unwrap();
        assert_eq!(panel.rows.len(), 4);
        assert!(
            matches!(
                panel.rotate_blocked,
                Some(RotateOutcome::NextNotReady { .. })
            ),
            "got {:?}",
            panel.rotate_blocked
        );

        // Aged next keys: rotate allowed.
        backdate(
            &state,
            &org_id,
            JwsAlgorithm::Es256,
            SigningKeyState::Next,
            25,
        )
        .await;
        backdate(
            &state,
            &org_id,
            JwsAlgorithm::Rs256,
            SigningKeyState::Next,
            25,
        )
        .await;
        let panel = super::org_key_panel(&state, &org_id).await.unwrap();
        assert_eq!(panel.rotate_blocked, None);

        // After a rotate: the unrevoked previous outranks the (young) next
        // key's warm-up as the rotate-blocked reason, and revoke is gated by
        // the drain window.
        rotate_org_keys(&state, &org_id, NO_OPERATOR).await.unwrap();
        let panel = super::org_key_panel(&state, &org_id).await.unwrap();
        assert_eq!(panel.rows.len(), 6);
        assert_eq!(panel.rotate_blocked, Some(RotateOutcome::PreviousUnrevoked));
        assert!(
            matches!(panel.revoke_blocked, Some(RevokeOutcome::NotReady { .. })),
            "got {:?}",
            panel.revoke_blocked
        );

        // Past the drain window: revoke allowed.
        backdate(
            &state,
            &org_id,
            JwsAlgorithm::Es256,
            SigningKeyState::Previous,
            30,
        )
        .await;
        backdate(
            &state,
            &org_id,
            JwsAlgorithm::Rs256,
            SigningKeyState::Previous,
            30,
        )
        .await;
        let panel = super::org_key_panel(&state, &org_id).await.unwrap();
        assert_eq!(panel.revoke_blocked, None);
    }
}
