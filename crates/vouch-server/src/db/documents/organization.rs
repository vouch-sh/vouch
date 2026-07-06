// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Organization document type.

use jiff::Timestamp;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::db::document_type::{DocumentType, IndexEntry};
use crate::db::documents::oauth::JwsAlgorithm;

/// An organization (tenant).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationDoc {
    pub domain: String,
    pub name: Option<String>,
    pub created_by_user_id: Option<String>,
    /// Additional email domains owned by the organization.
    ///
    /// Each entry must complete DNS TXT ownership verification before it
    /// participates in login matching. Pending entries are stored on the
    /// document but are not indexed.
    #[serde(default)]
    pub additional_domains: Vec<AdditionalDomain>,
    /// Subdomain label claimed as this org's OIDC issuer host for AWS
    /// workload identity federation (e.g. `acme-com` →
    /// `https://acme-com.us.vouch.sh`).
    ///
    /// Derived from the full registrable apex of one of the org's verified
    /// domains (`acme.com` → `acme-com`). Indexed for host→org lookup when
    /// serving discovery. The authoritative uniqueness record is the
    /// [`SubdomainClaimDoc`] slot; this field is the org-side mirror written
    /// in the same transaction.
    #[serde(default)]
    pub subdomain: Option<String>,
}

/// The claim slot for an issuer-subdomain label.
///
/// Stored under a **deterministic document ID** derived from the label, so
/// the `documents` primary key is what makes cross-org claims collide:
/// concurrent claimants either hit a unique violation on insert or a
/// version conflict on `compare_and_update` — an indexed lookup alone
/// cannot enforce cross-row uniqueness (the index only unique-constrains
/// per document). Same pattern as `deterministic_org_id` in enrollment.
///
/// The slot survives release (`released_at = Some`) and doubles as the
/// reuse-cooldown tombstone: a different org taking over a released slot
/// must `compare_and_update` the same row, so cooldown and apex checks are
/// atomic with the takeover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainClaimDoc {
    /// The claimed label (normalized lowercase).
    pub label: String,
    /// The organization currently or most recently holding the label.
    pub org_id: String,
    /// The verified registrable apex the label was derived from
    /// (`acme-com` ← `acme.com`). A *different* org taking over a released
    /// slot must be backed by this same apex — i.e. must have verified
    /// ownership of the domain itself — closing the rare case where two
    /// distinct apexes hyphen-collapse to the same label.
    pub apex: String,
    /// `None` while the claim is active; `Some(release time)` after the
    /// holder released it (starts the cross-org reuse cooldown).
    pub released_at: Option<Timestamp>,
}

impl DocumentType for SubdomainClaimDoc {
    const DOC_TYPE: &'static str = "subdomain_claim";

    fn index_entries(&self) -> Vec<IndexEntry> {
        // Looked up exclusively by deterministic document ID.
        Vec::new()
    }
}

/// Serialize a [`SecretString`] field by exposing it. Only for fields whose
/// document is sealed at rest by the store.
fn serialize_secret_string<S: serde::Serializer>(
    value: &SecretString,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value.expose_secret())
}

/// Lifecycle state of a per-org issuer signing key.
///
/// A key begins `Active` (the live signing key). When rotation is staged a
/// successor is written as `Pending`; after `PUBLISH_AHEAD_HOURS` the cleanup
/// loop activates it (the predecessor moves to `Retiring`). When the retirement
/// window elapses the `Retiring` key is reaped. Emergency rotation skips the
/// staged path: the predecessor is deleted outright and a new `Active` key is
/// inserted immediately.
///
/// The three-state machine maps to three deterministic document slots per
/// `(org_id, alg)`:
/// - current slot → `Active` (existing deterministic ID; backward-compatible)
/// - next slot    → `Pending` (new, with `"_next"` suffix in hash input)
/// - previous slot → `Retiring` (new, with `"_prev"` suffix in hash input)
///
/// `#[serde(default)]` ensures existing rows without a `state` field
/// deserialize as `Active`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SigningKeyState {
    /// The key currently used to sign tokens for this org and algorithm.
    Active,
    /// A staged successor waiting for `PUBLISH_AHEAD_HOURS` to elapse before
    /// the cleanup loop switches signing to it.
    Pending {
        /// When the cleanup loop may activate this key and retire the current one.
        activate_at: Timestamp,
    },
    /// A predecessor that is still valid for token verification but no longer
    /// used for signing. Reaped when `not_after` elapses.
    Retiring {
        /// After this timestamp the key may be safely deleted; all tokens it
        /// signed have expired or been superseded.
        not_after: Timestamp,
    },
}

impl SigningKeyState {
    /// Returns the timestamp after which this key may be safely deleted, if any.
    ///
    /// Only `Retiring` keys have a deadline; `Active` and `Pending` keys do not
    /// expire automatically. Used to populate the `ExpiresAt` document column on
    /// insert. Reaping is performed explicitly by `reap_org_retired_key` in the
    /// cleanup loop, which also emits the `org_issuer_key_reaped` audit event and
    /// invalidates the cache.
    pub fn expires_at(&self) -> Option<Timestamp> {
        match self {
            Self::Retiring { not_after } => Some(*not_after),
            _ => None,
        }
    }
}

fn default_signing_key_state() -> SigningKeyState {
    SigningKeyState::Active
}

/// A per-organization OIDC issuer signing key.
///
/// When an org claims an issuer subdomain, its OIDC federation tokens (AWS STS
/// and Identity Center, GCP/Azure workload identity, and any RFC 8693
/// token-exchange consumer) are signed with these keys and served only at the
/// org's own JWKS — making the issuer host a real cryptographic tenant
/// boundary. `alg` is the RFC 7518 JWS algorithm (ES256 or RS256).
///
/// One key per row, at a **deterministic slot ID** (current/next/previous per
/// `(org_id, alg)`) so retries and concurrent operations collide on the primary
/// key instead of creating duplicates. `kid` (RFC 7517) is a field (hash of the
/// random public key), never the document ID. See [`SigningKeyState`] for the
/// rotation lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgSigningKeyDoc {
    /// Owning organization (indexed, so the org's key set is one query).
    pub org_id: String,
    /// RFC 7518 JWS algorithm. Only `Es256`/`Rs256` are produced here.
    pub alg: JwsAlgorithm,
    /// JWK key ID (RFC 7517 §4.5), published in the org JWKS.
    pub kid: String,
    /// Base64 (standard) PKCS#8 DER of the private key. `SecretString` keeps
    /// it out of `Debug` output and zeroizes the buffer on drop; at rest the
    /// document store seals the whole document (keys are only ever created
    /// when `DocumentStore::is_encrypted`).
    #[serde(serialize_with = "serialize_secret_string")]
    pub private_pkcs8_der_b64: SecretString,
    /// Rotation lifecycle state. Defaults to `Active` so existing rows without
    /// this field deserialize correctly.
    #[serde(default = "default_signing_key_state")]
    pub state: SigningKeyState,
}

impl DocumentType for OrgSigningKeyDoc {
    const DOC_TYPE: &'static str = "org_signing_key";

    fn expires_at(&self) -> Option<Timestamp> {
        self.state.expires_at()
    }

    fn index_entries(&self) -> Vec<IndexEntry> {
        vec![IndexEntry {
            field: "org_id",
            value: self.org_id.clone(),
        }]
    }
}

/// Lifecycle state of an [`AdditionalDomain`].
///
/// Modeled as an enum so each state carries exactly the timestamps relevant
/// to it — invalid combinations (e.g., "verified but never verified_at") are
/// unrepresentable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AdditionalDomainState {
    /// Added but never verified. TXT record has not been observed.
    Pending,
    /// DNS TXT ownership confirmed; entry participates in login matching.
    Verified {
        verified_at: Timestamp,
        /// Last time the background re-verification task checked this domain.
        /// `None` means it has not yet been re-checked since verification.
        #[serde(default)]
        last_checked_at: Option<Timestamp>,
    },
    /// Was verified at some point but flipped back to unverified after
    /// repeated DNS recheck failures. Eligible for admin re-verification or
    /// auto-removal after the unverified TTL elapses.
    Unverified {
        /// When the entry was originally verified, before being flipped.
        verified_at: Timestamp,
        /// When the failing re-check that caused the flip ran.
        last_checked_at: Timestamp,
    },
}

/// A secondary email domain claimed by an organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdditionalDomain {
    /// Normalized lowercase ASCII domain.
    pub domain: String,
    /// Random hex token the admin must publish as `_vouch-verification.<domain>` TXT.
    pub verification_token: String,
    pub added_at: Timestamp,
    pub added_by_user_id: String,
    /// Email of the admin who added this entry, denormalized at write time
    /// so the admin UI doesn't need a per-row user lookup. May go stale if
    /// the user's email is changed later (acceptable: same trade-off as
    /// `SessionDoc.user_email`).
    pub added_by_email: String,
    /// Consecutive re-verification failures. Reset to 0 on a successful check.
    /// At [`UNVERIFY_FAILURE_THRESHOLD`] the entry flips to `Unverified`.
    #[serde(default)]
    pub consecutive_failures: u32,
    pub state: AdditionalDomainState,
}

/// Number of consecutive failed re-verifications before an entry is flipped
/// back to unverified.
pub const UNVERIFY_FAILURE_THRESHOLD: u32 = 3;

impl DocumentType for OrganizationDoc {
    const DOC_TYPE: &'static str = "organization";

    fn index_entries(&self) -> Vec<IndexEntry> {
        let cap = self.additional_domains.len().saturating_add(2);
        let mut entries = Vec::with_capacity(cap);
        entries.push(IndexEntry {
            field: "domain",
            value: self.domain.clone(),
        });
        for ad in &self.additional_domains {
            if matches!(ad.state, AdditionalDomainState::Verified { .. }) {
                entries.push(IndexEntry {
                    field: "domain",
                    value: ad.domain.clone(),
                });
            }
        }
        if let Some(label) = &self.subdomain {
            entries.push(IndexEntry {
                field: "subdomain",
                value: label.clone(),
            });
        }
        entries
    }
}
