// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Organization document type.

use jiff::Timestamp;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::crypto::alg::JwsAlgorithm;
use crate::db::document_type::{DocumentType, IndexEntry};

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

/// Cross-org uniqueness slot for a verified email domain.
///
/// Two organizations must never both claim the same email domain: domain →
/// org lookup resolves `ORDER BY created_at DESC LIMIT 1`, so a duplicate
/// silently routes enrollment to whichever org document was created later,
/// and the SCIM domain gate passes for both.
///
/// The `document_indexes` UNIQUE constraint is per-document, so it cannot
/// express that. Two orgs verifying the same domain write to two different
/// primary keys and never conflict. Hashing the domain into a shared
/// document ID is what forces them to collide — the same construction as
/// `deterministic_org_id` and [`SubdomainClaimDoc`].
///
/// Unlike a subdomain label, a released domain carries no reuse cooldown, so
/// the row is deleted on release rather than tombstoned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainClaimDoc {
    /// The claimed domain (normalized lowercase).
    pub domain: String,
    /// The organization holding the claim.
    pub org_id: String,
}

impl DocumentType for DomainClaimDoc {
    const DOC_TYPE: &'static str = "domain_claim";

    fn index_entries(&self) -> Vec<IndexEntry> {
        // Looked up exclusively by deterministic document ID.
        Vec::new()
    }
}

impl DocumentType for SubdomainClaimDoc {
    const DOC_TYPE: &'static str = "subdomain_claim";

    fn index_entries(&self) -> Vec<IndexEntry> {
        // Looked up exclusively by deterministic document ID.
        Vec::new()
    }
}

/// State of a per-org issuer signing key (Auth0-style rotation).
///
/// A key set always holds a `Current` signer and a `Next` successor: the
/// successor is created together with the first key and re-staged immediately
/// after every rotation, so relying-party JWKS caches are always pre-warmed
/// with the key that will sign next. An operator-triggered rotate promotes
/// `Next` to `Current` and demotes the old signer to `Previous`, which stays
/// published (verify-only) until the operator explicitly revokes it. Nothing
/// transitions on a timer.
///
/// The state doubles as the storage location: each state has its own
/// deterministic document ID per `(org_id, alg)` (see
/// [`crate::db::deterministic_org_key_id`]), so retries and concurrent
/// writers collide on the primary key instead of duplicating keys. `Current`
/// keeps the original pre-rotation hash prefix, and `#[serde(default)]`
/// deserializes rows without a `state` field as `Current` — existing rows
/// need no migration.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SigningKeyState {
    /// The key currently used to sign tokens for this org and algorithm.
    #[default]
    Current,
    /// The pre-staged successor, published in the JWKS so relying-party caches
    /// warm up before it ever signs. `OrgSigningKeyDoc::staged_at` records
    /// when its publish window started.
    Next,
    /// A demoted predecessor that still verifies outstanding tokens but no
    /// longer signs. `OrgSigningKeyDoc::demoted_at` feeds the revoke gate.
    Previous,
}

/// A per-organization OIDC issuer signing key.
///
/// When an org claims an issuer subdomain, its OIDC federation tokens (AWS STS
/// and Identity Center, GCP/Azure workload identity, and any RFC 8693
/// token-exchange consumer) are signed with these keys and served only at the
/// org's own JWKS — making the issuer host a real cryptographic tenant
/// boundary. `alg` is the RFC 7518 JWS algorithm (ES256 or RS256).
///
/// One key per row, at a **deterministic document ID** derived from
/// `(org_id, alg, state)` so retries and concurrent operations collide on the
/// primary key instead of creating duplicates. `kid` (RFC 7517) is a field
/// (hash of the random public key), never the document ID. See
/// [`SigningKeyState`] for the rotation lifecycle.
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
    #[serde(serialize_with = "vouch_common::serialize_secret_string")]
    pub private_pkcs8_der_b64: SecretString,
    /// Rotation state; also selects the document's deterministic ID. Defaults
    /// to `Current` so existing rows without this field deserialize correctly.
    #[serde(default)]
    pub state: SigningKeyState,
    /// When a `Next` key's publish window started. `None` for other states.
    #[serde(default)]
    pub staged_at: Option<Timestamp>,
    /// When a `Previous` key stopped signing. `None` for other states.
    #[serde(default)]
    pub demoted_at: Option<Timestamp>,
}

impl DocumentType for OrgSigningKeyDoc {
    const DOC_TYPE: &'static str = "org_signing_key";

    // No `expires_at` override: signing keys are never reaped by the generic
    // expiry cleanup. A `Previous` key lives until an operator revokes it.

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
#[derive(Clone, Serialize, Deserialize)]
pub struct AdditionalDomain {
    /// Normalized lowercase ASCII domain.
    pub domain: String,
    /// Random hex token the admin must publish as `_vouch-verification.<domain>` TXT.
    /// Serialized by exposure: the org document is sealed at rest by the store.
    #[serde(serialize_with = "vouch_common::serialize_secret_string")]
    pub verification_token: SecretString,
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

// Custom Debug that redacts verification_token to keep the DNS challenge
// value out of logs.
impl std::fmt::Debug for AdditionalDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdditionalDomain")
            .field("domain", &self.domain)
            .field("verification_token", &"[REDACTED]")
            .field("added_at", &self.added_at)
            .field("added_by_user_id", &self.added_by_user_id)
            .field("added_by_email", &self.added_by_email)
            .field("consecutive_failures", &self.consecutive_failures)
            .field("state", &self.state)
            .finish()
    }
}

/// Number of consecutive failed re-verifications before an entry is flipped
/// back to unverified.
pub const UNVERIFY_FAILURE_THRESHOLD: u32 = 3;

impl OrganizationDoc {
    /// Domains this org has proven ownership of: the primary domain plus
    /// every `additional_domains` entry that has completed DNS TXT
    /// verification.
    ///
    /// Pending and unverified (flipped-back) entries are excluded — this is
    /// the same set that participates in login matching and subdomain
    /// eligibility (see the doc comment on [`OrganizationDoc::additional_domains`]),
    /// and the set SCIM provisioning checks a candidate email's domain
    /// against.
    pub fn verified_domains(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.domain.as_str()).chain(self.additional_domains.iter().filter_map(
            |ad| {
                matches!(ad.state, AdditionalDomainState::Verified { .. })
                    .then_some(ad.domain.as_str())
            },
        ))
    }
}

impl DocumentType for OrganizationDoc {
    const DOC_TYPE: &'static str = "organization";

    fn index_entries(&self) -> Vec<IndexEntry> {
        let cap = self.additional_domains.len().saturating_add(2);
        let mut entries = Vec::with_capacity(cap);
        for domain in self.verified_domains() {
            entries.push(IndexEntry {
                field: "domain",
                value: domain.to_string(),
            });
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
