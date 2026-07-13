// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Pure validation for organization email domains and issuer subdomain labels.
//!
//! Everything here is synchronous and side-effect free: DNS-shape rules for
//! additional email domains, reserved-namespace checks, and derivation of
//! claimable issuer subdomain labels from verified apexes. Persistence and
//! the claim/release state machines live in the parent module.

use crate::db::documents::organization::{AdditionalDomain, AdditionalDomainState};

/// Top-level labels that must never be accepted as an additional domain.
///
/// Verifying a TXT record under one of these would force the server's
/// resolver to query internal/loopback infrastructure (SSRF) or reserved
/// namespaces with no public ownership semantics:
///
/// - `localhost`, `local` — loopback / mDNS (RFC 6761, RFC 6762)
/// - `example`, `invalid`, `test` — reserved for documentation (RFC 6761)
/// - `internal` — ICANN-reserved for private use (2024)
/// - `arpa` — reverse-DNS root (covers `home.arpa`, `in-addr.arpa`, `ip6.arpa`)
/// - `onion` — Tor hidden services (RFC 7686)
/// - `alt` — pseudo-TLD reserved by RFC 9476
const RESERVED_TLDS: &[&str] = &[
    "localhost",
    "local",
    "example",
    "invalid",
    "test",
    "internal",
    "arpa",
    "onion",
    "alt",
];

/// Why a candidate domain failed [`normalize_domain`].
///
/// The `Display` texts are log/diagnostic strings; the admin UI maps each
/// variant to a localized Fluent message instead of rendering them directly.
#[derive(Debug, thiserror::Error)]
pub enum DomainValidationError {
    /// Empty or whitespace-only input.
    #[error("domain must not be empty")]
    Empty,
    /// Contains non-ASCII characters (IDN domains must be punycode).
    #[error("domain must be ASCII (use punycode for internationalized domains)")]
    NotAscii,
    /// Looks like an IP address literal (IPv4 or IPv6).
    #[error("domain must be a hostname, not an IP address")]
    IpAddress,
    /// Total length exceeds the 253-character DNS limit.
    #[error("domain exceeds 253 characters")]
    TooLong,
    /// No dot separator — would be a bare hostname.
    #[error("domain must contain at least one dot")]
    NoDot,
    /// Starts or ends with a dot.
    #[error("domain must not start or end with a dot")]
    LeadingOrTrailingDot,
    /// Two or more consecutive dots produce an empty label.
    #[error("domain must not contain empty labels")]
    EmptyLabel,
    /// A single label exceeds the 63-character RFC 1035 limit.
    #[error("domain label exceeds 63 characters")]
    LabelTooLong,
    /// A label starts or ends with a hyphen.
    #[error("domain label must not start or end with a hyphen")]
    LabelHyphenEdge,
    /// A label contains characters outside `[a-z0-9-]`.
    #[error("domain label contains invalid characters")]
    LabelInvalidChar,
    /// The TLD is on the reserved/internal list.
    #[error("domain uses a reserved or internal top-level label ('.{0}')")]
    ReservedTld(String),
}

/// Validate the syntactic shape of a domain name.
///
/// Returns the normalized lowercase form on success. Rejects empty input,
/// non-ASCII characters, leading/trailing dots, double dots, labels longer
/// than 63 characters, total length over 253 characters, labels with
/// invalid characters or leading/trailing hyphens, IP-address literals, and
/// reserved top-level labels (see [`RESERVED_TLDS`]).
pub fn normalize_domain(input: &str) -> Result<String, DomainValidationError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(DomainValidationError::Empty);
    }
    if !trimmed.is_ascii() {
        return Err(DomainValidationError::NotAscii);
    }
    // Reject IP literals — these would point the resolver at a specific host
    // and bypass any TLD-level allow/deny logic. Also covers bracketed IPv6.
    let ip_candidate = trimmed.trim_start_matches('[').trim_end_matches(']');
    if ip_candidate.parse::<std::net::IpAddr>().is_ok() {
        return Err(DomainValidationError::IpAddress);
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.len() > 253 {
        return Err(DomainValidationError::TooLong);
    }
    if !lower.contains('.') {
        return Err(DomainValidationError::NoDot);
    }
    if lower.starts_with('.') || lower.ends_with('.') {
        return Err(DomainValidationError::LeadingOrTrailingDot);
    }
    for label in lower.split('.') {
        if label.is_empty() {
            return Err(DomainValidationError::EmptyLabel);
        }
        if label.len() > 63 {
            return Err(DomainValidationError::LabelTooLong);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(DomainValidationError::LabelHyphenEdge);
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(DomainValidationError::LabelInvalidChar);
        }
    }
    // Reject reserved/internal top-level labels. Iterating the constant is
    // a fixed-cost O(N) scan over a small list — clearer than a HashSet.
    let tld = lower.rsplit('.').next().unwrap_or("");
    if RESERVED_TLDS.contains(&tld) {
        return Err(DomainValidationError::ReservedTld(tld.to_string()));
    }
    Ok(lower)
}

/// Return the Unicode form of a domain that contains punycode labels, or
/// `None` if the domain has no `xn--` labels (so the ASCII form is also the
/// display form).
///
/// Used by the admin UI to surface the human-readable rendering of an IDN
/// alongside the ASCII form, so a domain like `xn--acme-cua.com` is visibly
/// `àcme.com` to an admin reviewing the org's claims. Decoding failures
/// (malformed punycode) return `None` rather than erroring — display is a
/// hint, not authoritative.
#[must_use]
pub fn unicode_form(domain: &str) -> Option<String> {
    if !domain.split('.').any(|label| label.starts_with("xn--")) {
        return None;
    }
    let (decoded, errors) = idna::domain_to_unicode(domain);
    if errors.is_err() || decoded == domain {
        return None;
    }
    Some(decoded)
}

/// Labels that must never be claimable as org issuer subdomains.
///
/// Grouped by rationale:
/// - current/future vouch service hosts and regional prefixes
///   (`us.vouch.sh`, `mtls`, `docs`, ...)
/// - protocol-magic or infrastructure names whose resolution or semantics
///   are special (`www`, `mail`, `ns*`, `autodiscover`, `wpad`, ...)
/// - names that would read as vouch-operated endpoints in a customer's
///   IAM trust-policy ARN (`admin`, `oauth`, `login`, `sso`, ...)
pub const RESERVED_SUBDOMAIN_LABELS: &[&str] = &[
    // vouch service hosts / regional prefixes
    "us",
    "eu",
    "ap",
    "jp",
    "vouch",
    "dev",
    "docs",
    "www",
    "mtls",
    "api",
    "app",
    "status",
    "health",
    "metrics",
    "enroll",
    "device",
    "conformance", // auth-adjacent names
    "admin",
    "oauth",
    "auth",
    "login",
    "logout",
    "sso",
    "id",
    "idp",
    "scim",
    "token",
    "jwks",
    "openid",
    "wellknown",
    "well-known",
    "metadata",
    "saml",
    "oidc",
    // protocol-magic / infrastructure names
    "mail",
    "smtp",
    "imap",
    "pop",
    "mx",
    "ns",
    "ns1",
    "ns2",
    "ftp",
    "cdn",
    "static",
    "assets",
    "autodiscover",
    "autoconfig",
    "wpad",
    "localhost",
    "local",
    "internal",
    "test",
    "staging",
    "stage",
    "prod",
    "production",
    "root",
    "github",
    "wildcard",
];

/// Why a candidate label failed [`validate_subdomain_label`].
///
/// The `Display` texts are log/diagnostic strings; the admin UI maps each
/// variant to a localized Fluent message instead of rendering them.
#[derive(Debug, thiserror::Error)]
pub enum SubdomainLabelError {
    /// Empty or whitespace-only input.
    #[error("subdomain must not be empty")]
    Empty,
    /// Contains non-ASCII characters (IDN labels must be punycode).
    #[error("subdomain must be ASCII (use punycode for internationalized names)")]
    NotAscii,
    /// Longer than the RFC 1035 63-character label limit.
    #[error("subdomain exceeds 63 characters")]
    TooLong,
    /// Contains a dot (would be a multi-label host).
    #[error("subdomain must not contain dots")]
    ContainsDot,
    /// Leading or trailing hyphen.
    #[error("subdomain must not start or end with a hyphen")]
    HyphenEdge,
    /// Characters outside letters, digits, and hyphens.
    #[error("subdomain may only contain letters, digits, and hyphens")]
    InvalidChar,
    /// All-numeric label (could read as an IP octet).
    #[error("subdomain must contain at least one letter")]
    NoLetter,
    /// On [`RESERVED_SUBDOMAIN_LABELS`].
    #[error("subdomain '{0}' is reserved")]
    Reserved(String),
}

/// Validate the syntactic shape of an issuer subdomain label.
///
/// Returns the normalized lowercase form on success. Enforces RFC 1035
/// LDH-label rules (1–63 chars, alphanumeric plus interior hyphens), requires
/// at least one letter (an all-numeric label could read as an IP octet), and
/// rejects entries on [`RESERVED_SUBDOMAIN_LABELS`].
///
/// # Errors
/// Returns the [`SubdomainLabelError`] variant for the violated rule.
pub fn validate_subdomain_label(input: &str) -> Result<String, SubdomainLabelError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(SubdomainLabelError::Empty);
    }
    if !trimmed.is_ascii() {
        return Err(SubdomainLabelError::NotAscii);
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.len() > 63 {
        return Err(SubdomainLabelError::TooLong);
    }
    if lower.contains('.') {
        return Err(SubdomainLabelError::ContainsDot);
    }
    if lower.starts_with('-') || lower.ends_with('-') {
        return Err(SubdomainLabelError::HyphenEdge);
    }
    if !lower
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(SubdomainLabelError::InvalidChar);
    }
    if !lower.bytes().any(|b| b.is_ascii_alphabetic()) {
        return Err(SubdomainLabelError::NoLetter);
    }
    if RESERVED_SUBDOMAIN_LABELS.contains(&lower.as_str()) {
        return Err(SubdomainLabelError::Reserved(lower));
    }
    Ok(lower)
}

/// `(apex, label)` candidates from the org's primary domain and every
/// *verified* additional domain, in encounter order (may contain duplicates).
///
/// The label is the domain's **full registrable apex** with dots collapsed
/// to hyphens, so it is unique per apex and encodes the TLD: `acme.com` →
/// `acme-com`, `acme.io` → `acme-io`, `acme.co.uk` → `acme-co-uk`, and
/// `mail.acme.com` → apex `acme.com` → `acme-com`. Distinct real-world
/// entities (`acme.com` vs `acme.io`) therefore never contend for one label,
/// and deriving from the apex (never the raw leftmost label) means a
/// subdomain of an unrelated registrable domain cannot yield someone else's
/// brand: `acme.evil.com` → apex `evil.com` → `evil-com`. Domains with no
/// registrable apex per the Public Suffix List contribute nothing. Inputs
/// are assumed already normalized (ASCII/punycode, lowercase) by
/// [`normalize_domain`].
///
/// [`eligible_subdomain_labels`] and [`ineligible_subdomain_candidates`]
/// partition the labels by [`validate_subdomain_label`];
/// [`backing_apex_for_label`] recovers the apex behind an eligible label.
fn verified_apex_label_pairs(
    primary_domain: &str,
    additional_domains: &[AdditionalDomain],
) -> Vec<(String, String)> {
    fn apex_pair(domain: &str) -> Option<(String, String)> {
        let apex = psl::domain_str(domain)?.trim().to_ascii_lowercase();
        if apex.is_empty() {
            return None;
        }
        let label = apex.replace('.', "-");
        Some((apex, label))
    }

    let mut pairs = Vec::new();
    pairs.extend(apex_pair(primary_domain));
    for ad in additional_domains {
        if matches!(ad.state, AdditionalDomainState::Verified { .. }) {
            pairs.extend(apex_pair(&ad.domain));
        }
    }
    pairs
}

/// Compute the subdomain labels an organization is eligible to claim.
///
/// A label is the full registrable apex of the org's primary domain or of a
/// *verified* additional domain, with dots collapsed to hyphens (verified
/// `acme.com` → eligible `acme-com`). Labels that fail
/// [`validate_subdomain_label`] (e.g. longer than a DNS label allows) are
/// silently dropped; the result is deduplicated in encounter order.
#[must_use]
pub fn eligible_subdomain_labels(
    primary_domain: &str,
    additional_domains: &[AdditionalDomain],
) -> Vec<String> {
    let mut labels = Vec::new();
    for (_, candidate) in verified_apex_label_pairs(primary_domain, additional_domains) {
        if let Ok(label) = validate_subdomain_label(&candidate)
            && !labels.contains(&label)
        {
            labels.push(label);
        }
    }
    labels
}

/// Apex-derived labels of the org's verified domains that can NOT be claimed
/// as issuer subdomains (e.g. longer than the 63-character DNS label limit),
/// deduped in encounter order.
///
/// Complements [`eligible_subdomain_labels`], which silently drops these:
/// the admin UI uses this to explain an empty eligible list for an org that
/// does have verified domains instead of implying no domain is verified.
#[must_use]
pub fn ineligible_subdomain_candidates(
    primary_domain: &str,
    additional_domains: &[AdditionalDomain],
) -> Vec<String> {
    let mut labels = Vec::new();
    for (_, candidate) in verified_apex_label_pairs(primary_domain, additional_domains) {
        if validate_subdomain_label(&candidate).is_err() && !labels.contains(&candidate) {
            labels.push(candidate);
        }
    }
    labels
}

/// The verified registrable apex behind an eligible `label`, or `None` when
/// no verified domain of the org derives it.
///
/// The claim slot records this apex so a released label can only be taken
/// over by an org that verified ownership of the same domain.
pub(super) fn backing_apex_for_label(
    primary_domain: &str,
    additional_domains: &[AdditionalDomain],
    label: &str,
) -> Option<String> {
    verified_apex_label_pairs(primary_domain, additional_domains)
        .into_iter()
        .find_map(|(apex, candidate)| (candidate == label).then_some(apex))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn normalize_domain_lowercases() {
        assert_eq!(normalize_domain("Acme.Co.UK").unwrap(), "acme.co.uk");
        assert_eq!(normalize_domain("  EXAMPLE.com  ").unwrap(), "example.com");
    }

    #[test]
    fn normalize_domain_rejects_invalid() {
        assert!(matches!(
            normalize_domain(""),
            Err(DomainValidationError::Empty)
        ));
        assert!(matches!(
            normalize_domain("no-dot"),
            Err(DomainValidationError::NoDot)
        ));
        assert!(matches!(
            normalize_domain(".leading.com"),
            Err(DomainValidationError::LeadingOrTrailingDot)
        ));
        assert!(matches!(
            normalize_domain("trailing.com."),
            Err(DomainValidationError::LeadingOrTrailingDot)
        ));
        assert!(matches!(
            normalize_domain("double..dots.com"),
            Err(DomainValidationError::EmptyLabel)
        ));
        assert!(matches!(
            normalize_domain("-leading.com"),
            Err(DomainValidationError::LabelHyphenEdge)
        ));
        assert!(matches!(
            normalize_domain("trailing-.com"),
            Err(DomainValidationError::LabelHyphenEdge)
        ));
        assert!(matches!(
            normalize_domain("under_score.com"),
            Err(DomainValidationError::LabelInvalidChar)
        ));
        assert!(matches!(
            normalize_domain("уникод.com"),
            Err(DomainValidationError::NotAscii)
        ));
    }

    #[test]
    fn normalize_domain_rejects_ip_literals() {
        assert!(matches!(
            normalize_domain("127.0.0.1"),
            Err(DomainValidationError::IpAddress)
        ));
        assert!(matches!(
            normalize_domain("10.0.0.5"),
            Err(DomainValidationError::IpAddress)
        ));
        assert!(matches!(
            normalize_domain("169.254.169.254"),
            Err(DomainValidationError::IpAddress)
        ));
        assert!(matches!(
            normalize_domain("::1"),
            Err(DomainValidationError::IpAddress)
        ));
        assert!(matches!(
            normalize_domain("[::1]"),
            Err(DomainValidationError::IpAddress)
        ));
        assert!(matches!(
            normalize_domain("fe80::1"),
            Err(DomainValidationError::IpAddress)
        ));
    }

    #[test]
    fn normalize_domain_rejects_reserved_tlds() {
        for d in [
            "internal.corp.localhost",
            "metadata.google.internal",
            "service.local",
            "anything.arpa",
            "1.0.0.127.in-addr.arpa",
            "hostname.home.arpa",
            "thing.example",
            "name.invalid",
            "service.test",
            "abcdef.onion",
            "ipfs.alt",
        ] {
            assert!(
                matches!(
                    normalize_domain(d),
                    Err(DomainValidationError::ReservedTld(_))
                ),
                "expected {d} to be rejected as reserved TLD"
            );
        }
    }

    #[test]
    fn normalize_domain_accepts_public_domains() {
        assert!(normalize_domain("acme.com").is_ok());
        assert!(normalize_domain("foo.bar.example.co.uk").is_ok());
        // xn-- punycode is allowed (homograph detection is out of scope).
        assert!(normalize_domain("xn--acme-cua.com").is_ok());
    }

    #[test]
    fn unicode_form_decodes_punycode() {
        // xn--bcher-kva is "bücher" in punycode.
        assert_eq!(
            unicode_form("xn--bcher-kva.example.com").as_deref(),
            Some("bücher.example.com"),
        );
    }

    #[test]
    fn unicode_form_returns_none_for_pure_ascii() {
        assert!(unicode_form("acme.com").is_none());
        assert!(unicode_form("foo.bar.example.co.uk").is_none());
    }

    #[test]
    fn unicode_form_returns_none_for_malformed_punycode() {
        // xn-- prefix but invalid encoding — display has no useful form.
        assert!(unicode_form("xn--.com").is_none());
    }

    // ========================================================================
    // Issuer subdomains
    // ========================================================================

    #[test]
    fn validate_subdomain_label_normalizes_and_accepts() {
        assert_eq!(validate_subdomain_label("Acme").unwrap(), "acme");
        assert_eq!(validate_subdomain_label("  a-1  ").unwrap(), "a-1");
        assert_eq!(validate_subdomain_label("x").unwrap(), "x");
        // Punycode labels are allowed — eligibility already requires a
        // verified (punycode) domain.
        assert_eq!(
            validate_subdomain_label("xn--acme-cua").unwrap(),
            "xn--acme-cua"
        );
    }

    #[test]
    fn validate_subdomain_label_rejects_invalid() {
        assert!(validate_subdomain_label("").is_err());
        assert!(validate_subdomain_label("   ").is_err());
        assert!(validate_subdomain_label("a.b").is_err());
        assert!(validate_subdomain_label("-acme").is_err());
        assert!(validate_subdomain_label("acme-").is_err());
        assert!(validate_subdomain_label("ac me").is_err());
        assert!(validate_subdomain_label("under_score").is_err());
        assert!(validate_subdomain_label("уникод").is_err());
        assert!(validate_subdomain_label(&"a".repeat(64)).is_err());
        // All-numeric labels could read as IP octets.
        assert!(validate_subdomain_label("12345").is_err());
    }

    #[test]
    fn validate_subdomain_label_rejects_reserved() {
        for label in ["www", "us", "mtls", "oauth", "admin", "WWW"] {
            assert!(
                validate_subdomain_label(label).is_err(),
                "'{label}' must be reserved"
            );
        }
    }

    #[test]
    fn apex_labels_cannot_collide_with_reserved_words() {
        // Every apex has at least two DNS labels, so derived labels always
        // contain a hyphen and can never equal the hyphen-free reserved
        // words — every apex-derived label must be claimable.
        assert_eq!(eligible_subdomain_labels("mail.io", &[]), ["mail-io"]);
        assert_eq!(eligible_subdomain_labels("vouch.sh", &[]), ["vouch-sh"]);
        assert!(ineligible_subdomain_candidates("vouch.sh", &[]).is_empty());
    }

    #[test]
    fn eligible_label_derives_from_registrable_apex() {
        // Verifying a subdomain of an unrelated registrable domain must not
        // grant a label derived from that subdomain's brand.
        assert_eq!(
            eligible_subdomain_labels("acme.evil.com", &[]),
            ["evil-com"]
        );
        // Multi-label public suffixes resolve to the true apex.
        assert_eq!(eligible_subdomain_labels("acme.co.uk", &[]), ["acme-co-uk"]);
        // A subdomain of the org's own apex still yields the apex label.
        assert_eq!(
            eligible_subdomain_labels("mail.acme.com", &[]),
            ["acme-com"]
        );
        // A plain apex maps 1:1 onto its hyphenated form.
        assert_eq!(eligible_subdomain_labels("acme.com", &[]), ["acme-com"]);
        // Different TLDs of the same brand yield distinct labels — two
        // real-world entities never contend for one issuer host.
        assert_ne!(
            eligible_subdomain_labels("acme.com", &[]),
            eligible_subdomain_labels("acme.io", &[])
        );
    }

    #[test]
    fn ineligible_candidate_surfaces_overlong_apex() {
        // An apex whose hyphenated form exceeds the 63-character DNS label
        // limit is surfaced so the empty eligible list is explained rather
        // than implying no verified domain.
        let long_domain = format!("{}.com", "a".repeat(60));
        assert!(eligible_subdomain_labels(&long_domain, &[]).is_empty());
        assert_eq!(
            ineligible_subdomain_candidates(&long_domain, &[]),
            [format!("{}-com", "a".repeat(60))]
        );
        // A subdomain of an unrelated domain resolves to a valid apex label
        // ("evil-com"), so it is eligible, not an ineligible candidate.
        assert!(ineligible_subdomain_candidates("admin.evil.com", &[]).is_empty());
    }
}
