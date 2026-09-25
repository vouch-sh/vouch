// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The identity an SSH user certificate was issued to.
//!
//! The Vouch SSH CA writes `{email}@{rp_id}` into every certificate's key ID.
//! The server builds that string with [`ssh_cert_key_id`], and the CLI and
//! agent check it with [`ssh_cert_issued_to`] before reusing a certificate
//! found on disk, so the format has one definition on both sides.

/// The key ID the Vouch SSH CA writes into a certificate issued to `email`
/// by the relying party `rp_id`.
pub fn ssh_cert_key_id(email: &str, rp_id: &str) -> String {
    format!("{email}@{rp_id}")
}

/// Whether a certificate with `key_id` was issued to `email` by the Vouch
/// server at `server_url`.
///
/// The email must match exactly. The relying-party ID after it must be
/// non-empty and, when `server_url` is known and names a DNS host, must be
/// that host or a parent domain of it: a WebAuthn RP ID is always the
/// origin's host or a registrable suffix of it, so a certificate minted by a
/// server on another domain does not match. An IP-literal host carries no
/// domain to compare, so only the email is checked for it, as it is when
/// `server_url` is `None`.
pub fn ssh_cert_issued_to(key_id: &str, email: &str, server_url: Option<&str>) -> bool {
    if email.is_empty() {
        return false;
    }
    let Some(rp_id) = key_id
        .strip_prefix(email)
        .and_then(|rest| rest.strip_prefix('@'))
    else {
        return false;
    };
    if rp_id.is_empty() {
        return false;
    }
    let Some(server_url) = server_url else {
        return true;
    };
    let Ok(parsed) = url::Url::parse(server_url) else {
        return false;
    };
    match parsed.host() {
        Some(url::Host::Domain(host)) => {
            let host = host.to_ascii_lowercase();
            let rp_id = rp_id.to_ascii_lowercase();
            host == rp_id
                || host
                    .strip_suffix(rp_id.as_str())
                    .is_some_and(|prefix| prefix.ends_with('.'))
        }
        Some(url::Host::Ipv4(_) | url::Host::Ipv6(_)) => true,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_round_trips_for_the_same_identity_and_server() {
        let key_id = ssh_cert_key_id("alice@example.com", "vouch.example.com");
        assert_eq!(key_id, "alice@example.com@vouch.example.com");
        assert!(ssh_cert_issued_to(
            &key_id,
            "alice@example.com",
            Some("https://vouch.example.com")
        ));
    }

    #[test]
    fn a_different_email_does_not_match() {
        let key_id = ssh_cert_key_id("alice@example.com", "vouch.example.com");
        assert!(!ssh_cert_issued_to(
            &key_id,
            "bob@example.com",
            Some("https://vouch.example.com")
        ));
        // A prefix of the real email is not the email.
        assert!(!ssh_cert_issued_to(&key_id, "alice@example", None));
        assert!(!ssh_cert_issued_to(&key_id, "", None));
    }

    #[test]
    fn a_certificate_from_another_server_does_not_match() {
        let key_id = ssh_cert_key_id("alice@example.com", "vouch.example.com");
        assert!(!ssh_cert_issued_to(
            &key_id,
            "alice@example.com",
            Some("https://vouch.other.example")
        ));
        // A host that merely ends in the same characters is not a subdomain.
        assert!(!ssh_cert_issued_to(
            &key_id,
            "alice@example.com",
            Some("https://evilvouch.example.com")
        ));
    }

    // WebAuthn Level 2 §4, the note under "Relying Party Identifier": "The RP
    // ID must be equal to the origin's effective domain, or a registrable
    // domain suffix of the origin's effective domain." So a server on a
    // subdomain of its RP ID matches.
    #[test]
    fn a_server_on_a_subdomain_of_the_rp_id_matches() {
        let key_id = ssh_cert_key_id("alice@example.com", "example.com");
        assert!(ssh_cert_issued_to(
            &key_id,
            "alice@example.com",
            Some("https://vouch.Example.com:8443")
        ));
    }

    #[test]
    fn missing_or_empty_rp_id_does_not_match() {
        assert!(!ssh_cert_issued_to(
            "alice@example.com",
            "alice@example.com",
            None
        ));
        assert!(!ssh_cert_issued_to(
            "alice@example.com@",
            "alice@example.com",
            None
        ));
        assert!(!ssh_cert_issued_to("", "alice@example.com", None));
    }

    #[test]
    fn unknown_server_checks_email_only() {
        let key_id = ssh_cert_key_id("alice@example.com", "vouch.example.com");
        assert!(ssh_cert_issued_to(&key_id, "alice@example.com", None));
    }

    #[test]
    fn ip_literal_server_checks_email_only() {
        let key_id = ssh_cert_key_id("alice@example.com", "localhost");
        assert!(ssh_cert_issued_to(
            &key_id,
            "alice@example.com",
            Some("http://127.0.0.1:3000")
        ));
        assert!(!ssh_cert_issued_to(
            &key_id,
            "bob@example.com",
            Some("http://127.0.0.1:3000")
        ));
    }

    #[test]
    fn unparseable_server_url_does_not_match() {
        let key_id = ssh_cert_key_id("alice@example.com", "vouch.example.com");
        assert!(!ssh_cert_issued_to(
            &key_id,
            "alice@example.com",
            Some("not a url")
        ));
    }
}
