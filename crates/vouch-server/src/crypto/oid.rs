// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Object identifiers used when parsing and verifying X.509 material.
//!
//! Every OID the crypto layer matches on lives here, so a value is written
//! once and the arc it belongs to is stated once. Before this module,
//! `id-ecPublicKey` and `rsaEncryption` were each spelled in two files.
//!
//! The constants are grouped by what they identify, because the distinction
//! decides which one a caller wants:
//!
//! * [`public_key`] — the algorithm of a *key*, from a `SubjectPublicKeyInfo`.
//!   These under-determine a signature: `id-ecPublicKey` names neither a curve
//!   nor a hash.
//! * [`signature`] — the algorithm of a *signature*, from a certificate's
//!   `signatureAlgorithm`. These are self-determining: `ecdsa-with-SHA256`
//!   fixes both the family and the digest.
//! * [`curve`] — named elliptic curves, used to confirm a key is on the curve
//!   a verifier expects.
//! * [`extension`] — X.509 extensions this server reads.

use const_oid::ObjectIdentifier;

/// Public-key algorithm identifiers, as they appear in a `SubjectPublicKeyInfo`.
pub(crate) mod public_key {
    use super::ObjectIdentifier;

    /// `id-ecPublicKey` — RFC 5480 Section 2.1.1.
    ///
    /// Names the key family only. The curve is carried separately in the
    /// algorithm parameters, and the digest is not carried at all, so this
    /// value alone cannot select a signature verifier.
    pub(crate) const EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

    /// `rsaEncryption` — RFC 3279 Section 2.3.1.
    pub(crate) const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

    /// `id-Ed25519` — RFC 8410 Section 3.
    ///
    /// Unlike [`EC`], this fully determines the signature scheme: RFC 8410
    /// binds the curve and the hash into the algorithm itself.
    pub(crate) const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
}

/// Signature algorithm identifiers, as they appear in `signatureAlgorithm`.
pub(crate) mod signature {
    use super::ObjectIdentifier;

    /// `ecdsa-with-SHA256` — RFC 5758 Section 3.2.
    pub(crate) const ECDSA_SHA256: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

    /// `sha256WithRSAEncryption` — RFC 4055 Section 5.
    pub(crate) const RSA_SHA256: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

    /// `sha384WithRSAEncryption` — RFC 4055 Section 5.
    pub(crate) const RSA_SHA384: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");

    /// `sha512WithRSAEncryption` — RFC 4055 Section 5.
    pub(crate) const RSA_SHA512: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
}

/// Named elliptic curves.
pub(crate) mod curve {
    use super::ObjectIdentifier;

    /// `prime256v1` / P-256 — RFC 5480 Section 2.1.1.1.
    pub(crate) const PRIME256V1: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
}

/// X.509 extensions this server reads.
pub(crate) mod extension {
    use super::ObjectIdentifier;

    /// `id-fido-gen-ce-aaguid` — WebAuthn Level 2 Section 8.2.1.
    ///
    /// Carries the authenticator's AAGUID, wrapped in two OCTET STRINGs.
    pub(crate) const FIDO_GEN_CE_AAGUID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dotted strings are the point of this module; a typo in one would
    /// otherwise surface only as a silently unmatched certificate.
    #[test]
    fn oids_render_to_their_documented_arcs() {
        assert_eq!(public_key::EC.to_string(), "1.2.840.10045.2.1");
        assert_eq!(public_key::RSA.to_string(), "1.2.840.113549.1.1.1");
        assert_eq!(public_key::ED25519.to_string(), "1.3.101.112");
        assert_eq!(signature::ECDSA_SHA256.to_string(), "1.2.840.10045.4.3.2");
        assert_eq!(signature::RSA_SHA256.to_string(), "1.2.840.113549.1.1.11");
        assert_eq!(signature::RSA_SHA384.to_string(), "1.2.840.113549.1.1.12");
        assert_eq!(signature::RSA_SHA512.to_string(), "1.2.840.113549.1.1.13");
        assert_eq!(curve::PRIME256V1.to_string(), "1.2.840.10045.3.1.7");
        assert_eq!(
            extension::FIDO_GEN_CE_AAGUID.to_string(),
            "1.3.6.1.4.1.45724.1.1.4"
        );
    }

    /// Public-key and signature OIDs are different namespaces. Matching a
    /// signature algorithm against a public-key OID never succeeds, which is
    /// why the two selectors that consume this module stay separate.
    #[test]
    fn public_key_and_signature_oids_are_disjoint() {
        let public_keys = [public_key::EC, public_key::RSA];
        let signatures = [
            signature::ECDSA_SHA256,
            signature::RSA_SHA256,
            signature::RSA_SHA384,
            signature::RSA_SHA512,
        ];
        for pk in public_keys {
            assert!(!signatures.contains(&pk), "{pk} appears in both namespaces");
        }
    }
}
