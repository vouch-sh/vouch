// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 7638 JWK Thumbprint.
//!
//! Shared by the server (DPoP proof keys, `cnf.jkt`) and the CLI (its FAPI
//! client key). The thumbprint is an identity that one party computes and
//! another compares, so the canonicalization has a single definition here.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The public key material a thumbprint is computed over.
///
/// Each variant carries exactly the members RFC 7638 Section 3.2 lists as
/// required for that key type. Optional members such as `alg` and `kid` are
/// not representable and so cannot reach the hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwkThumbprintKey<'a> {
    /// Elliptic curve public key. Required members: `crv`, `kty`, `x`, `y`.
    Ec {
        /// The `crv` member, e.g. `"P-256"`.
        crv: &'a str,
        /// The `x` coordinate, base64url.
        x: &'a str,
        /// The `y` coordinate, base64url.
        y: &'a str,
    },
    /// RSA public key. Required members: `e`, `kty`, `n`.
    Rsa {
        /// The `e` exponent, base64url.
        e: &'a str,
        /// The `n` modulus, base64url.
        n: &'a str,
    },
    /// Octet key pair (RFC 8037). Required members: `crv`, `kty`, `x`.
    Okp {
        /// The `crv` member, e.g. `"Ed25519"`.
        crv: &'a str,
        /// The public key, base64url.
        x: &'a str,
    },
}

impl<'a> JwkThumbprintKey<'a> {
    /// Read the required members from a JWK, dispatching on `kty`.
    ///
    /// Returns `None` when `kty` is unrecognised or a required member is
    /// absent or not a string.
    #[must_use]
    pub fn from_json(jwk: &'a serde_json::Value) -> Option<Self> {
        let member = |name: &str| jwk.get(name)?.as_str();
        match jwk.get("kty")?.as_str()? {
            "EC" => Some(Self::Ec {
                crv: member("crv")?,
                x: member("x")?,
                y: member("y")?,
            }),
            "RSA" => Some(Self::Rsa {
                e: member("e")?,
                n: member("n")?,
            }),
            "OKP" => Some(Self::Okp {
                crv: member("crv")?,
                x: member("x")?,
            }),
            _ => None,
        }
    }

    /// The `kty` value for this key type.
    fn kty(&self) -> &'static str {
        match self {
            Self::Ec { .. } => "EC",
            Self::Rsa { .. } => "RSA",
            Self::Okp { .. } => "OKP",
        }
    }

    /// Compute the RFC 7638 JWK Thumbprint, base64url-encoded.
    ///
    /// SHA-256 is the hash: RFC 9449 Section 6.1 requires it for `jkt`, and
    /// RFC 7638 Section 3.4 names it the default choice.
    ///
    /// RFC 7638 Section 3:
    ///
    /// > 1. Construct a JSON object [RFC7159] containing only the required
    /// >    members of a JWK representing the key and with no whitespace or
    /// >    line breaks before or after any syntactic elements and with the
    /// >    required members ordered lexicographically by the Unicode
    /// >    [UNICODE] code points of the member names.
    /// > 2. Hash the octets of the UTF-8 representation of this JSON object
    /// >    with a cryptographic hash function H.
    ///
    /// Members are written in lexicographic order per variant. `serde_json`
    /// escapes the values and emits no whitespace.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        let kty = self.kty();
        let canonical = match *self {
            Self::Ec { crv, x, y } => {
                serde_json::json!({ "crv": crv, "kty": kty, "x": x, "y": y })
            }
            Self::Rsa { e, n } => serde_json::json!({ "e": e, "kty": kty, "n": n }),
            Self::Okp { crv, x } => serde_json::json!({ "crv": crv, "kty": kty, "x": x }),
        };

        // `serde_json::Map` sorts its keys unless `preserve_order` is enabled,
        // which it is not, so serialization emits the required order.
        let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &bytes);
        URL_SAFE_NO_PAD.encode(digest.as_ref())
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    /// The RSA key from RFC 7638 Section 3.1, wrapped for line width.
    const RFC7638_N: &str = "\
         0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu\
         1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-\
         5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-\
         65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajr\
         n1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-\
         G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

    /// RFC 7638 Section 3.1 states the thumbprint of the example key.
    #[test]
    fn rfc7638_worked_example() {
        let key = JwkThumbprintKey::Rsa {
            e: "AQAB",
            n: RFC7638_N,
        };
        assert_eq!(
            key.thumbprint(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    /// RFC 9449 Section 6.1 states the `jkt` for the EC key in its DPoP proof
    /// examples, covering the EC member set and ordering.
    #[test]
    fn rfc9449_ec_key_thumbprint() {
        let key = JwkThumbprintKey::Ec {
            crv: "P-256",
            x: "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
            y: "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
        };
        assert_eq!(
            key.thumbprint(),
            "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
        );
    }

    /// Each key type has a distinct required-member set.
    #[test]
    fn key_types_produce_distinct_thumbprints() {
        let ec = JwkThumbprintKey::Ec {
            crv: "P-256",
            x: "aaa",
            y: "bbb",
        }
        .thumbprint();
        let okp = JwkThumbprintKey::Okp {
            crv: "P-256",
            x: "aaa",
        }
        .thumbprint();
        let rsa = JwkThumbprintKey::Rsa { e: "aaa", n: "bbb" }.thumbprint();

        assert_ne!(ec, okp);
        assert_ne!(ec, rsa);
        assert_ne!(okp, rsa);
    }

    /// `kty` is determined by the variant, not supplied by the caller.
    #[test]
    fn kty_comes_from_the_variant() {
        assert_eq!(
            JwkThumbprintKey::Ec {
                crv: "P-256",
                x: "",
                y: ""
            }
            .kty(),
            "EC"
        );
        assert_eq!(JwkThumbprintKey::Rsa { e: "", n: "" }.kty(), "RSA");
        assert_eq!(JwkThumbprintKey::Okp { crv: "", x: "" }.kty(), "OKP");
    }

    /// A quote inside a member value is escaped rather than interpolated, so
    /// it cannot reproduce another key's canonical form.
    #[test]
    fn values_are_escaped_not_interpolated() {
        let honest = JwkThumbprintKey::Ec {
            crv: "P-256",
            x: "a",
            y: "b",
        }
        .thumbprint();
        let forged = JwkThumbprintKey::Ec {
            crv: "P-256",
            x: r#"a","y":"b"#,
            y: "b",
        }
        .thumbprint();
        assert_ne!(honest, forged);
    }

    /// `from_json` reads the members `kty` selects, and nothing else.
    #[test]
    fn from_json_reads_the_required_members_per_kty() {
        let ec = serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": "xx", "y": "yy",
            "alg": "ES256", "kid": "ignored"
        });
        assert_eq!(
            JwkThumbprintKey::from_json(&ec),
            Some(JwkThumbprintKey::Ec {
                crv: "P-256",
                x: "xx",
                y: "yy"
            })
        );

        let rsa = serde_json::json!({"kty": "RSA", "e": "AQAB", "n": "nn"});
        assert_eq!(
            JwkThumbprintKey::from_json(&rsa),
            Some(JwkThumbprintKey::Rsa { e: "AQAB", n: "nn" })
        );

        let okp = serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": "xx"});
        assert_eq!(
            JwkThumbprintKey::from_json(&okp),
            Some(JwkThumbprintKey::Okp {
                crv: "Ed25519",
                x: "xx"
            })
        );
    }

    /// An optional member present in the JWK does not change the thumbprint.
    #[test]
    fn optional_members_do_not_affect_the_thumbprint() {
        let bare = serde_json::json!({"kty": "EC", "crv": "P-256", "x": "xx", "y": "yy"});
        let adorned = serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": "xx", "y": "yy",
            "alg": "ES256", "kid": "k1", "use": "sig"
        });
        assert_eq!(
            JwkThumbprintKey::from_json(&bare).unwrap().thumbprint(),
            JwkThumbprintKey::from_json(&adorned).unwrap().thumbprint()
        );
    }

    /// A missing required member or an unknown `kty` yields `None` rather than
    /// a thumbprint over empty strings.
    #[test]
    fn from_json_rejects_incomplete_and_unknown_keys() {
        for jwk in [
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": "xx"}),
            serde_json::json!({"kty": "RSA", "e": "AQAB"}),
            serde_json::json!({"kty": "OKP", "crv": "Ed25519"}),
            serde_json::json!({"kty": "oct", "k": "kk"}),
            serde_json::json!({"crv": "P-256", "x": "xx", "y": "yy"}),
            serde_json::json!({"kty": "EC", "crv": 256, "x": "xx", "y": "yy"}),
        ] {
            assert_eq!(JwkThumbprintKey::from_json(&jwk), None, "{jwk}");
        }
    }
}
