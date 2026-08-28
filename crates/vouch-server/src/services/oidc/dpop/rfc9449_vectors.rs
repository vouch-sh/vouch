// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9449 published test vectors.
//!
//! Every other DPoP test in this workspace builds a proof with the server's
//! own code and then verifies it with the server's own code. An encoding bug
//! shared by both sides — canonical JSON ordering, base64url alphabet,
//! signature-base construction — passes that loop unnoticed. These tests
//! instead check our implementation against values published in RFC 9449,
//! produced by a key and a signer we do not control.
//!
//! Vectors are lifted from `specs/rfc/rfc9449.txt`, whose sha256 matches the
//! `origin_sha256` column of `specs/manifest.tsv` (row `rfc9449`, marked
//! `verbatim`), so the file is byte-identical to
//! <https://www.rfc-editor.org/rfc/rfc9449.txt>.
//!
//! The proofs carry 2019 `iat` values. That is deliberate and costs nothing:
//! signature verification does not consult the clock, and
//! [`validate_dpop_claims`] takes `now` as an explicit parameter, so the
//! claims are checked against the RFC's own timeline rather than the
//! machine's.

use super::{
    DpopClaimsValidation, compute_access_token_hash, parse_and_verify_dpop_proof,
    validate_dpop_claims,
};
use crate::crypto::alg::JwsAlgorithm;
use crate::crypto::jwk::Jwk;

/// The DPoP proof from RFC 9449 Figure 2, reused verbatim in Figure 5.
///
/// Decoded content is shown in Figure 4.
const FIGURE_2_PROOF: &str = "\
     eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwi\
     eCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5\
     IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNy\
     diI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCI\
     sImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTY\
     yMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiO\
     SsX0x7NVY-FNyJK70nfbV37xRZT3Lg";

/// The DPoP proof from RFC 9449 Figure 13, a protected-resource request.
///
/// Decoded content, including `ath`, is shown in Figure 14.
const FIGURE_13_PROOF: &str = "\
     eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwi\
     eCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5\
     IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNy\
     diI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiw\
     iaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJ\
     jZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHh\
     XWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA\
     1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA";

/// The `jwk` embedded in every proof above, as shown in Figures 4 and 14.
const FIGURE_4_JWK: &str = r#"{
    "kty":"EC",
    "x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
    "y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
    "crv":"P-256"
}"#;

/// RFC 9449 Section 6.1, Figures 8 and 9: the `cnf.jkt` for the key above.
///
/// Section 6.1 states the value "is the hash of the public key from the DPoP
/// proofs in the examples shown in Section 5" — the same key embedded in all
/// three proofs here.
const FIGURE_9_JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

/// The access token presented in RFC 9449 Figure 13.
const FIGURE_13_ACCESS_TOKEN: &str = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";

/// The `ath` claim in Figure 14, which is the hash of the token above.
const FIGURE_14_ATH: &str = "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo";

/// RFC 7638 thumbprint of a published key must equal the published `jkt`.
///
/// This is the assertion that would catch a canonical-JSON defect: member
/// ordering, whitespace, or an unexpected member all change the hash, and a
/// self-signed test cannot detect any of them.
#[test]
fn thumbprint_matches_published_jkt() {
    let jwk: Jwk = serde_json::from_str(FIGURE_4_JWK).expect("Figure 4 JWK parses");
    assert_eq!(
        jwk.thumbprint(),
        FIGURE_9_JKT,
        "RFC 7638 thumbprint must match the jkt published in RFC 9449 Figure 9"
    );
}

/// A real ES256 proof signed by a key we do not control must verify.
///
/// Exercises the whole decode path against externally-produced bytes: JWK to
/// verifying key, base64url decoding, and the JWS signing input.
#[test]
fn figure_2_proof_signature_verifies() {
    let (header, claims) =
        parse_and_verify_dpop_proof(FIGURE_2_PROOF).expect("Figure 2 proof must verify");

    assert_eq!(header.alg, JwsAlgorithm::Es256);

    // Figure 4: the decoded claims of this proof.
    assert_eq!(claims.jti, "-BwC3ESc6acc2lTc");
    assert_eq!(claims.htm, "POST");
    assert_eq!(claims.htu, "https://server.example.com/token");
    assert_eq!(claims.iat, 1_562_262_616);
    assert_eq!(claims.ath, None);
    assert_eq!(claims.nonce, None);
}

/// The embedded key must be the one whose thumbprint the RFC publishes, tying
/// the proof and the `jkt` vector to the same key.
#[test]
fn figure_2_embedded_key_has_published_thumbprint() {
    let (header, _) =
        parse_and_verify_dpop_proof(FIGURE_2_PROOF).expect("Figure 2 proof must verify");
    assert_eq!(header.jwk.thumbprint(), FIGURE_9_JKT);
}

/// The protected-resource proof verifies and carries the published `ath`.
#[test]
fn figure_13_proof_signature_verifies() {
    let (header, claims) =
        parse_and_verify_dpop_proof(FIGURE_13_PROOF).expect("Figure 13 proof must verify");

    assert_eq!(header.alg, JwsAlgorithm::Es256);

    // Figure 14: the decoded claims of this proof.
    assert_eq!(claims.jti, "e1j3V_bKic8-LAEB");
    assert_eq!(claims.htm, "GET");
    assert_eq!(claims.htu, "https://resource.example.org/protectedresource");
    assert_eq!(claims.iat, 1_562_262_618);
    assert_eq!(claims.ath.as_deref(), Some(FIGURE_14_ATH));
}

/// `ath` must be base64url(SHA-256(access token)) per RFC 9449 Section 4.2.
///
/// Checked against the published pair in Figures 13 and 14 rather than
/// against our own hash of our own token.
#[test]
fn access_token_hash_matches_published_ath() {
    assert_eq!(
        compute_access_token_hash(FIGURE_13_ACCESS_TOKEN),
        FIGURE_14_ATH,
        "ath must match the value published in RFC 9449 Figure 14"
    );
}

/// End-to-end: a published proof passes full claims validation when the clock
/// is placed on the RFC's timeline.
#[test]
fn figure_13_claims_validate_against_rfc_timeline() {
    let (_, claims) =
        parse_and_verify_dpop_proof(FIGURE_13_PROOF).expect("Figure 13 proof must verify");

    let accepted = vec!["https://resource.example.org/protectedresource".to_string()];
    validate_dpop_claims(
        &claims,
        &DpopClaimsValidation {
            // One second after the proof was issued, per Figure 14's `iat`.
            now: 1_562_262_619,
            expected_method: "GET",
            accepted_uris: &accepted,
            max_age_seconds: 60,
            expected_nonce: None,
            expected_ath: Some(FIGURE_14_ATH),
        },
    )
    .expect("published proof must satisfy claims validation on the RFC timeline");
}

/// A stale proof is still rejected — the vectors do not disable freshness.
#[test]
fn figure_13_claims_rejected_when_stale() {
    let (_, claims) =
        parse_and_verify_dpop_proof(FIGURE_13_PROOF).expect("Figure 13 proof must verify");

    let accepted = vec!["https://resource.example.org/protectedresource".to_string()];
    let result = validate_dpop_claims(
        &claims,
        &DpopClaimsValidation {
            // Well beyond max_age_seconds after the published `iat`.
            now: 1_562_262_618 + 3600,
            expected_method: "GET",
            accepted_uris: &accepted,
            max_age_seconds: 60,
            expected_nonce: None,
            expected_ath: Some(FIGURE_14_ATH),
        },
    );
    assert!(
        result.is_err(),
        "a proof an hour past its iat must fail freshness validation"
    );
}
