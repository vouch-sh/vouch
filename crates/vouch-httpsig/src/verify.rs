// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9421 signature verification.

use crate::algorithm::VerifyingAlgorithm;
use crate::component::ComponentIdentifier;
use crate::error::HttpSigError;
use crate::sfv::parse::parse_dictionary;
use crate::sfv::serialize::serialize_inner_list_to_string;
use crate::sfv::types::{SfvBareItem, SfvDictMember};
use crate::signature_base::build_request_base_with_params_str;
use crate::signature_params::SignatureParams;

/// Verify a signature on an HTTP request.
///
/// Parses `Signature-Input` and `Signature` headers, reconstructs the
/// signature base, and verifies using the provided algorithm.
///
/// # Arguments
///
/// * `req` — The HTTP request to verify.
/// * `label` — The signature label to look up (e.g., `"sig1"`).
/// * `verifier` — The verification algorithm with the appropriate key.
/// * `max_age` — Optional maximum signature age in seconds.
///
/// # Errors
///
/// Returns [`HttpSigError`] on missing headers, parse errors, expired
/// signatures, or verification failures.
pub fn verify_request_signature<T>(
    req: &http::Request<T>,
    label: &str,
    verifier: &dyn VerifyingAlgorithm,
    max_age: Option<i64>,
) -> Result<CryptoVerified, HttpSigError> {
    let (params, params_str, signature_bytes) = extract_signature_parts(req.headers(), label)?;
    validate_algorithm(&params, verifier)?;
    validate_timestamps(&params, max_age)?;

    let base = build_request_base_with_params_str(req, &params, &params_str)?;
    verifier.verify(&base, &signature_bytes)?;

    Ok(CryptoVerified { params })
}

/// A signature whose cryptographic verification has succeeded.
///
/// First link in the verification chain. It proves the signature is authentic
/// over whatever components it happens to cover — not that those components
/// include anything meaningful, and not that a request body was bound. The
/// only way forward is [`CryptoVerified::require_coverage`].
#[derive(Debug)]
pub struct CryptoVerified {
    params: SignatureParams,
}

impl CryptoVerified {
    /// The verified signature parameters.
    #[must_use]
    pub fn params(&self) -> &SignatureParams {
        &self.params
    }

    /// Check that the signature covers every component in `required`
    /// (RFC 9421 Section 7.2.1).
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::InvalidSignature`] when a required component is
    /// not among the signature's covered components.
    pub fn require_coverage(
        self,
        required: &[ComponentIdentifier],
    ) -> Result<CoverageChecked, HttpSigError> {
        validate_coverage(&self.params, required)?;
        Ok(CoverageChecked {
            params: self.params,
        })
    }
}

/// A verified signature that covers the caller's required components.
///
/// Still insufficient for a request carrying a body: an unsigned
/// `Content-Digest` header could be swapped alongside the payload. The only
/// way forward is [`CoverageChecked::enforce_body_digest`].
#[derive(Debug)]
pub struct CoverageChecked {
    params: SignatureParams,
}

impl CoverageChecked {
    /// The verified signature parameters.
    #[must_use]
    pub fn params(&self) -> &SignatureParams {
        &self.params
    }

    /// Enforce RFC 9530 `Content-Digest` integrity for a signed request body.
    ///
    /// A signed request carrying a non-empty body must cover `content-digest`
    /// in its signature *and* present a matching header. Coverage is required
    /// because an unsigned digest header could be swapped alongside the body.
    /// Empty bodies (GET, bodyless POST) are exempt.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::MissingDigest`] when the body is not bound by a
    /// covered, present `Content-Digest`, or [`HttpSigError::DigestMismatch`]
    /// when the digest does not match the body.
    pub fn enforce_body_digest(
        self,
        headers: &http::HeaderMap,
        body: &[u8],
    ) -> Result<DigestEnforced, HttpSigError> {
        if body.is_empty() {
            return Ok(DigestEnforced {
                params: self.params,
            });
        }

        validate_coverage(
            &self.params,
            &[ComponentIdentifier::field("content-digest")],
        )
        .map_err(|_| HttpSigError::MissingDigest)?;

        let header = headers
            .get("content-digest")
            .ok_or(HttpSigError::MissingDigest)?
            .to_str()
            .map_err(|e| HttpSigError::SfvParse(format!("Content-Digest: {e}")))?;

        crate::digest::verify_content_digest(header, body)?;

        Ok(DigestEnforced {
            params: self.params,
        })
    }
}

/// A fully checked signature: verified, coverage-checked, and body-bound.
///
/// Reaching this state is the only way to build the `VerifiedSignature`
/// request extension, so a downstream handler cannot observe a signature
/// result that skipped a step. Producing one requires moving through
/// [`CryptoVerified`] and [`CoverageChecked`] in order — the sequence is
/// enforced by the types rather than by statement order in a caller.
#[derive(Debug)]
pub struct DigestEnforced {
    params: SignatureParams,
}

impl DigestEnforced {
    /// The verified signature parameters.
    #[must_use]
    pub fn params(&self) -> &SignatureParams {
        &self.params
    }

    /// Consume the proof, yielding the verified parameters.
    #[must_use]
    pub fn into_params(self) -> SignatureParams {
        self.params
    }
}

/// Validate that a signature covers at least the required components (RFC 9421 §7.2.1).
///
/// Verifiers SHOULD require signatures to cover a minimum set of components
/// appropriate for the application context. An empty covered components list
/// means the signature proves key possession but does not bind to any message content.
///
/// Private on purpose: a coverage check that returns `Ok(())` and nothing else
/// leaves no evidence it ran, which is the failure mode the verification chain
/// exists to remove. Callers reach it through
/// [`CryptoVerified::require_coverage`], which hands back a
/// [`CoverageChecked`] proof. Shared here because both that transition and
/// [`CoverageChecked::enforce_body_digest`] need the same comparison.
///
/// # Errors
///
/// Returns [`HttpSigError::InvalidSignature`] if any required component is missing
/// from the signature's covered components.
fn validate_coverage(
    params: &SignatureParams,
    required: &[ComponentIdentifier],
) -> Result<(), HttpSigError> {
    for req in required {
        let found = params.components.iter().any(|c| c.covers(req));
        if !found {
            return Err(HttpSigError::InvalidSignature(format!(
                "signature does not cover required component: {}",
                req.name()
            )));
        }
    }
    Ok(())
}

/// Extract all signature labels from the `Signature-Input` header.
///
/// # Errors
///
/// Returns [`HttpSigError::MissingHeader`] if the header is absent.
pub fn extract_signature_labels(headers: &http::HeaderMap) -> Result<Vec<String>, HttpSigError> {
    let input_header = headers
        .get("signature-input")
        .ok_or_else(|| HttpSigError::MissingHeader("Signature-Input".into()))?
        .to_str()
        .map_err(|e| HttpSigError::SfvParse(format!("Signature-Input: {e}")))?;

    let dict = parse_dictionary(input_header)?;
    Ok(dict.entries.into_iter().map(|(k, _)| k).collect())
}

/// Extract signature parameters and raw signature bytes for a given label.
fn extract_signature_parts(
    headers: &http::HeaderMap,
    label: &str,
) -> Result<(SignatureParams, String, Vec<u8>), HttpSigError> {
    let (params, params_str) = find_signature_input(headers, "signature-input", label)?;
    let signature_bytes = find_signature_value(headers, "signature", label)?;
    Ok((params, params_str, signature_bytes))
}

/// Find and parse the signature input for a specific label from header values.
fn find_signature_input(
    headers: &http::HeaderMap,
    header_name: &str,
    label: &str,
) -> Result<(SignatureParams, String), HttpSigError> {
    let mut found_header = false;
    for hv in headers.get_all(header_name).iter() {
        let value = hv
            .to_str()
            .map_err(|e| HttpSigError::SfvParse(format!("{header_name}: {e}")))?;
        found_header = true;

        let dict = parse_dictionary(value)?;
        if let Some(member) = dict.get(label) {
            return match member {
                SfvDictMember::InnerList(list) => {
                    let params = SignatureParams::from_inner_list(list)?;
                    let params_str = serialize_inner_list_to_string(list);
                    Ok((params, params_str))
                }
                _ => Err(HttpSigError::SfvParse(format!(
                    "Signature-Input '{label}' must be an inner list"
                ))),
            };
        }
    }
    if found_header {
        Err(HttpSigError::MissingHeader(format!(
            "Signature-Input label '{label}' not found"
        )))
    } else {
        Err(HttpSigError::MissingHeader(header_name.to_string()))
    }
}

/// Find and decode the signature bytes for a specific label from header values.
fn find_signature_value(
    headers: &http::HeaderMap,
    header_name: &str,
    label: &str,
) -> Result<Vec<u8>, HttpSigError> {
    let mut found_header = false;
    for hv in headers.get_all(header_name).iter() {
        let value = hv
            .to_str()
            .map_err(|e| HttpSigError::SfvParse(format!("{header_name}: {e}")))?;
        found_header = true;

        let dict = parse_dictionary(value)?;
        if let Some(member) = dict.get(label) {
            return match member {
                SfvDictMember::Item(item) => match &item.value {
                    SfvBareItem::ByteSequence(bytes) => Ok(bytes.clone()),
                    _ => Err(HttpSigError::InvalidSignature(format!(
                        "Signature '{label}' must be a byte sequence"
                    ))),
                },
                _ => Err(HttpSigError::InvalidSignature(format!(
                    "Signature '{label}' must be an item, not an inner list"
                ))),
            };
        }
    }
    if found_header {
        Err(HttpSigError::MissingHeader(format!(
            "Signature label '{label}' not found"
        )))
    } else {
        Err(HttpSigError::MissingHeader(header_name.to_string()))
    }
}

/// Validate that the signature's algorithm matches the verifier's algorithm.
fn validate_algorithm(
    params: &SignatureParams,
    verifier: &dyn VerifyingAlgorithm,
) -> Result<(), HttpSigError> {
    if let Some(alg) = &params.alg
        && alg != verifier.algorithm().as_str()
    {
        return Err(HttpSigError::UnsupportedAlgorithm(format!(
            "signature claims alg=\"{alg}\", but verifier implements \"{}\"",
            verifier.algorithm()
        )));
    }
    Ok(())
}

/// Validate signature timestamps against current time and optional max age.
fn validate_timestamps(params: &SignatureParams, max_age: Option<i64>) -> Result<(), HttpSigError> {
    let now = jiff::Timestamp::now().as_second();

    if let Some(expires) = params.expires
        && now > expires
    {
        return Err(HttpSigError::Expired(format!(
            "signature expired at {expires}, current time is {now}"
        )));
    }

    // Reject future-dated signatures regardless of max_age
    if let Some(created) = params.created
        && created > now.saturating_add(60)
    {
        return Err(HttpSigError::Expired(format!(
            "signature created in the future: {created} (now={now})"
        )));
    }

    // When max_age is set, created MUST be present — otherwise age cannot be checked
    if let Some(max_age) = max_age {
        let created = params.created.ok_or_else(|| {
            HttpSigError::Expired("max_age enforced but signature has no created timestamp".into())
        })?;
        if now.saturating_sub(created) > max_age {
            return Err(HttpSigError::Expired(format!(
                "signature created at {created} exceeds max age {max_age}s (now={now})"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::algorithm::SigningAlgorithm;
    use crate::algorithm::ecdsa_p256::EcdsaP256Signer;
    use crate::algorithm::ed25519::Ed25519Signer;
    use crate::algorithm::hmac_sha256::HmacSha256Key;
    use crate::sfv::parse::parse_inner_list;
    use crate::sfv::serialize::{serialize_dictionary, serialize_inner_list_to_string};
    use crate::sfv::types::{SfvDictionary, SfvItem, SfvParams};
    use crate::sign::SignatureBuilder;
    use crate::signature_base::build_request_base_with_params_str;

    fn make_request(method: &str, uri: &str, headers: &[(&str, &str)]) -> http::Request<()> {
        let mut builder = http::Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap()
    }

    // RFC 9421 §3.3.3: hmac-sha256 signs and verifies.
    #[test]
    fn test_hmac_sign_verify_roundtrip() {
        let key = HmacSha256Key::new(b"shared-secret", "test-key");
        let mut req = make_request(
            "POST",
            "https://example.com/foo",
            &[("content-type", "application/json")],
        );

        SignatureBuilder::new("sig1")
            .method()
            .authority()
            .path()
            .field("content-type")
            .created(1_618_884_473)
            .sign_request(&mut req, &key)
            .unwrap();

        let result = verify_request_signature(&req, "sig1", &key, None);
        result.unwrap();
    }

    // RFC 9421 §3.3.4: ecdsa-p256-sha256 signs and verifies.
    #[test]
    fn test_ecdsa_sign_verify_roundtrip() {
        let signer = EcdsaP256Signer::generate("ec-key").unwrap();
        let verifier = signer.verifier();

        let mut req = make_request(
            "GET",
            "https://example.com/api/v1/resource",
            &[("accept", "application/json")],
        );

        SignatureBuilder::new("sig1")
            .method()
            .authority()
            .path()
            .field("accept")
            .created(1_618_884_473)
            .sign_request(&mut req, &signer)
            .unwrap();

        verify_request_signature(&req, "sig1", &verifier, None).unwrap();
    }

    // RFC 9421 §3.3.6: ed25519 signs and verifies.
    #[test]
    fn test_ed25519_sign_verify_roundtrip() {
        let signer = Ed25519Signer::generate("ed-key").unwrap();
        let verifier = signer.verifier();

        let mut req = make_request("DELETE", "https://example.com/item/42", &[]);

        SignatureBuilder::new("sig1")
            .method()
            .path()
            .created(1_618_884_473)
            .sign_request(&mut req, &signer)
            .unwrap();

        verify_request_signature(&req, "sig1", &verifier, None).unwrap();
    }

    // RFC 9421 §3.2: verification fails when the key does not match the signature.
    #[test]
    fn test_wrong_key_rejects() {
        let key1 = HmacSha256Key::new(b"secret1", "k1");
        let key2 = HmacSha256Key::new(b"secret2", "k2");

        let mut req = make_request("GET", "https://example.com/", &[]);

        SignatureBuilder::new("sig1")
            .method()
            .created(1_618_884_473)
            .sign_request(&mut req, &key1)
            .unwrap();

        let result = verify_request_signature(&req, "sig1", &key2, None);
        assert!(result.is_err());
    }

    // RFC 9421 §3.2: altering a covered field invalidates the signature.
    #[test]
    fn test_tampered_header_rejects() {
        let key = HmacSha256Key::new(b"secret", "k");
        let mut req = make_request(
            "POST",
            "https://example.com/",
            &[("content-type", "application/json")],
        );

        SignatureBuilder::new("sig1")
            .method()
            .field("content-type")
            .created(1_618_884_473)
            .sign_request(&mut req, &key)
            .unwrap();

        // Tamper with the content-type header
        req.headers_mut()
            .insert("content-type", http::HeaderValue::from_static("text/plain"));

        let result = verify_request_signature(&req, "sig1", &key, None);
        assert!(result.is_err());
    }

    // RFC 9421 §3.2.1: a signature whose expires parameter has passed is rejected.
    #[test]
    fn test_expired_signature_rejects() {
        let key = HmacSha256Key::new(b"secret", "k");
        let mut req = make_request("GET", "https://example.com/", &[]);

        // Create with expiration in the past
        SignatureBuilder::new("sig1")
            .method()
            .created(1000)
            .expires_in(100) // expires at 1100
            .sign_request(&mut req, &key)
            .unwrap();

        let result = verify_request_signature(&req, "sig1", &key, None);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(HttpSigError::Expired(_))),
            "should be Expired"
        );
    }

    // RFC 9421 §3.2.1: the application may reject a signature older than its own limit.
    #[test]
    fn test_max_age_rejects_old_signature() {
        let key = HmacSha256Key::new(b"secret", "k");
        let mut req = make_request("GET", "https://example.com/", &[]);

        // Created far in the past
        SignatureBuilder::new("sig1")
            .method()
            .created(1000)
            .sign_request(&mut req, &key)
            .unwrap();

        let result = verify_request_signature(&req, "sig1", &key, Some(3600));
        assert!(result.is_err());
    }

    // RFC 9421 §4.1: a Signature-Input label with no matching Signature entry is an error.
    #[test]
    fn test_missing_label_returns_error() {
        let key = HmacSha256Key::new(b"secret", "k");
        let mut req = make_request("GET", "https://example.com/", &[]);

        SignatureBuilder::new("sig1")
            .method()
            .created(1_618_884_473)
            .sign_request(&mut req, &key)
            .unwrap();

        let result = verify_request_signature(&req, "sig2", &key, None);
        assert!(result.is_err());
    }

    // RFC 9421 §4.1: Signature-Input is a Dictionary keyed by signature label.
    #[test]
    fn test_extract_labels() {
        let key = HmacSha256Key::new(b"secret", "k");
        let mut req = make_request("GET", "https://example.com/", &[]);

        SignatureBuilder::new("sig1")
            .method()
            .created(100)
            .sign_request(&mut req, &key)
            .unwrap();

        let labels = extract_signature_labels(req.headers()).unwrap();
        assert!(labels.contains(&"sig1".to_string()));
    }

    // RFC 9421 §2.5: the signature base follows the component order given in Signature-Input.
    #[test]
    fn test_verify_request_uses_signature_input_param_order() {
        let key = HmacSha256Key::new(b"secret", "k");
        let mut req = make_request("GET", "https://example.com/", &[]);
        let params_str = "(\"@method\");created=1618884473;alg=\"hmac-sha256\";keyid=\"k\"";
        let list = parse_inner_list(params_str).unwrap();
        let params = SignatureParams::from_inner_list(&list).unwrap();
        let base = build_request_base_with_params_str(&req, &params, params_str).unwrap();
        let signature_bytes = key.sign(&base).unwrap();

        req.headers_mut().insert(
            "signature-input",
            http::HeaderValue::from_str(&format!("sig1={params_str}")).unwrap(),
        );
        req.headers_mut().insert(
            "signature",
            http::HeaderValue::from_str(&serialize_dictionary(&SfvDictionary {
                entries: vec![(
                    "sig1".to_string(),
                    SfvDictMember::Item(SfvItem {
                        value: SfvBareItem::ByteSequence(signature_bytes),
                        params: SfvParams::new(),
                    }),
                )],
            }))
            .unwrap(),
        );

        verify_request_signature(&req, "sig1", &key, None).unwrap();
    }

    // RFC 9421 §2 + §2.5 step 2.1, end to end: a request whose Signature-Input
    // carries two order-equivalent component identifiers (same name, same
    // parameter set, different parameter order) MUST be rejected before a
    // signature base is produced. §2 makes `"x-dict";key="a";sf` and
    // `"x-dict";sf;key="a"` equivalent, so §2.5 step 2.1 forbids both, and §2.5
    // requires the algorithm to "fail ... immediately, without outputting a
    // signature base." This drives the public verifier entry point with a
    // complete, validly signed request and confirms it returns an error rather
    // than `Ok(CryptoVerified)`. The signature is computed over the exact
    // duplicated base a pre-fix verifier would have built, so the only thing
    // the post-fix verifier can reject on is the §2.5 abort, not the crypto.
    #[test]
    fn end_to_end_order_equivalent_duplicate_is_rejected_by_verifier() {
        let key = HmacSha256Key::new(b"shared-secret", "test-key");

        // Two order-permuted but §2-equivalent component identifiers in one
        // Signature-Input inner list. Replicate the verifier's own params_str
        // derivation (parse_inner_list -> serialize_inner_list_to_string) so
        // the signature is over the exact @signature-params line it builds.
        let si_inner = "(\"x-dict\";key=\"a\";sf \"x-dict\";sf;key=\"a\");created=1618884473;\
             alg=\"hmac-sha256\"";
        let list = parse_inner_list(si_inner).unwrap();
        let params_str = serialize_inner_list_to_string(&list);

        // Build the duplicated signature base by hand: once the fix lands the
        // verifier refuses to produce one, so this is the only way to obtain
        // the bytes a pre-fix verifier would have signed and accepted. Both
        // order-permuted identifiers resolve the same dictionary member
        // ("a" = 1) to "1", so each covered-component line is "<id>: 1", and
        // the final line is the @signature-params line with no trailing
        // newline.
        let dup_base = format!(
            "\"x-dict\";key=\"a\";sf: 1\n\
             \"x-dict\";sf;key=\"a\": 1\n\
             \"@signature-params\": {params_str}"
        );
        let signature_bytes = key.sign(dup_base.as_bytes()).unwrap();

        let mut req = make_request("GET", "https://example.com/p", &[("x-dict", "a=1")]);
        req.headers_mut().insert(
            "signature-input",
            http::HeaderValue::from_str(&format!("sig1={params_str}")).unwrap(),
        );
        req.headers_mut().insert(
            "signature",
            http::HeaderValue::from_str(&serialize_dictionary(&SfvDictionary {
                entries: vec![(
                    "sig1".to_string(),
                    SfvDictMember::Item(SfvItem {
                        value: SfvBareItem::ByteSequence(signature_bytes),
                        params: SfvParams::new(),
                    }),
                )],
            }))
            .unwrap(),
        );

        let result = verify_request_signature(&req, "sig1", &key, None);
        assert!(
            matches!(result, Err(HttpSigError::BaseConstruction(_))),
            "RFC 9421 §2 + §2.5 require verify_request_signature to fail (produce \
             an error, no CryptoVerified) for a request whose Signature-Input \
             contains an order-equivalent duplicate component identifier; got {result:?}"
        );
    }

    // RFC 9421 §3.2.1: the verifier enforces its own required-component list.
    #[test]
    fn test_validate_coverage_passes() {
        let params = crate::SignatureParams {
            components: vec![
                crate::ComponentIdentifier::method(),
                crate::ComponentIdentifier::authority(),
                crate::ComponentIdentifier::field("content-type"),
            ],
            alg: None,
            keyid: None,
            created: None,
            expires: None,
            nonce: None,
            tag: None,
        };
        validate_coverage(
            &params,
            &[
                ComponentIdentifier::method(),
                ComponentIdentifier::authority(),
            ],
        )
        .unwrap();
    }

    // RFC 9421 §7.2.1: a signature that omits a required component is insufficient coverage.
    #[test]
    fn test_validate_coverage_rejects_missing() {
        let params = crate::SignatureParams {
            components: vec![crate::ComponentIdentifier::method()],
            alg: None,
            keyid: None,
            created: None,
            expires: None,
            nonce: None,
            tag: None,
        };
        let result = validate_coverage(
            &params,
            &[
                ComponentIdentifier::method(),
                ComponentIdentifier::authority(),
            ],
        );
        assert!(result.is_err());
    }

    // RFC 9421 §3.2.1: an empty requirement list imposes no coverage constraint.
    #[test]
    fn test_validate_coverage_empty_required() {
        let params = crate::SignatureParams {
            components: vec![],
            alg: None,
            keyid: None,
            created: None,
            expires: None,
            nonce: None,
            tag: None,
        };
        validate_coverage(&params, &[]).unwrap();
    }

    fn params_covering(components: Vec<crate::ComponentIdentifier>) -> SignatureParams {
        SignatureParams {
            components,
            alg: None,
            keyid: None,
            created: None,
            expires: None,
            nonce: None,
            tag: None,
        }
    }

    /// Enter the chain at the digest step. Only reachable here because the
    /// tests are a child module of `verify` — outside the crate the sole
    /// route to `CoverageChecked` is `CryptoVerified::require_coverage`.
    fn coverage_checked(components: Vec<crate::ComponentIdentifier>) -> CoverageChecked {
        CoverageChecked {
            params: params_covering(components),
        }
    }

    fn digest_header(body: &[u8]) -> http::HeaderValue {
        crate::digest::content_digest(body, crate::digest::DigestAlgorithm::Sha256)
            .parse()
            .unwrap()
    }

    // RFC 9421 §7.2.8: with no content there is nothing for a digest to bind.
    #[test]
    fn test_enforce_body_digest_empty_body_is_exempt() {
        let headers = http::HeaderMap::new();
        coverage_checked(vec![])
            .enforce_body_digest(&headers, b"")
            .unwrap();
    }

    // RFC 9530 §2: Content-Digest binds the message content the signature covers.
    #[test]
    fn test_enforce_body_digest_valid() {
        let body = b"{\"x\":1}";
        let mut headers = http::HeaderMap::new();
        headers.insert("content-digest", digest_header(body));
        coverage_checked(vec![
            crate::ComponentIdentifier::method(),
            crate::ComponentIdentifier::field("content-digest"),
        ])
        .enforce_body_digest(&headers, body)
        .unwrap();
    }

    // RFC 9421 §7.2.8: a request with content but no Content-Digest leaves the content unsigned.
    #[test]
    fn test_enforce_body_digest_missing_header() {
        let body = b"body";
        let headers = http::HeaderMap::new();
        assert!(matches!(
            coverage_checked(vec![crate::ComponentIdentifier::field("content-digest")])
                .enforce_body_digest(&headers, body),
            Err(HttpSigError::MissingDigest)
        ));
    }

    // RFC 9421 §7.2.8: a Content-Digest the signature does not cover does not protect the content.
    #[test]
    fn test_enforce_body_digest_not_covered() {
        let body = b"body";
        let mut headers = http::HeaderMap::new();
        headers.insert("content-digest", digest_header(body));
        assert!(matches!(
            coverage_checked(vec![crate::ComponentIdentifier::method()])
                .enforce_body_digest(&headers, body),
            Err(HttpSigError::MissingDigest)
        ));
    }

    // RFC 9530 §2: a Content-Digest that does not match the content is rejected.
    #[test]
    fn test_enforce_body_digest_mismatch() {
        let mut headers = http::HeaderMap::new();
        headers.insert("content-digest", digest_header(b"other body"));
        assert!(matches!(
            coverage_checked(vec![crate::ComponentIdentifier::field("content-digest")])
                .enforce_body_digest(&headers, b"body"),
            Err(HttpSigError::DigestMismatch(_))
        ));
    }
}
