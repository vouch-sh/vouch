// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9421 signature verification.

use crate::algorithm::VerifyingAlgorithm;
use crate::error::HttpSigError;
use crate::sfv::parse::parse_dictionary;
use crate::sfv::types::{SfvBareItem, SfvDictMember};
use crate::signature_base::{build_request_base, build_response_base};
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
) -> Result<SignatureParams, HttpSigError> {
    let (params, signature_bytes) = extract_signature_parts(req.headers(), label)?;
    validate_algorithm(&params, verifier)?;
    validate_timestamps(&params, max_age)?;

    let base = build_request_base(req, &params)?;
    verifier.verify(&base, &signature_bytes)?;

    Ok(params)
}

/// Verify a signature on an HTTP response.
///
/// # Errors
///
/// Returns [`HttpSigError`] on missing headers, parse errors, expired
/// signatures, or verification failures.
pub fn verify_response_signature<T, U>(
    resp: &http::Response<T>,
    label: &str,
    verifier: &dyn VerifyingAlgorithm,
    req: Option<&http::Request<U>>,
    max_age: Option<i64>,
) -> Result<SignatureParams, HttpSigError> {
    let (params, signature_bytes) = extract_signature_parts(resp.headers(), label)?;
    validate_algorithm(&params, verifier)?;
    validate_timestamps(&params, max_age)?;

    let base = build_response_base(resp, req, &params)?;
    verifier.verify(&base, &signature_bytes)?;

    Ok(params)
}

/// Validate that a signature covers at least the required components (RFC 9421 §7.2.1).
///
/// Verifiers SHOULD require signatures to cover a minimum set of components
/// appropriate for the application context. An empty covered components list
/// means the signature proves key possession but does not bind to any message content.
///
/// # Errors
///
/// Returns [`HttpSigError::InvalidSignature`] if any required component is missing
/// from the signature's covered components.
pub fn validate_coverage(params: &SignatureParams, required: &[&str]) -> Result<(), HttpSigError> {
    for req_name in required {
        let found = params.components.iter().any(|c| {
            // Extract the bare component name without parameters
            let name = match c {
                crate::component::ComponentIdentifier::Field { name, .. } => name.clone(),
                crate::component::ComponentIdentifier::Derived { component, .. } => {
                    crate::component::derived_component_name(component)
                }
            };
            name == *req_name
        });
        if !found {
            return Err(HttpSigError::InvalidSignature(format!(
                "signature does not cover required component: {req_name}"
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
) -> Result<(SignatureParams, Vec<u8>), HttpSigError> {
    let params = find_signature_input(headers, "signature-input", label)?;
    let signature_bytes = find_signature_value(headers, "signature", label)?;
    Ok((params, signature_bytes))
}

/// Find and parse the signature input for a specific label from header values.
fn find_signature_input(
    headers: &http::HeaderMap,
    header_name: &str,
    label: &str,
) -> Result<SignatureParams, HttpSigError> {
    let mut found_header = false;
    for hv in headers.get_all(header_name).iter() {
        let value = hv
            .to_str()
            .map_err(|e| HttpSigError::SfvParse(format!("{header_name}: {e}")))?;
        found_header = true;

        let dict = parse_dictionary(value)?;
        if let Some(member) = dict.get(label) {
            return match member {
                SfvDictMember::InnerList(list) => SignatureParams::from_inner_list(list),
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
        && alg != verifier.algorithm_id()
    {
        return Err(HttpSigError::UnsupportedAlgorithm(format!(
            "signature claims alg=\"{alg}\", but verifier implements \"{}\"",
            verifier.algorithm_id()
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
        && created > now + 60
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
        if now - created > max_age {
            return Err(HttpSigError::Expired(format!(
                "signature created at {created} exceeds max age {max_age}s (now={now})"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use crate::algorithm::ecdsa_p256::EcdsaP256Signer;
    use crate::algorithm::ed25519::Ed25519Signer;
    use crate::algorithm::hmac_sha256::HmacSha256Key;
    use crate::sign::SignatureBuilder;

    fn make_request(method: &str, uri: &str, headers: &[(&str, &str)]) -> http::Request<()> {
        let mut builder = http::Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap()
    }

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

    #[test]
    fn test_response_sign_verify() {
        let key = HmacSha256Key::new(b"secret", "server-key");
        let mut resp = http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(())
            .unwrap();

        SignatureBuilder::new("sig1")
            .status()
            .field("content-type")
            .created(1_618_884_473)
            .tag("vouch-server")
            .sign_response(&mut resp, None::<&http::Request<()>>, &key)
            .unwrap();

        verify_response_signature(&resp, "sig1", &key, None::<&http::Request<()>>, None).unwrap();
    }

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
        validate_coverage(&params, &["@method", "@authority"]).unwrap();
    }

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
        let result = validate_coverage(&params, &["@method", "@authority"]);
        assert!(result.is_err());
    }

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
}
