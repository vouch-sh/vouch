// SPDX-License-Identifier: Apache-2.0 OR MIT
//! XML-DSig signature verification for SAML 2.0 responses.
//!
//! Implements enveloped XML Digital Signature verification per
//! <https://www.w3.org/TR/xmldsig-core1/> with exclusive XML canonicalization
//! per <https://www.w3.org/TR/xml-exc-c14n/>.
//!
//! # Security: XSW Mitigations
//!
//! XML Signature Wrapping (XSW) is the most common SAML vulnerability class.
//! This module implements mandatory mitigations:
//!
//! - Empty URI references are rejected (no whole-document signatures)
//! - Reference URI must start with `#` and point to an existing element ID
//! - After verification, the signed element is re-resolved by ID (no cached positions)
//! - Only the signed element's ID is returned; callers must extract data from that element
//!
//! See: <https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky>

use aws_lc_rs::digest;
use aws_lc_rs::signature;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use der::Decode;
use x509_cert::Certificate;

use super::c14n;

// ============================================================================
// XML-DSig algorithm URIs
// ============================================================================

/// Enveloped signature transform URI.
const TRANSFORM_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// Exclusive XML Canonicalization transform URI.
const TRANSFORM_EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// RSA-SHA256 signature algorithm URI.
const SIG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

/// ECDSA-SHA256 signature algorithm URI.
const SIG_ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

/// XML-DSig namespace URI.
const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Exclusive canonicalization InclusiveNamespaces element namespace.
const NS_EC: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

// ============================================================================
// Error type
// ============================================================================

/// Errors during XML signature verification.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SignatureError {
    /// No `<ds:Signature>` element found in the document.
    #[error("no Signature element found")]
    NoSignature,
    /// The `<ds:Reference URI>` is invalid (empty, missing `#`, etc.).
    #[error("invalid Reference URI: {0}")]
    InvalidReference(String),
    /// The element referenced by the `<ds:Reference URI>` does not exist.
    #[error("referenced element not found: {0}")]
    ReferencedElementNotFound(String),
    /// The digest of the canonicalized signed element does not match.
    #[error("digest mismatch")]
    DigestMismatch,
    /// The cryptographic signature over `<ds:SignedInfo>` is invalid.
    #[error("signature verification failed")]
    SignatureInvalid,
    /// No signing certificate in the IdP metadata matched the signature.
    #[error("no matching certificate")]
    NoCertificateMatch,
    /// The signature or digest algorithm is not supported.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// Other errors (XML structure, encoding, etc.).
    #[error("{0}")]
    Other(String),
}

// ============================================================================
// Public types
// ============================================================================

/// The ID attribute of the element whose signature was successfully verified.
///
/// Callers must re-resolve this ID in the document to extract identity data,
/// rather than using a cached DOM position (XSW mitigation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignedElementId(pub String);

// ============================================================================
// Public API
// ============================================================================

/// Verify the XML Digital Signature in a SAML document.
///
/// Algorithm:
/// 1. Locate `<ds:Signature>` in the document
/// 2. Extract and validate `<ds:Reference URI="#id">`
/// 3. Find the referenced element by ID
/// 4. Canonicalize it (exc-c14n, excluding the Signature subtree)
/// 5. Compare SHA-256 digest with `<ds:DigestValue>`
/// 6. Canonicalize `<ds:SignedInfo>` with exc-c14n
/// 7. Verify the signature over SignedInfo using each certificate
///
/// # Errors
///
/// Returns `SignatureError` if the signature is missing, malformed, invalid,
/// uses an unsupported algorithm, or no provided certificate matches.
pub(crate) fn verify_xml_signature(
    doc: &roxmltree::Document,
    signing_certificates: &[Vec<u8>],
) -> Result<SignedElementId, SignatureError> {
    // Step 1: Locate <ds:Signature> as a direct child of a SAML element.
    // Only consider Signature elements that are direct children of the
    // Response or Assertion root elements, not arbitrary descendants.
    // This prevents an attacker from injecting a Signature elsewhere in the tree.
    let sig_node = find_saml_signature(doc).ok_or(SignatureError::NoSignature)?;

    // Step 2: Extract <ds:Reference URI>
    let signed_info = find_child_element(sig_node, NS_DS, "SignedInfo")
        .ok_or_else(|| SignatureError::Other("missing SignedInfo element".to_string()))?;

    // Reject multiple <ds:Reference> elements. SAML 2.0 expects exactly one
    // Reference in SignedInfo; multiple References produce undefined behavior.
    let references: Vec<_> = signed_info
        .children()
        .filter(|n| n.has_tag_name((NS_DS, "Reference")))
        .collect();
    if references.len() > 1 {
        return Err(SignatureError::Other(
            "multiple Reference elements in SignedInfo (expected exactly one)".to_string(),
        ));
    }
    let reference_node = references
        .into_iter()
        .next()
        .ok_or_else(|| SignatureError::Other("missing Reference element".to_string()))?;

    let ref_uri = reference_node
        .attribute("URI")
        .ok_or_else(|| SignatureError::InvalidReference("URI attribute missing".to_string()))?;

    // XSW mitigation: reject empty URI (whole-document signatures)
    if ref_uri.is_empty() {
        return Err(SignatureError::InvalidReference(
            "empty URI (whole-document signatures are not supported)".to_string(),
        ));
    }

    // XSW mitigation: require #id form
    if !ref_uri.starts_with('#') {
        return Err(SignatureError::InvalidReference(format!(
            "URI must start with '#', got: {ref_uri}"
        )));
    }

    #[expect(
        clippy::string_slice,
        reason = "ref_uri is verified to start with '#' (ASCII, single byte); slice at [1..] is safe"
    )]
    let element_id = &ref_uri[1..];
    if element_id.is_empty() {
        return Err(SignatureError::InvalidReference(
            "empty element ID after '#'".to_string(),
        ));
    }

    // Step 3: Find the referenced element by ID attribute
    let signed_element = find_element_by_id(doc, element_id)
        .ok_or_else(|| SignatureError::ReferencedElementNotFound(element_id.to_string()))?;

    // Step 4: Extract transforms and InclusiveNamespaces PrefixList
    let transforms_node = find_child_element(reference_node, NS_DS, "Transforms");
    let inclusive_prefixes_owned = extract_inclusive_prefixes(transforms_node);
    let inclusive_prefixes: Vec<&str> = inclusive_prefixes_owned
        .iter()
        .map(|s| s.as_str())
        .collect();

    // Verify transforms include enveloped-signature and exc-c14n (warn if missing)
    if let Some(transforms) = transforms_node {
        let algorithms: Vec<&str> = transforms
            .children()
            .filter(|n| n.has_tag_name((NS_DS, "Transform")))
            .filter_map(|n| n.attribute("Algorithm"))
            .collect();
        if !algorithms.contains(&TRANSFORM_EXC_C14N) {
            tracing::warn!(
                "Signature transforms do not include exc-c14n; \
                 canonicalization may produce unexpected results"
            );
        }
        if !algorithms.contains(&TRANSFORM_ENVELOPED) {
            tracing::warn!("Signature transforms do not include enveloped-signature transform");
        }
    }

    // Step 5: Canonicalize the signed element (enveloped-signature: exclude Signature subtree)
    let canonical_element = c14n_excluding_signature(signed_element, sig_node, &inclusive_prefixes);

    // Step 6: Compute SHA-256 digest and compare with <ds:DigestValue>
    let digest_value_b64 = find_child_element(reference_node, NS_DS, "DigestValue")
        .and_then(|n| n.text())
        .ok_or_else(|| SignatureError::Other("missing DigestValue".to_string()))?;

    let expected_digest = BASE64_STANDARD
        .decode(digest_value_b64.trim())
        .map_err(|e| SignatureError::Other(format!("invalid DigestValue base64: {e}")))?;

    let actual_digest = digest::digest(&digest::SHA256, canonical_element.as_bytes());
    if actual_digest.as_ref() != expected_digest.as_slice() {
        return Err(SignatureError::DigestMismatch);
    }

    // Step 7: Canonicalize <ds:SignedInfo>
    let signed_info_node = find_child_element(sig_node, NS_DS, "SignedInfo")
        .ok_or_else(|| SignatureError::Other("missing SignedInfo element".to_string()))?;

    // Extract InclusiveNamespaces from CanonicalizationMethod for SignedInfo c14n
    let c14n_method = find_child_element(signed_info_node, NS_DS, "CanonicalizationMethod");
    let si_prefixes_owned = extract_inclusive_prefixes(c14n_method);
    let si_prefixes: Vec<&str> = si_prefixes_owned.iter().map(|s| s.as_str()).collect();

    let canonical_signed_info = c14n::exclusive_c14n(signed_info_node, &si_prefixes);

    // Step 8: Extract <ds:SignatureValue>
    let sig_value_b64 = find_child_element(sig_node, NS_DS, "SignatureValue")
        .and_then(|n| n.text())
        .ok_or_else(|| SignatureError::Other("missing SignatureValue".to_string()))?;

    let sig_bytes = BASE64_STANDARD
        .decode(
            sig_value_b64
                .split_whitespace()
                .collect::<String>()
                .as_str(),
        )
        .map_err(|e| SignatureError::Other(format!("invalid SignatureValue base64: {e}")))?;

    // Determine signature algorithm
    let sig_algorithm = find_child_element(signed_info_node, NS_DS, "SignatureMethod")
        .and_then(|n| n.attribute("Algorithm"))
        .ok_or_else(|| SignatureError::Other("missing SignatureMethod Algorithm".to_string()))?;

    // Step 9: Verify signature against each certificate
    verify_signature_with_certs(
        sig_algorithm,
        &sig_bytes,
        canonical_signed_info.as_bytes(),
        signing_certificates,
    )?;

    // XSW mitigation: return the ID so callers re-resolve by ID, not cached node
    Ok(SignedElementId(element_id.to_string()))
}

// ============================================================================
// Internal helpers
// ============================================================================

/// SAML 2.0 protocol namespace.
const NS_SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

/// SAML 2.0 assertion namespace.
const NS_SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

/// Find a `<ds:Signature>` that is a direct child of a SAML Response or Assertion.
///
/// Scoping the search prevents an attacker from injecting a valid Signature
/// elsewhere in the document tree (e.g., inside an unsigned extension element).
fn find_saml_signature<'a, 'input>(
    doc: &'a roxmltree::Document<'input>,
) -> Option<roxmltree::Node<'a, 'input>> {
    // Check direct children of the document root element (Response)
    let root_element = doc.root().children().find(|n| n.is_element())?;
    if let Some(sig) = root_element
        .children()
        .find(|n| n.has_tag_name((NS_DS, "Signature")))
    {
        return Some(sig);
    }
    // Check direct children of Assertion elements (Response-child Assertions)
    for child in root_element.children() {
        if (child.has_tag_name((NS_SAML, "Assertion"))
            || child.has_tag_name((NS_SAMLP, "Response")))
            && let Some(sig) = child
                .children()
                .find(|n| n.has_tag_name((NS_DS, "Signature")))
        {
            return Some(sig);
        }
    }
    None
}

/// Find a direct child element matching the given namespace+local-name.
fn find_child_element<'a, 'input>(
    parent: roxmltree::Node<'a, 'input>,
    namespace: &str,
    local_name: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    parent
        .children()
        .find(|n| n.has_tag_name((namespace, local_name)))
}

/// Find an element whose `ID` attribute (case-sensitive) matches the given value.
///
/// Searches by common SAML ID attribute names: `ID`, `Id`, `id`.
///
/// This is the XML Signature Wrapping mitigation's identity function, so both
/// halves of it must resolve identically: `verify_xml_signature` uses it to find
/// the `Reference URI` target before verifying, and `response.rs` uses it again
/// afterwards to re-resolve the element it consumes. Two copies that drift would
/// silently turn that second lookup into a different element.
pub(super) fn find_element_by_id<'a, 'input>(
    doc: &'a roxmltree::Document<'input>,
    id: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    doc.root().descendants().find(|n| {
        n.is_element()
            && (n.attribute("ID") == Some(id)
                || n.attribute("Id") == Some(id)
                || n.attribute("id") == Some(id))
    })
}

/// Extract the `InclusiveNamespaces PrefixList` from a transform or c14n method node.
///
/// Returns an empty vec if no `<ec:InclusiveNamespaces PrefixList="...">` child
/// is present. Splits the `PrefixList` attribute on whitespace.
fn extract_inclusive_prefixes(parent: Option<roxmltree::Node<'_, '_>>) -> Vec<String> {
    let Some(parent) = parent else {
        return Vec::new();
    };
    for child in parent.children() {
        if child.has_tag_name((NS_EC, "InclusiveNamespaces"))
            && let Some(prefix_list) = child.attribute("PrefixList")
        {
            return prefix_list.split_whitespace().map(str::to_string).collect();
        }
    }
    Vec::new()
}

/// Canonicalize a signed element, skipping the `<ds:Signature>` subtree.
///
/// Implements the enveloped-signature transform: the Signature element and all
/// its children are excluded from canonicalization.
///
/// This is done by building the canonical form of the element manually,
/// excluding the Signature node. Because `c14n::exclusive_c14n` recurses through
/// children, we instead canonicalize a reconstructed subtree string without
/// the Signature child.
///
/// Implementation approach: serialize the canonical form character by character,
/// delegating to `c14n::exclusive_c14n` for the element but we need a way to
/// exclude the Signature. We use the document's canonical representation and
/// surgically remove the Signature subtree.
///
/// Actually the simplest correct approach for enveloped-signature transform is:
/// canonicalize the element but when recursing, skip the Signature element.
/// Since `c14n::exclusive_c14n` doesn't have that hook, we canonicalize without
/// the signature by parsing a modified version of the document.
fn c14n_excluding_signature(
    signed_element: roxmltree::Node<'_, '_>,
    sig_node: roxmltree::Node<'_, '_>,
    inclusive_prefixes: &[&str],
) -> String {
    // Build canonical form by iterating children and excluding the Signature.
    // We need to produce the canonical opening tag of signed_element, then
    // recurse into children (skipping sig_node), then close.
    //
    // The cleanest approach: serialize the signed_element to XML without the
    // Signature subtree, then parse that and canonicalize it. The serialization
    // copies namespace declarations down from ancestors so the fragment stands
    // alone as a well-formed document.
    let mut xml_without_sig = String::with_capacity(4096);
    serialize_node_excl(&mut xml_without_sig, signed_element, sig_node.id());

    let doc = match roxmltree::Document::parse(&xml_without_sig) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("Failed to reparse element for c14n (enveloped-sig): {e}");
            // Fall back to full c14n (less secure but prevents crash)
            return c14n::exclusive_c14n(signed_element, inclusive_prefixes);
        }
    };

    if let Some(root_elem) = doc.root().children().find(|n| n.is_element()) {
        c14n::exclusive_c14n(root_elem, inclusive_prefixes)
    } else {
        String::new()
    }
}

/// Recursively serialize a node, skipping the node with the given ID.
fn serialize_node_excl(
    out: &mut String,
    node: roxmltree::Node<'_, '_>,
    exclude_id: roxmltree::NodeId,
) {
    if node.id() == exclude_id {
        return;
    }

    if node.is_element() {
        // Opening tag
        out.push('<');
        let qname = element_qname(node);
        out.push_str(&qname);

        // Emit ALL namespace declarations visible on this node
        for ns in node.namespaces() {
            let prefix = ns.name().unwrap_or("");
            let uri = ns.uri();
            if prefix.is_empty() {
                out.push_str(" xmlns=\"");
                out.push_str(&xml_escape_attr_str(uri));
                out.push('"');
            } else {
                out.push_str(" xmlns:");
                out.push_str(prefix);
                out.push_str("=\"");
                out.push_str(&xml_escape_attr_str(uri));
                out.push('"');
            }
        }

        // Emit attributes (skip xmlns declarations, already handled above)
        for attr in node.attributes() {
            let attr_ns = attr.namespace().unwrap_or("");
            if attr_ns == "http://www.w3.org/2000/xmlns/" {
                continue;
            }
            out.push(' ');
            if !attr_ns.is_empty() && attr_ns != "http://www.w3.org/XML/1998/namespace" {
                // Find the prefix for this attribute's namespace
                if let Some(prefix) = find_ns_prefix(node, attr_ns)
                    && !prefix.is_empty()
                {
                    out.push_str(prefix);
                    out.push(':');
                }
            } else if attr_ns == "http://www.w3.org/XML/1998/namespace" {
                out.push_str("xml:");
            }
            out.push_str(attr.name());
            out.push_str("=\"");
            out.push_str(&xml_escape_attr_str(attr.value()));
            out.push('"');
        }
        out.push('>');

        // Recurse into children
        for child in node.children() {
            if child.id() == exclude_id {
                continue;
            }
            if child.is_element() {
                serialize_node_excl(out, child, exclude_id);
            } else if child.is_text()
                && let Some(text) = child.text()
            {
                out.push_str(&xml_escape_text_str(text));
            }
        }

        // Closing tag
        out.push_str("</");
        out.push_str(&qname);
        out.push('>');
    }
}

/// Return the qualified element name (`prefix:local` or just `local`).
fn element_qname(node: roxmltree::Node<'_, '_>) -> String {
    let local = node.tag_name().name();
    let ns_uri = match node.tag_name().namespace() {
        Some(u) if !u.is_empty() => u,
        _ => return local.to_string(),
    };
    if let Some(prefix) = find_ns_prefix(node, ns_uri) {
        if prefix.is_empty() {
            local.to_string()
        } else {
            format!("{prefix}:{local}")
        }
    } else {
        local.to_string()
    }
}

/// Find the namespace prefix for a given URI by searching this node and ancestors.
fn find_ns_prefix<'a>(node: roxmltree::Node<'_, 'a>, uri: &str) -> Option<&'a str> {
    let mut current = Some(node);
    while let Some(n) = current {
        for ns in n.namespaces() {
            if ns.uri() == uri {
                return Some(ns.name().unwrap_or(""));
            }
        }
        current = n.parent();
    }
    None
}

/// Escape a string for XML text content.
fn xml_escape_text_str(s: &str) -> String {
    c14n::escape_text(s)
}

/// Escape a string for XML attribute values.
fn xml_escape_attr_str(s: &str) -> String {
    c14n::escape_attribute(s)
}

/// Verify the signature bytes over the signed_info bytes using the provided certificates.
///
/// Tries each certificate in order. Returns `Ok(())` on first success.
/// Returns `SignatureError::NoCertificateMatch` if no certificate matches.
fn verify_signature_with_certs(
    algorithm_uri: &str,
    sig_bytes: &[u8],
    signed_info_bytes: &[u8],
    signing_certificates: &[Vec<u8>],
) -> Result<(), SignatureError> {
    if signing_certificates.is_empty() {
        return Err(SignatureError::NoCertificateMatch);
    }

    for cert_der in signing_certificates {
        match try_verify_with_cert(algorithm_uri, sig_bytes, signed_info_bytes, cert_der) {
            Ok(()) => return Ok(()),
            Err(SignatureError::SignatureInvalid) => continue,
            Err(SignatureError::NoCertificateMatch) => continue,
            Err(e) => return Err(e),
        }
    }

    Err(SignatureError::NoCertificateMatch)
}

/// Attempt to verify a signature using a single DER-encoded X.509 certificate.
fn try_verify_with_cert(
    algorithm_uri: &str,
    sig_bytes: &[u8],
    message: &[u8],
    cert_der: &[u8],
) -> Result<(), SignatureError> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| SignatureError::Other(format!("certificate parse error: {e}")))?;

    // Extract SubjectPublicKeyInfo (SPKI) bytes for aws-lc-rs
    let spki_der = der::Encode::to_der(&cert.tbs_certificate.subject_public_key_info)
        .map_err(|e| SignatureError::Other(format!("SPKI encode error: {e}")))?;

    // Parse SPKI to get the raw public key bit string
    let spki = spki::SubjectPublicKeyInfoRef::from_der(&spki_der)
        .map_err(|e| SignatureError::Other(format!("SPKI parse error: {e}")))?;
    let pk_bytes = spki.subject_public_key.raw_bytes();

    if algorithm_uri == SIG_RSA_SHA256 {
        let pk =
            signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, pk_bytes);
        pk.verify(message, sig_bytes)
            .map_err(|_| SignatureError::SignatureInvalid)
    } else if algorithm_uri == SIG_ECDSA_SHA256 {
        let pk = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, pk_bytes);
        pk.verify(message, sig_bytes)
            .map_err(|_| SignatureError::SignatureInvalid)
    } else {
        Err(SignatureError::UnsupportedAlgorithm(
            algorithm_uri.to_string(),
        ))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: panic on assertion failure is acceptable"
    )]
    use super::*;

    // =========================================================================
    // Reference URI validation tests
    // =========================================================================

    #[test]
    fn empty_ref_uri_is_rejected() {
        // Build minimal XML with empty Reference URI
        let xml = r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                         xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                         ID="_response1">
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>abc=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>sig=</ds:SignatureValue>
  </ds:Signature>
</samlp:Response>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let err = verify_xml_signature(&doc, &[]).unwrap_err();
        assert!(
            matches!(err, SignatureError::InvalidReference(_)),
            "Expected InvalidReference for empty URI, got: {err}"
        );
    }

    #[test]
    fn missing_hash_prefix_is_rejected() {
        let xml = r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                         xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                         ID="_response1">
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="response1">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>abc=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>sig=</ds:SignatureValue>
  </ds:Signature>
</samlp:Response>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let err = verify_xml_signature(&doc, &[]).unwrap_err();
        assert!(
            matches!(err, SignatureError::InvalidReference(_)),
            "Expected InvalidReference for URI without '#', got: {err}"
        );
    }

    #[test]
    fn referenced_element_not_found_returns_error() {
        let xml = r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                         xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                         ID="_response1">
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#nonexistent">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>abc=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>sig=</ds:SignatureValue>
  </ds:Signature>
</samlp:Response>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let err = verify_xml_signature(&doc, &[]).unwrap_err();
        assert!(
            matches!(err, SignatureError::ReferencedElementNotFound(_)),
            "Expected ReferencedElementNotFound, got: {err}"
        );
    }

    #[test]
    fn multiple_references_rejected() {
        let xml = r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                         xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                         ID="_response1">
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#_response1">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>abc=</ds:DigestValue>
      </ds:Reference>
      <ds:Reference URI="#_assertion1">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>def=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>sig=</ds:SignatureValue>
  </ds:Signature>
</samlp:Response>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let err = verify_xml_signature(&doc, &[]).unwrap_err();
        assert!(
            matches!(err, SignatureError::Other(ref msg) if msg.contains("multiple Reference")),
            "Expected rejection of multiple References, got: {err}"
        );
    }

    #[test]
    fn no_signature_element_returns_error() {
        let xml = r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                         ID="_response1">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  ID="_assertion1">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
  </saml:Assertion>
</samlp:Response>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let err = verify_xml_signature(&doc, &[]).unwrap_err();
        assert!(
            matches!(err, SignatureError::NoSignature),
            "Expected NoSignature, got: {err}"
        );
    }

    // =========================================================================
    // Algorithm parsing tests
    // =========================================================================

    #[test]
    fn unsupported_algorithm_returns_error() {
        // Construct a scenario where signature verification is attempted with
        // a known cert but unsupported algorithm
        let result = try_verify_with_cert(
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1",
            b"sig",
            b"message",
            // Build a minimal DER cert to trigger algorithm check
            &minimal_test_cert_der(),
        );
        assert!(
            matches!(result, Err(SignatureError::UnsupportedAlgorithm(_))),
            "Expected UnsupportedAlgorithm, got: {result:?}"
        );
    }

    // =========================================================================
    // Error type construction tests
    // =========================================================================

    #[test]
    fn error_types_display_correctly() {
        let e = SignatureError::NoSignature;
        assert!(e.to_string().contains("Signature"));

        let e = SignatureError::InvalidReference("bad uri".to_string());
        assert!(e.to_string().contains("bad uri"));

        let e = SignatureError::ReferencedElementNotFound("_id".to_string());
        assert!(e.to_string().contains("_id"));

        let e = SignatureError::DigestMismatch;
        assert!(e.to_string().contains("digest"));

        let e = SignatureError::SignatureInvalid;
        assert!(e.to_string().contains("signature"));

        let e = SignatureError::NoCertificateMatch;
        assert!(e.to_string().contains("certificate"));

        let e = SignatureError::UnsupportedAlgorithm("foo".to_string());
        assert!(e.to_string().contains("foo"));
    }

    // =========================================================================
    // find_element_by_id tests
    // =========================================================================

    #[test]
    fn find_element_by_id_finds_by_id_attribute() {
        let xml = r##"<root><child ID="_test123"/></root>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let elem = find_element_by_id(&doc, "_test123");
        assert!(elem.is_some(), "Should find element by ID attribute");
    }

    #[test]
    fn find_element_by_id_returns_none_for_missing() {
        let xml = r##"<root><child ID="_test123"/></root>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let elem = find_element_by_id(&doc, "_missing");
        assert!(elem.is_none(), "Should return None for missing ID");
    }

    // =========================================================================
    // inclusive prefixes extraction tests
    // =========================================================================

    #[test]
    fn extract_inclusive_prefixes_from_transform() {
        let xml = r##"<ds:Transform xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                         xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
                         Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
  <ec:InclusiveNamespaces PrefixList="#default saml ds xs xsi"/>
</ds:Transform>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let transform = doc.root().children().find(|n| n.is_element()).unwrap();
        let prefixes = extract_inclusive_prefixes(Some(transform));
        assert_eq!(prefixes, vec!["#default", "saml", "ds", "xs", "xsi"]);
    }

    #[test]
    fn extract_inclusive_prefixes_returns_empty_when_absent() {
        let xml = r##"<ds:Transform xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                         Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        "##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let transform = doc.root().children().find(|n| n.is_element()).unwrap();
        let prefixes = extract_inclusive_prefixes(Some(transform));
        assert!(prefixes.is_empty());
    }

    // =========================================================================
    // Helper for generating a minimal DER certificate (RSA)
    // =========================================================================

    /// Build a minimal (invalid but parseable) self-signed X.509 certificate DER.
    /// Used purely to trigger code paths that need a Certificate object.
    fn minimal_test_cert_der() -> Vec<u8> {
        // Use the same approach as attestation_chain.rs tests
        let key_pair = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        build_self_signed_der(&key_pair)
    }

    fn build_self_signed_der(key_pair: &aws_lc_rs::rsa::KeyPair) -> Vec<u8> {
        use aws_lc_rs::signature::KeyPair;
        let alg_oid = &[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
        ];
        let alg_params = &[0x05, 0x00];
        let alg_id = der_sequence(&[alg_oid, alg_params]);
        let version = &[0xa0, 0x03, 0x02, 0x01, 0x02];
        let serial = der_integer(&[0x01]);
        let cn_oid = &[0x06, 0x03, 0x55, 0x04, 0x03];
        let cn_value = &[0x0c, 0x04, b'T', b'e', b's', b't'];
        let attr_type_and_value = der_sequence(&[cn_oid, cn_value]);
        let rdn_set = der_set(&[&attr_type_and_value]);
        let name = der_sequence(&[&rdn_set]);
        let not_before: &[u8] = b"\x17\x0d240101000000Z";
        let not_after: &[u8] = b"\x17\x0d490101000000Z";
        let validity = der_sequence(&[not_before, not_after]);
        let pk_der = key_pair.public_key().as_ref();
        let spki = der_sequence(&[&alg_id, &der_bit_string(pk_der)]);
        let tbs = der_sequence(&[version, &serial, &alg_id, &name, &validity, &name, &spki]);
        let mut sig_buf = vec![0u8; key_pair.public_modulus_len()];
        let rng = aws_lc_rs::rand::SystemRandom::new();
        key_pair
            .sign(
                &aws_lc_rs::signature::RSA_PKCS1_SHA256,
                &rng,
                &tbs,
                &mut sig_buf,
            )
            .unwrap();
        let sig_bit_string = der_bit_string(&sig_buf);
        der_sequence(&[&tbs, &alg_id, &sig_bit_string])
    }

    fn der_sequence(items: &[&[u8]]) -> Vec<u8> {
        let content: Vec<u8> = items.iter().flat_map(|s| s.iter().copied()).collect();
        der_wrap(0x30, &content)
    }
    fn der_set(items: &[&[u8]]) -> Vec<u8> {
        let content: Vec<u8> = items.iter().flat_map(|s| s.iter().copied()).collect();
        der_wrap(0x31, &content)
    }
    fn der_integer(value: &[u8]) -> Vec<u8> {
        der_wrap(0x02, value)
    }
    fn der_bit_string(value: &[u8]) -> Vec<u8> {
        let mut content = vec![0x00];
        content.extend_from_slice(value);
        der_wrap(0x03, &content)
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "DER short-form length: each `as u8` is guarded by an explicit branch bound"
    )]
    fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
        let len = content.len();
        let mut out = vec![tag];
        if len < 0x80 {
            out.push(len as u8);
        } else if len < 0x100 {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push((len & 0xff) as u8);
        }
        out.extend_from_slice(content);
        out
    }

    // =========================================================================
    // Scoped signature search tests
    // =========================================================================

    #[test]
    fn deeply_nested_signature_not_found() {
        // Signature inside a nested element (not direct child of Response/Assertion)
        // should NOT be found by find_saml_signature
        let xml = r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                         xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                         xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                         ID="_response1">
  <saml:Assertion ID="_assertion1">
    <saml:Subject>
      <ds:Signature>
        <ds:SignedInfo>
          <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
          <ds:Reference URI="#_assertion1">
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <ds:DigestValue>abc=</ds:DigestValue>
          </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>sig=</ds:SignatureValue>
      </ds:Signature>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let err = verify_xml_signature(&doc, &[]).unwrap_err();
        assert!(
            matches!(err, SignatureError::NoSignature),
            "Expected NoSignature for deeply nested sig, got: {err}"
        );
    }
}
