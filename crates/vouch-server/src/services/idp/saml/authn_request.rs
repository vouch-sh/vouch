// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SAML 2.0 AuthnRequest generation.
//!
//! Generates AuthnRequest XML for SP-initiated SSO and encodes it for the
//! appropriate binding (HTTP-POST or HTTP-Redirect).
//!
//! Per SAML Bindings spec:
//! - HTTP-POST: base64-encode the raw XML into a form field
//! - HTTP-Redirect: DEFLATE-compress (raw, no zlib header), then base64-encode

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use flate2::Compression;
use flate2::write::DeflateEncoder;
use std::io::Write as _;

use super::SamlProvider;

// ============================================================================
// SAML URN constants
// ============================================================================

/// SAML 2.0 protocol namespace.
const NS_SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

/// SAML 2.0 assertion namespace.
const NS_SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

/// HTTP-POST binding URI.
const BINDING_HTTP_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

/// NameID format: emailAddress.
const NAMEID_FORMAT_EMAIL: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress";

// ============================================================================
// Public types
// ============================================================================

/// Result of building a SAML AuthnRequest.
#[derive(Debug)]
pub(crate) struct AuthnRequestResult {
    /// The SAML AuthnRequest ID (`_` + 32 hex chars). Used for `InResponseTo` validation.
    pub request_id: String,
    /// Encoded AuthnRequest XML: base64 for POST, DEFLATE+base64 for Redirect.
    pub encoded_request: String,
    /// IdP SSO endpoint URL.
    pub sso_url: String,
    /// `true` if using HTTP-POST binding, `false` if using HTTP-Redirect.
    pub is_post_binding: bool,
}

/// Errors during AuthnRequest generation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AuthnRequestError {
    /// Failed to generate random bytes for the request ID.
    #[error("failed to generate random request ID: {0}")]
    RandomId(String),
    /// DEFLATE compression failed.
    #[error("DEFLATE compression failed: {0}")]
    Deflate(String),
    /// No SSO URL is configured in the IdP metadata.
    #[error("no SSO URL configured in IdP metadata")]
    NoSsoUrl,
}

// ============================================================================
// Public API
// ============================================================================

/// Build a SAML AuthnRequest for the given provider.
///
/// Selects the binding (HTTP-POST preferred, HTTP-Redirect as fallback) based
/// on the IdP metadata. Returns the encoded request, SSO URL, and the request
/// ID needed for `InResponseTo` validation.
///
/// # Errors
///
/// Returns `AuthnRequestError` if random ID generation fails, DEFLATE
/// compression fails (Redirect binding only), or no SSO URL is configured.
pub(crate) fn build_authn_request(
    provider: &SamlProvider,
) -> Result<AuthnRequestResult, AuthnRequestError> {
    let request_id = generate_request_id()?;
    let issue_instant = current_utc_iso8601();

    let xml = build_xml(
        &request_id,
        &issue_instant,
        &provider.sp_entity_id,
        &provider.acs_url,
        provider
            .idp_metadata
            .sso_post_url
            .as_deref()
            .or(provider.idp_metadata.sso_redirect_url.as_deref())
            .ok_or(AuthnRequestError::NoSsoUrl)?,
    );

    if let Some(sso_url) = &provider.idp_metadata.sso_post_url {
        // HTTP-POST binding: base64-encode raw XML
        let encoded = BASE64_STANDARD.encode(xml.as_bytes());
        Ok(AuthnRequestResult {
            request_id,
            encoded_request: encoded,
            sso_url: sso_url.clone(),
            is_post_binding: true,
        })
    } else if let Some(sso_url) = &provider.idp_metadata.sso_redirect_url {
        // HTTP-Redirect binding: raw DEFLATE (no zlib header) then base64
        let deflated = deflate_raw(&xml)?;
        let encoded = BASE64_STANDARD.encode(&deflated);
        Ok(AuthnRequestResult {
            request_id,
            encoded_request: encoded,
            sso_url: sso_url.clone(),
            is_post_binding: false,
        })
    } else {
        Err(AuthnRequestError::NoSsoUrl)
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Generate a SAML request ID: `_` + 32 lowercase hex characters.
///
/// The `_` prefix ensures the ID is a valid XML NCName. SAML IDs may not
/// start with a digit.
fn generate_request_id() -> Result<String, AuthnRequestError> {
    let mut bytes = [0u8; 16];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|e| AuthnRequestError::RandomId(e.to_string()))?;
    let hex: String = bytes.iter().fold(String::with_capacity(32), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    });
    Ok(format!("_{hex}"))
}

/// Return the current UTC time formatted as ISO 8601 (`YYYY-MM-DDTHH:MM:SSZ`).
fn current_utc_iso8601() -> String {
    use jiff::Timestamp;
    let now = Timestamp::now();
    // Format: 2026-03-19T12:34:56Z
    now.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Build the AuthnRequest XML string.
///
/// All dynamic values are XML-attribute-escaped before insertion.
fn build_xml(
    request_id: &str,
    issue_instant: &str,
    sp_entity_id: &str,
    acs_url: &str,
    destination: &str,
) -> String {
    let escaped_id = xml_escape_attr(request_id);
    let escaped_instant = xml_escape_attr(issue_instant);
    let escaped_destination = xml_escape_attr(destination);
    let escaped_issuer = xml_escape_attr(sp_entity_id);
    let escaped_acs_url = xml_escape_attr(acs_url);

    // ProtocolBinding specifies how the IdP should send the response back (always HTTP-POST).
    // This is independent of which binding we use to send the AuthnRequest.
    format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<samlp:AuthnRequest"#,
            r#" xmlns:samlp="{ns_samlp}""#,
            r#" xmlns:saml="{ns_saml}""#,
            r#" ID="{id}""#,
            r#" Version="2.0""#,
            r#" IssueInstant="{instant}""#,
            r#" Destination="{destination}""#,
            r#" ProtocolBinding="{binding}""#,
            r#" AssertionConsumerServiceURL="{acs_url}">"#,
            r#"<saml:Issuer>{issuer}</saml:Issuer>"#,
            r#"<samlp:NameIDPolicy Format="{nameid_format}" AllowCreate="true"/>"#,
            r#"</samlp:AuthnRequest>"#,
        ),
        ns_samlp = NS_SAMLP,
        ns_saml = NS_SAML,
        id = escaped_id,
        instant = escaped_instant,
        destination = escaped_destination,
        binding = BINDING_HTTP_POST,
        acs_url = escaped_acs_url,
        issuer = escaped_issuer,
        nameid_format = NAMEID_FORMAT_EMAIL,
    )
}

/// Raw DEFLATE compression (no zlib header/trailer), as required by SAML HTTP-Redirect binding.
fn deflate_raw(input: &str) -> Result<Vec<u8>, AuthnRequestError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(input.as_bytes())
        .map_err(|e| AuthnRequestError::Deflate(e.to_string()))?;
    encoder
        .finish()
        .map_err(|e| AuthnRequestError::Deflate(e.to_string()))
}

/// Escape a string for use as an XML attribute value (double-quoted).
fn xml_escape_attr(s: &str) -> String {
    super::c14n::escape_attribute(s)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::services::idp::saml::{IdpMetadata, SamlProvider};
    use flate2::read::DeflateDecoder;
    use std::io::Read as _;

    fn make_provider(post_url: Option<&str>, redirect_url: Option<&str>) -> SamlProvider {
        SamlProvider {
            idp_metadata: IdpMetadata {
                entity_id: "https://idp.example.com".to_string(),
                sso_post_url: post_url.map(str::to_string),
                sso_redirect_url: redirect_url.map(str::to_string),
                signing_certificates: vec![],
            },
            sp_entity_id: "https://vouch.example.com".to_string(),
            acs_url: "https://vouch.example.com/saml/acs".to_string(),
            email_attribute: None,
            domain_attribute: None,
        }
    }

    #[test]
    fn request_id_starts_with_underscore() {
        let id = generate_request_id().unwrap();
        assert!(id.starts_with('_'), "Request ID must start with '_': {id}");
    }

    #[test]
    fn request_id_is_ncname_valid() {
        let id = generate_request_id().unwrap();
        // NCName: starts with letter or '_', followed by letters, digits, '.', '-', '_'
        assert!(id.starts_with('_'), "Must start with '_': {id}");
        assert!(
            id.chars().skip(1).all(|c| c.is_ascii_hexdigit()),
            "Remaining chars must be hex: {id}"
        );
        assert_eq!(id.len(), 33, "ID must be '_' + 32 hex chars: {id}");
    }

    #[test]
    fn two_calls_produce_different_ids() {
        let id1 = generate_request_id().unwrap();
        let id2 = generate_request_id().unwrap();
        assert_ne!(id1, id2, "Each call must produce a unique ID");
    }

    #[test]
    fn generated_xml_is_parseable() {
        let provider = make_provider(Some("https://idp.example.com/sso"), None);
        let result = build_authn_request(&provider).unwrap();
        // Decode the base64 back to XML
        let xml_bytes = BASE64_STANDARD.decode(&result.encoded_request).unwrap();
        let xml = std::str::from_utf8(&xml_bytes).unwrap();
        let doc = roxmltree::Document::parse(xml);
        assert!(doc.is_ok(), "Generated XML must be parseable: {xml}");
    }

    #[test]
    fn generated_xml_contains_required_fields() {
        let provider = make_provider(Some("https://idp.example.com/sso"), None);
        let result = build_authn_request(&provider).unwrap();
        let xml_bytes = BASE64_STANDARD.decode(&result.encoded_request).unwrap();
        let xml = std::str::from_utf8(&xml_bytes).unwrap();

        assert!(
            xml.contains(&result.request_id),
            "XML must contain request ID: {xml}"
        );
        assert!(
            xml.contains("https://vouch.example.com/saml/acs"),
            "XML must contain ACS URL: {xml}"
        );
        assert!(
            xml.contains("https://vouch.example.com"),
            "XML must contain issuer (SP entity ID): {xml}"
        );
        assert!(
            xml.contains(BINDING_HTTP_POST),
            "XML must contain ProtocolBinding (HTTP-POST): {xml}"
        );
        assert!(
            xml.contains(NAMEID_FORMAT_EMAIL),
            "XML must contain NameID format emailAddress: {xml}"
        );
    }

    #[test]
    fn post_binding_uses_standard_base64() {
        let provider = make_provider(Some("https://idp.example.com/sso"), None);
        let result = build_authn_request(&provider).unwrap();
        assert!(result.is_post_binding, "Should use POST binding");
        // Standard base64 (not URL-safe): may contain +, /, = padding
        // Verify it decodes correctly with STANDARD engine
        let decoded = BASE64_STANDARD.decode(&result.encoded_request);
        assert!(decoded.is_ok(), "POST binding must produce valid base64");
    }

    #[test]
    fn redirect_binding_produces_deflate_base64() {
        let provider = make_provider(None, Some("https://idp.example.com/sso"));
        let result = build_authn_request(&provider).unwrap();
        assert!(!result.is_post_binding, "Should use Redirect binding");

        // Decode standard base64
        let deflated = BASE64_STANDARD
            .decode(&result.encoded_request)
            .expect("Must be valid base64");

        // Decompress raw DEFLATE
        let mut decoder = DeflateDecoder::new(deflated.as_slice());
        let mut xml = String::new();
        decoder.read_to_string(&mut xml).expect("Must decompress");

        // Verify it's valid XML
        let doc = roxmltree::Document::parse(&xml);
        assert!(doc.is_ok(), "Decompressed XML must be parseable: {xml}");
    }

    #[test]
    fn post_binding_preferred_over_redirect() {
        let provider = make_provider(
            Some("https://idp.example.com/sso/post"),
            Some("https://idp.example.com/sso/redirect"),
        );
        let result = build_authn_request(&provider).unwrap();
        assert!(result.is_post_binding, "POST binding must be preferred");
        assert_eq!(result.sso_url, "https://idp.example.com/sso/post");
    }

    #[test]
    fn no_sso_url_returns_error() {
        let provider = make_provider(None, None);
        let err = build_authn_request(&provider).unwrap_err();
        assert!(
            matches!(err, AuthnRequestError::NoSsoUrl),
            "Expected NoSsoUrl: {err}"
        );
    }

    #[test]
    fn request_id_matches_xml_id_attribute() {
        let provider = make_provider(Some("https://idp.example.com/sso"), None);
        let result = build_authn_request(&provider).unwrap();
        let xml_bytes = BASE64_STANDARD.decode(&result.encoded_request).unwrap();
        let xml = std::str::from_utf8(&xml_bytes).unwrap();
        let doc = roxmltree::Document::parse(xml).unwrap();
        let authn_req = doc
            .root()
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "AuthnRequest")
            .expect("AuthnRequest element must exist");
        let id_attr = authn_req.attribute("ID").expect("ID attribute must exist");
        assert_eq!(
            id_attr, result.request_id,
            "XML ID must match result.request_id"
        );
    }
}
