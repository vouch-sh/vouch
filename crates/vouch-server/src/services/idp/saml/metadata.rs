// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SAML IdP metadata parsing and SP metadata generation.
//!
//! Parses IdP metadata XML (fetched at startup) using `roxmltree`. Extracts
//! entity ID, SSO endpoints (HTTP-POST and HTTP-Redirect bindings), and
//! signing certificates. Also generates SP metadata XML for `/saml/metadata`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

/// Maximum size for IdP metadata documents (1 MiB).
///
/// Federation metadata (EntitiesDescriptor) can be very large. Reject
/// oversized documents to avoid OOM during parsing.
const MAX_METADATA_SIZE: usize = 1024 * 1024;

/// SAML 2.0 Metadata namespace.
const NS_MD: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
/// XML Digital Signature namespace.
const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// SAML HTTP-POST binding URI.
const BINDING_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
/// SAML HTTP-Redirect binding URI.
const BINDING_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

/// Parsed identity provider metadata.
///
/// Extracted from the IdP's SAML metadata XML document.
/// At least one SSO URL (POST or Redirect) must be present.
#[derive(Debug, Clone)]
pub struct IdpMetadata {
    /// IdP entity ID from `EntityDescriptor@entityID`.
    pub entity_id: String,
    /// `SingleSignOnService` URL for HTTP-POST binding (preferred).
    pub sso_post_url: Option<String>,
    /// `SingleSignOnService` URL for HTTP-Redirect binding (fallback).
    pub sso_redirect_url: Option<String>,
    /// DER-encoded X.509 signing certificates from
    /// `KeyDescriptor[@use="signing"]` (or no `@use`).
    pub signing_certificates: Vec<Vec<u8>>,
}

/// Errors during IdP metadata parsing.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MetadataError {
    /// The metadata document exceeds the maximum allowed size.
    #[error("metadata document too large ({size} bytes, max {MAX_METADATA_SIZE})")]
    TooLarge {
        /// Actual document size in bytes.
        size: usize,
    },
    /// The XML could not be parsed.
    #[error("failed to parse metadata XML: {0}")]
    XmlParse(String),
    /// No `EntityDescriptor` element was found.
    #[error("missing EntityDescriptor element")]
    MissingEntityDescriptor,
    /// The `EntityDescriptor` has no `entityID` attribute.
    #[error("missing entityID attribute on EntityDescriptor")]
    MissingEntityId,
    /// No `SingleSignOnService` with a supported binding was found.
    #[error("no SingleSignOnService endpoint found (need HTTP-POST or HTTP-Redirect)")]
    NoSsoEndpoint,
    /// A signing certificate could not be decoded from base64.
    #[error("failed to decode signing certificate: {0}")]
    CertificateDecode(String),
}

/// Parse SAML IdP metadata XML.
///
/// Extracts entity ID, SSO endpoints (HTTP-POST and HTTP-Redirect bindings),
/// and signing certificates from the metadata document.
///
/// At least one SSO endpoint must be present. Certificates are base64-decoded
/// from `X509Certificate` elements under `KeyDescriptor[@use="signing"]` or
/// `KeyDescriptor` without a `@use` attribute (which means signing + encryption).
/// `KeyDescriptor[@use="encryption"]` certificates are skipped.
///
/// A `tracing::warn` is emitted if no signing certificates are found (some IdPs
/// publish metadata without certs during initial setup).
///
/// # Errors
///
/// Returns `MetadataError` if the XML is malformed, required elements are missing,
/// the document exceeds 1 MiB, or certificate base64 decoding fails.
pub(crate) fn parse_idp_metadata(xml: &str) -> Result<IdpMetadata, MetadataError> {
    // Size check before parsing to avoid OOM on large federation metadata.
    let size = xml.len();
    if size > MAX_METADATA_SIZE {
        return Err(MetadataError::TooLarge { size });
    }

    let doc =
        roxmltree::Document::parse(xml).map_err(|e| MetadataError::XmlParse(e.to_string()))?;

    // Find EntityDescriptor -- descendants() handles both a direct root and the
    // EntitiesDescriptor wrapper some federations use (ADFS, Shibboleth).
    let entity_descriptor = doc
        .root()
        .descendants()
        .find(|n| n.has_tag_name((NS_MD, "EntityDescriptor")))
        .ok_or(MetadataError::MissingEntityDescriptor)?;

    // Extract entityID attribute.
    let entity_id = entity_descriptor
        .attribute("entityID")
        .ok_or(MetadataError::MissingEntityId)?
        .to_string();

    // Find IDPSSODescriptor.
    let idp_descriptor = entity_descriptor
        .children()
        .find(|n| n.has_tag_name((NS_MD, "IDPSSODescriptor")));

    let mut sso_post_url: Option<String> = None;
    let mut sso_redirect_url: Option<String> = None;
    let mut signing_certificates: Vec<Vec<u8>> = Vec::new();

    if let Some(idp_desc) = idp_descriptor {
        // Extract SingleSignOnService endpoints.
        for child in idp_desc.children() {
            if child.has_tag_name((NS_MD, "SingleSignOnService")) {
                let binding = child.attribute("Binding").unwrap_or("");
                let location = child.attribute("Location").unwrap_or("");
                if binding == BINDING_POST && sso_post_url.is_none() {
                    sso_post_url = Some(location.to_string());
                } else if binding == BINDING_REDIRECT && sso_redirect_url.is_none() {
                    sso_redirect_url = Some(location.to_string());
                }
            }
        }

        // Extract signing certificates from KeyDescriptor elements.
        for child in idp_desc.children() {
            if child.has_tag_name((NS_MD, "KeyDescriptor")) {
                let use_attr = child.attribute("use");
                // Include if @use="signing" or @use is absent (means both signing and encryption).
                // Skip if @use="encryption".
                if let Some("encryption") = use_attr {
                    continue;
                }
                // Navigate: KeyDescriptor -> KeyInfo (NS_DS) -> X509Data (NS_DS) -> X509Certificate (NS_DS)
                for key_info in child.children() {
                    if !key_info.has_tag_name((NS_DS, "KeyInfo")) {
                        continue;
                    }
                    for x509_data in key_info.children() {
                        if !x509_data.has_tag_name((NS_DS, "X509Data")) {
                            continue;
                        }
                        for x509_cert_node in x509_data.children() {
                            if !x509_cert_node.has_tag_name((NS_DS, "X509Certificate")) {
                                continue;
                            }
                            let cert_text = super::c14n::element_text(x509_cert_node)
                                .unwrap_or_default()
                                // Strip whitespace (certs often have line breaks in metadata).
                                .split_whitespace()
                                .collect::<String>();
                            if cert_text.is_empty() {
                                continue;
                            }
                            let der = BASE64_STANDARD
                                .decode(&cert_text)
                                .map_err(|e| MetadataError::CertificateDecode(e.to_string()))?;
                            signing_certificates.push(der);
                        }
                    }
                }
            }
        }
    }

    // Validate at least one SSO URL.
    if sso_post_url.is_none() && sso_redirect_url.is_none() {
        return Err(MetadataError::NoSsoEndpoint);
    }

    // Metadata without signing certificates is accepted but unusable for
    // response verification, so surface it rather than failing the parse.
    if signing_certificates.is_empty() {
        tracing::warn!(
            entity_id,
            "IdP metadata contains no signing certificates. \
             Signature verification will fail when processing SAML responses."
        );
    }

    Ok(IdpMetadata {
        entity_id,
        sso_post_url,
        sso_redirect_url,
        signing_certificates,
    })
}

/// Generate SP metadata XML for the `/saml/metadata` endpoint.
///
/// Produces a minimal SAML 2.0 SP metadata document with the SP entity ID and
/// Assertion Consumer Service URL (HTTP-POST binding).
///
/// The output is valid XML with entity ID and ACS URL XML-attribute-escaped.
/// No SP metadata signing is included (optional per spec).
#[must_use]
pub(crate) fn generate_sp_metadata(sp_entity_id: &str, acs_url: &str) -> String {
    let escaped_entity_id = xml_escape_attr(sp_entity_id);
    let escaped_acs_url = xml_escape_attr(acs_url);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{escaped_entity_id}">
  <md:SPSSODescriptor
      AuthnRequestsSigned="false"
      WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{escaped_acs_url}"
        index="0"
        isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"#
    )
}

/// Escape a string for use as an XML attribute value (double-quoted).
///
/// Escapes: `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;`,
/// `\t` → `&#x9;`, `\n` → `&#xA;`, `\r` → `&#xD;`
fn xml_escape_attr(s: &str) -> String {
    // Reuse the c14n escape_attribute function which handles all required characters.
    super::c14n::escape_attribute(s)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: panic on assertion failure is acceptable"
    )]
    use super::*;

    // =========================================================================
    // parse_idp_metadata tests
    // =========================================================================

    const MINIMAL_METADATA: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://idp.example.com/saml">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>dGVzdC1jZXJ0LWRlci1ieXRlcw==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="https://idp.example.com/saml/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;

    #[test]
    fn minimal_valid_metadata() {
        let meta = parse_idp_metadata(MINIMAL_METADATA).unwrap();
        assert_eq!(meta.entity_id, "https://idp.example.com/saml");
        assert_eq!(
            meta.sso_post_url,
            Some("https://idp.example.com/saml/sso".to_string())
        );
        assert!(meta.sso_redirect_url.is_none());
        assert_eq!(meta.signing_certificates.len(), 1);
    }

    #[test]
    fn okta_style_metadata() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="http://www.okta.com/exk1abc123">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false"
                        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIC</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="https://dev-123.okta.com/app/example/sso/saml"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://dev-123.okta.com/app/example/sso/saml"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;
        let meta = parse_idp_metadata(xml).unwrap();
        assert_eq!(meta.entity_id, "http://www.okta.com/exk1abc123");
        assert_eq!(
            meta.sso_post_url,
            Some("https://dev-123.okta.com/app/example/sso/saml".to_string())
        );
        assert_eq!(
            meta.sso_redirect_url,
            Some("https://dev-123.okta.com/app/example/sso/saml".to_string())
        );
        assert_eq!(meta.signing_certificates.len(), 1);
    }

    #[test]
    fn entra_style_metadata_default_namespace() {
        // Entra uses default namespace (no md: prefix).
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="https://sts.windows.net/tenant-id/">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>MIIC</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>MIID</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                          Location="https://login.microsoftonline.com/tenant-id/saml2"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                          Location="https://login.microsoftonline.com/tenant-id/saml2"/>
  </IDPSSODescriptor>
</EntityDescriptor>"#;
        let meta = parse_idp_metadata(xml).unwrap();
        assert_eq!(meta.entity_id, "https://sts.windows.net/tenant-id/");
        assert_eq!(
            meta.sso_post_url,
            Some("https://login.microsoftonline.com/tenant-id/saml2".to_string())
        );
        assert_eq!(
            meta.sso_redirect_url,
            Some("https://login.microsoftonline.com/tenant-id/saml2".to_string())
        );
        assert_eq!(meta.signing_certificates.len(), 2);
    }

    #[test]
    fn google_workspace_metadata() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://accounts.google.com/o/saml2?idpid=C01abc">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false"
                        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIC</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="https://accounts.google.com/o/saml2/idp?idpid=C01abc"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://accounts.google.com/o/saml2/idp?idpid=C01abc"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;
        let meta = parse_idp_metadata(xml).unwrap();
        assert_eq!(
            meta.entity_id,
            "https://accounts.google.com/o/saml2?idpid=C01abc"
        );
        assert_eq!(
            meta.sso_post_url,
            Some("https://accounts.google.com/o/saml2/idp?idpid=C01abc".to_string())
        );
        assert_eq!(
            meta.sso_redirect_url,
            Some("https://accounts.google.com/o/saml2/idp?idpid=C01abc".to_string())
        );
        assert_eq!(meta.signing_certificates.len(), 1);
    }

    /// MockSAML (https://mocksaml.com/) metadata — a real public SAML 2.0 test IdP.
    /// This validates that our parser handles real-world metadata from a live service.
    #[test]
    fn mocksaml_public_idp_metadata() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://saml.example.com/entityid" validUntil="2036-03-19T22:20:14.943Z">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIC4jCCAcoCCQC33wnybT5QZDANBgkqhkiG9w0BAQsFADAyMQswCQYDVQQGEwJVSzEPMA0GA1UECgwGQm94eUhRMRIwEAYDVQQDDAlNb2NrIFNBTUwwIBcNMjIwMjI4MjE0NjM4WhgPMzAyMTA3MDEyMTQ2MzhaMDIxCzAJBgNVBAYTAlVLMQ8wDQYDVQQKDAZCb3h5SFExEjAQBgNVBAMMCU1vY2sgU0FNTDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALGfYettMsct1T6tVUwTudNJH5Pnb9GGnkXi9Zw/e6x45DD0RuRONbFlJ2T4RjAE/uG+AjXxXQ8o2SZfb9+GgmCHuTJFNgHoZ1nFVXCmb/Hg8Hpd4vOAGXndixaReOiq3EH5XvpMjMkJ3+8+9VYMzMZOjkgQtAqO36eAFFfNKX7dTj3VpwLkvz6/KFCq8OAwY+AUi4eZm5J57D31GzjHwfjH9WTeX0MyndmnNB1qV75qQR3b2/W5sGHRv+9AarggJkF+ptUkXoLtVA51wcfYm6hILptpde5FQC8RWY1YrswBWAEZNfyrR4JeSweElNHg4NVOs4TwGjOPwWGqzTfgTlECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAAYRlYflSXAWoZpFfwNiCQVE5d9zZ0DPzNdWhAybXcTyMf0z5mDf6FWBW5Gyoi9u3EMEDnzLcJNkwJAAc39Apa4I2/tml+Jy29dk8bTyX6m93ngmCgdLh5Za4khuU3AM3L63g7VexCuO7kwkjh/+LqdcIXsVGO6XDfu2QOs1Xpe9zIzLpwm/RNYeXUjbSj5ce/jekpAw7qyVVL4xOyh8AtUW1ek3wIw1MJvEgEPt0d16oshWJpoS1OT8Lr/22SvYEo3EmSGdTVGgk3x3s+A0qWAqTcyjr7Q4s/GKYRFfomGwz0TZ4Iw1ZN99Mm0eo2USlSRTVl7QHRTuiuSThHpLKQQ==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://mocksaml.com/api/saml/sso"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://mocksaml.com/api/saml/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;

        let meta = parse_idp_metadata(xml).unwrap();
        assert_eq!(meta.entity_id, "https://saml.example.com/entityid");
        assert_eq!(
            meta.sso_post_url.as_deref(),
            Some("https://mocksaml.com/api/saml/sso")
        );
        assert_eq!(
            meta.sso_redirect_url.as_deref(),
            Some("https://mocksaml.com/api/saml/sso")
        );
        assert_eq!(meta.signing_certificates.len(), 1);
        // Verify the certificate DER has reasonable size (not empty/truncated)
        let cert_len = meta.signing_certificates.first().map_or(0, Vec::len);
        assert!(
            cert_len > 100,
            "Certificate DER should be substantial, got {cert_len} bytes",
        );
    }

    /// SAMLtest.dev (https://www.samltest.dev/) metadata — a free test IdP service.
    /// Notable: POST and Redirect bindings use different URLs, and
    /// WantAuthnRequestsSigned is false (unlike MockSAML which requires it).
    #[test]
    fn samltest_dev_metadata() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor entityID="https://www.samltest.dev/apps/app_01km431zdf0fzkrx0qzkg9c4d0" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIDBzCCAe+gAwIBAgIUCLBK4f75EXEe4gyroYnVaqLoSp4wDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIZHVtbXlpZHAwHhcNMjQwNTEzMjE1NDE2WhcNMzQwNTExMjE1NDE2WjATMREwDwYDVQQDDAhkdW1teWlkcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKhmgQmWb8NvGhz952XY4SlJlpWIK72RilhOZS9frDYhqWVJHsGH9Z7sSzrM/0+YvCyEWuZV9gpMeIaHZxEPDqW3RJ7KG51fn/s/qFvwctf+CZDjyfGDzYs+XIgf7p56U48EmYeWpB/aUW64gSbnPqrtWmVFBisOfIx5aY3NubtTsn+g0XbdX0L57+NgSvPQHXh/GPXA7xCIWm54G5kqjozxbKEFA0DS3yb6oHRQWHqIAM/7mJMdUVZNIV1q7c2JIgAl23uDWq+2KTE2R5liP/KjvjwKonVKtTqGqX6ei25rsTHOaDpBH/LdQK2txgsm7R7+IThWNvUI0TttrmwBqyMCAwEAAaNTMFEwHQYDVR0OBBYEFD142gxIAJMhpgMkgpzmRNoW9XbEMB8GA1UdIwQYMBaAFD142gxIAJMhpgMkgpzmRNoW9XbEMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADQd6k6zFIc20GfGHY5C2MFwyGOmP5/UG/JiTq7Zky28G6D0NA0je+GztzXx7VYDfCfHxLcm2k5t9nYhb9kVawiLUUDVF6s+yZUXA4gUA3KoTWh1/oRxR3ggW7dKYm9fsNOdQAbxUUkzp7HLZ45ZlpKUS0hO7es+fPyF5KVw0g0SrtQWwWucnQMAQE9m+B0aOf+92y7JQkdgdR8Gd/XZ4NZfoOnKV7A1utT4rWxYCgICeRTHx9tly5OhPW4hQr5qOpngcsJ9vhr86IjznQXhfj3hql5lA3VbHW04ro37ROIkh2bShDq5dwJJHpYCGrF3MQv8S3m+jzGhYL6m9gFTm/8=</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://www.samltest.dev/apps/app_01km431zdf0fzkrx0qzkg9c4d0/sso"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://www.samltest.dev/apps/app_01km431zdf0fzkrx0qzkg9c4d0/login"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;

        let meta = parse_idp_metadata(xml).unwrap();
        assert_eq!(
            meta.entity_id,
            "https://www.samltest.dev/apps/app_01km431zdf0fzkrx0qzkg9c4d0"
        );
        // POST and Redirect bindings have DIFFERENT URLs (unlike MockSAML)
        assert_eq!(
            meta.sso_post_url.as_deref(),
            Some("https://www.samltest.dev/apps/app_01km431zdf0fzkrx0qzkg9c4d0/sso")
        );
        assert_eq!(
            meta.sso_redirect_url.as_deref(),
            Some("https://www.samltest.dev/apps/app_01km431zdf0fzkrx0qzkg9c4d0/login")
        );
        assert_eq!(meta.signing_certificates.len(), 1);
    }

    #[test]
    fn missing_sso_url_returns_error() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="https://idp.example.com">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;
        let err = parse_idp_metadata(xml).unwrap_err();
        assert!(
            matches!(err, MetadataError::NoSsoEndpoint),
            "Expected NoSsoEndpoint, got: {err}"
        );
    }

    #[test]
    fn redirect_only_metadata() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="https://idp.example.com">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://idp.example.com/saml/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;
        let meta = parse_idp_metadata(xml).unwrap();
        assert!(meta.sso_post_url.is_none());
        assert_eq!(
            meta.sso_redirect_url,
            Some("https://idp.example.com/saml/sso".to_string())
        );
    }

    #[test]
    fn keydescriptor_no_use_attribute_included() {
        // KeyDescriptor without @use means signing + encryption -- include it.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://idp.example.com">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor>
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIC</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="https://idp.example.com/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;
        let meta = parse_idp_metadata(xml).unwrap();
        assert_eq!(
            meta.signing_certificates.len(),
            1,
            "KeyDescriptor without @use should be included"
        );
    }

    #[test]
    fn keydescriptor_encryption_only_skipped() {
        // KeyDescriptor with @use="encryption" must be skipped.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://idp.example.com">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIC</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="https://idp.example.com/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;
        let meta = parse_idp_metadata(xml).unwrap();
        assert_eq!(
            meta.signing_certificates.len(),
            0,
            "KeyDescriptor with use=encryption should be skipped"
        );
    }

    #[test]
    fn entities_descriptor_wrapper() {
        // Some IdPs (ADFS, federations) wrap in EntitiesDescriptor.
        let xml = r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:EntityDescriptor entityID="https://idp.example.com">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                              Location="https://idp.example.com/sso"/>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>"#;
        let meta = parse_idp_metadata(xml).unwrap();
        assert_eq!(meta.entity_id, "https://idp.example.com");
        assert_eq!(
            meta.sso_post_url,
            Some("https://idp.example.com/sso".to_string())
        );
    }

    #[test]
    fn missing_entity_descriptor_returns_error() {
        let xml = r#"<?xml version="1.0"?><root/>"#;
        let err = parse_idp_metadata(xml).unwrap_err();
        assert!(
            matches!(err, MetadataError::MissingEntityDescriptor),
            "Expected MissingEntityDescriptor, got: {err}"
        );
    }

    #[test]
    fn invalid_xml_returns_error() {
        let err = parse_idp_metadata("<unclosed>").unwrap_err();
        assert!(
            matches!(err, MetadataError::XmlParse(_)),
            "Expected XmlParse, got: {err}"
        );
    }

    #[test]
    fn too_large_returns_error() {
        // Create a string larger than 1 MiB.
        let large = "x".repeat(MAX_METADATA_SIZE + 1);
        let err = parse_idp_metadata(&large).unwrap_err();
        assert!(
            matches!(err, MetadataError::TooLarge { .. }),
            "Expected TooLarge, got: {err}"
        );
    }

    /// Empty signing_certificates should trigger a tracing::warn but not fail.
    #[test]
    fn empty_signing_certificates_is_accepted_with_warning() {
        // No KeyDescriptor elements -- metadata is valid but no certs.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="https://idp.example.com">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="https://idp.example.com/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;
        // Should parse successfully (warn is emitted, not error).
        let meta = parse_idp_metadata(xml).unwrap();
        assert_eq!(meta.signing_certificates.len(), 0);
        assert_eq!(meta.entity_id, "https://idp.example.com");
    }

    #[test]
    fn invalid_base64_cert_returns_error() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://idp.example.com">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>!!!not-valid-base64!!!</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="https://idp.example.com/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;
        let err = parse_idp_metadata(xml).unwrap_err();
        assert!(
            matches!(err, MetadataError::CertificateDecode(_)),
            "Expected CertificateDecode, got: {err}"
        );
    }

    // =========================================================================
    // generate_sp_metadata tests
    // =========================================================================

    #[test]
    fn sp_metadata_generation_basic() {
        let xml = generate_sp_metadata(
            "https://vouch.example.com",
            "https://vouch.example.com/saml/acs",
        );
        assert!(
            xml.contains(r#"entityID="https://vouch.example.com""#),
            "Missing entityID: {xml}"
        );
        assert!(
            xml.contains(r#"WantAssertionsSigned="true""#),
            "Missing WantAssertionsSigned: {xml}"
        );
        assert!(
            xml.contains(r#"Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""#),
            "Missing Binding: {xml}"
        );
        assert!(
            xml.contains(r#"Location="https://vouch.example.com/saml/acs""#),
            "Missing Location: {xml}"
        );
    }

    #[test]
    fn sp_metadata_is_valid_xml() {
        let xml = generate_sp_metadata(
            "https://vouch.example.com",
            "https://vouch.example.com/saml/acs",
        );
        let doc = roxmltree::Document::parse(&xml);
        assert!(doc.is_ok(), "Generated SP metadata is not valid XML: {xml}");
    }

    #[test]
    fn sp_metadata_escaping() {
        let xml = generate_sp_metadata(
            "https://vouch.example.com/sp?org=acme&env=prod",
            "https://vouch.example.com/saml/acs",
        );
        assert!(
            xml.contains("org=acme&amp;env=prod"),
            "Ampersand should be escaped: {xml}"
        );
        assert!(
            !xml.contains("org=acme&env=prod"),
            "Raw ampersand should not appear: {xml}"
        );
        // Verify it's still valid XML after escaping.
        let doc = roxmltree::Document::parse(&xml);
        assert!(
            doc.is_ok(),
            "Escaped SP metadata should be valid XML: {xml}"
        );
    }

    #[test]
    fn sp_metadata_quote_escaping() {
        let xml = generate_sp_metadata(
            r#"https://vouch.example.com/sp?name="test""#,
            "https://vouch.example.com/saml/acs",
        );
        assert!(
            xml.contains("&quot;"),
            "Double quotes should be escaped: {xml}"
        );
        let doc = roxmltree::Document::parse(&xml);
        assert!(
            doc.is_ok(),
            "Escaped SP metadata should be valid XML: {xml}"
        );
    }
}
