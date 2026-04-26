// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SAML 2.0 Response parsing and validation.
//!
//! Validates base64-encoded SAML Response XML, verifying the XML signature,
//! time constraints, subject confirmation, and extracting identity assertions.
//!
//! # Security
//!
//! - XSW mitigations: extracts identity only from the verified signed element
//! - Multiple assertions are rejected
//! - Clock skew tolerance is capped at 120 seconds
//! - Replay prevention: callers must consume the state record after this returns Ok

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use jiff::Timestamp;

use super::{SamlProvider, signature::SignatureError};

// ============================================================================
// SAML namespace constants
// ============================================================================

/// SAML 2.0 protocol namespace.
const NS_SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

/// SAML 2.0 assertion namespace.
const NS_SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

/// SAML status code for success.
const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

/// Maximum clock skew tolerance in seconds.
const CLOCK_SKEW_SECS: i64 = 120;

/// Maximum decoded SAML response size (1 MiB). Prevents DoS via oversized XML.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

// ============================================================================
// Public types
// ============================================================================

/// Identity assertion extracted from a validated SAML Response.
#[derive(Debug, Clone)]
pub(crate) struct SamlAssertion {
    /// Email address extracted from NameID or configured attribute.
    pub email: String,
    /// Domain extracted from email or configured domain attribute.
    pub domain: Option<String>,
    /// Display name extracted from configured name attribute, if available.
    #[expect(dead_code, reason = "reserved for serde DTO conformance / future use")]
    pub name: Option<String>,
    /// Session expiry time from `<AuthnStatement SessionNotOnOrAfter>`.
    #[expect(dead_code, reason = "reserved for serde DTO conformance / future use")]
    pub session_not_on_or_after: Option<Timestamp>,
}

/// SAML 2.0 bearer subject confirmation method URI.
/// SAML Core Section 2.4.1.2.
const SUBJECT_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

/// Errors during SAML response validation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ResponseError {
    /// The base64 decoding of the SAMLResponse failed.
    #[error("failed to decode SAML response: {0}")]
    DecodeFailed(String),
    /// The XML could not be parsed.
    #[error("failed to parse SAML response XML: {0}")]
    XmlParse(String),
    /// XML signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureInvalid(#[from] SignatureError),
    /// The `Destination` attribute does not match the ACS URL.
    #[error("destination mismatch: expected {expected}, got {actual}")]
    DestinationMismatch { expected: String, actual: String },
    /// The `Destination` attribute is missing (required per SAML Bindings
    /// Section 3.5.5.2 for POST binding).
    #[error("missing Destination attribute (required for POST binding)")]
    MissingDestination,
    /// The `InResponseTo` attribute does not match the stored request ID.
    #[error("InResponseTo mismatch: expected {expected}, got {actual}")]
    InResponseToMismatch { expected: String, actual: String },
    /// The `InResponseTo` attribute is missing (required for SP-initiated SSO
    /// per SAML Profiles Section 4.1.4.3).
    #[error("missing InResponseTo attribute (required for SP-initiated SSO)")]
    MissingInResponseTo,
    /// The SAML Status is not `urn:oasis:names:tc:SAML:2.0:status:Success`.
    #[error("SAML status is not Success: {0}")]
    StatusNotSuccess(String),
    /// `NotBefore` / `NotOnOrAfter` time window validation failed.
    #[error("assertion time validation failed: {0}")]
    TimeValidation(String),
    /// More than one `<saml:Assertion>` was found (XSW protection).
    #[error("multiple assertions found (potential XSW attack)")]
    MultipleAssertions,
    /// No `<saml:Assertion>` was found in the response.
    #[error("no assertion found in response")]
    NoAssertion,
    /// The `<saml:Issuer>` does not match the IdP entity ID
    /// (SAML Core Section 2.3.3).
    #[error("issuer mismatch: expected {expected}, got {actual}")]
    IssuerMismatch { expected: String, actual: String },
    /// The `<saml:AudienceRestriction>` does not include the SP entity ID
    /// (SAML Core Section 2.5.1.4).
    #[error("audience restriction violated: SP entity ID '{sp_entity_id}' not in audience list")]
    AudienceRestrictionViolation { sp_entity_id: String },
    /// `<SubjectConfirmation>` does not use the bearer method
    /// (SAML Core Section 2.4.1.2).
    #[error("invalid SubjectConfirmation Method: expected bearer, got {0}")]
    InvalidSubjectConfirmationMethod(String),
    /// The email could not be extracted from the assertion.
    #[error("could not extract email from assertion")]
    NoEmail,
    /// Other structural or parsing errors.
    #[error("{0}")]
    Other(String),
}

// ============================================================================
// Public API
// ============================================================================

/// Validate a base64-encoded SAML Response and extract the identity assertion.
///
/// Validation steps (per SAML Core 2.0, Bindings 2.0, Profiles 2.0):
///
/// 1. Base64-decode the response
/// 2. Parse the XML
/// 3. Verify XML signature (XML-DSig Core)
/// 4. Require `Destination` matches the ACS URL (Bindings 3.5.5.2)
/// 5. Require `InResponseTo` matches the expected request ID (Profiles 4.1.4.3)
/// 6. Check SAML Status is Success (Core 3.2.2.2)
/// 7. Find exactly one `<saml:Assertion>` (reject multiple — XSW)
/// 8. Validate `<saml:Issuer>` matches IdP entity ID (Core 2.3.3)
/// 9. Validate `<saml:AudienceRestriction>` includes SP entity ID (Core 2.5.1.4)
/// 10. Validate `NotBefore` / `NotOnOrAfter` with clock skew tolerance (Core 2.5.1)
/// 11. Validate `SubjectConfirmation` Method is bearer (Core 2.4.1.2)
/// 12. Validate `SubjectConfirmationData` Recipient and time (Profiles 4.1.4.3)
/// 13. Extract email from NameID or configured attribute
/// 14. Extract domain from email or configured attribute
///
/// # Errors
///
/// Returns `ResponseError` for any validation failure. The caller must delete the
/// SAML state record (replay prevention) after this function returns `Ok`.
pub(crate) fn validate_saml_response(
    base64_response: &str,
    expected_request_id: &str,
    provider: &SamlProvider,
) -> Result<SamlAssertion, ResponseError> {
    // Step 1: Base64-decode
    let xml_bytes = BASE64_STANDARD
        .decode(base64_response.trim())
        .map_err(|e| ResponseError::DecodeFailed(e.to_string()))?;

    // Size check: prevent DoS via oversized XML before DOM parsing
    if xml_bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ResponseError::DecodeFailed(format!(
            "decoded response exceeds maximum size ({} bytes > {MAX_RESPONSE_BYTES})",
            xml_bytes.len()
        )));
    }

    let xml = std::str::from_utf8(&xml_bytes)
        .map_err(|e| ResponseError::DecodeFailed(format!("invalid UTF-8: {e}")))?;

    // Step 2: Parse XML
    let doc =
        roxmltree::Document::parse(xml).map_err(|e| ResponseError::XmlParse(e.to_string()))?;

    // Step 3: Verify XML signature (delegates to signature.rs)
    let signed_id =
        super::signature::verify_xml_signature(&doc, &provider.idp_metadata.signing_certificates)?;

    // After verification, re-resolve signed element by ID (XSW mitigation)
    let signed_element = find_element_by_id(&doc, &signed_id.0).ok_or_else(|| {
        ResponseError::Other(format!(
            "signed element '{}' not found after verification",
            signed_id.0
        ))
    })?;

    // Step 4: Require Destination matches ACS URL
    // SAML Bindings Section 3.5.5.2: Destination is REQUIRED for POST binding.
    let response_root = doc
        .root()
        .children()
        .find(|n| n.has_tag_name((NS_SAMLP, "Response")))
        .ok_or_else(|| ResponseError::Other("missing Response element".to_string()))?;

    // XSW mitigation: the signed element must be either the Response itself
    // or an Assertion that is a direct child of the Response. Reject documents
    // where the signed element lives elsewhere in the tree.
    if !signed_element.has_tag_name((NS_SAMLP, "Response"))
        && !signed_element.has_tag_name((NS_SAML, "Assertion"))
    {
        return Err(ResponseError::Other(
            "signed element is neither Response nor Assertion".to_string(),
        ));
    }
    if signed_element.has_tag_name((NS_SAMLP, "Response"))
        && signed_element.id() != response_root.id()
    {
        return Err(ResponseError::Other(
            "signed Response element does not match document root Response (XSW)".to_string(),
        ));
    }
    if signed_element.has_tag_name((NS_SAML, "Assertion")) {
        let is_direct_child = response_root
            .children()
            .any(|child| child.id() == signed_element.id());
        if !is_direct_child {
            return Err(ResponseError::Other(
                "signed Assertion is not a direct child of Response (XSW)".to_string(),
            ));
        }
    }

    let destination = response_root
        .attribute("Destination")
        .ok_or(ResponseError::MissingDestination)?;
    if destination != provider.acs_url {
        return Err(ResponseError::DestinationMismatch {
            expected: provider.acs_url.clone(),
            actual: destination.to_string(),
        });
    }

    // Step 5: Require InResponseTo matches expected request ID
    // SAML Profiles Section 4.1.4.3: MUST be present for SP-initiated SSO.
    let in_response_to = response_root
        .attribute("InResponseTo")
        .ok_or(ResponseError::MissingInResponseTo)?;
    if in_response_to != expected_request_id {
        return Err(ResponseError::InResponseToMismatch {
            expected: expected_request_id.to_string(),
            actual: in_response_to.to_string(),
        });
    }

    // Step 6: Check Status (Core 3.2.2.2)
    validate_status(response_root)?;

    // Step 7: Find exactly one Assertion (XSW protection)
    let assertions: Vec<_> = response_root
        .children()
        .filter(|n| n.has_tag_name((NS_SAML, "Assertion")))
        .collect();

    if assertions.len() > 1 {
        return Err(ResponseError::MultipleAssertions);
    }

    // The assertion must be either the signed element or a direct child of the signed Response.
    // If the assertion itself is signed, it's the signed_element.
    // If the Response is signed, the assertion must be its direct child.
    let assertion = if signed_element.has_tag_name((NS_SAML, "Assertion")) {
        // The assertion itself was signed — use it directly
        signed_element
    } else if signed_element.has_tag_name((NS_SAMLP, "Response")) {
        // The response was signed — assertion must be a direct child
        assertions
            .first()
            .copied()
            .ok_or(ResponseError::NoAssertion)?
    } else {
        return Err(ResponseError::Other(
            "signed element is neither Response nor Assertion".to_string(),
        ));
    };

    // Step 8: Validate Issuer matches IdP entity ID (Core 2.3.3)
    validate_issuer(assertion, &provider.idp_metadata.entity_id)?;

    // Step 9: Validate AudienceRestriction includes SP entity ID (Core 2.5.1.4)
    validate_audience_restriction(assertion, &provider.sp_entity_id)?;

    // Step 10: Validate time conditions (Core 2.5.1)
    let now = Timestamp::now();
    validate_conditions(assertion, now)?;

    // Step 11: Validate SubjectConfirmation Method is bearer (Core 2.4.1.2)
    // Step 12: Validate SubjectConfirmationData (Profiles 4.1.4.3)
    validate_subject_confirmation(assertion, expected_request_id, &provider.acs_url, now)?;

    // Step 10: Extract session expiry
    let session_not_on_or_after = extract_session_not_on_or_after(assertion);

    // Step 11: Extract email
    let email = extract_email(assertion, provider.email_attribute.as_deref())?;

    // Step 12: Extract domain
    let domain = extract_domain(assertion, provider.domain_attribute.as_deref(), &email);

    // Step 13: Extract display name (best-effort)
    let name = extract_display_name(assertion);

    Ok(SamlAssertion {
        email,
        domain,
        name,
        session_not_on_or_after,
    })
}

// ============================================================================
// Internal validation helpers
// ============================================================================

/// Validate the SAML Status element is Success.
fn validate_status(response: roxmltree::Node<'_, '_>) -> Result<(), ResponseError> {
    let status = response
        .children()
        .find(|n| n.has_tag_name((NS_SAMLP, "Status")))
        .ok_or_else(|| ResponseError::Other("missing Status element".to_string()))?;

    let status_code = status
        .children()
        .find(|n| n.has_tag_name((NS_SAMLP, "StatusCode")))
        .ok_or_else(|| ResponseError::Other("missing StatusCode element".to_string()))?;

    let value = status_code
        .attribute("Value")
        .ok_or_else(|| ResponseError::Other("missing StatusCode Value".to_string()))?;

    if value != STATUS_SUCCESS {
        return Err(ResponseError::StatusNotSuccess(value.to_string()));
    }
    Ok(())
}

/// Validate `<saml:Issuer>` matches the configured IdP entity ID.
///
/// SAML Core Section 2.3.3: The `<saml:Issuer>` identifies the entity that
/// generated the assertion. It MUST match the IdP entity ID from metadata.
fn validate_issuer(
    assertion: roxmltree::Node<'_, '_>,
    expected_entity_id: &str,
) -> Result<(), ResponseError> {
    let issuer = assertion
        .children()
        .find(|n| n.has_tag_name((NS_SAML, "Issuer")))
        .and_then(|n| n.text())
        .map(str::trim)
        .ok_or_else(|| ResponseError::Other("missing Issuer element in assertion".to_string()))?;

    if issuer != expected_entity_id {
        return Err(ResponseError::IssuerMismatch {
            expected: expected_entity_id.to_string(),
            actual: issuer.to_string(),
        });
    }
    Ok(())
}

/// Validate `<saml:AudienceRestriction>` includes the SP entity ID.
///
/// SAML Core Section 2.5.1.4: If `<AudienceRestriction>` is present, the
/// relying party MUST be a member of the specified audience(s). An assertion
/// intended for a different SP at the same IdP must be rejected.
fn validate_audience_restriction(
    assertion: roxmltree::Node<'_, '_>,
    sp_entity_id: &str,
) -> Result<(), ResponseError> {
    // Conditions must exist (enforced by validate_conditions called before us).
    let conditions = assertion
        .children()
        .find(|n| n.has_tag_name((NS_SAML, "Conditions")))
        .ok_or_else(|| {
            ResponseError::Other("missing Conditions element for audience check".to_string())
        })?;

    // SAML Profiles 4.1.4.3: AudienceRestriction MUST be present and MUST
    // include the SP entity ID. Reject assertions without AudienceRestriction.
    let audience_restriction = conditions
        .children()
        .find(|n| n.has_tag_name((NS_SAML, "AudienceRestriction")))
        .ok_or(ResponseError::AudienceRestrictionViolation {
            sp_entity_id: sp_entity_id.to_string(),
        })?;

    // Check if any <saml:Audience> element matches the SP entity ID
    let has_match = audience_restriction
        .children()
        .filter(|n| n.has_tag_name((NS_SAML, "Audience")))
        .filter_map(|n| n.text())
        .any(|text| text.trim() == sp_entity_id);

    if !has_match {
        return Err(ResponseError::AudienceRestrictionViolation {
            sp_entity_id: sp_entity_id.to_string(),
        });
    }
    Ok(())
}

/// Validate `<saml:Conditions>` `NotBefore` and `NotOnOrAfter` with clock skew tolerance.
fn validate_conditions(
    assertion: roxmltree::Node<'_, '_>,
    now: Timestamp,
) -> Result<(), ResponseError> {
    // SAML Profiles 4.1.4.3: Conditions with AudienceRestriction MUST be present.
    // Reject assertions without Conditions to prevent infinite-lifetime assertions.
    let conditions = assertion
        .children()
        .find(|n| n.has_tag_name((NS_SAML, "Conditions")))
        .ok_or_else(|| {
            ResponseError::Other(
                "missing Conditions element (required for Web Browser SSO)".to_string(),
            )
        })?;

    if let Some(not_before_str) = conditions.attribute("NotBefore") {
        let not_before = parse_saml_timestamp(not_before_str)?;
        // Allow up to CLOCK_SKEW_SECS of clock skew
        let skewed_now = now
            .checked_add(jiff::Span::new().seconds(CLOCK_SKEW_SECS))
            .unwrap_or(now);
        if skewed_now < not_before {
            return Err(ResponseError::TimeValidation(format!(
                "assertion not yet valid: NotBefore={not_before_str}, now={now}"
            )));
        }
    }

    if let Some(not_on_or_after_str) = conditions.attribute("NotOnOrAfter") {
        let not_on_or_after = parse_saml_timestamp(not_on_or_after_str)?;
        // Allow up to CLOCK_SKEW_SECS of clock skew
        let skewed_now = now
            .checked_sub(jiff::Span::new().seconds(CLOCK_SKEW_SECS))
            .unwrap_or(now);
        if skewed_now >= not_on_or_after {
            return Err(ResponseError::TimeValidation(format!(
                "assertion has expired: NotOnOrAfter={not_on_or_after_str}, now={now}"
            )));
        }
    }

    Ok(())
}

/// Validate `<saml:SubjectConfirmation>` Method and `SubjectConfirmationData`.
///
/// SAML Core Section 2.4.1.2: The Method MUST be bearer for Web Browser SSO.
/// SAML Profiles Section 4.1.4.3: SubjectConfirmationData Recipient and
/// NotOnOrAfter MUST be validated.
fn validate_subject_confirmation(
    assertion: roxmltree::Node<'_, '_>,
    expected_request_id: &str,
    acs_url: &str,
    now: Timestamp,
) -> Result<(), ResponseError> {
    // SAML Profiles 4.1.4.3: Subject MUST be present for Web Browser SSO.
    let subject = assertion
        .children()
        .find(|n| n.has_tag_name((NS_SAML, "Subject")))
        .ok_or_else(|| {
            ResponseError::Other(
                "missing Subject element (required for Web Browser SSO)".to_string(),
            )
        })?;

    // SAML Profiles 4.1.4.3: At least one SubjectConfirmation with bearer
    // Method MUST be present. Without it, there's no proof the bearer is the
    // intended subject.
    let confirmations: Vec<_> = subject
        .children()
        .filter(|n| n.has_tag_name((NS_SAML, "SubjectConfirmation")))
        .collect();

    if confirmations.is_empty() {
        return Err(ResponseError::Other(
            "missing SubjectConfirmation element (required for Web Browser SSO)".to_string(),
        ));
    }

    for confirmation in confirmations {
        // SAML Core 2.4.1.2: Verify Method is bearer
        let method = confirmation.attribute("Method").unwrap_or("");
        if method != SUBJECT_BEARER {
            return Err(ResponseError::InvalidSubjectConfirmationMethod(
                method.to_string(),
            ));
        }

        let conf_data = confirmation
            .children()
            .find(|n| n.has_tag_name((NS_SAML, "SubjectConfirmationData")))
            .ok_or_else(|| {
                ResponseError::Other(
                    "missing SubjectConfirmationData (required for bearer)".to_string(),
                )
            })?;

        // SAML Profiles 4.1.4.3: Recipient MUST match ACS URL.
        let recipient = conf_data.attribute("Recipient").ok_or_else(|| {
            ResponseError::Other(
                "missing Recipient in SubjectConfirmationData (required)".to_string(),
            )
        })?;
        if recipient != acs_url {
            return Err(ResponseError::DestinationMismatch {
                expected: acs_url.to_string(),
                actual: recipient.to_string(),
            });
        }

        // Check InResponseTo matches request ID
        if let Some(in_response_to) = conf_data.attribute("InResponseTo")
            && in_response_to != expected_request_id
        {
            return Err(ResponseError::InResponseToMismatch {
                expected: expected_request_id.to_string(),
                actual: in_response_to.to_string(),
            });
        }

        // Check NotOnOrAfter
        if let Some(not_on_or_after_str) = conf_data.attribute("NotOnOrAfter") {
            let not_on_or_after = parse_saml_timestamp(not_on_or_after_str)?;
            let skewed_now = now
                .checked_sub(jiff::Span::new().seconds(CLOCK_SKEW_SECS))
                .unwrap_or(now);
            if skewed_now >= not_on_or_after {
                return Err(ResponseError::TimeValidation(format!(
                    "SubjectConfirmationData expired: NotOnOrAfter={not_on_or_after_str}"
                )));
            }
        }
    }

    Ok(())
}

// ============================================================================
// Extraction helpers
// ============================================================================

/// Extract the email address from the assertion.
///
/// Checks (in order):
/// 1. The configured `email_attribute` SAML attribute
/// 2. The `<saml:NameID>` element
fn extract_email(
    assertion: roxmltree::Node<'_, '_>,
    email_attribute: Option<&str>,
) -> Result<String, ResponseError> {
    // Try configured attribute first
    if let Some(attr_name) = email_attribute
        && let Some(value) = find_saml_attribute(assertion, attr_name)
    {
        return Ok(value);
    }

    // Fall back to NameID
    let name_id = assertion
        .children()
        .find(|n| n.has_tag_name((NS_SAML, "Subject")))
        .and_then(|s| s.children().find(|n| n.has_tag_name((NS_SAML, "NameID"))))
        .and_then(|n| n.text())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    name_id.map(str::to_string).ok_or(ResponseError::NoEmail)
}

/// Extract the domain from the assertion or derive it from the email.
fn extract_domain(
    assertion: roxmltree::Node<'_, '_>,
    domain_attribute: Option<&str>,
    email: &str,
) -> Option<String> {
    // Try configured domain attribute
    if let Some(attr_name) = domain_attribute
        && let Some(value) = find_saml_attribute(assertion, attr_name)
    {
        return Some(value);
    }

    // Derive from email address
    email.split('@').nth(1).map(str::to_string)
}

/// Extract display name from common SAML attributes.
fn extract_display_name(assertion: roxmltree::Node<'_, '_>) -> Option<String> {
    // Try common display name attribute names
    for attr_name in &[
        "displayName",
        "urn:oid:2.16.840.1.113730.3.1.241",
        "http://schemas.microsoft.com/identity/claims/displayname",
        "name",
    ] {
        if let Some(value) = find_saml_attribute(assertion, attr_name) {
            return Some(value);
        }
    }
    None
}

/// Extract `AuthnStatement SessionNotOnOrAfter` timestamp.
fn extract_session_not_on_or_after(assertion: roxmltree::Node<'_, '_>) -> Option<Timestamp> {
    assertion
        .children()
        .find(|n| n.has_tag_name((NS_SAML, "AuthnStatement")))
        .and_then(|n| n.attribute("SessionNotOnOrAfter"))
        .and_then(|s| parse_saml_timestamp(s).ok())
}

/// Find the value of a SAML attribute by name.
///
/// Looks through `<saml:AttributeStatement>` / `<saml:Attribute>` elements
/// for a matching `Name` attribute and returns the first `AttributeValue` text.
fn find_saml_attribute(assertion: roxmltree::Node<'_, '_>, attr_name: &str) -> Option<String> {
    let attr_stmt = assertion
        .children()
        .find(|n| n.has_tag_name((NS_SAML, "AttributeStatement")))?;

    for attribute in attr_stmt
        .children()
        .filter(|n| n.has_tag_name((NS_SAML, "Attribute")))
    {
        if attribute.attribute("Name") == Some(attr_name)
            && let Some(value_node) = attribute
                .children()
                .find(|n| n.has_tag_name((NS_SAML, "AttributeValue")))
            && let Some(text) = value_node.text()
        {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Find an element whose `ID` attribute matches the given value.
fn find_element_by_id<'a, 'input>(
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

/// Parse a SAML timestamp string (ISO 8601 / RFC 3339) into a `jiff::Timestamp`.
///
/// SAML uses `YYYY-MM-DDTHH:MM:SSZ` or `YYYY-MM-DDTHH:MM:SS.sssZ` format.
fn parse_saml_timestamp(s: &str) -> Result<Timestamp, ResponseError> {
    // jiff::Timestamp::from_str parses RFC 3339 / ISO 8601
    s.parse::<Timestamp>()
        .map_err(|e| ResponseError::TimeValidation(format!("invalid timestamp '{s}': {e}")))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::string_slice,
        reason = "test code: panic on assertion failure is acceptable"
    )]
    use super::*;

    // =========================================================================
    // Timestamp parsing tests
    // =========================================================================

    #[test]
    fn parse_saml_timestamp_utc() {
        let ts = parse_saml_timestamp("2026-03-19T12:00:00Z").unwrap();
        assert_eq!(ts.to_string(), "2026-03-19T12:00:00Z");
    }

    #[test]
    fn parse_saml_timestamp_with_milliseconds() {
        let ts = parse_saml_timestamp("2026-03-19T12:00:00.000Z").unwrap();
        assert_eq!(ts.to_string(), "2026-03-19T12:00:00Z");
    }

    #[test]
    fn parse_saml_timestamp_invalid() {
        let err = parse_saml_timestamp("not-a-timestamp").unwrap_err();
        assert!(
            matches!(err, ResponseError::TimeValidation(_)),
            "Expected TimeValidation, got: {err}"
        );
    }

    // =========================================================================
    // Status validation tests
    // =========================================================================

    #[test]
    fn status_success_passes() {
        let xml = r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:Response>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let response = doc.root().children().find(|n| n.is_element()).unwrap();
        assert!(validate_status(response).is_ok());
    }

    #[test]
    fn status_non_success_returns_error() {
        let xml = r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/>
  </samlp:Status>
</samlp:Response>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let response = doc.root().children().find(|n| n.is_element()).unwrap();
        let err = validate_status(response).unwrap_err();
        assert!(
            matches!(err, ResponseError::StatusNotSuccess(_)),
            "Expected StatusNotSuccess, got: {err}"
        );
    }

    // =========================================================================
    // Conditions time validation tests
    // =========================================================================

    #[test]
    fn conditions_valid_time_window_passes() {
        // NotBefore = 1 hour ago, NotOnOrAfter = 1 hour from now
        let now = Timestamp::now();
        let one_hour_ago = now
            .checked_sub(jiff::Span::new().hours(1))
            .unwrap()
            .strftime("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let one_hour_from_now = now
            .checked_add(jiff::Span::new().hours(1))
            .unwrap()
            .strftime("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        let xml = format!(
            r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Conditions NotBefore="{one_hour_ago}" NotOnOrAfter="{one_hour_from_now}"/>
</saml:Assertion>"##
        );
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        assert!(validate_conditions(assertion, now).is_ok());
    }

    #[test]
    fn conditions_expired_returns_error() {
        // NotOnOrAfter = 10 minutes ago (beyond clock skew tolerance)
        let now = Timestamp::now();
        let expired = now
            .checked_sub(jiff::Span::new().minutes(10))
            .unwrap()
            .strftime("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        let xml = format!(
            r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Conditions NotOnOrAfter="{expired}"/>
</saml:Assertion>"##
        );
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        let err = validate_conditions(assertion, now).unwrap_err();
        assert!(
            matches!(err, ResponseError::TimeValidation(_)),
            "Expected TimeValidation for expired assertion, got: {err}"
        );
    }

    #[test]
    fn conditions_not_yet_valid_returns_error() {
        // NotBefore = 10 minutes from now (beyond clock skew tolerance)
        let now = Timestamp::now();
        let future = now
            .checked_add(jiff::Span::new().minutes(10))
            .unwrap()
            .strftime("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        let xml = format!(
            r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Conditions NotBefore="{future}"/>
</saml:Assertion>"##
        );
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        let err = validate_conditions(assertion, now).unwrap_err();
        assert!(
            matches!(err, ResponseError::TimeValidation(_)),
            "Expected TimeValidation for future assertion, got: {err}"
        );
    }

    #[test]
    fn clock_skew_within_tolerance_passes() {
        // NotOnOrAfter = 30 seconds ago (within 120s skew tolerance)
        let now = Timestamp::now();
        let recent_past = now
            .checked_sub(jiff::Span::new().seconds(30))
            .unwrap()
            .strftime("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        let xml = format!(
            r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Conditions NotOnOrAfter="{recent_past}"/>
</saml:Assertion>"##
        );
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        assert!(validate_conditions(assertion, now).is_ok());
    }

    // =========================================================================
    // Email extraction tests
    // =========================================================================

    #[test]
    fn email_extracted_from_name_id() {
        let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress">
      user@example.com
    </saml:NameID>
  </saml:Subject>
</saml:Assertion>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        let email = extract_email(assertion, None).unwrap();
        assert_eq!(email, "user@example.com");
    }

    #[test]
    fn email_extracted_from_configured_attribute() {
        let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:AttributeStatement>
    <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">
      <saml:AttributeValue>user@example.com</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        let email = extract_email(
            assertion,
            Some("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"),
        )
        .unwrap();
        assert_eq!(email, "user@example.com");
    }

    #[test]
    fn email_attribute_takes_precedence_over_name_id() {
        let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Subject>
    <saml:NameID>nameid@example.com</saml:NameID>
  </saml:Subject>
  <saml:AttributeStatement>
    <saml:Attribute Name="email">
      <saml:AttributeValue>attr@example.com</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        let email = extract_email(assertion, Some("email")).unwrap();
        assert_eq!(email, "attr@example.com");
    }

    #[test]
    fn missing_email_returns_error() {
        let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Subject>
    <saml:NameID></saml:NameID>
  </saml:Subject>
</saml:Assertion>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        let err = extract_email(assertion, None).unwrap_err();
        assert!(
            matches!(err, ResponseError::NoEmail),
            "Expected NoEmail, got: {err}"
        );
    }

    // =========================================================================
    // Domain extraction tests
    // =========================================================================

    #[test]
    fn domain_extracted_from_email() {
        let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        "##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        let domain = extract_domain(assertion, None, "user@example.com");
        assert_eq!(domain, Some("example.com".to_string()));
    }

    #[test]
    fn domain_extracted_from_configured_attribute() {
        let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:AttributeStatement>
    <saml:Attribute Name="domain">
      <saml:AttributeValue>custom.example.com</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        let domain = extract_domain(assertion, Some("domain"), "user@example.com");
        assert_eq!(domain, Some("custom.example.com".to_string()));
    }

    // =========================================================================
    // Destination validation tests (via validate_saml_response)
    // =========================================================================

    #[test]
    fn destination_mismatch_returns_error() {
        // Test via direct construction of the ResponseError type
        let err = ResponseError::DestinationMismatch {
            expected: "https://vouch.example.com/saml/acs".to_string(),
            actual: "https://evil.example.com/saml/acs".to_string(),
        };
        assert!(
            err.to_string().contains("destination mismatch"),
            "Error message should mention destination mismatch: {err}"
        );
    }

    #[test]
    fn in_response_to_mismatch_returns_error() {
        let err = ResponseError::InResponseToMismatch {
            expected: "_expected_id".to_string(),
            actual: "_actual_id".to_string(),
        };
        assert!(
            err.to_string().contains("InResponseTo"),
            "Error message should mention InResponseTo: {err}"
        );
    }

    // =========================================================================
    // Multiple assertions rejection test
    // =========================================================================

    #[test]
    fn multiple_assertions_error_displays_correctly() {
        let err = ResponseError::MultipleAssertions;
        assert!(
            err.to_string().contains("multiple"),
            "Should mention multiple assertions: {err}"
        );
        assert!(err.to_string().contains("XSW"), "Should mention XSW: {err}");
    }

    // =========================================================================
    // decode error test
    // =========================================================================

    #[test]
    fn invalid_base64_returns_decode_error() {
        use crate::services::idp::saml::IdpMetadata;
        use crate::services::idp::saml::SamlProvider;

        let provider = SamlProvider {
            idp_metadata: IdpMetadata {
                entity_id: "https://idp.example.com".to_string(),
                sso_post_url: Some("https://idp.example.com/sso".to_string()),
                sso_redirect_url: None,
                signing_certificates: vec![],
            },
            sp_entity_id: "https://vouch.example.com".to_string(),
            acs_url: "https://vouch.example.com/saml/acs".to_string(),
            email_attribute: None,
            domain_attribute: None,
        };

        let err =
            validate_saml_response("!!!not-valid-base64!!!", "_request_id", &provider).unwrap_err();
        assert!(
            matches!(err, ResponseError::DecodeFailed(_)),
            "Expected DecodeFailed for invalid base64, got: {err}"
        );
    }

    #[test]
    fn invalid_xml_returns_xml_parse_error() {
        use crate::services::idp::saml::IdpMetadata;
        use crate::services::idp::saml::SamlProvider;
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

        let provider = SamlProvider {
            idp_metadata: IdpMetadata {
                entity_id: "https://idp.example.com".to_string(),
                sso_post_url: Some("https://idp.example.com/sso".to_string()),
                sso_redirect_url: None,
                signing_certificates: vec![],
            },
            sp_entity_id: "https://vouch.example.com".to_string(),
            acs_url: "https://vouch.example.com/saml/acs".to_string(),
            email_attribute: None,
            domain_attribute: None,
        };

        let bad_xml = BASE64_STANDARD.encode("<unclosed");
        let err = validate_saml_response(&bad_xml, "_request_id", &provider).unwrap_err();
        assert!(
            matches!(err, ResponseError::XmlParse(_)),
            "Expected XmlParse for invalid XML, got: {err}"
        );
    }

    // =========================================================================
    // Issuer validation tests (SAML Core 2.3.3)
    // =========================================================================

    #[test]
    fn issuer_matching_passes() {
        let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
</saml:Assertion>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        assert!(validate_issuer(assertion, "https://idp.example.com").is_ok());
    }

    #[test]
    fn issuer_mismatch_returns_error() {
        let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Issuer>https://evil.example.com</saml:Issuer>
</saml:Assertion>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        let err = validate_issuer(assertion, "https://idp.example.com").unwrap_err();
        assert!(
            matches!(err, ResponseError::IssuerMismatch { .. }),
            "Expected IssuerMismatch, got: {err}"
        );
    }

    #[test]
    fn missing_issuer_returns_error() {
        let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
</saml:Assertion>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        let err = validate_issuer(assertion, "https://idp.example.com").unwrap_err();
        assert!(
            matches!(err, ResponseError::Other(_)),
            "Expected Other (missing Issuer), got: {err}"
        );
    }

    // =========================================================================
    // AudienceRestriction validation tests (SAML Core 2.5.1.4)
    // =========================================================================

    #[test]
    fn audience_restriction_matching_passes() {
        let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Conditions>
    <saml:AudienceRestriction>
      <saml:Audience>https://vouch.example.com</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
</saml:Assertion>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        assert!(validate_audience_restriction(assertion, "https://vouch.example.com").is_ok());
    }

    #[test]
    fn audience_restriction_wrong_sp_returns_error() {
        let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Conditions>
    <saml:AudienceRestriction>
      <saml:Audience>https://other-sp.example.com</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
</saml:Assertion>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        let err =
            validate_audience_restriction(assertion, "https://vouch.example.com").unwrap_err();
        assert!(
            matches!(err, ResponseError::AudienceRestrictionViolation { .. }),
            "Expected AudienceRestrictionViolation, got: {err}"
        );
    }

    #[test]
    fn audience_restriction_multiple_audiences_one_matching() {
        let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Conditions>
    <saml:AudienceRestriction>
      <saml:Audience>https://other-sp.example.com</saml:Audience>
      <saml:Audience>https://vouch.example.com</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
</saml:Assertion>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        assert!(validate_audience_restriction(assertion, "https://vouch.example.com").is_ok());
    }

    #[test]
    fn audience_restriction_absent_conditions_returns_error() {
        // No Conditions element — now required per SAML Profiles 4.1.4.3
        let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        let err =
            validate_audience_restriction(assertion, "https://vouch.example.com").unwrap_err();
        assert!(
            matches!(err, ResponseError::Other(_)),
            "Expected error for missing Conditions, got: {err}"
        );
    }

    #[test]
    fn audience_restriction_conditions_without_restriction_returns_error() {
        // Conditions exists but no AudienceRestriction — now required
        let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Conditions NotBefore="2026-01-01T00:00:00Z"/>
</saml:Assertion>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        let err =
            validate_audience_restriction(assertion, "https://vouch.example.com").unwrap_err();
        assert!(
            matches!(err, ResponseError::AudienceRestrictionViolation { .. }),
            "Expected AudienceRestrictionViolation, got: {err}"
        );
    }

    // =========================================================================
    // SubjectConfirmation Method validation tests (SAML Core 2.4.1.2)
    // =========================================================================

    #[test]
    fn subject_confirmation_bearer_method_passes() {
        let now = Timestamp::now();
        let future = now
            .checked_add(jiff::Span::new().hours(1))
            .unwrap()
            .strftime("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let xml = format!(
            r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Subject>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData
        Recipient="https://vouch.example.com/saml/acs"
        InResponseTo="_req123"
        NotOnOrAfter="{future}"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
</saml:Assertion>"##
        );
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        assert!(
            validate_subject_confirmation(
                assertion,
                "_req123",
                "https://vouch.example.com/saml/acs",
                now
            )
            .is_ok()
        );
    }

    #[test]
    fn subject_confirmation_non_bearer_method_returns_error() {
        let now = Timestamp::now();
        let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Subject>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:holder-of-key">
      <saml:SubjectConfirmationData Recipient="https://vouch.example.com/saml/acs"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
</saml:Assertion>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        let err = validate_subject_confirmation(
            assertion,
            "_req123",
            "https://vouch.example.com/saml/acs",
            now,
        )
        .unwrap_err();
        assert!(
            matches!(err, ResponseError::InvalidSubjectConfirmationMethod(_)),
            "Expected InvalidSubjectConfirmationMethod, got: {err}"
        );
    }

    #[test]
    fn subject_confirmation_missing_method_returns_error() {
        let now = Timestamp::now();
        let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Subject>
    <saml:SubjectConfirmation>
      <saml:SubjectConfirmationData Recipient="https://vouch.example.com/saml/acs"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
</saml:Assertion>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        let err = validate_subject_confirmation(
            assertion,
            "_req123",
            "https://vouch.example.com/saml/acs",
            now,
        )
        .unwrap_err();
        assert!(
            matches!(err, ResponseError::InvalidSubjectConfirmationMethod(_)),
            "Expected InvalidSubjectConfirmationMethod for missing Method, got: {err}"
        );
    }

    // =========================================================================
    // New error variant display tests
    // =========================================================================

    #[test]
    fn missing_destination_error_displays_correctly() {
        let err = ResponseError::MissingDestination;
        assert!(err.to_string().contains("Destination"));
    }

    #[test]
    fn missing_in_response_to_error_displays_correctly() {
        let err = ResponseError::MissingInResponseTo;
        assert!(err.to_string().contains("InResponseTo"));
    }

    #[test]
    fn issuer_mismatch_error_displays_correctly() {
        let err = ResponseError::IssuerMismatch {
            expected: "https://idp.example.com".to_string(),
            actual: "https://evil.example.com".to_string(),
        };
        assert!(err.to_string().contains("issuer mismatch"));
    }

    #[test]
    fn audience_restriction_error_displays_correctly() {
        let err = ResponseError::AudienceRestrictionViolation {
            sp_entity_id: "https://sp.example.com".to_string(),
        };
        assert!(err.to_string().contains("audience restriction"));
    }

    // =========================================================================
    // End-to-end signature pipeline tests
    // =========================================================================

    /// Build a real RSA key pair and a self-signed X.509 DER certificate.
    /// Reuses the same helpers from signature.rs tests.
    fn generate_test_key_and_cert() -> (aws_lc_rs::rsa::KeyPair, Vec<u8>) {
        let key_pair = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let cert_der = build_self_signed_der(&key_pair);
        (key_pair, cert_der)
    }

    /// Build a minimal (parseable) self-signed X.509 DER certificate for the key pair.
    fn build_self_signed_der(key_pair: &aws_lc_rs::rsa::KeyPair) -> Vec<u8> {
        use aws_lc_rs::signature::KeyPair as _;
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

    /// Construct a complete, fully-signed SAML Response XML string.
    ///
    /// The assertion is signed using an enveloped RSA-SHA256 signature with exc-c14n.
    /// Returns the XML string (not yet base64-encoded).
    ///
    /// # Whitespace design
    ///
    /// The Signature element is inserted immediately after `</saml:Issuer>` with no
    /// leading whitespace text node between them. This means the canonical form of
    /// the assertion after enveloped-signature exclusion exactly matches the canonical
    /// form computed before the Signature was inserted, because:
    ///
    /// - Before insertion: text(`\n  `) + Issuer + text(`\n  `) + Subject
    /// - After insertion: text(`\n  `) + Issuer + Signature(excluded) + text(`\n  `) + Subject
    ///
    /// Both produce the same canonical bytes.
    #[expect(
        clippy::too_many_arguments,
        reason = "test helper builds SAML response with all signed-element parameters"
    )]
    fn build_signed_saml_response(
        key_pair: &aws_lc_rs::rsa::KeyPair,
        email: &str,
        response_id: &str,
        assertion_id: &str,
        in_response_to: &str,
        destination: &str,
        issuer: &str,
        sp_entity_id: &str,
        not_before: &str,
        not_on_or_after: &str,
    ) -> String {
        use aws_lc_rs::digest;
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as B64;

        // Step 1: Build the assertion XML *without* the Signature element.
        // The Signature will be inserted immediately after </saml:Issuer> without
        // adding any extra whitespace text nodes around it (see whitespace design note).
        let assertion_body = format!(
            r#"
  <saml:Issuer>{issuer}</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress">{email}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData Recipient="{destination}" InResponseTo="{in_response_to}" NotOnOrAfter="{not_on_or_after}"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
    <saml:AudienceRestriction>
      <saml:Audience>{sp_entity_id}</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="{not_before}" SessionNotOnOrAfter="{not_on_or_after}">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
"#
        );
        let assertion_open = format!(
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}" Version="2.0" IssueInstant="{not_before}">"#
        );
        let assertion_without_sig = format!("{assertion_open}{assertion_body}</saml:Assertion>");

        // Step 2: Canonicalize the assertion (exc-c14n, no inclusive prefixes).
        let doc_no_sig = roxmltree::Document::parse(&assertion_without_sig).unwrap();
        let assertion_node = doc_no_sig
            .root()
            .children()
            .find(|n| n.is_element())
            .unwrap();
        let canonical_assertion = super::super::c14n::exclusive_c14n(assertion_node, &[]);

        // Step 3: Compute SHA-256 digest over canonicalized assertion.
        let digest_bytes = digest::digest(&digest::SHA256, canonical_assertion.as_bytes());
        let digest_b64 = B64.encode(digest_bytes.as_ref());

        // Step 4: Build SignedInfo with the computed digest.
        let ref_uri = format!("#{assertion_id}");
        let signed_info_xml = format!(
            r#"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="{ref_uri}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>{digest_b64}</ds:DigestValue></ds:Reference></ds:SignedInfo>"#
        );

        // Step 5: The canonical form of SignedInfo IS the SignedInfo XML itself
        // (already canonical: no whitespace, empty elements expanded, etc.).
        // Parse and re-canonicalize to be safe.
        let doc_si = roxmltree::Document::parse(&signed_info_xml).unwrap();
        let signed_info_node = doc_si.root().children().find(|n| n.is_element()).unwrap();
        let canonical_signed_info = super::super::c14n::exclusive_c14n(signed_info_node, &[]);

        // Step 6: Sign the canonical SignedInfo with RSA-PKCS1-SHA256.
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let mut sig_buf = vec![0u8; key_pair.public_modulus_len()];
        key_pair
            .sign(
                &aws_lc_rs::signature::RSA_PKCS1_SHA256,
                &rng,
                canonical_signed_info.as_bytes(),
                &mut sig_buf,
            )
            .unwrap();
        let sig_b64 = B64.encode(&sig_buf);

        // Step 7: Build the Signature element. Inserted immediately after
        // </saml:Issuer> with no leading whitespace (see whitespace design note).
        let signature_xml = format!(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info_xml}<ds:SignatureValue>{sig_b64}</ds:SignatureValue></ds:Signature>"#
        );

        // Step 8: Build the complete assertion.
        // The Signature is inserted immediately after </saml:Issuer> — no extra
        // whitespace text node is added before or after the Signature element.
        let issuer_close = format!("<saml:Issuer>{issuer}</saml:Issuer>");
        let assertion_with_sig = assertion_without_sig.replacen(
            &issuer_close,
            &format!("{issuer_close}{signature_xml}"),
            1,
        );

        // Step 9: Wrap in a <samlp:Response>.
        format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{response_id}" Version="2.0" IssueInstant="{not_before}" Destination="{destination}" InResponseTo="{in_response_to}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  {assertion_with_sig}
</samlp:Response>"#
        )
    }

    /// Build a `SamlProvider` for the test IdP/SP configuration.
    fn test_provider(cert_der: Vec<u8>) -> super::super::SamlProvider {
        use crate::services::idp::saml::IdpMetadata;
        super::super::SamlProvider {
            idp_metadata: IdpMetadata {
                entity_id: "https://idp.example.com".to_string(),
                sso_post_url: Some("https://idp.example.com/sso".to_string()),
                sso_redirect_url: None,
                signing_certificates: vec![cert_der],
            },
            sp_entity_id: "https://vouch.example.com".to_string(),
            acs_url: "https://vouch.example.com/saml/acs".to_string(),
            email_attribute: None,
            domain_attribute: None,
        }
    }

    /// Returns (not_before, not_on_or_after) strings suitable for a currently-valid assertion.
    fn valid_time_window() -> (String, String) {
        let now = Timestamp::now();
        let not_before = now
            .checked_sub(jiff::Span::new().minutes(5))
            .unwrap()
            .strftime("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let not_on_or_after = now
            .checked_add(jiff::Span::new().hours(1))
            .unwrap()
            .strftime("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        (not_before, not_on_or_after)
    }

    /// Happy-path: a fully-signed SAML Response must pass validation and return
    /// the correct email and domain.
    #[test]
    fn validate_saml_response_rsa_signed_happy_path() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as B64;

        let (key_pair, cert_der) = generate_test_key_and_cert();
        let provider = test_provider(cert_der);
        let (not_before, not_on_or_after) = valid_time_window();

        let xml = build_signed_saml_response(
            &key_pair,
            "alice@example.com",
            "_response001",
            "_assertion001",
            "_request001",
            "https://vouch.example.com/saml/acs",
            "https://idp.example.com",
            "https://vouch.example.com",
            &not_before,
            &not_on_or_after,
        );

        let base64_response = B64.encode(xml.as_bytes());
        let result = validate_saml_response(&base64_response, "_request001", &provider);
        let assertion = result.expect("Expected Ok");

        assert_eq!(assertion.email, "alice@example.com");
        assert_eq!(assertion.domain, Some("example.com".to_string()));
    }

    /// Tamper-detection: modifying the email in the assertion after signing must
    /// cause digest mismatch during validation.
    #[test]
    fn validate_saml_response_tampered_email_fails_digest_check() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as B64;

        let (key_pair, cert_der) = generate_test_key_and_cert();
        let provider = test_provider(cert_der);
        let (not_before, not_on_or_after) = valid_time_window();

        let xml = build_signed_saml_response(
            &key_pair,
            "alice@example.com",
            "_response002",
            "_assertion002",
            "_request002",
            "https://vouch.example.com/saml/acs",
            "https://idp.example.com",
            "https://vouch.example.com",
            &not_before,
            &not_on_or_after,
        );

        // Tamper: replace the NameID email after signing.
        let tampered_xml = xml.replace("alice@example.com", "mallory@evil.com");
        assert_ne!(xml, tampered_xml, "Tamper must actually change the XML");

        let base64_response = B64.encode(tampered_xml.as_bytes());
        let result = validate_saml_response(&base64_response, "_request002", &provider);

        assert!(
            result.is_err(),
            "Expected Err for tampered assertion, got Ok"
        );
        let err = result.unwrap_err();
        // The digest of the canonicalized assertion will not match what was signed.
        assert!(
            matches!(
                err,
                ResponseError::SignatureInvalid(
                    super::super::signature::SignatureError::DigestMismatch
                )
            ),
            "Expected DigestMismatch for tampered assertion, got: {err}"
        );
    }

    // =========================================================================
    // Gap tests: Conditions required, Subject required, size limit, etc.
    // =========================================================================

    #[test]
    fn conditions_missing_element_returns_error() {
        let now = Timestamp::now();
        let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
</saml:Assertion>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        let err = validate_conditions(assertion, now).unwrap_err();
        assert!(
            matches!(err, ResponseError::Other(ref msg) if msg.contains("Conditions")),
            "Expected error for missing Conditions, got: {err}"
        );
    }

    #[test]
    fn subject_confirmation_missing_subject_returns_error() {
        let now = Timestamp::now();
        // Assertion with no Subject element at all
        let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
</saml:Assertion>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        let err = validate_subject_confirmation(
            assertion,
            "_req123",
            "https://vouch.example.com/saml/acs",
            now,
        )
        .unwrap_err();
        assert!(
            matches!(err, ResponseError::Other(ref msg) if msg.contains("Subject")),
            "Expected error for missing Subject, got: {err}"
        );
    }

    #[test]
    fn subject_confirmation_empty_children_returns_error() {
        let now = Timestamp::now();
        // Subject exists but has no SubjectConfirmation children
        let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Subject>
    <saml:NameID>user@example.com</saml:NameID>
  </saml:Subject>
</saml:Assertion>"##;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
        let err = validate_subject_confirmation(
            assertion,
            "_req123",
            "https://vouch.example.com/saml/acs",
            now,
        )
        .unwrap_err();
        assert!(
            matches!(err, ResponseError::Other(ref msg) if msg.contains("SubjectConfirmation")),
            "Expected error for zero SubjectConfirmation children, got: {err}"
        );
    }

    /// XSW mitigation: a signed Assertion that is NOT a direct child of the
    /// Response must be rejected, even if the signature itself is valid.
    ///
    /// Attack: the Signature is placed inside a wrapper Assertion (direct
    /// child of Response — an allowed position for `find_saml_signature`),
    /// but its Reference URI points to the real Assertion nested inside a
    /// Container element. Without the direct-child check the victim's
    /// identity would be accepted.
    #[test]
    fn xsw_nested_assertion_rejected() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as B64;

        let (key_pair, cert_der) = generate_test_key_and_cert();
        let provider = test_provider(cert_der);
        let (not_before, not_on_or_after) = valid_time_window();

        // Build a legitimately signed response first.
        let xml = build_signed_saml_response(
            &key_pair,
            "victim@example.com",
            "_response_xsw",
            "_assertion_xsw",
            "_request_xsw",
            "https://vouch.example.com/saml/acs",
            "https://idp.example.com",
            "https://vouch.example.com",
            &not_before,
            &not_on_or_after,
        );

        // Extract the Assertion (which contains an enveloped Signature
        // whose Reference URI is "#_assertion_xsw").
        let assertion_start = xml.find("<saml:Assertion").unwrap();
        let assertion_end = xml.find("</saml:Assertion>").unwrap() + "</saml:Assertion>".len();
        let assertion_xml = &xml[assertion_start..assertion_end];

        // Extract just the Signature from the assertion.
        let sig_start = assertion_xml.find("<ds:Signature").unwrap();
        let sig_end = assertion_xml.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
        let signature_xml = &assertion_xml[sig_start..sig_end];

        // Build the victim's assertion WITHOUT its Signature.
        let assertion_no_sig = format!(
            "{}{}",
            &assertion_xml[..sig_start],
            &assertion_xml[sig_end..],
        );

        // Construct the XSW attack payload:
        // - A wrapper Assertion (direct child of Response) holds the
        //   Signature in an allowed position.
        // - The real victim Assertion (with matching ID) is nested inside
        //   a <Container> — NOT a direct child of Response.
        let response_close_idx = xml.find("</samlp:Response>").unwrap();
        let xsw_xml = format!(
            "{}<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \
             ID=\"_wrapper\" Version=\"2.0\" IssueInstant=\"{not_before}\">\
             {signature_xml}</saml:Assertion>\
             <Container>{assertion_no_sig}</Container>\
             {}",
            &xml[..assertion_start],
            &xml[response_close_idx..],
        );

        let base64_response = B64.encode(xsw_xml.as_bytes());
        let result = validate_saml_response(&base64_response, "_request_xsw", &provider);

        assert!(result.is_err(), "Expected Err for nested Assertion XSW");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("XSW") || err_msg.contains("direct child"),
            "Expected XSW-related error, got: {err_msg}"
        );
    }

    #[test]
    fn oversized_response_returns_decode_error() {
        use crate::services::idp::saml::IdpMetadata;
        use crate::services::idp::saml::SamlProvider;

        let provider = SamlProvider {
            idp_metadata: IdpMetadata {
                entity_id: "https://idp.example.com".to_string(),
                sso_post_url: Some("https://idp.example.com/sso".to_string()),
                sso_redirect_url: None,
                signing_certificates: vec![],
            },
            sp_entity_id: "https://vouch.example.com".to_string(),
            acs_url: "https://vouch.example.com/saml/acs".to_string(),
            email_attribute: None,
            domain_attribute: None,
        };

        // Create a payload that exceeds MAX_RESPONSE_BYTES when decoded
        let oversized = vec![b'A'; MAX_RESPONSE_BYTES + 1];
        let encoded = BASE64_STANDARD.encode(&oversized);
        let err = validate_saml_response(&encoded, "_req", &provider).unwrap_err();
        assert!(
            matches!(err, ResponseError::DecodeFailed(ref msg) if msg.contains("maximum size")),
            "Expected DecodeFailed for oversized response, got: {err}"
        );
    }
}
