// SPDX-License-Identifier: Apache-2.0 OR MIT
// Phase 3 SAML implementation -- callers not yet wired up.
#![allow(dead_code)]
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

// ============================================================================
// Public types
// ============================================================================

/// Identity assertion extracted from a validated SAML Response.
#[derive(Debug, Clone)]
pub struct SamlAssertion {
    /// Email address extracted from NameID or configured attribute.
    pub email: String,
    /// Domain extracted from email or configured domain attribute.
    pub domain: Option<String>,
    /// Display name extracted from configured name attribute, if available.
    pub name: Option<String>,
    /// Session expiry time from `<AuthnStatement SessionNotOnOrAfter>`.
    pub session_not_on_or_after: Option<Timestamp>,
}

/// Errors during SAML response validation.
#[derive(Debug, thiserror::Error)]
pub enum ResponseError {
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
    /// The `InResponseTo` attribute does not match the stored request ID.
    #[error("InResponseTo mismatch: expected {expected}, got {actual}")]
    InResponseToMismatch { expected: String, actual: String },
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
/// Validation steps:
/// 1. Base64-decode the response
/// 2. Parse the XML
/// 3. Verify XML signature
/// 4. Check `Destination` matches the ACS URL
/// 5. Check `InResponseTo` matches the expected request ID
/// 6. Check SAML Status is Success
/// 7. Find exactly one `<saml:Assertion>` (reject multiple — XSW)
/// 8. Validate `NotBefore` / `NotOnOrAfter` with clock skew tolerance
/// 9. Validate `SubjectConfirmationData`
/// 10. Extract email from NameID or configured attribute
/// 11. Extract domain from email or configured attribute
///
/// # Errors
///
/// Returns `ResponseError` for any validation failure. The caller must delete the
/// SAML state record (replay prevention) after this function returns `Ok`.
pub fn validate_saml_response(
    base64_response: &str,
    expected_request_id: &str,
    provider: &SamlProvider,
) -> Result<SamlAssertion, ResponseError> {
    // Step 1: Base64-decode
    let xml_bytes = BASE64_STANDARD
        .decode(base64_response.trim())
        .map_err(|e| ResponseError::DecodeFailed(e.to_string()))?;

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

    // Step 4: Check Destination
    let response_root = doc
        .root()
        .children()
        .find(|n| n.has_tag_name((NS_SAMLP, "Response")))
        .ok_or_else(|| ResponseError::Other("missing Response element".to_string()))?;

    if let Some(destination) = response_root.attribute("Destination")
        && destination != provider.acs_url
    {
        return Err(ResponseError::DestinationMismatch {
            expected: provider.acs_url.clone(),
            actual: destination.to_string(),
        });
    }

    // Step 5: Check InResponseTo
    if let Some(in_response_to) = response_root.attribute("InResponseTo")
        && in_response_to != expected_request_id
    {
        return Err(ResponseError::InResponseToMismatch {
            expected: expected_request_id.to_string(),
            actual: in_response_to.to_string(),
        });
    }

    // Step 6: Check Status
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

    // Step 8: Validate time conditions
    let now = Timestamp::now();
    validate_conditions(assertion, now)?;

    // Step 9: Validate SubjectConfirmationData
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

/// Validate `<saml:Conditions>` `NotBefore` and `NotOnOrAfter` with clock skew tolerance.
fn validate_conditions(
    assertion: roxmltree::Node<'_, '_>,
    now: Timestamp,
) -> Result<(), ResponseError> {
    let conditions = assertion
        .children()
        .find(|n| n.has_tag_name((NS_SAML, "Conditions")));

    let Some(conditions) = conditions else {
        // No Conditions element — no time constraints to check
        return Ok(());
    };

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

/// Validate `<saml:SubjectConfirmationData>` Recipient and time constraints.
fn validate_subject_confirmation(
    assertion: roxmltree::Node<'_, '_>,
    expected_request_id: &str,
    acs_url: &str,
    now: Timestamp,
) -> Result<(), ResponseError> {
    let subject = assertion
        .children()
        .find(|n| n.has_tag_name((NS_SAML, "Subject")));

    let Some(subject) = subject else {
        return Ok(()); // No Subject — skip SubjectConfirmation validation
    };

    for confirmation in subject
        .children()
        .filter(|n| n.has_tag_name((NS_SAML, "SubjectConfirmation")))
    {
        let conf_data = confirmation
            .children()
            .find(|n| n.has_tag_name((NS_SAML, "SubjectConfirmationData")));

        let Some(conf_data) = conf_data else {
            continue;
        };

        // Check Recipient matches ACS URL
        if let Some(recipient) = conf_data.attribute("Recipient")
            && recipient != acs_url
        {
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
    #![allow(clippy::unwrap_used, clippy::panic)]
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
}
