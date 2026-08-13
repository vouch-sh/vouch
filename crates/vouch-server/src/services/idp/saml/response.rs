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
    /// The `<saml:NameID>` text, when present. Paired with the IdP
    /// entity ID this is the stable upstream identity used for account
    /// matching (unless the format is transient — see `name_id_format`).
    pub name_id: Option<String>,
    /// The NameID `Format` attribute, when present. Transient-format
    /// NameIDs change on every login and must not be bound as identity.
    pub name_id_format: Option<String>,
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

    // After verification, re-resolve signed element by ID (XSW mitigation).
    // Deliberately the same lookup verify_xml_signature used, so the element we
    // consume is provably the element that was verified.
    let signed_element =
        super::signature::find_element_by_id(&doc, &signed_id.0).ok_or_else(|| {
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

    // Step 10: Extract email
    let email = extract_email(assertion, provider.email_attribute.as_deref())?;

    // Step 11: Extract domain
    let domain = extract_domain(assertion, provider.domain_attribute.as_deref(), &email);

    // Step 12: Extract the NameID and its Format for identity binding.
    let (name_id, name_id_format) = match extract_name_id(assertion) {
        Some((id, format)) => (Some(id), format),
        None => (None, None),
    };

    Ok(SamlAssertion {
        email,
        domain,
        name_id,
        name_id_format,
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
/// SAML Core Section 2.4.1: A `<Subject>` containing more than one
/// `<SubjectConfirmation>` is considered confirmed if **any one** of those
/// `<SubjectConfirmation>` elements is satisfied. This iterates every
/// `<SubjectConfirmation>` and returns `Ok` as soon as one passes all bearer
/// checks; it only returns an error when none are valid.
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

    // SAML Core 2.4.1: A Subject with multiple SubjectConfirmation elements
    // is considered confirmed if ANY ONE is satisfied. Try each one and
    // return Ok as soon as a bearer SubjectConfirmation passes all checks.
    // Only error if none are valid; surface the first error encountered so
    // single-confirmation failures still report a specific cause.
    let mut first_error: Option<ResponseError> = None;
    for confirmation in confirmations {
        match validate_single_subject_confirmation(confirmation, expected_request_id, acs_url, now)
        {
            Ok(()) => return Ok(()),
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }

    Err(first_error.unwrap_or_else(|| {
        ResponseError::Other("no valid bearer SubjectConfirmation found".to_string())
    }))
}

/// Validate a single `<saml:SubjectConfirmation>` element as a bearer
/// confirmation suitable for Web Browser SSO.
///
/// SAML Core Section 2.4.1.2: The Method MUST be bearer.
/// SAML Profiles Section 4.1.4.3: SubjectConfirmationData Recipient,
/// InResponseTo, and NotOnOrAfter MUST be validated.
fn validate_single_subject_confirmation(
    confirmation: roxmltree::Node<'_, '_>,
    expected_request_id: &str,
    acs_url: &str,
    now: Timestamp,
) -> Result<(), ResponseError> {
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
        ResponseError::Other("missing Recipient in SubjectConfirmationData (required)".to_string())
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
    extract_name_id(assertion)
        .map(|(id, _format)| id)
        .ok_or(ResponseError::NoEmail)
}

/// Extract the `<saml:Subject>/<saml:NameID>` text and its `Format`
/// attribute. Returns `None` when the element is missing or empty.
fn extract_name_id(assertion: roxmltree::Node<'_, '_>) -> Option<(String, Option<String>)> {
    let node = assertion
        .children()
        .find(|n| n.has_tag_name((NS_SAML, "Subject")))
        .and_then(|s| s.children().find(|n| n.has_tag_name((NS_SAML, "NameID"))))?;
    let text = node.text().map(str::trim).filter(|s| !s.is_empty())?;
    let format = node.attribute("Format").map(str::to_string);
    Some((text.to_string(), format))
}

/// Extract the domain from the assertion or derive it from the email.
///
/// Normalizes the result to ASCII lowercase so org lookups match regardless
/// of the case the IdP returned.
fn extract_domain(
    assertion: roxmltree::Node<'_, '_>,
    domain_attribute: Option<&str>,
    email: &str,
) -> Option<String> {
    // Try configured domain attribute
    if let Some(attr_name) = domain_attribute
        && let Some(value) = find_saml_attribute(assertion, attr_name)
    {
        return Some(value.to_ascii_lowercase());
    }

    // Derive from email address (last-`@` split, matching the audit and
    // org-domain layers)
    crate::email::Email::domain_of(email)
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
mod tests;
