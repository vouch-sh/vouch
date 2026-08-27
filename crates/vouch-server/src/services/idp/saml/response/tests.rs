// SPDX-License-Identifier: Apache-2.0 OR MIT
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

// SAML Core §1.3.3: instants are UTC xsd:dateTime values.
#[test]
fn parse_saml_timestamp_utc() {
    let ts = parse_saml_timestamp("2026-03-19T12:00:00Z").unwrap();
    assert_eq!(ts.to_string(), "2026-03-19T12:00:00Z");
}

// SAML Core §1.3.3: fractional seconds are permitted.
#[test]
fn parse_saml_timestamp_with_milliseconds() {
    let ts = parse_saml_timestamp("2026-03-19T12:00:00.000Z").unwrap();
    assert_eq!(ts.to_string(), "2026-03-19T12:00:00Z");
}

// SAML Core §1.3.3: a value that is not an xsd:dateTime is rejected.
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

// SAML Core §3.2.2.2: the top-level status code reports whether the request succeeded.
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

// SAML Core §3.2.2.2: a non-Success status is not an authentication.
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

// SAML Core §2.5.1: the assertion is used only inside its validity window.
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

// SAML Core §2.5.1: an assertion past NotOnOrAfter is rejected.
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

// SAML Core §2.5.1: an assertion before NotBefore is rejected.
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

// SAML Core §2.5.1: a bounded clock skew allowance is applied to the window.
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

// SAML Core §2.2.2: the subject identifier carries the principal's name.
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

// SAML Core §2.7.3: an attribute statement can carry the principal's name.
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

// SAML Core §2.7.3: a configured attribute is preferred over the subject identifier.
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

// SAML Profiles §4.1.4: an assertion with no usable identity is rejected.
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

// SAML Core §2.2.2: the identity is parsed out of the subject identifier.
#[test]
fn domain_extracted_from_email() {
    let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
    "##;
    let doc = roxmltree::Document::parse(xml).unwrap();
    let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
    let domain = extract_domain(assertion, None, "user@example.com");
    assert_eq!(domain, Some("example.com".to_string()));
}

// SAML Core §2.7.3: the identity is parsed out of the named attribute.
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

/// Regression: mixed-case configured-attribute value must be lowercased
/// so org lookups (which match against the lowercase-stored primary or
/// additional domain) find the right org.
// SAML Core §2.7.3: the domain is compared case-insensitively.
#[test]
fn domain_from_configured_attribute_is_lowercased() {
    let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:AttributeStatement>
<saml:Attribute Name="domain">
  <saml:AttributeValue>CORP.Example.COM</saml:AttributeValue>
</saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>"##;
    let doc = roxmltree::Document::parse(xml).unwrap();
    let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
    let domain = extract_domain(assertion, Some("domain"), "user@example.com");
    assert_eq!(domain, Some("corp.example.com".to_string()));
}

/// Regression: when falling back to the email domain, the extracted
/// domain must be lowercased.
// SAML Core §2.2.2: the domain is compared case-insensitively.
#[test]
fn domain_from_email_fallback_is_lowercased() {
    let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
    "##;
    let doc = roxmltree::Document::parse(xml).unwrap();
    let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
    let domain = extract_domain(assertion, None, "Alice@CORP.Example.COM");
    assert_eq!(domain, Some("corp.example.com".to_string()));
}

// =========================================================================
// Destination validation tests (via validate_saml_response)
// =========================================================================

// SAML Core §3.2.2: the recipient checks that Destination names where the message was delivered.
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

// SAML Core §3.2.2: InResponseTo must match the ID of the request that provoked it.
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

// SAML Profiles §4.1.4: the response carries the assertions the profile expects.
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

// SAML Bindings §3.5.4: the SAMLResponse form control is base64 encoded.
#[test]
fn invalid_base64_returns_decode_error() {
    use crate::services::idp::saml::IdpMetadata;
    use crate::services::idp::saml::SamlProvider;

    let provider = SamlProvider {
        id: "corp-saml".to_string(),
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

// SAML Bindings §3.5.4: the decoded form control is a SAML protocol message.
#[test]
fn invalid_xml_returns_xml_parse_error() {
    use crate::services::idp::saml::IdpMetadata;
    use crate::services::idp::saml::SamlProvider;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

    let provider = SamlProvider {
        id: "corp-saml".to_string(),
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

// SAML Core §2.3.3: the assertion Issuer identifies the issuing identity provider.
#[test]
fn issuer_matching_passes() {
    let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
</saml:Assertion>"##;
    let doc = roxmltree::Document::parse(xml).unwrap();
    let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
    assert!(validate_issuer(assertion, "https://idp.example.com").is_ok());
}

// SAML Core §2.3.3: an assertion from an unexpected issuer is rejected.
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

// SAML Core §2.3.3: the Issuer element is required on an assertion.
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

// SAML Core §2.5.1.4: the service provider must be an intended audience.
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

// SAML Core §2.5.1.4: an assertion addressed to another audience is rejected.
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
    let err = validate_audience_restriction(assertion, "https://vouch.example.com").unwrap_err();
    assert!(
        matches!(err, ResponseError::AudienceRestrictionViolation { .. }),
        "Expected AudienceRestrictionViolation, got: {err}"
    );
}

// SAML Core §2.5.1.4: one matching Audience satisfies the restriction.
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

// SAML Core §2.5.1.4: an assertion with no audience restriction is not accepted.
#[test]
fn audience_restriction_absent_conditions_returns_error() {
    // No Conditions element — now required per SAML Profiles 4.1.4.3
    let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>"##;
    let doc = roxmltree::Document::parse(xml).unwrap();
    let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
    let err = validate_audience_restriction(assertion, "https://vouch.example.com").unwrap_err();
    assert!(
        matches!(err, ResponseError::Other(_)),
        "Expected error for missing Conditions, got: {err}"
    );
}

// SAML Core §2.5.1.4: conditions without an AudienceRestriction are not accepted.
#[test]
fn audience_restriction_conditions_without_restriction_returns_error() {
    // Conditions exists but no AudienceRestriction — now required
    let xml = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Conditions NotBefore="2026-01-01T00:00:00Z"/>
</saml:Assertion>"##;
    let doc = roxmltree::Document::parse(xml).unwrap();
    let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
    let err = validate_audience_restriction(assertion, "https://vouch.example.com").unwrap_err();
    assert!(
        matches!(err, ResponseError::AudienceRestrictionViolation { .. }),
        "Expected AudienceRestrictionViolation, got: {err}"
    );
}

// =========================================================================
// SubjectConfirmation Method validation tests (SAML Core 2.4.1.2)
// =========================================================================

// SAML Profiles §4.1.4: the subject is confirmed by the bearer method.
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
            now,
        )
        .is_ok()
    );
}

// SAML Profiles §4.1.4: a confirmation method other than bearer is not accepted.
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

// SAML Core §2.4.1.2: SubjectConfirmation names a confirmation method.
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
// Multiple SubjectConfirmation tests (SAML Core 2.4.1: "any one" semantics)
// =========================================================================

/// Helper: build an assertion XML string whose `<saml:Subject>` contains the
/// given `<saml:SubjectConfirmation>` fragments verbatim. Callers parse the
/// returned string in their own scope so the borrowed `Node` outlives use.
fn assertion_with_subject_confirmations(confirmations_xml: &str) -> String {
    format!(
        r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Subject>
{confirmations_xml}
  </saml:Subject>
</saml:Assertion>"##
    )
}

/// SAML Core 2.4.1: a Subject with multiple SubjectConfirmation elements is
/// confirmed if ANY ONE is satisfied. The first bearer here has a wrong
/// Recipient (fails), the second is fully valid — the assertion MUST pass.
// SAML Profiles §4.1.4: one satisfied bearer confirmation is enough.
#[test]
fn subject_confirmation_multiple_one_valid_bearer_passes() {
    let now = Timestamp::now();
    let future = now
        .checked_add(jiff::Span::new().hours(1))
        .unwrap()
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let acs = "https://vouch.example.com/saml/acs";
    let wrong = "https://wrong.example.com/saml/acs";
    let confirmations = format!(
        r#"<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
  <saml:SubjectConfirmationData Recipient="{wrong}" InResponseTo="_req123" NotOnOrAfter="{future}"/>
</saml:SubjectConfirmation>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
  <saml:SubjectConfirmationData Recipient="{acs}" InResponseTo="_req123" NotOnOrAfter="{future}"/>
</saml:SubjectConfirmation>"#
    );
    let xml = assertion_with_subject_confirmations(&confirmations);
    let doc = roxmltree::Document::parse(&xml).unwrap();
    let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
    let result = validate_subject_confirmation(assertion, "_req123", acs, now);
    assert!(
        result.is_ok(),
        "Expected Ok when at least one SubjectConfirmation is valid, got: {result:?}"
    );
}

/// When every bearer SubjectConfirmation fails (all Recipients wrong), the
/// assertion MUST be rejected.
// SAML Core §2.4.1.2: Recipient must name this service provider's endpoint.
#[test]
fn subject_confirmation_multiple_all_invalid_recipient_returns_error() {
    let now = Timestamp::now();
    let future = now
        .checked_add(jiff::Span::new().hours(1))
        .unwrap()
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let acs = "https://vouch.example.com/saml/acs";
    let wrong1 = "https://wrong1.example.com/saml/acs";
    let wrong2 = "https://wrong2.example.com/saml/acs";
    let confirmations = format!(
        r#"<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
  <saml:SubjectConfirmationData Recipient="{wrong1}" InResponseTo="_req123" NotOnOrAfter="{future}"/>
</saml:SubjectConfirmation>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
  <saml:SubjectConfirmationData Recipient="{wrong2}" InResponseTo="_req123" NotOnOrAfter="{future}"/>
</saml:SubjectConfirmation>"#
    );
    let xml = assertion_with_subject_confirmations(&confirmations);
    let doc = roxmltree::Document::parse(&xml).unwrap();
    let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
    let err = validate_subject_confirmation(assertion, "_req123", acs, now).unwrap_err();
    assert!(
        matches!(err, ResponseError::DestinationMismatch { .. }),
        "Expected DestinationMismatch when all Recipients are wrong, got: {err}"
    );
}

/// Mixed methods: a non-bearer (holder-of-key) SubjectConfirmation followed by
/// a valid bearer one. Vouch supports only bearer, but per SAML Core 2.4.1 the
/// assertion is confirmed by the valid bearer SubjectConfirmation.
// SAML Profiles §4.1.4: a satisfied bearer confirmation among others is enough.
#[test]
fn subject_confirmation_mixed_methods_one_valid_bearer_passes() {
    let now = Timestamp::now();
    let future = now
        .checked_add(jiff::Span::new().hours(1))
        .unwrap()
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let acs = "https://vouch.example.com/saml/acs";
    let confirmations = format!(
        r#"<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:holder-of-key">
  <saml:SubjectConfirmationData Recipient="{acs}" InResponseTo="_req123" NotOnOrAfter="{future}"/>
</saml:SubjectConfirmation>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
  <saml:SubjectConfirmationData Recipient="{acs}" InResponseTo="_req123" NotOnOrAfter="{future}"/>
</saml:SubjectConfirmation>"#
    );
    let xml = assertion_with_subject_confirmations(&confirmations);
    let doc = roxmltree::Document::parse(&xml).unwrap();
    let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
    let result = validate_subject_confirmation(assertion, "_req123", acs, now);
    assert!(
        result.is_ok(),
        "Expected Ok when a bearer SubjectConfirmation is present alongside a non-bearer one, got: {result:?}"
    );
}

/// The first bearer SubjectConfirmation is expired (NotOnOrAfter in the past,
/// beyond clock skew), the second is valid. Per "any one" semantics the
/// assertion MUST be accepted via the second.
// SAML Core §2.4.1.2: an expired confirmation does not disqualify a valid one.
#[test]
fn subject_confirmation_multiple_first_expired_second_valid_passes() {
    let now = Timestamp::now();
    let future = now
        .checked_add(jiff::Span::new().hours(1))
        .unwrap()
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let expired = now
        .checked_sub(jiff::Span::new().hours(1))
        .unwrap()
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let acs = "https://vouch.example.com/saml/acs";
    let confirmations = format!(
        r#"<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
  <saml:SubjectConfirmationData Recipient="{acs}" InResponseTo="_req123" NotOnOrAfter="{expired}"/>
</saml:SubjectConfirmation>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
  <saml:SubjectConfirmationData Recipient="{acs}" InResponseTo="_req123" NotOnOrAfter="{future}"/>
</saml:SubjectConfirmation>"#
    );
    let xml = assertion_with_subject_confirmations(&confirmations);
    let doc = roxmltree::Document::parse(&xml).unwrap();
    let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
    let result = validate_subject_confirmation(assertion, "_req123", acs, now);
    assert!(
        result.is_ok(),
        "Expected Ok when a later SubjectConfirmation is valid despite an expired first one, got: {result:?}"
    );
}

// =========================================================================
// New error variant display tests
// =========================================================================

// SAML Core §3.2.2: a missing Destination is reported as such.
#[test]
fn missing_destination_error_displays_correctly() {
    let err = ResponseError::MissingDestination;
    assert!(err.to_string().contains("Destination"));
}

// SAML Core §3.2.2: a missing InResponseTo is reported as such.
#[test]
fn missing_in_response_to_error_displays_correctly() {
    let err = ResponseError::MissingInResponseTo;
    assert!(err.to_string().contains("InResponseTo"));
}

// SAML Core §2.3.3: an issuer mismatch is reported as such.
#[test]
fn issuer_mismatch_error_displays_correctly() {
    let err = ResponseError::IssuerMismatch {
        expected: "https://idp.example.com".to_string(),
        actual: "https://evil.example.com".to_string(),
    };
    assert!(err.to_string().contains("issuer mismatch"));
}

// SAML Core §2.5.1.4: an audience mismatch is reported as such.
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
    subject_confirmation_in_response_to: Option<&str>,
) -> String {
    use aws_lc_rs::digest;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;

    // Build the optional InResponseTo attribute for SubjectConfirmationData.
    // When None, the attribute is omitted entirely (tests the case where an
    // IdP legitimately excludes it).
    let scd_irt_attr = match subject_confirmation_in_response_to {
        Some(irt) => format!(r#" InResponseTo="{irt}""#),
        None => String::new(),
    };

    // Step 1: Build the assertion XML *without* the Signature element.
    // The Signature will be inserted immediately after </saml:Issuer> without
    // adding any extra whitespace text nodes around it (see whitespace design note).
    let assertion_body = format!(
        r#"
  <saml:Issuer>{issuer}</saml:Issuer>
  <saml:Subject>
<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress">{email}</saml:NameID>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
  <saml:SubjectConfirmationData Recipient="{destination}"{scd_irt_attr} NotOnOrAfter="{not_on_or_after}"/>
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
    let assertion_with_sig =
        assertion_without_sig.replacen(&issuer_close, &format!("{issuer_close}{signature_xml}"), 1);

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

/// Construct a SAML Response where the **Response** element itself is signed
/// (not just the Assertion). The Signature is a direct child of the Response,
/// and the Reference URI points to the Response ID.
///
/// Used to test the complement case: when the Response is signed,
/// `Response.InResponseTo` is covered by the signature, so
/// `SubjectConfirmationData.InResponseTo` is NOT required.
///
/// Follows the same whitespace design as `build_signed_saml_response`: the
/// Signature is inserted immediately after the Response-level `</saml:Issuer>`
/// with no extra whitespace text nodes, so the canonical form after
/// enveloped-signature exclusion matches the canonical form computed before
/// the Signature was inserted.
#[expect(
    clippy::too_many_arguments,
    reason = "test helper builds SAML response with all signed-element parameters"
)]
fn build_response_signed_saml_response(
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
    subject_confirmation_in_response_to: Option<&str>,
) -> String {
    use aws_lc_rs::digest;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;

    let scd_irt_attr = match subject_confirmation_in_response_to {
        Some(irt) => format!(r#" InResponseTo="{irt}""#),
        None => String::new(),
    };

    // Step 1: Build the Assertion WITHOUT a Signature (the Response will be signed).
    let assertion_xml = format!(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}" Version="2.0" IssueInstant="{not_before}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <saml:Subject>
<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress">{email}</saml:NameID>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
  <saml:SubjectConfirmationData Recipient="{destination}"{scd_irt_attr} NotOnOrAfter="{not_on_or_after}"/>
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
</saml:Assertion>"#
    );

    // Step 2: Build the Response WITHOUT the Signature element.
    let response_without_sig = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{response_id}" Version="2.0" IssueInstant="{not_before}" Destination="{destination}" InResponseTo="{in_response_to}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Status>
<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  {assertion_xml}
</samlp:Response>"#
    );

    // Step 3: Canonicalize the Response (exc-c14n, no inclusive prefixes).
    let doc_no_sig = roxmltree::Document::parse(&response_without_sig).unwrap();
    let response_node = doc_no_sig
        .root()
        .children()
        .find(|n| n.is_element())
        .unwrap();
    let canonical_response = super::super::c14n::exclusive_c14n(response_node, &[]);

    // Step 4: Compute SHA-256 digest over canonicalized Response.
    let digest_bytes = digest::digest(&digest::SHA256, canonical_response.as_bytes());
    let digest_b64 = B64.encode(digest_bytes.as_ref());

    // Step 5: Build SignedInfo with the computed digest. Reference URI = #response_id.
    let ref_uri = format!("#{response_id}");
    let signed_info_xml = format!(
        r#"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="{ref_uri}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>{digest_b64}</ds:DigestValue></ds:Reference></ds:SignedInfo>"#
    );

    // Step 6: Canonicalize SignedInfo.
    let doc_si = roxmltree::Document::parse(&signed_info_xml).unwrap();
    let signed_info_node = doc_si.root().children().find(|n| n.is_element()).unwrap();
    let canonical_signed_info = super::super::c14n::exclusive_c14n(signed_info_node, &[]);

    // Step 7: Sign the canonical SignedInfo with RSA-PKCS1-SHA256.
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

    // Step 8: Build the Signature element.
    let signature_xml = format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info_xml}<ds:SignatureValue>{sig_b64}</ds:SignatureValue></ds:Signature>"#
    );

    // Step 9: Insert the Signature immediately after the Response-level
    // </saml:Issuer> with no extra whitespace (same whitespace design as
    // build_signed_saml_response). replacen with count 1 targets the
    // Response-level Issuer (which precedes the Assertion-level Issuer).
    let issuer_close = format!("<saml:Issuer>{issuer}</saml:Issuer>");
    response_without_sig.replacen(&issuer_close, &format!("{issuer_close}{signature_xml}"), 1)
}

/// Build a `SamlProvider` for the test IdP/SP configuration.
fn test_provider(cert_der: Vec<u8>) -> super::super::SamlProvider {
    use crate::services::idp::saml::IdpMetadata;
    super::super::SamlProvider {
        id: "corp-saml".to_string(),
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
// XML Signature §3.2.2: a correctly signed response validates.
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
        Some("_request001"),
    );

    let base64_response = B64.encode(xml.as_bytes());
    let result = validate_saml_response(&base64_response, "_request001", &provider);
    let assertion = result.expect("Expected Ok");

    assert_eq!(assertion.email, "alice@example.com");
    assert_eq!(assertion.domain, Some("example.com".to_string()));
    // NameID and its Format must be captured for identity binding.
    assert_eq!(assertion.name_id.as_deref(), Some("alice@example.com"));
    assert_eq!(
        assertion.name_id_format.as_deref(),
        Some("urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"),
    );
}

/// The NameID extractor returns the text and Format together, and
/// `None` when the Format attribute is absent.
// SAML Core §2.2.2: the identifier carries a Format and a value.
#[test]
fn extract_name_id_reads_text_and_format() {
    let with_format = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">stable-id-1</saml:NameID>
        </saml:Subject>
    </saml:Assertion>"#;
    let doc = roxmltree::Document::parse(with_format).expect("parse");
    let assertion = doc.root_element();
    let (id, format) = super::extract_name_id(assertion).expect("name id present");
    assert_eq!(id, "stable-id-1");
    assert_eq!(
        format.as_deref(),
        Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
    );

    let no_format = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Subject>
            <saml:NameID>bare-id</saml:NameID>
        </saml:Subject>
    </saml:Assertion>"#;
    let doc = roxmltree::Document::parse(no_format).expect("parse");
    let (id, format) = super::extract_name_id(doc.root_element()).expect("name id present");
    assert_eq!(id, "bare-id");
    assert_eq!(format, None);
}

/// An XML comment splits an element's text into multiple text nodes, but
/// canonicalization concatenates them all and drops the comment — so the
/// signature stays valid over the whole value. Every extractor must read the
/// whole value too; reading only the first text node would let a holder of a
/// legitimately signed assertion truncate it to another user's identity
/// (CVE-2017-11427 class).
// XML Signature §3.2.1: the verifier reads the same characters the digest covers.
#[test]
fn comment_split_text_is_read_whole_not_truncated() {
    let assertion_xml = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Issuer>https://idp.example.com<!---->.evil.tld</saml:Issuer>
        <saml:Subject>
            <saml:NameID>alice@example.com<!---->.evil.tld</saml:NameID>
        </saml:Subject>
        <saml:Conditions>
            <saml:AudienceRestriction>
                <saml:Audience>https://vouch.example.com<!---->.evil.tld</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AttributeStatement>
            <saml:Attribute Name="email">
                <saml:AttributeValue>alice@example.com<!---->.evil.tld</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>"#;
    let doc = roxmltree::Document::parse(assertion_xml).expect("parse");
    let assertion = doc.root_element();

    let (name_id, _format) = super::extract_name_id(assertion).expect("name id present");
    assert_eq!(
        name_id, "alice@example.com.evil.tld",
        "NameID must be the whole signed value, not the prefix before the comment"
    );

    let attr = super::find_saml_attribute(assertion, "email").expect("attribute present");
    assert_eq!(
        attr, "alice@example.com.evil.tld",
        "AttributeValue must be the whole signed value"
    );

    // The audience is not the SP entity ID, so the restriction must not match.
    assert!(
        super::validate_audience_restriction(assertion, "https://vouch.example.com").is_err(),
        "An Audience of https://vouch.example.com.evil.tld must not satisfy \
         https://vouch.example.com"
    );

    // The issuer is not the configured entity ID, so it must not match.
    assert!(
        super::validate_issuer(assertion, "https://idp.example.com").is_err(),
        "An Issuer of https://idp.example.com.evil.tld must not satisfy \
         https://idp.example.com"
    );

    // A leading comment puts the text after a comment node rather than
    // splitting it. The value is still fully signed, so it must still be read.
    let leading = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Subject>
            <saml:NameID><!---->alice@example.com</saml:NameID>
        </saml:Subject>
    </saml:Assertion>"#;
    let doc = roxmltree::Document::parse(leading).expect("parse");
    let (id, _) = super::extract_name_id(doc.root_element()).expect("name id present");
    assert_eq!(id, "alice@example.com");
}

/// End-to-end: injecting a comment into the NameID of a *validly signed*
/// assertion keeps the signature valid (canonicalization drops comments), so
/// the attack has to be stopped by reading the whole value. The resulting
/// identity must be the full attacker-controlled string, never the victim
/// prefix.
// XML Signature §3.2.1: a comment node must not change the identity the verifier reads.
#[test]
fn validate_saml_response_comment_injection_does_not_truncate_identity() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;

    let (key_pair, cert_der) = generate_test_key_and_cert();
    let provider = test_provider(cert_der);
    let (not_before, not_on_or_after) = valid_time_window();

    let xml = build_signed_saml_response(
        &key_pair,
        "attacker@example.com.evil.tld",
        "_response003",
        "_assertion003",
        "_request003",
        "https://vouch.example.com/saml/acs",
        "https://idp.example.com",
        "https://vouch.example.com",
        &not_before,
        &not_on_or_after,
        Some("_request003"),
    );

    // Split the signed NameID with a comment, aiming to truncate the identity
    // down to the victim's address. The signature is untouched.
    let injected_xml = xml.replace(
        "attacker@example.com.evil.tld",
        "attacker@example.com<!---->.evil.tld",
    );
    assert_ne!(xml, injected_xml, "Injection must actually change the XML");

    let base64_response = B64.encode(injected_xml.as_bytes());
    let assertion = validate_saml_response(&base64_response, "_request003", &provider)
        .expect("comment injection leaves the signature valid, so validation succeeds");

    assert_eq!(
        assertion.email, "attacker@example.com.evil.tld",
        "Identity must be the whole signed value; truncating to \
         attacker@example.com would authenticate as a different user"
    );
    assert_eq!(
        assertion.name_id.as_deref(),
        Some("attacker@example.com.evil.tld")
    );
}

/// Tamper-detection: modifying the email in the assertion after signing must
/// cause digest mismatch during validation.
// XML Signature §3.2.1: altering signed content breaks the reference digest.
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
        Some("_request002"),
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

// SAML Profiles §4.1.4: the assertion must carry conditions the service provider can evaluate.
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

// SAML Profiles §4.1.4: the assertion must carry a Subject the profile can confirm.
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

// SAML Core §2.4.1.2: a Subject with no SubjectConfirmation cannot be confirmed.
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
// SAML Core §5: a signature must cover the assertion that is relied upon.
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
        Some("_request_xsw"),
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

// SAML Bindings §3.5.4: the decoded message size is bounded.
#[test]
fn oversized_response_returns_decode_error() {
    use crate::services::idp::saml::IdpMetadata;
    use crate::services::idp::saml::SamlProvider;

    let provider = SamlProvider {
        id: "corp-saml".to_string(),
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

// =========================================================================
// InResponseTo XSW vulnerability tests
//
// When only the Assertion is signed (Response is unsigned), the
// Response.InResponseTo attribute is not covered by any signature and can be
// modified without invalidating the assertion signature. In that case,
// SubjectConfirmationData.InResponseTo (inside the signed Assertion) is
// REQUIRED as the signed binding to the expected request ID.
// =========================================================================

/// The new error variant must produce a helpful, searchable message.
// SAML Core §2.4.1.2: a missing InResponseTo is reported as such.
#[test]
fn missing_subject_confirmation_in_response_to_error_displays_correctly() {
    let err = ResponseError::MissingSubjectConfirmationInResponseTo;
    let msg = err.to_string();
    assert!(
        msg.contains("InResponseTo"),
        "Should mention InResponseTo: {msg}"
    );
    assert!(
        msg.contains("SubjectConfirmationData"),
        "Should mention SubjectConfirmationData: {msg}"
    );
    assert!(
        msg.contains("not signed"),
        "Should mention the unsigned-Response condition: {msg}"
    );
}

// --- Unit tests for the require_irt parameter ---

/// When `require_irt` is true and SubjectConfirmationData.InResponseTo is
/// absent, validation MUST fail with MissingSubjectConfirmationInResponseTo.
// SAML Core §2.4.1.2: bearer confirmation data carries InResponseTo when the request is known.
#[test]
fn subject_confirmation_require_irt_missing_irt_returns_error() {
    let now = Timestamp::now();
    let future = now
        .checked_add(jiff::Span::new().hours(1))
        .unwrap()
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    // SCD has Recipient and NotOnOrAfter but NO InResponseTo.
    let xml = format!(
        r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Subject>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
  <saml:SubjectConfirmationData Recipient="https://vouch.example.com/saml/acs" NotOnOrAfter="{future}"/>
</saml:SubjectConfirmation>
  </saml:Subject>
</saml:Assertion>"##
    );
    let doc = roxmltree::Document::parse(&xml).unwrap();
    let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
    let err = validate_subject_confirmation(
        assertion,
        "_req123",
        "https://vouch.example.com/saml/acs",
        now,
    )
    .unwrap_err();
    assert!(
        matches!(err, ResponseError::MissingSubjectConfirmationInResponseTo),
        "Expected MissingSubjectConfirmationInResponseTo, got: {err}"
    );
}

/// When `require_irt` is true and SubjectConfirmationData.InResponseTo is
/// present and matches, validation MUST pass.
// SAML Core §2.4.1.2: a matching InResponseTo confirms the subject.
#[test]
fn subject_confirmation_require_irt_present_matching_passes() {
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
  <saml:SubjectConfirmationData Recipient="https://vouch.example.com/saml/acs" InResponseTo="_req123" NotOnOrAfter="{future}"/>
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
            now,
        )
        .is_ok()
    );
}

/// When `require_irt` is true and SubjectConfirmationData.InResponseTo is
/// present but wrong, validation MUST fail with InResponseToMismatch.
// SAML Core §2.4.1.2: an InResponseTo naming another request is rejected.
#[test]
fn subject_confirmation_require_irt_mismatch_fails() {
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
  <saml:SubjectConfirmationData Recipient="https://vouch.example.com/saml/acs" InResponseTo="_wrong" NotOnOrAfter="{future}"/>
</saml:SubjectConfirmation>
  </saml:Subject>
</saml:Assertion>"##
    );
    let doc = roxmltree::Document::parse(&xml).unwrap();
    let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
    let err = validate_subject_confirmation(
        assertion,
        "_req123",
        "https://vouch.example.com/saml/acs",
        now,
    )
    .unwrap_err();
    assert!(
        matches!(err, ResponseError::InResponseToMismatch { .. }),
        "Expected InResponseToMismatch, got: {err}"
    );
}

/// SAML Profiles 4.1.4.3 requires the bearer SubjectConfirmationData to
/// carry InResponseTo for a solicited response, "Regardless of the SAML
/// binding used". An assertion without it is rejected whatever is signed.
// SAML Core §2.4.1.2: bearer confirmation without InResponseTo is rejected.
#[test]
fn subject_confirmation_missing_irt_is_rejected() {
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
  <saml:SubjectConfirmationData Recipient="https://vouch.example.com/saml/acs" NotOnOrAfter="{future}"/>
</saml:SubjectConfirmation>
  </saml:Subject>
</saml:Assertion>"##
    );
    let doc = roxmltree::Document::parse(&xml).unwrap();
    let assertion = doc.root().children().find(|n| n.is_element()).unwrap();
    let err = validate_subject_confirmation(
        assertion,
        "_req123",
        "https://vouch.example.com/saml/acs",
        now,
    )
    .unwrap_err();
    assert!(
        matches!(err, ResponseError::MissingSubjectConfirmationInResponseTo),
        "Expected MissingSubjectConfirmationInResponseTo, got: {err}"
    );
}

// --- End-to-end tests via validate_saml_response ---

/// CORE VULNERABILITY TEST: When only the Assertion is signed and
/// SubjectConfirmationData.InResponseTo is absent, the unsigned
/// Response.InResponseTo must NOT be trusted. Validation MUST reject.
///
/// Before the fix, this test would pass (is_ok) because the unsigned
/// Response.InResponseTo was the sole binding to the request ID. After the
/// fix, it fails with MissingSubjectConfirmationInResponseTo.
// SAML Core §2.4.1.2: an unsigned response is bound to its request through the confirmation data.
#[test]
fn xsw_inresponseto_unsigned_response_missing_scd_irt_rejected() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;

    let (key_pair, cert_der) = generate_test_key_and_cert();
    let provider = test_provider(cert_der);
    let (not_before, not_on_or_after) = valid_time_window();

    // Assertion-only signature, SCD.InResponseTo absent.
    // Response.InResponseTo = "_attacker_req" (matches expected below).
    let xml = build_signed_saml_response(
        &key_pair,
        "victim@example.com",
        "_response_irt_1",
        "_assertion_irt_1",
        "_attacker_req",
        "https://vouch.example.com/saml/acs",
        "https://idp.example.com",
        "https://vouch.example.com",
        &not_before,
        &not_on_or_after,
        None, // SubjectConfirmationData.InResponseTo is ABSENT
    );

    let base64_response = B64.encode(xml.as_bytes());
    let result = validate_saml_response(&base64_response, "_attacker_req", &provider);

    let err = result.unwrap_err();
    assert!(
        matches!(err, ResponseError::MissingSubjectConfirmationInResponseTo),
        "Expected MissingSubjectConfirmationInResponseTo (unsigned Response.InResponseTo must not be trusted), got: {err}"
    );
}

/// NO REGRESSION: When only the Assertion is signed and
/// SubjectConfirmationData.InResponseTo is present and matches, validation
/// MUST pass. This is the common IdP configuration (Azure AD, Okta, etc.).
// SAML Core §2.4.1.2: a matching confirmation InResponseTo binds the unsigned response.
#[test]
fn xsw_inresponseto_unsigned_response_with_matching_scd_irt_passes() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;

    let (key_pair, cert_der) = generate_test_key_and_cert();
    let provider = test_provider(cert_der);
    let (not_before, not_on_or_after) = valid_time_window();

    let xml = build_signed_saml_response(
        &key_pair,
        "alice@example.com",
        "_response_irt_2",
        "_assertion_irt_2",
        "_request_irt_2",
        "https://vouch.example.com/saml/acs",
        "https://idp.example.com",
        "https://vouch.example.com",
        &not_before,
        &not_on_or_after,
        Some("_request_irt_2"),
    );

    let base64_response = B64.encode(xml.as_bytes());
    let result = validate_saml_response(&base64_response, "_request_irt_2", &provider);
    let assertion = result
        .expect("Expected Ok for assertion-only signed response with matching SCD.InResponseTo");
    assert_eq!(assertion.email, "alice@example.com");
}

/// When only the Assertion is signed and SubjectConfirmationData.InResponseTo
/// is present but differs from the expected request ID, validation MUST fail
/// with InResponseToMismatch. The signed SCD.InResponseTo is the authoritative
/// binding.
// SAML Core §2.4.1.2: a mismatched confirmation InResponseTo is rejected.
#[test]
fn xsw_inresponseto_scd_irt_mismatch_fails() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;

    let (key_pair, cert_der) = generate_test_key_and_cert();
    let provider = test_provider(cert_der);
    let (not_before, not_on_or_after) = valid_time_window();

    // Response.InResponseTo = "_attacker_req" (matches expected).
    // SCD.InResponseTo = "_victim_req" (signed, differs from expected).
    let xml = build_signed_saml_response(
        &key_pair,
        "victim@example.com",
        "_response_irt_3",
        "_assertion_irt_3",
        "_attacker_req",
        "https://vouch.example.com/saml/acs",
        "https://idp.example.com",
        "https://vouch.example.com",
        &not_before,
        &not_on_or_after,
        Some("_victim_req"),
    );

    let base64_response = B64.encode(xml.as_bytes());
    let result = validate_saml_response(&base64_response, "_attacker_req", &provider);

    let err = result.unwrap_err();
    assert!(
        matches!(err, ResponseError::InResponseToMismatch { .. }),
        "Expected InResponseToMismatch (signed SCD.InResponseTo differs from expected), got: {err}"
    );
}

/// FULL ATTACK SCENARIO: An attacker with MITM capability intercepts a
/// victim's SAML response and modifies the unsigned Response.InResponseTo to
/// match the attacker's own request ID. The signed SubjectConfirmationData.
/// InResponseTo (inside the signed Assertion) still carries the victim's
/// request ID and cannot be modified without invalidating the signature.
///
/// Validation MUST reject because the signed SCD.InResponseTo does not match
/// the attacker's expected request ID.
// SAML Core §5: relocating a signed element must not transfer its protection.
#[test]
fn xsw_inresponseto_attack_scenario_rejected() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;

    let (key_pair, cert_der) = generate_test_key_and_cert();
    let provider = test_provider(cert_der);
    let (not_before, not_on_or_after) = valid_time_window();

    // Build a legitimate response for the victim.
    // Both Response.InResponseTo and SCD.InResponseTo = "_victim_req".
    let xml = build_signed_saml_response(
        &key_pair,
        "victim@example.com",
        "_response_irt_4",
        "_assertion_irt_4",
        "_victim_req",
        "https://vouch.example.com/saml/acs",
        "https://idp.example.com",
        "https://vouch.example.com",
        &not_before,
        &not_on_or_after,
        Some("_victim_req"),
    );

    // Attacker modifies the UNSIGNED Response.InResponseTo to their own
    // request ID. Only the first occurrence (Response-level) is changed;
    // the SCD-level InResponseTo is inside the signed Assertion and cannot
    // be modified without invalidating the signature.
    let attacked_xml = xml.replacen(
        r#"InResponseTo="_victim_req""#,
        r#"InResponseTo="_attacker_req""#,
        1,
    );
    assert_ne!(xml, attacked_xml, "Attack must actually change the XML");

    let base64_response = B64.encode(attacked_xml.as_bytes());
    // Attacker submits with their own request ID as expected.
    let result = validate_saml_response(&base64_response, "_attacker_req", &provider);

    let err = result.unwrap_err();
    assert!(
        matches!(err, ResponseError::InResponseToMismatch { .. }),
        "Expected InResponseToMismatch: signed SCD.InResponseTo (_victim_req) must not match \
         attacker's expected (_attacker_req). Got: {err}"
    );
}

/// Response.InResponseTo is still validated (defense-in-depth). When it
/// differs from the expected request ID (even if SCD.InResponseTo matches),
/// validation MUST fail at the Response-level check. This is existing
/// behavior that must not regress.
// SAML Core §3.2.2: the response and its assertion must agree on the request they answer.
#[test]
fn xsw_inresponseto_assertion_matches_but_response_differs_fails() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;

    let (key_pair, cert_der) = generate_test_key_and_cert();
    let provider = test_provider(cert_der);
    let (not_before, not_on_or_after) = valid_time_window();

    // Response.InResponseTo = "_wrong_req" (differs from expected).
    // SCD.InResponseTo = "_req_irt_5" (matches expected).
    let xml = build_signed_saml_response(
        &key_pair,
        "alice@example.com",
        "_response_irt_5",
        "_assertion_irt_5",
        "_wrong_req",
        "https://vouch.example.com/saml/acs",
        "https://idp.example.com",
        "https://vouch.example.com",
        &not_before,
        &not_on_or_after,
        Some("_req_irt_5"),
    );

    let base64_response = B64.encode(xml.as_bytes());
    let result = validate_saml_response(&base64_response, "_req_irt_5", &provider);

    let err = result.unwrap_err();
    assert!(
        matches!(err, ResponseError::InResponseToMismatch { .. }),
        "Expected InResponseToMismatch (Response.InResponseTo differs from expected), got: {err}"
    );
}

// --- Response-signed complement tests ---

/// Signing the Response does not excuse a missing
/// SubjectConfirmationData.InResponseTo. SAML Profiles 4.1.4.3 lists the
/// check under "Regardless of the SAML binding used, the service provider
/// MUST do the following", with no exemption based on which element carries
/// the signature — and 4.1.4.5 requires the assertion to be signed for the
/// POST binding anyway, so the attribute is always inside signed content.
// SAML Core §2.4.1.2: signing the response does not excuse the confirmation binding.
#[test]
fn response_signed_missing_scd_irt_is_still_rejected() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;

    let (key_pair, cert_der) = generate_test_key_and_cert();
    let provider = test_provider(cert_der);
    let (not_before, not_on_or_after) = valid_time_window();

    // Response-signed, SCD.InResponseTo absent.
    let xml = build_response_signed_saml_response(
        &key_pair,
        "alice@example.com",
        "_response_irt_6",
        "_assertion_irt_6",
        "_request_irt_6",
        "https://vouch.example.com/saml/acs",
        "https://idp.example.com",
        "https://vouch.example.com",
        &not_before,
        &not_on_or_after,
        None,
    );

    let base64_response = B64.encode(xml.as_bytes());
    let err = validate_saml_response(&base64_response, "_request_irt_6", &provider)
        .expect_err("a solicited response must carry SubjectConfirmationData.InResponseTo");
    assert!(
        matches!(err, ResponseError::MissingSubjectConfirmationInResponseTo),
        "Expected MissingSubjectConfirmationInResponseTo, got: {err}"
    );
}

/// When the Response is signed and SCD.InResponseTo is present and matches,
/// validation MUST pass (happy path for Response-signed configuration).
// SAML Core §2.4.1.2: a signed response with matching confirmation data is accepted.
#[test]
fn response_signed_with_scd_irt_passes() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;

    let (key_pair, cert_der) = generate_test_key_and_cert();
    let provider = test_provider(cert_der);
    let (not_before, not_on_or_after) = valid_time_window();

    let xml = build_response_signed_saml_response(
        &key_pair,
        "alice@example.com",
        "_response_irt_7",
        "_assertion_irt_7",
        "_request_irt_7",
        "https://vouch.example.com/saml/acs",
        "https://idp.example.com",
        "https://vouch.example.com",
        &not_before,
        &not_on_or_after,
        Some("_request_irt_7"),
    );

    let base64_response = B64.encode(xml.as_bytes());
    let result = validate_saml_response(&base64_response, "_request_irt_7", &provider);
    let assertion = result.expect("Expected Ok for Response-signed with matching SCD.InResponseTo");
    assert_eq!(assertion.email, "alice@example.com");
}

/// When the Response is signed and SCD.InResponseTo is present but wrong,
/// validation MUST still fail (the signed SCD.InResponseTo is checked when
/// present, regardless of whether the Response is signed).
// SAML Core §2.4.1.2: a signed response with mismatched confirmation data is rejected.
#[test]
fn response_signed_scd_irt_mismatch_fails() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;

    let (key_pair, cert_der) = generate_test_key_and_cert();
    let provider = test_provider(cert_der);
    let (not_before, not_on_or_after) = valid_time_window();

    let xml = build_response_signed_saml_response(
        &key_pair,
        "alice@example.com",
        "_response_irt_8",
        "_assertion_irt_8",
        "_request_irt_8",
        "https://vouch.example.com/saml/acs",
        "https://idp.example.com",
        "https://vouch.example.com",
        &not_before,
        &not_on_or_after,
        Some("_wrong_req"),
    );

    let base64_response = B64.encode(xml.as_bytes());
    let result = validate_saml_response(&base64_response, "_request_irt_8", &provider);

    let err = result.unwrap_err();
    assert!(
        matches!(err, ResponseError::InResponseToMismatch { .. }),
        "Expected InResponseToMismatch (SCD.InResponseTo differs from expected), got: {err}"
    );
}
