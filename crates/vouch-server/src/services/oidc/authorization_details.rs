// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9396: OAuth 2.0 Rich Authorization Requests.
//!
//! Provides types and validation for the `authorization_details` parameter,
//! a JSON array of typed objects that allows clients to express fine-grained
//! authorization requirements beyond simple scopes.

use crate::services::{OAuthErrorCode, ServiceError, ServiceResult};
use serde::{Deserialize, Serialize};

/// Maximum allowed size of the raw `authorization_details` JSON string (bytes).
const MAX_SIZE: usize = 8192;

/// Maximum allowed nesting depth for JSON values within authorization details.
const MAX_DEPTH: usize = 5;

/// RFC 9396 Section 2: A single authorization detail object.
///
/// Wraps `serde_json::Value`, validated to be a JSON object with a required
/// string `type` field. The inner value is opaque — Vouch does not interpret
/// type-specific fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationDetail(serde_json::Value);

impl AuthorizationDetail {
    /// Extract the `type` field from this authorization detail.
    ///
    /// Safe to call unconditionally: the constructor guarantees that `type`
    /// exists and is a non-empty string.
    #[must_use]
    pub fn type_name(&self) -> &str {
        self.0
            .get("type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
    }
}

/// RFC 9396 Section 2: Array of authorization detail objects.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationDetails(Vec<AuthorizationDetail>);

impl AuthorizationDetails {
    /// Parse and validate an `authorization_details` JSON string.
    ///
    /// Enforces:
    /// - Size limit ([`MAX_SIZE`] bytes)
    /// - Must be a JSON array
    /// - Each element must be a JSON object with a non-empty string `type` field
    /// - Nesting depth ≤ [`MAX_DEPTH`]
    /// - No control characters in string values (RFC 9396 Section 12)
    ///
    /// # Errors
    ///
    /// Returns `InvalidAuthorizationDetails` for any validation failure.
    pub fn parse(raw: &str) -> ServiceResult<Self> {
        if raw.len() > MAX_SIZE {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidAuthorizationDetails,
                format!("authorization_details exceeds maximum size of {MAX_SIZE} bytes"),
            ));
        }

        let value: serde_json::Value = serde_json::from_str(raw).map_err(|e| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidAuthorizationDetails,
                format!("Invalid authorization_details JSON: {e}"),
            )
        })?;

        let arr = value.as_array().ok_or_else(|| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidAuthorizationDetails,
                "authorization_details must be a JSON array",
            )
        })?;

        if arr.is_empty() {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidAuthorizationDetails,
                "authorization_details must not be empty",
            ));
        }

        let mut details = Vec::with_capacity(arr.len());

        for (i, item) in arr.iter().enumerate() {
            let obj = item.as_object().ok_or_else(|| {
                ServiceError::oauth(
                    OAuthErrorCode::InvalidAuthorizationDetails,
                    format!("authorization_details[{i}] must be a JSON object"),
                )
            })?;

            let type_val = obj.get("type").ok_or_else(|| {
                ServiceError::oauth(
                    OAuthErrorCode::InvalidAuthorizationDetails,
                    format!("authorization_details[{i}] missing required 'type' field"),
                )
            })?;

            let type_str = type_val.as_str().ok_or_else(|| {
                ServiceError::oauth(
                    OAuthErrorCode::InvalidAuthorizationDetails,
                    format!("authorization_details[{i}] 'type' must be a string"),
                )
            })?;

            if type_str.is_empty() {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidAuthorizationDetails,
                    format!("authorization_details[{i}] 'type' must not be empty"),
                ));
            }

            if !validate_depth(item, MAX_DEPTH) {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidAuthorizationDetails,
                    format!(
                        "authorization_details[{i}] exceeds maximum nesting depth of {MAX_DEPTH}"
                    ),
                ));
            }

            if !validate_no_control_chars(item) {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidAuthorizationDetails,
                    format!("authorization_details[{i}] contains control characters"),
                ));
            }

            details.push(AuthorizationDetail(item.clone()));
        }

        Ok(Self(details))
    }

    /// Whether this collection is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check whether every detail in `self` has an exact match in `granted`.
    ///
    /// Clients downscope by omitting entire detail entries, not by modifying
    /// fields within an entry. Field-level downscoping would require
    /// type-specific knowledge that Vouch does not have.
    ///
    /// Comparison uses full JSON equality (including array element ordering
    /// and object key ordering). This is intentional: reordering fields or
    /// array elements within a detail object constitutes a modification.
    #[must_use]
    pub fn is_subset_of(&self, granted: &Self) -> bool {
        self.0.iter().all(|requested| granted.0.contains(requested))
    }
}

impl TryFrom<&serde_json::Value> for AuthorizationDetails {
    type Error = ();

    /// Reconstruct from a `serde_json::Value` that was previously
    /// validated and stored.
    ///
    /// Expects a JSON array of objects with `type` fields.
    fn try_from(value: &serde_json::Value) -> Result<Self, Self::Error> {
        let arr = value.as_array().ok_or(())?;
        let details: Vec<AuthorizationDetail> = arr
            .iter()
            .filter_map(|item| {
                let obj = item.as_object()?;
                obj.get("type")?.as_str()?;
                Some(AuthorizationDetail(item.clone()))
            })
            .collect();
        Ok(Self(details))
    }
}

impl From<&AuthorizationDetails> for serde_json::Value {
    fn from(ad: &AuthorizationDetails) -> Self {
        Self::Array(ad.0.iter().map(|d| d.0.clone()).collect())
    }
}

/// Check that a JSON value does not exceed `max_depth` levels of nesting.
///
/// Arrays and objects each add one level. Returns `true` if within limits.
fn validate_depth(value: &serde_json::Value, max_depth: usize) -> bool {
    if max_depth == 0 {
        return !value.is_array() && !value.is_object();
    }
    match value {
        serde_json::Value::Array(arr) => arr.iter().all(|v| validate_depth(v, max_depth - 1)),
        serde_json::Value::Object(map) => map.values().all(|v| validate_depth(v, max_depth - 1)),
        _ => true,
    }
}

/// Check that no string values or object keys contain ASCII control characters
/// (0x00–0x1F, 0x7F).
///
/// RFC 9396 Section 12: Authorization servers should sanitize or reject
/// values containing control characters to prevent injection attacks.
fn validate_no_control_chars(value: &serde_json::Value) -> bool {
    fn has_control_chars(s: &str) -> bool {
        s.bytes().any(|b| b < 0x20 || b == 0x7F)
    }

    match value {
        serde_json::Value::String(s) => !has_control_chars(s),
        serde_json::Value::Array(arr) => arr.iter().all(validate_no_control_chars),
        serde_json::Value::Object(map) => {
            map.keys().all(|k| !has_control_chars(k)) && map.values().all(validate_no_control_chars)
        }
        _ => true,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_array() {
        let raw = r#"[{"type":"payment_initiation","amount":100}]"#;
        let details = AuthorizationDetails::parse(raw).unwrap();
        assert_eq!(details.0.len(), 1);
        assert_eq!(details.0[0].type_name(), "payment_initiation");
    }

    #[test]
    fn test_parse_multiple_entries() {
        let raw = r#"[{"type":"a"},{"type":"b","extra":true}]"#;
        let details = AuthorizationDetails::parse(raw).unwrap();
        assert_eq!(details.0.len(), 2);
        assert_eq!(details.0[0].type_name(), "a");
        assert_eq!(details.0[1].type_name(), "b");
    }

    #[test]
    fn test_parse_non_array() {
        let raw = r#"{"type":"payment_initiation"}"#;
        let err = AuthorizationDetails::parse(raw).unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidAuthorizationDetails)
        );
    }

    #[test]
    fn test_parse_missing_type() {
        let raw = r#"[{"amount":100}]"#;
        assert!(AuthorizationDetails::parse(raw).is_err());
    }

    #[test]
    fn test_parse_non_string_type() {
        let raw = r#"[{"type":42}]"#;
        assert!(AuthorizationDetails::parse(raw).is_err());
    }

    #[test]
    fn test_parse_empty_type() {
        let raw = r#"[{"type":""}]"#;
        assert!(AuthorizationDetails::parse(raw).is_err());
    }

    #[test]
    fn test_parse_empty_array() {
        let raw = "[]";
        assert!(AuthorizationDetails::parse(raw).is_err());
    }

    #[test]
    fn test_parse_oversized() {
        let big = format!(r#"[{{"type":"x","data":"{}"}}]"#, "a".repeat(MAX_SIZE));
        assert!(AuthorizationDetails::parse(&big).is_err());
    }

    #[test]
    fn test_parse_control_characters() {
        let raw = r#"[{"type":"test","value":"hello\u0000world"}]"#;
        // serde_json parses \u0000 as a null byte in the string
        let parsed: serde_json::Value = serde_json::from_str(raw).unwrap();
        let arr = parsed.as_array().unwrap();
        assert!(!validate_no_control_chars(&arr[0]));
    }

    #[test]
    fn test_parse_control_chars_in_keys_rejected() {
        // Control characters in object keys should also be rejected
        let raw = "[{\"type\":\"test\",\"he\x01llo\":\"world\"}]";
        assert!(AuthorizationDetails::parse(raw).is_err());
    }

    #[test]
    fn test_parse_del_character_rejected() {
        // DEL (0x7F) should be rejected as a control character
        let raw = "[{\"type\":\"test\",\"value\":\"hello\x7Fworld\"}]";
        assert!(AuthorizationDetails::parse(raw).is_err());
    }

    #[test]
    fn test_parse_deep_nesting() {
        // 6 levels of nesting (exceeds MAX_DEPTH=5)
        let raw = r#"[{"type":"t","a":{"b":{"c":{"d":{"e":{"f":"deep"}}}}}}]"#;
        assert!(AuthorizationDetails::parse(raw).is_err());
    }

    #[test]
    fn test_parse_nesting_at_limit() {
        // 5 levels: obj -> a:obj -> b:obj -> c:obj -> d:obj -> e:str
        let raw = r#"[{"type":"t","a":{"b":{"c":{"d":"ok"}}}}]"#;
        assert!(AuthorizationDetails::parse(raw).is_ok());
    }

    #[test]
    fn test_type_name_accessor() {
        let raw = r#"[{"type":"my_type","data":1}]"#;
        let details = AuthorizationDetails::parse(raw).unwrap();
        assert_eq!(details.0[0].type_name(), "my_type");
    }

    #[test]
    fn test_is_subset_of_exact_match() {
        let raw = r#"[{"type":"a","v":1},{"type":"b"}]"#;
        let granted = AuthorizationDetails::parse(raw).unwrap();
        let requested = AuthorizationDetails::parse(raw).unwrap();
        assert!(requested.is_subset_of(&granted));
    }

    #[test]
    fn test_is_subset_of_proper_subset() {
        let granted = AuthorizationDetails::parse(r#"[{"type":"a"},{"type":"b"}]"#).unwrap();
        let requested = AuthorizationDetails::parse(r#"[{"type":"a"}]"#).unwrap();
        assert!(requested.is_subset_of(&granted));
    }

    #[test]
    fn test_is_subset_of_extra_entry_fails() {
        let granted = AuthorizationDetails::parse(r#"[{"type":"a"}]"#).unwrap();
        let requested = AuthorizationDetails::parse(r#"[{"type":"a"},{"type":"b"}]"#).unwrap();
        assert!(!requested.is_subset_of(&granted));
    }

    #[test]
    fn test_is_subset_of_different_fields_fails() {
        let granted = AuthorizationDetails::parse(r#"[{"type":"a","v":1}]"#).unwrap();
        let requested = AuthorizationDetails::parse(r#"[{"type":"a","v":2}]"#).unwrap();
        assert!(!requested.is_subset_of(&granted));
    }

    #[test]
    fn test_is_subset_of_reordered_array() {
        let granted = AuthorizationDetails::parse(r#"[{"type":"a"},{"type":"b"}]"#).unwrap();
        let requested = AuthorizationDetails::parse(r#"[{"type":"b"},{"type":"a"}]"#).unwrap();
        assert!(requested.is_subset_of(&granted));
    }

    #[test]
    fn test_round_trip_via_json_value() {
        let raw = r#"[{"type":"payment","amount":100}]"#;
        let details = AuthorizationDetails::parse(raw).unwrap();
        let value = serde_json::Value::from(&details);
        let round_tripped = AuthorizationDetails::try_from(&value).unwrap();
        assert_eq!(details, round_tripped);
    }

    #[test]
    fn test_to_json_value() {
        let raw = r#"[{"type":"t"}]"#;
        let details = AuthorizationDetails::parse(raw).unwrap();
        let value = serde_json::Value::from(&details);
        assert!(value.is_array());
        assert_eq!(value.as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_is_empty() {
        let details = AuthorizationDetails(vec![]);
        assert!(details.is_empty());

        let non_empty = AuthorizationDetails::parse(r#"[{"type":"a"}]"#).unwrap();
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn test_non_object_element() {
        let raw = r#"["string"]"#;
        assert!(AuthorizationDetails::parse(raw).is_err());
    }

    #[test]
    fn test_invalid_json() {
        assert!(AuthorizationDetails::parse("not json").is_err());
    }

    #[test]
    fn test_validate_depth_scalars() {
        assert!(validate_depth(&serde_json::json!(42), 0));
        assert!(validate_depth(&serde_json::json!("str"), 0));
        assert!(validate_depth(&serde_json::json!(true), 0));
        assert!(validate_depth(&serde_json::json!(null), 0));
    }

    #[test]
    fn test_validate_depth_array_at_zero() {
        assert!(!validate_depth(&serde_json::json!([1]), 0));
    }

    #[test]
    fn test_validate_no_control_chars_clean() {
        assert!(validate_no_control_chars(&serde_json::json!("hello world")));
    }

    #[test]
    fn test_validate_no_control_chars_tab() {
        assert!(!validate_no_control_chars(&serde_json::Value::String(
            "hello\tworld".to_string()
        )));
    }
}
