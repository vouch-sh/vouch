// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM filter expressions (RFC 7644 §3.4.2.2).
//!
//! Vouch evaluates one attribute comparison, the ABNF's
//! `attrPath SP compareOp SP compValue`. Every other form of the grammar
//! (`pr`, `and`/`or`, `not`, grouping, a bracketed `valuePath`) is rejected,
//! and RFC 7644 §3.12 Table 9 gives the error for both cases: `invalidFilter`,
//! "The specified filter syntax was invalid (does not comply with Figure 1),
//! or the specified attribute and filter comparison combination is not
//! supported." Filtering is OPTIONAL for a provider (§3.4.2.2), so declining a
//! form is conformant. Widening to every resource is not: "When specified,
//! only those resources matching the filter expression SHALL be returned."
//!
//! List filters, the `members[...]` and `emails[...]` PATCH path filters, and
//! the resource-specific filter types built from [`AttrExp`] all parse here, so
//! the call sites cannot read one expression differently.
//!
//! Whitespace is read leniently: any run of spaces or tabs separates tokens,
//! leading or trailing whitespace is ignored, and a value may follow its
//! operator directly, as in RFC 7644 §3.5.2.2's own example
//! `members[value eq\"2819c223...\"]`. The ABNF's `SP` binds the client's
//! filter; accepting more is not a violation.

/// The attribute path with the resource's core schema URN prefix removed.
///
/// RFC 7644 §3.10: "Clients MAY omit core schema attribute URN prefixes",
/// so `urn:ietf:params:scim:schemas:core:2.0:User:userName` and `userName`
/// address the same attribute, and "All facets (URN, attribute, and
/// sub-attribute name) of the fully encoded attribute name are case
/// insensitive." Paths under any other URN (schema extensions) are returned
/// unchanged.
pub(crate) fn unqualified<'p>(path: &'p str, schema_urn: &str) -> &'p str {
    path.get(..schema_urn.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(schema_urn))
        .and_then(|_| path.get(schema_urn.len()..))
        .and_then(|rest| rest.strip_prefix(':'))
        .unwrap_or(path)
}

/// RFC 7644 §3.4.2.2 `compareOp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompareOp {
    Eq,
    Ne,
    Co,
    Sw,
    Ew,
    Gt,
    Lt,
    Ge,
    Le,
}

impl CompareOp {
    /// "Attribute names and attribute operators used in filters are case
    /// insensitive." (RFC 7644 §3.4.2.2)
    fn parse(token: &str) -> Option<Self> {
        let op = match token.to_ascii_lowercase().as_str() {
            "eq" => Self::Eq,
            "ne" => Self::Ne,
            "co" => Self::Co,
            "sw" => Self::Sw,
            "ew" => Self::Ew,
            "gt" => Self::Gt,
            "lt" => Self::Lt,
            "ge" => Self::Ge,
            "le" => Self::Le,
            _ => return None,
        };
        Some(op)
    }
}

/// One attribute comparison: `attrPath SP compareOp SP compValue`.
#[derive(Debug, PartialEq)]
pub(crate) struct AttrExp<'f> {
    /// `attrPath` without the resource's core schema URN, e.g. `userName` or
    /// `emails.value`. Match it case-insensitively.
    pub attribute: &'f str,
    pub op: CompareOp,
    /// `compValue`, decoded as JSON (RFC 7159): a string, number, boolean, or
    /// null. A string's escapes are already resolved.
    pub value: serde_json::Value,
}

impl AttrExp<'_> {
    /// Whether the attribute is `name`, ignoring ASCII case.
    pub(crate) fn is(&self, name: &str) -> bool {
        self.attribute.eq_ignore_ascii_case(name)
    }

    /// The comparison value as a string, or [`FilterError`] for any other
    /// JSON type.
    pub(crate) fn string_value(&self) -> Result<&str, FilterError> {
        self.value.as_str().ok_or_else(|| {
            FilterError(format!(
                "{} takes a string comparison value",
                self.attribute
            ))
        })
    }

    /// [`FilterError`] for an attribute and operator combination the caller
    /// does not support.
    pub(crate) fn unsupported(&self) -> FilterError {
        FilterError(format!(
            "filtering on {} with {:?} is not supported",
            self.attribute, self.op
        ))
    }
}

/// Why a filter was declined; RFC 7644 §3.12 `invalidFilter`. The message is
/// the SCIM error `detail`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub(crate) struct FilterError(String);

/// Whitespace between tokens: any run of spaces or tabs.
fn is_separator(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// Split off the token before the first separator, and the rest with its
/// leading separators removed.
fn next_token(s: &str) -> Option<(&str, &str)> {
    let (token, rest) = s.split_once(is_separator)?;
    Some((token, rest.trim_start_matches(is_separator)))
}

/// `ATTRNAME = ALPHA *(nameChar)`, `nameChar = "-" / "_" / DIGIT / ALPHA`.
fn is_attr_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Parse `filter` as one attribute comparison on the resource whose core
/// schema is `schema_urn`.
///
/// # Errors
///
/// [`FilterError`] for anything that is not a single
/// `attrPath compareOp compValue` with a JSON scalar value: a malformed
/// expression, `pr`, a logical or grouped expression, a bracketed value
/// filter, an extension-schema attribute, or trailing text.
pub(crate) fn parse<'f>(filter: &'f str, schema_urn: &str) -> Result<AttrExp<'f>, FilterError> {
    let single = || {
        FilterError("only a single attrPath compareOp compValue comparison is supported".to_owned())
    };
    let filter = filter.trim_matches(is_separator);
    let (path, rest) = next_token(filter).ok_or_else(single)?;
    let op_end = rest
        .find(|c: char| !c.is_ascii_alphabetic())
        .ok_or_else(single)?;
    let (op_token, value_text) = rest.split_at(op_end);
    let value_text = value_text.trim_start_matches(is_separator);

    let attribute = unqualified(path, schema_urn);
    let valid_path = match attribute.split_once('.') {
        Some((name, sub)) => is_attr_name(name) && is_attr_name(sub),
        None => is_attr_name(attribute),
    };
    if !valid_path {
        return Err(FilterError(format!(
            "{path} is not a supported attribute path"
        )));
    }
    let op = CompareOp::parse(op_token)
        .ok_or_else(|| FilterError(format!("{op_token} is not a comparison operator")))?;

    let mut values = serde_json::Deserializer::from_str(value_text).into_iter();
    let value: serde_json::Value = match values.next() {
        Some(Ok(value)) => value,
        Some(Err(_)) | None => {
            return Err(FilterError(format!(
                "{value_text} is not a JSON comparison value"
            )));
        }
    };
    let trailing = value_text
        .get(values.byte_offset()..)
        .unwrap_or_default()
        .trim_matches(is_separator);
    if !trailing.is_empty() {
        return Err(single());
    }
    if value.is_object() || value.is_array() {
        return Err(FilterError(format!(
            "{value_text} is not a JSON comparison value"
        )));
    }

    Ok(AttrExp {
        attribute,
        op,
        value,
    })
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use serde_json::json;

    const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";

    fn exp(attribute: &str, op: CompareOp, value: serde_json::Value) -> AttrExp<'_> {
        AttrExp {
            attribute,
            op,
            value,
        }
    }

    // RFC 7644 §3.4.2.2: "SCIM filters MUST conform to the following ABNF";
    // attrExp = attrPath SP compareOp SP compValue, and compValue is built on
    // the JSON (RFC 7159) rules.
    #[test]
    fn parses_attribute_comparisons() {
        let cases = [
            (
                r#"userName eq "a@example.com""#,
                exp("userName", CompareOp::Eq, json!("a@example.com")),
            ),
            (
                r#"userName co "smith""#,
                exp("userName", CompareOp::Co, json!("smith")),
            ),
            (
                r#"externalId sw "ext""#,
                exp("externalId", CompareOp::Sw, json!("ext")),
            ),
            (
                r#"emails.value eq "a@example.com""#,
                exp("emails.value", CompareOp::Eq, json!("a@example.com")),
            ),
            (
                r#"displayName eq "Domain\\Admins""#,
                exp("displayName", CompareOp::Eq, json!(r"Domain\Admins")),
            ),
            (
                r#"displayName eq "Team \"A\"""#,
                exp("displayName", CompareOp::Eq, json!(r#"Team "A""#)),
            ),
            (
                r#"displayName eq "équipe""#,
                exp("displayName", CompareOp::Eq, json!("équipe")),
            ),
            (
                r#"displayName eq "山田太郎""#,
                exp("displayName", CompareOp::Eq, json!("山田太郎")),
            ),
            (
                r#"userName eq "사용자@example.com""#,
                exp("userName", CompareOp::Eq, json!("사용자@example.com")),
            ),
            (
                r#"displayName eq "Test 🔑 Key""#,
                exp("displayName", CompareOp::Eq, json!("Test 🔑 Key")),
            ),
            ("active eq true", exp("active", CompareOp::Eq, json!(true))),
            (
                "primary eq false",
                exp("primary", CompareOp::Eq, json!(false)),
            ),
            ("x ne null", exp("x", CompareOp::Ne, json!(null))),
            (
                "meta.version gt 5",
                exp("meta.version", CompareOp::Gt, json!(5)),
            ),
            (
                r#"userName EQ "a""#,
                exp("userName", CompareOp::Eq, json!("a")),
            ),
            (
                r#"urn:ietf:params:scim:schemas:core:2.0:User:userName eq "a""#,
                exp("userName", CompareOp::Eq, json!("a")),
            ),
            (
                r#"URN:IETF:PARAMS:SCIM:SCHEMAS:CORE:2.0:USER:userName eq "a""#,
                exp("userName", CompareOp::Eq, json!("a")),
            ),
            // Lenient whitespace: runs of spaces or tabs, and trimmed ends.
            (
                "userName  eq \"a\"",
                exp("userName", CompareOp::Eq, json!("a")),
            ),
            (
                "userName\teq\t\"a\"",
                exp("userName", CompareOp::Eq, json!("a")),
            ),
            (
                " userName eq \"a\" ",
                exp("userName", CompareOp::Eq, json!("a")),
            ),
            // RFC 7644 §3.5.2.2's example has no space before the value.
            (
                r#"value eq"2819c223""#,
                exp("value", CompareOp::Eq, json!("2819c223")),
            ),
            // A value may contain the text of another expression.
            (
                r#"externalId eq "displayName eq x""#,
                exp("externalId", CompareOp::Eq, json!("displayName eq x")),
            ),
        ];
        for (filter, expected) in cases {
            assert_eq!(parse(filter, USER), Ok(expected), "{filter}");
        }
    }

    // RFC 7644 §3.12 Table 9: invalidFilter when "The specified filter syntax
    // was invalid (does not comply with Figure 1), or the specified attribute
    // and filter comparison combination is not supported."
    #[test]
    fn declines_everything_but_one_comparison() {
        let cases = [
            "",
            "userName",
            r#"userName eq"#,
            r#"userName "a""#,
            "userName pr",
            r#"userName eq "a" and active eq false"#,
            r#"userName eq "a" or userName eq "b""#,
            r#"not (userName eq "a")"#,
            r#"(userName eq "a")"#,
            r#"emails[type eq "work"]"#,
            r#"emails[type eq "work"].value eq "a""#,
            r#"userName xx "a""#,
            r#"userName eqx "a""#,
            r#"userName eq a"#,
            r#"userName eq "unterminated"#,
            r#"userName eq "a" trailing"#,
            r#"userName eq {"a":1}"#,
            r#"userName eq ["a"]"#,
            r#"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber eq "1""#,
            r#"1userName eq "a""#,
            r#"user.name.first eq "a""#,
            r#"user$name eq "a""#,
        ];
        for filter in cases {
            assert!(parse(filter, USER).is_err(), "{filter} must be declined");
        }
    }

    #[test]
    fn string_value_rejects_other_json_types() {
        let exp = parse("userName eq 5", USER).unwrap();
        assert!(exp.string_value().is_err());
        let exp = parse(r#"userName eq "5""#, USER).unwrap();
        assert_eq!(exp.string_value(), Ok("5"));
    }

    // RFC 7644 §3.10: "All facets (URN, attribute, and sub-attribute name) of
    // the fully encoded attribute name are case insensitive."
    #[test]
    fn attribute_match_ignores_case() {
        let exp = parse(r#"USERNAME eq "a""#, USER).unwrap();
        assert!(exp.is("userName"));
        assert!(!exp.is("externalId"));
    }
}
