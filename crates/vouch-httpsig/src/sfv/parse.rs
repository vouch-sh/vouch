// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 8941 Structured Field Values parser.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::error::HttpSigError;

use super::types::{
    SfvBareItem, SfvDictMember, SfvDictionary, SfvInnerList, SfvItem, SfvList, SfvParams,
};

/// RFC 8941 §3.3.1: integers must be in the range ±999,999,999,999,999.
const SFV_INTEGER_MAX: i64 = 999_999_999_999_999;
const SFV_INTEGER_MIN: i64 = -999_999_999_999_999;

/// Parser state wrapping a byte slice with a cursor position.
struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn advance(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    fn skip_sp(&mut self) {
        while self.peek() == Some(b' ') {
            self.advance();
        }
    }

    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.advance();
        }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.input.len()
    }

    /// Parse an SFV Dictionary (RFC 8941 Section 4.2.2).
    fn parse_dictionary(&mut self) -> Result<SfvDictionary, HttpSigError> {
        let mut entries = Vec::new();
        self.skip_sp();

        if self.is_empty() {
            return Ok(SfvDictionary { entries });
        }

        let (key, member) = self.parse_dict_member()?;
        entries.push((key, member));

        loop {
            self.skip_ows();
            if self.peek() != Some(b',') {
                break;
            }
            self.advance(); // consume ','
            self.skip_ows();

            if self.is_empty() {
                return Err(HttpSigError::SfvParse(
                    "trailing comma in dictionary".into(),
                ));
            }

            let (key, member) = self.parse_dict_member()?;
            entries.push((key, member));
        }

        Ok(SfvDictionary { entries })
    }

    /// Parse an SFV List (RFC 8941 Section 4.2.1).
    fn parse_list(&mut self) -> Result<SfvList, HttpSigError> {
        let mut members = Vec::new();
        self.skip_sp();

        if self.is_empty() {
            return Ok(SfvList { members });
        }

        let member = self.parse_list_member()?;
        members.push(member);

        loop {
            self.skip_ows();
            if self.peek() != Some(b',') {
                break;
            }
            self.advance();
            self.skip_ows();

            if self.is_empty() {
                return Err(HttpSigError::SfvParse("trailing comma in list".into()));
            }

            let member = self.parse_list_member()?;
            members.push(member);
        }

        Ok(SfvList { members })
    }

    fn parse_list_member(&mut self) -> Result<SfvDictMember, HttpSigError> {
        if self.peek() == Some(b'(') {
            let inner_list = self.parse_inner_list()?;
            Ok(SfvDictMember::InnerList(inner_list))
        } else {
            let item = self.parse_item()?;
            Ok(SfvDictMember::Item(item))
        }
    }

    fn parse_dict_member(&mut self) -> Result<(String, SfvDictMember), HttpSigError> {
        let key = self.parse_key()?;
        let member = if self.peek() == Some(b'=') {
            self.advance();
            self.parse_member_value()?
        } else {
            // Boolean true with parameters
            let params = self.parse_parameters()?;
            SfvDictMember::Item(SfvItem {
                value: SfvBareItem::Boolean(true),
                params,
            })
        };
        Ok((key, member))
    }

    fn parse_member_value(&mut self) -> Result<SfvDictMember, HttpSigError> {
        if self.peek() == Some(b'(') {
            let inner_list = self.parse_inner_list()?;
            Ok(SfvDictMember::InnerList(inner_list))
        } else {
            let item = self.parse_item()?;
            Ok(SfvDictMember::Item(item))
        }
    }

    /// Parse an SFV Inner List (RFC 8941 Section 4.2.1.2).
    fn parse_inner_list(&mut self) -> Result<SfvInnerList, HttpSigError> {
        if self.peek() != Some(b'(') {
            return Err(HttpSigError::SfvParse("expected '(' for inner list".into()));
        }
        self.advance(); // consume '('

        let mut items = Vec::new();
        loop {
            self.skip_sp();
            if self.peek() == Some(b')') {
                self.advance();
                break;
            }
            if self.is_empty() {
                return Err(HttpSigError::SfvParse("unterminated inner list".into()));
            }
            let item = self.parse_item()?;
            items.push(item);
        }

        let params = self.parse_parameters()?;
        Ok(SfvInnerList { items, params })
    }

    /// Parse an SFV Item (RFC 8941 Section 4.2.3).
    fn parse_item(&mut self) -> Result<SfvItem, HttpSigError> {
        let value = self.parse_bare_item()?;
        let params = self.parse_parameters()?;
        Ok(SfvItem { value, params })
    }

    /// Parse an SFV Bare Item (RFC 8941 Section 4.2.3.1).
    fn parse_bare_item(&mut self) -> Result<SfvBareItem, HttpSigError> {
        match self.peek() {
            Some(b'"') => self.parse_string(),
            Some(b':') => self.parse_byte_sequence(),
            Some(b'?') => self.parse_boolean(),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.parse_integer_or_decimal(),
            Some(c) if c.is_ascii_alphabetic() || c == b'*' => self.parse_token(),
            Some(c) => Err(HttpSigError::SfvParse(format!(
                "unexpected character: '{}'",
                char::from(c)
            ))),
            None => Err(HttpSigError::SfvParse("unexpected end of input".into())),
        }
    }

    /// Parse an integer or decimal (RFC 8941 §4.2.4 / §4.2.5).
    ///
    /// Both start with optional `-` followed by digits. If a `.` appears,
    /// it's a decimal; otherwise it's an integer.
    fn parse_integer_or_decimal(&mut self) -> Result<SfvBareItem, HttpSigError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.advance();
        }
        if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            return Err(HttpSigError::SfvParse("expected digit in number".into()));
        }
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.advance();
        }

        // Check for decimal point
        if self.peek() == Some(b'.') {
            return self.parse_decimal_remainder(start);
        }

        let s = std::str::from_utf8(self.input.get(start..self.pos).unwrap_or_default())
            .map_err(|e| HttpSigError::SfvParse(format!("invalid UTF-8 in integer: {e}")))?;

        let val: i64 = s
            .parse()
            .map_err(|e| HttpSigError::SfvParse(format!("integer parse error: {e}")))?;

        // RFC 8941 §3.3.1: range ±999,999,999,999,999
        if !(SFV_INTEGER_MIN..=SFV_INTEGER_MAX).contains(&val) {
            return Err(HttpSigError::SfvParse(format!(
                "integer {val} out of range (±{SFV_INTEGER_MAX})"
            )));
        }

        Ok(SfvBareItem::Integer(val))
    }

    /// Parse the fractional part of a decimal after the integer part and `.`
    /// have been identified. `start` is the position of the first digit/sign.
    fn parse_decimal_remainder(&mut self, start: usize) -> Result<SfvBareItem, HttpSigError> {
        self.advance(); // consume '.'

        let frac_start = self.pos;
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.advance();
        }

        let frac_len = self.pos.saturating_sub(frac_start);
        if frac_len == 0 || frac_len > 3 {
            return Err(HttpSigError::SfvParse(format!(
                "decimal fractional part must be 1-3 digits, got {frac_len}"
            )));
        }

        let s = std::str::from_utf8(self.input.get(start..self.pos).unwrap_or_default())
            .map_err(|e| HttpSigError::SfvParse(format!("invalid UTF-8 in decimal: {e}")))?;

        let val: f64 = s
            .parse()
            .map_err(|e| HttpSigError::SfvParse(format!("decimal parse error: {e}")))?;

        // RFC 8941 §3.3.2: integer component up to 12 digits
        let int_part_len = frac_start.saturating_sub(1).saturating_sub(start); // -1 for the '.'
        let has_sign = self.input.get(start).is_some_and(|&b| b == b'-');
        let digit_len = if has_sign {
            int_part_len.saturating_sub(1)
        } else {
            int_part_len
        };
        if digit_len > 12 {
            return Err(HttpSigError::SfvParse(format!(
                "decimal integer part must be at most 12 digits, got {digit_len}"
            )));
        }

        Ok(SfvBareItem::Decimal(val))
    }

    fn parse_string(&mut self) -> Result<SfvBareItem, HttpSigError> {
        if self.peek() != Some(b'"') {
            return Err(HttpSigError::SfvParse("expected '\"' for string".into()));
        }
        self.advance(); // consume opening quote

        let mut result = String::new();
        loop {
            match self.peek() {
                None => {
                    return Err(HttpSigError::SfvParse("unterminated string".into()));
                }
                Some(b'"') => {
                    self.advance();
                    return Ok(SfvBareItem::String(result));
                }
                Some(b'\\') => {
                    self.advance();
                    match self.peek() {
                        Some(b'"') | Some(b'\\') => {
                            let ch = self.peek().ok_or_else(|| {
                                HttpSigError::SfvParse("unexpected end in escape".into())
                            })?;
                            result.push(char::from(ch));
                            self.advance();
                        }
                        _ => {
                            return Err(HttpSigError::SfvParse("invalid escape in string".into()));
                        }
                    }
                }
                Some(c) if (0x20..=0x7e).contains(&c) => {
                    result.push(char::from(c));
                    self.advance();
                }
                Some(c) => {
                    return Err(HttpSigError::SfvParse(format!(
                        "invalid character in string: 0x{c:02x}"
                    )));
                }
            }
        }
    }

    fn parse_token(&mut self) -> Result<SfvBareItem, HttpSigError> {
        let start = self.pos;
        if !matches!(self.peek(), Some(c) if c.is_ascii_alphabetic() || c == b'*') {
            return Err(HttpSigError::SfvParse("expected token start".into()));
        }
        self.advance();

        while matches!(self.peek(), Some(c) if is_token_char(c)) {
            self.advance();
        }

        let s = std::str::from_utf8(self.input.get(start..self.pos).unwrap_or_default())
            .map_err(|e| HttpSigError::SfvParse(format!("invalid UTF-8 in token: {e}")))?;
        Ok(SfvBareItem::Token(s.to_string()))
    }

    fn parse_byte_sequence(&mut self) -> Result<SfvBareItem, HttpSigError> {
        if self.peek() != Some(b':') {
            return Err(HttpSigError::SfvParse(
                "expected ':' for byte sequence".into(),
            ));
        }
        self.advance(); // consume opening ':'

        let start = self.pos;
        while self.peek() != Some(b':') {
            if self.is_empty() {
                return Err(HttpSigError::SfvParse("unterminated byte sequence".into()));
            }
            self.advance();
        }

        let b64 = std::str::from_utf8(self.input.get(start..self.pos).unwrap_or_default())
            .map_err(|e| HttpSigError::SfvParse(format!("invalid UTF-8 in byte sequence: {e}")))?;
        self.advance(); // consume closing ':'

        let bytes = STANDARD
            .decode(b64)
            .map_err(|e| HttpSigError::SfvParse(format!("base64 decode error: {e}")))?;
        Ok(SfvBareItem::ByteSequence(bytes))
    }

    fn parse_boolean(&mut self) -> Result<SfvBareItem, HttpSigError> {
        if self.peek() != Some(b'?') {
            return Err(HttpSigError::SfvParse("expected '?' for boolean".into()));
        }
        self.advance();

        match self.peek() {
            Some(b'0') => {
                self.advance();
                Ok(SfvBareItem::Boolean(false))
            }
            Some(b'1') => {
                self.advance();
                Ok(SfvBareItem::Boolean(true))
            }
            _ => Err(HttpSigError::SfvParse(
                "expected '0' or '1' after '?'".into(),
            )),
        }
    }

    /// Parse parameters (RFC 8941 Section 4.2.3.2).
    fn parse_parameters(&mut self) -> Result<SfvParams, HttpSigError> {
        let mut params = SfvParams::new();

        while self.peek() == Some(b';') {
            self.advance(); // consume ';'
            self.skip_sp();

            let key = self.parse_key()?;
            let value = if self.peek() == Some(b'=') {
                self.advance();
                Some(self.parse_bare_item()?)
            } else {
                None
            };
            params.insert(key, value);
        }

        Ok(params)
    }

    /// Parse an SFV key (RFC 8941 Section 4.2.3.3).
    fn parse_key(&mut self) -> Result<String, HttpSigError> {
        let start = self.pos;
        if !matches!(self.peek(), Some(c) if c.is_ascii_lowercase() || c == b'*') {
            return Err(HttpSigError::SfvParse("expected key start".into()));
        }
        self.advance();

        while matches!(
            self.peek(),
            Some(c) if c.is_ascii_lowercase()
                || c.is_ascii_digit()
                || c == b'_'
                || c == b'-'
                || c == b'.'
                || c == b'*'
        ) {
            self.advance();
        }

        let s = std::str::from_utf8(self.input.get(start..self.pos).unwrap_or_default())
            .map_err(|e| HttpSigError::SfvParse(format!("invalid UTF-8 in key: {e}")))?;
        Ok(s.to_string())
    }
}

/// Check whether a byte is a valid token continuation character (RFC 8941).
fn is_token_char(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
                | b':'
                | b'/'
        )
}

/// Maximum input length for SFV parsing (8 KB).
const MAX_SFV_INPUT_LEN: usize = 8192;

/// Parse an SFV Dictionary from a header value string.
///
/// # Errors
///
/// Returns [`HttpSigError::SfvParse`] on malformed input or if input exceeds 8 KB.
pub fn parse_dictionary(input: &str) -> Result<SfvDictionary, HttpSigError> {
    if input.len() > MAX_SFV_INPUT_LEN {
        return Err(HttpSigError::SfvParse(format!(
            "input too large: {} bytes (max {MAX_SFV_INPUT_LEN})",
            input.len()
        )));
    }
    let mut parser = Parser::new(input.as_bytes());
    let dict = parser.parse_dictionary()?;
    parser.skip_sp();
    if !parser.is_empty() {
        return Err(HttpSigError::SfvParse(format!(
            "trailing data after dictionary at position {}",
            parser.pos
        )));
    }
    Ok(dict)
}

/// Parse an SFV List from a header value string (RFC 8941 §3.1).
///
/// # Errors
///
/// Returns [`HttpSigError::SfvParse`] on malformed input or if input exceeds 8 KB.
pub fn parse_list(input: &str) -> Result<SfvList, HttpSigError> {
    if input.len() > MAX_SFV_INPUT_LEN {
        return Err(HttpSigError::SfvParse(format!(
            "input too large: {} bytes (max {MAX_SFV_INPUT_LEN})",
            input.len()
        )));
    }
    let mut parser = Parser::new(input.as_bytes());
    let list = parser.parse_list()?;
    parser.skip_sp();
    if !parser.is_empty() {
        return Err(HttpSigError::SfvParse(format!(
            "trailing data after list at position {}",
            parser.pos
        )));
    }
    Ok(list)
}

/// Parse an SFV Inner List from a string.
///
/// # Errors
///
/// Returns [`HttpSigError::SfvParse`] on malformed input.
pub fn parse_inner_list(input: &str) -> Result<SfvInnerList, HttpSigError> {
    if input.len() > MAX_SFV_INPUT_LEN {
        return Err(HttpSigError::SfvParse(format!(
            "input too large: {} bytes (max {MAX_SFV_INPUT_LEN})",
            input.len()
        )));
    }
    let mut parser = Parser::new(input.as_bytes());
    let list = parser.parse_inner_list()?;
    parser.skip_sp();
    if !parser.is_empty() {
        return Err(HttpSigError::SfvParse(format!(
            "trailing data after inner list at position {}",
            parser.pos
        )));
    }
    Ok(list)
}

/// Parse an SFV Item from a string.
///
/// # Errors
///
/// Returns [`HttpSigError::SfvParse`] on malformed input.
pub fn parse_item(input: &str) -> Result<SfvItem, HttpSigError> {
    if input.len() > MAX_SFV_INPUT_LEN {
        return Err(HttpSigError::SfvParse(format!(
            "input too large: {} bytes (max {MAX_SFV_INPUT_LEN})",
            input.len()
        )));
    }
    let mut parser = Parser::new(input.as_bytes());
    let item = parser.parse_item()?;
    parser.skip_sp();
    if !parser.is_empty() {
        return Err(HttpSigError::SfvParse(format!(
            "trailing data after item at position {}",
            parser.pos
        )));
    }
    Ok(item)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_integer() {
        let item = parse_item("42").unwrap();
        assert_eq!(item.value, SfvBareItem::Integer(42));
    }

    #[test]
    fn test_parse_negative_integer() {
        let item = parse_item("-7").unwrap();
        assert_eq!(item.value, SfvBareItem::Integer(-7));
    }

    #[test]
    fn test_parse_string() {
        let item = parse_item("\"hello\"").unwrap();
        assert_eq!(item.value, SfvBareItem::String("hello".into()));
    }

    #[test]
    fn test_parse_string_with_escape() {
        let item = parse_item("\"he\\\"llo\"").unwrap();
        assert_eq!(item.value, SfvBareItem::String("he\"llo".into()));
    }

    #[test]
    fn test_parse_token() {
        let item = parse_item("foo").unwrap();
        assert_eq!(item.value, SfvBareItem::Token("foo".into()));
    }

    #[test]
    fn test_parse_byte_sequence() {
        let item = parse_item(":dGVzdA==:").unwrap();
        assert_eq!(item.value, SfvBareItem::ByteSequence(b"test".to_vec()));
    }

    #[test]
    fn test_parse_boolean_true() {
        let item = parse_item("?1").unwrap();
        assert_eq!(item.value, SfvBareItem::Boolean(true));
    }

    #[test]
    fn test_parse_boolean_false() {
        let item = parse_item("?0").unwrap();
        assert_eq!(item.value, SfvBareItem::Boolean(false));
    }

    #[test]
    fn test_parse_item_with_params() {
        let item = parse_item("\"val\";key=1;flag").unwrap();
        assert_eq!(item.value, SfvBareItem::String("val".into()));
        assert_eq!(item.params.get("key"), Some(&Some(SfvBareItem::Integer(1))));
        assert_eq!(item.params.get("flag"), Some(&None));
    }

    #[test]
    fn test_parse_inner_list() {
        let list = parse_inner_list("(\"a\" \"b\");created=1").unwrap();
        assert_eq!(list.items.len(), 2);
        assert_eq!(list.items[0].value, SfvBareItem::String("a".into()));
        assert_eq!(list.items[1].value, SfvBareItem::String("b".into()));
        assert_eq!(
            list.params.get("created"),
            Some(&Some(SfvBareItem::Integer(1)))
        );
    }

    #[test]
    fn test_parse_dictionary_single() {
        let dict = parse_dictionary("sig1=:dGVzdA==:").unwrap();
        assert_eq!(dict.entries.len(), 1);
        assert_eq!(dict.entries[0].0, "sig1");
    }

    #[test]
    fn test_parse_dictionary_multiple() {
        let dict = parse_dictionary("sig1=:dGVzdA==:, sig2=:YWJj:").unwrap();
        assert_eq!(dict.entries.len(), 2);
        assert_eq!(dict.entries[0].0, "sig1");
        assert_eq!(dict.entries[1].0, "sig2");
    }

    #[test]
    fn test_parse_dictionary_with_inner_list() {
        let dict = parse_dictionary(
            "sig1=(\"@method\" \"@authority\");created=1618884473;alg=\"hmac-sha256\"",
        )
        .unwrap();
        assert_eq!(dict.entries.len(), 1);
        match &dict.entries[0].1 {
            SfvDictMember::InnerList(list) => {
                assert_eq!(list.items.len(), 2);
                assert_eq!(
                    list.params.get("created"),
                    Some(&Some(SfvBareItem::Integer(1_618_884_473)))
                );
                assert_eq!(
                    list.params.get("alg"),
                    Some(&Some(SfvBareItem::String("hmac-sha256".into())))
                );
            }
            _ => panic!("expected inner list"),
        }
    }

    #[test]
    fn test_parse_empty_inner_list() {
        let list = parse_inner_list("()").unwrap();
        assert!(list.items.is_empty());
    }

    #[test]
    fn test_parse_boolean_dict_member() {
        let dict = parse_dictionary("flag").unwrap();
        assert_eq!(dict.entries.len(), 1);
        match &dict.entries[0].1 {
            SfvDictMember::Item(item) => {
                assert_eq!(item.value, SfvBareItem::Boolean(true));
            }
            _ => panic!("expected item"),
        }
    }

    // Decimal tests

    #[test]
    fn test_parse_decimal() {
        let item = parse_item("3.12").unwrap();
        assert_eq!(item.value, SfvBareItem::Decimal(3.12));
    }

    #[test]
    fn test_parse_negative_decimal() {
        let item = parse_item("-2.5").unwrap();
        assert_eq!(item.value, SfvBareItem::Decimal(-2.5));
    }

    #[test]
    fn test_parse_decimal_one_fractional_digit() {
        let item = parse_item("1.0").unwrap();
        assert_eq!(item.value, SfvBareItem::Decimal(1.0));
    }

    #[test]
    fn test_parse_decimal_three_fractional_digits() {
        let item = parse_item("99.123").unwrap();
        assert_eq!(item.value, SfvBareItem::Decimal(99.123));
    }

    #[test]
    fn test_parse_decimal_four_fractional_digits_rejected() {
        let result = parse_item("1.1234");
        assert!(result.is_err(), "4 fractional digits must be rejected");
    }

    #[test]
    fn test_parse_decimal_no_fractional_digits_rejected() {
        // "1." with no fractional digits is invalid
        let result = parse_item("1.");
        assert!(result.is_err(), "0 fractional digits must be rejected");
    }

    // Integer range tests

    #[test]
    fn test_parse_integer_max_valid() {
        let item = parse_item("999999999999999").unwrap();
        assert_eq!(item.value, SfvBareItem::Integer(999_999_999_999_999));
    }

    #[test]
    fn test_parse_integer_min_valid() {
        let item = parse_item("-999999999999999").unwrap();
        assert_eq!(item.value, SfvBareItem::Integer(-999_999_999_999_999));
    }

    #[test]
    fn test_parse_integer_over_max_rejected() {
        let result = parse_item("1000000000000000");
        assert!(result.is_err(), "integer above max must be rejected");
    }

    #[test]
    fn test_parse_integer_under_min_rejected() {
        let result = parse_item("-1000000000000000");
        assert!(result.is_err(), "integer below min must be rejected");
    }

    // List tests

    #[test]
    fn test_parse_list_items() {
        let list = parse_list("\"a\", \"b\", \"c\"").unwrap();
        assert_eq!(list.members.len(), 3);
        match &list.members[0] {
            SfvDictMember::Item(item) => {
                assert_eq!(item.value, SfvBareItem::String("a".into()));
            }
            _ => panic!("expected item"),
        }
    }

    #[test]
    fn test_parse_list_with_inner_list() {
        let list = parse_list("\"a\", (\"b\" \"c\"), \"d\"").unwrap();
        assert_eq!(list.members.len(), 3);
        match &list.members[1] {
            SfvDictMember::InnerList(inner) => {
                assert_eq!(inner.items.len(), 2);
            }
            _ => panic!("expected inner list"),
        }
    }

    #[test]
    fn test_parse_list_single_item() {
        let list = parse_list("42").unwrap();
        assert_eq!(list.members.len(), 1);
    }

    #[test]
    fn test_parse_list_empty() {
        let list = parse_list("").unwrap();
        assert!(list.members.is_empty());
    }

    #[test]
    fn test_parse_list_with_params() {
        let list = parse_list("\"a\";x=1, \"b\";y=2").unwrap();
        assert_eq!(list.members.len(), 2);
    }

    // Input length limit

    #[test]
    fn test_parse_dictionary_rejects_oversized_input() {
        let input = "a".repeat(8193);
        let result = parse_dictionary(&input);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_list_rejects_oversized_input() {
        let input = "a".repeat(8193);
        let result = parse_list(&input);
        assert!(result.is_err());
    }
}
