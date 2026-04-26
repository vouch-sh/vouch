// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 8941 Structured Field Values serializer.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::types::{
    SfvBareItem, SfvDictMember, SfvDictionary, SfvInnerList, SfvItem, SfvList, SfvParams,
};

/// Serialize an SFV Dictionary to a string.
#[must_use]
pub fn serialize_dictionary(dict: &SfvDictionary) -> String {
    let mut out = String::new();
    for (i, (key, member)) in dict.entries.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(key);
        match member {
            SfvDictMember::Item(item) => {
                // Omit "=?1" for bare boolean true
                if item.value != SfvBareItem::Boolean(true) {
                    out.push('=');
                    serialize_bare_item(&item.value, &mut out);
                }
                serialize_params(&item.params, &mut out);
            }
            SfvDictMember::InnerList(list) => {
                out.push('=');
                serialize_inner_list(list, &mut out);
            }
        }
    }
    out
}

/// Serialize an SFV List to a string (RFC 8941 §4.1.1).
#[must_use]
pub fn serialize_list(list: &SfvList) -> String {
    let mut out = String::new();
    for (i, member) in list.members.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        match member {
            SfvDictMember::Item(item) => {
                serialize_bare_item(&item.value, &mut out);
                serialize_params(&item.params, &mut out);
            }
            SfvDictMember::InnerList(inner) => {
                serialize_inner_list(inner, &mut out);
            }
        }
    }
    out
}

/// Serialize an SFV Inner List to a string.
pub fn serialize_inner_list(list: &SfvInnerList, out: &mut String) {
    out.push('(');
    for (i, item) in list.items.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        serialize_bare_item(&item.value, out);
        serialize_params(&item.params, out);
    }
    out.push(')');
    serialize_params(&list.params, out);
}

/// Serialize an SFV Inner List to a new string.
#[must_use]
pub fn serialize_inner_list_to_string(list: &SfvInnerList) -> String {
    let mut out = String::new();
    serialize_inner_list(list, &mut out);
    out
}

/// Serialize an SFV Item to a string.
#[must_use]
pub fn serialize_item(item: &SfvItem) -> String {
    let mut out = String::new();
    serialize_bare_item(&item.value, &mut out);
    serialize_params(&item.params, &mut out);
    out
}

fn serialize_bare_item(item: &SfvBareItem, out: &mut String) {
    match item {
        SfvBareItem::Integer(v) => {
            use std::fmt::Write;
            // Writing to a String never fails; ignore the formal Result.
            let _written = write!(out, "{v}");
        }
        SfvBareItem::Decimal(v) => {
            // RFC 8941 §4.1.5: serialize with up to 3 fractional digits,
            // at least 1 fractional digit.
            let s = format!("{v:.3}");
            // Trim trailing zeros but keep at least one fractional digit
            let s = s.trim_end_matches('0');
            let s = if s.ends_with('.') {
                format!("{s}0")
            } else {
                s.to_string()
            };
            out.push_str(&s);
        }
        SfvBareItem::String(s) => {
            out.push('"');
            for ch in s.chars() {
                if ch == '"' || ch == '\\' {
                    out.push('\\');
                }
                out.push(ch);
            }
            out.push('"');
        }
        SfvBareItem::Token(t) => {
            out.push_str(t);
        }
        SfvBareItem::ByteSequence(bytes) => {
            out.push(':');
            out.push_str(&STANDARD.encode(bytes));
            out.push(':');
        }
        SfvBareItem::Boolean(b) => {
            out.push('?');
            out.push(if *b { '1' } else { '0' });
        }
    }
}

fn serialize_params(params: &SfvParams, out: &mut String) {
    for (key, value) in params.iter() {
        out.push(';');
        out.push_str(key);
        if let Some(val) = value {
            out.push('=');
            serialize_bare_item(val, out);
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::sfv::parse;

    #[test]
    fn test_serialize_item_integer() {
        let item = SfvItem {
            value: SfvBareItem::Integer(42),
            params: SfvParams::new(),
        };
        assert_eq!(serialize_item(&item), "42");
    }

    #[test]
    fn test_serialize_item_string() {
        let item = SfvItem {
            value: SfvBareItem::String("hello".into()),
            params: SfvParams::new(),
        };
        assert_eq!(serialize_item(&item), "\"hello\"");
    }

    #[test]
    fn test_serialize_byte_sequence() {
        let item = SfvItem {
            value: SfvBareItem::ByteSequence(b"test".to_vec()),
            params: SfvParams::new(),
        };
        assert_eq!(serialize_item(&item), ":dGVzdA==:");
    }

    #[test]
    fn test_serialize_inner_list() {
        let list = SfvInnerList {
            items: vec![
                SfvItem {
                    value: SfvBareItem::String("@method".into()),
                    params: SfvParams::new(),
                },
                SfvItem {
                    value: SfvBareItem::String("@authority".into()),
                    params: SfvParams::new(),
                },
            ],
            params: {
                let mut p = SfvParams::new();
                p.insert("created".into(), Some(SfvBareItem::Integer(1_618_884_473)));
                p
            },
        };
        let s = serialize_inner_list_to_string(&list);
        assert_eq!(s, "(\"@method\" \"@authority\");created=1618884473");
    }

    #[test]
    fn test_serialize_dictionary() {
        let dict = SfvDictionary {
            entries: vec![
                (
                    "sig1".into(),
                    SfvDictMember::Item(SfvItem {
                        value: SfvBareItem::ByteSequence(b"test".to_vec()),
                        params: SfvParams::new(),
                    }),
                ),
                (
                    "sig2".into(),
                    SfvDictMember::Item(SfvItem {
                        value: SfvBareItem::ByteSequence(b"abc".to_vec()),
                        params: SfvParams::new(),
                    }),
                ),
            ],
        };
        assert_eq!(serialize_dictionary(&dict), "sig1=:dGVzdA==:, sig2=:YWJj:");
    }

    #[test]
    fn test_roundtrip_dictionary() {
        let input = "sig1=(\"@method\" \"@authority\");created=1618884473;alg=\"hmac-sha256\"";
        let dict = parse::parse_dictionary(input).unwrap();
        let output = serialize_dictionary(&dict);
        let dict2 = parse::parse_dictionary(&output).unwrap();
        assert_eq!(dict, dict2);
    }

    #[test]
    fn test_roundtrip_inner_list() {
        let input = "(\"@method\" \"content-type\");created=100;keyid=\"key1\"";
        let list = parse::parse_inner_list(input).unwrap();
        let output = serialize_inner_list_to_string(&list);
        let list2 = parse::parse_inner_list(&output).unwrap();
        assert_eq!(list, list2);
    }

    #[test]
    fn test_serialize_string_with_escape() {
        let item = SfvItem {
            value: SfvBareItem::String("he\"llo".into()),
            params: SfvParams::new(),
        };
        assert_eq!(serialize_item(&item), "\"he\\\"llo\"");
    }

    #[test]
    fn test_serialize_boolean_true() {
        let item = SfvItem {
            value: SfvBareItem::Boolean(true),
            params: SfvParams::new(),
        };
        assert_eq!(serialize_item(&item), "?1");
    }

    #[test]
    fn test_serialize_boolean_dict_member() {
        let dict = SfvDictionary {
            entries: vec![(
                "flag".into(),
                SfvDictMember::Item(SfvItem {
                    value: SfvBareItem::Boolean(true),
                    params: SfvParams::new(),
                }),
            )],
        };
        assert_eq!(serialize_dictionary(&dict), "flag");
    }

    #[test]
    fn test_serialize_decimal() {
        let item = SfvItem {
            value: SfvBareItem::Decimal(3.12),
            params: SfvParams::new(),
        };
        assert_eq!(serialize_item(&item), "3.12");
    }

    #[test]
    fn test_serialize_decimal_trailing_zeros() {
        let item = SfvItem {
            value: SfvBareItem::Decimal(1.0),
            params: SfvParams::new(),
        };
        assert_eq!(serialize_item(&item), "1.0");
    }

    #[test]
    fn test_serialize_negative_decimal() {
        let item = SfvItem {
            value: SfvBareItem::Decimal(-2.5),
            params: SfvParams::new(),
        };
        assert_eq!(serialize_item(&item), "-2.5");
    }

    #[test]
    fn test_roundtrip_decimal() {
        let input = "3.12";
        let item = parse::parse_item(input).unwrap();
        let output = serialize_item(&item);
        let item2 = parse::parse_item(&output).unwrap();
        assert_eq!(item, item2);
    }

    #[test]
    fn test_serialize_list() {
        let list = SfvList {
            members: vec![
                SfvDictMember::Item(SfvItem {
                    value: SfvBareItem::String("a".into()),
                    params: SfvParams::new(),
                }),
                SfvDictMember::Item(SfvItem {
                    value: SfvBareItem::Integer(42),
                    params: SfvParams::new(),
                }),
            ],
        };
        assert_eq!(serialize_list(&list), "\"a\", 42");
    }

    #[test]
    fn test_roundtrip_list() {
        let input = "\"a\", (\"b\" \"c\"), 42";
        let list = parse::parse_list(input).unwrap();
        let output = serialize_list(&list);
        let list2 = parse::parse_list(&output).unwrap();
        assert_eq!(list, list2);
    }
}
