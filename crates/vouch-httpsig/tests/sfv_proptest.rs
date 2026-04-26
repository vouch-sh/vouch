// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Property-based tests for the SFV parser/serializer roundtrip.

#![expect(
    clippy::unwrap_used,
    clippy::let_underscore_must_use,
    reason = "test code: panic on assertion failure is acceptable; proptest fuzz harness intentionally discards parse results"
)]

use proptest::prelude::*;

use vouch_httpsig::sfv::parse;
use vouch_httpsig::sfv::serialize;
use vouch_httpsig::sfv::types::*;

/// Strategy for valid SFV strings (printable ASCII, no backslash/quote issues).
fn sfv_string_strategy() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 ]{0,20}"
}

/// Strategy for valid SFV tokens (start with alpha or *, then token chars).
fn sfv_token_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-zA-Z][a-zA-Z0-9!#$%&'*+.^_`|~:/\\-]{0,15}",
        "\\*[a-zA-Z0-9!#$%&'*+.^_`|~:/\\-]{0,15}",
    ]
}

/// Strategy for valid SFV keys (lowercase + digits + _-.* after first char).
fn sfv_key_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_.*\\-]{0,10}"
}

/// Strategy for SFV integers within the RFC 8941 range.
fn sfv_integer_strategy() -> impl Strategy<Value = i64> {
    -999_999_999_999_999_i64..=999_999_999_999_999_i64
}

/// Strategy for SFV decimals (1-3 fractional digits, up to 12 integer digits).
fn sfv_decimal_strategy() -> impl Strategy<Value = f64> {
    (-999_999_999_999_i64..=999_999_999_999_i64, 0_u32..=999_u32).prop_map(
        |(int_part, frac_part)| {
            let frac = f64::from(frac_part) / 1000.0;
            int_part as f64 + frac.copysign(int_part as f64)
        },
    )
}

/// Strategy for SFV bare items (all 6 types).
fn sfv_bare_item_strategy() -> impl Strategy<Value = SfvBareItem> {
    prop_oneof![
        sfv_integer_strategy().prop_map(SfvBareItem::Integer),
        sfv_decimal_strategy().prop_map(SfvBareItem::Decimal),
        sfv_string_strategy().prop_map(SfvBareItem::String),
        sfv_token_strategy().prop_map(SfvBareItem::Token),
        prop::collection::vec(any::<u8>(), 0..32).prop_map(SfvBareItem::ByteSequence),
        any::<bool>().prop_map(SfvBareItem::Boolean),
    ]
}

/// Strategy for SFV parameters (0-3 params, insertion-order-preserving).
fn sfv_params_strategy() -> impl Strategy<Value = SfvParams> {
    prop::collection::vec(
        (
            sfv_key_strategy(),
            prop::option::of(prop_oneof![
                sfv_integer_strategy().prop_map(SfvBareItem::Integer),
                sfv_string_strategy().prop_map(SfvBareItem::String),
                sfv_token_strategy().prop_map(SfvBareItem::Token),
                any::<bool>().prop_map(SfvBareItem::Boolean),
            ]),
        ),
        0..3,
    )
    .prop_map(|entries| {
        let mut params = SfvParams::new();
        for (key, value) in entries {
            params.insert(key, value);
        }
        params
    })
}

/// Strategy for SFV items.
fn sfv_item_strategy() -> impl Strategy<Value = SfvItem> {
    (sfv_bare_item_strategy(), sfv_params_strategy())
        .prop_map(|(value, params)| SfvItem { value, params })
}

/// Strategy for SFV inner lists.
fn sfv_inner_list_strategy() -> impl Strategy<Value = SfvInnerList> {
    (
        prop::collection::vec(sfv_item_strategy(), 0..4),
        sfv_params_strategy(),
    )
        .prop_map(|(items, params)| SfvInnerList { items, params })
}

proptest! {
    #[test]
    fn test_item_roundtrip(item in sfv_item_strategy()) {
        let serialized = serialize::serialize_item(&item);
        let parsed = parse::parse_item(&serialized).unwrap();
        prop_assert_eq!(item, parsed);
    }

    #[test]
    fn test_inner_list_roundtrip(list in sfv_inner_list_strategy()) {
        let serialized = serialize::serialize_inner_list_to_string(&list);
        let parsed = parse::parse_inner_list(&serialized).unwrap();
        prop_assert_eq!(list, parsed);
    }

    #[test]
    fn test_dictionary_roundtrip(
        entries in prop::collection::vec(
            (sfv_key_strategy(), prop_oneof![
                sfv_item_strategy().prop_map(SfvDictMember::Item),
                sfv_inner_list_strategy().prop_map(SfvDictMember::InnerList),
            ]),
            1..4,
        )
    ) {
        let dict = SfvDictionary { entries };
        let serialized = serialize::serialize_dictionary(&dict);
        let parsed = parse::parse_dictionary(&serialized).unwrap();
        prop_assert_eq!(dict, parsed);
    }

    #[test]
    fn test_list_roundtrip(
        members in prop::collection::vec(
            prop_oneof![
                sfv_item_strategy().prop_map(SfvDictMember::Item),
                sfv_inner_list_strategy().prop_map(SfvDictMember::InnerList),
            ],
            1..4,
        )
    ) {
        let list = SfvList { members };
        let serialized = serialize::serialize_list(&list);
        let parsed = parse::parse_list(&serialized).unwrap();
        prop_assert_eq!(list, parsed);
    }

    #[test]
    fn test_integer_range(val in sfv_integer_strategy()) {
        let item = SfvItem {
            value: SfvBareItem::Integer(val),
            params: SfvParams::new(),
        };
        let serialized = serialize::serialize_item(&item);
        let parsed = parse::parse_item(&serialized).unwrap();
        prop_assert_eq!(item, parsed);
    }

    #[test]
    fn test_malformed_input_never_panics(s in "[\\x00-\\x7f]{0,300}") {
        let _ = parse::parse_dictionary(&s);
        let _ = parse::parse_list(&s);
        let _ = parse::parse_inner_list(&s);
        let _ = parse::parse_item(&s);
    }

    #[test]
    fn test_params_preserve_insertion_order(
        entries in prop::collection::vec(
            (sfv_key_strategy(), prop::option::of(
                sfv_integer_strategy().prop_map(SfvBareItem::Integer)
            )),
            1..5,
        )
    ) {
        let mut params = SfvParams::new();
        let mut unique_keys = Vec::new();
        for (key, value) in &entries {
            if !unique_keys.contains(key) {
                unique_keys.push(key.clone());
            }
            params.insert(key.clone(), value.clone());
        }
        // Verify iteration order matches insertion order of unique keys
        let iter_keys: Vec<&String> = params.iter().map(|(k, _)| k).collect();
        let expected_keys: Vec<&String> = unique_keys.iter().collect();
        prop_assert_eq!(iter_keys, expected_keys);
    }
}
