// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Structured Field Value types (RFC 8941).

/// An SFV bare item — the primitive values used inside structured fields.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum SfvBareItem {
    /// An integer value (RFC 8941 §3.3.1).
    /// Range: ±999,999,999,999,999.
    Integer(i64),
    /// A decimal value (RFC 8941 §3.3.2).
    /// Integer part up to 12 digits, fractional part up to 3 digits.
    Decimal(f64),
    /// A quoted string value (RFC 8941 §3.3.3).
    String(std::string::String),
    /// A token (unquoted alphanumeric identifier) (RFC 8941 §3.3.4).
    Token(std::string::String),
    /// A byte sequence (standard base64 in colons) (RFC 8941 §3.3.5).
    ByteSequence(Vec<u8>),
    /// A boolean value (RFC 8941 §3.3.6).
    Boolean(bool),
}

/// Insertion-order-preserving parameters attached to an SFV item or inner list
/// (RFC 8941 §3.1.2).
///
/// RFC 8941 requires parameters to be serialized in the order they appear.
/// This type preserves insertion order, unlike `BTreeMap` which sorts
/// alphabetically.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SfvParams {
    entries: Vec<(std::string::String, Option<SfvBareItem>)>,
}

impl SfvParams {
    /// Create an empty parameter set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert a parameter. If the key already exists, its value is replaced
    /// in-place (preserving its position).
    pub fn insert(&mut self, key: std::string::String, value: Option<SfvBareItem>) {
        if let Some(entry) = self.entries.iter_mut().find(|(k, _)| *k == key) {
            entry.1 = value;
        } else {
            self.entries.push((key, value));
        }
    }

    /// Look up a parameter value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Option<SfvBareItem>> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Check whether a parameter key exists.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.iter().any(|(k, _)| k == key)
    }

    /// Iterate over parameters in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&std::string::String, &Option<SfvBareItem>)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }
}

/// An SFV item: a bare item with optional parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct SfvItem {
    /// The bare item value.
    pub value: SfvBareItem,
    /// Parameters associated with this item.
    pub params: SfvParams,
}

/// An SFV inner list: a parenthesized sequence of items with parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct SfvInnerList {
    /// The items within the inner list.
    pub items: Vec<SfvItem>,
    /// Parameters associated with the inner list itself.
    pub params: SfvParams,
}

/// A member in an SFV dictionary — either an item or an inner list.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum SfvDictMember {
    /// A single item with parameters.
    Item(SfvItem),
    /// An inner list with parameters.
    InnerList(SfvInnerList),
}

/// An SFV list: an ordered sequence of members (RFC 8941 §3.1).
#[derive(Debug, Clone, PartialEq)]
pub struct SfvList {
    /// The ordered members in the list.
    pub members: Vec<SfvDictMember>,
}

/// An SFV dictionary: an ordered map of string keys to members (RFC 8941 §3.2).
#[derive(Debug, Clone, PartialEq)]
pub struct SfvDictionary {
    /// The ordered entries in the dictionary.
    pub entries: Vec<(std::string::String, SfvDictMember)>,
}

impl SfvDictionary {
    /// Look up a member by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&SfvDictMember> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
}
