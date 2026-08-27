// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9421 Signature Parameters.
//!
//! `SignatureParams` represents the metadata associated with a signature:
//! which components are covered, what algorithm was used, when it was created, etc.
//! It serializes to/from an SFV Inner List for the `Signature-Input` header.

use crate::component::ComponentIdentifier;
use crate::error::HttpSigError;
use crate::sfv::serialize::serialize_inner_list_to_string;
use crate::sfv::types::{SfvBareItem, SfvInnerList, SfvItem, SfvParams};

/// Signature parameters per RFC 9421 Section 2.3.
#[derive(Debug, Clone)]
pub struct SignatureParams {
    /// The ordered list of component identifiers covered by the signature.
    pub components: Vec<ComponentIdentifier>,
    /// The algorithm identifier (e.g., `"ecdsa-p256-sha256"`).
    pub alg: Option<String>,
    /// The key identifier.
    pub keyid: Option<String>,
    /// Creation timestamp (Unix seconds).
    pub created: Option<i64>,
    /// Expiration timestamp (Unix seconds).
    pub expires: Option<i64>,
    /// A nonce value for replay prevention.
    pub nonce: Option<String>,
    /// An application-specific tag.
    pub tag: Option<String>,
}

impl SignatureParams {
    /// Create empty signature params with no components.
    #[must_use]
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
            alg: None,
            keyid: None,
            created: None,
            expires: None,
            nonce: None,
            tag: None,
        }
    }

    /// Serialize to an SFV Inner List.
    #[must_use]
    pub fn to_inner_list(&self) -> SfvInnerList {
        let items: Vec<SfvItem> = self
            .components
            .iter()
            .map(ComponentIdentifier::to_sfv_item)
            .collect();

        let mut params = SfvParams::new();
        if let Some(ref alg) = self.alg {
            params.insert("alg".into(), Some(SfvBareItem::String(alg.clone())));
        }
        if let Some(created) = self.created {
            params.insert("created".into(), Some(SfvBareItem::Integer(created)));
        }
        if let Some(expires) = self.expires {
            params.insert("expires".into(), Some(SfvBareItem::Integer(expires)));
        }
        if let Some(ref keyid) = self.keyid {
            params.insert("keyid".into(), Some(SfvBareItem::String(keyid.clone())));
        }
        if let Some(ref nonce) = self.nonce {
            params.insert("nonce".into(), Some(SfvBareItem::String(nonce.clone())));
        }
        if let Some(ref tag) = self.tag {
            params.insert("tag".into(), Some(SfvBareItem::String(tag.clone())));
        }

        SfvInnerList { items, params }
    }

    /// Serialize to an SFV Inner List string.
    #[must_use]
    pub fn serialize(&self) -> String {
        serialize_inner_list_to_string(&self.to_inner_list())
    }

    /// Parse from an SFV Inner List.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::SfvParse`] on parse failure.
    pub fn from_inner_list(list: &SfvInnerList) -> Result<Self, HttpSigError> {
        let mut components = Vec::with_capacity(list.items.len());
        for item in &list.items {
            components.push(ComponentIdentifier::from_sfv_item(item)?);
        }

        let alg = extract_string_param(&list.params, "alg");
        let keyid = extract_string_param(&list.params, "keyid");
        let created = extract_integer_param(&list.params, "created");
        let expires = extract_integer_param(&list.params, "expires");
        let nonce = extract_string_param(&list.params, "nonce");
        let tag = extract_string_param(&list.params, "tag");

        Ok(Self {
            components,
            alg,
            keyid,
            created,
            expires,
            nonce,
            tag,
        })
    }
}

impl Default for SignatureParams {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_string_param(params: &SfvParams, key: &str) -> Option<String> {
    match params.get(key) {
        Some(Some(SfvBareItem::String(s))) => Some(s.clone()),
        _ => None,
    }
}

fn extract_integer_param(params: &SfvParams, key: &str) -> Option<i64> {
    match params.get(key) {
        Some(Some(SfvBareItem::Integer(n))) => Some(*n),
        _ => None,
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::sfv::parse::parse_inner_list;

    // RFC 9421 §2.3: signature parameters serialize as an Inner List with parameters.
    #[test]
    fn test_serialize_empty() {
        let params = SignatureParams::new();
        assert_eq!(params.serialize(), "()");
    }

    // RFC 9421 §2.3: covered component identifiers serialize in order.
    #[test]
    fn test_serialize_with_components() {
        let params = SignatureParams {
            components: vec![
                ComponentIdentifier::method(),
                ComponentIdentifier::authority(),
            ],
            alg: Some("hmac-sha256".into()),
            keyid: Some("test-key-1".into()),
            created: Some(1_618_884_473),
            expires: None,
            nonce: None,
            tag: None,
        };
        let s = params.serialize();
        assert!(s.contains("\"@method\""));
        assert!(s.contains("\"@authority\""));
        assert!(s.contains(";alg=\"hmac-sha256\""));
        assert!(s.contains(";created=1618884473"));
        assert!(s.contains(";keyid=\"test-key-1\""));
    }

    // RFC 9421 §2.3: serialized signature parameters parse back to the same value.
    #[test]
    fn test_roundtrip() {
        let params = SignatureParams {
            components: vec![
                ComponentIdentifier::method(),
                ComponentIdentifier::path(),
                ComponentIdentifier::field("content-type"),
            ],
            alg: Some("ecdsa-p256-sha256".into()),
            keyid: Some("my-key".into()),
            created: Some(1_618_884_473),
            expires: Some(1_618_888_073),
            nonce: Some("abc123".into()),
            tag: Some("vouch-api".into()),
        };

        let serialized = params.serialize();
        let list = parse_inner_list(&serialized).unwrap();
        let parsed = SignatureParams::from_inner_list(&list).unwrap();

        assert_eq!(parsed.components.len(), 3);
        assert_eq!(parsed.alg.as_deref(), Some("ecdsa-p256-sha256"));
        assert_eq!(parsed.keyid.as_deref(), Some("my-key"));
        assert_eq!(parsed.created, Some(1_618_884_473));
        assert_eq!(parsed.expires, Some(1_618_888_073));
        assert_eq!(parsed.nonce.as_deref(), Some("abc123"));
        assert_eq!(parsed.tag.as_deref(), Some("vouch-api"));
    }

    // RFC 9421 §2.3: the parameter form given in the specification parses.
    #[test]
    fn test_parse_from_rfc_example() {
        let input = "(\"@method\" \"@authority\" \"content-type\")\
                     ;created=1618884473;alg=\"hmac-sha256\";keyid=\"test-key-1\"";
        let list = parse_inner_list(input).unwrap();
        let params = SignatureParams::from_inner_list(&list).unwrap();

        assert_eq!(params.components.len(), 3);
        assert_eq!(params.alg.as_deref(), Some("hmac-sha256"));
        assert_eq!(params.keyid.as_deref(), Some("test-key-1"));
        assert_eq!(params.created, Some(1_618_884_473));
    }
}
