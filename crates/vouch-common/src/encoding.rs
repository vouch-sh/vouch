// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Type-safe encoding wrappers for FIDO2 data.
//!
//! This module provides compile-time tracking of data encoding formats.
//! The key insight is that the same bytes can be represented differently:
//! - Raw bytes (for internal processing, binary protocols)
//! - Base64url strings (for browser APIs, JSON in WebAuthn)
//!
//! By tracking the encoding at the type level, we prevent mixing up
//! raw bytes with base64url-decoded bytes at compile time.
//!
//! # Example
//!
//! ```rust
//! use vouch_common::encoding::{Encoded, Raw, Base64Url, ConvertEncoding};
//!
//! // Create from raw bytes
//! struct ChallengeData;
//! let raw: Encoded<ChallengeData, Raw> = Encoded::from_raw(vec![1, 2, 3]);
//!
//! // Convert to base64url for browser
//! let b64 = raw.clone().to_base64url();
//! assert_eq!(b64.as_base64url(), "AQID");
//!
//! // Convert back
//! let back = b64.to_raw();
//! assert_eq!(raw.as_bytes(), back.as_bytes());
//! ```

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::marker::PhantomData;

// ============================================================================
// Encoding Markers
// ============================================================================

/// Marker trait for data encoding formats.
///
/// This is a sealed trait - only `Raw` and `Base64Url` implement it.
pub trait Encoding: private::Sealed + Clone + Default + Send + Sync + 'static {}

/// Raw bytes (no encoding applied).
///
/// Use this when working with binary data internally or with binary protocols.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Raw;

/// Base64url encoding (URL-safe, no padding).
///
/// Use this when data needs to be transmitted as a string (JSON, URLs).
/// This is the encoding used by WebAuthn browser APIs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Base64Url;

impl Encoding for Raw {}
impl Encoding for Base64Url {}

mod private {
    pub trait Sealed {}
    impl Sealed for super::Raw {}
    impl Sealed for super::Base64Url {}
}

// ============================================================================
// Encoded<T, E> - The Core Type
// ============================================================================

/// A value with encoding tracked at the type level.
///
/// - `T` is a semantic marker (e.g., `ChallengeData`, `CredentialIdData`)
/// - `E` is the encoding format (`Raw` or `Base64Url`)
///
/// The underlying data is always stored as decoded bytes internally.
/// The encoding marker only affects serialization/deserialization.
pub struct Encoded<T, E: Encoding> {
    /// The actual bytes (always stored decoded)
    data: Vec<u8>,
    /// Phantom data for the semantic type and encoding
    _marker: PhantomData<(T, E)>,
}

// Manual Clone implementation to avoid requiring T: Clone
impl<T, E: Encoding> Clone for Encoded<T, E> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            _marker: PhantomData,
        }
    }
}

// Manual PartialEq implementation to avoid requiring T: PartialEq
impl<T, E: Encoding> PartialEq for Encoded<T, E> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<T, E: Encoding> Eq for Encoded<T, E> {}

impl<T, E: Encoding> Encoded<T, E> {
    /// Access the underlying bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Consume and return the underlying bytes.
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Get the length of the underlying data.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the data is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ============================================================================
// Raw-specific methods
// ============================================================================

impl<T> Encoded<T, Raw> {
    /// Create from raw bytes.
    #[inline]
    pub fn from_raw(data: Vec<u8>) -> Self {
        Self {
            data,
            _marker: PhantomData,
        }
    }

    /// Create from a byte slice.
    #[inline]
    pub fn from_slice(data: &[u8]) -> Self {
        Self::from_raw(data.to_vec())
    }
}

// ============================================================================
// Base64Url-specific methods
// ============================================================================

impl<T> Encoded<T, Base64Url> {
    /// Create from a base64url-encoded string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not valid base64url.
    pub fn from_base64url(s: &str) -> Result<Self, base64::DecodeError> {
        use base64::Engine;
        let data = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?;
        Ok(Self {
            data,
            _marker: PhantomData,
        })
    }

    /// Get the base64url string representation.
    pub fn as_base64url(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.data)
    }
}

// ============================================================================
// Encoding Conversion
// ============================================================================

/// Trait for converting between encodings.
///
/// This is the main way to switch between `Raw` and `Base64Url` encodings.
pub trait ConvertEncoding<T>: Sized {
    /// Convert to raw encoding.
    fn to_raw(self) -> Encoded<T, Raw>;
    /// Convert to base64url encoding.
    fn to_base64url(self) -> Encoded<T, Base64Url>;
}

impl<T> ConvertEncoding<T> for Encoded<T, Raw> {
    #[inline]
    fn to_raw(self) -> Encoded<T, Raw> {
        self
    }

    #[inline]
    fn to_base64url(self) -> Encoded<T, Base64Url> {
        Encoded {
            data: self.data,
            _marker: PhantomData,
        }
    }
}

impl<T> ConvertEncoding<T> for Encoded<T, Base64Url> {
    #[inline]
    fn to_raw(self) -> Encoded<T, Raw> {
        Encoded {
            data: self.data,
            _marker: PhantomData,
        }
    }

    #[inline]
    fn to_base64url(self) -> Encoded<T, Base64Url> {
        self
    }
}

// ============================================================================
// Serde Implementations
// ============================================================================

// Raw encoding: serialize as byte array [1,2,3] (JSON) or raw bytes (binary formats)
impl<T> Serialize for Encoded<T, Raw> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.data.serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for Encoded<T, Raw> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let data = Vec::<u8>::deserialize(deserializer)?;
        Ok(Self::from_raw(data))
    }
}

// Base64Url encoding: serialize as string "AQID" (for browser APIs)
impl<T> Serialize for Encoded<T, Base64Url> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_base64url())
    }
}

impl<'de, T> Deserialize<'de> for Encoded<T, Base64Url> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_base64url(&s).map_err(serde::de::Error::custom)
    }
}

// ============================================================================
// From/Into Conversions
// ============================================================================

// Allow direct conversion from Vec<u8> for ease of use
impl<T> From<Vec<u8>> for Encoded<T, Raw> {
    #[inline]
    fn from(data: Vec<u8>) -> Self {
        Self::from_raw(data)
    }
}

impl<T> From<Encoded<T, Raw>> for Vec<u8> {
    #[inline]
    fn from(encoded: Encoded<T, Raw>) -> Self {
        encoded.into_bytes()
    }
}

// Allow conversion from &[u8] slices
impl<T> From<&[u8]> for Encoded<T, Raw> {
    #[inline]
    fn from(data: &[u8]) -> Self {
        Self::from_slice(data)
    }
}

// Allow direct conversion from String for Base64Url
impl<T> TryFrom<String> for Encoded<T, Base64Url> {
    type Error = base64::DecodeError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_base64url(&s)
    }
}

impl<T> TryFrom<&str> for Encoded<T, Base64Url> {
    type Error = base64::DecodeError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::from_base64url(s)
    }
}

impl<T> From<Encoded<T, Base64Url>> for String {
    fn from(encoded: Encoded<T, Base64Url>) -> Self {
        encoded.as_base64url()
    }
}

// ============================================================================
// Standard Trait Implementations (aws-lc-rs pattern)
// ============================================================================

impl<T, E: Encoding> AsRef<[u8]> for Encoded<T, E> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<T, E: Encoding> std::ops::Deref for Encoded<T, E> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

// Borrow as slice (aws-lc-rs pattern)
impl<T, E: Encoding> std::borrow::Borrow<[u8]> for Encoded<T, E> {
    #[inline]
    fn borrow(&self) -> &[u8] {
        &self.data
    }
}

// Hash for use in HashMaps (credential_id lookups)
impl<T, E: Encoding> std::hash::Hash for Encoded<T, E> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.data.hash(state);
    }
}

// Debug implementation - show hex for readability
impl<T, E: Encoding> std::fmt::Debug for Encoded<T, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Truncate long data for readability
        let hex = if self.data.len() > 16 {
            format!(
                "{}...",
                hex::encode(self.data.get(..16).unwrap_or(&self.data))
            )
        } else {
            hex::encode(&self.data)
        };
        f.debug_struct("Encoded")
            .field("len", &self.data.len())
            .field("data", &hex)
            .finish()
    }
}

// Hex formatting for debugging (aws-lc-rs pattern)
impl<T, E: Encoding> std::fmt::LowerHex for Encoded<T, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.data {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // Test marker type
    struct TestData;

    #[test]
    fn test_raw_round_trip() {
        let original = vec![1u8, 2, 3, 4, 5];
        let encoded: Encoded<TestData, Raw> = Encoded::from_raw(original.clone());
        assert_eq!(encoded.as_bytes(), &original);
        assert_eq!(encoded.into_bytes(), original);
    }

    #[test]
    fn test_base64url_round_trip() {
        let original = vec![1u8, 2, 3];
        let raw: Encoded<TestData, Raw> = Encoded::from_raw(original.clone());
        let b64 = raw.to_base64url();
        assert_eq!(b64.as_base64url(), "AQID");
        let back = b64.to_raw();
        assert_eq!(back.as_bytes(), &original);
    }

    #[test]
    fn test_from_base64url_string() {
        let encoded: Encoded<TestData, Base64Url> = Encoded::from_base64url("AQID").unwrap();
        assert_eq!(encoded.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn test_serde_raw_json() {
        let original: Encoded<TestData, Raw> = Encoded::from_raw(vec![1, 2, 3]);
        let json = serde_json::to_string(&original).unwrap();
        // Raw encoding uses JSON array format
        assert_eq!(json, "[1,2,3]");
        let decoded: Encoded<TestData, Raw> = serde_json::from_str(&json).unwrap();
        assert_eq!(original.as_bytes(), decoded.as_bytes());
    }

    #[test]
    fn test_serde_base64url_json() {
        let raw: Encoded<TestData, Raw> = Encoded::from_raw(vec![1, 2, 3]);
        let original: Encoded<TestData, Base64Url> = raw.to_base64url();
        let json = serde_json::to_string(&original).unwrap();
        // Base64Url encoding uses string format
        assert_eq!(json, "\"AQID\"");
        let decoded: Encoded<TestData, Base64Url> = serde_json::from_str(&json).unwrap();
        assert_eq!(original.as_bytes(), decoded.as_bytes());
    }

    #[test]
    fn test_from_vec() {
        let data = vec![1u8, 2, 3];
        let encoded: Encoded<TestData, Raw> = data.clone().into();
        assert_eq!(encoded.as_bytes(), &data);
    }

    #[test]
    fn test_into_vec() {
        let encoded: Encoded<TestData, Raw> = Encoded::from_raw(vec![1, 2, 3]);
        let data: Vec<u8> = encoded.into();
        assert_eq!(data, vec![1, 2, 3]);
    }

    #[test]
    fn test_from_slice() {
        let slice = &[1u8, 2, 3][..];
        let encoded: Encoded<TestData, Raw> = slice.into();
        assert_eq!(encoded.as_bytes(), slice);
    }

    #[test]
    fn test_as_ref() {
        let encoded: Encoded<TestData, Raw> = Encoded::from_raw(vec![1, 2, 3]);
        let slice: &[u8] = encoded.as_ref();
        assert_eq!(slice, &[1, 2, 3]);
    }

    #[test]
    fn test_deref() {
        let encoded: Encoded<TestData, Raw> = Encoded::from_raw(vec![1, 2, 3]);
        // Can use slice methods via Deref
        assert_eq!(encoded.len(), 3);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;

        let e1: Encoded<TestData, Raw> = Encoded::from_raw(vec![1, 2, 3]);
        let e2: Encoded<TestData, Raw> = Encoded::from_raw(vec![1, 2, 3]);
        let e3: Encoded<TestData, Raw> = Encoded::from_raw(vec![4, 5, 6]);

        let mut set = HashSet::new();
        set.insert(e1.clone());
        assert!(set.contains(&e2));
        assert!(!set.contains(&e3));
    }

    #[test]
    fn test_debug() {
        let encoded: Encoded<TestData, Raw> = Encoded::from_raw(vec![0xAB, 0xCD]);
        let debug = format!("{:?}", encoded);
        assert!(debug.contains("abcd"));
    }

    #[test]
    fn test_lower_hex() {
        let encoded: Encoded<TestData, Raw> = Encoded::from_raw(vec![0xAB, 0xCD, 0xEF]);
        let hex = format!("{:x}", encoded);
        assert_eq!(hex, "abcdef");
    }

    #[test]
    fn test_empty() {
        let encoded: Encoded<TestData, Raw> = Encoded::from_raw(vec![]);
        assert!(encoded.is_empty());
        assert_eq!(encoded.len(), 0);
    }

    #[test]
    fn test_all_byte_values() {
        let all_bytes: Vec<u8> = (0..=255).collect();
        let raw: Encoded<TestData, Raw> = Encoded::from_raw(all_bytes.clone());

        // Test JSON round-trip
        let json = serde_json::to_string(&raw).unwrap();
        let decoded: Encoded<TestData, Raw> = serde_json::from_str(&json).unwrap();
        assert_eq!(all_bytes.as_slice(), decoded.as_bytes());

        // Test encoding conversion
        let b64 = raw.to_base64url();
        let back = b64.to_raw();
        assert_eq!(all_bytes.as_slice(), back.as_bytes());
    }

    #[test]
    fn test_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Encoded<TestData, Raw>>();
        assert_send_sync::<Encoded<TestData, Base64Url>>();
    }

    #[test]
    fn test_clone() {
        let original: Encoded<TestData, Raw> = Encoded::from_raw(vec![1, 2, 3]);
        let cloned = original.clone();
        assert_eq!(original.as_bytes(), cloned.as_bytes());
    }
}
