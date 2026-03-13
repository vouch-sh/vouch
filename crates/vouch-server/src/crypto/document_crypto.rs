// SPDX-License-Identifier: BUSL-1.1
//! Client-side document encryption using HPKE (RFC 9180).
//!
//! Provides two implementations of the [`DocumentCrypto`] trait:
//!
//! - [`HpkeDocumentCrypto`] — Production. Uses DHKEM(P-384) + HKDF-SHA384 + AES-256-GCM
//!   via `rustls::crypto::aws_lc_rs::hpke`. Writes require only the public key (no KMS call);
//!   reads require the private key (decrypted from KMS on startup).
//!
//! - [`PlaintextDocumentCrypto`] — Development. Identity functions: `seal()` returns plaintext
//!   JSON, `hmac_index()` returns plaintext values.

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD};
use rustls::crypto::hpke::{HpkePrivateKey, HpkePublicKey};
use zeroize::Zeroizing;

/// Encrypted document payload for storage.
#[derive(Debug, Clone)]
pub struct EncryptedDocument {
    /// Base64-encoded HPKE encapsulated key. `None` in dev/plaintext mode.
    pub encapped_key: Option<String>,
    /// Base64-encoded HPKE ciphertext (prod) or plaintext JSON (dev).
    pub data: String,
}

/// Trait for document-level encryption and index hashing.
///
/// `info` binds ciphertext to the document type (e.g., `b"user"`).
/// `aad` binds ciphertext to the specific document ID, preventing relocation.
pub trait DocumentCrypto: Send + Sync + std::fmt::Debug {
    /// Encrypt plaintext with the public key.
    ///
    /// # Errors
    ///
    /// Returns an error if HPKE sealing fails.
    fn seal(&self, info: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<EncryptedDocument>;

    /// Decrypt ciphertext with the private key.
    ///
    /// # Errors
    ///
    /// Returns an error if HPKE opening fails or the AAD/info don't match.
    fn open(&self, info: &[u8], aad: &[u8], doc: &EncryptedDocument) -> Result<Vec<u8>>;

    /// Compute a deterministic index value for blind equality lookups.
    ///
    /// In production: `base64url(HMAC-SHA256(hmac_key, value))`.
    /// In dev: returns `value` as-is.
    fn hmac_index(&self, value: &str) -> String;
}

// ============================================================================
// Plaintext Implementation (Development)
// ============================================================================

/// Development-mode crypto that performs no encryption.
///
/// `seal()` stores plaintext JSON directly. `hmac_index()` returns the
/// plaintext value, enabling human-readable database inspection during
/// development.
#[derive(Debug)]
pub struct PlaintextDocumentCrypto;

impl DocumentCrypto for PlaintextDocumentCrypto {
    fn seal(&self, _info: &[u8], _aad: &[u8], plaintext: &[u8]) -> Result<EncryptedDocument> {
        let data = String::from_utf8(plaintext.to_vec()).context("plaintext is not valid UTF-8")?;
        Ok(EncryptedDocument {
            encapped_key: None,
            data,
        })
    }

    fn open(&self, _info: &[u8], _aad: &[u8], doc: &EncryptedDocument) -> Result<Vec<u8>> {
        Ok(doc.data.as_bytes().to_vec())
    }

    fn hmac_index(&self, value: &str) -> String {
        value.to_string()
    }
}

// ============================================================================
// HPKE Implementation (Production)
// ============================================================================

/// Production crypto using HPKE (RFC 9180) with DHKEM(P-384) + HKDF-SHA384 +
/// AES-256-GCM.
///
/// The public key is used for `seal()` (no KMS call needed). The private key
/// is used for `open()` (decrypted from KMS on startup). The HMAC key is
/// derived from the public key via HKDF so that writers can compute index
/// values without access to the private key.
pub struct HpkeDocumentCrypto {
    public_key: HpkePublicKey,
    private_key: HpkePrivateKey,
    hmac_key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for HpkeDocumentCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HpkeDocumentCrypto")
            .field(
                "public_key",
                &format_args!("[{} bytes]", self.public_key.0.len()),
            )
            .field("private_key", &"[REDACTED]")
            .field("hmac_key", &"[REDACTED]")
            .finish()
    }
}

impl HpkeDocumentCrypto {
    /// Create a new HPKE document crypto instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the HMAC key derivation fails.
    pub fn new(public_key: HpkePublicKey, private_key: HpkePrivateKey) -> Result<Self> {
        let hmac_key = derive_hmac_key(&public_key.0)?;
        Ok(Self {
            public_key,
            private_key,
            hmac_key: Zeroizing::new(hmac_key),
        })
    }

    fn hpke_suite() -> &'static rustls::crypto::aws_lc_rs::hpke::HpkeAwsLcRs<32, 48> {
        rustls::crypto::aws_lc_rs::hpke::DH_KEM_P384_HKDF_SHA384_AES_256
    }
}

impl DocumentCrypto for HpkeDocumentCrypto {
    fn seal(&self, info: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<EncryptedDocument> {
        use rustls::crypto::hpke::Hpke;

        let (enc, ciphertext) = Self::hpke_suite()
            .seal(info, aad, plaintext, &self.public_key)
            .map_err(|e| anyhow::anyhow!("HPKE seal failed: {e}"))?;

        Ok(EncryptedDocument {
            encapped_key: Some(BASE64.encode(&enc.0)),
            data: BASE64.encode(&ciphertext),
        })
    }

    fn open(&self, info: &[u8], aad: &[u8], doc: &EncryptedDocument) -> Result<Vec<u8>> {
        use rustls::crypto::hpke::Hpke;

        let Some(enc_bytes) = doc.encapped_key.as_ref() else {
            tracing::debug!(
                doc_type = %String::from_utf8_lossy(info),
                doc_id = %String::from_utf8_lossy(aad),
                "no encapped_key found; returning as unencrypted plaintext"
            );
            return Ok(doc.data.as_bytes().to_vec());
        };
        let enc_decoded = BASE64
            .decode(enc_bytes)
            .context("invalid base64 in encapped_key")?;
        let enc = rustls::crypto::hpke::EncapsulatedSecret(enc_decoded);

        let ciphertext = BASE64
            .decode(&doc.data)
            .context("invalid base64 in ciphertext")?;

        Self::hpke_suite()
            .open(&enc, info, aad, &ciphertext, &self.private_key)
            .map_err(|e| anyhow::anyhow!("HPKE open failed: {e}"))
    }

    fn hmac_index(&self, value: &str) -> String {
        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &self.hmac_key);
        let tag = aws_lc_rs::hmac::sign(&key, value.as_bytes());
        URL_SAFE_NO_PAD.encode(tag.as_ref())
    }
}

// ============================================================================
// HMAC Key Derivation
// ============================================================================

/// Derive a 32-byte HMAC key from the public key using HKDF-SHA384.
///
/// `HKDF-SHA384(salt=SHA384(public_key), ikm=public_key, info="vouch-index-hmac")` → 32 bytes.
///
/// The public key is used as IKM intentionally: the HMAC key enables
/// deterministic blind indexing (equality lookups without decryption),
/// not confidentiality. Anyone with the public key can compute index
/// values — this is by design, so that writers can index documents
/// without access to the private key.
fn derive_hmac_key(public_key: &[u8]) -> Result<Vec<u8>> {
    use aws_lc_rs::digest;
    use aws_lc_rs::hkdf;

    let pk_hash = digest::digest(&digest::SHA384, public_key);
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA384, pk_hash.as_ref());
    let prk = salt.extract(public_key);

    let mut hmac_key = Zeroizing::new([0u8; 32]);
    prk.expand(&[b"vouch-index-hmac"], HkdfLen(32))
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?
        .fill(&mut *hmac_key)
        .map_err(|_| anyhow::anyhow!("HKDF fill failed"))?;

    Ok(hmac_key.to_vec())
}

/// Helper type that implements `KeyType` for a fixed-length output.
struct HkdfLen(usize);

impl aws_lc_rs::hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

// ============================================================================
// DER-to-HPKE Key Conversion
// ============================================================================

/// Extract an HPKE key pair from a DER-encoded ECPrivateKey (SEC1/RFC 5915).
///
/// Uses `aws_lc_rs::agreement::PrivateKey` to parse the DER and extract
/// the raw P-384 scalar and uncompressed public point, then wraps them
/// in rustls HPKE types.
///
/// # Errors
///
/// Returns an error if the DER is malformed, the key is not P-384,
/// or the extracted key sizes are unexpected.
pub fn p384_hpke_keys_from_private_key_der(der: &[u8]) -> Result<(HpkePublicKey, HpkePrivateKey)> {
    use aws_lc_rs::agreement;
    use aws_lc_rs::encoding::AsBigEndian;

    let private_key = agreement::PrivateKey::from_private_key_der(&agreement::ECDH_P384, der)
        .map_err(|e| anyhow::anyhow!("failed to parse DER as P-384 ECPrivateKey: {e}"))?;

    let scalar: aws_lc_rs::encoding::EcPrivateKeyBin = private_key
        .as_be_bytes()
        .map_err(|e| anyhow::anyhow!("failed to extract P-384 private key scalar: {e}"))?;
    if scalar.as_ref().len() != 48 {
        bail!(
            "unexpected P-384 private key length: {} (expected 48)",
            scalar.as_ref().len()
        );
    }

    let public_point = private_key
        .compute_public_key()
        .map_err(|e| anyhow::anyhow!("failed to compute P-384 public key: {e}"))?;
    if public_point.as_ref().len() != 97 {
        bail!(
            "unexpected P-384 public key length: {} (expected 97)",
            public_point.as_ref().len()
        );
    }
    if public_point.as_ref().first().copied() != Some(0x04) {
        bail!("P-384 public key is not in uncompressed point format");
    }

    let hpke_private = HpkePrivateKey::from(scalar.as_ref().to_vec());
    let hpke_public = HpkePublicKey(public_point.as_ref().to_vec());

    Ok((hpke_public, hpke_private))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_roundtrip() {
        let crypto = PlaintextDocumentCrypto;
        let plaintext = b"hello, world";

        let sealed = crypto.seal(b"user", b"doc-123", plaintext).unwrap();
        assert!(sealed.encapped_key.is_none());
        assert_eq!(sealed.data, "hello, world");

        let opened = crypto.open(b"user", b"doc-123", &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn plaintext_hmac_index_is_identity() {
        let crypto = PlaintextDocumentCrypto;
        assert_eq!(crypto.hmac_index("test@example.com"), "test@example.com");
    }

    #[test]
    fn hpke_roundtrip() {
        let crypto = make_test_crypto();

        let plaintext = b"{\"email\":\"test@example.com\"}";
        let sealed = crypto.seal(b"user", b"doc-123", plaintext).unwrap();

        assert!(sealed.encapped_key.is_some());
        assert_ne!(sealed.data, String::from_utf8_lossy(plaintext));

        let opened = crypto.open(b"user", b"doc-123", &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn hpke_aad_binding() {
        let crypto = make_test_crypto();

        let plaintext = b"secret data";
        let sealed = crypto.seal(b"user", b"doc-123", plaintext).unwrap();

        // Opening with different AAD (different doc ID) should fail
        let result = crypto.open(b"user", b"doc-456", &sealed);
        assert!(result.is_err());
    }

    #[test]
    fn hpke_info_binding() {
        let crypto = make_test_crypto();

        let plaintext = b"secret data";
        let sealed = crypto.seal(b"user", b"doc-123", plaintext).unwrap();

        // Opening with different info (different doc type) should fail
        let result = crypto.open(b"session", b"doc-123", &sealed);
        assert!(result.is_err());
    }

    #[test]
    fn hpke_hmac_index_deterministic() {
        let crypto = make_test_crypto();

        let a = crypto.hmac_index("test@example.com");
        let b = crypto.hmac_index("test@example.com");
        assert_eq!(a, b);

        let c = crypto.hmac_index("other@example.com");
        assert_ne!(a, c);
    }

    #[test]
    fn hpke_hmac_index_differs_across_keys() {
        let crypto1 = make_test_crypto();
        let crypto2 = make_test_crypto();

        let a = crypto1.hmac_index("test@example.com");
        let b = crypto2.hmac_index("test@example.com");
        assert_ne!(a, b);
    }

    #[test]
    fn hpke_each_seal_produces_different_ciphertext() {
        let crypto = make_test_crypto();

        let plaintext = b"same data";
        let sealed1 = crypto.seal(b"user", b"doc-123", plaintext).unwrap();
        let sealed2 = crypto.seal(b"user", b"doc-123", plaintext).unwrap();

        // Ephemeral keys differ per seal
        assert_ne!(sealed1.encapped_key, sealed2.encapped_key);
        assert_ne!(sealed1.data, sealed2.data);

        // Both still decrypt to the same plaintext
        let opened1 = crypto.open(b"user", b"doc-123", &sealed1).unwrap();
        let opened2 = crypto.open(b"user", b"doc-123", &sealed2).unwrap();
        assert_eq!(opened1, plaintext);
        assert_eq!(opened2, plaintext);
    }

    #[test]
    fn p384_key_sizes() {
        use rustls::crypto::hpke::Hpke;

        let suite = &rustls::crypto::aws_lc_rs::hpke::DH_KEM_P384_HKDF_SHA384_AES_256;
        let (pub_key, priv_key) = suite.generate_key_pair().unwrap();

        assert_eq!(pub_key.0.len(), 97); // uncompressed P-384
        assert_eq!(priv_key.secret_bytes().len(), 48); // P-384 scalar
    }

    #[test]
    fn p384_der_roundtrip() {
        // Generate a P-384 key pair via agreement API, export as DER,
        // then parse it back with our function
        use aws_lc_rs::agreement;
        use aws_lc_rs::encoding::AsDer;

        let private_key = agreement::PrivateKey::generate(&agreement::ECDH_P384).unwrap();
        let der: aws_lc_rs::encoding::EcPrivateKeyRfc5915Der = private_key.as_der().unwrap();
        let (pub_key, priv_key) = p384_hpke_keys_from_private_key_der(der.as_ref()).unwrap();

        assert_eq!(pub_key.0.len(), 97);
        assert_eq!(priv_key.secret_bytes().len(), 48);

        // Verify the extracted keys work for HPKE
        let crypto = HpkeDocumentCrypto::new(pub_key, priv_key).unwrap();
        let sealed = crypto.seal(b"test", b"aad", b"hello").unwrap();
        let opened = crypto.open(b"test", b"aad", &sealed).unwrap();
        assert_eq!(opened, b"hello");
    }

    #[test]
    fn hpke_plaintext_fallback() {
        let crypto = make_test_crypto();
        let doc = EncryptedDocument {
            encapped_key: None,
            data: r#"{"email":"test@example.com"}"#.to_string(),
        };
        let opened = crypto.open(b"user", b"doc-123", &doc).unwrap();
        assert_eq!(opened, br#"{"email":"test@example.com"}"#);
    }

    #[test]
    fn hpke_plaintext_fallback_ignores_info_and_aad() {
        let crypto = make_test_crypto();
        let doc = EncryptedDocument {
            encapped_key: None,
            data: "hello".to_string(),
        };
        // Different info/aad values should not affect fallback
        let a = crypto.open(b"user", b"doc-1", &doc).unwrap();
        let b = crypto.open(b"session", b"doc-999", &doc).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, b"hello");
    }

    #[test]
    fn hpke_plaintext_fallback_empty_data() {
        let crypto = make_test_crypto();
        let doc = EncryptedDocument {
            encapped_key: None,
            data: String::new(),
        };
        let opened = crypto.open(b"user", b"doc-1", &doc).unwrap();
        assert!(opened.is_empty());
    }

    #[test]
    fn hpke_open_invalid_base64_in_encapped_key() {
        let crypto = make_test_crypto();
        let doc = EncryptedDocument {
            encapped_key: Some("not-valid-base64!!!".to_string()),
            data: BASE64.encode(b"ciphertext"),
        };
        let err = crypto.open(b"user", b"doc-1", &doc).unwrap_err();
        assert!(
            format!("{err:#}").contains("base64"),
            "expected base64 error, got: {err:#}"
        );
    }

    #[test]
    fn hpke_open_invalid_base64_in_data() {
        let crypto = make_test_crypto();
        // Valid base64 for encapped_key but garbage for data
        let doc = EncryptedDocument {
            encapped_key: Some(BASE64.encode(b"fake-encapped-key")),
            data: "not-valid-base64!!!".to_string(),
        };
        let err = crypto.open(b"user", b"doc-1", &doc).unwrap_err();
        assert!(
            format!("{err:#}").contains("base64"),
            "expected base64 error, got: {err:#}"
        );
    }

    fn make_test_crypto() -> HpkeDocumentCrypto {
        use rustls::crypto::hpke::Hpke;

        let suite = &rustls::crypto::aws_lc_rs::hpke::DH_KEM_P384_HKDF_SHA384_AES_256;
        let (pub_key, priv_key) = suite.generate_key_pair().unwrap();
        HpkeDocumentCrypto::new(pub_key, priv_key.secret_bytes().to_vec().into()).unwrap()
    }
}
