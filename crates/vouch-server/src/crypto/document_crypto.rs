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
#[derive(Debug)]
pub struct HpkeDocumentCrypto {
    public_key: rustls::crypto::hpke::HpkePublicKey,
    private_key: Zeroizing<Vec<u8>>,
    hmac_key: Zeroizing<Vec<u8>>,
}

impl HpkeDocumentCrypto {
    /// Create a new HPKE document crypto instance.
    ///
    /// `public_key_bytes`: raw big-endian uncompressed P-384 public key.
    /// `private_key_bytes`: raw big-endian P-384 private key (scalar).
    ///
    /// # Errors
    ///
    /// Returns an error if the HMAC key derivation fails.
    pub fn new(public_key_bytes: Vec<u8>, private_key_bytes: Vec<u8>) -> Result<Self> {
        let hmac_key = derive_hmac_key(&public_key_bytes)?;
        Ok(Self {
            public_key: rustls::crypto::hpke::HpkePublicKey(public_key_bytes),
            private_key: Zeroizing::new(private_key_bytes),
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

        let enc_bytes = doc
            .encapped_key
            .as_ref()
            .context("missing encapped_key for HPKE decryption")?;
        let enc_decoded = BASE64
            .decode(enc_bytes)
            .context("invalid base64 in encapped_key")?;
        let enc = rustls::crypto::hpke::EncapsulatedSecret(enc_decoded);

        let ciphertext = BASE64
            .decode(&doc.data)
            .context("invalid base64 in ciphertext")?;

        let private_key: rustls::crypto::hpke::HpkePrivateKey = self.private_key.to_vec().into();

        Self::hpke_suite()
            .open(&enc, info, aad, &ciphertext, &private_key)
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
fn derive_hmac_key(public_key: &[u8]) -> Result<Vec<u8>> {
    use aws_lc_rs::digest;
    use aws_lc_rs::hkdf;

    let pk_hash = digest::digest(&digest::SHA384, public_key);
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA384, pk_hash.as_ref());
    let prk = salt.extract(public_key);

    let mut hmac_key = [0u8; 32];
    prk.expand(&[b"vouch-index-hmac"], HkdfLen(32))
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?
        .fill(&mut hmac_key)
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
// DER-to-Raw P-384 Key Conversion
// ============================================================================

/// Extract the raw public key bytes from a DER-encoded
/// `SubjectPublicKeyInfo` structure (P-384).
///
/// KMS returns DER-encoded public keys. The rustls HPKE API requires raw
/// uncompressed point format (0x04 || x || y, 97 bytes for P-384).
///
/// # Errors
///
/// Returns an error if the DER is malformed or not a P-384 key.
pub fn p384_public_key_from_der(der: &[u8]) -> Result<Vec<u8>> {
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm  AlgorithmIdentifier,
    //   subjectPublicKey  BIT STRING
    // }
    // The BIT STRING's content (after the unused-bits byte) is the
    // uncompressed EC point.
    let mut parser = SimpleDerParser::new(der);
    parser.enter_sequence()?;
    parser.skip_element()?; // AlgorithmIdentifier
    let bit_string = parser.read_bit_string()?;

    // P-384 uncompressed point: 0x04 + 48 bytes x + 48 bytes y = 97 bytes
    if bit_string.len() != 97 {
        bail!(
            "unexpected P-384 public key length: {} (expected 97)",
            bit_string.len()
        );
    }
    if bit_string.first().copied() != Some(0x04) {
        bail!("P-384 public key is not in uncompressed point format");
    }
    Ok(bit_string)
}

/// Extract the raw private key scalar from a DER-encoded `ECPrivateKey`
/// structure (P-384, SEC 1 / RFC 5915).
///
/// # Errors
///
/// Returns an error if the DER is malformed or the key is not 48 bytes.
pub fn p384_private_key_from_der(der: &[u8]) -> Result<Vec<u8>> {
    // ECPrivateKey ::= SEQUENCE {
    //   version        INTEGER { ecPrivkeyVer1(1) },
    //   privateKey     OCTET STRING,
    //   parameters [0] ECParameters OPTIONAL,
    //   publicKey  [1] BIT STRING OPTIONAL
    // }
    let mut parser = SimpleDerParser::new(der);
    parser.enter_sequence()?;
    parser.skip_element()?; // version
    let private_key = parser.read_octet_string()?;

    if private_key.len() != 48 {
        bail!(
            "unexpected P-384 private key length: {} (expected 48)",
            private_key.len()
        );
    }
    Ok(private_key)
}

// ============================================================================
// Minimal DER Parser
// ============================================================================

/// Minimal DER parser for extracting keys from SPKI and ECPrivateKey
/// structures. Not a full ASN.1 parser — handles only the subset needed
/// for P-384 key extraction.
struct SimpleDerParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SimpleDerParser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }

    fn read_byte(&mut self) -> Result<u8> {
        let b = *self
            .remaining()
            .first()
            .context("unexpected end of DER data")?;
        self.pos += 1;
        Ok(b)
    }

    fn read_length(&mut self) -> Result<usize> {
        let first = self.read_byte()?;
        if first < 0x80 {
            return Ok(first as usize);
        }
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 {
            bail!("DER length too large: {num_bytes} length bytes");
        }
        let mut len: usize = 0;
        for _ in 0..num_bytes {
            let b = self.read_byte()?;
            len = len.checked_shl(8).context("DER length overflow")? | (b as usize);
        }
        Ok(len)
    }

    fn read_bytes(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(count).context("DER offset overflow")?;
        let slice = self
            .data
            .get(self.pos..end)
            .context("unexpected end of DER data")?;
        self.pos = end;
        Ok(slice)
    }

    fn enter_sequence(&mut self) -> Result<()> {
        let tag = self.read_byte()?;
        if tag != 0x30 {
            bail!("expected SEQUENCE (0x30), got 0x{tag:02x}");
        }
        let _len = self.read_length()?;
        Ok(())
    }

    fn skip_element(&mut self) -> Result<()> {
        let _tag = self.read_byte()?;
        let len = self.read_length()?;
        if self.pos.checked_add(len).is_none() || self.pos + len > self.data.len() {
            bail!("element extends past end of DER data");
        }
        self.pos += len;
        Ok(())
    }

    fn read_bit_string(&mut self) -> Result<Vec<u8>> {
        let tag = self.read_byte()?;
        if tag != 0x03 {
            bail!("expected BIT STRING (0x03), got 0x{tag:02x}");
        }
        let len = self.read_length()?;
        if len < 1 {
            bail!("BIT STRING too short");
        }
        let unused_bits = self.read_byte()?;
        if unused_bits != 0 {
            bail!("non-zero unused bits in BIT STRING: {unused_bits}");
        }
        let content = self.read_bytes(len - 1)?;
        Ok(content.to_vec())
    }

    fn read_octet_string(&mut self) -> Result<Vec<u8>> {
        let tag = self.read_byte()?;
        if tag != 0x04 {
            bail!("expected OCTET STRING (0x04), got 0x{tag:02x}");
        }
        let len = self.read_length()?;
        let content = self.read_bytes(len)?;
        Ok(content.to_vec())
    }
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

    fn make_test_crypto() -> HpkeDocumentCrypto {
        use rustls::crypto::hpke::Hpke;

        let suite = &rustls::crypto::aws_lc_rs::hpke::DH_KEM_P384_HKDF_SHA384_AES_256;
        let (pub_key, priv_key) = suite.generate_key_pair().unwrap();
        HpkeDocumentCrypto::new(pub_key.0, priv_key.secret_bytes().to_vec()).unwrap()
    }
}
