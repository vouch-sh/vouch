// SPDX-License-Identifier: Apache-2.0 OR MIT
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
//!
//! ## Cipher-suite agility
//!
//! Every encapsulated key written since suite tagging landed is self-describing:
//! `hpke:<kem_id>:<kdf_id>:<aead_id>:<base64>` with the RFC 9180 codepoints in
//! four-digit lowercase hex. Untagged values (plain base64) predate tagging and
//! are read as [`LEGACY_SUITE`]. This lets rows sealed under different suites
//! coexist in one database, so a future KEM migration (e.g. the ML-KEM hybrids
//! from draft-ietf-hpke-pq) is a key rotation, not a format break.

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD};
use rustls::crypto::hpke::{Hpke, HpkePrivateKey, HpkePublicKey};
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

    /// Whether documents are actually encrypted at rest.
    ///
    /// `true` for real (KMS-rooted) encryption, `false` for the development
    /// plaintext mode. Callers that persist private key material (per-org
    /// issuer signing keys) gate on this so a key is never stored in
    /// plaintext. Deliberately no default: every implementation must state
    /// its answer, so a new impl can't silently inherit the unsafe one.
    fn is_encrypted(&self) -> bool;
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
pub(crate) struct PlaintextDocumentCrypto;

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

    fn is_encrypted(&self) -> bool {
        false
    }
}

// ============================================================================
// Cipher-Suite Identity
// ============================================================================

/// RFC 9180 cipher-suite identifier: KEM, KDF, and AEAD codepoints.
///
/// Persisted with every ciphertext (as a prefix on the encapsulated key) so
/// the suite a row was sealed under is recorded on the row itself rather than
/// implied by the compiled binary. New codepoints — such as the ML-KEM and
/// hybrid KEMs registered by draft-ietf-hpke-pq — only need an arm in
/// [`suite_for`] and key material; the storage format already carries them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HpkeSuiteId {
    /// RFC 9180 KEM codepoint (e.g. `0x0011` = DHKEM(P-384, HKDF-SHA384)).
    pub kem_id: u16,
    /// RFC 9180 KDF codepoint (e.g. `0x0002` = HKDF-SHA384).
    pub kdf_id: u16,
    /// RFC 9180 AEAD codepoint (e.g. `0x0002` = AES-256-GCM).
    pub aead_id: u16,
}

/// DHKEM(P-384, HKDF-SHA384) + HKDF-SHA384 + AES-256-GCM.
pub(crate) const SUITE_DHKEM_P384_SHA384_AES256: HpkeSuiteId = HpkeSuiteId {
    kem_id: 0x0011,
    kdf_id: 0x0002,
    aead_id: 0x0002,
};

/// Suite assumed for untagged (plain base64) encapsulated keys, which were
/// written before suite tagging existed. Fixed forever — do not repoint this
/// at a new suite, or pre-tagging rows become undecryptable.
pub(crate) const LEGACY_SUITE: HpkeSuiteId = SUITE_DHKEM_P384_SHA384_AES256;

impl HpkeSuiteId {
    /// Human-readable name for logs and operator output.
    #[must_use]
    pub fn label(self) -> &'static str {
        if self == SUITE_DHKEM_P384_SHA384_AES256 {
            "DHKEM(P-384)+HKDF-SHA384+AES-256-GCM"
        } else {
            "unknown"
        }
    }
}

impl std::fmt::Display for HpkeSuiteId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "kem=0x{:04x} kdf=0x{:04x} aead=0x{:04x}",
            self.kem_id, self.kdf_id, self.aead_id
        )
    }
}

/// Resolve a suite ID to its HPKE implementation.
///
/// The single place that maps codepoints to code. Adding a suite (e.g. an
/// ML-KEM hybrid from draft-ietf-hpke-pq once rustls/aws-lc-rs expose it)
/// means adding one arm here plus the matching key-material handling.
///
/// # Errors
///
/// Returns an error naming the codepoints if the suite is not supported by
/// this build — e.g. a row written by a newer server.
fn suite_for(id: HpkeSuiteId) -> Result<&'static dyn Hpke> {
    if id == SUITE_DHKEM_P384_SHA384_AES256 {
        return Ok(rustls::crypto::aws_lc_rs::hpke::DH_KEM_P384_HKDF_SHA384_AES_256);
    }
    bail!("unsupported HPKE suite ({id}); this server may be too old to read this document")
}

/// Tag prefix marking a self-describing encapsulated key.
///
/// Safe discriminator: standard base64 never contains `:`, so an untagged
/// (legacy) value can never be mistaken for a tagged one.
const SUITE_TAG_PREFIX: &str = "hpke:";

/// Encode an encapsulated key with its suite tag:
/// `hpke:<kem_id>:<kdf_id>:<aead_id>:<base64>` (codepoints as four-digit
/// lowercase hex).
fn encode_encapped_key(suite: HpkeSuiteId, enc: &[u8]) -> String {
    format!(
        "{SUITE_TAG_PREFIX}{:04x}:{:04x}:{:04x}:{}",
        suite.kem_id,
        suite.kdf_id,
        suite.aead_id,
        BASE64.encode(enc)
    )
}

/// Decode a stored encapsulated key into its suite ID and raw bytes.
///
/// Tagged values carry their own suite; untagged values are read as
/// [`LEGACY_SUITE`].
///
/// # Errors
///
/// Returns an error on a malformed tag or invalid base64.
fn decode_encapped_key(value: &str) -> Result<(HpkeSuiteId, Vec<u8>)> {
    let Some(rest) = value.strip_prefix(SUITE_TAG_PREFIX) else {
        let bytes = BASE64
            .decode(value)
            .context("invalid base64 in encapped_key")?;
        return Ok((LEGACY_SUITE, bytes));
    };

    let mut parts = rest.splitn(4, ':');
    let kem_id = parse_codepoint(parts.next(), "kem_id")?;
    let kdf_id = parse_codepoint(parts.next(), "kdf_id")?;
    let aead_id = parse_codepoint(parts.next(), "aead_id")?;
    let encoded = parts
        .next()
        .context("encapped_key suite tag is missing the key material")?;
    let bytes = BASE64
        .decode(encoded)
        .context("invalid base64 in encapped_key")?;

    Ok((
        HpkeSuiteId {
            kem_id,
            kdf_id,
            aead_id,
        },
        bytes,
    ))
}

/// Parse one four-digit lowercase-hex codepoint field of a suite tag.
fn parse_codepoint(part: Option<&str>, what: &str) -> Result<u16> {
    let text = part.with_context(|| format!("encapped_key suite tag is missing {what}"))?;
    if text.len() != 4 {
        bail!("encapped_key suite tag has malformed {what} (expected 4 hex digits)");
    }
    u16::from_str_radix(text, 16)
        .with_context(|| format!("encapped_key suite tag has malformed {what}"))
}

// ============================================================================
// HPKE Implementation (Production)
// ============================================================================

/// Production crypto using HPKE (RFC 9180). The write suite is configured at
/// construction (currently always DHKEM(P-384) + HKDF-SHA384 + AES-256-GCM);
/// reads resolve each row's suite from its tag.
///
/// The public key is used for `seal()` (no KMS call needed). The private key
/// is used for `open()` (decrypted from KMS on startup). The HMAC key is
/// derived from the public key via HKDF so that writers can compute index
/// values without access to the private key.
pub(crate) struct HpkeDocumentCrypto {
    /// Suite used for new writes; also the suite the key pair belongs to.
    suite_id: HpkeSuiteId,
    /// Resolved implementation of `suite_id`, cached for `seal()`.
    suite: &'static dyn Hpke,
    public_key: HpkePublicKey,
    private_key: HpkePrivateKey,
    hmac_key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for HpkeDocumentCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HpkeDocumentCrypto")
            .field("suite_id", &format_args!("{}", self.suite_id))
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
    /// Create a new HPKE document crypto instance whose key pair belongs to
    /// `suite_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the suite is unsupported or the HMAC key
    /// derivation fails.
    pub(crate) fn new(
        suite_id: HpkeSuiteId,
        public_key: HpkePublicKey,
        private_key: HpkePrivateKey,
    ) -> Result<Self> {
        let suite = suite_for(suite_id)?;
        let hmac_key = derive_hmac_key(&public_key.0)?;
        Ok(Self {
            suite_id,
            suite,
            public_key,
            private_key,
            hmac_key: Zeroizing::new(hmac_key),
        })
    }

    /// Build an instance with a freshly generated key, for tests needing real
    /// at-rest encryption (`is_encrypted() == true`).
    #[cfg(any(test, feature = "test-utils"))]
    #[expect(clippy::expect_used, reason = "test-only key generation")]
    #[must_use]
    pub(crate) fn generate_for_test() -> Self {
        let (public_key, private_key) = suite_for(SUITE_DHKEM_P384_SHA384_AES256)
            .expect("default HPKE suite is always supported")
            .generate_key_pair()
            .expect("generate HPKE test key pair");
        Self::new(
            SUITE_DHKEM_P384_SHA384_AES256,
            public_key,
            private_key.secret_bytes().to_vec().into(),
        )
        .expect("build HPKE test crypto")
    }
}

impl DocumentCrypto for HpkeDocumentCrypto {
    fn seal(&self, info: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<EncryptedDocument> {
        let (enc, ciphertext) = self
            .suite
            .seal(info, aad, plaintext, &self.public_key)
            .map_err(|e| anyhow::anyhow!("HPKE seal failed: {e}"))?;

        Ok(EncryptedDocument {
            encapped_key: Some(encode_encapped_key(self.suite_id, &enc.0)),
            data: BASE64.encode(&ciphertext),
        })
    }

    fn open(&self, info: &[u8], aad: &[u8], doc: &EncryptedDocument) -> Result<Vec<u8>> {
        let enc_value = doc
            .encapped_key
            .as_ref()
            .context("encrypted document missing encapped_key")?;
        let (row_suite_id, enc_decoded) = decode_encapped_key(enc_value)?;
        let suite = if row_suite_id == self.suite_id {
            self.suite
        } else {
            suite_for(row_suite_id)?
        };
        let enc = rustls::crypto::hpke::EncapsulatedSecret(enc_decoded);

        let ciphertext = BASE64
            .decode(&doc.data)
            .context("invalid base64 in ciphertext")?;

        suite
            .open(&enc, info, aad, &ciphertext, &self.private_key)
            .map_err(|e| anyhow::anyhow!("HPKE open failed: {e}"))
    }

    fn hmac_index(&self, value: &str) -> String {
        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &self.hmac_key);
        let tag = aws_lc_rs::hmac::sign(&key, value.as_bytes());
        URL_SAFE_NO_PAD.encode(tag.as_ref())
    }

    fn is_encrypted(&self) -> bool {
        true
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
pub(crate) fn p384_hpke_keys_from_private_key_der(
    der: &[u8],
) -> Result<(HpkePublicKey, HpkePrivateKey)> {
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
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
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
        let crypto =
            HpkeDocumentCrypto::new(SUITE_DHKEM_P384_SHA384_AES256, pub_key, priv_key).unwrap();
        let sealed = crypto.seal(b"test", b"aad", b"hello").unwrap();
        let opened = crypto.open(b"test", b"aad", &sealed).unwrap();
        assert_eq!(opened, b"hello");
    }

    #[test]
    fn hpke_open_rejects_null_encapped_key() {
        let crypto = make_test_crypto();
        let doc = EncryptedDocument {
            encapped_key: None,
            data: "hello".to_string(),
        };
        let err = crypto.open(b"user", b"doc-1", &doc).unwrap_err();
        assert!(
            format!("{err:#}").contains("encapped_key"),
            "expected encapped_key error, got: {err:#}"
        );
    }

    #[test]
    fn hpke_open_rejects_null_encapped_key_with_injected_payload() {
        // Guards against the privilege-escalation scenario from issue #387: an attacker
        // with DB write access sets encapped_key=NULL and injects an admin payload.
        // The error must not echo the injected data (defense against future log
        // regressions that include doc.data in error context).
        let crypto = make_test_crypto();
        let doc = EncryptedDocument {
            encapped_key: None,
            data: r#"{"is_org_admin":true}"#.to_string(),
        };
        let err = crypto.open(b"user", b"doc-123", &doc).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("encapped_key"));
        assert!(
            !msg.contains("is_org_admin"),
            "error must not echo injected payload: {msg}"
        );
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

    #[test]
    fn seal_emits_suite_tagged_encapped_key() {
        let crypto = make_test_crypto();
        let sealed = crypto.seal(b"user", b"doc-123", b"payload").unwrap();
        let encapped = sealed.encapped_key.unwrap();
        assert!(
            encapped.starts_with("hpke:0011:0002:0002:"),
            "expected suite-tagged encapped_key, got: {encapped}"
        );
    }

    #[test]
    fn open_accepts_legacy_untagged_encapped_key() {
        // Rows written before suite tagging stored the encapped key as plain
        // base64. Stripping the tag from a fresh seal reproduces that format
        // exactly; it must decrypt via the LEGACY_SUITE fallback.
        let crypto = make_test_crypto();
        let plaintext = b"legacy row";
        let sealed = crypto.seal(b"user", b"doc-123", plaintext).unwrap();

        let tagged = sealed.encapped_key.unwrap();
        let bare_base64 = tagged.rsplit(':').next().unwrap().to_string();
        assert!(!bare_base64.contains(':'));
        let legacy = EncryptedDocument {
            encapped_key: Some(bare_base64),
            data: sealed.data,
        };

        let opened = crypto.open(b"user", b"doc-123", &legacy).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn open_rejects_unknown_suite_tag() {
        let crypto = make_test_crypto();
        let sealed = crypto.seal(b"user", b"doc-123", b"payload").unwrap();
        let tagged = sealed.encapped_key.unwrap();

        // Re-tag with ML-KEM-768 (0x0041, draft-ietf-hpke-pq), which this
        // build does not support.
        let bare_base64 = tagged.rsplit(':').next().unwrap();
        let foreign = EncryptedDocument {
            encapped_key: Some(format!("hpke:0041:0002:0002:{bare_base64}")),
            data: sealed.data.clone(),
        };

        let err = crypto.open(b"user", b"doc-123", &foreign).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("unsupported HPKE suite") && msg.contains("0x0041"),
            "expected unsupported-suite error naming the codepoint, got: {msg}"
        );
    }

    #[test]
    fn open_rejects_malformed_suite_tag() {
        let crypto = make_test_crypto();
        let sealed = crypto.seal(b"user", b"doc-123", b"payload").unwrap();

        for bad in [
            "hpke:11:0002:0002:AAAA",   // codepoint not 4 digits
            "hpke:zzzz:0002:0002:AAAA", // codepoint not hex
            "hpke:0011:0002:0002",      // key material missing
            "hpke:0011:0002",           // fields missing
        ] {
            let doc = EncryptedDocument {
                encapped_key: Some(bad.to_string()),
                data: sealed.data.clone(),
            };
            let err = crypto.open(b"user", b"doc-123", &doc).unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains("suite tag"),
                "expected suite-tag error for {bad:?}, got: {msg}"
            );
        }
    }

    #[test]
    fn encode_decode_encapped_key_roundtrip() {
        let suite = HpkeSuiteId {
            kem_id: 0x0051, // MLKEM1024-P384 (draft-ietf-hpke-pq)
            kdf_id: 0x0011, // SHAKE256
            aead_id: 0x0002,
        };
        let bytes = vec![0u8, 1, 2, 255];
        let encoded = encode_encapped_key(suite, &bytes);
        let (decoded_suite, decoded_bytes) = decode_encapped_key(&encoded).unwrap();
        assert_eq!(decoded_suite, suite);
        assert_eq!(decoded_bytes, bytes);
    }

    fn make_test_crypto() -> HpkeDocumentCrypto {
        HpkeDocumentCrypto::generate_for_test()
    }
}
