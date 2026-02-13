// SPDX-License-Identifier: BUSL-1.1
//! Minimal ASN.1 BER/DER parser for CMS envelope extraction.
//!
//! Parses the subset of ASN.1 needed to extract fields from CMS (PKCS#7)
//! `EnvelopedData` structures returned by AWS KMS `CiphertextForRecipient`.
//!
//! ## Why BER?
//!
//! RFC 5652 (CMS) Section 1 mandates BER encoding. AWS KMS uses indefinite-length
//! encoding on constructed types, which strict DER parsers reject.
//!
//! ## Encoding rules implemented
//!
//! **DER** (ITU-T X.690 Section 10): Definite-length only. Tag + length + value.
//!
//! **BER** (ITU-T X.690 Sections 8.1.3.6, 8.1.5): Superset of DER. Constructed
//! types may use indefinite-length encoding (length octet `0x80`), terminated by
//! end-of-contents (EOC) octets (`0x00 0x00`).
//!
//! ## References
//!
//! - [ITU-T X.690](https://www.itu.int/rec/T-REC-X.690): ASN.1 BER/CER/DER encoding rules
//!   - Section 8.1.2: Tag encoding
//!   - Section 8.1.3: Length encoding (short form, long form, indefinite form)
//!   - Section 8.1.3.6: Indefinite-length encoding (`0x80`)
//!   - Section 8.1.5: End-of-contents octets (`0x00 0x00`)
//!   - Section 10: DER restrictions
//! - [ITU-T X.680](https://www.itu.int/rec/T-REC-X.680): ASN.1 basic notation
//! - [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652): CMS -- mandates BER (Section 1)

use anyhow::{Context, Result};

/// Maximum nesting depth for BER indefinite-length scanning.
/// CMS structures are ~6 levels deep. 32 provides ample headroom
/// while preventing stack overflow from pathological input.
const MAX_BER_DEPTH: usize = 32;

/// Lightweight ASN.1 BER/DER parser for extracting fields from CMS structures.
///
/// This is intentionally minimal -- it only handles the subset of BER/DER needed
/// to parse KMS CMS `CiphertextForRecipient` responses.
pub(crate) struct DerParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerParser<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Read a TLV (tag-length-value) and return (tag, value_bytes).
    pub(crate) fn read_tlv(&mut self) -> Result<(u8, &'a [u8])> {
        if self.pos >= self.data.len() {
            anyhow::bail!("DER: unexpected end of data at position {}", self.pos);
        }

        let tag = *self.data.get(self.pos).context("DER: missing tag byte")?;
        self.pos += 1;

        let length = self.read_length()?;

        if self.pos + length > self.data.len() {
            anyhow::bail!(
                "DER: value length {} exceeds remaining data {} at position {}",
                length,
                self.data.len() - self.pos,
                self.pos
            );
        }

        let value = self
            .data
            .get(self.pos..self.pos + length)
            .context("DER: failed to read value bytes")?;
        self.pos += length;

        Ok((tag, value))
    }

    /// Read a TLV that may use BER indefinite length encoding.
    ///
    /// KMS CMS responses use BER (not strict DER), which may encode
    /// constructed types with indefinite length (`0x80`). For indefinite
    /// length, the content ends at end-of-contents octets (`0x00 0x00`).
    /// We scan for the EOC by walking nested TLVs to avoid false matches.
    pub(crate) fn read_tlv_ber(&mut self) -> Result<(u8, &'a [u8])> {
        if self.pos >= self.data.len() {
            anyhow::bail!("BER: unexpected end of data at position {}", self.pos);
        }

        let tag = *self.data.get(self.pos).context("BER: missing tag byte")?;
        self.pos += 1;

        let first = *self
            .data
            .get(self.pos)
            .context("BER: missing length byte")?;

        if first == 0x80 {
            // Indefinite length: scan for end-of-contents (0x00 0x00)
            self.pos += 1; // consume the 0x80 length byte
            let content_start = self.pos;

            // Walk nested TLVs to find the matching EOC
            loop {
                if self.pos + 1 >= self.data.len() {
                    anyhow::bail!(
                        "BER: unterminated indefinite length at position {content_start}"
                    );
                }
                let b0 = self.data.get(self.pos).copied().unwrap_or(1);
                let b1 = self.data.get(self.pos + 1).copied().unwrap_or(1);
                if b0 == 0x00 && b1 == 0x00 {
                    // Found end-of-contents
                    let value = self
                        .data
                        .get(content_start..self.pos)
                        .context("BER: failed to extract indefinite content")?;
                    self.pos += 2; // skip the EOC bytes
                    return Ok((tag, value));
                }
                // Skip one nested TLV element (start at depth 0)
                self.skip_ber_element_bounded(0)?;
            }
        } else {
            // Definite length -- delegate to normal read_length
            let length = self.read_length()?;

            if self.pos + length > self.data.len() {
                anyhow::bail!(
                    "BER: value length {} exceeds remaining data {} at position {}",
                    length,
                    self.data.len() - self.pos,
                    self.pos
                );
            }

            let value = self
                .data
                .get(self.pos..self.pos + length)
                .context("BER: failed to read value bytes")?;
            self.pos += length;

            Ok((tag, value))
        }
    }

    /// Skip one BER element with bounded recursion depth.
    ///
    /// Prevents stack overflow from pathological inputs with deep nesting.
    fn skip_ber_element_bounded(&mut self, depth: usize) -> Result<()> {
        if depth >= MAX_BER_DEPTH {
            anyhow::bail!("BER: nesting depth exceeds {MAX_BER_DEPTH} (possible malicious input)");
        }

        if self.pos >= self.data.len() {
            anyhow::bail!("BER: unexpected end while skipping element");
        }

        // Skip tag
        self.pos += 1;

        let first = *self
            .data
            .get(self.pos)
            .context("BER: missing length in skip")?;

        if first == 0x80 {
            // Nested indefinite length -- recurse by scanning for EOC
            self.pos += 1;
            loop {
                if self.pos + 1 >= self.data.len() {
                    anyhow::bail!("BER: unterminated nested indefinite length");
                }
                let b0 = self.data.get(self.pos).copied().unwrap_or(1);
                let b1 = self.data.get(self.pos + 1).copied().unwrap_or(1);
                if b0 == 0x00 && b1 == 0x00 {
                    self.pos += 2;
                    return Ok(());
                }
                self.skip_ber_element_bounded(depth + 1)?;
            }
        } else {
            // Definite length
            let length = self.read_length()?;
            if self.pos + length > self.data.len() {
                anyhow::bail!("BER: skip exceeds data bounds");
            }
            self.pos += length;
            Ok(())
        }
    }

    /// Read a DER length field.
    fn read_length(&mut self) -> Result<usize> {
        let first = *self
            .data
            .get(self.pos)
            .context("DER: missing length byte")?;
        self.pos += 1;

        if first < 0x80 {
            // Short form
            Ok(first as usize)
        } else if first == 0x80 {
            anyhow::bail!("DER: indefinite length not supported");
        } else {
            // Long form
            let num_bytes = (first & 0x7f) as usize;
            if num_bytes > 4 {
                anyhow::bail!("DER: length field too long ({} bytes)", num_bytes);
            }

            let mut length: usize = 0;
            for _ in 0..num_bytes {
                let byte = *self
                    .data
                    .get(self.pos)
                    .context("DER: truncated length field")?;
                self.pos += 1;
                length = length.checked_shl(8).context("DER: length overflow")? | (byte as usize);
            }

            Ok(length)
        }
    }

    /// Skip one TLV element.
    pub(crate) fn skip_tlv(&mut self) -> Result<()> {
        let _ = self.read_tlv()?;
        Ok(())
    }

    /// Expect a SEQUENCE (tag 0x30) and return its contents.
    #[allow(dead_code)]
    pub(crate) fn expect_sequence(&mut self) -> Result<&'a [u8]> {
        let (tag, value) = self.read_tlv()?;
        if tag != 0x30 {
            anyhow::bail!("DER: expected SEQUENCE (0x30), got 0x{tag:02x}");
        }
        Ok(value)
    }

    /// Expect a SET (tag 0x31) and return its contents.
    #[allow(dead_code)]
    pub(crate) fn expect_set(&mut self) -> Result<&'a [u8]> {
        let (tag, value) = self.read_tlv()?;
        if tag != 0x31 {
            anyhow::bail!("DER: expected SET (0x31), got 0x{tag:02x}");
        }
        Ok(value)
    }

    /// Expect an OCTET STRING (tag 0x04) and return its contents.
    pub(crate) fn expect_octet_string(&mut self) -> Result<&'a [u8]> {
        let (tag, value) = self.read_tlv()?;
        if tag != 0x04 {
            anyhow::bail!("DER: expected OCTET STRING (0x04), got 0x{tag:02x}");
        }
        Ok(value)
    }

    /// Expect context-specific EXPLICIT [n] (tag 0xa0 + n) and return inner contents.
    #[allow(dead_code)]
    pub(crate) fn expect_context_explicit(&mut self, n: u8) -> Result<&'a [u8]> {
        let expected_tag = 0xa0 | n;
        let (tag, value) = self.read_tlv()?;
        if tag != expected_tag {
            anyhow::bail!("DER: expected context [{n}] (0x{expected_tag:02x}), got 0x{tag:02x}");
        }
        Ok(value)
    }

    /// Expect context-specific IMPLICIT [n] (tag 0x80 + n) and return raw value.
    #[allow(dead_code)]
    pub(crate) fn expect_context_implicit(&mut self, n: u8) -> Result<&'a [u8]> {
        let expected_tag = 0x80 | n;
        let (tag, value) = self.read_tlv()?;
        if tag != expected_tag {
            anyhow::bail!("DER: expected implicit [{n}] (0x{expected_tag:02x}), got 0x{tag:02x}");
        }
        Ok(value)
    }

    // BER-aware variants for KMS CMS responses that may use indefinite length.

    /// Expect a SEQUENCE, tolerating BER indefinite length.
    pub(crate) fn expect_sequence_ber(&mut self) -> Result<&'a [u8]> {
        let (tag, value) = self.read_tlv_ber()?;
        if tag != 0x30 {
            anyhow::bail!("BER: expected SEQUENCE (0x30), got 0x{tag:02x}");
        }
        Ok(value)
    }

    /// Expect context-specific EXPLICIT [n], tolerating BER indefinite length.
    pub(crate) fn expect_context_explicit_ber(&mut self, n: u8) -> Result<&'a [u8]> {
        let expected_tag = 0xa0 | n;
        let (tag, value) = self.read_tlv_ber()?;
        if tag != expected_tag {
            anyhow::bail!("BER: expected context [{n}] (0x{expected_tag:02x}), got 0x{tag:02x}");
        }
        Ok(value)
    }

    /// Expect a SET, tolerating BER indefinite length.
    pub(crate) fn expect_set_ber(&mut self) -> Result<&'a [u8]> {
        let (tag, value) = self.read_tlv_ber()?;
        if tag != 0x31 {
            anyhow::bail!("BER: expected SET (0x31), got 0x{tag:02x}");
        }
        Ok(value)
    }

    /// Skip one TLV element, tolerating BER indefinite length.
    pub(crate) fn skip_tlv_ber(&mut self) -> Result<()> {
        let _ = self.read_tlv_ber()?;
        Ok(())
    }

    /// Expect context-specific IMPLICIT [n], tolerating BER indefinite length.
    #[allow(dead_code)]
    pub(crate) fn expect_context_implicit_ber(&mut self, n: u8) -> Result<&'a [u8]> {
        let expected_tag = 0x80 | n;
        let (tag, value) = self.read_tlv_ber()?;
        if tag != expected_tag {
            anyhow::bail!("BER: expected implicit [{n}] (0x{expected_tag:02x}), got 0x{tag:02x}");
        }
        Ok(value)
    }

    /// Read `[n] IMPLICIT OCTET STRING` handling both primitive and BER
    /// constructed encodings.
    ///
    /// Per ITU-T X.690 Section 8.1.2.2, IMPLICIT tags preserve the primitive/
    /// constructed bit from the underlying type. OCTET STRING (universal tag 4)
    /// may be encoded as:
    /// - **Primitive** (tag `0x80|n`): value bytes are the raw content.
    /// - **Constructed** (tag `0xa0|n`): value contains one or more OCTET STRING
    ///   chunks (each `0x04 len data...`) that must be concatenated. BER uses
    ///   this form for indefinite-length encoding (ITU-T X.690 Section 8.1.3.6
    ///   requires constructed form for indefinite length).
    ///
    /// Returns the reassembled content as `Vec<u8>` since constructed encoding
    /// requires concatenation of multiple chunks.
    pub(crate) fn read_implicit_octet_string_ber(&mut self, n: u8) -> Result<Vec<u8>> {
        let primitive_tag = 0x80 | n;
        let constructed_tag = 0xa0 | n;
        let (tag, value) = self.read_tlv_ber()?;

        if tag == primitive_tag {
            // Primitive: value is the raw content directly
            Ok(value.to_vec())
        } else if tag == constructed_tag {
            // Constructed: value contains OCTET STRING chunks to reassemble
            let mut inner = DerParser::new(value);
            let mut result = Vec::new();
            while inner.pos < inner.data.len() {
                let chunk = inner.expect_octet_string()?;
                result.extend_from_slice(chunk);
            }
            Ok(result)
        } else {
            anyhow::bail!(
                "BER: expected implicit [{n}] (0x{primitive_tag:02x} or \
                 0x{constructed_tag:02x}), got 0x{tag:02x}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    // ====================================================================
    // DER parser tests (moved from tpm_decrypt.rs)
    // ====================================================================

    #[test]
    fn test_der_parser_sequence() {
        // A simple SEQUENCE { INTEGER 1 }
        let data = [0x30, 0x03, 0x02, 0x01, 0x01];
        let mut parser = DerParser::new(&data);
        let seq = parser.expect_sequence().unwrap();
        assert_eq!(seq, &[0x02, 0x01, 0x01]);
    }

    #[test]
    fn test_der_parser_octet_string() {
        let data = [0x04, 0x03, 0x01, 0x02, 0x03];
        let mut parser = DerParser::new(&data);
        let octets = parser.expect_octet_string().unwrap();
        assert_eq!(octets, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_der_parser_long_length() {
        // OCTET STRING with 128 bytes (long form length: 0x81 0x80)
        let mut data = vec![0x04, 0x81, 0x80];
        data.extend_from_slice(&[0xAA; 128]);
        let mut parser = DerParser::new(&data);
        let octets = parser.expect_octet_string().unwrap();
        assert_eq!(octets.len(), 128);
    }

    #[test]
    fn test_der_parser_skip_tlv() {
        // Two OCTET STRINGs in sequence
        let data = [0x04, 0x02, 0x01, 0x02, 0x04, 0x01, 0x03];
        let mut parser = DerParser::new(&data);
        parser.skip_tlv().unwrap();
        let octets = parser.expect_octet_string().unwrap();
        assert_eq!(octets, &[0x03]);
    }

    #[test]
    fn test_der_parser_error_on_truncated() {
        let data = [0x04, 0x05, 0x01]; // claims 5 bytes but only has 1
        let mut parser = DerParser::new(&data);
        assert!(parser.expect_octet_string().is_err());
    }

    #[test]
    fn test_der_parser_error_on_wrong_tag() {
        let data = [0x02, 0x01, 0x01]; // INTEGER, not SEQUENCE
        let mut parser = DerParser::new(&data);
        assert!(parser.expect_sequence().is_err());
    }

    #[test]
    fn test_der_parser_empty_input() {
        let mut parser = DerParser::new(&[]);
        assert!(parser.read_tlv().is_err());
    }

    #[test]
    fn test_der_parser_zero_length_value() {
        // OCTET STRING with zero length
        let data = [0x04, 0x00];
        let mut parser = DerParser::new(&data);
        let octets = parser.expect_octet_string().unwrap();
        assert!(octets.is_empty());
    }

    #[test]
    fn test_der_parser_indefinite_length_rejected() {
        let data = [0x30, 0x80, 0x00, 0x00]; // SEQUENCE with indefinite length
        let mut parser = DerParser::new(&data);
        let err = parser.expect_sequence().unwrap_err();
        assert!(
            format!("{err}").contains("indefinite"),
            "Expected indefinite length error, got: {err}"
        );
    }

    #[test]
    fn test_der_parser_max_long_form_length() {
        // OCTET STRING with 4-byte long-form length encoding 256 bytes
        // 0x84 means 4 length bytes follow, value = 0x00000100 = 256
        let mut data = vec![0x04, 0x84, 0x00, 0x00, 0x01, 0x00];
        data.extend_from_slice(&[0xBB; 256]);
        let mut parser = DerParser::new(&data);
        let octets = parser.expect_octet_string().unwrap();
        assert_eq!(octets.len(), 256);
    }

    #[test]
    fn test_der_parser_length_too_long_rejected() {
        // 0x85 means 5 length bytes -- exceeds our 4-byte limit
        let data = [0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mut parser = DerParser::new(&data);
        let err = parser.expect_octet_string().unwrap_err();
        assert!(
            format!("{err}").contains("too long"),
            "Expected length-too-long error, got: {err}"
        );
    }

    // ====================================================================
    // BER parser tests (moved from tpm_decrypt.rs)
    // ====================================================================

    #[test]
    fn test_ber_parser_indefinite_length_sequence() {
        // SEQUENCE with indefinite length containing an INTEGER (0x02 0x01 0x42) + EOC
        let data = [0x30, 0x80, 0x02, 0x01, 0x42, 0x00, 0x00];
        let mut parser = DerParser::new(&data);
        let seq = parser.expect_sequence_ber().unwrap();
        assert_eq!(seq, &[0x02, 0x01, 0x42]);
    }

    #[test]
    fn test_ber_parser_nested_indefinite_length() {
        // SEQUENCE(indef) { SEQUENCE(indef) { INTEGER 0x42 } EOC } EOC
        let data = [
            0x30, 0x80, // outer SEQUENCE indefinite
            0x30, 0x80, // inner SEQUENCE indefinite
            0x02, 0x01, 0x42, // INTEGER 0x42
            0x00, 0x00, // inner EOC
            0x00, 0x00, // outer EOC
        ];
        let mut parser = DerParser::new(&data);
        let outer = parser.expect_sequence_ber().unwrap();
        // outer content is the inner SEQUENCE + its EOC
        let mut inner_parser = DerParser::new(outer);
        let inner = inner_parser.expect_sequence_ber().unwrap();
        assert_eq!(inner, &[0x02, 0x01, 0x42]);
    }

    #[test]
    fn test_ber_parser_definite_length_passthrough() {
        let data = [0x30, 0x03, 0x02, 0x01, 0x01];
        let mut parser = DerParser::new(&data);
        let seq = parser.expect_sequence_ber().unwrap();
        assert_eq!(seq, &[0x02, 0x01, 0x01]);
    }

    // ====================================================================
    // New tests: depth limit, edge cases
    // ====================================================================

    /// 33+ nested indefinite-length SEQUENCEs must error (not stack overflow).
    #[test]
    fn test_ber_max_depth_exceeded() {
        // Build 33 nested indefinite-length SEQUENCEs:
        // Each level: 0x30 0x80 ... 0x00 0x00
        let depth = MAX_BER_DEPTH + 1;
        let mut data = Vec::new();

        // Opening tags + indefinite lengths
        for _ in 0..depth {
            data.push(0x30); // SEQUENCE tag
            data.push(0x80); // indefinite length
        }

        // Innermost element: a simple INTEGER
        data.extend_from_slice(&[0x02, 0x01, 0x42]);

        // Closing EOCs (one per level)
        for _ in 0..depth {
            data.push(0x00);
            data.push(0x00);
        }

        let mut parser = DerParser::new(&data);
        let err = parser.expect_sequence_ber().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("nesting depth exceeds"),
            "Expected depth exceeded error, got: {msg}"
        );
    }

    /// Missing EOC on indefinite-length encoding should error.
    #[test]
    fn test_ber_unterminated_indefinite() {
        // SEQUENCE with indefinite length, INTEGER inside, but no EOC
        let data = [0x30, 0x80, 0x02, 0x01, 0x42];
        let mut parser = DerParser::new(&data);
        let err = parser.expect_sequence_ber().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unterminated"),
            "Expected unterminated error, got: {msg}"
        );
    }

    /// SET with indefinite length should be accepted by expect_set_ber.
    #[test]
    fn test_ber_set_indefinite() {
        // SET with indefinite length containing an INTEGER + EOC
        let data = [0x31, 0x80, 0x02, 0x01, 0x07, 0x00, 0x00];
        let mut parser = DerParser::new(&data);
        let set_contents = parser.expect_set_ber().unwrap();
        assert_eq!(set_contents, &[0x02, 0x01, 0x07]);
    }

    /// [0] EXPLICIT with indefinite length should be accepted.
    #[test]
    fn test_ber_context_explicit_indefinite() {
        // [0] EXPLICIT (tag 0xa0) with indefinite length, INTEGER inside + EOC
        let data = [0xa0, 0x80, 0x02, 0x01, 0x99, 0x00, 0x00];
        let mut parser = DerParser::new(&data);
        let contents = parser.expect_context_explicit_ber(0).unwrap();
        assert_eq!(contents, &[0x02, 0x01, 0x99]);
    }

    /// [0] IMPLICIT with indefinite length should be accepted.
    #[test]
    fn test_ber_context_implicit_indefinite() {
        // [0] IMPLICIT (tag 0x80) with indefinite length, raw bytes + EOC
        // Note: tag 0x80 is the same as the indefinite length marker,
        // but the parser reads tag first, then the length byte.
        let data = [0x80, 0x80, 0x02, 0x01, 0xAB, 0x00, 0x00];
        let mut parser = DerParser::new(&data);
        let contents = parser.expect_context_implicit_ber(0).unwrap();
        assert_eq!(contents, &[0x02, 0x01, 0xAB]);
    }

    /// 2-byte long-form length encoding (300 bytes).
    #[test]
    fn test_der_two_byte_long_form_length() {
        // OCTET STRING with 2-byte long-form length: 0x82 0x01 0x2c = 300
        let mut data = vec![0x04, 0x82, 0x01, 0x2c];
        data.extend_from_slice(&[0xCC; 300]);
        let mut parser = DerParser::new(&data);
        let octets = parser.expect_octet_string().unwrap();
        assert_eq!(octets.len(), 300);
    }

    /// Outer indefinite-length SEQUENCE containing inner definite-length elements.
    #[test]
    fn test_ber_mixed_definite_indefinite() {
        // SEQUENCE(indef) { OCTET STRING(definite, 2 bytes) | INTEGER(definite, 1 byte) } EOC
        let data = [
            0x30, 0x80, // SEQUENCE indefinite
            0x04, 0x02, 0xAA, 0xBB, // OCTET STRING, 2 bytes
            0x02, 0x01, 0x42, // INTEGER 0x42
            0x00, 0x00, // EOC
        ];
        let mut parser = DerParser::new(&data);
        let seq = parser.expect_sequence_ber().unwrap();
        // Content should be the definite-length elements (without EOC)
        assert_eq!(seq, &[0x04, 0x02, 0xAA, 0xBB, 0x02, 0x01, 0x42]);

        // Verify we can parse the inner elements
        let mut inner = DerParser::new(seq);
        let octets = inner.expect_octet_string().unwrap();
        assert_eq!(octets, &[0xAA, 0xBB]);

        let (tag, value) = inner.read_tlv().unwrap();
        assert_eq!(tag, 0x02); // INTEGER
        assert_eq!(value, &[0x42]);
    }

    // ====================================================================
    // Tests for read_implicit_octet_string_ber (constructed OCTET STRING)
    // ====================================================================

    /// Primitive [0] IMPLICIT OCTET STRING (tag 0x80): value is raw content.
    #[test]
    fn test_implicit_octet_string_primitive() {
        // [0] IMPLICIT primitive, 3 bytes
        let data = [0x80, 0x03, 0xAA, 0xBB, 0xCC];
        let mut parser = DerParser::new(&data);
        let result = parser.read_implicit_octet_string_ber(0).unwrap();
        assert_eq!(result, vec![0xAA, 0xBB, 0xCC]);
    }

    /// Constructed [0] IMPLICIT OCTET STRING (tag 0xa0) with a single chunk.
    /// This is what KMS produces: the content is one OCTET STRING TLV.
    #[test]
    fn test_implicit_octet_string_constructed_single_chunk() {
        // [0] CONSTRUCTED (0xa0), definite length 5
        //   OCTET STRING (0x04), 3 bytes: AA BB CC
        let data = [0xa0, 0x05, 0x04, 0x03, 0xAA, 0xBB, 0xCC];
        let mut parser = DerParser::new(&data);
        let result = parser.read_implicit_octet_string_ber(0).unwrap();
        assert_eq!(result, vec![0xAA, 0xBB, 0xCC]);
    }

    /// Constructed [0] IMPLICIT OCTET STRING with multiple chunks (BER chunking).
    #[test]
    fn test_implicit_octet_string_constructed_multiple_chunks() {
        // [0] CONSTRUCTED (0xa0), definite length 11
        //   OCTET STRING (0x04), 2 bytes: AA BB   = 4 bytes
        //   OCTET STRING (0x04), 3 bytes: CC DD EE = 5 bytes
        //   OCTET STRING (0x04), 0 bytes (empty)   = 2 bytes
        //   Total inner: 4 + 5 + 2 = 11
        let data = [
            0xa0, 0x0b, // constructed [0], 11 bytes
            0x04, 0x02, 0xAA, 0xBB, // chunk 1
            0x04, 0x03, 0xCC, 0xDD, 0xEE, // chunk 2
            0x04, 0x00, // chunk 3 (empty, valid)
        ];
        let mut parser = DerParser::new(&data);
        let result = parser.read_implicit_octet_string_ber(0).unwrap();
        assert_eq!(result, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    }

    /// Constructed [0] IMPLICIT OCTET STRING with indefinite length.
    #[test]
    fn test_implicit_octet_string_constructed_indefinite() {
        // [0] CONSTRUCTED (0xa0), indefinite length (0x80)
        //   OCTET STRING (0x04), 2 bytes: AA BB
        //   EOC (0x00 0x00)
        let data = [
            0xa0, 0x80, // constructed [0], indefinite
            0x04, 0x02, 0xAA, 0xBB, // chunk
            0x00, 0x00, // EOC
        ];
        let mut parser = DerParser::new(&data);
        let result = parser.read_implicit_octet_string_ber(0).unwrap();
        assert_eq!(result, vec![0xAA, 0xBB]);
    }

    /// Wrong tag should error.
    #[test]
    fn test_implicit_octet_string_wrong_tag() {
        // Tag 0x30 (SEQUENCE) instead of 0x80 or 0xa0
        let data = [0x30, 0x03, 0x02, 0x01, 0x42];
        let mut parser = DerParser::new(&data);
        let err = parser.read_implicit_octet_string_ber(0).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("expected implicit"),
            "Expected implicit tag error, got: {msg}"
        );
    }
}
