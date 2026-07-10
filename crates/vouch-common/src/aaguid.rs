// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AAGUID (Authenticator Attestation GUID) lookup for device model identification.
//!
//! The AAGUID is a 16-byte identifier embedded in FIDO2 authenticator data that
//! uniquely identifies the model of authenticator.
//!
//! Source: https://support.yubico.com/hc/en-us/articles/360016648959-YubiKey-hardware-FIDO2-AAGUIDs

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::LazyLock;
use uuid::Uuid;

/// Known AAGUIDs mapped to device model names.
/// Source: Yubico official documentation (January 2026)
static AAGUID_MAP: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();

    // =========================================================================
    // Production YubiKey AAGUIDs
    // =========================================================================

    // YubiKey 5 Series
    m.insert("cb69481e-8ff7-4039-93ec-0a2729a154a8", "YubiKey 5 (USB-A)"); // FW 5.1
    m.insert("ee882879-721c-4913-9775-3dfcce97072a", "YubiKey 5 (USB-A)"); // FW 5.2, 5.4
    m.insert("fa2b99dc-9e39-4257-8f92-4a30d23c4118", "YubiKey 5 NFC"); // FW 5.1
    m.insert("2fc0579f-8113-47ea-b116-bb5a8db9202a", "YubiKey 5 NFC"); // FW 5.2, 5.4
    m.insert("a25342c0-3cdc-4414-8e46-f4807fca511c", "YubiKey 5 NFC"); // FW 5.7 (first half)
    m.insert("d7781e5d-e353-46aa-afe2-3ca49f13332a", "YubiKey 5 NFC"); // FW 5.7 (second half)
    m.insert(
        "662ef48a-95e2-4aaa-a6c1-5b9c40375824",
        "YubiKey 5 NFC - Enhanced PIN",
    ); // FW 5.7
    m.insert("c5ef55ff-ad9a-4b9f-b580-adebafe026d0", "YubiKey 5Ci"); // FW 5.2, 5.4
    m.insert("a02167b9-ae71-4ac7-9a07-06432ebb6f1c", "YubiKey 5Ci"); // FW 5.7 (first half)
    m.insert("24673149-6c86-42e7-98d9-433fb5b73296", "YubiKey 5Ci"); // FW 5.7 (second half)

    // YubiKey 5C Series
    m.insert(
        "73bb0cd4-e502-49b8-9c6f-b59445bf720b",
        "YubiKey 5C Nano FIPS",
    ); // FW 5.4 (also 5C FIPS, 5 Nano FIPS)
    m.insert("19083c3d-8383-4b18-bc03-8f1c9ab2fd1b", "YubiKey 5C"); // FW 5.7 (first half)
    m.insert("ff4dac45-ede8-4ec2-aced-cf66103f4335", "YubiKey 5C"); // FW 5.7 (second half)

    // YubiKey 5C NFC
    // FW 5.2, 5.4 uses same AAGUID as YubiKey 5 NFC: 2fc0579f-8113-47ea-b116-bb5a8db9202a

    // YubiKey 5 Nano
    // FW 5.1 uses same AAGUID as YubiKey 5: cb69481e-8ff7-4039-93ec-0a2729a154a8
    // FW 5.2, 5.4 uses same AAGUID as YubiKey 5: ee882879-721c-4913-9775-3dfcce97072a

    // YubiKey 5C Nano
    // FW 5.1 uses same AAGUID as YubiKey 5: cb69481e-8ff7-4039-93ec-0a2729a154a8
    // FW 5.2, 5.4 uses same AAGUID as YubiKey 5: ee882879-721c-4913-9775-3dfcce97072a

    // YubiKey 5 FIPS Series (FW 5.4)
    m.insert("c1f9a0bc-1dd2-404a-b27f-8e29047a43fd", "YubiKey 5 NFC FIPS"); // Also 5C NFC FIPS
    m.insert("85203421-48f9-4355-9bc8-8a53846e5083", "YubiKey 5Ci FIPS");

    // YubiKey 5 FIPS RC Series (FW 5.7)
    m.insert(
        "fcc0118f-cd45-435b-8da1-9782b2da0715",
        "YubiKey 5 NFC FIPS RC",
    ); // Also 5C NFC FIPS RC
    m.insert(
        "57f7de54-c807-4eab-b1c6-1c9be7984e92",
        "YubiKey 5 Nano FIPS RC",
    ); // Also 5C Nano FIPS RC, 5C FIPS RC
    m.insert(
        "7b96457d-e3cd-432b-9ceb-c9fdd7ef7432",
        "YubiKey 5Ci FIPS RC",
    );

    // YubiKey Bio Series
    m.insert(
        "d8522d9f-575b-4866-88a9-ba99fa02f35b",
        "YubiKey Bio - FIDO Edition",
    ); // FW 5.5, 5.6
    m.insert(
        "dd86a2da-86a0-4cbe-b462-4bd31f57bc6f",
        "YubiKey Bio - FIDO Edition",
    ); // FW 5.7 (first half)
    m.insert(
        "7409272d-1ff9-4e10-9fc9-ac0019c124fd",
        "YubiKey Bio - FIDO Edition",
    ); // FW 5.7 (second half)
    m.insert(
        "7d1351a6-e097-4852-b8bf-c9ac5c9ce4a3",
        "YubiKey Bio - Multi-protocol",
    ); // FW 5.6
    m.insert(
        "90636e1f-ef82-43bf-bdcf-5255f139d12f",
        "YubiKey Bio - Multi-protocol",
    ); // FW 5.7 (first half)
    m.insert(
        "34744913-4f57-4e6e-a527-e9ec3c4b94e6",
        "YubiKey Bio - Multi-protocol",
    ); // FW 5.7 (second half)

    // Security Key Series
    m.insert(
        "f8a011f3-8c0a-4d15-8006-17111f9edc7d",
        "Security Key by Yubico",
    ); // FW 5.1 (Blue)
    m.insert(
        "b92c3f9a-c014-4056-887f-140a2501163b",
        "Security Key by Yubico",
    ); // FW 5.2 (Blue)
    m.insert("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73", "Security Key NFC"); // FW 5.1 (Blue)
    m.insert("149a2021-8ef6-4133-96b8-81f8d5b7f1f5", "Security Key NFC"); // FW 5.2, 5.4 (Blue)
    m.insert(
        "a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa",
        "Security Key NFC (Black)",
    ); // FW 5.4
    m.insert(
        "e77e3c64-05e3-428b-8824-0cbeb04b829d",
        "Security Key NFC (Black)",
    ); // FW 5.7 (first half)
    m.insert(
        "b7d3f68e-88a6-471e-9ecf-2df26d041ede",
        "Security Key NFC (Black)",
    ); // FW 5.7 (second half)
    m.insert(
        "0bb43545-fd2c-4185-87dd-feb0b2916ace",
        "Security Key NFC - Enterprise",
    ); // FW 5.4 (Black)
    m.insert(
        "47ab2fb4-66ac-4184-9ae1-86be814012d5",
        "Security Key NFC - Enterprise",
    ); // FW 5.7 (first half)
    m.insert(
        "ed042a3a-4b22-4455-bb69-a267b652ae7e",
        "Security Key NFC - Enterprise",
    ); // FW 5.7 (second half)

    // YubiKey 5 CSPN Series (FW 5.4)
    // Most share AAGUIDs with standard YubiKey 5 series
    m.insert("3aa78eb1-ddd8-46a8-a821-8f8ec57a7bd5", "YubiKey 5 CSPN NFC");
    m.insert(
        "4fc84f16-2545-4e53-b8fc-7bf4d7282a10",
        "YubiKey 5 CSPN NFC (Enterprise)",
    );

    // =========================================================================
    // Enterprise Attestation Capable YubiKey AAGUIDs
    // =========================================================================

    // YubiKey 5 Series (Enterprise) - FW 5.7
    m.insert(
        "1ac71f64-468d-4fe0-bef1-0e5f2f551f18",
        "YubiKey 5 NFC (Enterprise)",
    ); // First half
    m.insert(
        "6ab56fad-881f-4a43-acb2-0be065924522",
        "YubiKey 5 NFC (Enterprise)",
    ); // Second half
    m.insert(
        "b2c1a50b-dad8-4dc7-ba4d-0ce9597904bc",
        "YubiKey 5 NFC - Enhanced PIN (Enterprise)",
    );
    m.insert(
        "20ac7a17-c814-4833-93fe-539f0d5e3389",
        "YubiKey 5 Nano (Enterprise)",
    ); // First half (also 5C Nano, 5C)
    m.insert(
        "4599062e-6926-4fe7-9566-9e8fb1aedaa0",
        "YubiKey 5 Nano (Enterprise)",
    ); // Second half
    m.insert(
        "b90e7dc1-316e-4fee-a25a-56a666a670fe",
        "YubiKey 5Ci (Enterprise)",
    ); // First half
    m.insert(
        "3b24bf49-1d45-4484-a917-13175df0867b",
        "YubiKey 5Ci (Enterprise)",
    ); // Second half

    // YubiKey 5 FIPS RC Series (Enterprise) - FW 5.7
    m.insert(
        "79f3c8ba-9e35-484b-8f47-53a5a0f5c630",
        "YubiKey 5 NFC FIPS (Enterprise)",
    ); // Also 5C NFC FIPS
    m.insert(
        "905b4cb4-ed6f-4da9-92fc-45e0d4e9b5c7",
        "YubiKey 5 Nano FIPS (Enterprise)",
    ); // Also 5C Nano FIPS, 5C FIPS
    m.insert(
        "3a662962-c6d4-4023-bebb-98ae92e78e20",
        "YubiKey 5Ci FIPS (Enterprise)",
    );

    // YubiKey Bio Series (Enterprise)
    m.insert(
        "83c47309-aabb-4108-8470-8be838b573cb",
        "YubiKey Bio - FIDO Edition (Enterprise)",
    ); // FW 5.6
    m.insert(
        "8c39ee86-7f9a-4a95-9ba3-f6b097e5c2ee",
        "YubiKey Bio - FIDO Edition (Enterprise)",
    ); // FW 5.7 (first half)
    m.insert(
        "ad08c78a-4e41-49b9-86a2-ac15b06899e2",
        "YubiKey Bio - FIDO Edition (Enterprise)",
    ); // FW 5.7 (second half)
    m.insert(
        "97e6a830-c952-4740-95fc-7c78dc97ce47",
        "YubiKey Bio - Multi-protocol (Enterprise)",
    ); // FW 5.7 (first half)
    m.insert(
        "6ec5cff2-a0f9-4169-945b-f33b563f7b99",
        "YubiKey Bio - Multi-protocol (Enterprise)",
    ); // FW 5.7 (second half)

    // Security Key Series (Enterprise)
    m.insert(
        "9ff4cc65-6154-4fff-ba09-9e2af7882ad2",
        "Security Key NFC - Enterprise Edition",
    ); // FW 5.7 (first half)
    m.insert(
        "72c6b72d-8512-4c66-8359-9d3d10d9222f",
        "Security Key NFC - Enterprise Edition",
    ); // FW 5.7 (second half)

    // Preview (pre-production) AAGUIDs
    m.insert(
        "34f5766d-1536-4a24-9033-0e294e510fb0",
        "YubiKey 5 NFC (Preview)",
    );
    m.insert(
        "3124e301-f14e-4e38-876d-fbeeb090e7bf",
        "YubiKey 5Ci (Preview)",
    );
    m.insert(
        "62e54e98-c209-4df3-b692-de71bb6a8528",
        "YubiKey 5 NFC FIPS (Preview)",
    );
    m.insert(
        "5b0e46ba-db02-44ac-b979-ca9b84f5e335",
        "YubiKey 5Ci FIPS (Preview)",
    );
    m.insert(
        "760eda36-00aa-4d29-855b-4012a182cdeb",
        "Security Key NFC (Preview)",
    );
    m.insert(
        "2772ce93-eb4b-4090-8b73-330f48477d73",
        "Security Key NFC - Enterprise (Preview)",
    );

    // RC Preview (release candidate, FIPS validation in progress) AAGUIDs
    m.insert(
        "d2fbd093-ee62-488d-9dad-1e36389f8826",
        "YubiKey 5 FIPS (RC Preview)",
    );
    m.insert(
        "ce6bf97f-9f69-4ba7-9032-97adc6ca5cf1",
        "YubiKey 5 NFC FIPS (RC Preview)",
    );
    m.insert(
        "9e66c661-e428-452a-a8fb-51f7ed088acf",
        "YubiKey 5Ci FIPS (RC Preview)",
    );

    // Batch/SKU variants
    m.insert(
        "9eb7eabc-9db5-49a1-b6c3-555a802093f4",
        "YubiKey 5 NFC (KVZR57)",
    );
    m.insert(
        "58276709-bb4b-4bb3-baf1-60eea99282a7",
        "YubiKey Bio - Multi-protocol (1VDJSN)",
    );

    // Custom/Organization-specific Enterprise AAGUIDs
    m.insert(
        "28969c24-0487-4a46-be39-37bc6337a24f",
        "YubiKey 5C Nano FIPS (Enterprise)",
    ); // Custom enterprise

    m
});

/// AAGUIDs for FIPS-certified YubiKey models.
///
/// Derived from `AAGUID_MAP` by matching names containing "FIPS".
/// Includes production, enterprise, preview, and RC preview variants.
static FIPS_AAGUIDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    AAGUID_MAP
        .iter()
        .filter(|(_, name)| name.contains("FIPS"))
        .map(|(aaguid, _)| *aaguid)
        .collect()
});

/// AAGUIDs for any YubiKey 5 series model.
///
/// Derived from `AAGUID_MAP` by matching names starting with "YubiKey 5"
/// or "YubiKey Bio - Multi-protocol". Excludes Security Key series and
/// Bio FIDO-only edition (not branded "YubiKey 5").
static YUBIKEY_5_AAGUIDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    AAGUID_MAP
        .iter()
        .filter(|(_, name)| {
            name.starts_with("YubiKey 5") || name.starts_with("YubiKey Bio - Multi-protocol")
        })
        .map(|(aaguid, _)| *aaguid)
        .collect()
});

/// Returns `true` if the AAGUID belongs to a FIPS-certified YubiKey.
///
/// Accepts AAGUIDs in both hyphenated and non-hyphenated formats (case-insensitive).
#[must_use]
pub fn is_fips(aaguid: &str) -> bool {
    let normalized = normalize_aaguid(aaguid);
    FIPS_AAGUIDS.contains(normalized.as_str())
}

/// Returns `true` if the AAGUID belongs to any YubiKey 5 series model.
///
/// This includes FIPS variants, Enterprise attestation variants, and Bio
/// Multi-protocol models. It excludes Security Key series and Bio FIDO Edition.
///
/// Accepts AAGUIDs in both hyphenated and non-hyphenated formats (case-insensitive).
#[must_use]
pub fn is_yubikey_5(aaguid: &str) -> bool {
    let normalized = normalize_aaguid(aaguid);
    YUBIKEY_5_AAGUIDS.contains(normalized.as_str())
}

/// Normalize an AAGUID to lowercase hyphenated UUID format.
///
/// Returns the normalized string, or the input unchanged (lowercased) if it
/// cannot be parsed as a UUID.
fn normalize_aaguid(aaguid: &str) -> String {
    let lower = aaguid.to_lowercase();
    if let Ok(uuid) = Uuid::try_parse(&lower) {
        uuid.as_hyphenated().to_string()
    } else {
        lower
    }
}

/// Policy controlling which AAGUID (authenticator model) values are accepted
/// during WebAuthn registration.
///
/// Configured via the `VOUCH_ALLOWED_AAGUIDS` environment variable:
/// - Empty or unset → `Any` (all hardware keys accepted)
/// - `"fips-only"` → `FipsOnly`
/// - `"yubikey-5"` → `YubiKey5Only`
/// - Comma-separated AAGUIDs → `AllowList`
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AaguidPolicy {
    /// Accept any AAGUID (default). Hardware attestation format is still required.
    #[default]
    Any,
    /// Only accept FIPS-certified YubiKey models.
    FipsOnly,
    /// Only accept YubiKey 5 series models (includes FIPS and Enterprise variants).
    YubiKey5Only,
    /// Only accept AAGUIDs from an explicit allowlist.
    AllowList(std::collections::HashSet<String>),
}

impl AaguidPolicy {
    /// Returns `true` if the given AAGUID is permitted by this policy.
    #[must_use]
    pub fn is_allowed(&self, aaguid: &str) -> bool {
        match self {
            Self::Any => true,
            Self::FipsOnly => is_fips(aaguid),
            Self::YubiKey5Only => is_yubikey_5(aaguid),
            Self::AllowList(set) => {
                let normalized = normalize_aaguid(aaguid);
                set.contains(&normalized)
            }
        }
    }

    /// Parse an `AaguidPolicy` from a configuration string.
    ///
    /// # Errors
    ///
    /// Returns an error string if any entry in a comma-separated list is not
    /// a valid UUID.
    pub fn parse(s: &str) -> Result<Self, String> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Ok(Self::Any);
        }
        let lower = trimmed.to_ascii_lowercase();
        match lower.as_str() {
            "fips-only" => Ok(Self::FipsOnly),
            "yubikey-5" => Ok(Self::YubiKey5Only),
            _ => {
                let entries: Result<std::collections::HashSet<String>, String> = trimmed
                    .split(',')
                    .map(|entry| {
                        let e = entry.trim();
                        Uuid::try_parse(e)
                            .map(|u| u.as_hyphenated().to_string())
                            .map_err(|_| format!("invalid AAGUID: '{e}'"))
                    })
                    .collect();
                Ok(Self::AllowList(entries?))
            }
        }
    }
}

/// Look up the device model name for an AAGUID.
///
/// Returns the human-readable device model name if known, or `None` if the
/// AAGUID is not in the lookup table.
///
/// Accepts AAGUIDs in both hyphenated (`28969c24-0487-4a46-be39-37bc6337a24f`)
/// and non-hyphenated (`28969c2404874a46be3937bc6337a24f`) formats.
#[must_use]
pub fn lookup_device_model(aaguid: &str) -> Option<&'static str> {
    let normalized = normalize_aaguid(aaguid);
    AAGUID_MAP.get(normalized.as_str()).copied()
}

/// Extract AAGUID from authenticator data.
///
/// The authenticator data structure is:
/// - rpIdHash: 32 bytes
/// - flags: 1 byte
/// - signCount: 4 bytes
/// - attestedCredentialData (if AT flag set):
///   - aaguid: 16 bytes
///   - credIdLen: 2 bytes (big-endian)
///   - credId: credIdLen bytes
///   - credentialPublicKey: COSE-encoded
///
/// Returns the AAGUID as a UUID string if present and valid.
#[must_use]
pub fn extract_aaguid_from_auth_data(auth_data: &[u8]) -> Option<String> {
    // Minimum length: rpIdHash(32) + flags(1) + signCount(4) + aaguid(16) = 53
    if auth_data.len() < 53 {
        return None;
    }

    // Check AT flag (bit 6) — WebAuthn §6.1, Table 1
    let flags = auth_data.get(32)?;
    if flags & 0x40 == 0 {
        // AT flag not set, no attested credential data
        return None;
    }

    // AAGUID is at offset 37 (after rpIdHash + flags + signCount)
    let aaguid_slice = auth_data.get(37..53)?;
    let aaguid_bytes: [u8; 16] = aaguid_slice.try_into().ok()?;

    // Format as UUID string
    Some(Uuid::from_bytes(aaguid_bytes).to_string())
}

/// Extract the COSE-encoded public key from authenticator data.
///
/// The authenticator data structure (for registration with AT flag):
/// - rpIdHash: 32 bytes
/// - flags: 1 byte
/// - signCount: 4 bytes
/// - attestedCredentialData (if AT flag set):
///   - aaguid: 16 bytes
///   - credIdLen: 2 bytes (big-endian)
///   - credId: credIdLen bytes
///   - credentialPublicKey: COSE-encoded (remaining bytes)
///
/// Returns the raw COSE public key bytes if present and valid.
#[must_use]
pub fn extract_public_key_from_auth_data(auth_data: &[u8]) -> Option<Vec<u8>> {
    // Minimum length: rpIdHash(32) + flags(1) + signCount(4) + aaguid(16) + credIdLen(2) = 55
    if auth_data.len() < 55 {
        return None;
    }

    // Check AT flag (bit 6) — WebAuthn §6.1, Table 1
    let flags = auth_data.get(32)?;
    if flags & 0x40 == 0 {
        // AT flag not set, no attested credential data
        return None;
    }

    // Credential ID length is at offset 53-54 (big-endian)
    let cred_id_len_bytes: [u8; 2] = auth_data.get(53..55)?.try_into().ok()?;
    let cred_id_len = u16::from_be_bytes(cred_id_len_bytes) as usize;

    // Public key starts after credId
    let public_key_offset = 55_usize.checked_add(cred_id_len)?;

    // The rest of auth_data is the COSE-encoded public key
    auth_data.get(public_key_offset..).map(|s| s.to_vec())
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    // =========================================================================
    // Device Model Lookup Tests
    // =========================================================================

    #[test]
    fn test_lookup_yubikey_5_nfc() {
        assert_eq!(
            lookup_device_model("2fc0579f-8113-47ea-b116-bb5a8db9202a"),
            Some("YubiKey 5 NFC")
        );
    }

    #[test]
    fn test_lookup_yubikey_5c_nano_fips() {
        assert_eq!(
            lookup_device_model("73bb0cd4-e502-49b8-9c6f-b59445bf720b"),
            Some("YubiKey 5C Nano FIPS")
        );
    }

    #[test]
    fn test_lookup_unknown_device() {
        assert_eq!(
            lookup_device_model("00000000-0000-0000-0000-000000000000"),
            None
        );
    }

    #[test]
    fn test_lookup_case_insensitive() {
        assert_eq!(
            lookup_device_model("2FC0579F-8113-47EA-B116-BB5A8DB9202A"),
            Some("YubiKey 5 NFC")
        );
    }

    #[test]
    fn test_lookup_non_hyphenated_uuid_format() {
        // UUID without hyphens should still work
        assert_eq!(
            lookup_device_model("2fc0579f811347eab116bb5a8db9202a"),
            Some("YubiKey 5 NFC")
        );
    }

    #[test]
    fn test_lookup_invalid_uuid_format() {
        // Invalid UUID format returns None
        assert_eq!(lookup_device_model("not-a-valid-uuid"), None);
        assert_eq!(lookup_device_model(""), None);
        assert_eq!(
            lookup_device_model("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"),
            None
        );
    }

    // =========================================================================
    // AAGUID Extraction Tests
    // =========================================================================

    #[test]
    fn test_extract_aaguid_valid() {
        // Minimal auth data with AT flag set and a known AAGUID
        let mut auth_data = vec![0u8; 53];
        auth_data[32] = 0x41; // flags: AT flag (0x40) + UP flag (0x01)
        // Insert AAGUID for YubiKey 5 NFC at offset 37
        let aaguid_bytes = [
            0x2f, 0xc0, 0x57, 0x9f, 0x81, 0x13, 0x47, 0xea, 0xb1, 0x16, 0xbb, 0x5a, 0x8d, 0xb9,
            0x20, 0x2a,
        ];
        auth_data[37..53].copy_from_slice(&aaguid_bytes);

        let result = extract_aaguid_from_auth_data(&auth_data);
        assert_eq!(
            result,
            Some("2fc0579f-8113-47ea-b116-bb5a8db9202a".to_string())
        );
    }

    #[test]
    fn test_extract_aaguid_no_at_flag() {
        let mut auth_data = vec![0u8; 53];
        auth_data[32] = 0x01; // flags: only UP flag, no AT flag

        let result = extract_aaguid_from_auth_data(&auth_data);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_aaguid_too_short() {
        let auth_data = vec![0u8; 40]; // Too short

        let result = extract_aaguid_from_auth_data(&auth_data);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_aaguid_exactly_minimum() {
        // Exactly 53 bytes - minimum for AAGUID extraction
        let mut auth_data = vec![0u8; 53];
        auth_data[32] = 0x41; // AT + UP flags
        // Set AAGUID at offset 37
        auth_data[37..53].copy_from_slice(&[0x01; 16]);

        let result = extract_aaguid_from_auth_data(&auth_data);
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_aaguid_one_byte_short() {
        // 52 bytes - just under minimum
        let mut auth_data = vec![0u8; 52];
        auth_data[32] = 0x41; // AT + UP flags

        let result = extract_aaguid_from_auth_data(&auth_data);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_aaguid_with_extra_data() {
        // More than minimum, should still work
        let mut auth_data = vec![0u8; 200];
        auth_data[32] = 0x41; // AT + UP flags
        let aaguid_bytes = [
            0x2f, 0xc0, 0x57, 0x9f, 0x81, 0x13, 0x47, 0xea, 0xb1, 0x16, 0xbb, 0x5a, 0x8d, 0xb9,
            0x20, 0x2a,
        ];
        auth_data[37..53].copy_from_slice(&aaguid_bytes);

        let result = extract_aaguid_from_auth_data(&auth_data);
        assert_eq!(
            result,
            Some("2fc0579f-8113-47ea-b116-bb5a8db9202a".to_string())
        );
    }

    #[test]
    fn test_extract_aaguid_zero_aaguid() {
        // Zero AAGUID (valid but means "unknown authenticator")
        let mut auth_data = vec![0u8; 53];
        auth_data[32] = 0x41; // AT + UP flags
        // AAGUID is all zeros (default)

        let result = extract_aaguid_from_auth_data(&auth_data);
        assert_eq!(
            result,
            Some("00000000-0000-0000-0000-000000000000".to_string())
        );
    }

    // =========================================================================
    // Public Key Extraction Tests
    // =========================================================================

    #[test]
    fn test_extract_public_key_from_auth_data_valid() {
        // Create auth data with AT flag and a credential
        // Structure: rpIdHash(32) + flags(1) + signCount(4) + aaguid(16) + credIdLen(2) + credId + publicKey
        let mut auth_data = vec![0u8; 55 + 16 + 77]; // 55 base + 16 byte cred ID + 77 byte public key

        auth_data[32] = 0x41; // AT + UP flags
        // credIdLen at offset 53-54 (big-endian)
        auth_data[53] = 0x00;
        auth_data[54] = 0x10; // 16 bytes for credential ID
        // Credential ID at offset 55-70
        auth_data[55..71].fill(0xAA);
        // Public key starts at offset 71 (55 + 16)
        auth_data[71..].fill(0xBB);

        let result = extract_public_key_from_auth_data(&auth_data);
        assert!(result.is_some());
        let pk = result.unwrap();
        assert_eq!(pk.len(), 77);
        assert!(pk.iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn test_extract_public_key_from_auth_data_no_at_flag() {
        let mut auth_data = vec![0u8; 100];
        auth_data[32] = 0x01; // UP flag only, no AT flag

        let result = extract_public_key_from_auth_data(&auth_data);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_public_key_from_auth_data_too_short() {
        // Less than 55 bytes (minimum for public key extraction)
        let mut auth_data = vec![0u8; 54];
        auth_data[32] = 0x41; // AT + UP flags

        let result = extract_public_key_from_auth_data(&auth_data);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_public_key_cred_id_len_exceeds_data() {
        // credIdLen claims more bytes than available
        let mut auth_data = vec![0u8; 60]; // Only 60 bytes total
        auth_data[32] = 0x41; // AT + UP flags
        auth_data[53] = 0x00;
        auth_data[54] = 0xFF; // credIdLen = 255, but not enough data

        let result = extract_public_key_from_auth_data(&auth_data);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_public_key_huge_cred_id_len() {
        // credIdLen at maximum u16 value
        let mut auth_data = vec![0u8; 100];
        auth_data[32] = 0x41; // AT + UP flags
        auth_data[53] = 0xFF;
        auth_data[54] = 0xFF; // credIdLen = 65535

        let result = extract_public_key_from_auth_data(&auth_data);
        // Should return None because 55 + 65535 > auth_data.len()
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_public_key_zero_cred_id_len() {
        // Zero-length credential ID
        let mut auth_data = vec![0u8; 100];
        auth_data[32] = 0x41; // AT + UP flags
        auth_data[53] = 0x00;
        auth_data[54] = 0x00; // credIdLen = 0
        // Public key starts immediately at offset 55
        auth_data[55..].fill(0xCC);

        let result = extract_public_key_from_auth_data(&auth_data);
        assert!(result.is_some());
        let pk = result.unwrap();
        assert_eq!(pk.len(), 45); // 100 - 55 = 45
    }

    #[test]
    fn test_extract_public_key_empty_result() {
        // No bytes left after credential ID
        let mut auth_data = vec![0u8; 71]; // Exactly 55 + 16 bytes for cred ID
        auth_data[32] = 0x41; // AT + UP flags
        auth_data[53] = 0x00;
        auth_data[54] = 0x10; // credIdLen = 16

        let result = extract_public_key_from_auth_data(&auth_data);
        // Returns Some with empty vec
        assert_eq!(result, Some(vec![]));
    }

    // =========================================================================
    // Edge Cases and Boundary Conditions
    // =========================================================================

    #[test]
    fn test_extract_aaguid_flags_byte_boundary() {
        // Test various flag combinations
        let test_flags = [
            (0x40, true),  // AT only (valid)
            (0x41, true),  // AT + UP (valid)
            (0x45, true),  // AT + UV + UP (valid)
            (0xC1, true),  // AT + ED + UP (valid)
            (0x00, false), // No flags
            (0x01, false), // UP only
            (0x04, false), // UV only
            (0x80, false), // ED only
        ];

        for (flags, should_extract) in test_flags {
            let mut auth_data = vec![0u8; 53];
            auth_data[32] = flags;
            auth_data[37..53].fill(0xAB);

            let result = extract_aaguid_from_auth_data(&auth_data);
            assert_eq!(
                result.is_some(),
                should_extract,
                "Failed for flags: 0x{:02X}",
                flags
            );
        }
    }

    #[test]
    fn test_extract_aaguid_all_ff_bytes() {
        // All 0xFF bytes AAGUID
        let mut auth_data = vec![0u8; 53];
        auth_data[32] = 0x41;
        auth_data[37..53].fill(0xFF);

        let result = extract_aaguid_from_auth_data(&auth_data);
        assert_eq!(
            result,
            Some("ffffffff-ffff-ffff-ffff-ffffffffffff".to_string())
        );
    }

    // =========================================================================
    // is_fips / is_yubikey_5 Tests
    // =========================================================================

    #[test]
    fn test_fips_aaguids_count() {
        assert_eq!(FIPS_AAGUIDS.len(), 15);
    }

    #[test]
    fn test_yubikey_5_aaguids_count() {
        assert_eq!(YUBIKEY_5_AAGUIDS.len(), 45);
    }

    #[test]
    fn test_cspn_is_yubikey_5_not_fips() {
        // CSPN (French certification) is YubiKey 5 but not FIPS
        assert!(is_yubikey_5("3aa78eb1-ddd8-46a8-a821-8f8ec57a7bd5"));
        assert!(!is_fips("3aa78eb1-ddd8-46a8-a821-8f8ec57a7bd5"));
    }

    #[test]
    fn test_is_fips_known_fips_aaguid() {
        assert!(is_fips("73bb0cd4-e502-49b8-9c6f-b59445bf720b")); // YubiKey 5C Nano FIPS
        assert!(is_fips("c1f9a0bc-1dd2-404a-b27f-8e29047a43fd")); // YubiKey 5 NFC FIPS
        assert!(is_fips("85203421-48f9-4355-9bc8-8a53846e5083")); // YubiKey 5Ci FIPS
        assert!(is_fips("fcc0118f-cd45-435b-8da1-9782b2da0715")); // YubiKey 5 NFC FIPS RC
        assert!(is_fips("57f7de54-c807-4eab-b1c6-1c9be7984e92")); // YubiKey 5 Nano FIPS RC
        assert!(is_fips("7b96457d-e3cd-432b-9ceb-c9fdd7ef7432")); // YubiKey 5Ci FIPS RC
        assert!(is_fips("79f3c8ba-9e35-484b-8f47-53a5a0f5c630")); // YubiKey 5 NFC FIPS (Enterprise)
        assert!(is_fips("905b4cb4-ed6f-4da9-92fc-45e0d4e9b5c7")); // YubiKey 5 Nano FIPS (Enterprise)
        assert!(is_fips("3a662962-c6d4-4023-bebb-98ae92e78e20")); // YubiKey 5Ci FIPS (Enterprise)
        assert!(is_fips("28969c24-0487-4a46-be39-37bc6337a24f")); // YubiKey 5C Nano FIPS (Enterprise)
    }

    #[test]
    fn test_is_fips_non_fips_aaguid() {
        assert!(!is_fips("2fc0579f-8113-47ea-b116-bb5a8db9202a")); // YubiKey 5 NFC (non-FIPS)
        assert!(!is_fips("ee882879-721c-4913-9775-3dfcce97072a")); // YubiKey 5 (USB-A)
        assert!(!is_fips("f8a011f3-8c0a-4d15-8006-17111f9edc7d")); // Security Key
        assert!(!is_fips("00000000-0000-0000-0000-000000000000")); // Unknown
    }

    #[test]
    fn test_is_fips_case_insensitive() {
        assert!(is_fips("73BB0CD4-E502-49B8-9C6F-B59445BF720B"));
        assert!(is_fips("73bb0cd4e50249b89c6fb59445bf720b")); // No hyphens
    }

    #[test]
    fn test_is_yubikey_5_standard_models() {
        assert!(is_yubikey_5("2fc0579f-8113-47ea-b116-bb5a8db9202a")); // YubiKey 5 NFC
        assert!(is_yubikey_5("ee882879-721c-4913-9775-3dfcce97072a")); // YubiKey 5 (USB-A)
        assert!(is_yubikey_5("c5ef55ff-ad9a-4b9f-b580-adebafe026d0")); // YubiKey 5Ci
        assert!(is_yubikey_5("73bb0cd4-e502-49b8-9c6f-b59445bf720b")); // YubiKey 5C Nano FIPS
    }

    #[test]
    fn test_is_yubikey_5_fips_models() {
        // All FIPS models are also YubiKey 5 series
        assert!(is_yubikey_5("c1f9a0bc-1dd2-404a-b27f-8e29047a43fd"));
        assert!(is_yubikey_5("85203421-48f9-4355-9bc8-8a53846e5083"));
        assert!(is_yubikey_5("79f3c8ba-9e35-484b-8f47-53a5a0f5c630"));
    }

    #[test]
    fn test_is_yubikey_5_bio_multiprotocol() {
        assert!(is_yubikey_5("7d1351a6-e097-4852-b8bf-c9ac5c9ce4a3")); // Bio Multi-protocol FW 5.6
        assert!(is_yubikey_5("90636e1f-ef82-43bf-bdcf-5255f139d12f")); // Bio Multi-protocol FW 5.7
    }

    #[test]
    fn test_is_yubikey_5_excludes_security_key_and_bio_fido() {
        assert!(!is_yubikey_5("f8a011f3-8c0a-4d15-8006-17111f9edc7d")); // Security Key
        assert!(!is_yubikey_5("b92c3f9a-c014-4056-887f-140a2501163b")); // Security Key NFC
        assert!(!is_yubikey_5("d8522d9f-575b-4866-88a9-ba99fa02f35b")); // Bio FIDO Edition
        assert!(!is_yubikey_5("00000000-0000-0000-0000-000000000000")); // Unknown
    }

    // =========================================================================
    // AaguidPolicy Tests
    // =========================================================================

    #[test]
    fn test_policy_any_allows_all() {
        let policy = AaguidPolicy::Any;
        assert!(policy.is_allowed("2fc0579f-8113-47ea-b116-bb5a8db9202a"));
        assert!(policy.is_allowed("f8a011f3-8c0a-4d15-8006-17111f9edc7d"));
        assert!(policy.is_allowed("00000000-0000-0000-0000-000000000000"));
    }

    #[test]
    fn test_policy_fips_only() {
        let policy = AaguidPolicy::FipsOnly;
        assert!(policy.is_allowed("73bb0cd4-e502-49b8-9c6f-b59445bf720b")); // FIPS
        assert!(!policy.is_allowed("2fc0579f-8113-47ea-b116-bb5a8db9202a")); // Non-FIPS YK5
        assert!(!policy.is_allowed("f8a011f3-8c0a-4d15-8006-17111f9edc7d")); // Security Key
    }

    #[test]
    fn test_policy_yubikey_5_only() {
        let policy = AaguidPolicy::YubiKey5Only;
        assert!(policy.is_allowed("2fc0579f-8113-47ea-b116-bb5a8db9202a")); // YubiKey 5 NFC
        assert!(policy.is_allowed("73bb0cd4-e502-49b8-9c6f-b59445bf720b")); // FIPS (also YK5)
        assert!(!policy.is_allowed("f8a011f3-8c0a-4d15-8006-17111f9edc7d")); // Security Key
        assert!(!policy.is_allowed("d8522d9f-575b-4866-88a9-ba99fa02f35b")); // Bio FIDO Edition
    }

    #[test]
    fn test_policy_allowlist() {
        let policy = AaguidPolicy::AllowList(
            ["2fc0579f-8113-47ea-b116-bb5a8db9202a".to_string()]
                .into_iter()
                .collect(),
        );
        assert!(policy.is_allowed("2fc0579f-8113-47ea-b116-bb5a8db9202a"));
        assert!(!policy.is_allowed("ee882879-721c-4913-9775-3dfcce97072a"));
    }

    #[test]
    fn test_policy_allowlist_case_insensitive() {
        let policy = AaguidPolicy::AllowList(
            ["2fc0579f-8113-47ea-b116-bb5a8db9202a".to_string()]
                .into_iter()
                .collect(),
        );
        assert!(policy.is_allowed("2FC0579F-8113-47EA-B116-BB5A8DB9202A"));
        assert!(policy.is_allowed("2fc0579f811347eab116bb5a8db9202a")); // No hyphens
    }

    #[test]
    fn test_policy_parse_empty() {
        assert_eq!(AaguidPolicy::parse("").unwrap(), AaguidPolicy::Any);
        assert_eq!(AaguidPolicy::parse("  ").unwrap(), AaguidPolicy::Any);
    }

    #[test]
    fn test_policy_parse_fips_only() {
        assert_eq!(
            AaguidPolicy::parse("fips-only").unwrap(),
            AaguidPolicy::FipsOnly
        );
    }

    #[test]
    fn test_policy_parse_yubikey_5() {
        assert_eq!(
            AaguidPolicy::parse("yubikey-5").unwrap(),
            AaguidPolicy::YubiKey5Only
        );
    }

    #[test]
    fn test_policy_parse_allowlist_single() {
        let policy = AaguidPolicy::parse("2fc0579f-8113-47ea-b116-bb5a8db9202a").unwrap();
        assert!(matches!(policy, AaguidPolicy::AllowList(ref set) if set.len() == 1));
        assert!(policy.is_allowed("2fc0579f-8113-47ea-b116-bb5a8db9202a"));
    }

    #[test]
    fn test_policy_parse_allowlist_multiple() {
        let policy = AaguidPolicy::parse(
            "2fc0579f-8113-47ea-b116-bb5a8db9202a, \
             73bb0cd4-e502-49b8-9c6f-b59445bf720b",
        )
        .unwrap();
        assert!(matches!(policy, AaguidPolicy::AllowList(ref set) if set.len() == 2));
        assert!(policy.is_allowed("2fc0579f-8113-47ea-b116-bb5a8db9202a"));
        assert!(policy.is_allowed("73bb0cd4-e502-49b8-9c6f-b59445bf720b"));
    }

    #[test]
    fn test_policy_parse_case_insensitive_keywords() {
        assert_eq!(
            AaguidPolicy::parse("FIPS-ONLY").unwrap(),
            AaguidPolicy::FipsOnly
        );
        assert_eq!(
            AaguidPolicy::parse("Fips-Only").unwrap(),
            AaguidPolicy::FipsOnly
        );
        assert_eq!(
            AaguidPolicy::parse("YUBIKEY-5").unwrap(),
            AaguidPolicy::YubiKey5Only
        );
    }

    #[test]
    fn test_policy_parse_invalid_uuid_errors() {
        let result = AaguidPolicy::parse("not-a-uuid");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("invalid AAGUID"), "unexpected error: {err}");
    }

    #[test]
    fn test_policy_default_is_any() {
        assert_eq!(AaguidPolicy::default(), AaguidPolicy::Any);
    }
}
