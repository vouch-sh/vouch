//! AAGUID (Authenticator Attestation GUID) lookup for device model identification.
//!
//! The AAGUID is a 16-byte identifier embedded in FIDO2 authenticator data that
//! uniquely identifies the model of authenticator.
//!
//! Source: https://support.yubico.com/hc/en-us/articles/360016648959-YubiKey-hardware-FIDO2-AAGUIDs

use std::collections::HashMap;
use std::sync::LazyLock;

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

    // Custom/Organization-specific Enterprise AAGUIDs
    m.insert(
        "28969c24-0487-4a46-be39-37bc6337a24f",
        "YubiKey 5C Nano FIPS (Enterprise)",
    ); // Custom enterprise

    m
});

/// Look up the device model name for an AAGUID.
///
/// Returns the human-readable device model name if known, or `None` if the
/// AAGUID is not in the lookup table.
#[must_use]
pub fn lookup_device_model(aaguid: &str) -> Option<&'static str> {
    // Normalize to lowercase for comparison
    let normalized = aaguid.to_lowercase();
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

    // Check AT flag (bit 6) to see if attested credential data is present
    let flags = auth_data.get(32)?;
    if flags & 0x40 == 0 {
        // AT flag not set, no attested credential data
        return None;
    }

    // AAGUID is at offset 37 (after rpIdHash + flags + signCount)
    let aaguid_slice = auth_data.get(37..53)?;
    let aaguid_bytes: [u8; 16] = aaguid_slice.try_into().ok()?;

    // Format as UUID string
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        aaguid_bytes[0],
        aaguid_bytes[1],
        aaguid_bytes[2],
        aaguid_bytes[3],
        aaguid_bytes[4],
        aaguid_bytes[5],
        aaguid_bytes[6],
        aaguid_bytes[7],
        aaguid_bytes[8],
        aaguid_bytes[9],
        aaguid_bytes[10],
        aaguid_bytes[11],
        aaguid_bytes[12],
        aaguid_bytes[13],
        aaguid_bytes[14],
        aaguid_bytes[15],
    ))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

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
}
