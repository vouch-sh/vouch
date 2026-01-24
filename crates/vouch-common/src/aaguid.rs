//! AAGUID (Authenticator Attestation GUID) lookup for device model identification.
//!
//! The AAGUID is a 16-byte identifier embedded in FIDO2 authenticator data that
//! uniquely identifies the model of authenticator.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Known AAGUIDs mapped to device model names.
/// Source: FIDO Alliance Metadata Service and Yubico documentation.
static AAGUID_MAP: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();

    // YubiKey 5 Series
    m.insert("2fc0579f-8113-47ea-b116-bb5a8db9202a", "YubiKey 5 NFC");
    m.insert("c5ef55ff-ad9a-4b9f-b580-adebafe026d0", "YubiKey 5C");
    m.insert("fa2b99dc-9e39-4257-8f92-4a30d23c4118", "YubiKey 5C NFC");
    m.insert("cb69481e-8ff7-4039-93ec-0a2729a154a8", "YubiKey 5 Nano");
    m.insert("c1f9a0bc-1dd2-404a-b27f-8e29047a43fd", "YubiKey 5C Nano");
    m.insert("73bb0cd4-e502-49b8-9c6f-b59445bf720b", "YubiKey 5Ci");
    m.insert("85203421-48f9-4355-9bc8-8a53846e5083", "YubiKey 5A");

    // YubiKey 5 FIPS Series
    m.insert("ee882879-721c-4913-9775-3dfcce97072a", "YubiKey 5 NFC FIPS");
    m.insert("c1f9a0bc-1dd2-404a-b27f-8e29047a43fd", "YubiKey 5C FIPS");
    m.insert("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73", "YubiKey 5Ci FIPS");

    // YubiKey Bio Series
    m.insert("d8522d9f-575b-4866-88a9-ba99fa02f35b", "YubiKey Bio");
    m.insert("f8a011f3-8c0a-4d15-8006-17111f9edc7d", "YubiKey Bio FIPS");

    // Security Key Series (blue keys)
    m.insert("149a2021-8ef6-4133-96b8-81f8d5b7f1f5", "Security Key NFC");
    m.insert("a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa", "Security Key NFC");
    m.insert("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73", "Security Key C NFC");

    // YubiKey 4 Series (older)
    m.insert("f8a011f3-8c0a-4d15-8006-17111f9edc7d", "YubiKey 4");
    m.insert("b92c3f9a-c014-4056-887f-140a2501163b", "YubiKey 4 Nano");
    m.insert("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73", "YubiKey 4C");
    m.insert("e1a96183-5016-4f24-b55b-e3ae23614cc6", "YubiKey 4C Nano");

    // Newer models (2024+)
    m.insert("a25342c0-3cdc-4414-8e46-f4807fca511c", "YubiKey 5 NFC");
    m.insert("0bb43545-fd2c-4185-87dd-feb0b2916ace", "YubiKey 5C NFC");

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
    let aaguid_bytes = auth_data.get(37..53)?;

    // Format as UUID string
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        aaguid_bytes.first().unwrap_or(&0),
        aaguid_bytes.get(1).unwrap_or(&0),
        aaguid_bytes.get(2).unwrap_or(&0),
        aaguid_bytes.get(3).unwrap_or(&0),
        aaguid_bytes.get(4).unwrap_or(&0),
        aaguid_bytes.get(5).unwrap_or(&0),
        aaguid_bytes.get(6).unwrap_or(&0),
        aaguid_bytes.get(7).unwrap_or(&0),
        aaguid_bytes.get(8).unwrap_or(&0),
        aaguid_bytes.get(9).unwrap_or(&0),
        aaguid_bytes.get(10).unwrap_or(&0),
        aaguid_bytes.get(11).unwrap_or(&0),
        aaguid_bytes.get(12).unwrap_or(&0),
        aaguid_bytes.get(13).unwrap_or(&0),
        aaguid_bytes.get(14).unwrap_or(&0),
        aaguid_bytes.get(15).unwrap_or(&0),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_known_device() {
        assert_eq!(
            lookup_device_model("2fc0579f-8113-47ea-b116-bb5a8db9202a"),
            Some("YubiKey 5 NFC")
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
}
