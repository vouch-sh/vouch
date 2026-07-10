#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise CBOR attestation object parsing with arbitrary bytes.

    // Try parsing as a CBOR value first, then re-encode and parse
    // as attestation object components.
    if let Ok(value) = ciborium::de::from_reader::<ciborium::Value, _>(data) {
        // If it decoded as CBOR, try extracting attestation fields
        if let ciborium::Value::Map(entries) = &value {
            for (key, val) in entries {
                if let ciborium::Value::Text(k) = key {
                    match k.as_str() {
                        "authData" => {
                            if let ciborium::Value::Bytes(auth_data) = val {
                                let _ = vouch_common::aaguid::extract_aaguid_from_auth_data(
                                    auth_data,
                                );
                                let _ =
                                    vouch_common::aaguid::extract_public_key_from_auth_data(
                                        auth_data,
                                    );
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // Also try raw auth data extraction directly
    let _ = vouch_common::aaguid::extract_aaguid_from_auth_data(data);
    let _ = vouch_common::aaguid::extract_public_key_from_auth_data(data);
});
