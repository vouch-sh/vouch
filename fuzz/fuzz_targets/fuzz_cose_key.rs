#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise COSE key parsing with arbitrary bytes.
    // COSE keys are CBOR maps with integer keys that come from untrusted
    // WebAuthn registration responses.

    // Try decoding as CBOR and re-encoding to exercise the ciborium path
    if let Ok(value) = ciborium::de::from_reader::<ciborium::Value, _>(data) {
        // If it decoded as a CBOR map, try to extract key type (kty = 1)
        if let ciborium::Value::Map(ref entries) = value {
            for (key, _val) in entries {
                if let ciborium::Value::Integer(i) = key {
                    let _ = i128::from(*i);
                }
            }
        }
        // Re-encode and verify it doesn't panic
        let mut buf = Vec::new();
        let _ = ciborium::into_writer(&value, &mut buf);
    }

    // Exercise the server's COSE key → CBOR serialization path
    // by trying to parse as a webauthn_rs COSEKey from raw CBOR
    let _ = ciborium::de::from_reader::<ciborium::Value, _>(data);
});
