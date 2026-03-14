#![no_main]

use libfuzzer_sys::fuzz_target;
use vouch_server::crypto::ber::DerParser;

fuzz_target!(|data: &[u8]| {
    // Exercise all DerParser entry points with arbitrary bytes.
    // None of these should panic.

    let mut p = DerParser::new(data);
    let _ = p.read_tlv();

    let mut p = DerParser::new(data);
    let _ = p.read_tlv_ber();

    let mut p = DerParser::new(data);
    let _ = p.expect_octet_string();

    let mut p = DerParser::new(data);
    let _ = p.expect_sequence_ber();

    let mut p = DerParser::new(data);
    let _ = p.expect_set_ber();

    let mut p = DerParser::new(data);
    let _ = p.skip_tlv();

    let mut p = DerParser::new(data);
    let _ = p.skip_tlv_ber();

    for n in 0..4u8 {
        let mut p = DerParser::new(data);
        let _ = p.expect_context_explicit_ber(n);

        let mut p = DerParser::new(data);
        let _ = p.read_implicit_octet_string_ber(n);
    }

    // Sequential reads until exhaustion
    let mut p = DerParser::new(data);
    for _ in 0..20 {
        if p.read_tlv_ber().is_err() {
            break;
        }
    }
});
