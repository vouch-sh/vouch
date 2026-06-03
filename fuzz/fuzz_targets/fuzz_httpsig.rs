#![no_main]

use libfuzzer_sys::fuzz_target;
use vouch_httpsig::sfv::parse::{parse_dictionary, parse_inner_list, parse_item, parse_list};
use vouch_httpsig::signature_params::SignatureParams;

fuzz_target!(|data: &[u8]| {
    // Only process valid UTF-8 — HTTP headers are nominally ASCII/UTF-8.
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    // Exercise all SFV parsing entry points. None should panic.
    let _ = parse_dictionary(input);
    let _ = parse_list(input);
    let _ = parse_item(input);

    // parse_inner_list is the format used by Signature-Input values.
    if let Ok(inner_list) = parse_inner_list(input) {
        // If we successfully parsed an inner list, try the full
        // signature params pipeline (component parsing, param extraction).
        let _ = SignatureParams::from_inner_list(&inner_list);
    }

    // Exercise Content-Digest verification with arbitrary header values.
    // The body doesn't matter here — we're fuzzing the parsing path.
    let _ = vouch_httpsig::digest::verify_content_digest(input, b"");
});
