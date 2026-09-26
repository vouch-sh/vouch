#![no_main]

use libfuzzer_sys::fuzz_target;
use vouch_server::test_utils;

// Admin-supplied Dogwood/Cedar policy text runs through parse → lower →
// validate on the server (release profile: panic = "abort"). No input may
// panic this path.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    test_utils::fuzz_validate_policy_text(text);
});
