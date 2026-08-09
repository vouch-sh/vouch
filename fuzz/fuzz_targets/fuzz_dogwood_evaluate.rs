#![no_main]

use libfuzzer_sys::fuzz_target;

// The runtime evaluation path: a validated policy set decided against an
// arbitrary replayed history. This executes on every login and token
// exchange once a temporal policy is active, under `panic = "abort"`.
fuzz_target!(|rows: Vec<(String, String, String, i64)>| {
    // Bound the trace so the fuzzer explores shapes, not sheer volume.
    if rows.len() > 64 {
        return;
    }
    vouch_server::test_utils::fuzz_evaluate_history(&rows);
});
