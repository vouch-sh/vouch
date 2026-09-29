# No Case-Fold Offset Remap

An offset located in a case-folded copy of a string must never be mapped back into the original string by counting characters or bytes.

## What to look for

Unicode case conversion (`to_lowercase()` / `to_uppercase()`) is not length-preserving in either bytes or codepoints:

- `ß` (U+00DF) lowercases to `ss` — two bytes become four, so a byte offset drifts.
- `İ` (U+0130, LATIN CAPITAL LETTER I WITH DOT ABOVE) lowercases to `i\u{307}` — one char becomes two, so a **char-count** offset also drifts.

The defect pattern has two sub-forms:

**Sub-form A — byte-offset remap (incorrect):**  
Call `to_lowercase()`, run `find()` on the result to get a byte position, then use that byte position to index into the original string.

**Sub-form B — char-count remap (also incorrect, subtler):**  
Call `to_lowercase()`, run `find()` to get a byte position in the folded string, convert that to a `chars().count()`, then call `char_indices().nth(count)` on the original string to recover a byte position. This was the form introduced in this repo as the "fix" for sub-form A; it still fails for U+0130 because one codepoint in the original maps to two codepoints in the folded copy, so the count diverges.

**The only safe strategies are:**

1. **Search the original string directly** using `eq_ignore_ascii_case`, `windows(...).position(|w| w.eq_ignore_ascii_case(...))`, or a similar API that never touches a folded copy.
2. **Derive the result entirely from the folded copy** — only safe when the extracted value is known to be ASCII-only (e.g., a structured keyword, not user data).
3. **Use a case-insensitive regex or iterator** that operates on the original bytes/chars throughout.

Triggers to scan for:

- Any block where `to_lowercase()` or `to_uppercase()` is called on the same binding that is later passed to `.find()`, followed by indexing or slicing of the **original** (un-folded) variable.
- The idiom `lower.find(needle) → lower_end → lower.get(..lower_end).chars().count() → orig.char_indices().nth(n)`.
- `path.to_lowercase()` / `filter.to_lowercase()` used as a search proxy when the goal is to extract a substring from `path` / `filter`.

## Violation examples

**Byte-offset remap (sub-form A) — the original case-sensitive bug:**

```rust
// Case-sensitive: only matches lowercase "value eq \""; any other casing silently no-ops
fn parse_member_filter(path: &str) -> Option<String> {
    if let Some(start) = path.find("value eq \"") {   // BUG: literal match, no case folding
        let start_idx = start.saturating_add(10);
        if let Some(rest) = path.get(start_idx..)
            && let Some(end) = rest.find('"')
        {
            return rest.get(..end).map(String::from);
        }
    }
    None
}
```

**Char-count remap (sub-form B) — the "fix" that still drifts for U+0130:**

```rust
// WRONG: char count from the folded string != char count from the original
// when a single original char folds to two chars (e.g. İ → i + combining dot)
fn parse_member_filter(path: &str) -> Option<String> {
    let lower = path.to_lowercase();
    let needle = "value eq \"";
    let lower_end = lower.find(needle)?.saturating_add(needle.len());

    let char_offset = lower.get(..lower_end)?.chars().count();          // measured in `lower`
    let orig_byte_pos = path.char_indices().nth(char_offset).map(|(i, _)| i)?; // applied to `path`
    let rest = path.get(orig_byte_pos..)?;                              // offset can land mid-value

    let end = rest.find('"')?;
    rest.get(..end).map(String::from)
}
// Input:  members[İ value eq "victim-user-id"]
// Output: Some("ictim-user-id")   ← first char truncated
```

The same char-count remap pattern exists in `parse_scim_filter` (`db/scim.rs:1000–1009`) and is a latent instance of sub-form B.

## Correct patterns

**Match the needle ASCII-case-insensitively against the original string (no fold, no remap):**

```rust
fn parse_member_filter(path: &str) -> Option<String> {
    let needle = b"value eq \"";
    let start = path
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))?
        .saturating_add(needle.len());

    let rest = path.get(start..)?;
    let end = rest.find('"')?;
    rest.get(..end).map(String::from)
}
```

This is safe because:
- The search and the result both operate on the same string.
- No offset is ever moved from a folded copy back to the original.
- Every matched byte is ASCII, so the resulting `start` is guaranteed to be a valid UTF-8 boundary.

**Alternatively, derive everything from the folded copy when the result is known ASCII:**

```rust
// Only safe when the value you extract is guaranteed to be ASCII-only.
let lower = input.to_lowercase();
let Some(pos) = lower.find("keyword") else { return None };
let extracted = lower.get(pos + "keyword".len()..)?; // use `lower`, not `input`
```

## Scope

All files in:

- `crates/vouch-server/src/handlers/scim/` — especially `groups.rs` (`parse_member_filter`) and `users.rs`
- `crates/vouch-server/src/db/scim.rs` — especially `parse_scim_filter` (lines 950–1019) which contains a live char-count remap
- Any future parser or filter function in the SCIM, OAuth, or HTTP handler layers that needs case-insensitive string matching followed by value extraction from user-supplied input
