---
name: Bug report
about: Something behaves differently from its spec, its docs, or a sibling code path
title: ""
labels: bug
---

<!--
Security vulnerabilities: do not open a public issue. Email security@vouch.sh
(see SECURITY.md).

Title: describe the problem, not the fix, e.g.
"scim: list filter on an unknown attribute returns every user".

Sections marked (optional) may be deleted. Keep the others, and write "None"
when one does not apply.
-->

## Summary

- **Context**: <!-- what the code is for: function, file, endpoint or command -->
- **Bug**: <!-- the defect, precisely: which check is missing, which value is wrong -->
- **Expected vs. actual**: <!-- expected behavior and where it comes from (spec, docs, a sibling path); then what happens instead -->
- **Impact**: <!-- who is affected and how: security, data, availability, audit. Say what limits it -->

## Affected sites (optional)

<!--
For a bug that recurs in several places. One checkbox per site, so a single
fix can cover them all:
- [ ] `path/to/file.rs:123` — one line on the defect
-->

## Reproduction Steps

1.
2.
3. Observe:

## Failing test (optional)

<!--
A test that fails on the commit named under Environment and passes once the
bug is fixed. Give the path to save it at and the command to run it, include
a positive control that passes, and paste the real output of the failing run.
-->

Save as `crates/…` and run:

```bash
cargo test -p <crate> --test <name>
```

```rust
```

Output:

```
```

## Expected Behavior

## Actual Behavior

## Code with the Bug (optional)

<!-- The smallest excerpt that shows the defect, with the defective lines marked. -->

```rust
```

## Specification (optional)

<!--
Each normative statement the report rests on: document, section, strength
(MUST / SHOULD / MAY), and a verbatim quote, e.g. from specs/rfc/rfcNNNN.txt.
Say so when the specs are silent.
-->

## Environment

- Version / commit:
- Crate / feature flags:
- Backend (if DB-related): SQLite / PostgreSQL / Aurora DSQL
- OS (CLI and agent):

## Logs / Evidence

## Suggested Fix (optional)

## History (optional)

<!-- The commit or PR that introduced the bug, and related or earlier issues. -->
