# Bug-hunt issue template

Modeled on Detail's issue format (for example vouch#1440, vouch#1447), plus the
reproduction and failing test Detail usually leaves out. Keep every section. Write
"None" rather than dropping a section that does not apply. Everything in `<…>`
is filled from the run's evidence (`.local/bug-hunt-<date>/`), never from
memory.

## Title

```
[Bug Hunt] <Area>: <what goes wrong, in the user's or operator's terms>
```

Describe the problem, not the fix (`.claude/rules/commits-and-issues.md`).
`<Area>` is the subsystem as a reader would name it: `OIDC mTLS`, `SCIM`,
`GitHub App`, `Agent IPC`, `CLI`. Example:
`[Bug Hunt] OIDC mTLS: tls_client_auth accepts a self-signed certificate with a matching subject DN`.

## Body: single finding

````markdown
# Bug Hunt Report

Found by the `bug-hunt` skill on <YYYY-MM-DD> against `main` at `<sha>`.

Introduced in [#<pr>](https://github.com/<owner>/<repo>/pull/<pr>) by @<author> on <Mon DD, YYYY>

# Summary
- **Context**: <what the code is for, one sentence, naming the function and file>
- **Bug**: <the defect, precisely: which check is missing or which value is wrong>
- **Actual vs. expected**: <expected behavior, with its source (spec, doc, sibling path)>; instead <actual behavior>
- **Impact**: <who is affected and how: security, data, availability, audit. Say what limits it>

# Code with Bug

`<path>`, `<function>`:

```rust
<the smallest excerpt that shows the defect, copied from the tree at <sha>>
<mark each defective line with a trailing comment:  // <-- BUG 🔴 <why>>
```

# Explanation
- <step-by-step reasoning from input to wrong output, one bullet per step>

## Codebase Inconsistency
<the sibling path, doc comment, or operator doc that already does or promises
the right thing, with its path and a short excerpt. "None" if there is none.>

## Specification
<Each normative statement the finding rests on: document, section, strength
(MUST / SHOULD / MAY), and a verbatim quote from `specs/`, with the file
path. Mark a converted file as unverified until checked against its source
URL. "The specs do not address this" when that is the case; then the expected
behavior comes from the codebase inconsistency above.>

<If the finding contradicts a recorded decision: "This contradicts
<decision link>. The spec outranks it (.claude/rules/specs-are-source-of-truth.md)."
Say which part of the decision still holds.>

# Reproduction

## Failing test

Save as `crates/vouch-tests/tests/<name>.rs` and run:

```bash
cargo test -p vouch-tests --test <name>
```

```rust
<the complete test file, verbatim from .local/bug-hunt-<date>/tests/, including its positive control>
```

Output at `<sha>`:

```
<the real cargo output of the failing run: the test names with ok/FAILED,
the panic message, and the result line>
```

The positive control `<control test name>` passes. It shows the path is
exercised and the failure is the defect, not the setup.

<For an in-crate test: "Add as a `#[cfg(test)]` module in
`crates/<crate>/src/…` and run `cargo test -p <crate> --lib <filter>`".
For a live-server proof: the full script, the environment it needs,
and its output, in place of the test.>

## Manual reproduction
1. <shortest sequence of real requests or commands that shows the bug to someone
   running the server or CLI, e.g. curl calls with placeholders>
2. Observe: <the exact response or state that shows it>

# Exploit Scenario
<Security findings only. Numbered steps from the attacker's starting position to
the outcome, stating what the attacker needs. "None: not a security issue"
otherwise.>

# Recommended Fix
- <the change, at the layer where the invariant belongs>
- <the guardrail that stops the next sibling: a shared helper or type, a single
  chokepoint, or a test over every path. Say which siblings it covers>

The failing test above becomes the regression test: it must pass after the
fix, and fail again if the fix is reverted.

# History
<from `git log -L` / blame on full history: the commit that introduced it, what
that change was doing, why the defect slipped in, and any later commits that
kept it. Link sibling issues that were closed with a narrower fix.>
````

## Body: class issue

Same header, then:

````markdown
# Summary
- **Invariant**: <the one rule every site breaks, and where it is stated>
- **Sites**: <N> (<list of ids>)
- **Impact**: <worst site first>

# Sites

- [ ] <site 1: file:line, one line on the defect>
- [ ] <site 2 …>

## <Site 1 title>
<"Code with Bug", "Explanation", "Failing test", "Output" subsections as in
the single-finding body, for this site>

## <Site 2 title>
…

# Specification
<as above, once for the shared invariant>

# Recommended Fix
<one change that fixes every site, plus the guardrail that makes the next site
fail to compile or fail a test. List any site deliberately left out and why.>

# History
<per site, one line each: introducing commit and PR>
````
