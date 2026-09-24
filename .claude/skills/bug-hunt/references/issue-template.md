# Filling the bug report template from a bug hunt

Every issue uses the repository's template, `.github/ISSUE_TEMPLATE/bug_report.md`,
the same one a person gets from the GitHub issue form. This file says how to
fill each of its sections from the run's evidence in `.local/bug-hunt-<date>/`,
to the standard of Detail's issues (e.g. vouch#1440, vouch#1447). A bug hunt
fills **every** optional section: it always has the test, the code, and the
history. Nothing is written from memory.

## Title

Repo convention: describe the problem, not the fix; lowercase, no trailing
period; lead with the subsystem.

```
<subsystem>: <what goes wrong, in the user's or operator's terms>
```

Examples: `oidc mtls: tls_client_auth accepts a self-signed certificate with a
matching subject DN`, `scim: list filters return every user or match nothing`
(a class).

## First lines of the body

Before the template's first heading, add these two lines. They record where the
issue came from and give the introducing change, in the same form Detail uses:

```
Found by the bug-hunt skill on <YYYY-MM-DD> against `main` at `<sha>`.

Introduced in [#<pr>](https://github.com/<owner>/<repo>/pull/<pr>) on <Mon DD, YYYY>
```

For a class, write "Introduced in" once for each site under History instead.

## Sections

| Template section | Filled from |
|---|---|
| **Summary** | The hypothesis and the verdict. Context names the function and file. Expected vs. actual names its source: a spec, an operator doc, or the sibling path that does it right. Impact is honest about limits, e.g. "masked in production because…". |
| **Affected sites** | A class only (step 5's grouping): one checkbox per site with `file:line` and a one-line defect. A single finding writes "None: single site". |
| **Reproduction Steps** | The manual path a person running the server or CLI would take: real requests with placeholders (`curl`), config, or CLI commands, ending in "Observe: <the exact response or state>". For a live-server proof, this is the proof script in prose. |
| **Failing test** | The test **verbatim** from `tests/bughunt_<id>.rs`, including its positive control, with the path to save it at, the exact command, and the **real** output from `tests/bughunt_<id>.out`. In-crate tests say which module file to add and which `cargo test -p <crate> --lib <filter>` to run. A live-server proof gives the full script and its output here. Add one sentence: the positive control passes, so the failure is the defect and not the setup. |
| **Expected / Actual Behavior** | One short paragraph each, matching the test's assertion. |
| **Code with the Bug** | The smallest excerpt from the tree at `<sha>` that shows the defect. Mark each defective line with `// <-- BUG 🔴 <why>`. Then a short explanation, one bullet per step from input to wrong result. Then **Codebase inconsistency**: the sibling path, doc comment or operator doc that already does or promises the right thing, with an excerpt. A claim about how the sibling *behaves* (for example "the applications API returns 401") needs a comparison test that ran and is shown under Failing test. Otherwise describe only what its code says. |
| **Specification** | Each normative statement: document, section, strength (MUST / SHOULD / MAY), a verbatim quote, and the `specs/` path. Mark a converted file as unverified until it is checked against its source URL. If the specs are silent, say so. If the finding contradicts a recorded decision, link it, say the spec outranks it (`.claude/rules/specs-are-source-of-truth.md`), and say which part of the decision still holds. |
| **Environment** | Commit `<sha>`, the crate, the feature flags the test used (`test-utils`), the backend the test ran on (usually SQLite in-memory, followed by "only SQLite was run"), and the OS for CLI and agent findings. Do not predict other backends. |
| **Logs / Evidence** | Anything beyond the test output: server log lines, the database state before and after, a second backend. "None beyond the failing test" otherwise. |
| **Suggested Fix** | The change at the layer where the invariant belongs, plus the guardrail that stops the next sibling (a shared helper or type, a single chokepoint, a test over every path), naming the siblings it covers. End with: the failing test becomes the regression test; it passes after the fix and fails if the fix is reverted. |
| **History** | A regression claim ("the old code accepted this") needs a run against the older commit. Otherwise state only what the commits changed. From `git log -L` / blame on full history: the introducing commit and PR, what that change was doing, why the defect slipped in, later commits that kept it, and closed issues that fixed a narrower sibling (e.g. "#1440 fixed the same gap in `POST /logout` but not `/oauth/revoke`"). |

## A class issue

Same template, with these differences:

- **Summary** names the one invariant every site breaks and where it is
  stated, the site count, and the worst site's impact first.
- **Affected sites** lists every site, and every site listed has its own
  proof under Failing test. A site with the same shape but no proof is left
  out and recorded as not proven.
- **Failing test** has one subsection per site (`### <site>`), each with its own test,
  command and output. Several sites may share one test file.
- **Code with the Bug** has one excerpt per site.
- **Suggested Fix** is one change covering every site, plus the guardrail that
  makes a new site fail to compile or fail a test. List any site left out on
  purpose, and why.

## Security findings

Use the same template. `SECURITY.md` says not to open public issues for
vulnerabilities, so a security draft is filed only after the user confirms it
by name (see step 6 in `SKILL.md`). Until then it stays in `.local/`.
