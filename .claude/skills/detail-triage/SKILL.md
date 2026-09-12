---
name: detail-triage
description: Triage a batch of Detail bug issues and fix PRs — measure the trend, classify each finding as an instance or a class, review each fix for defects in the fix itself, and decide what merges versus what gets fixed as a class with a guardrail. Use when asked to "triage the Detail batch", "Detail opened a batch", "why is Detail volume rising", "classify Detail findings", or when a new batch of `[Detail Bug]` issues appears.
---

# Triage a Detail Batch

Detail scans the whole repository on each pass and files one issue per finding,
usually with a paired fix PR. Merging each PR on its own closes the instance and
leaves the pattern in place for the next pass to rediscover somewhere else. This
skill exists to break that loop: measure what is actually happening, separate
instances from classes, and make sure every class fix carries something that
prevents the class from coming back.

Work through the steps in order. Step 2 gates everything after it — nothing
merges before the classification table exists.

## Step 0: Know what you may not edit

`.claude/skills/detail-rules/` and `.claude/skills/detail-create-rules/` are
managed on the Detail side and synced down via `detail rules pull`. **Never edit
files in those directories by hand** — they are generated artifacts, and local
edits are overwritten on the next sync without ever reaching the scanner.

That is a restriction on authoring rule *text*, not on creating rules. New rules
are requested through the Detail CLI, which generates them for you — see step 5.

Everything under `.claude/skills/detail-triage/` is repo-owned and yours to
maintain.

## Step 1: Measure the batch and the trend

```bash
python3 .claude/skills/detail-triage/scripts/detail-stats.py
python3 .claude/skills/detail-triage/scripts/detail-stats.py --json   # for scripting
```

The script reads every Detail-authored issue through `gh`, extracts the
"Introduced in [#N] … on DATE" attribution from each body, and reports volume,
bug age, and keyword-clustered classes per detection month.

Read three things together:

- **median / p90 age** — how far back into history this pass reached.
- **`<30d`** — findings against code merged in the last month.
- **`from fix PR`** — findings attributed to one of Detail's *own* earlier fix
  PRs.

A climbing median with a flat `<30d` means Detail is working through backlog:
volume is high for a reason that no process change will fix, and the right
response is throughput. A climbing `<30d` means new code is generating findings
as fast as old code is cleaned up, and the right response is a guardrail. Say
which of the two you are looking at before proposing any remedy.

`from fix PR` is the one that decides how this batch gets merged. When it is
high, merging fix PRs as-is is feeding the next scan, and the loop only breaks
by making class decisions *before* merging. Part of the signal is mechanical —
as Detail's merged PR count grows, its commits are increasingly the last to
touch any given line — so confirm a spike by checking whether the finding is a
defect in the logic the fix *added* rather than merely in a file it touched.
The 2026-09-08 batch is the recorded worked example: all seven findings were
attributed to fix PRs merged two days earlier, and each was a defect in the
added logic (a stale timestamp in a retry the fix introduced, a zero-boundary
bypass of a cap the fix introduced, a residual gap in a window the fix
widened).

The class table is **keyword clustering over titles — directional, not
rigorous**. Titles overlap classes and a large share match none. Use it to spot
recurrence worth investigating; never quote its counts as fact.

Compare against `references/volume-log.md`, which holds the measured history.

## Step 2: Classify every open finding

For each open issue in the batch, establish three things and put them in one
table:

| column | what it means |
|---|---|
| class | which recurring pattern it belongs to, or "isolated" |
| live? | is the defect still present in current `main`? |
| siblings | other call sites sharing the pattern, found by reading the code |

**Verify "live?" against the tree, never against the issue body.** Detail
authors a batch from a snapshot, and that snapshot can predate a merge from the
same day. Worked example: issue #1284 quoted
`jiff::Timestamp::now().as_second()` in `handlers/oidc/authorize.rs`, but PR
#1274 had already replaced that call hours earlier. The finding was still real —
the whole-second truncation it described survived at line 1397 — but the
citation was stale, and a reviewer trusting the body would have reached the
wrong conclusion in either direction.

Finding the siblings is the actual work of this step, and it is what turns a
list of instances into a class. Prefer `codegraph_explore` or `ast-grep` over
ripgrep here: the question is structural ("every comparison that truncates a
timestamp before comparing"), not textual.

**The sibling hunt disqualifies classes as often as it confirms them, and that
is a result worth having.** Exclude test-only sites, and judge each sibling's
consequence rather than counting matches. Both apparent classes on 2026-09-11
collapsed under this:

- Blind read-then-write looked like six `store.update(` sites in `db/`. Five
  were test helpers (two documented as bypassing validation, three using
  `.unwrap()`), leaving one production instance — so the reported issue was
  nearly isolated and a refactor was not warranted.
- Fail-open on a DB read had three production sites, but one only affects what
  the UI displays and another fails in the safe direction, with the
  authoritative guard inside a transaction. Only the reported site had real
  consequence.

A class of three where two members are harmless is not a class. Say so, and
merge the instance.

Issues Detail filed **without** a paired fix PR belong in this table too. They
are usually the ones it judged too structural to auto-fix, which makes them the
strongest class candidates in the batch, not the weakest.

## Step 3: Decide instance versus class

Three or more open instances of one pattern makes this decision mandatory, not
optional. For each class pick one and record which:

- **Instance** — genuinely isolated. Merge Detail's PR as-is once green, per the
  standing strategy for bot PRs. No surrounding refactor.
- **Class** — one change that fixes every site found in step 2, per CLAUDE.md
  "fix the class, not the instance". Close Detail's individual PRs as superseded
  rather than merging them, and say so in each.

A class fix that lands without a guardrail will regress, so step 4 is part of
the same PR, not a follow-up.

## Step 4: Attach a guardrail to every class fix

Pick the strongest mechanism that fits, and be honest about what it does not
cover.

1. **A type whose invalid state cannot be constructed.** The strongest option:
   the wrong thing stops compiling. `ArrivalTime` (`crates/vouch-server/src/arrival.rs`)
   has no public constructor outside tests, so holding one is evidence it came
   from the middleware. The `Domain` newtype from #1272 does the same for parsed
   domains. Best fit whenever the class is "compared or stored a value that was
   never normalized".
2. **A clippy `disallowed_methods` entry** in `.clippy.toml`, as already exists
   for `jiff::Timestamp::now`. Cheap and real — `-D warnings` turns it into a CI
   failure — but it matches *a named function*, nothing more.
3. **A behavioral test** asserting the invariant across every site. Never a test
   that scans source text; the project rules that out explicitly.

**A guardrail can under-cover its class.** The ArrivalTime work fixed the clock
*source* everywhere and installed a lint for it, then #1284 landed against the
clock *precision* — `arrival.as_second().saturating_sub(...)` on one path while
its sibling compared full-precision `SignedDuration`. The lint could not see the
difference because it targets the constructor. When you pick a mechanism, write
down the part of the class it does not cover, and either add a second mechanism
or state the residue in the PR.

Verify the guardrail the way the project verifies tests: break the code, confirm
CI catches it, then fix it. A guardrail never observed failing is not known to
work.

## Step 5: Request a Detail rule for each confirmed class

This is the step that reduces future volume. A class the scanner knows about is
reported as a rule violation on the way in, rather than rediscovered instance by
instance for months.

**Request the rule; never write one.** `detail rules create` submits a request
and *Detail* generates the rule text. Hand-editing a rule file under
`.claude/skills/detail-rules/references/` is the thing that is forbidden — those
are generated artifacts and the next sync overwrites local edits.

Use the `detail-create-rules` skill. The evidence is already in the issues:
`detail-stats.py --json` emits an `open_bug_ids` map from issue number to the
`bug_<uuid>` in its body.

```bash
detail rules create --description "<the invariant, stated as a rule>" \
                    --bug-ids <bug_id1,bug_id2,...>
```

Then poll with `detail rules requests show <rcr_...>`, review each result with
`detail rules show <rule_id>`, pull with `detail rules pull <rule_id>`, and
commit the synced files as `chore(detail): …` — matching how `2673a121` and
`ccbcd1f8` landed.

A good rule states an invariant, not an incident. From the 2026-09-11 batch,
"an offset found in a lowercased string must not be mapped back into the
original by counting characters, because Unicode lowercasing is not
length-preserving" is a rule; "issue #1290 was fixed wrong" is not.

When a rule for the class **already exists and did not catch it**, say so in the
description and ask for refinement rather than adding a second overlapping rule.
Three rules already cover optimistic concurrency
(`optimistic-concurrency-required`,
`prefer-store-modify-over-blind-store-update`,
`use-store-modify-for-concurrent-updates`) and it is still the largest class,
which is evidence that more overlapping coverage is not the lever.

Note also that the `detail-rules` skill is wired into no CI job, git hook, or
Makefile target — it only runs when someone asks, so a rule that exists still
does not gate a merge. If the goal is to stop a class at the door, changing that
wiring is a separate decision to raise with the user rather than assume.

## Step 6: Review each fix for defects in the fix itself

This is the step that earns the triage. On the 2026-09-11 batch it found three
PRs that should not merge, two of which reintroduced the very class they were
fixing. Do not treat it as a merge checklist.

### Scope the reading first

Most of a Detail PR is tests. Split production from test additions so the batch
is tractable — on 2026-09-11 this took 7,500 added lines down to ~2,800 of
production code:

```bash
python3 .claude/skills/detail-triage/scripts/detail-stats.py --pr-diff-sizes 1303-1324
```

Read the production hunks. Read tests only to check that the assertion pins the
behavior the issue describes.

The split is by file path, so a PR reporting zero test lines has inline
`#[cfg(test)] mod tests` in the production file rather than no tests — treat
its production figure as an upper bound.

### The failure-mode checklist

The 2026-09-08 batch was seven findings, every one a defect in logic a previous
fix had *added*. So interrogate what the fix introduces, not just whether it
addresses the report:

- **A new retry** — does each attempt re-stamp time and re-read state, or does
  it capture once outside the loop? (#1256 was a stale timestamp in a retry
  #1229 added.)
- **A new cap or bound** — what happens at exactly zero, and at equality?
  (#1255 bypassed the cap #1236 added when the remaining lifetime was zero.)
- **A new window** — is there residual gap at either end? (#1254 was a ~1s
  remainder in the window #1238 widened.)
- **A new guard** — does it cover every call site, or only the reported one?
  Grep the codebase for the pattern, do not trust the diff's coverage.
- **A new normalizer or parser** — does it alter input it should leave alone?
- **A new error path** — does it swallow, and does that match how the adjacent
  code treats the same error?

### Check the fix against the class it fixes

When the bug is a parsing, normalization, or canonicalization defect, the fix is
written in the same idiom that produced it and tends to inherit the same blind
spot. Both blockers on 2026-09-11 were this:

- **#1312** lowercased the string, found an offset in it, then mapped that
  offset back into the original by counting chars — assuming lowercasing
  preserves char count. `İ` (U+0130) lowercases to two chars, so the extracted
  ID lost its first character. The fix for a silent-no-op bug silently no-ops.
- **#1321** stripped whitespace after any comma, including a comma escaped
  inside an attribute value, corrupting the value instead of the separator.

So: test the fix against the spec's own examples, and against neighbouring
inputs in the same class. RFC 4514 §4 supplied the counterexample for #1321
directly — `CN=James \"Jim\" Smith\, III,DC=example,DC=net`.

### Reproduce, do not argue

For a suspected defect in a pure function, extract the function body into a
scratch file and run it. It takes a minute and converts "this looks wrong" into
a confirmed blocker with output to paste into the review:

```bash
rustc -O -o /tmp/t /tmp/t.rs && /tmp/t   # the PR's function body, verbatim
```

A review comment saying "I think this mishandles Unicode" invites debate. One
showing `Some("ictim-user-id")` does not.

### Then the hygiene checks

- Confirm the spec citation matches the actual text — open the document under
  `specs/` and quote it; never accept the PR body's paraphrase.
- Confirm fixtures come from the shared helpers in
  `crates/vouch-server/src/test_utils.rs`, not hand-rolled `Create*Params`.
- Confirm no single-caller helpers were added.

### Merge mechanics

Read CI status fresh with `gh pr checks <n>` at the moment you decide. Do not
reuse a run ID captured earlier in the session — runs get superseded, and on
this batch an earlier failing run for #1312 had already been replaced by a
passing one, which I initially reported as a failure.

Enqueue with the GraphQL `enqueuePullRequest` mutation; `gh pr merge` does not
work with this repo's merge queue. After the batch lands, re-run `make lint` and
`make test` on `main` — branches touching disjoint files can still break each
other (#1131 removed a helper #1125 called, with zero file overlap).

## Step 7: Record the metric

Write the batch record to `.local/detail-triage-<YYYY-MM-DD>.md`: the
classification table, the review findings, and the decisions. `.local/` is
gitignored working memory and already holds prior records — **read the most
recent one before starting**. Doing so on 2026-09-11 surfaced a SAML
XML-comment truncation issue found outside Detail in August, which a check
against the tree confirmed was since fixed.

Then append this pass to `references/volume-log.md`: the monthly row, the
per-class counts, the self-caused share, and what was decided. The next run
reads it to tell a trend from a blip.

Success is **the `<30d` count and the per-class counts falling** over successive
batches. It is not an empty issue list — while Detail is still excavating
backlog, a high total is expected and says nothing about code quality going in.
