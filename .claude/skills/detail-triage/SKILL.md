---
name: detail-triage
description: Triage a batch of Detail bug issues and fix PRs — measure the trend, classify each finding as an instance or a class, decide what gets merged versus fixed as a class with a guardrail, and push confirmed classes back upstream as Detail rules. Use when asked to "triage the Detail batch", "Detail opened a batch", "why is Detail volume rising", "classify Detail findings", or when a new batch of `[Detail Bug]` issues appears.
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
files in those directories.** Local edits are overwritten on the next sync and
never reach the scanner. Rule changes go upstream through the Detail CLI — see
step 5.

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

## Step 5: Push confirmed classes upstream as Detail rules

This is the step that reduces future volume. A class the scanner knows about
gets reported as a rule violation on the way in, rather than rediscovered
instance by instance for months.

Use the `detail-create-rules` skill. The evidence to submit is already in the
issues — `detail-stats.py --json` emits an `open_bug_ids` map of issue number to
the `bug_<uuid>` from its body:

```bash
detail rules create --description "<the invariant, stated as a rule>" \
                    --bug-ids <bug_id1,bug_id2,...>
```

Then poll with `detail rules requests show <rcr_...>`, review with `detail rules
show <rule_id>`, pull with `detail rules pull <rule_id>`, and commit the synced
files as `chore(detail): …` — matching how `2673a121` and `ccbcd1f8` landed.

When a rule for the class **already exists and did not catch it**, say that in
the description and ask for refinement. Do not write a second overlapping rule:
three rules already cover optimistic concurrency
(`optimistic-concurrency-required`, `prefer-store-modify-over-blind-store-update`,
`use-store-modify-for-concurrent-updates`) and it is still the largest class,
which is evidence that more overlapping rules is not the lever.

Note also that the `detail-rules` skill is not wired into CI, any git hook, or
the Makefile — it only runs when someone asks. A rule that exists still does not
gate a merge. If the goal is to stop a class at the door, changing that wiring
is a separate decision worth raising with the user rather than assuming.

## Step 6: Merge what survived

For each PR being merged as an instance:

- Read the diff against its issue. Confirm the spec citation matches the actual
  text — open the document under `specs/` and quote it; do not accept the PR
  body's paraphrase.
- Confirm it builds fixtures through the shared helpers in
  `crates/vouch-server/src/test_utils.rs` rather than hand-rolled `Create*Params`
  literals.
- Confirm it adds no single-caller helpers.
- Enqueue with the GraphQL `enqueuePullRequest` mutation. `gh pr merge` does not
  work with this repo's merge queue.

After the batch lands, re-run `make lint` and `make test` on `main`. Branches
touching disjoint files can still break each other — #1131 removed a helper
#1125 called, with zero file overlap between them.

## Step 7: Record the metric

Append this pass to `references/volume-log.md`: the monthly row, the per-class
counts, and what was decided (merged as instances, fixed as classes, rules
requested). The next run reads it to tell a trend from a blip.

Success is **the `<30d` count and the per-class counts falling** over successive
batches. It is not an empty issue list — while Detail is still excavating
backlog, a high total is expected and says nothing about code quality going in.
