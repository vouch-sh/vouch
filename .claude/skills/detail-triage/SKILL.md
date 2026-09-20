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
- **`Detail PR` and `PR<=3d`** (per-batch table) — findings attributed to one of
  Detail's own fix PRs, and to any PR merged at most three days before
  detection, whoever wrote it. The same table counts Detail's fix PRs and its
  Dead Code PRs, which file no issue.

A climbing median with a flat `<30d` means Detail is working through backlog:
volume is high for a reason that no process change will fix, and the right
response is throughput. A climbing `<30d` means new code is generating findings
as fast as old code is cleaned up, and the right response is a guardrail. Say
which of the two you are looking at before proposing any remedy.

`PR<=3d` is the one that decides how this batch gets merged. When it is
high, merging fix PRs as-is is feeding the next scan, and the loop only breaks
by making class decisions *before* merging. Part of the signal is mechanical —
as Detail's merged PR count grows, its commits are increasingly the last to
touch any given line — so confirm a spike by checking whether the finding is a
defect in the logic the fix *added* rather than merely in a file it touched.
The 2026-09-08 batch is the recorded worked example: all seven findings were
attributed to fix PRs merged two days earlier, and each was a defect in the
added logic (a stale timestamp in a retry the fix introduced, a zero-boundary
bypass of a cap the fix introduced, a residual gap in a window the fix
widened). The human-authored case matters as much: on 2026-09-14 and
2026-09-15 every finding (3 of 3, then 6 of 6) was in a class fix we had merged
the day before, while the Detail-only column read 0 and 1.

The class table is **keyword clustering over titles — directional, not
rigorous**. Titles overlap classes and a large share match none. Use it to spot
recurrence worth investigating; never quote its counts as fact.

Compare against `references/volume-log.md`, which holds the measured history;
its batch table is the per-batch series to extend.

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

**Match against stated residue before hunting.** Read the residue and
open-decision sections of the last few records in `.local/`. A finding that
matches something a review already accepted is a residue recurrence, not a
surprise: on 2026-09-13, all three self-caused findings had been written down
the day before as residue or an open decision. Count it in the batch table. The
lever for a residue recurrence is fixing residue in the PR that left it, not a
new guardrail.

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

### Dead Code PRs

Detail also opens Dead Code PRs (branch `detail/dead-code/…`) that file no
issue. CI builds every workspace target, so the compiler proves most removals: a
function, impl, or constant that still had a caller would not build. Review the
removals the compiler cannot see:

- **A field on a persisted or wire-format struct** — a `DocumentType` document
  or a state-token payload. Old and new servers read the same rows during a
  rolling refresh, so a required field no code reads is still a contract with
  the previous release (rule `wire-format-compat-on-persisted-structs`). #1379
  on 2026-09-15 would have made every newly registered authenticator unreadable
  to old servers. Keep the field with `#[serde(default)]`, write it empty, and
  delete it a release later.
- **Index entries** — find the readers by field name. A write-only index entry
  is dead, and it is rarely alone: #1380 had six siblings.
- **Anything `fuzz/` uses** — that crate is outside the workspace and CI does
  not build it.
- **Unreachable branches kept on purpose** — check the knowledge base for
  defense-in-depth arms before accepting their deletion.

## Step 3: Decide instance versus class

**A Detail fix PR is a reviewed draft, never a merge candidate.** That is the
standing policy (set 2026-09-12), and it replaces the earlier "bot PRs merge
mostly as-is". Green CI, a detailed PR body, and a full test suite make a PR
look finished; step 6 exists because two of the 22 in the 2026-09-11 batch were
actively wrong under exactly that appearance.

The policy is not a claim that Detail writes bad fixes — measured over 811
merged PRs, its fixes are blamed by a later finding at roughly half the rate of
human PRs (3.6% vs 7.6% within 14 days of merge, 4.3% vs 8.7% within 30). The
point is that post-merge blame understates the defect rate, because the scanner
does not re-find everything it introduces. Review is what closes that gap, and
it is worth doing regardless of who wrote the fix.

Three or more open instances of one pattern makes this decision mandatory, not
optional. For each class pick one and record which:

- **Instance** — genuinely isolated. Merge Detail's PR once it has been through
  step 6 and is green. No surrounding refactor.
- **Class** — one change that fixes every site found in step 2, per CLAUDE.md
  "fix the class, not the instance". Close Detail's individual PRs as superseded
  rather than merging them, and say so in each.

**Never merge the instance PR for a finding that belongs to a class.** Merging
it closes the instance and erases the evidence that the class exists, so the
next pass rediscovers the same pattern at a different call site and the cycle
repeats. Of every rule here, this is the one that would have changed the most
outcomes historically.

**Settle contradictory findings together.** A batch can hold findings that pull
in opposite directions, or a fix that reverses a decision already on record.
#985 reverted a boundary Detail itself had chosen in #924. On 2026-09-15, #1385
asked for native clients holding a registered secret to be treated as public,
while #1381 and #1382 asked for them to be held to that secret, and #1392
restored code #1369 had deleted on purpose. Resolve the governing spec text or
recorded decision once — memory, the knowledge base, the PR that made the
decision — then dispose of the whole set against it.

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

**A class fix produces the next batch's findings.** Rule 6 of
`development-discipline.md` applies to the mechanism the fix introduces, not
only the one the issue reported. On 2026-09-14 a mechanism recorded the day
before had been applied to one of its two call sites; on 2026-09-15 the #1369
client-type refactor, itself the structural answer to three batches, drew five
findings within a day. Before merging a class fix, hunt siblings of the new type
or guard: every consumer of the old axis it replaces, and every caller it did
not touch.

Look past Rust handlers. On 2026-09-16 both misses in a two-PR class fix were
elsewhere: the rotation gate moved to the registered auth method, but the
Askama template still showed "Add Secret" by application type; and the OCSF
export learned a top-level `refusal` member, but the SCIM writer kept its
refusal inside a `details` string. When a fix changes who is eligible for an
action, check every template that renders the action. When it changes what a
stored record means, check every reader of the record: the admin UI, the OCSF
projection, and `docs/`.

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

**Read the generated rule against the merged tree before pulling it, and read
its correct-pattern section, not only its detection section.** Detail generates
from the bug-report snapshot, which predates the batch's own fixes, so a rule
can hold up as "already correct" the exact code the batch just replaced. That
is worse than no rule: it tells the next reviewer the defect is the model.
`rule_879e9e96` did this on 2026-09-19, presenting the pre-#1475 re-link write
as the pattern to follow hours after #1475 fixed it.

The remedy is a fresh `detail rules create` whose description names the stale
rule and spells out what it got wrong. Hand-editing the pulled file is
forbidden (step 0) and the next sync would overwrite it, and the CLI has
`create`, `pull`, `show`, `list` and `propose` — no refine verb.

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
behavior the issue describes. Before reporting a test as missing, search the
PR's test files for it: a diff filtered to production paths hides them, and
the 2026-09-16 review wrongly reported #1409 as lacking an mTLS test.

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
- **A new branch or match arm** — the inverse of the guard question: does
  anything *upstream* stop it being reached? A fix that adds an arm to an
  existing match inherits every early return above it. #1474 was the new
  `Unresolved` arm #1453 added, unreachable because a pre-existing
  `seen.insert(...) { continue; }` gate ran before the classifier. Read the
  enclosing function from its top, not from the diff hunk.
- **A new write to a field another path also writes** — do the two paths share
  an invariant, and does the new one carry it? #1472 was a token-only write
  #1469 added, correct under OCC on its own but with no check that the identity
  it was pairing the credential with had not changed.
- **A new normalizer or parser** — does it alter input it should leave alone?
- **A new error path** — does it swallow, and does that match how the adjacent
  code treats the same error?
- **A new server-side requirement** — does the shipped first-party client
  already satisfy it? #1308 added a grant check the released CLI failed,
  breaking WIF in v2026.9.3; #1388 required a client assertion `vouch enroll`
  never sent. Ship the client change first and enforce a release later.
- **A changed serde shape** — the rolling-deploy constraint under Dead Code PRs
  (step 2) applies to any field a fix removes, renames, or tightens.

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

A test whose input is derived from the code's own output cannot find a
disagreement with the real producer. Three batches fixed `canonicalize_dn`
against subject strings built from the certificate's own rendering, so an
RDN-order mismatch with OpenSSL's output could never surface; one string
captured verbatim from `openssl x509 -noout -subject` found it. When a function
exists to accept external input, require at least one fixture captured from the
external producer.

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
  `specs/` and quote it; never accept the PR body's paraphrase. Check the
  quote's scope as well as its strength: #1389 quoted a SHOULD from a section
  that governs only multiple-valued response types, and #985 quoted one sentence
  while omitting the next, which reversed its meaning.
- When trimming narrative comments, keep every spec citation (section and
  verbatim quote). Cut the history, not the requirement; fix an imprecise
  citation rather than deleting it.
- Confirm fixtures come from the shared helpers in
  `crates/vouch-server/src/test_utils.rs`, not hand-rolled `Create*Params`.
- Confirm no single-caller helpers were added.

### Merge mechanics

Read CI status fresh with `gh pr checks <n>` at the moment you decide. Do not
reuse a run ID captured earlier in the session — runs get superseded, and on
this batch an earlier failing run for #1312 had already been replaced by a
passing one, which I initially reported as a failure.

Before enqueueing, check that every commit is signed. Detail's follow-up
commits — a rustfmt or baseline fix pushed after its CI fails — have arrived
unsigned on #981, #1338, and #1379, and the merge queue rejects the whole
branch:

```bash
gh api repos/vouch-sh/vouch/pulls/<n>/commits \
  --jq '.[] | "\(.sha[0:8]) \(.commit.verification.verified)"'
```

Rebuild such a branch with signed commits rather than rewriting Detail's.

A queued PR's branch rejects pushes ("protected branch hook declined"). To
change one, dequeue it first with the GraphQL `dequeuePullRequest` mutation,
push, then run `gh pr merge <n> --auto` with no strategy flag: it enters the
queue when its checks pass, so nothing has to watch CI. If a green PR with
auto-merge armed still has no queue entry, enqueue it with the GraphQL
`enqueuePullRequest` mutation. When a wait is unavoidable, background
`gh pr checks <n> --watch` rather than sleeping.

After the batch lands, re-run `make lint` and `make test` on `main` — branches
touching disjoint files can still break each other (#1131 removed a helper
#1125 called, with zero file overlap).

## Step 7: Record the metric

Write the batch record to `.local/detail-triage-<YYYY-MM-DD>.md`: the
classification table, the review findings, and the decisions. `.local/` is
gitignored working memory and already holds prior records — **read the most
recent one before starting**. Doing so on 2026-09-11 surfaced a SAML
XML-comment truncation issue found outside Detail in August, which a check
against the tree confirmed was since fixed.

Give the record a **Residue** section listing everything the review accepted and
did not fix, each with the finding it would become. The next pass matches new
findings against it (step 2).

A gap the review notices is residue only after the user chooses to leave it.
"Not a regression" or "already true before this PR" is an observation, not a
decision: the 2026-09-15 review saw that the new rotation gate admitted
`private_key_jwt` and mTLS clients, called it pre-existing, and the next day's
batch filed it as #1405 and #1406 — including the token-endpoint acceptance the
review had not traced. Put such a gap on the decision list, and follow what it
admits to where that artifact is consumed before sizing it.

Then extend `references/volume-log.md`: add a row to the batch table, with the
counts from `detail-stats.py` and the judgement columns defined above the table,
and append a section with the monthly row, the classes, and what was decided.
The next run reads both to tell a trend from a blip.

Every few batches, read all the records in `.local/` together and fold any
lesson that has recurred into this skill. Otherwise the records are read one at
a time, and a lesson that lives only in a record is not applied.

Success is **the `<30d` count and the per-class counts falling** over successive
batches. It is not an empty issue list — while Detail is still excavating
backlog, a high total is expected and says nothing about code quality going in.
