---
name: bug-hunt
description: Hunt for bugs the way Detail does — pick targets from recent changes and their siblings, have parallel agents form hypotheses and prove each one with a test that fails on main, then dedup and report by class. Parallel agents share one checkout and one target/ so the workspace is compiled once. Use when asked to "hunt for bugs", "run a bug hunt", "scan recent changes for bugs", or "find bugs like Detail".
---

# Bug Hunt

Reading code produces suspects cheaply; running code is what makes a finding
precise. This skill does both: agents read in parallel and form hypotheses,
and a hypothesis becomes a finding only when a test proves it by failing on
unchanged `main`. No failing test, no report.

The disk budget shapes the whole design. **There is one checkout and one
`target/`.** Agents never get worktrees, because each worktree compiles the
workspace from scratch. Instead each prover writes its own integration-test
file, which Cargo compiles as a separate test binary on top of the one shared
build of the dependencies and `vouch-server`.

Work through the steps in order.

## Step 0: Set up the build once

1. Confirm the checkout is clean and on the commit under test:

   ```bash
   git status --short
   git rev-parse HEAD
   ```

   Record the SHA. Every finding is "fails at this SHA".

2. Fix the cargo environment for the whole run and write it down. Every agent
   uses **exactly** this command; any difference in profile env vars or
   features makes Cargo rebuild the workspace, and the old artifacts stay on
   disk beside the new ones.

   - If `target/debug` already holds a warm build, add no env vars — reuse it.
   - If there is no build yet, use `CARGO_PROFILE_DEV_DEBUG=line-tables-only`
     to cut debug info while keeping file:line backtraces.

   ```bash
   PROVE="cargo test -p vouch-tests --test"   # prefixed with the chosen env vars, if any
   ```

3. Check free space (`df -h .`), then warm the shared build by compiling the
   test crate's library and one existing small test:

   ```bash
   $PROVE negative_auth
   du -sh target
   ```

   Record the `du` figure in the report. Before each later build, stop the
   run if free space is below twice the size of one test binary
   (`ls -l target/debug/deps/negative_auth-*`). On a "no space left on device"
   error, stop — do not retry — and run the cleanup in step 6 first. In a
   cloud container with a per-session disk allowance, `df` can misreport; a
   failed write is the reliable signal.

## Step 1: Pick targets

Default window: commits on `main` in the last 7 days (or since the last
`.local/bug-hunt-*.md` record, whichever is later). The user may name a
different window, a path, or a PR.

```bash
git log --since='7 days ago' --no-merges --format='%h %s' main
git diff <oldest>^..HEAD --stat -- crates/
```

For each changed file, list the functions whose bodies changed. Those are the
**seeds**. Skip tests, generated files, `specs/`, and the Detail-managed
`.claude/skills/detail-rules/` directory.

Recent diffs are where Detail's recent batches were found: from 2026-09-12 to
09-17, every finding was in a PR merged in the three days before (see
`.claude/skills/detail-triage/references/volume-log.md`).

## Step 2: Expand each seed (parallel, read-only)

Spawn one Explore/general-purpose agent per group of related seeds (cap at
about 6 concurrent). These agents **only read** — no cargo, no edits. Each
returns, per seed:

- **Siblings** — code that must obey the same invariant as the seed:
  - the paired path: create vs update (RFC 7592 PUT, admin API, web form,
    SCIM PATCH *and* DELETE), issue vs revoke, login vs refresh;
  - the twin in another crate (`vouch-cli` vs `vouch-server` vs
    `vouch-common`), and the JSON-API twin of a web-UI handler;
  - every converter for the same error type (e.g. each `ServiceError` →
    response mapping, including catch-all `_ =>` arms);
  - Askama templates, the audit writer and OCSF projection, and `docs/` that
    describe the same behavior.
- **Invariants** — what the code claims or must satisfy: doc comments and
  inline comments on the seed, CLAUDE.md rules, `specs/requirements.tsv` rows
  for the area, and any `.claude/skills/detail-rules/references/*.md` rule
  whose scope covers it.

## Step 3: Form hypotheses (parallel, read-only)

For each seed plus its siblings, an agent proposes concrete ways it could be
wrong. Each hypothesis states the input, the expected behavior, the suspected
actual behavior, and the file:line it points at. Checklist, drawn from what
Detail has found in this repository:

- A check present on one path and missing on a sibling path.
- A fix applied to one call site and not the others (grep the whole
  workspace, especially the other crate).
- A comment or doc stating something the code does not do.
- A cap or limit wrong at zero or at equality.
- A retry that re-uses a timestamp captured before the loop.
- A time window with a gap at its edge, or two clock reads deciding one
  request (`ArrivalTime` exists for this).
- A normalizer that changes input it should leave alone (escapes, case of
  fields that are case-exact).
- A transient infrastructure failure mapped to a 4xx client error.
- A blind `store.get()` + `store.update()` instead of `store.modify()`.
- A secret in a plain `String` reachable through `Debug`.

Drop hypotheses that contradict a recorded decision (knowledge base
`decisions/`, a closed issue marked wontfix, a PR body that deliberately left
it). A hypothesis resting on a spec requirement must quote the sentence from
`specs/` with its section number; a paraphrase is not a basis for a finding.

Keep at most about 30 hypotheses per run, ranked by how bad the failure would
be if real. Precision beats volume.

## Step 4: Prove each hypothesis (parallel agents, one shared build)

Spawn one prover agent per hypothesis (cap at about 4 concurrent — builds
queue on Cargo's lock anyway). Give each the hypothesis, the recorded SHA, the
`$PROVE` command verbatim, and these rules:

1. **Write only** `crates/vouch-tests/tests/bughunt_<id>.rs`, where `<id>` is
   short and unique. Never edit `src/`, `Cargo.toml`, or anyone else's file —
   one change under `src/` rebuilds the workspace for every agent and means the
   test no longer runs against `main`. The pattern is gitignored.
2. Drive the server through the public surface: `vouch_tests::TestHarness`
   (`crates/vouch-tests/src/harness.rs`) builds the full router and has
   helpers for users, orgs, sessions, OAuth clients and SCIM tokens; the
   `vouch_server` modules that are `pub` (`db`, `services`, `crypto`, `infra`,
   `test_utils`) may be called directly. Handlers are `pub(crate)` — reach
   them over HTTP. Mirror an existing file in `crates/vouch-tests/tests/`.
3. Run only your own binary: `$PROVE bughunt_<id>`. If Cargo prints
   "Blocking waiting for file lock", that is another prover building; wait.
4. The test must **fail by assertion**, with a message that states the
   hypothesis. A compile error, a harness setup panic, or a timeout is not a
   proof — fix the test or report "not proven".
5. No wall-clock waits (CLAUDE.md "Tests never wait on the wall clock"). Use
   `ArrivalTime::for_test`, `TestVerification::Verified { auth_time }`, or the
   config override instead.
6. Run the failing test a second time. A result that changes between runs is
   "not proven (nondeterministic)".
7. When done, save the file's full text into the result, then delete the
   file and its binaries:

   ```bash
   rm -f crates/vouch-tests/tests/bughunt_<id>.rs target/debug/deps/bughunt_<id>-*
   ```

Each prover returns: id, verdict (`proven` / `not proven` / `disproven`), the
test text, the assertion output, and the seed file:line.

**Private-only bugs.** When a hypothesis can only be reached through a
`pub(crate)` item, the prover returns `needs in-crate test` with the test
text instead of editing `src/`. After every prover has finished, the
orchestrator puts all such tests in one temporary module, declares it in the
crate root, runs `cargo test -p vouch-server bughunt` once, records each
result, and then reverts both files (`git checkout -- crates/vouch-server/src/`
and `rm` the module). This is the only step that changes `src/`, and it runs
once, serially, at the end.

## Step 5: Dedup, classify, report

For every proven finding:

1. **Attribute it** — `git log -L` or `git blame` on the seed line to find the
   commit and PR that introduced it.
2. **Dedup** — search open issues (including `[Detail Bug]` issues) and
   knowledge-base `decisions/` for the same function and behavior. A match is
   "already known", not a new finding.
3. **Classify** — group findings that break the same invariant. Three or more
   in one group is a class; report it as one item listing every site, per the
   repo rule "fix the class, not the instance". A class that no
   `detail-rules` reference covers is a candidate for `detail rules create`
   (see the `detail-triage` skill, step 5).

Write the record to `.local/bug-hunt-<YYYY-MM-DD>.md`:

- run header: SHA, window, `$PROVE` command, `du -sh target` figure, counts
  (seeds, hypotheses, proven, not proven, disproven, already known);
- one section per class or isolated finding: the invariant, every site
  (file:line), the introducing commit, the failing test in full, and the
  assertion output;
- a short list of the not-proven hypotheses worth a human look, with the
  reason each could not be proven.

Do not file issues or open fix PRs on your own. Show the user the summary and
ask which findings to file or fix.

## Step 6: Clean up

```bash
rm -f crates/vouch-tests/tests/bughunt_*.rs target/debug/deps/bughunt_*
git status --short   # must show nothing from this run
```

Leave the warm shared build in place for the next run unless the user asks
for space back (`rm -rf target/debug/incremental` reclaims the incremental
cache without forcing a full rebuild of dependencies).
