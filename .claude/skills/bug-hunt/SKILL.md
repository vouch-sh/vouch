---
name: bug-hunt
description: Hunt for bugs the way Detail does — pick targets from recent changes and their siblings, have parallel agents form hypotheses and prove each one with a test that fails on main, then dedup, report by class, and draft Detail-quality issues with a reproducing test. Parallel agents share one checkout and one target/ so the workspace is compiled once. Use when asked to "hunt for bugs", "run a bug hunt", "scan recent changes for bugs", "find bugs like Detail", or "file the bug-hunt findings".
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

   A fresh container can lack system libraries: `hidapi` (pulled in through
   `vouch-cli`) needs `libudev-dev` and `pkg-config` on Debian/Ubuntu. Install
   them and re-run the same command; the dependencies already compiled are
   kept.

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

**When in doubt, the spec decides.** Whenever the correct behavior is in
question, the oracle is the text in `specs/`, not the code, its comments, or
a local convention. A hypothesis resting on a spec requirement must quote the
sentence from `specs/` with its section number and its real strength (MUST,
SHOULD, MAY); a paraphrase is not a basis for a finding.

A recorded decision (knowledge base `decisions/`, a closed issue marked
wontfix, a PR body that deliberately left it) drops a hypothesis only when
the spec is silent or permits the recorded behavior. When a recorded decision
contradicts a MUST or MUST NOT, keep the hypothesis and mark it "contradicts
recorded decision <link>": the spec outranks the decision, including a merged
PR (`.claude/rules/specs-are-source-of-truth.md`).

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
   hypothesis. When the expected behavior comes from a spec, the test asserts
   what the spec requires and cites it above the test (repo convention:
   section number plus the quoted sentence). A compile error, a harness setup panic, or a timeout is not a
   proof — fix the test or report "not proven".
5. No wall-clock waits (CLAUDE.md "Tests never wait on the wall clock"). Use
   `ArrivalTime::for_test`, `TestVerification::Verified { auth_time }`, or the
   config override instead.
6. Run the failing test a second time. A result that changes between runs is
   "not proven (nondeterministic)".
7. When done, keep the evidence the issue in step 6 is built from, then
   delete the file and its binaries. Save the test verbatim, and the output
   of the failing run exactly as cargo printed it (trim only unrelated
   lines), under the run's record directory:

   ```bash
   R=.local/bug-hunt-<YYYY-MM-DD>/tests
   mkdir -p $R && cp crates/vouch-tests/tests/bughunt_<id>.rs $R/
   # the failing run's output, from the terminal, into $R/bughunt_<id>.out
   rm -f crates/vouch-tests/tests/bughunt_<id>.rs target/debug/deps/bughunt_<id>-*
   ```

Each prover returns: id, verdict (`proven` / `not proven` / `disproven`), the
test text, the assertion output, and the seed file:line.

**Live server.** Some hypotheses are proven most directly against a running
server: a real TLS client against the mTLS listener, a row state that no
public API produces (a legacy duplicate, a corrupted document), or a race set
up by editing the database between two requests. For those, the prover runs
its own server instead of writing a test:

1. The orchestrator builds the binary once, with the same env vars, the same
   feature set as `vouch-tests`, and **`--profile test`**, so it reuses the
   shared build. A plain `cargo build` uses the `dev` profile and recompiles
   the dependencies into a second copy on disk.

   ```bash
   CARGO_PROFILE_DEV_DEBUG=line-tables-only cargo build --profile test \
     -p vouch-server --features test-utils --bin vouch-server
   ```

2. Each prover starts `target/debug/vouch-server` on its own loopback port
   with its own database under `.local/bughunt/<id>/`. No IdP and no
   encryption key are needed: certification test mode
   (`VOUCH_CERTIFICATION_TEST_TOKEN`) waives the IdP requirement and enables
   the `/certification/complete-login` bypass. It also disables rate limiting,
   so bind to `127.0.0.1` only and never point it at shared infrastructure.

   ```bash
   VOUCH_RP_ID=localhost VOUCH_LISTEN_ADDR=127.0.0.1:<port> \
   VOUCH_JWT_SECRET=<random, 32+ chars> \
   VOUCH_CERTIFICATION_TEST_TOKEN=<random> \
   VOUCH_DATABASE_URL="sqlite:.local/bughunt/<id>/vouch.db?mode=rwc" \
     target/debug/vouch-server > .local/bughunt/<id>/server.log 2>&1 &
   ```

   Set `VOUCH_TLS_CERT` / `VOUCH_TLS_KEY` (base64 PEM, self-signed is fine)
   when the hypothesis needs HTTPS or the mTLS listener
   (`VOUCH_MTLS_PORT`). In TLS mode the server binds `[::]:443`, `[::]:80`
   and `[::]:<mtls port>`, so it will not start in a container without IPv6;
   there, prove mTLS behavior with an integration test that injects the
   client certificate (`test_utils::http_post_form_with_cert`), which is the
   same input the listener hands the handler.
3. Without an encryption key, documents are plain JSON in the `documents`
   table's `data` column. Seed or corrupt rows with Python's `sqlite3`
   module (the `sqlite3` CLI may be absent). The server caches sessions and
   some documents, so restart it after an edit unless the edit is meant to
   race the cache.
4. The proof is a script: the exact requests (`curl`) and database edits,
   with the responses that show the defect. It must reproduce on a second run
   from a fresh database, the same bar as a failing test. Save the script
   and its output in the result, then stop the server and delete
   `.local/bughunt/<id>/`.
5. Stop a server by its PID (`kill $(cat .local/bughunt/<id>/pid)`), never
   with `pkill -f`: the pattern also matches, and kills, the shell running
   the command.

**Private-only bugs.** When a hypothesis can only be reached through a
`pub(crate)` item, the prover returns `needs in-crate test` with the test
text instead of editing `src/`. After every prover has finished, the
orchestrator puts all such tests in one temporary module
(`crates/<crate>/src/bughunt_tests.rs`, gitignored), declares it in the
crate root, runs `cargo test -p vouch-server bughunt` once, records each
result, and then reverts both files (`git checkout -- crates/vouch-server/src/`
and `rm` the module). This is the only step that changes `src/`, and it runs
once, serially, at the end.

## Step 5: Dedup, classify, report

For every proven finding:

1. **Attribute it** — `git log -L` or `git blame` on the seed line to find the
   commit and PR that introduced it. Check `git rev-parse
   --is-shallow-repository` first: on a shallow clone, blame assigns every
   older line to the clone's boundary commit. Deepen it
   (`git fetch --deepen=3000 origin main`) before attributing.
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

Show the user the summary, then continue to step 6. Do not open fix PRs from
this skill.

## Step 6: Draft and file issues

Every issue is built from the evidence the run produced, not rewritten from
memory. A reader must be able to reproduce the bug from the issue alone:
paste the test into the named path, run the named command, and see the named
failure. The template is `references/issue-template.md`; follow it section by
section.

### Decide the grouping

- **One issue per class.** Findings that break the same invariant (step 5's
  classification, three or more sites) become one issue. It has a checklist
  with one item per site, and a subsection for each site with its own code,
  test, and output. The repo policy is to fix a class in one change with a
  guardrail. One issue per site would invite point fixes that leave siblings
  behind.
- **One issue per isolated finding.** A finding that shares its invariant
  with fewer than two others gets its own issue. Cross-link issues that share
  a root cause.
- **Security findings do not go in a public issue first.** Check the
  repository's visibility (`gh repo view --json visibility` or the GitHub
  tools). If it is public, and a finding lets someone gain access, credentials, or
  another tenant's data, draft it the same way but do not file it. Ask the user
  whether to open a private security advisory
  (`gh api -X POST repos/<owner>/<repo>/security-advisories`) or to fix first
  and file afterwards. Pull those sites out of any class issue and link to
  them by title only.

### Draft

Write one Markdown file per issue under
`.local/bug-hunt-<YYYY-MM-DD>/issues/NN-<id>.md`, with the title on the first
line. Checks before a draft is final:

- The failing test is complete and compiles as written, at the path the
  issue names. It includes its positive control. It is copied from
  `tests/bughunt_<id>.rs`, not retyped.
- The output block is the real output from the run, not a paraphrase.
- Every normative claim quotes `specs/` verbatim with its section and
  strength (MUST / SHOULD / MAY). A converted file under `specs/w3c/`,
  `specs/fido/` or `specs/oasis/` is marked as such until the quote is
  checked against its source URL.
- A finding that contradicts a recorded decision says so and links it. The
  spec outranks the decision.
- No internal review labels (CLAUDE.md "What NOT to Do" #11). Run
  `rg -n '\b([A-Z]{1,4}[0-9]{1,2}|GAP[0-9]+)\b'` over the drafts.

### File

Filing is outward-facing, so show the user the list of titles, the grouping,
and any held-back security drafts, and file only what they approve. Then,
for each approved draft:

```bash
gh issue create --repo <owner>/<repo> --title "<first line>" \
  --body-file <draft without the title line> --label bug --label <component>
```

(or the GitHub `issue_write` tool). Component labels are `server`, `cli`,
`agent`, per `.claude/rules/commits-and-issues.md`. Record each issue number
next to its finding in `.local/bug-hunt-<YYYY-MM-DD>.md`. Future runs match
new hypotheses against these issues in step 5's dedup.

## Step 7: Clean up

```bash
rm -f crates/vouch-tests/tests/bughunt_*.rs target/debug/deps/bughunt_*
git status --short   # must show nothing from this run
```

Leave the warm shared build in place for the next run unless the user asks
for space back (`rm -rf target/debug/incremental` reclaims the incremental
cache without forcing a full rebuild of dependencies).
