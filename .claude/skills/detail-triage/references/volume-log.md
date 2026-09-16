# Detail Volume Log

Measured history of Detail's findings, so a later run can tell a trend from a
blip. Add a row to the batch table and append one section per triage pass.
Counted figures come from `scripts/detail-stats.py`; do not hand-edit them. The
judgement columns come from the batch's record in `.local/`.

## Batch table

| column | source | meaning |
|---|---|---|
| issues, fix PRs, dead-code PRs | script | what Detail opened on the detection date |
| Detail PR | script | findings blamed on one of Detail's own PRs |
| PR≤3d | script | findings blamed on any PR merged at most 3 days before detection, ours included |
| not as written | record | PRs that needed changes, were superseded, or were closed after review |
| dispositions | record | what happened to the batch's PRs |
| residue | record | findings that match residue or an open decision in an earlier record |
| rules | record | Detail rules requested for the batch's classes, and whether synced |

| batch | issues | fix PRs | dead-code PRs | Detail PR | PR≤3d | not as written | dispositions | residue | rules |
|---|---|---|---|---|---|---|---|---|---|
| 2026-08-20 | 12 | 11 | 0 | 0 | 0 | 10 of 11 | not recorded | not recorded | 0 |
| 2026-09-11 | 24 | 22 | 0 | 2 | 0 | 3 of 22 | all merged; #1312 and #1321 amended first | none (first record) | `no-case-fold-offset-remap`, synced #1327 |
| 2026-09-12 | 8 | 8 | 0 | 4 | 8 | 5 of 8 | 3 merged as-is, 2 amended, 3 closed; class PRs #1346, #1347 | not checked | `use-arrival-time-for-request-deciding-expiry`, synced #1349 |
| 2026-09-13 | 5 | 1 | 0 | 3 | 5 | 1 of 1 | 1 superseded; class PRs #1356–#1359; #1352 wontfix | 3 of 5 | 0 |
| 2026-09-14 | 3 | 3 | 0 | 0 | 3 | 3 of 3 | 3 amended, merged | 1 of 3 | 0 |
| 2026-09-15 | 6 | 6 | 7 | 1 | 6 | 6 of 6 fix, 2 of 7 dead-code | dead-code: 5 merged, 2 superseded (#1393, #1394); fix: 3 amended, 1 superseded (#1396), 2 closed | 1 of 6 | `wire-format-compat-on-persisted-structs`, synced #1395 |
| 2026-09-16 | 4 | 3 | 0 | 2 | 4 | 3 of 3 | 3 amended, merged; #1406 fixed by #1409; siblings in `fix/secret-ui-and-scim-refusal` | 2 of 4 | client-type rule requested (`rcr_3b87ceaa…`), not synced |

Batches before 2026-08-20 have no record, so only their counted columns exist:
run the script. `escape-unaware-delimiter-normalization` exists on Detail's side
(created 2026-09-12) and has never been synced into this repository.

**Reading:** from 2026-09-12 on, PR≤3d equals the issue count in every batch —
every finding was in something merged in the previous three days — while the
Detail-only column never did. And review changed or rejected most of what
arrived in every recorded batch except 2026-09-11, so the batch's outcome is
decided in review, not by Detail's PRs.

## 2026-09-11 — baseline

259 issues, 2026-04-15 through 2026-09-11.

| month | n | no attr | median age | p90 age | <30d | >90d |
|-------|---|---------|-----------|---------|------|------|
| 2026-04 | 19 | 6 | 41 | 74 | 3 | 0 |
| 2026-05 | 23 | 3 | 53 | 110 | 8 | 5 |
| 2026-06 | 33 | 3 | 6 | 116 | 19 | 8 |
| 2026-07 | 48 | 3 | 132 | 156 | 13 | 30 |
| 2026-08 | 69 | 6 | 152 | 187 | 23 | 40 |
| 2026-09 (11 days) | 67 | 7 | 90 | 194 | 25 | 30 |

Ages are in days between the "Introduced in" attribution and the detection
date. "no attr" counts issues whose body carries no attribution line.

**Reading:** both drivers are active at once. The p90 age climbs every month
without exception (74 → 194), so Detail is reaching progressively further back
through history — backlog excavation that throughput, not process, addresses.
At the same time `<30d` has risen from 3 to 25, so recently merged code is
generating findings at a rate that has not improved since June. The first
number explains the volume; the second is the one to drive down.

### Classes (keyword clustering over titles — directional, not rigorous)

| class | total | 04 | 05 | 06 | 07 | 08 | 09 |
|-------|-------|----|----|----|----|----|----|
| concurrency/lost-update | 34 | 2 | 6 | 4 | 5 | 8 | 9 |
| authz gap | 34 | 6 | 5 | 2 | 5 | 7 | 9 |
| incomplete revocation | 27 | 6 | 0 | 3 | 0 | 6 | 12 |
| string canonicalization | 22 | 0 | 1 | 2 | 4 | 5 | 10 |
| time/clock boundary | 15 | 1 | 0 | 1 | 1 | 4 | 8 |
| fail-open error path | 15 | 0 | 1 | 1 | 4 | 5 | 4 |
| missing audit event | 12 | 0 | 1 | 1 | 1 | 6 | 3 |
| metadata vs behavior | 11 | 0 | 0 | 2 | 2 | 2 | 5 |
| stale-cache invalidation | 10 | 0 | 2 | 0 | 2 | 2 | 4 |

114 of 259 issues matched no class. Clusters overlap, so the column does not
sum to the monthly total.

Every class is at or near its monthly peak in September. Concurrency is the
largest and is already covered by three hosted rules
(`optimistic-concurrency-required`,
`prefer-store-modify-over-blind-store-update`,
`use-store-modify-for-concurrent-updates`), which is the clearest evidence in
this table that adding overlapping rules is not the lever — the `detail-rules`
skill is wired into no CI job, git hook, or Makefile target, so no rule gates a
merge.

### Findings introduced by Detail's own fix PRs

| batch | issues | attributed | from a fix PR |
|-------|--------|-----------|---------------|
| 2026-04-15 → 2026-08-29 (14 batches) | 151 | 129 | 0 |
| 2026-08-31 | 9 | 9 | 8 |
| 2026-09-02 | 5 | 5 | 4 |
| 2026-09-06 | 27 | 23 | 1 |
| 2026-09-08 | 7 | 7 | 7 |
| 2026-09-11 | 24 | 21 | 2 |

Zero for four and a half months, then a sudden onset at the end of August. The
2026-09-08 batch is the worked example the skill cites: every finding was
attributed to a fix PR merged two days earlier, and each was a defect in the
logic the fix added — #1256 ← #1229 (stale timestamp in the new OCC retry),
#1255 ← #1236 (zero-boundary bypass of the new subject-TTL cap), #1254 ← #1238
(residual gap in the widened DPoP JTI window).

Part of the rise is mechanical: Detail has merged 100+ PRs since early August,
so its commits are increasingly the last to touch any line. That cannot explain
the 09-08 cases, which are bugs in the added logic itself.

### Fix quality, Detail vs human (2026-09-12)

How often a merged PR is later blamed by a Detail finding, counting only PRs
with the full window of exposure since merge
(`detail-stats.py --fix-defect-rate 2026-09-12`):

| window | Detail PRs | blamed | human PRs | blamed |
|--------|-----------|--------|-----------|--------|
| 14 days | 167 | 3.6% | 511 | 7.6% |
| 30 days | 139 | 4.3% | 438 | 8.7% |
| 60 days | 75 | 0.0% | 371 | 10.2% |

The 60-day row is small-sample for Detail and covers only PRs merged before
self-attribution began, so it should not be leaned on.

Detail's fixes are blamed at roughly half the human rate. Not like-for-like —
Detail PRs are small targeted fixes, human PRs include feature work — but it
is strong enough to settle the question: auto-fixing is not a net source of
defects, and disabling it would move the work to authors with a higher
observed rate.

What the number does *not* capture: review of the 2026-09-11 batch found real
defects in 3 of 22 (14%), well above the 4.3% later-blame rate, because the
scanner does not re-find everything it introduces. That gap is the entire
argument for the disposition policy below.

**Policy set 2026-09-12:** auto-fixing stays enabled; a Detail PR is a
reviewed draft, not a merge candidate; and the instance PR for any finding
belonging to a class of three or more is never merged, because merging it
erases the evidence that the class exists.

### Batch under triage

Issues #1279–#1302 (24) and fix PRs #1303–#1324 (22), all opened between
22:47 and 22:54 UTC on 2026-09-11. #1283 and #1285 arrived without a fix PR;
both are concurrency-class. #1312 failed Unit Tests on linux and macOS on
arrival. #1303 is the size outlier at 968 added lines across 20 files.

Decisions: recorded in the next section once step 3 completes.

## 2026-09-12

Issues #1330–#1337 (8), fix PRs #1338–#1345 (8), 1:1. Full record in
`.local/detail-triage-2026-09-12.md`.

| month | n | median age | p90 | <30d | >90d |
|-------|---|-----------|-----|------|------|
| 2026-07 | 48 | 132 | 156 | 13 | 30 |
| 2026-08 | 69 | 152 | 187 | 23 | 40 |
| 2026-09 | 75 | 33 | 194 | **33** | 30 |

September's `<30d` (33) is the highest of any month and the median age has
collapsed from 152d to 33d. The backlog-excavation reading no longer holds:
the scanner is now working mostly on recent code.

Self-caused: 4 of 8, from PRs merged in the previous 24 hours (#1308 ×2,
#1321, #1303). All four are defects in logic the fix added.

### Classes

- **arrival under-coverage, db layer — 5 members, 1 reported (#1337).** The
  module-wide `#[expect(clippy::disallowed_methods)]` in `db/mod.rs` is granted
  per *module* for row stamping and OCC retries, so it also exempts
  request-deciding expiry *comparisons*. Siblings: `try_consume_authorization_code`,
  `get_pushed_authorization_request`, `get_pending_oauth_authorization`,
  `get_scim_token_by_hash`. All over-reject at the tail of a lifetime.
- **ID token minted from a second clock — #1331 and #1333 are one defect.**
  Two sites (`claims.rs:321`, `token.rs:986`), each with an `#[expect]` naming
  the "artifact minting" category to cover a request-scoped decision.
- **#1330 + #1334 are two halves of PR #1308** — the call site its guard
  missed, and the client the guard broke.

### Review findings

- **#1332/#1340's premise is false.** OpenSSL 3.6.4's default `x509 -noout
  -subject` emits `O=Acme, CN=foo` (bare `=`); the `=`-padded form needs an
  explicit `-nameopt oneline`. Verified locally. The parser change is sound but
  the doc comment commits the false claim.
- **#1341 supersedes #1339** (same three files). #1341 makes `issued_at`
  required and deletes the `#[expect]`; #1339 keeps the ambient fallback.
- **#1344 fixes the read, not the comparison.** `update_authenticator_counter`
  still does a signed `max` over bitwise-reinterpreted `u32`, so a counter
  crossing 2^31 freezes permanently.
- **#1345 cites the guardrail hole as permission** for its ambient wrapper.
- **#1338** fails only the spec-coverage ratchet (baseline prune needed).

### Operational

**#1334 is in a shipped release.** #1308 merged 04:45 UTC; v2026.9.3 shipped
15:34 UTC. WIF (`vouch credential openai`/`anthropic`) returns 401
`unauthorized_client` for every already-enrolled CLI client. #1342 fixes new
registrations only.

### Decided

User decisions: no migration for #1334 (no users yet); fix the entire class;
follow the spec 100%.

- **The db-layer arrival class was fixed as one change (#1346), and the
  guardrail is what sized it.** Replacing the 14 module-wide `#[expect]`s in
  `db/mod.rs` with 33 per-function ones turned a 5-member class into a
  9-member one: client-credential validity, the OIDC state consume, the PAR
  consume, and the pending-auth consume were all invisible while the exemption
  was granted per module. Verified by breaking it — a reintroduced ambient
  clock is now a clippy error under `-D warnings`.
- #1341 merged as the ID-token class fix; #1339 closed as superseded.
- #1340 and #1344 amended before merge: #1340's OpenSSL justification
  corrected, #1344 completed with the u32-space counter comparison (both
  directions pinned by tests verified to fail against the old code).
- #1347 replaces #1338 and adds the RFC 7591 §2 fix — an absent `grant_types`
  reads as `["authorization_code"]`, not as authorized-for-nothing.

### Operational lesson: unsigned bot commits block the queue

`543053bc` on #1338 (`chore: prune rfc8628#5.2 from coverage baseline`, pushed
by detail-app[bot] after its CI failed) was unsigned, and the merge queue
rejects the whole branch with "Commits must have verified signatures." Its
other commits are signed, so this is a separate path in Detail's tooling.
Correcting it in place means rewriting a shared branch, so the fix is to
cherry-pick onto a fresh branch and re-open. Worth checking on any Detail PR
that has had a follow-up commit pushed to it:

    gh api repos/vouch-sh/vouch/pulls/<n>/commits \
      --jq '.[] | "\(.sha[0:8]) \(.commit.verification.verified)"'

### Outcome (four PRs, two issues closed without a fix)

#1356 (#1350), #1357 (#1353), #1358 (#1354, superseding Detail's #1355), #1359
(#1351). #1352 closed `wontfix` — WIF has no users, so the population an RFC
7592 update path would repair is empty. #1355 closed as superseded.

### The lesson that generalizes: verify against the real input, not a fixture

Three consecutive batches produced a defect in `canonicalize_dn`. The `+` arm
fixed this one's stated gap, but the scenario in the issue **still fails**, for
a reason the issue never named: RDN *ordering*. OpenSSL's default
`x509 -noout -subject` emits DER order; RFC 4514 §2.1 specifies the reverse
("starting with the last element of the sequence and moving backwards toward
the first"), which is what `-nameopt rfc2253` prints and what RFC 8705 §2.1.2
requires the registered value to be.

Every subject-DN test derived its input from the certificate's **own**
rendering, so the order agreed by construction and the mismatch could never
surface. Adding more cases in that shape would never have found it. Feeding
one real `openssl` string did, in a minute.

So: when a function exists to accept external input, at least one test must use
input captured from the external producer verbatim. The new
`test_verify_tls_client_auth_openssl_subject_renderings` pins the literal
OpenSSL 3.6.4 strings and asserts acceptance in both directions.

### Report the half you did not fix

Two issues overstated their scope, and saying so is part of the fix:

- **#1350's own example is still rejected**, deliberately — the paste is not an
  RFC 4514 DN. The PR and an issue comment say that with the quote instead of
  letting the close imply it works.
- **#1351 lists three surfaces; only two are sequentially exploitable.** On the
  admin UI the actor must be an active admin to pass authorization, so a second
  always exists when the target is someone else. An HTTP test was written,
  found to produce only 403, and deleted rather than shipped asserting the
  wrong thing. The floor there guards the concurrent mutual-removal race,
  covered at the db level instead.

### Mechanism notes

- **Let the test suite pick the guard value.** `delete_user` took a required
  `LastAdminGuard` (one test deliberately deletes an org's sole admin to reach
  the cascade's no-admin-remains branch). Setting all 12 call sites to
  `Enforce` first and running showed 9 were unaffected; only 3 needed `Bypass`.
  Guessing would have over-applied the bypass and silently weakened the tests.
- **A `compare_and_update` seam on `StoreTransaction` deadlocks on SQLite** —
  the hook's concurrent writer blocks against the open transaction. The
  store-level seam works only because it fires before the transaction opens.
  Reverted. Don't re-attempt without a different mechanism.
- **A floor placed after `revoke_then_persist` logs the user out and then
  refuses.** That helper revokes before persisting by design, so a cross-row
  guard needs an advisory pre-check ahead of revocation, with the
  in-transaction count still authoritative.
- **Diagnose a ratchet failure before applying its suggested fix.** #1356's
  first run failed `normative_coverage_does_not_regress`, and the prescribed
  prune would have marked an unrelated RFC 4514 §2.3 SHOULD as covered. The
  actual problem was a wrong citation in the new test — the `+` separator is
  §2.2 — and correcting it made the ratchet pass with no prune at all.

## 2026-09-14

Issues #1363–#1365 (3), fix PRs #1366–#1368 (3), 1:1. Full record in
`.local/detail-triage-2026-09-14.md`.

| month | n | median age | p90 | <30d | >90d |
|-------|---|-----------|-----|------|------|
| 2026-07 | 48 | 132 | 156 | 13 | 30 |
| 2026-08 | 69 | 152 | 187 | 23 | 40 |
| 2026-09 | 83 | 19 | 194 | **41** | 30 |

Volume 24 → 8 → 5 → 3 over four days.

**Self-caused: 3 of 3, and the stats script reports 0.** The blamed PRs
(#1357, #1359) are human class fixes from yesterday's triage, not Detail fix
PRs, so the "from fix PR" column misses them. Every finding is a defect in
logic the class fix added:

- #1363 — #1359 put `LastAdminGuard::Enforce` on SCIM DELETE but the advisory
  pre-check it added to SCIM PATCH (for exactly this revoke-then-refuse
  ordering) was not applied to DELETE.
- #1364 — #1357's reverse `response_types` check runs on RFC 7592 PUT and
  rejects a faithful restatement of the `["code"]` default the server itself
  stored before #1357.
- #1365 — #1357 gated `grant_types` at the token endpoint; `/oauth/authorize`
  still never read `client.response_types`. Third batch of the
  "contract consulted at one layer, not another" class (#1330 → #1353 →
  #1365); after #1368 every issuance layer consults the pair, and the other
  registered fields (`request_uris`, `require_signed_request_object`) were
  already consulted.

### The lesson: a class fix's own residue is next batch's volume

Yesterday's record wrote down the #1363 mechanism ("a floor placed after
`revoke_then_persist` logs the user out and then refuses — needs an advisory
pre-check ahead of revocation") and applied it to one of the two paths with
that ordering. Rule 6 (enumerate every code path that touches the invariant)
has to be applied to the mechanism the fix *introduces*, not only the one the
issue reported. Same for #1357: the reverse check was added to a validator
shared with the update path, and the PR that added it did not ask what the
second caller would do with it.

### Review findings

- #1366: correct; a narrating comment to trim.
- #1367: correct semantics, two single-caller helpers plus a commit hash in a
  function name for a population that no first-party client can be in (CLI
  has sent `[]` since #96; self-service apps cannot PUT). Inline or won't-fix.
- #1368: correct; JAR and `request_uri` `response_types: []` tests left "as a
  follow-up" in the PR body — add before merge.

### Decided

All three Detail PRs merged after edits on their branches: #1366 with the
comment trimmed; #1368 with JAR and `request_uri` tests added (each shown to
fail with its gate removed) and a `response_types` axis on `TestClientSpec`;
#1367 slimmed from three helpers to one inline condition with its test client
built through the shared factory. A `GrantAuthorizedClient` newtype was
approved as a separate PR, design first.

## 2026-09-15

Two arrivals. 06:45 UTC: seven Dead Code PRs (#1374–#1380), no issues. 13:51
UTC: issues #1381–#1386 with fix PRs #1387–#1392. Full record in
`.local/detail-triage-2026-09-15.md`.

| month | n | median age | p90 | <30d | >90d |
|-------|---|-----------|-----|------|------|
| 2026-08 | 69 | 152 | 187 | 23 | 40 |
| 2026-09 | 89 | 4 | 194 | **47** | 30 |

**Self-caused: 6 of 6, script reports 1.** Five findings blame #1369 (the
client-type model), one #1368, one #1359 — class fixes from the previous two
days. The script's column counts only Detail-authored PRs.

**Dead Code PRs are invisible to `detail-stats.py`** (no issue is filed).
Branch prefix `detail/dead-code/`; ~80 merged since 2026-06-19.

### Classes

- **Removing a required field from a cross-version serde struct** — #684
  (`ChallengeStateDoc.doc_id`, shipped), #1165 (caught), #1170 (wontfix),
  #1379 (`AuthenticatorDoc.user_email`). Old and new servers overlap daily
  (ASG `min_healthy_percentage = 100`, `max_instance_lifetime = 86400`), and
  serde rejects a missing non-`Option` field, so the dead-code scanner's
  "never read" is not "safe to delete". Rule requested
  (`rcr_ee104618-4551-403f-b8fa-fbc3c073fd5a`).
- **Write-only index entries** — #1380 plus six siblings; one class PR.
- **#1369 residue** — two real members (#1381 rotation gates on
  `requires_secret()`, #1382 device flow on `internal_endpoint()`), and the
  sibling enumeration found no others. Two findings were not defects: #1385 is
  answered by RFC 8252 §8.4's per-instance-secret exception (8252 "Updates:
  6749"), #1386 targets a population the 09-14 check found empty.

### Review findings worth keeping

- **A server-side MUST can be blocked by the first-party client.** #1388
  enforces RFC 8628 §3.1/§3.4 client authentication correctly, but the CLI
  registers `private_key_jwt` and never sends an assertion to `/oauth/device`;
  merging would break `vouch enroll` for every installed CLI. When a fix
  tightens what the server accepts, check what the shipped first-party client
  sends before calling it mergeable.
- **Detail findings can contradict each other within one batch** (#1385 vs
  #1381/#1382). Resolve the governing spec question once, then dispose of the
  set, instead of reviewing each PR against its own issue.
- #1389 fixed PAR but not the pending-auth completion path with the same
  pass-`None`-then-overlay shape; #1390 duplicated an existing test hook.

### Decided

#1374–#1378 merged. #1391/#1385 closed (RFC 8252 §8.4); #1392/#1386 closed
wontfix. #1380 superseded by #1393 (all seven write-only index entries).
#1379 superseded by #1394 (plumbing removed, `#[serde(default)] user_email`
kept and written empty). #1387's comments reworked to verbatim spec quotes;
#1389 fixed for PAR and pending-auth with its citation corrected; #1390 moved
onto the existing delete hook. #1388 superseded by a CLI-first PR (assertion
at the device request and every poll); server enforcement for #1382 follows
after rollout. The wire-format rule was synced in #1395.

- **Citations are not history.** Trimming comments must keep spec citations
  (section plus verbatim quote) and cut only the narrative; #1387's RFC 8252
  §8.4 citation was dropped once and restored.
- **Check a quoted SHOULD's scope.** #1389 quoted a §2.2 sentence that
  governs only multiple-valued response types; §2.1's definition of
  `response_mode` was the applicable text.

## 2026-09-16 — three class fixes, two residue recurrences

| month | n | median age | p90 | <30d | >90d |
|-------|---|-----------|-----|------|------|
| 2026-09 | 93 | 4 | 194 | **51** | 30 |

**Self-caused: 4 of 4.** Blame: #1399 (device-flow client authentication), #1359
(last-admin floor), #1387 (rotation gate) — all merged in the previous two days.

### Classes

- **Shared-secret decisions keyed on the wrong axis** (#1405, #1406). Six sites
  used `client_type()` or `is_fapi()` where the question was whether the
  registered method uses a secret; `authenticate_client` accepted a secret from
  a non-FAPI `private_key_jwt` client, against OIDC Core 1.0 §3.1.3.1. The
  2026-09-15 review had seen the gate admit these clients and judged it not a
  regression. Fixed with `TokenEndpointAuthMethod::uses_client_secret()`; the
  detail template was a seventh site, found afterwards.
- **Refusal after committed revocation, unaudited on the admin side** (#1404).
  Named in the 2026-09-14 record. #1408's audit row would have exported to OCSF
  as a successful deletion; the projection now reports a top-level `refusal` as
  Failure, and the SCIM writer, which kept its refusal inside `details`, moved to
  a shared `Refusal` type.
- **#1403** was isolated: one handler's comment promised a JTI commit on every
  poll that three early returns skipped. RFC 7523 §3 replay prevention is a MAY.

### Lessons folded into the skill

Queued branches reject pushes; sibling hunts must reach templates and audit
readers; a gap a review notices is a decision for the user, not residue; search
test files before reporting a test missing.
