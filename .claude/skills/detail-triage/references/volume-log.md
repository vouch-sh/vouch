# Detail Volume Log

Measured history of Detail's findings, so a later run can tell a trend from a
blip. Append one section per triage pass. All figures come from
`scripts/detail-stats.py`; do not hand-edit them.

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
