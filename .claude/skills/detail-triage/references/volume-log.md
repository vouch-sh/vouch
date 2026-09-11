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

### Batch under triage

Issues #1279–#1302 (24) and fix PRs #1303–#1324 (22), all opened between
22:47 and 22:54 UTC on 2026-09-11. #1283 and #1285 arrived without a fix PR;
both are concurrency-class. #1312 failed Unit Tests on linux and macOS on
arrival. #1303 is the size outlier at 968 added lines across 20 files.

Decisions: recorded in the next section once step 3 completes.
