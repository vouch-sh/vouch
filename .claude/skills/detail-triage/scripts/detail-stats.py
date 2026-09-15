#!/usr/bin/env python3
"""Measure the volume, age, and recurring classes of Detail's bug findings.

Detail re-scans the whole repository on each pass rather than only the latest
diff, so its output mixes two populations that call for opposite responses:

  * Backlog excavation -- old code it previously walked past. Finite, and not
    something a process change shortens.
  * Fresh regressions -- code merged in the last month. This is the number a
    process change can actually move.

The age columns separate the two. A rising median age with a flat under-30-day
count means the backlog is being worked through and nothing is wrong with the
development process; a rising under-30-day count means the opposite.

The class table is a keyword clustering over issue titles. It is directional,
not rigorous: titles overlap several classes and some match none. Use it to
spot recurrence worth investigating, never as a count to quote as fact.

Usage:
    python3 detail-stats.py                        # monthly + class tables
    python3 detail-stats.py --json                 # machine-readable
    python3 detail-stats.py --since 2026-08        # detections from this month on
    python3 detail-stats.py --pr-diff-sizes 1303-1324   # prod vs test lines per PR
"""

from __future__ import annotations

import argparse
import collections
import json
import math
import re
import statistics
import subprocess
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone

DEFAULT_AUTHOR = "app/detail-app"

# Detail's Dead Code PRs arrive on this branch prefix and file no issue.
DEAD_CODE_BRANCH = "detail/dead-code/"

# A finding blamed on a PR merged this many days before detection counts as
# caused by a recent merge, whoever authored the PR.
RECENT_MERGE_DAYS = 3

# "Introduced in [#992](https://github.com/...) by @jplock on Aug 20, 2026"
INTRODUCED_RE = re.compile(
    r"Introduced in \[#(?P<pr>\d+)\][^\n]*? on (?P<when>[A-Za-z]{3,9} \d{1,2}, \d{4})"
)

# Detail links each issue to its hosted bug record. These IDs are what
# `detail rules create --bug-ids` takes as evidence when requesting a rule for a
# confirmed class (step 5), and they also let a triage record cite the upstream
# bug alongside the issue number.
BUG_ID_RE = re.compile(r"\b(bug_[0-9a-f-]{36})\b")

# Keyword clusters over issue titles. Deliberately overlapping -- an issue can
# belong to more than one class, and the point is recurrence, not partition.
CLASSES: tuple[tuple[str, str], ...] = (
    ("concurrency/lost-update",
     r"concurren|\brace|racing|lost update|OCC|simultaneous|TOCTOU|retry"),
    ("stale-cache invalidation",
     r"cache|cached|stale"),
    ("time/clock boundary",
     (r"expir|max_age|TTL|lifetime|timestamp|clock|skew|freshness|boundary"
      r"|auth_time|NotOnOrAfter|staleness")),
    ("incomplete revocation",
     r"revok|revoc|logout|invalidat.*session"),
    ("string canonicalization",
     (r"canonical|whitespace|casing|case-insensitiv|leading zero|normaliz"
      r"|trailing|encod|escap|comma|anchor|suffix|malformed")),
    ("missing audit event",
     r"audit"),
    ("metadata vs behavior",
     r"metadata|advertis|discovery|announce|echo|omits"),
    ("fail-open error path",
     r"silently|ignores|fail.?open|no-?op|best-effort|swallow"),
    ("authz gap",
     (r"unauthoriz|without .*authoriz|bypass|allows .*without|deactivated"
      r"|can delete|another user|takeover|grant_types")),
)


@dataclass(frozen=True)
class Finding:
    number: int
    title: str
    state: str
    detected: date
    introduced: date | None
    introduced_pr: int | None
    bug_id: str | None

    @property
    def age_days(self) -> int | None:
        if self.introduced is None:
            return None
        return (self.detected - self.introduced).days

    @property
    def month(self) -> str:
        return self.detected.strftime("%Y-%m")

    def classes(self) -> list[str]:
        return [
            name for name, pattern in CLASSES if re.search(pattern, self.title, re.IGNORECASE)
        ]


@dataclass(frozen=True)
class PullRequest:
    number: int
    author: str
    branch: str
    created: date
    merged: date | None


def fetch_prs(limit: int) -> list[PullRequest]:
    """Every PR, for attributing findings and counting Detail's arrivals per batch."""
    proc = subprocess.run(
        [
            "gh", "pr", "list",
            "--state", "all",
            "--limit", str(limit),
            "--json", "number,author,headRefName,createdAt,mergedAt",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        sys.exit(f"gh pr list failed: {proc.stderr.strip()}")
    return [
        PullRequest(
            number=row["number"],
            author=(row.get("author") or {}).get("login") or "",
            branch=row.get("headRefName") or "",
            created=date.fromisoformat(row["createdAt"][:10]),
            merged=date.fromisoformat(row["mergedAt"][:10]) if row.get("mergedAt") else None,
        )
        for row in json.loads(proc.stdout)
    ]


def fetch(author: str, limit: int) -> list[Finding]:
    """Read every Detail-authored issue through the gh CLI."""
    proc = subprocess.run(
        [
            "gh", "issue", "list",
            "--state", "all",
            "--limit", str(limit),
            "--json", "number,title,createdAt,state,author,body",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        sys.exit(f"gh issue list failed: {proc.stderr.strip()}")

    findings: list[Finding] = []
    for row in json.loads(proc.stdout):
        if (row.get("author") or {}).get("login") != author:
            continue
        body = row.get("body") or ""
        introduced = introduced_pr = None
        if match := INTRODUCED_RE.search(body):
            introduced = (
                datetime.strptime(match["when"], "%b %d, %Y").replace(tzinfo=timezone.utc).date()
            )
            introduced_pr = int(match["pr"])
        bug = BUG_ID_RE.search(body)
        findings.append(
            Finding(
                number=row["number"],
                title=row["title"],
                state=row["state"],
                detected=date.fromisoformat(row["createdAt"][:10]),
                introduced=introduced,
                introduced_pr=introduced_pr,
                bug_id=bug.group(1) if bug else None,
            )
        )
    return findings


def diff_sizes(spec: str) -> list[dict[str, object]]:
    """Split each PR's added lines into production and test, via `gh pr diff`.

    Most of a Detail fix PR is tests, so reviewing the whole diff buries the
    logic the fix introduces -- which is where the defects are. This reports
    what to actually read.

    The split is by file path, so it over-counts production for files carrying
    an inline `#[cfg(test)] mod tests` -- which this repo keeps in the
    production file until it passes ~500 lines. A PR reporting zero test lines
    has inline tests, not no tests.
    """
    if "-" in spec:
        lo, hi = spec.split("-", 1)
        numbers = list(range(int(lo), int(hi) + 1))
    else:
        numbers = [int(n) for n in spec.split(",")]

    rows: list[dict[str, object]] = []
    for number in numbers:
        proc = subprocess.run(
            ["gh", "pr", "diff", str(number)],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0:
            rows.append({"pr": number, "error": proc.stderr.strip()[:80]})
            continue

        is_test = False
        prod = test = 0
        prod_files: list[str] = []
        for line in proc.stdout.splitlines():
            if line.startswith("+++ b/"):
                path = line.removeprefix("+++ b/")
                is_test = "test" in path or path.startswith("specs/")
                if not is_test:
                    prod_files.append(path)
            elif line.startswith("+") and not line.startswith("+++"):
                if is_test:
                    test += 1
                else:
                    prod += 1
        rows.append({"pr": number, "prod": prod, "test": test, "files": prod_files})
    return rows


def render_diff_sizes(rows: list[dict[str, object]]) -> None:
    print(f"{'pr':>6} {'prod+':>6} {'test+':>6}  production files")
    for row in rows:
        if "error" in row:
            print(f"{row['pr']:>6} {'-':>6} {'-':>6}  ERROR: {row['error']}")
            continue
        shown = ", ".join(
            f.removeprefix("crates/vouch-server/src/") for f in row["files"][:3]
        )
        if len(row["files"]) > 3:
            shown += f", +{len(row['files']) - 3} more"
        print(f"{row['pr']:>6} {row['prod']:>6} {row['test']:>6}  {shown}")
    total_prod = sum(r.get("prod", 0) for r in rows)
    total_test = sum(r.get("test", 0) for r in rows)
    print(f"\n  {total_prod} production lines to read, {total_test} test lines to skim.")
    print("  Split is by file path: a PR showing 0 test lines has inline "
          "#[cfg(test)] tests,")
    print("  counted as production. Treat its prod figure as an upper bound.")


def fix_defect_rate(findings: list[Finding], prs: list[PullRequest], author: str,
                    today: date) -> list[dict[str, object]]:
    """How often a merged PR is later blamed by a Detail finding, bot vs human.

    This is the number the "draft, not merge candidate" policy rests on. If
    Detail's fixes were markedly worse than ours, turning auto-fixing off would
    be the right call; measured, they are not.

    Exposure is controlled by only counting PRs that have had the full window
    available since merge, and asking whether the *first* blame landed inside
    it. Two caveats to state whenever quoting this: it is not like-for-like,
    because Detail PRs are small targeted fixes while human PRs include feature
    work; and post-merge blame understates the true defect rate, because the
    scanner does not re-find everything it introduces.
    """
    merged: dict[int, tuple[str, date]] = {
        pr.number: (pr.author, pr.merged)
        for pr in prs
        if pr.merged is not None and pr.author != "app/dependabot"
    }

    first_blame: dict[int, date] = {}
    for finding in findings:
        pr = finding.introduced_pr
        if pr is None:
            continue
        if pr not in first_blame or finding.detected < first_blame[pr]:
            first_blame[pr] = finding.detected

    rows: list[dict[str, object]] = []
    for window in (14, 30, 60):
        counts: dict[str, list[int]] = {"detail": [0, 0], "human": [0, 0]}
        for number, (login, merged_on) in merged.items():
            if (today - merged_on).days < window:
                continue
            group = "detail" if login == author else "human"
            counts[group][0] += 1
            blamed = first_blame.get(number)
            if blamed and (blamed - merged_on).days <= window:
                counts[group][1] += 1
        rows.append({
            "window_days": window,
            "detail_eligible": counts["detail"][0], "detail_blamed": counts["detail"][1],
            "human_eligible": counts["human"][0], "human_blamed": counts["human"][1],
        })
    return rows


def render_fix_defect_rate(rows: list[dict[str, object]]) -> None:
    def pct(hit: int, total: int) -> str:
        return f"{hit / total * 100:.1f}%" if total else "-"

    print("Merged PRs later blamed by a Detail finding, by author")
    print(f"  {'window':>7} {'detail n':>9} {'detail':>7} {'human n':>8} {'human':>7}")
    for row in rows:
        print(f"  {row['window_days']:>6}d {row['detail_eligible']:9} "
              f"{pct(row['detail_blamed'], row['detail_eligible']):>7} "
              f"{row['human_eligible']:8} "
              f"{pct(row['human_blamed'], row['human_eligible']):>7}")
    print("\n  Not like-for-like: Detail PRs are small targeted fixes, human PRs")
    print("  include feature work. Post-merge blame also understates the real")
    print("  defect rate -- the scanner does not re-find all it introduces.")


def percentile(values: list[int], fraction: float) -> int:
    """Nearest-rank percentile. Exact on small samples, unlike interpolation."""
    ordered = sorted(values)
    rank = max(1, math.ceil(fraction * len(ordered)))
    return ordered[rank - 1]


def monthly(findings: list[Finding]) -> list[dict[str, object]]:
    by_month: dict[str, list[Finding]] = collections.defaultdict(list)
    for finding in findings:
        by_month[finding.month].append(finding)

    rows: list[dict[str, object]] = []
    for month in sorted(by_month):
        bucket = by_month[month]
        ages = [f.age_days for f in bucket if f.age_days is not None]
        rows.append(
            {
                "month": month,
                "issues": len(bucket),
                "no_attribution": sum(1 for f in bucket if f.age_days is None),
                "median_age": round(statistics.median(ages)) if ages else None,
                "p90_age": percentile(ages, 0.9) if ages else None,
                "under_30d": sum(1 for a in ages if a < 30),
                "over_90d": sum(1 for a in ages if a > 90),
            }
        )
    return rows


def by_class(findings: list[Finding]) -> tuple[list[str], list[dict[str, object]], list[Finding]]:
    months = sorted({f.month for f in findings})
    counts: dict[str, collections.Counter[str]] = {
        name: collections.Counter() for name, _ in CLASSES
    }
    unmatched: list[Finding] = []
    for finding in findings:
        hits = finding.classes()
        if not hits:
            unmatched.append(finding)
        for name in hits:
            counts[name][finding.month] += 1

    rows = [
        {
            "class": name,
            "total": sum(counts[name].values()),
            "by_month": {m: counts[name].get(m, 0) for m in months},
        }
        for name, _ in CLASSES
    ]
    rows.sort(key=lambda r: r["total"], reverse=True)
    return months, rows, unmatched


def batches(findings: list[Finding], prs: list[PullRequest],
            author: str) -> list[dict[str, object]]:
    """Per detection date: what Detail opened, and how much of it recent merges caused.

    `from_detail_pr` counts findings blamed on a Detail-authored PR. A rising
    share means merging the fix PRs is feeding the next scan, though part of it
    is mechanical: as Detail's PR count grows, its commits are increasingly the
    last to touch any line. Confirm a spike by reading whether the finding is a
    defect in the logic the fix added.

    `from_recent_pr` counts findings blamed on any PR merged at most
    RECENT_MERGE_DAYS before detection, whoever wrote it. It exists because
    `from_detail_pr` misses class fixes a human merged: on 2026-09-14 and
    2026-09-15 every finding came from one (3 of 3, 6 of 6) while
    `from_detail_pr` read 0 and 1.

    Dead Code PRs file no issue, so they appear only in `dead_code_prs`.
    """
    by_number = {pr.number: pr for pr in prs}
    detail_prs = {pr.number for pr in prs if pr.author == author}

    issues: dict[date, list[Finding]] = collections.defaultdict(list)
    for finding in findings:
        issues[finding.detected].append(finding)
    fix_prs: collections.Counter[date] = collections.Counter()
    dead_code_prs: collections.Counter[date] = collections.Counter()
    for pr in prs:
        if pr.author != author:
            continue
        if pr.branch.startswith(DEAD_CODE_BRANCH):
            dead_code_prs[pr.created] += 1
        else:
            fix_prs[pr.created] += 1

    earliest = min(issues)
    rows: list[dict[str, object]] = []
    for day in sorted(set(issues) | set(fix_prs) | set(dead_code_prs)):
        if day < earliest:
            continue
        attributed = [f for f in issues.get(day, []) if f.introduced_pr is not None]
        from_detail = from_recent = 0
        for finding in attributed:
            if finding.introduced_pr in detail_prs:
                from_detail += 1
            blamed = by_number.get(finding.introduced_pr)
            if (blamed and blamed.merged
                    and 0 <= (day - blamed.merged).days <= RECENT_MERGE_DAYS):
                from_recent += 1
        rows.append(
            {
                "date": day.isoformat(),
                "issues": len(issues.get(day, [])),
                "fix_prs": fix_prs[day],
                "dead_code_prs": dead_code_prs[day],
                "attributed": len(attributed),
                "from_detail_pr": from_detail,
                "from_recent_pr": from_recent,
            }
        )
    return rows


def render(findings: list[Finding], months: list[str], class_rows: list[dict[str, object]],
           unmatched: list[Finding], batch_rows: list[dict[str, object]]) -> None:
    print(f"{len(findings)} Detail issues, "
          f"{findings[0].detected.isoformat()} to {findings[-1].detected.isoformat()}\n")

    print("Volume and bug age by detection month")
    print(f"  {'month':8} {'n':>4} {'noattr':>7} {'median':>7} {'p90':>5} {'<30d':>5} {'>90d':>5}")
    for row in monthly(findings):
        median = "-" if row["median_age"] is None else row["median_age"]
        p90 = "-" if row["p90_age"] is None else row["p90_age"]
        print(f"  {row['month']:8} {row['issues']:4} {row['no_attribution']:7} "
              f"{median:>7} {p90:>5} {row['under_30d']:5} {row['over_90d']:5}")

    print("\n  <30d is the number a process change can move. A rising median with a")
    print("  flat <30d means backlog excavation, not a regression in development.")

    print("\nRecurring classes (keyword clustering over titles -- directional only)")
    header = " ".join(f"{m[5:]:>3}" for m in months)
    print(f"  {'class':28} {'total':>5}  {header}")
    for row in class_rows:
        cells = " ".join(f"{row['by_month'][m]:3}" for m in months)
        print(f"  {row['class']:28} {row['total']:5}  {cells}")
    print(f"\n  {len(unmatched)} issues matched no class; read those titles directly.")

    print("\nPer batch (days with 3+ issues or any Detail PR)")
    print(f"  {'batch':10} {'issues':>6} {'fix PRs':>7} {'dead-code':>9} {'attrib':>6} "
          f"{'Detail PR':>9} {f'PR<={RECENT_MERGE_DAYS}d':>7}")
    for row in batch_rows:
        if row["issues"] < 3 and not row["fix_prs"] and not row["dead_code_prs"]:
            continue
        print(f"  {row['date']:10} {row['issues']:6} {row['fix_prs']:7} "
              f"{row['dead_code_prs']:9} {row['attributed']:6} "
              f"{row['from_detail_pr']:9} {row['from_recent_pr']:7}")
    print("\n  Detail PR: blamed on one of Detail's own PRs. "
          f"PR<={RECENT_MERGE_DAYS}d: blamed on any PR merged")
    print(f"  at most {RECENT_MERGE_DAYS} days before detection, including class fixes we "
          "wrote. A high")
    print("  share means our recent merges are feeding the scan; confirm by checking")
    print("  the finding is in the logic the PR added.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--author", default=DEFAULT_AUTHOR,
                        help=f"issue author to treat as Detail (default: {DEFAULT_AUTHOR})")
    parser.add_argument("--limit", type=int, default=1000,
                        help="maximum issues to read from gh (default: 1000)")
    parser.add_argument("--pr-limit", type=int, default=5000,
                        help="maximum PRs to read from gh (default: 5000)")
    parser.add_argument("--since", metavar="YYYY-MM",
                        help="only count detections in this month or later")
    parser.add_argument("--pr-diff-sizes", metavar="RANGE",
                        help="split added lines into production vs test for these PRs "
                             "(e.g. 1303-1324 or 1303,1307); skips the issue analysis")
    parser.add_argument("--fix-defect-rate", metavar="YYYY-MM-DD",
                        help="how often merged PRs are later blamed by a finding, Detail "
                             "vs human, as of this date; the evidence behind the "
                             "draft-not-merge-candidate policy")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="emit machine-readable output")
    args = parser.parse_args()

    if args.pr_diff_sizes:
        rows = diff_sizes(args.pr_diff_sizes)
        if args.as_json:
            json.dump(rows, sys.stdout, indent=2)
            print()
        else:
            render_diff_sizes(rows)
        return 0

    findings = fetch(args.author, args.limit)
    if args.since:
        findings = [f for f in findings if f.month >= args.since]
    if not findings:
        sys.exit(f"no issues authored by {args.author} found")
    findings.sort(key=lambda f: f.detected)

    prs = fetch_prs(args.pr_limit)

    if args.fix_defect_rate:
        rows = fix_defect_rate(findings, prs, args.author,
                               date.fromisoformat(args.fix_defect_rate))
        if args.as_json:
            json.dump(rows, sys.stdout, indent=2)
            print()
        else:
            render_fix_defect_rate(rows)
        return 0

    months, class_rows, unmatched = by_class(findings)
    batch_rows = batches(findings, prs, args.author)
    if args.as_json:
        json.dump(
            {
                "total": len(findings),
                "monthly": monthly(findings),
                "classes": class_rows,
                "batches": batch_rows,
                "unmatched": [{"number": f.number, "title": f.title} for f in unmatched],
                "open_bug_ids": {
                    f.number: f.bug_id for f in findings if f.state == "OPEN" and f.bug_id
                },
            },
            sys.stdout,
            indent=2,
        )
        print()
    else:
        render(findings, months, class_rows, unmatched, batch_rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
