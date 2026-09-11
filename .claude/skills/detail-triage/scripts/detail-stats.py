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
    python3 detail-stats.py                  # monthly + class tables
    python3 detail-stats.py --json           # machine-readable
    python3 detail-stats.py --since 2026-08  # only detections from this month on
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
from datetime import date, datetime

DEFAULT_AUTHOR = "app/detail-app"

# "Introduced in [#992](https://github.com/...) by @jplock on Aug 20, 2026"
INTRODUCED_RE = re.compile(
    r"Introduced in \[#(?P<pr>\d+)\][^\n]*? on (?P<when>[A-Za-z]{3,9} \d{1,2}, \d{4})"
)

# Detail links each issue to the hosted bug record. These IDs are what
# `detail rules create --bug-ids` expects as evidence for a class rule.
BUG_ID_RE = re.compile(r"\b(bug_[0-9a-f-]{36})\b")

# Keyword clusters over issue titles. Deliberately overlapping -- an issue can
# belong to more than one class, and the point is recurrence, not partition.
CLASSES: tuple[tuple[str, str], ...] = (
    ("concurrency/lost-update",
     r"concurren|\brace|racing|lost update|OCC|simultaneous|TOCTOU|retry"),
    ("stale-cache invalidation",
     r"cache|cached|stale"),
    ("time/clock boundary",
     r"expir|max_age|TTL|lifetime|timestamp|clock|skew|freshness|boundary"
     r"|auth_time|NotOnOrAfter|staleness"),
    ("incomplete revocation",
     r"revok|revoc|logout|invalidat.*session"),
    ("string canonicalization",
     r"canonical|whitespace|casing|case-insensitiv|leading zero|normaliz"
     r"|trailing|encod|escap|comma|anchor|suffix|malformed"),
    ("missing audit event",
     r"audit"),
    ("metadata vs behavior",
     r"metadata|advertis|discovery|announce|echo|omits"),
    ("fail-open error path",
     r"silently|ignores|fail.?open|no-?op|best-effort|swallow"),
    ("authz gap",
     r"unauthoriz|without .*authoriz|bypass|allows .*without|deactivated"
     r"|can delete|another user|takeover|grant_types"),
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
        return [name for name, pattern in CLASSES if re.search(pattern, self.title, re.I)]


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
            introduced = datetime.strptime(match["when"], "%b %d, %Y").date()
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


def render(findings: list[Finding], months: list[str], class_rows: list[dict[str, object]],
           unmatched: list[Finding]) -> None:
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--author", default=DEFAULT_AUTHOR,
                        help=f"issue author to treat as Detail (default: {DEFAULT_AUTHOR})")
    parser.add_argument("--limit", type=int, default=1000,
                        help="maximum issues to read from gh (default: 1000)")
    parser.add_argument("--since", metavar="YYYY-MM",
                        help="only count detections in this month or later")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="emit machine-readable output")
    args = parser.parse_args()

    findings = fetch(args.author, args.limit)
    if args.since:
        findings = [f for f in findings if f.month >= args.since]
    if not findings:
        sys.exit(f"no issues authored by {args.author} found")
    findings.sort(key=lambda f: f.detected)

    months, class_rows, unmatched = by_class(findings)
    if args.as_json:
        json.dump(
            {
                "total": len(findings),
                "monthly": monthly(findings),
                "classes": class_rows,
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
        render(findings, months, class_rows, unmatched)
    return 0


if __name__ == "__main__":
    sys.exit(main())
