#!/usr/bin/env python3
"""Map the test suite onto the normative requirements extracted from specs/.

Reads ``specs/requirements.tsv`` (produced by ``audit-normative.py``) and
``specs/audit-scope.tsv``, walks every test function in ``crates/``, and links a
test to a requirement when the test cites that requirement's spec and section.

Linkage is *section-level*: a test citing "RFC 9449 Section 4.3" is recorded
against every requirement in RFC 9449 section 4.3.  That is deliberately
optimistic -- it answers "has anyone tested near this text", not "is this exact
sentence asserted".  A requirement with no citing test is an unambiguous gap;
one with a citing test still needs a human to confirm the assertion matches.
Statement-level verdicts live in ``specs/coverage.tsv`` and override this.

Usage:
    scripts/audit-coverage.py            # write specs/coverage-report.md
    scripts/audit-coverage.py --json     # machine-readable summary
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REQUIREMENTS = REPO / "specs" / "requirements.tsv"
SCOPE = REPO / "specs" / "audit-scope.tsv"
CRATES = REPO / "crates"
REPORT = REPO / "specs" / "coverage-report.md"

# Prose names that appear in test comments, mapped to manifest spec ids.
ALIASES = {
    r"OIDC Core": "oidc-core-1_0",
    r"OpenID Connect Core": "oidc-core-1_0",
    r"OIDC Discovery": "oidc-discovery-1_0",
    r"OpenID Connect Discovery": "oidc-discovery-1_0",
    r"OIDC Registration": "oidc-registration-1_0",
    r"OpenID Connect Dynamic Client Registration": "oidc-registration-1_0",
    r"RP-Initiated Logout": "oidc-rpinitiated-1_0",
    r"Back-?Channel Logout": "oidc-backchannel-1_0",
    r"Front-?Channel Logout": "oidc-frontchannel-1_0",
    r"Session Management": "oidc-session-1_0",
    r"FAPI 2\.0 Message Signing": "fapi-2_0-message-signing",
    r"Message Signing": "fapi-2_0-message-signing",
    r"FAPI ?2(\.0)?": "fapi-2_0-security-profile",
    r"FAPI": "fapi-2_0-security-profile",
    r"JARM": "jarm",
    r"Form Post": "oauth-form-post-response-mode-1_0",
    r"WebAuthn": "webauthn-2",
    r"CTAP2?": "ctap-2.0-ps-20190130",
    r"SAML Core": "saml-core-2.0-os",
    r"SAML Bindings": "saml-bindings-2.0-os",
    r"SAML Profiles": "saml-profiles-2.0-os",
    r"SAML Metadata": "saml-metadata-2.0-os",
    r"XML ?Sig(nature)?": "xmldsig-core1",
    r"Exclusive C14N": "xml-exc-c14n",
}

SECTION = r"(?:§|[Ss]ection[  ]|[Ss]ec\.[  ])[  ]?(\d+(?:\.\d+)*)"
RFC_CITE = re.compile(r"RFC[  ]?(\d{3,4})[^.\n]{0,12}?" + SECTION)
ALIAS_CITES = [
    (re.compile(name + r"[^.\n]{0,12}?" + SECTION), spec) for name, spec in ALIASES.items()
]
BARE_SECTION = re.compile(SECTION)

# Test-file basename -> the spec its bare "§4.3" citations refer to.
FILE_DEFAULTS = [
    (re.compile(r"^rfc(\d{3,4})"), lambda m: f"rfc{m.group(1)}"),
    (re.compile(r"^oidc_core"), lambda m: "oidc-core-1_0"),
    (re.compile(r"^oidc_discovery"), lambda m: "oidc-discovery-1_0"),
    (re.compile(r"^oidc_userinfo"), lambda m: "oidc-core-1_0"),
    (re.compile(r"^fapi2?"), lambda m: "fapi-2_0-security-profile"),
    (re.compile(r"^jarm"), lambda m: "jarm"),
    (re.compile(r"^webauthn"), lambda m: "webauthn-2"),
    (re.compile(r"^scim"), lambda m: "rfc7644"),
    (re.compile(r"^saml"), lambda m: "saml-core-2.0-os"),
]

TEST_ATTR = re.compile(r"#\[(?:tokio::)?test\b[^\]]*\]|#\[test_case[^\]]*\]")
FN_NAME = re.compile(r"\bfn\s+([A-Za-z0-9_]+)")


def load_rows(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        lines = [l for l in fh if not l.startswith("#") and l.strip()]
    return list(csv.DictReader(lines, delimiter="\t"))


def file_default(path: Path) -> str | None:
    stem = path.stem
    for pattern, resolve in FILE_DEFAULTS:
        m = pattern.match(stem)
        if m:
            return resolve(m)
    return None


def test_blocks(text: str) -> list[tuple[str, str]]:
    """Yield (test_name, source_text) for every test function in a file.

    The source text starts a few lines above the attribute so that a leading
    comment block describing which requirement the test pins is included.
    """
    blocks = []
    for m in TEST_ATTR.finditer(text):
        name_m = FN_NAME.search(text, m.end())
        if not name_m:
            continue
        brace = text.find("{", name_m.end())
        if brace < 0:
            continue
        depth, i = 0, brace
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        # Walk backwards over any contiguous comment lines above the attribute.
        start = text.rfind("\n\n", 0, m.start())
        start = 0 if start < 0 else start
        blocks.append((name_m.group(1), text[start : i + 1]))
    return blocks


def citations(source: str, default_spec: str | None) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for m in RFC_CITE.finditer(source):
        found.add((f"rfc{m.group(1)}", m.group(2)))
    for pattern, spec in ALIAS_CITES:
        for m in pattern.finditer(source):
            found.add((spec, m.group(m.lastindex)))
    if default_spec:
        for m in BARE_SECTION.finditer(source):
            found.add((default_spec, m.group(1)))
    return found


def collect_tests() -> dict[tuple[str, str], set[str]]:
    """(spec, section) -> {test identifiers citing it}."""
    index: dict[tuple[str, str], set[str]] = collections.defaultdict(set)
    for path in CRATES.rglob("*.rs"):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "#[test" not in text and "#[tokio::test" not in text:
            continue
        default = file_default(path)
        rel = path.relative_to(REPO)
        for name, source in test_blocks(text):
            for spec, section in citations(source, default):
                index[(spec, section)].add(f"{rel}::{name}")
    return index


def ancestors(section: str) -> list[str]:
    parts = section.split(".")
    return [".".join(parts[: i + 1]) for i in range(len(parts))]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    scope = {r["spec_id"]: r for r in load_rows(SCOPE)}
    reqs = load_rows(REQUIREMENTS)
    tests = collect_tests()

    rows = []
    for r in reqs:
        sc = scope.get(r["spec"])
        if sc is None or sc["scope"] == "reference":
            continue
        # A test citing section 4 counts for 4.3 only if it cites 4.3 or a
        # descendant; citing the parent alone is too weak to claim coverage.
        hits = set(tests.get((r["spec"], r["section"]), set()))
        for key, names in tests.items():
            if key[0] == r["spec"] and key[1].startswith(r["section"] + "."):
                hits |= names
        rows.append({**r, "scope": sc["scope"], "tests": sorted(hits)})

    total = len(rows)
    covered = sum(1 for r in rows if r["tests"])
    by_spec: dict[str, dict] = collections.defaultdict(
        lambda: {"total": 0, "covered": 0, "must": 0, "must_gap": 0}
    )
    for r in rows:
        s = by_spec[r["spec"]]
        s["total"] += 1
        s["covered"] += 1 if r["tests"] else 0
        if r["strength"] in ("MUST", "MUST NOT"):
            s["must"] += 1
            if not r["tests"]:
                s["must_gap"] += 1

    if args.json:
        print(json.dumps({"total": total, "covered": covered, "by_spec": by_spec}, indent=2))
        return 0

    lines = [
        "# Normative coverage report",
        "",
        "Generated by `scripts/audit-coverage.py`. Do not edit by hand.",
        "",
        f"In-scope normative statements: **{total}**  ",
        f"With at least one citing test: **{covered}** ({covered * 100 // max(total, 1)}%)  ",
        f"With no citing test: **{total - covered}**",
        "",
        "Linkage is section-level: a test citing a spec section is credited with",
        "every requirement in that section. It answers \"has anything been tested",
        "here\", not \"is this sentence asserted\".",
        "",
        "| Spec | Scope | Reqs | Cited | MUST/MUST NOT | MUST gaps |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for spec, s in sorted(by_spec.items(), key=lambda kv: (-kv[1]["must_gap"], kv[0])):
        lines.append(
            f"| `{spec}` | {scope[spec]['scope']} | {s['total']} | {s['covered']} "
            f"| {s['must']} | {s['must_gap']} |"
        )
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"in-scope: {total}   cited-by-a-test: {covered}   uncited: {total - covered}")
    print(f"wrote {REPORT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
