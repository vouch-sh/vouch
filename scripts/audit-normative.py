#!/usr/bin/env python3
"""Extract every normative requirement from the cached specification corpus.

Walks the files listed in ``specs/manifest.tsv``, reflows their prose, and emits
one row per normative statement (MUST / MUST NOT / SHALL / SHALL NOT / SHOULD /
SHOULD NOT) to ``specs/requirements.tsv``.

Requirement IDs are ``{spec_id}#{section}#{digest}`` where ``digest`` is the
first 8 hex chars of the SHA-1 of the normalized statement text.  Keying on the
text rather than an ordinal means the ID survives unrelated edits elsewhere in
the document, and a statement whose wording actually changes gets a new ID --
which surfaces as a stale coverage entry rather than a silent drift.

Usage:
    scripts/audit-normative.py                 # regenerate specs/requirements.tsv
    scripts/audit-normative.py --check         # exit 1 if the committed file is stale
    scripts/audit-normative.py --spec rfc9449  # print one spec's requirements
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "specs" / "manifest.tsv"
OUT = REPO / "specs" / "requirements.tsv"

# Normative keywords, strongest first.  RFC 2119 / RFC 8174.
KEYWORDS = [
    "MUST NOT",
    "SHALL NOT",
    "SHOULD NOT",
    "NOT RECOMMENDED",
    "MUST",
    "SHALL",
    "REQUIRED",
    "SHOULD",
    "RECOMMENDED",
]

# The audit tracks obligations, not permissions: MAY / OPTIONAL are excluded by
# design.  REQUIRED and RECOMMENDED are normalized onto MUST / SHOULD because
# RFC 2119 defines them as equivalent.
STRENGTH = {
    "MUST": "MUST",
    "SHALL": "MUST",
    "REQUIRED": "MUST",
    "MUST NOT": "MUST NOT",
    "SHALL NOT": "MUST NOT",
    "SHOULD": "SHOULD",
    "RECOMMENDED": "SHOULD",
    "SHOULD NOT": "SHOULD NOT",
    "NOT RECOMMENDED": "SHOULD NOT",
}

KEYWORD_PATTERN = r"(?<![A-Za-z])(" + "|".join(re.escape(k) for k in KEYWORDS) + r")(?![A-Za-z])"
KEYWORD_RE = re.compile(KEYWORD_PATTERN)
# ISO/IEC drafting conventions spell the same keywords in lower case.  The
# OpenID Foundation drafts FAPI and JARM that way: FAPI 2.0 Security Profile
# contains 61 lower-case "shall" and not one upper-case "MUST".
KEYWORD_RE_CI = re.compile(KEYWORD_PATTERN, re.IGNORECASE)

# A document that declares its keywords in lower case, e.g. FAPI 2.0:
# 'The keywords "shall", "shall not", ... are to be interpreted as described in'
ISO_CONVENTION_RE = re.compile(
    r"keywords?\s+[\"\u201c\u2018']?shall[\"\u201d\u2019']?\s*,", re.IGNORECASE
)

# A list item marker.  Converted W3C and OASIS documents delimit numbered steps
# with tabs ("\t13\tVerify that the rpIdHash in authData ..."), which is how
# WebAuthn writes the 23 steps of the registration ceremony -- the densest block
# of relying-party obligations in the document.
LIST_ITEM_RE = re.compile(
    r"^[ \t]*(?:\(?\d{1,2}[.)]|[a-z][.)]|[*+o•◦‣–—-])[ \t]+\S"
    r"|^[ \t]*\d{1,2}[ \t]*\t[ \t]*\S"
)

# Converted files carry typographic whitespace that regexes for " " miss.
UNICODE_SPACES = {
    0x00A0: " ", 0x2000: " ", 0x2001: " ", 0x2002: " ", 0x2003: " ", 0x2004: " ",
    0x2005: " ", 0x2006: " ", 0x2007: " ", 0x2008: " ", 0x2009: " ", 0x200A: " ",
    0x202F: " ", 0x205F: " ", 0x3000: " ", 0x200B: "", 0x2028: " ", 0x2029: " ",
}

# Specs converted from PDF carry the PDF's line numbers in column 0.
LINE_NUMBERED = re.compile(r"^\s*\d{1,5}\s{2,}(?=\S)")

# "4.3.  Checking DPoP Proofs" / "   4.3.  Checking DPoP Proofs".  Indentation
# is not a reliable discriminator: RFC 6749 sets headings flush left while
# RFC 9449 indents them three spaces, and converted files do either.
HEADING = re.compile(r"^ {0,8}(\d+(?:\.\d+)*)\.?[ \t]{1,6}(\S.*?)\s*$")
# Table-of-contents entries nest much further than headings ever do.
TOC_ENTRY = re.compile(r"^ {0,24}(\d+(?:\.\d+)*)\.?[ \t]{1,6}(\S.*?)\s*$")

# Table-of-contents rows: dot leaders and/or a trailing page number.
TOC_RE = re.compile(r"(\. ?){4,}|\s{3,}\d{1,4}\s*$")
# RFC page furniture: "Jones                    Standards Track       [Page 12]"
PAGE_RE = re.compile(r"\[Page \d+\]\s*$|^\f")
RFC_HEADER_RE = re.compile(r"^RFC \d+\s{2,}.*\s{2,}\w+ \d{4}\s*$")

# Boilerplate paragraphs that mention the keywords without imposing anything.
BOILERPLATE_RE = re.compile(
    r"key ?words? .{0,80}(are to be interpreted|MUST NOT.{0,40}SHOULD)"
    r"|BCP ?14|RFC ?2119.{0,60}RFC ?8174"
    r"|^The key words\b"
    r"|IANA .{0,40}(registr|template)"
    r"|This document is subject to BCP 78"
    r"|Copyright \(c\) \d{4} IETF Trust"
    r"|keywords? .{0,60}are to be interpreted as described in"
    r"|ISO/IEC Directives",
    re.IGNORECASE,
)

# Sentence splitter that does not break on "e.g.", "i.e.", "Section 4.2.", etc.
ABBREV = r"(?<!\be\.g)(?<!\bi\.e)(?<!\bcf)(?<!\bvs)(?<!\betc)(?<!\bal)(?<!\bNo)(?<!\bFig)(?<!\bSec)(?<!\bresp)"
SENTENCE_SPLIT = re.compile(ABBREV + r"(?<!\s\w)(?<!\d)\.(?=\s+[A-Z\"'\[(])|(?<=[.!?])\s+(?=[A-Z][a-z])")


def read_manifest() -> list[dict]:
    rows = []
    with MANIFEST.open(encoding="utf-8") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            if not line.strip():
                continue
            values = line.rstrip("\n").split("\t")
            rows.append(dict(zip(header, values)))
    return rows


def strip_furniture(lines: list[str]) -> list[str]:
    """Drop page breaks, running headers/footers, and PDF line numbers."""
    numbered = sum(1 for ln in lines[:400] if LINE_NUMBERED.match(ln)) > 60
    out = []
    for raw in lines:
        line = raw.rstrip("\n").replace("\f", "")
        line = line.translate(UNICODE_SPACES)
        if PAGE_RE.search(line) or RFC_HEADER_RE.match(line):
            out.append("")
            continue
        if numbered:
            line = LINE_NUMBERED.sub("", line, count=1)
        out.append(line)
    return out


def is_toc_line(line: str) -> bool:
    return bool(TOC_RE.search(line)) and bool(re.match(r"^\s*\d", line))


def parse_number(number: str) -> list[int] | None:
    try:
        return [int(part) for part in number.split(".")]
    except ValueError:
        return None


def is_successor(current: list[int], candidate: list[int]) -> bool:
    """True if ``candidate`` can plausibly follow ``current`` in a section tree.

    This is what separates a real heading from a numbered list item.  Inside
    section 4.3, a line reading "1.  There is not more than one DPoP header"
    looks exactly like a heading; it is rejected because 1 cannot follow 4.3.
    The same rule rejects "400  Bad Request" inside an example HTTP response.
    """
    if not candidate:
        return False
    # First child: 4.3 -> 4.3.1
    if candidate[:-1] == current and candidate[-1] == 1:
        return True
    # Sibling at some ancestor level: 4.3 -> 4.4, or 4.3 -> 5.
    # A small forward skip is tolerated because some documents omit a number.
    for level in range(len(candidate)):
        if candidate[:level] != current[:level]:
            continue
        if level < len(current) and len(candidate) == level + 1:
            if current[level] < candidate[level] <= current[level] + 3:
                return True
    return False


TOC_START_RE = re.compile(r"^\s*(Table of Contents|Contents|TABLE OF CONTENTS)\s*:?\s*$")


def title_key(title: str) -> str:
    """Normalize a heading title so a TOC entry and its body heading compare equal."""
    title = re.sub(r"(\.\s?){3,}.*$", "", title)      # dot leaders + page number
    title = re.sub(r"\s{2,}\d{1,4}\s*$", "", title)   # bare trailing page number
    title = re.sub(r"[^a-z0-9]+", "", title.lower())
    return title


def read_toc(lines: list[str]) -> tuple[set[tuple[str, str]], int]:
    """Collect the numbered entries of the table of contents.

    Modern RFCs (RFC 9449 among them) print the TOC with no dot leaders and no
    page numbers, so a TOC entry is byte-for-byte indistinguishable from the
    heading it points at.  Reading the TOC first and then accepting only body
    headings that appear in it resolves that ambiguity, and incidentally
    rejects every numbered list item in the document.
    """
    for i, line in enumerate(lines):
        if TOC_START_RE.match(line):
            break
    else:
        return set(), 0

    entries: set[tuple[str, str]] = set()
    misses = 0
    scanned = 0
    end = i
    for j in range(i + 1, min(len(lines), i + 700)):
        line = lines[j]
        if not line.strip():
            continue
        scanned += 1
        m = TOC_ENTRY.match(line)
        if m and parse_number(m.group(1)) is not None:
            entries.add((m.group(1), title_key(m.group(2))))
            end = j
            misses = 0
        else:
            misses += 1
            # Two consecutive non-entry lines of prose mean the TOC has ended.
            if misses >= 4:
                break
    # Some documents print the words "Table of Contents" immediately above the
    # body itself (FAPI 2.0 Message Signing does).  A real table is dense --
    # almost every line is an entry -- so prose between entries means this is
    # not one, and the successor heuristic should be used instead.
    if len(entries) < 3 or scanned == 0 or len(entries) / scanned < 0.6:
        return set(), 0
    return entries, end


def parse_sections(lines: list[str]) -> list[tuple[str, str, list[str]]]:
    """Split a document into (section_number, section_title, body_lines)."""
    toc, toc_end = read_toc(lines)

    sections: list[tuple[str, str, list[str]]] = [("0", "(front matter)", [])]
    current: list[int] = []
    for index, line in enumerate(lines):
        if index <= toc_end or is_toc_line(line):
            continue
        m = HEADING.match(line)
        if m and len(line) < 90 and not line.rstrip().endswith((",", ";", ":", ".")):
            number, title = m.group(1), m.group(2)
            parsed = parse_number(number)
            if parsed is not None and 1 <= len(title.split()) <= 14 and title[0].isupper():
                # With a TOC, membership in it is authoritative.  Without one,
                # fall back to the section-successor heuristic.
                accepted = (
                    (number, title_key(title)) in toc
                    if toc
                    else is_successor(current, parsed) and not KEYWORD_RE.search(title)
                )
                if accepted:
                    current = parsed
                    sections.append((number, title, []))
                    continue
        sections[-1][2].append(line)
    return sections


def paragraphs(body: list[str]) -> list[tuple[bool, str]]:
    """Reflow wrapped lines into (is_list_item, text) paragraphs.

    Whether a paragraph is a list item has to be decided here, while the raw
    line is still intact: joining the lines collapses the tab that marks an
    item in the converted W3C and OASIS documents.
    """
    paras: list[tuple[bool, str]] = []
    current: list[str] = []
    current_is_item = False

    def flush_current():
        if current:
            text = " ".join(current)
            text = re.sub(r"\s+", " ", text).strip()
            if text:
                paras.append((current_is_item, text))
            current.clear()

    for line in body:
        if not line.strip():
            flush_current()
            current_is_item = False
            continue
        # A new list item starts its own paragraph so that each bullet under a
        # "MUST ensure the following:" stem becomes its own requirement rather
        # than being glued into one blob.
        starts_item = bool(LIST_ITEM_RE.match(line))
        if starts_item and current:
            flush_current()
        if not current:
            current_is_item = starts_item
        current.append(line.strip())
    flush_current()
    return paras


# ISO-drafted specs enumerate obligations as "servers 1 shall do X; 2 shall do
# Y; 3 shall do Z".  The HTML original marks these up as list items; the text
# conversion flattens them onto one line, so they have to be split back apart or
# a dozen separate obligations are recorded as a single requirement.
ISO_CLAUSE_RE = re.compile(
    r"(?:(?<=[;:.])|(?<=,))\s+(?=\d{1,2}\s+(?:shall|should|must|may)\b)", re.IGNORECASE
)
ISO_ENUM_RE = re.compile(r"\s\d{1,2}\s+(?=(?:shall|should|must|may)\b)", re.IGNORECASE)

# In ISO/IEC drafting conventions a NOTE is informative, not normative.
ISO_NOTE_RE = re.compile(r"^(?:NOTE|EXAMPLE)\b\s*\d*\s*[:.]", re.IGNORECASE)


def split_iso_clauses(sentence: str) -> list[str]:
    """Split a flattened ISO enumeration, re-attaching the shared stem.

    "Authorization servers 1 shall do X; 2 shall do Y" becomes two requirements,
    each carrying the "Authorization servers" stem so it reads on its own.
    """
    parts = ISO_CLAUSE_RE.split(sentence)
    if len(parts) < 2:
        return [sentence]
    # The shared subject is whatever precedes the first enumerator, e.g.
    # "Authorization servers" in "Authorization servers 1 shall ...; 2 shall ...".
    head = ISO_ENUM_RE.search(parts[0])
    stem = parts[0][: head.start()].strip(" ;:,.") if head else ""
    if len(stem.split()) > 12:
        stem = ""
    out = [parts[0]]
    for part in parts[1:]:
        out.append(f"{stem} {part}" if stem else part)
    return out


def split_sentences(paragraph: str) -> list[str]:
    parts = SENTENCE_SPLIT.split(paragraph)
    out = []
    for part in parts:
        if part is None:
            continue
        part = part.strip()
        if part:
            out.append(part if part.endswith((".", ":", ";", "!", "?")) else part + ".")
    return out or [paragraph]


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def req_id(spec: str, section: str, text: str) -> str:
    digest = hashlib.sha1(normalize(text).encode("utf-8")).hexdigest()[:8]
    return f"{spec}#{section}#{digest}"


def strengths_in(text: str, keyword_re: re.Pattern = KEYWORD_RE) -> list[str]:
    found = []
    for m in keyword_re.finditer(text):
        s = STRENGTH[m.group(1).upper()]
        if s not in found:
            found.append(s)
    return found


def rank(strength: str) -> int:
    return {"MUST": 0, "MUST NOT": 1, "SHOULD": 2, "SHOULD NOT": 3}.get(strength, 9)


def extract(spec_id: str, path: Path) -> list[dict]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    lines = strip_furniture(raw.splitlines())
    keyword_re = KEYWORD_RE_CI if ISO_CONVENTION_RE.search(raw) else KEYWORD_RE
    results: list[dict] = []
    seen: set[str] = set()

    for number, title, body in parse_sections(lines):
        pending_stem: str | None = None
        for is_item, para in paragraphs(body):
            if BOILERPLATE_RE.search(para):
                pending_stem = None
                continue

            # A bullet under a normative stem ("... MUST ensure the following:")
            # inherits the stem's obligation even though the bullet itself has
            # no keyword.  Each such bullet is a separately testable condition.
            if is_item and pending_stem and not keyword_re.search(para):
                text = f"{pending_stem} {para}"
                inherited = True
            else:
                text = para
                inherited = False

            if not keyword_re.search(text):
                if not is_item:
                    pending_stem = None
                continue

            units = [text] if inherited else split_sentences(text)
            units = [c for u in units for c in split_iso_clauses(u)]
            units = [u for u in units if not ISO_NOTE_RE.match(u.strip())]
            for unit in units:
                found = strengths_in(unit, keyword_re)
                if not found:
                    continue
                primary = sorted(found, key=rank)[0]
                if rank(primary) == 9:
                    continue
                clean = normalize(unit)
                if len(clean) < 25:
                    continue
                rid = req_id(spec_id, number, clean)
                if rid in seen:
                    continue
                seen.add(rid)
                results.append(
                    {
                        "req_id": rid,
                        "spec": spec_id,
                        "section": number,
                        "strength": primary,
                        "all_strengths": ",".join(sorted(found, key=rank)),
                        "section_title": normalize(title),
                        "text": clean,
                    }
                )

            # Remember a normative stem that introduces a list.
            if para.rstrip().endswith(":") and keyword_re.search(para) and not is_item:
                pending_stem = normalize(para)
            elif not is_item:
                pending_stem = None

    return results


COLUMNS = ["req_id", "spec", "section", "strength", "all_strengths", "section_title", "text"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="fail if the committed TSV is stale")
    ap.add_argument("--spec", help="print requirements for one spec id and exit")
    args = ap.parse_args()

    rows: list[dict] = []
    for entry in read_manifest():
        spec_id = entry["id"]
        path = REPO / entry["path"]
        if not path.exists():
            print(f"warning: missing {path}", file=sys.stderr)
            continue
        rows.extend(extract(spec_id, path))

    if args.spec:
        for r in rows:
            if r["spec"] == args.spec:
                print(f"[{r['strength']}] §{r['section']}  {r['text'][:160]}")
        return 0

    body = "\t".join(COLUMNS) + "\n"
    body += "".join("\t".join(r[c].replace("\t", " ") for c in COLUMNS) + "\n" for r in rows)

    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != body:
            print("specs/requirements.tsv is stale; run scripts/audit-normative.py", file=sys.stderr)
            return 1
        print(f"specs/requirements.tsv up to date ({len(rows)} requirements)")
        return 0

    OUT.write_text(body, encoding="utf-8")
    print(f"wrote {OUT.relative_to(REPO)} ({len(rows)} requirements)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
