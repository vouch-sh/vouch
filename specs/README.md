# Cached specifications

The text of every specification Vouch implements, cached in-tree so it can be
grepped instead of re-fetched.

Vouch implements ~100 normative documents and is OpenID Certified for the FAPI
2.0 OP Security Profile. `.claude/rules/specs-are-source-of-truth.md` requires
every normative claim to carry a section number, a verbatim quote, and a source
— and re-fetching those quotes through a summarizer is unreliable. Three fetches
of the same RFC sentence have returned three different wordings, which is how a
FAPI §5.2.2 mis-citation ended up replicated across ~30 sites (vouch#1009).

A cached corpus makes quotes byte-verifiable and gives every worktree and CI job
the same text.

## Layout

| Path | Contents |
|---|---|
| `manifest.tsv` | The roster — one row per document |
| `rfc/rfcNNNN.txt` | IETF RFCs, verbatim |
| `rfc/errata/rfcNNNN.json` | Errata for that RFC, when any exist |
| `ietf-drafts/` | Internet-Drafts, verbatim, pinned to a revision |
| `openid/` | OpenID Connect and OAuth extension specs |
| `w3c/` | WebAuthn, XML Signature, Exclusive C14N |
| `fido/` | CTAP |
| `oasis/` | SAML 2.0 |

## Verbatim vs converted

**Verbatim** files (`rfc/`, `ietf-drafts/`, and the `.txt` entries in `openid/`)
are byte-identical to their origin. Verify one at any time:

```sh
shasum -a 256 specs/rfc/rfc9449.txt
awk -F'\t' '$1=="rfc9449"{print $5}' specs/manifest.tsv
```

Those two hashes match, and both match a fresh `curl | shasum` of the origin
URL. Quoting from a verbatim file is equivalent to quoting from the source.

**Converted** files carry a `CACHED SPEC - CONVERTED, NOT AUTHORITATIVE` banner
recording the origin URL, the origin byte count, and the sha256 of the *source*
bytes. W3C, FIDO, and OASIS publish no plain text — WebAuthn and CTAP are HTML
only, SAML is PDF only — so those bodies are converted with `textutil` or
`pdftotext -layout`. Section numbering and prose survive; exact formatting does
not. Use a converted file to locate a passage, then confirm a load-bearing quote
against the banner's Source URL.

The `origin_sha256` column always covers the *origin* bytes, never the converted
output, so a converted file can still be checked for upstream drift.

## Errata

RFC text is frozen at publication, so a Verified erratum can change what a
document requires. `rfc/errata/rfcNNNN.json` exists only for RFCs that have
errata:

```sh
jq -r '.[] | select(.errata_status_code=="Verified")
       | "\(.section)\t\(.orig_text[0:60])"' specs/rfc/errata/rfc9449.json
```

## Normative coverage audit

Four further files turn the corpus into a coverage audit of the test suite:

| Path | Contents |
|---|---|
| `requirements.tsv` | Every MUST / MUST NOT / SHOULD / SHOULD NOT statement, one per row |
| `audit-scope.tsv` | Whether each spec imposes obligations on Vouch, with a reason |
| `audit-exclusions.tsv` | Sections of an in-scope spec that Vouch does not owe, with a reason |
| `coverage-baseline.tsv` | The statements with no citing test -- the accepted backlog |
| `coverage-report.md` | Per-spec summary rendered from the four above |

A statement counts as covered when a test function names its spec and section
in a comment or assertion message, e.g. `// RFC 9421 §2.1.4: ...`. Linkage is
section-level and deliberately optimistic: it establishes that a statement is
untested, not that a cited one is tested well.

`crates/vouch-tests/tests/spec_coverage.rs` owns the scan and gates it as a
ratchet -- the existing backlog is tolerated, but a statement that loses its
citing test fails the build, and a statement that gains one fails until the
baseline is pruned, so the backlog can only shrink.

### Scope and exclusions

The two scope files answer different questions, and keeping them apart is what
stops the backlog filling with work nobody owes.

`audit-scope.tsv` is per specification: does this document impose obligations
on Vouch at all? A `reference` spec is cited for a constant or a definition and
contributes nothing.

`audit-exclusions.tsv` is per section of a spec that *is* in scope. A section
is excluded when its requirements are addressed to an actor Vouch is not, or
cover a feature Vouch does not implement by design -- RFC 6265 section 5 is the
browser-side cookie algorithm and Vouch is a server; RFC 9700 section 4.14 is
refresh token replay detection and Vouch issues no refresh tokens. An excluded
statement is not untested, it is *not owed*, so it never enters the denominator
and never reaches the backlog.

A prefix covers everything beneath it: `4` covers 4, 4.8 and 4.8.1, but not 40.

Two rules stop the file becoming a place to park work, both enforced by the
gate:

* an exclusion that matches no statement fails -- a re-cached spec renumbers
  its sections, and a stale exclusion would silently stop covering anything;
* an excluded section that a test cites fails -- the exclusion says there is no
  obligation while a test asserts behavior, so a human has to say which is
  wrong.

Prefer an exclusion with a reason over a test that pins behavior Vouch does not
have. Prefer a test over an exclusion whenever the obligation is real.

Regenerate all of it, in this order:

```sh
scripts/audit-normative.py
UPDATE_SPEC_COVERAGE_BASELINE=1 cargo test -p vouch-tests --test spec_coverage
scripts/audit-coverage.py
```

The extractor skips sections whose title is a reference list, an
acknowledgements roll or a changelog appendix: they carry no obligation but
their prose reproduces requirement keywords, and RFC 9325's "Differences from
RFC 7525" appendix alone contributed 16 statements of the form "Added TLS 1.3
at a 'SHOULD' level", which describe a requirement level rather than stating
one.

Known limitation: a nested enumeration collapses to its outer item. FAPI 2.0
section 5.4.1 lists "1 adhere to [RFC8725]; 2 use PS256, ES256, or EdDSA; 3
not use the none algorithm" under an outer item, and those three are recorded
as one statement rather than three.

## Refreshing

```sh
scripts/refresh-specs.sh              # refresh anything that changed upstream
scripts/refresh-specs.sh --check      # report drift, write nothing, exit 1 if stale
scripts/refresh-specs.sh --reconcile  # RFCs cited in code but not cached
```

Requires `curl`, `jq`, `shasum`, `perl`, `textutil` (macOS, for HTML), and
`pdftotext` (poppler, for PDF).

RFCs are immutable, but OpenID specs are **republished in place** — OIDC Core
changed on 2023-12-16 for errata set 2 under the same URL — so a periodic
`--check` is worth running.

Like `scripts/update-geoip.sh`, this is a refresh tool whose output is committed
rather than something the build runs — nothing in CI or `make` invokes it.
**`manifest.tsv` is the roster, not an output**: the corpus is reproducible from
the manifest alone.

## Adding a spec

Append a row to `manifest.tsv` with the first four columns and the path, leaving
the four provenance columns as `-`, then run the refresh:

```
id <TAB> title <TAB> url <TAB> verbatim|converted <TAB> - <TAB> - <TAB> - <TAB> - <TAB> specs/rfc/rfc1234.txt
```

Set `fidelity` to `verbatim` only when the origin serves `text/plain`; the
script rejects the row otherwise. Prefer a plain-text origin where one exists:
`rfc-editor.org` serves `.txt` for every RFC, and `openid.net` serves `.txt` for
the OIDC family (swap `.html` → `.txt`).

Take the `title` from the document itself rather than writing one from memory.

## Version pinning

Cached versions mirror what the code implements, not the newest published.
CTAP is pinned at **2.0 PS (2019-01-30)** and WebAuthn at **Level 2** because
that is what Vouch implements and is certified against; CTAP 2.3 and WebAuthn
Level 3 exist and differ substantially. Internet-Drafts are pinned to an
explicit revision for the same reason. Changing a pin is a deliberate decision:
edit the row's `url` and `path` together.

## Gotchas the refresh script guards against

These are live behaviors of the origins, each of which would otherwise be cached
as if it were spec text:

- **openid.net answers 404 with a 122 KB HTML body**, and OASIS answers 404 with
  41 KB. A body-size check alone would accept both.
- **openid.net answers 200 with a 605-byte meta-refresh stub** for renamed FAPI
  specs — `fapi-2_0-security-profile.html` is a redirect page, not the spec. The
  real document is at `fapi-security-profile-2_0-final.html`.
- **There is no per-RFC errata endpoint.** `/api/v1/errata/?rfc=N` is 404 and
  `errata_search.php` ignores `&format=csv`. The script fetches the global dump
  once and shards it in a single pass.

A rejected row keeps its existing file and manifest values, so one bad origin
cannot corrupt the corpus. The script exits non-zero if anything was rejected.

## Hygiene

`specs/` is excluded from prek in `.pre-commit-config.yaml`. This is load-bearing:
`trailing-whitespace`, `end-of-file-fixer`, and `mixed-line-ending` all auto-fix,
and would rewrite the bytes that verbatim fidelity depends on. `.gitattributes`
marks the corpus `-diff linguist-generated=true` so it stays out of code review,
with `manifest.tsv` and this README exempted so roster changes remain visible.
