# scripts/

Maintenance tools that are run by hand and whose output is **committed**. Nothing
here runs in CI or from `make` — the build consumes the checked-in results
(`specs/*.tsv`, `crates/vouch-server/data/*.mmdb`), not these scripts. Run them
from the repository root; each one resolves its own paths, so `scripts/foo.sh`
works from anywhere inside the checkout.

| Script | What it does | Writes |
|--------|--------------|--------|
| `refresh-specs.sh` | Re-fetch the cached specification corpus from upstream | `specs/` |
| `audit-normative.py` | Extract every normative statement from that corpus | `specs/requirements.tsv` |
| `audit-coverage.py` | Render the spec-coverage report | `specs/coverage-report.md` |
| `update-geoip.sh` | Download the MaxMind GeoLite2 databases | `crates/vouch-server/data/` |
| `ykman-clear-fido-credentials.sh` | Wipe a YubiKey's FIDO2 discoverable credentials | nothing (touches hardware) |

## Specification corpus

`specs/` holds the text of every specification Vouch implements so a normative
claim can be quoted from disk rather than from memory. `specs/manifest.tsv` is
the roster; the corpus is reproducible from it alone. See `specs/README.md` for
the file layout and fidelity rules.

### `refresh-specs.sh`

Walks each manifest row, fetches the URL, validates the response, converts
HTML/PDF sources to text, and rewrites the manifest with fresh hashes. Also
refreshes the per-RFC errata shards under `specs/rfc/errata/`.

```sh
scripts/refresh-specs.sh              # refresh anything that changed upstream
scripts/refresh-specs.sh --check      # report drift, write nothing, exit 1 if stale
scripts/refresh-specs.sh --reconcile  # list RFCs cited in source but not cached
```

Requires `curl`, `jq`, `shasum`, `perl`, `textutil` (macOS, for HTML), and
`pdftotext` (poppler, for PDF). Exits non-zero if any row was rejected.

RFCs are immutable, but OpenID specs are republished in place under the same URL
— OIDC Core changed on 2023-12-16 for errata set 2 — so a periodic `--check` is
worth running even when nothing looks stale.

To add a spec, append a manifest row with `id`, `title`, `url`, `fidelity` and
`path`, leave the four provenance columns as `-`, and re-run the refresh.

### `audit-normative.py` and `audit-coverage.py`

`audit-normative.py` skips sections whose title is a reference list,
acknowledgements or a changelog appendix — they carry no obligation but their
prose reproduces requirement keywords — then reflows the cached prose and emits
one row per normative
statement (MUST / MUST NOT / SHOULD / SHOULD NOT — `MAY` and `OPTIONAL` are
excluded by design, since the audit tracks obligations).

```sh
scripts/audit-normative.py                 # regenerate specs/requirements.tsv
scripts/audit-normative.py --check         # exit 1 if the committed TSV is stale
scripts/audit-normative.py --spec rfc9449  # print one spec's requirements
```

`audit-coverage.py` renders `specs/coverage-report.md` from four committed
files — `requirements.tsv`, `audit-scope.tsv`, `audit-exclusions.tsv`, and
`coverage-baseline.tsv`. It
does **not** scan the test suite: the scan and the ratchet live in
`crates/vouch-tests/tests/spec_coverage.rs`, which owns the baseline it checks.
A second implementation here drifted from it by 627 statements before the two
were split apart.

```sh
scripts/audit-coverage.py                  # write specs/coverage-report.md
scripts/audit-coverage.py --json           # machine-readable summary
scripts/audit-coverage.py --spec rfc9449   # gaps for one specification
```

Because the baseline sits between them, regenerate in this order — anything else
produces a report that disagrees with the gate:

```sh
scripts/audit-normative.py
UPDATE_SPEC_COVERAGE_BASELINE=1 cargo test -p vouch-tests --test spec_coverage
scripts/audit-coverage.py
```

## `update-geoip.sh`

Downloads the latest GeoLite2-Country and GeoLite2-ASN databases, verifies the
published SHA-256 for each archive, and writes the `.mmdb` files into
`crates/vouch-server/data/`.

```sh
scripts/update-geoip.sh
```

Needs a free MaxMind account — sign up at
<https://www.maxmind.com/en/geolite2/signup> — and `MAXMIND_ACCOUNT_ID` plus
`MAXMIND_LICENSE_KEY` in the environment or in the repo-root `.env`, which the
script loads if present. Requires `curl` and `tar`.

`crates/vouch-server/src/geo.rs` pulls both databases in with `include_bytes!`,
so an update only takes effect after rebuilding the server, and the refreshed
`.mmdb` files are committed like any other source change.

## `ykman-clear-fido-credentials.sh`

Deletes **every** FIDO2 discoverable credential on the attached YubiKey — for
resetting a development key between enrollment runs, not for a key in real use.

```sh
scripts/ykman-clear-fido-credentials.sh
```

Prompts for the FIDO2 PIN, lists what it found, and asks once for confirmation
before deleting. It removes credentials for all relying parties on the key, not
just Vouch's, and there is no undo. Requires `ykman`
(`brew install ykman`).
