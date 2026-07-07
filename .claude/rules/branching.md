# Git Branching

Branch naming conventions for Vouch.
This file is read by `/rust-agents:solve-issue` to derive branch names from GitHub issues.

## Branch Naming

Branch names mirror the Conventional Commit type of the work (see `commits-and-issues.md`).

- Features: `feat/{issue-number}-{feature-slug}`
- Bug fixes: `fix/{issue-number}-{short-slug}`
- Hotfixes: `hotfix/{issue-number}-{short-slug}`
- Other (docs/ci/chore/refactor): `{type}/{issue-number}-{short-slug}`
- If no issue exists, omit the issue-number segment: `feat/{feature-slug}`
- Examples: `feat/567-rp-initiated-logout`, `fix/58-dsql-retry`, `docs/env-vars`

## Workflow

- **Never push directly to `main`.** All changes land via feature branch + PR.
- For each new issue, use `/rust-agents:solve-issue <number>` to create a branch and start development.
- One writer at a time in the main checkout. Agents editing **in parallel** must each use their own worktree (`wt switch <branch>`). Before reassigning in-flight work in the main checkout, stand the old agent down and snapshot the diff first (see `development-discipline.md`).
- PRs are squash-merged; the PR title becomes the Conventional Commit subject (e.g. `feat(cli): pre-fill device code (#566)`).

## Before Creating a PR

Run the project gates from the workspace root (all are `make` targets):

```bash
make fmt        # cargo +nightly fmt — ALWAYS run before pushing; never a follow-up commit
make lint       # cargo clippy --all-targets --all-features -- -D warnings (zero warnings)
make test       # unit tests (--all-features; covers feature-gated middleware/tests)
prek run        # git hooks (formatting, lint, secrets)
```

When the change touches cross-crate behavior or the server API/DB, also run:

```bash
make test-integration   # vouch-tests crate (integration + property-based)
make audit              # cargo-deny: advisories, licenses, bans (dependency changes)
```

Project-specific gates:

- **No-panic policy** — clippy denies `unwrap`/`expect`/`panic`/`[]` indexing/`as` casts outside the `vouch-tests` crate. `make lint` must be clean.
- **Live-test credential/serialization paths** that unit tests can't catch — OIDC token issuance, FIDO2 assertion verification, RFC 9421 signing, DB migrations across SQLite/Postgres/DSQL.
- **i18n parity** — adding UI strings requires matching Fluent catalog entries; the completeness tests fail otherwise.
- **No internal review labels** in code, comments, or test names — sweep changed files with `rg -n '\b([A-Z]{1,4}[0-9]{1,2}|GAP[0-9]+)\b'` before committing (CLAUDE.md "What NOT to Do" #11).
- Update `docs/` (mdBook) when server behavior or environment variables change. `docs/` is **internal system-administrator documentation** — how to run and operate the Vouch server — not public-facing or end-user documentation; write it for the operator, not the customer. There is **no `CHANGELOG.md`** in this repo — do not add one.
