# Commit Messages and Issue Guidelines

This file is read by `rust-team`, `rust-code-reviewer`, and `/rust-agents:solve-issue`.

## Commit Message Format

Follow the [Conventional Commits 1.0.0 specification](https://www.conventionalcommits.org/en/v1.0.0/#specification).

### Structure

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Rules

1. Every commit MUST have a type prefix followed by a colon and space.
2. `BREAKING CHANGE:` footer or `!` after the type/scope signals a breaking change.
3. Description uses imperative, present tense, no trailing period, ≤72 chars.
4. Body and footers are separated from the description by a blank line.
5. `fix` → **PATCH**, `feat` → **MINOR**, `BREAKING CHANGE` → **MAJOR**.
6. End commit messages with the trailer (per this repo's convention):
   `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`

### Allowed Types

| Type | Semver | Use for |
|------|--------|---------|
| `feat` | MINOR | New user-visible feature |
| `fix` | PATCH | User-visible bug fix |
| `docs` | — | Documentation only (`docs/`, README, mdBook) |
| `style` | — | Formatting, whitespace — no logic change |
| `refactor` | — | Code restructure without behavior change |
| `test` | — | Adding or correcting tests |
| `build` | — | Build system, Makefile, Docker, dependency updates |
| `ci` | — | GitHub Actions / CI pipeline changes |
| `perf` | — | Performance improvement |
| `chore` | — | Housekeeping (version bumps, lock files, release prep) |

### Scopes

Scopes are optional but used widely in this repo. Prefer a crate or subsystem noun:

`cli`, `agent`, `server`, `common`, `httpsig`, `i18n`, `ui`, `test`, `db`, `oidc`, `fido2`, `ssh`, `scim`, `deps`

Examples from history: `feat(cli):`, `feat(server):`, `feat(httpsig):`, `feat(ui):`, `fix(server):`, `refactor(test):`.

### Examples

```
feat(cli): pre-fill device code

fix(server): retry DSQL writes on OCC conflict

docs: update environment-variables reference

chore: release prep
```

### Anti-patterns

- Do not use past tense: ~~"added support"~~ → `feat: add support`
- Do not use vague types: ~~`update: ...`~~ — pick a specific type from the table
- Do not use emoji in commit messages
- Do not use language like "critical", "comprehensive", "robust" — a fix is a fix

## Issue Guidelines

### Labels

This repo uses category + component labels (there is **no P0–P4 priority scheme**).

**Category** — pick one: `bug`, `enhancement`, `feature`, `documentation`, `architecture` (structural/architectural debt), `code-quality` (findings from audits), `question`.

**Component** — add all that apply: `server`, `cli`, `agent`, `windows`, `docker`, `rust`.

**Lifecycle** — applied during triage: `duplicate`, `wontfix`, `invalid`, `good first issue`, `help wanted`.

Dependency/CI bots use `dependencies` and `github_actions`.

### Filing Protocol

1. **Reproduce** — confirm the issue is consistent, not a one-off fluke.
2. **Check duplicates** before filing:
   ```bash
   gh issue list --state open --limit 100 --json number,title,labels
   ```
3. **File** via `gh issue create` with a category label, the relevant component label(s), and the body template below.
4. **Link** related issues when they share a root cause.

### Issue Title Conventions

- Describe the problem, not the fix: `parser crashes on empty input` not `fix parser crash`
- Lowercase, no trailing period; mention the affected crate/subsystem when helpful.

### Issue Body Template

```markdown
## Description
[What happened and why it matters]

## Reproduction Steps
1. [Step one]
2. [Step two]
3. Observe: [...]

## Expected Behavior
[What should happen]

## Actual Behavior
[What actually happened]

## Environment
- Version: [project version or commit]
- Crate/feature flags: [e.g. vouch-server, yubikey-tests]
- Backend (if DB-related): SQLite / PostgreSQL / Aurora DSQL

## Logs / Evidence
[Relevant excerpts]
```

### Triage Rules

- Issues labeled `wontfix`, `duplicate`, or `invalid` are skipped in future cycles.
- When a previously filed issue is no longer reproducible, add a comment with the verification result.
- After a fix lands, re-run the original scenario and update the issue.
