# CodeArtifact Native Support — Implementation Plan

## Goal

Bring CodeArtifact integration to the same level of native, frictionless experience as
CodeCommit. After the recent CodeCommit PR removed the AWS CLI dependency and added
transparent credential helpers, CodeArtifact is the next service that can benefit from
similar treatment.

## Current State

CodeArtifact already has no AWS CLI dependency — it calls STS and the CodeArtifact API
directly using the shared SigV4 signing utilities. However, significant friction remains:

| Area | CodeCommit (ideal) | CodeArtifact (current) |
|------|--------------------|------------------------|
| Token lifecycle | Signed on-demand per git op | pip/npm: static token expires in ~12h |
| Credential caching | Via agent (`aws:{role_arn}`) | None — fresh STS + CA API call every time |
| Setup parameters | `vouch setup codecommit --configure` | 5 required flags: `--tool --domain --domain-owner --region --repository` |
| Package managers | N/A (git only) | Cargo (dynamic), pip/npm (static only) |
| Additional tools | N/A | No Maven, NuGet, Go, Poetry support |

## Changes

### 1. Agent credential caching for CodeArtifact tokens

**Files:**
- `crates/vouch-cli/src/commands/credential/codeartifact.rs`

**What:** Wrap the `get_token()` flow with the existing `cache::get_or_fetch()` pattern,
exactly like CodeCommit and `vouch credential aws` already do.

**How:**
- Cache key: `codeartifact:{domain}:{domain_owner}:{region}` (more specific than the STS
  `aws:{role_arn}` key since different domains produce different tokens)
- Cache the full `CodeArtifactToken` (authorization_token + expiration) as JSON
- Expiration: derive from the `CodeArtifactToken.expiration` Unix timestamp
- Falls back to cache on network errors (existing `get_or_fetch` behavior)

**Why:** CodeArtifact tokens are valid for ~12 hours. Currently every `cargo build`,
every pip install, every npm install triggers a full OIDC → STS → CodeArtifact API
roundtrip (3 network calls). With caching, subsequent calls within the token lifetime
return instantly from the agent.

**Impact on Cargo:** The Cargo credential provider in `cargo.rs` calls
`codeartifact::get_token()` — it automatically benefits from caching with zero changes.

---

### 2. Profile-based CodeArtifact defaults (reduce parameter burden)

**Files:**
- `crates/vouch-cli/src/integrations/aws/codeartifact.rs` — add `CodeArtifactConfig` struct and persistence
- `crates/vouch-cli/src/commands/setup/codeartifact.rs` — save config during setup
- `crates/vouch-cli/src/commands/credential/codeartifact.rs` — load defaults when flags omitted

**What:** When the user runs `vouch setup codeartifact`, save the domain/domain-owner/region
settings so subsequent commands can use them as defaults. Store in `~/.vouch/codeartifact.toml`.

**Config format:**
```toml
# Saved by `vouch setup codeartifact`
domain = "my-domain"
domain_owner = "123456789012"
region = "us-east-1"
```

**CLI changes:**
- `vouch credential codeartifact` — make `--domain`, `--domain-owner`, `--region` optional.
  If omitted, load from saved config. Error with helpful message if neither flags nor config
  are present.
- `vouch setup codeartifact` — save config after successful setup.
- Saved config also read by Cargo credential provider when detecting CodeArtifact URLs
  (no change needed there since it parses the URL directly).

**Why:** After initial `vouch setup codeartifact --tool pip --domain X --domain-owner Y
--region Z --repository R`, refreshing the pip token becomes just
`vouch setup codeartifact --tool pip --repository R` (or even shorter with repository
defaults per tool).

---

### 3. pip credential helper via `keyring` protocol

**Files:**
- `crates/vouch-cli/src/commands/credential/pip.rs` (new)
- `crates/vouch-cli/src/commands/credential/mod.rs` — add `pip` module
- `crates/vouch-cli/src/main.rs` — wire up `vouch credential pip` command
- `crates/vouch-cli/src/commands/setup/codeartifact.rs` — update pip setup to use keyring

**What:** pip supports the `keyring` CLI protocol for dynamic credential lookup. When
configured, pip calls `keyring get <service_url> <username>` before each HTTP request.
We implement this protocol so pip can fetch fresh CodeArtifact tokens transparently.

**pip keyring protocol:**
```
$ keyring get https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/pypi/my-repo/simple/ aws
<token printed to stdout>
```

pip invokes the keyring CLI, which we can replace with vouch:
```
$ vouch credential pip get <url> <username>
<token printed to stdout>
```

**Setup changes:** Instead of embedding a static token in `pip.conf`, the updated pip setup
writes:
```ini
[global]
index-url = https://aws@my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/pypi/my-repo/simple/
```

And creates a `keyring` wrapper script at `~/.local/bin/keyring` (or configures pip's
`keyring.backend`):
```bash
#!/bin/sh
exec vouch credential pip "$@"
```

Or uses pip's `--keyring-provider subprocess` with a direct vouch invocation.

**How the credential flow works:**
1. pip requests `https://aws@{ca_host}/pypi/{repo}/simple/`
2. pip calls keyring for the password for username `aws` at that URL
3. vouch parses the CodeArtifact URL, calls `get_token()` (with caching from step 1)
4. Returns the token to pip via stdout
5. pip uses it as the password — no expiry concerns

**Why:** Eliminates the 12-hour token expiry problem for pip. After setup, `pip install`
just works indefinitely (as long as the user has a valid vouch session).

---

### 4. npm credential helper via `_auth` + credential exec

**Files:**
- `crates/vouch-cli/src/commands/credential/npm.rs` (new)
- `crates/vouch-cli/src/commands/credential/mod.rs` — add `npm` module
- `crates/vouch-cli/src/main.rs` — wire up hidden `vouch credential npm` command
- `crates/vouch-cli/src/commands/setup/codeartifact.rs` — update npm setup

**What:** npm doesn't have a native credential provider protocol like Cargo or pip's
keyring. However, we can use a shell wrapper approach:

**Option A — `_authToken` script wrapper (recommended):**
Create a tiny shell script at `~/.local/bin/vouch-npm-token` that npm calls to get a
fresh token. Configure `.npmrc` to use it via npm's `tokenHelper` or by using npm's
`execpath` configuration.

Actually, npm does not natively support dynamic token helpers. The approach is:

1. Write a small shell wrapper that refreshes `.npmrc` before npm runs
2. Or configure npm to use a `preinstall`/`preresolve` lifecycle script

**Better approach — npm preauth wrapper:**
Instead of modifying npm internals, provide a `vouch credential npm refresh` command and
document its use. The setup command creates an npm lifecycle hook or shell alias:
```bash
alias npm='vouch credential npm refresh --quiet && command npm'
```

Or for project-level: add to `.npmrc`:
```
; Use vouch for authentication
```
And provide a simple `vouch npm` wrapper command that refreshes the token then delegates
to npm.

**Revised simpler approach:** Since npm lacks a dynamic credential protocol, the best
we can do without changing npm itself is:

1. **Auto-refresh on `vouch credential npm`**: A command that refreshes the `.npmrc` token
   in-place, designed to be run before npm operations
2. **Smart refresh in setup**: Only re-fetch the token if the current one is expired or
   about to expire (check the existing `.npmrc` for token expiry)
3. **Shell integration**: Provide an opt-in shell function that auto-refreshes:
   ```bash
   # Added to ~/.bashrc by `vouch setup codeartifact --tool npm --configure`
   npm() { vouch credential npm refresh --quiet 2>/dev/null; command npm "$@"; }
   ```

**Why:** While not as seamless as pip's keyring protocol, this still eliminates the
manual "re-run setup every 12 hours" workflow. The token refresh becomes automatic.

---

### 5. `CODEARTIFACT_AUTH_TOKEN` environment variable support

**Files:**
- `crates/vouch-cli/src/commands/credential/codeartifact.rs` — add `--export` flag

**What:** Add a `--export` flag to `vouch credential codeartifact` that outputs
shell-eval-friendly export statements:
```bash
$ vouch credential codeartifact --export
export CODEARTIFACT_AUTH_TOKEN=eyJ...
```

This is useful for:
- CI/CD scripts that set the env var for multiple tools
- Tools that check `CODEARTIFACT_AUTH_TOKEN` (AWS CLI, some SDK integrations)
- Shell initialization (e.g., in `.bashrc` or `.envrc`)

**Also support `--format` flag for flexible output:**
```bash
$ vouch credential codeartifact --format json
{"token": "eyJ...", "expiration": 1708189234}
```

---

### 6. Additional package manager setup support

**Files:**
- `crates/vouch-cli/src/commands/setup/codeartifact.rs` — add Maven, NuGet, Go, Poetry tools

**What:** Extend the `Tool` enum and setup logic for additional package managers:

#### a. Poetry (Python)
Poetry supports custom sources with token auth. Setup writes `~/.config/pypoetry/auth.toml`:
```toml
[http-basic.codeartifact]
username = "aws"
password = "<token>"
```
And configures the source in `pyproject.toml` or global config.

Like pip, Poetry also supports the keyring protocol — so the pip keyring helper from
step 3 works for Poetry too. Setup just needs to configure the source URL.

#### b. Maven
Maven reads credentials from `~/.m2/settings.xml`. Setup writes/updates the `<server>`
entry with the CodeArtifact token. Like npm, this is a static token but we can provide
a refresh command.

#### c. NuGet (.NET)
NuGet reads from `~/.nuget/NuGet/NuGet.Config`. Setup adds a `<packageSource>` with
credentials.

#### d. Go modules
Go module proxy auth uses `.netrc` or `GONOSUMCHECK`/`GONOSUMDB` + `GOPROXY`. Setup
configures `GOPROXY` to point to the CodeArtifact Go repository with auth.

**Priority:** Poetry and Maven are the highest priority since they're widely used.
NuGet and Go are lower priority.

---

## Implementation Order

1. **Agent credential caching** (step 1) — Immediate performance win, small change, benefits all tools
2. **Profile-based defaults** (step 2) — Reduces parameter burden for all subsequent work
3. **pip keyring helper** (step 3) — Highest-impact UX improvement (eliminates 12h expiry for pip)
4. **npm refresh command** (step 4) — Addresses npm's 12h expiry with best available approach
5. **Export flag** (step 5) — Small addition, useful for CI and scripting
6. **Additional package managers** (step 6) — Poetry first, then Maven, then others

## Files Changed Summary

| File | Change |
|------|--------|
| `crates/vouch-cli/src/commands/credential/codeartifact.rs` | Add caching, profile defaults, `--export` flag |
| `crates/vouch-cli/src/commands/credential/pip.rs` | **New** — pip keyring credential helper |
| `crates/vouch-cli/src/commands/credential/npm.rs` | **New** — npm token refresh command |
| `crates/vouch-cli/src/commands/credential/mod.rs` | Add `pip`, `npm` modules |
| `crates/vouch-cli/src/commands/setup/codeartifact.rs` | Update pip/npm setup, add Poetry/Maven, save config |
| `crates/vouch-cli/src/integrations/aws/codeartifact.rs` | Add `CodeArtifactConfig` persistence |
| `crates/vouch-cli/src/main.rs` | Wire up new credential commands, make CA flags optional |

## Testing Strategy

- Unit tests for config parsing/serialization in `codeartifact.rs`
- Unit tests for pip keyring protocol parsing in `pip.rs`
- Unit tests for npm token refresh logic in `npm.rs`
- Existing tests continue to pass (credential URL parsing, Cargo protocol, etc.)
- Manual testing with actual CodeArtifact repositories for each package manager

## Security Considerations

- All tokens continue to use `SecretString` / `ZeroizeOnDrop`
- Config file at `~/.vouch/codeartifact.toml` contains no secrets (just domain/owner/region)
- pip/npm config files written with 0o600 permissions (existing pattern)
- Cached tokens in agent memory are `CachedCredential` with `SecretString` data field
- No new dependencies required
