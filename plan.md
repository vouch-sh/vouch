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
- `crates/vouch-cli/src/config.rs` — add `codeartifact` field to `Config`/`ConfigFile`
- `crates/vouch-cli/src/commands/setup/codeartifact.rs` — save config during setup
- `crates/vouch-cli/src/commands/credential/codeartifact.rs` — load defaults when flags omitted

**What:** When the user runs `vouch setup codeartifact`, save the domain/domain-owner/region
settings into the existing `~/.vouch/config.json` file under a `codeartifact` key.

**Config format (in `~/.vouch/config.json`):**
```json
{
  "server_url": "https://vouch.example.com",
  "token": "eyJ...",
  "email": "alice@example.com",
  "codeartifact": {
    "domain": "my-domain",
    "domain_owner": "123456789012",
    "region": "us-east-1"
  }
}
```

**Changes to `Config` struct:**
```rust
pub struct Config {
    server_url: Option<String>,
    token: Option<SecretString>,
    email: Option<String>,
    codeartifact: Option<CodeArtifactDefaults>,  // NEW
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CodeArtifactDefaults {
    pub domain: Option<String>,
    pub domain_owner: Option<String>,
    pub region: Option<String>,
}
```

**CLI changes:**
- `vouch credential codeartifact` — make `--domain`, `--domain-owner`, `--region` optional.
  If omitted, load from `config.codeartifact`. Error with helpful message if neither flags
  nor config are present.
- `vouch setup codeartifact` — save CodeArtifact defaults to config after successful setup.
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

### 4. `vouch exec` and `vouch env` support for CodeArtifact

**Files:**
- `crates/vouch-cli/src/commands/exec.rs` — add `Codeartifact` variant to `CredentialType`
- `crates/vouch-cli/src/commands/env.rs` — add `Codeartifact` variant to `CredentialType`
- `crates/vouch-cli/src/main.rs` — add `--domain`, `--domain-owner`, `--region` flags to exec/env

**What:** Add CodeArtifact as a credential type to the existing `vouch exec` and `vouch env`
commands, which already support AWS and GitHub credentials.

**Usage:**
```bash
# Inject CODEARTIFACT_AUTH_TOKEN into a subprocess
vouch exec --type codeartifact -- pip install my-package

# With explicit domain (overrides config defaults)
vouch exec --type codeartifact --domain my-domain --domain-owner 123456789012 --region us-east-1 -- pip install my-package

# Export for shell eval
eval "$(vouch env --type codeartifact --shell bash)"
# → export CODEARTIFACT_AUTH_TOKEN='eyJ...';
```

**How:**
- Add `Codeartifact` to the `CredentialType` enum in both `exec.rs` and `env.rs`
- When type is `Codeartifact`, load domain/owner/region from flags or config defaults
- Call `codeartifact::get_token()` (benefits from caching in step 1)
- Inject/export `CODEARTIFACT_AUTH_TOKEN` environment variable

**Why:** Reuses the existing credential injection infrastructure. No new `--export` flag
needed on the codeartifact command — `vouch exec` and `vouch env` already handle shell
quoting, caching, and multiple shell formats.

---

### 5. Additional package manager setup support

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
4. **`vouch exec`/`vouch env` for CodeArtifact** (step 4) — Extends existing infra, small change
5. **Additional package managers** (step 5) — Poetry first, then Maven, then others

## Files Changed Summary

| File | Change |
|------|--------|
| `crates/vouch-cli/src/commands/credential/codeartifact.rs` | Add caching, load config defaults |
| `crates/vouch-cli/src/commands/credential/pip.rs` | **New** — pip keyring credential helper |
| `crates/vouch-cli/src/commands/credential/mod.rs` | Add `pip` module |
| `crates/vouch-cli/src/config.rs` | Add `codeartifact` field to `Config`/`ConfigFile` |
| `crates/vouch-cli/src/commands/setup/codeartifact.rs` | Update pip setup, add Poetry/Maven, save config defaults |
| `crates/vouch-cli/src/commands/exec.rs` | Add `Codeartifact` variant, inject `CODEARTIFACT_AUTH_TOKEN` |
| `crates/vouch-cli/src/commands/env.rs` | Add `Codeartifact` variant, export `CODEARTIFACT_AUTH_TOKEN` |
| `crates/vouch-cli/src/main.rs` | Wire up pip credential command, add CA flags to exec/env |

## Testing Strategy

- Unit tests for config parsing/serialization with `codeartifact` field
- Unit tests for pip keyring protocol parsing in `pip.rs`
- Existing tests continue to pass (credential URL parsing, Cargo protocol, etc.)
- Manual testing with actual CodeArtifact repositories for each package manager

## Security Considerations

- All tokens continue to use `SecretString` / `ZeroizeOnDrop`
- CodeArtifact defaults in `~/.vouch/config.json` contain no secrets (just domain/owner/region)
- pip config files written with 0o600 permissions (existing pattern)
- Cached tokens in agent memory are `CachedCredential` with `SecretString` data field
- `vouch exec` and `vouch env` already handle shell injection protection (single-quoting)
- No new dependencies required
