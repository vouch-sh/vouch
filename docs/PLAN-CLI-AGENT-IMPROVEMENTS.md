# vouch-cli & vouch-agent Improvement Plan

Based on analysis of the current codebase and research into what makes single-purpose
developer tools become trusted infrastructure (curl, age, direnv, ssh-agent, aws-vault).

The guiding principle: **Vouch should be the narrow waist between hardware keys and every
credential consumer.** The improvements below make that interface more reliable, more
composable, and more invisible.

---

## Priority 1: Reliability — Turn the agent into trusted infrastructure

These changes address the gap between "nice background process" and "something you forget
is running because it never breaks."

### 1.1 macOS LaunchAgent plist

**Gap:** The agent ships a systemd unit file (`packaging/vouch-agent.service`) but has no
macOS equivalent. macOS is a primary platform for developer tools.

**What to build:**
- Ship `com.vouch.agent.plist` in `packaging/` targeting `~/Library/LaunchAgents/`
- Use `KeepAlive: true` and `RunAtLoad: true` so the agent survives logout/crash/reboot
- The postinstall script should install the plist automatically (matching the systemd
  `enable --now` pattern already in `packaging/postinstall.sh`)

**Why it matters:** Without this, macOS users must manually start the agent after every
reboot. That friction means they stop using it.

### 1.2 Structured exit codes

**Gap:** Every CLI error exits with code 1. Scripts and `credential_process` consumers
cannot distinguish "session expired" from "YubiKey missing" from "network down."

**What to build:**
- Define an exit code enum in `vouch-cli/src/`:

  | Code | Meaning |
  |------|---------|
  | 0 | Success |
  | 1 | General/unknown error |
  | 2 | Not authenticated (session expired or missing) |
  | 3 | Hardware key not detected |
  | 4 | Network/server unreachable |
  | 5 | Permission denied / unauthorized |
  | 6 | Configuration error |

- Map `anyhow::Error` to the appropriate code in `main()` using a thin classification
  layer (inspect the error chain for known types like `AgentError::SessionExpired`,
  `AgentError::NotAuthenticated`, reqwest connection errors, etc.)
- Expose `vouch` exit codes in `--help` and a man page section

**Why it matters:** `credential_process` failures propagate through the AWS SDK as opaque
errors. Distinct exit codes let wrapper scripts retry on network errors but prompt
re-auth on expired sessions. The CLI Interface Guidelines (clig.dev) consider this
table stakes.

### 1.3 YubiKey wait timeout

**Gap:** `YubiKey::wait_for_device()` (`fido2.rs:204-230`) polls indefinitely with no
timeout. If a user runs `vouch login` without their key nearby, the CLI hangs forever.

**What to build:**
- Add a `--timeout` flag (default 60s) to `login` and `register` commands
- After the timeout, exit with code 3 (hardware key not detected) and a clear message:
  `"Timed out waiting for YubiKey. Insert your key and try again."`
- Keep the infinite-wait behavior available via `--timeout 0` for interactive use

### 1.4 `vouch doctor` exit code reflects check results

**Gap:** `vouch doctor` always returns `Ok(())` / exit 0, even when checks fail. CI
scripts and automation cannot use it as a gate.

**What to build:**
- Return exit code 1 if any check fails
- Add `--quiet` flag that suppresses output (for use in scripts that only care about the
  exit code)

---

## Priority 2: Composability — Make Vouch a proper UNIX building block

These changes implement the integration patterns that make authentication invisible.

### 2.1 `vouch exec` command

**Gap:** There is no way to run `vouch exec -- aws s3 ls` to inject credentials as
environment variables into a subprocess. This is the second most important integration
pattern after `credential_process` (used by aws-vault, saml2aws, `op run`).

**What to build:**
- `vouch exec [--profile PROFILE] -- <command> [args...]`
- Sets `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` in the child
  environment
- Supports `--credential-type aws|github` to control what gets injected
- For GitHub: sets `GITHUB_TOKEN` and `GH_TOKEN`
- The `--` separator convention clearly separates vouch args from the wrapped command
- Child process exit code passes through as vouch's exit code

**Why it matters:** `credential_process` covers AWS SDK consumers, but many tools read
environment variables directly (Terraform with certain providers, CI scripts, custom
tooling). `exec` is the universal adapter.

### 2.2 `--json` flag for machine-readable output

**Gap:** No command supports `--json`. Only `vouch credential aws` outputs JSON (because
the `credential_process` spec requires it). All other output is unstructured text.

**What to build:**
- Add `--json` to `status`, `keys`, `doctor`, and `diag`
- `vouch status --json` returns:
  ```json
  {
    "authenticated": true,
    "email": "user@example.com",
    "expires_at": "2024-01-15T18:30:45Z",
    "expires_in_seconds": 27000,
    "agent_running": true,
    "integrations": { "ssh": "configured", "aws": "configured", ... }
  }
  ```
- `vouch doctor --json` returns an array of check results with pass/fail/message
- stdout/stderr separation: JSON goes to stdout, diagnostics to stderr

**Why it matters:** Machine-readable output enables pipeline integration (`vouch status
--json | jq .expires_in_seconds`), monitoring dashboards, and shell prompt integrations.

### 2.3 `eval $(vouch env)` for shell integration

**Gap:** No way to export credentials as shell variables without subprocessing.

**What to build:**
- `vouch env [--credential-type aws|github] [--shell bash|zsh|fish]`
- Outputs `export VAR=value` statements for the detected or specified shell
- Can be used as `eval $(vouch env)` in scripts or shell rc files

**Why it matters:** Complements `exec` for cases where the user wants credentials in
their current shell rather than a subprocess. This is how `aws-vault` and `saml2aws`
work in interactive use.

### 2.4 Shell hook for auth status

**Gap:** No shell hook exists. Users have no ambient awareness of their auth state.

**What to build:**
- `vouch init <shell>` outputs a shell hook (like `eval "$(direnv hook bash)"`)
- The hook runs `vouch status --json` (or a faster agent IPC check) on each prompt
- Sets `VOUCH_AUTHENTICATED=1|0` and `VOUCH_EMAIL` and `VOUCH_EXPIRES_IN` environment
  variables
- Optionally sets `VOUCH_STATUS` for prompt customization (e.g., showing remaining time)
- Must be fast — the agent IPC round-trip (Unix socket, in-memory lookup) takes <1ms,
  so checking via the agent is acceptable on every prompt; skip the HTTP server call

**Why it matters:** direnv proved this pattern. Ambient awareness prevents the "why is my
deploy failing? oh, my session expired 2 hours ago" scenario.

---

## Priority 3: Credential management improvements

### 3.1 Agent-side credential caching for non-SSH credentials

**Gap:** SSH certificates are cached in the agent with lazy-loading and background
refresh. AWS, GitHub, Docker, and CodeArtifact credentials are stateless fresh-per-call
through the CLI with zero caching.

**Current state (for reference):**

| Credential | Cached? | Auto-refresh? | Offline? |
|------------|---------|---------------|----------|
| SSH cert | Agent + disk | Yes (30min before expiry) | Until cert expires |
| AWS STS | No (AWS SDK caches via `Expiration`) | No | No |
| GitHub token | No | No | No |
| Docker | No | No | No |
| CodeArtifact | No | No | No |

**What to build:**
- Add credential cache slots to `AgentState` for AWS and GitHub tokens
- New IPC methods: `get_aws_credentials`, `get_github_token` (alongside existing
  `get_session`, `store_ssh_credentials`)
- Cache with TTL based on the credential's own expiration (AWS STS tokens = 1h, GitHub
  installation tokens = 1h)
- Background refresh using the same pattern as SSH cert refresh (30 min before expiry,
  rate-limited to 5 min intervals)
- CLI checks agent cache first, falls back to fresh fetch on cache miss

**Why it matters:** For tools that invoke `credential_process` frequently (Terraform
running many AWS API calls, or `git fetch` on a repo with many submodules), the round-trip
through Vouch server + STS adds latency. Agent caching turns O(n) server calls into O(1).
The AWS SDK itself caches `credential_process` output in-process, but each new process
invocation (e.g., each Terraform provider process) starts cold.

### 3.2 Offline/degraded mode for cached credentials

**Gap:** If the Vouch server is unreachable, all credential commands except SSH fail
immediately. No retry, no cache fallback.

**What to build:**
- When the agent has cached credentials that are still valid (not expired), serve them
  even if the server is unreachable
- Log a warning: `"Serving cached credentials (server unreachable). Expires in Xm."`
- When credentials are expired AND server is unreachable, fail with a clear message:
  `"Credentials expired and server unreachable. Check your network and run 'vouch login'."`
- Add retry with backoff for transient network errors in background refresh (not in the
  hot path — the hot path serves from cache or fails fast)

### 3.3 Session expiry warnings

**Gap:** The session expires after 8 hours with no advance warning. Users discover this
when a credential command fails.

**What to build:**
- The agent monitors session expiry and emits a desktop notification (via `notify-rust`
  or macOS `osascript`) at configurable thresholds (e.g., 30 min and 5 min before expiry)
- The shell hook (2.4) provides ambient awareness as a complementary signal
- `vouch status` already shows remaining time — this is about proactive notification

---

## Priority 4: Error experience refinements

### 4.1 Server error message passthrough

**Gap:** Server API errors are shown as raw `"{code}: {message}"` strings
(`client.rs:200`). HTTP errors show `"server error ({status}): {error_text}"` which may
include HTML or opaque text.

**What to build:**
- Parse the server's `ApiError` JSON and present only the `message` field to users
- For HTTP errors with non-JSON bodies, show a generic message with the status code and
  a hint: `"Server returned {status}. Run 'vouch doctor' to check connectivity."`
- For connection-refused errors, suggest checking the server URL and network

### 4.2 `SuppressStdout` safety annotation

**Gap:** The `SuppressStdout` guard in `fido2.rs:50-104` uses `libc::dup`/`dup2` to
redirect fd 1. This is process-global and thread-unsafe. The code documents this
assumption but doesn't enforce it.

**What to build:**
- Add a `debug_assert!` or runtime check that the guard is only used from the main thread
- Alternatively, refactor to capture stdout at the `ctap-hid-fido2` crate level (upstream
  PR) or use `gag` crate which handles the platform-specific details more robustly
- At minimum, add a `// SAFETY:` comment block documenting the single-threaded invariant

---

## Priority 5: Testing and observability

### 5.1 End-to-end IPC integration tests

**Gap:** Unit tests exist for individual agent components, but there are no tests
exercising the full CLI → agent IPC flow. The `vouch-tests` crate focuses on server
integration tests.

**What to build:**
- Add tests in `vouch-tests/` that:
  - Start the agent in `--foreground` mode
  - Exercise the CLI commands against the agent (store session, get session, clear session)
  - Verify SSH agent protocol responses
  - Test the recovery flow (agent restart with persisted credentials)
- Use the existing `TestTransportPair` abstraction where possible, but also test real
  Unix socket communication

### 5.2 Agent audit log

**Gap:** The agent logs operational events via `tracing` but has no structured audit trail
of authentication events.

**What to build:**
- Emit structured JSON log lines for security-relevant events:
  - Session stored (login)
  - Session cleared (logout)
  - Session expired
  - SSH certificate provisioned
  - SSH signing operation performed
  - Credential served from cache
- Write to `~/.vouch/audit.log` (separate from the operational log)
- Keep it simple — a newline-delimited JSON file, not a database
- This composes with external log aggregation tools rather than building an audit UI

---

## Priority 6: Agent architecture hardening

### 6.1 Consolidate `SshAgentState` locks

**Gap:** `SshAgentState` uses four separate `RwLock` fields. Operations that read or
update multiple fields acquire multiple locks independently, risking inconsistent reads.

**What to build:**
- Refactor to a single `RwLock<SshAgentStateInner>` struct
- All reads/writes are atomic with respect to the full state
- Use `Arc<SshCredentials>` internally to avoid cloning the private key on the
  `REQUEST_IDENTITIES` hot path (`state.rs:86` currently deep-clones)

### 6.2 Graceful shutdown for SSH agent server

**Gap:** The SSH agent server loop (`ssh_agent/server.rs:51-66`) has no cancellation
mechanism. The main agent uses `tokio::select!` with signal handlers, but the SSH server
itself never checks for shutdown.

**What to build:**
- Pass a `CancellationToken` to the SSH agent server
- Select on both `listener.accept()` and the cancellation token
- On cancellation, stop accepting new connections and let in-flight connections drain

### 6.3 Wire format safety

**Gap:** `encode_string` (`wire.rs:79`) casts `bytes.len() as u32` which silently
truncates values > 4GB. This is extremely unlikely but inconsistent with the project's
strict safety standards.

**What to build:**
- Use `u32::try_from(bytes.len()).context("message too large")?` instead of `as u32`
- Same for `encode_bytes` at `wire.rs:87`

---

## What NOT to build

Guided by the research on scope discipline, these are explicit non-goals:

- **Secrets manager** — that's Vault, 1Password, AWS Secrets Manager
- **Full identity provider** — that's Okta, Auth0, Keycloak
- **Cloud IAM policy management** — that's AWS IAM, GCP IAM
- **Certificate authority UI** — the server has an SSH CA; keep it as an internal detail
- **Signing service** — even age excluded this deliberately
- **VPN/tunnel** — that's WireGuard, Tailscale
- **Configuration manager** — that's direnv, dotenv
- **Audit/compliance dashboard** — compose with external logging (5.2 provides the data)
- **Multi-key-type support beyond FIDO2** — YubiKey-only is a feature, not a limitation
- **Browser extension** — the enrollment flow already uses the browser; don't maintain a
  separate extension
- **GUI application** — the CLI and agent are the interface; a GUI adds maintenance
  burden without improving the core primitive

---

## Implementation order

The improvements are ordered by the ratio of user impact to implementation effort:

| Phase | Items | Rationale |
|-------|-------|-----------|
| **Phase 1** | 1.2 (exit codes), 1.3 (wait timeout), 1.4 (doctor exit code), 4.1 (error messages), 6.3 (wire safety) | Low effort, high reliability signal. Foundation for everything else. |
| **Phase 2** | 2.2 (`--json`), 1.1 (LaunchAgent plist), 2.1 (`vouch exec`) | Composability basics. `--json` unblocks shell hook and monitoring. LaunchAgent fixes macOS reliability. |
| **Phase 3** | 2.3 (`vouch env`), 2.4 (shell hook), 3.3 (expiry warnings) | Developer experience polish. Shell hook depends on `--json` from Phase 2. |
| **Phase 4** | 3.1 (credential caching), 3.2 (offline mode), 6.1 (state locks), 6.2 (graceful shutdown) | Agent architecture improvements. Credential caching is high value but higher effort. |
| **Phase 5** | 5.1 (IPC tests), 5.2 (audit log), 4.2 (stdout guard) | Testing and observability. Important but not user-facing. |
