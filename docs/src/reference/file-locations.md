# File Locations (CLI & Agent)

The `vouch` CLI and `vouch-agent` follow the
[XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/latest/).
Files are split by purpose across the standard base directories, and the
relevant `XDG_*` environment variables are honored on **all** platforms —
including macOS, where Vouch uses `~/.config` rather than
`~/Library/Application Support`, matching the convention of tools like `gh` and
`git`.

## Locations

| File | Purpose | Base directory (env → default) | Default path |
|------|---------|--------------------------------|--------------|
| `config.json` | CLI configuration, session token, OAuth/DPoP client metadata | `XDG_CONFIG_HOME` → `~/.config` | `~/.config/vouch/config.json` |
| `cookie.txt` | Netscape session cookie for `curl -b` usage | `XDG_STATE_HOME` → `~/.local/state` | `~/.local/state/vouch/cookie.txt` |
| `audit.log` | Agent security audit log (newline-delimited JSON) | `XDG_STATE_HOME` → `~/.local/state` | `~/.local/state/vouch/audit.log` |
| `client_key.json` | FAPI client key — **fallback only**; the OS keychain is the primary store | `XDG_DATA_HOME` → `~/.local/share` | `~/.local/share/vouch/client_key.json` |
| `agent.pid`, `agent.log` | Agent PID and daemon log | `XDG_CACHE_HOME` → `~/.cache` | `~/.cache/vouch/` |
| `agent.sock`, `ssh-agent.sock` | Agent IPC and SSH-agent Unix sockets | `XDG_RUNTIME_DIR` → cache fallback | `$XDG_RUNTIME_DIR/vouch/*.sock` |

All files written by Vouch are created with owner-only permissions (`0600` for
files, `0700` for directories) on Unix.

### Runtime sockets

Unix sockets live in `XDG_RUNTIME_DIR` — a private, user-owned, `0700` tmpfs
that the login session manager clears on logout. `XDG_RUNTIME_DIR` is only set
on Linux sessions managed by a login manager; on macOS and headless logins it
is absent, so Vouch falls back to a `0700` directory under the cache base
(`~/.cache/vouch`), chosen because its short path stays within the macOS
`sun_path` socket-path length limit.

## Migration from `~/.vouch/`

Earlier versions of Vouch stored everything flat under `~/.vouch/`. On the first
run of a newer `vouch` or `vouch-agent`, files found there
(`config.json`, `cookie.txt`, `audit.log`, `client_key.json`) are moved
automatically to their XDG locations, preserving permissions. The migration is
idempotent and prints a one-time notice. Sockets are not migrated — they are
recreated on demand.

One thing the migration cannot fix automatically: if you previously ran
`vouch setup ssh`, your `~/.ssh/config` may contain an `IdentityAgent` line
pointing at the old `~/.vouch/ssh-agent.sock`. Re-running `vouch setup ssh`
detects and rewrites that stale path to the new socket location.
