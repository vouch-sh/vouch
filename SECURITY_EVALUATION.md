# Security Evaluation — June 2026

A point-in-time security evaluation of the Vouch codebase, with a prioritized
remediation list. For the vulnerability disclosure policy, see
[SECURITY.md](SECURITY.md).

## Scope and Methodology

Source-level review of the full workspace at commit `ac57629`:

- **vouch-server** — OIDC/OAuth token issuance, DPoP, WebAuthn/FIDO2
  verification, crypto primitives (`jwt.rs`, `ssh_ca.rs`, `ber.rs`, `pem.rs`,
  `tpm_decrypt.rs`), session/cookie handling, SCIM, GitHub webhooks, admin
  APIs, database layer, TLS/headers/rate limiting, config loading.
- **vouch-cli / vouch-agent / vouch-common** — agent IPC (Unix socket,
  wire protocol), SSH agent protocol, token/secret storage, FAPI client
  (DPoP keys, HTTP client), enrollment/login flows, PIN handling, file
  writes, command execution.
- **Supply chain and operations** — workspace dependencies, `deny.toml`,
  CI workflows, Dockerfile, packaging scripts.

Each finding below was verified directly against the source; file and line
references are to commit `ac57629`.

## Posture Summary

**Overall posture: strong. No critical or directly exploitable
vulnerabilities were found.** The codebase shows deliberate security
engineering throughout:

- Algorithm-pinned JWT validation (ES256, `typ: at+jwt` per RFC 9068);
  no algorithm-confusion or `none` paths (`crypto/jwt.rs:384-411`).
- Atomic single-use enforcement for authorization codes, FIDO2 challenge
  states, and DPoP `jti` via deterministic-primary-key inserts with
  compile-time witness types (`db/challenge_states.rs`,
  `db/authorization_codes.rs`, `db/dpop.rs`).
- Constant-time comparisons (`subtle::ct_eq`) for every secret comparison
  found (DPoP nonce/`ath`, webhook HMAC); SCIM tokens compared via SHA-256
  hash lookup.
- Exact-match redirect URI validation, S256-only PKCE, PAR, FAPI 2.0 flows.
- Agent socket at 0600 in a 0700 directory with symlink-safe ownership
  validation and `SO_PEERCRED` UID checks; bounded wire protocol (1 MiB cap,
  checked arithmetic, no panics on untrusted input).
- Systematic `SecretString`/`Zeroizing` usage with redacted `Debug` impls;
  atomic 0600 file writes (`atomic_write_secure`).
- BCP 195 TLS via aws-lc-rs, strict CSP and security headers, GCRA rate
  limiting with trusted-proxy handling.
- Hash-pinned CI actions, `permissions: {}` workflows, distroless non-root
  containers, `cargo-deny` in release, workspace-wide deny lints on
  panics/unsafe/indexing/unchecked arithmetic.

## Prioritized Remediation List

> **Remediation status (update):** P1.1, P2.1, P2.2, P2.4, and P2.5 are
> resolved, and P3.5 (audit trail for clone detection) is addressed as part of
> P1.1. P2.3 was handled as **hardening only** (no activation guard): the
> certification/conformance test mode runs over TLS with self-signed certs, so
> gating it on `tls_configured()` — or a build flag — would break the very flow
> it exists for; instead the test-mode switch now emits loud `warn`-level
> security logs at startup and at router build, and its full blast radius
> (login bypass, rate-limiting disabled, IdP requirement relaxed) is documented
> at every touch point. P3.1–P3.4 remain open.

### P1 — High

#### P1.1 WebAuthn signCount clone-detection bypass — RESOLVED

`crates/vouch-server/src/crypto/webauthn_verify.rs:298`

```rust
// 5. Verify counter is increasing (if not zero - some authenticators don't use counters)
if counter != 0 && stored_counter != 0 && counter <= stored_counter {
    return Err(VerifyError::CounterNotIncreasing);
}
```

A cloned credential that reports `signCount = 0` bypasses clone detection
entirely, even when the stored counter is nonzero. WebAuthn Level 2 §6.1.1
treats `authData.signCount <= storedSignCount` as a cloning signal whenever
**either** value is nonzero; this check only fires when **both** are
nonzero. Because the stated threat model is YubiKey-only — and YubiKeys
always increment the signature counter — a zero counter arriving after a
nonzero stored value is unambiguous evidence of cloning or forgery, and is
currently accepted.

This check is in both live login paths:
`handlers/browser_login.rs:634-669` and
`services/oidc/fido2_grant.rs:267`.

**Remediation:** change the guard to
`if stored_counter != 0 && counter <= stored_counter` (a credential that
has ever reported a nonzero counter may never regress, including to zero),
emit a security audit event when it fires (see P3.5), and update the unit
tests in `webauthn_verify.rs` (~lines 1490–1770) to cover the
regression-to-zero case. Credentials that have only ever reported zero
(counter-less authenticators) remain accepted, preserving current
compatibility.

### P2 — Medium

#### P2.1 Agent IPC peer-credential check fails open — RESOLVED

`crates/vouch-agent/src/server.rs:94-97`

```rust
Err(e) => {
    // Best-effort: allow connection if peer creds unavailable
    debug!("Could not verify peer credentials: {e}");
}
```

If `get_peer_credentials()` errors, the connection is allowed with only a
debug log. The 0600 socket mode is the primary access gate, but the UID
check is the defense-in-depth layer against permission misconfiguration,
and on Linux (`SO_PEERCRED`) and macOS (`LOCAL_PEERCRED`) retrieval failure
is anomalous rather than expected.

**Remediation:** reject the connection on peer-credential failure on
platforms where retrieval is reliable; log at `warn` and emit a
`ConnectionRejected` audit event (the audit plumbing already exists at
`server.rs:86-90`).

#### P2.2 Localhost origin relaxation compiled into production WebAuthn verification — RESOLVED

`crates/vouch-server/src/crypto/webauthn_verify.rs:320-343`

Origin mismatches are tolerated whenever both the expected and presented
origins are loopback hosts, and ports are deliberately not compared. This
is only reachable when the server itself is configured with a loopback
origin, so a correctly configured production deployment is unaffected —
but nothing prevents a misconfigured deployment (loopback `rp_id` behind a
reverse proxy) from silently weakening origin binding, and the relaxation
is logged only at `debug`.

**Remediation:** gate the relaxation on an explicit development-mode
config flag (or `#[cfg(debug_assertions)]`), and raise the log to `warn`
so any production use is visible.

#### P2.3 Certification test endpoint enabled by a runtime environment variable — HARDENED

`crates/vouch-server/src/infra/router.rs:140-157`

Setting `VOUCH_CERTIFICATION_TEST_TOKEN` activates
`GET /certification/complete-login` in any build, including release
binaries. A leaked or mistakenly set environment variable in production
enables a login-bypass-shaped endpoint, with only a startup warning log as
the guard.

**Remediation:** move the endpoint behind a compile-time cargo feature
excluded from release builds; at minimum, refuse to enable it when TLS or
other production-indicating config is present.

#### P2.4 Fragile `innerHTML` string-building in UI JavaScript — RESOLVED

`crates/vouch-server/static/js/keys.js:99-116`

The keys list is rendered by concatenating HTML strings into
`container.innerHTML`. `escapeHtml()` is applied consistently today, so
there is **no current XSS**, but the pattern is one missed escape call away
from stored XSS via user-controlled key names. The same pattern appears in
`static/js/tests-runner.js` and `static/js/common.js:16-20`.

**Remediation:** migrate to `createElement`/`textContent` DOM
construction so escaping is structural rather than per-call-site.

#### P2.5 No mechanical negative-auth coverage of API routes — RESOLVED

Individual SCIM, admin, and OIDC handlers verify authentication correctly,
but the audit could not mechanically prove that **every** route under
`/v1`, `/api/v1`, `/oauth`, and `/scim` enforces auth — coverage rests on
each handler doing the right thing.

**Remediation:** add an integration test in `crates/vouch-tests` that
builds the full router and asserts every non-public route returns 401/403
without credentials. This turns "looks right" into a regression-proof
invariant for all future routes.

### P3 — Low / Hardening

#### P3.1 SSH certificate written non-atomically with default umask

`crates/vouch-agent/src/ssh_agent/provisioning.rs:236-245` — the
lazy-provisioned certificate is written with `std::fs::write` (default
umask, typically 0644) and then chmod'd to 0600, leaving a brief
world-readable window. Impact is low (SSH certificates are public
material), but the CLI already has an `atomic_write_secure()` helper
(`crates/vouch-cli/src/utils.rs`) that sets permissions on the temp file
before the atomic rename — reuse that pattern for consistency.

#### P3.2 `VOUCH_ALLOW_INSECURE` accepted silently

`crates/vouch-agent/src/server.rs:295-305` — the insecure-URL override is
honored without any prominent signal. Add a one-time `warn`-level startup
log when the variable is set (mirroring the existing clock-skew warning
pattern).

#### P3.3 Ignored advisory RUSTSEC-2025-0134

`deny.toml:19-21` — the `rustls-pemfile` advisory is ignored with a
documented reason and tracked migration. Complete the migration to
`rustls-pki-types` so the ignore entry can be removed.

#### P3.4 Custom BER parser lacks fuzz coverage

`crates/vouch-server/src/crypto/ber.rs` — the hand-written ASN.1 BER
parser for AWS KMS CMS envelopes is bounded (max depth 32, correct
indefinite-length/EOC handling) and looks correct, but homegrown parsing
of attacker-influenceable encodings warrants a `cargo-fuzz` target — or
migration to the `der` crate, which now supports indefinite-length
encoding.

#### P3.5 Counter-regression events should reach the audit trail — RESOLVED

When P1.1's check fires, the result is an error returned to the client.
A failed clone-detection check is a high-signal security event and should
be recorded in the auth-events audit trail with the credential and user
IDs, not just surfaced as a login failure.

## Verified Non-Issues

Items checked during the evaluation that need no action, recorded to save
future audits the effort:

- **Empty `VOUCH_JWT_SECRET` default** — rejected at startup by
  `ServerConfig::validate()` (`config.rs:911-942`: minimum 32 chars,
  degenerate and low-entropy checks) unless KMS HMAC signing is configured.
- **HTTP→HTTPS redirect router** — present and correct
  (`lib.rs:114-173`): 308, Host header validated against `rp_id`, redirect
  target built from config rather than the untrusted Host header, with
  tests.
- **FIDO2 challenge replay** — atomic single-use via deterministic-PK
  insert witness (`db/challenge_states.rs`), race-safe across SQLite,
  Postgres, and DSQL.
- **SQL injection** — document-store abstraction over sea-query/sqlx;
  no string-built SQL found.
- **GitHub webhook HMAC and DPoP nonce/`ath`** — constant-time
  comparisons via `subtle::ct_eq`.
- **CLI HTTP client** — `redirect(Policy::none())`, default TLS
  verification, non-HTTPS URLs rejected unless loopback.

## Suggested Order of Work

1. **P1.1** — one-line check change plus tests; close the clone-detection
   gap first.
2. **P2.5** — the negative-auth integration test; cheap, and it hardens
   every future route.
3. **P2.1–P2.3** — small, contained changes to the agent listener,
   WebAuthn origin relaxation, and certification endpoint gating.
4. **P2.4** — mechanical JS refactor.
5. **P3.x** — fold into routine maintenance.
