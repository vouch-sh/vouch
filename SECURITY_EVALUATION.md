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
> at every touch point. P3.1, P3.2, and P3.3 are now resolved. P3.4 is resolved
> as well: the BER parser is already covered by a fuzz target
> (`fuzz/fuzz_targets/fuzz_ber_parse.rs`), and migrating to the `der` crate was
> rejected because `der` 0.8's BER support would pull a second major version of
> `der` into the tree (the P-256/x509 stack pins `der` 0.7), tripping
> `cargo-deny`'s `multiple-versions = "deny"`. All P3 items are now closed.

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

#### P3.1 SSH certificate written non-atomically with default umask — RESOLVED

`crates/vouch-agent/src/ssh_agent/provisioning.rs` — the
lazy-provisioned certificate was written with `std::fs::write` (default
umask, typically 0644) and then chmod'd to 0600, leaving a brief
world-readable window. Impact is low (SSH certificates are public
material), but the CLI already had an `atomic_write_secure()` helper that
sets permissions on the temp file before the atomic rename.

**Resolution:** the atomic-write helpers moved from `vouch-cli` to
`vouch-common` (`crates/vouch-common/src/fs.rs`, reachable by both the CLI
and the agent), and the provisioning path now calls
`vouch_common::fs::write_secure_file`, so the file is never visible with
default permissions.

#### P3.2 `VOUCH_ALLOW_INSECURE` accepted silently — RESOLVED

`crates/vouch-agent/src/server.rs` — the insecure-URL override was honored
without any prominent boot-time signal (a per-request `warn` fired only when
an insecure URL was actually stored).

**Resolution:** `AgentServer::run()` now emits a one-time `warn`-level log at
startup whenever `VOUCH_ALLOW_INSECURE` is set, so a set-but-unused flag is
still visible. The existing per-request warning is retained.

#### P3.3 Ignored advisory RUSTSEC-2025-0134 — RESOLVED

`deny.toml` — the `rustls-pemfile` advisory was ignored with a documented
reason and tracked migration.

**Resolution:** the four PEM-parsing call sites in
`crates/vouch-server/src/infra/tls.rs` were migrated to `rustls-pki-types`
(`PemObject::pem_slice_iter` / `from_pem_slice`), the `rustls-pemfile`
dependency was dropped, and the `RUSTSEC-2025-0134` ignore entry was removed
from `deny.toml`.

#### P3.4 Custom BER parser lacks fuzz coverage — RESOLVED

`crates/vouch-server/src/crypto/ber.rs` — the hand-written ASN.1 BER
parser for AWS KMS CMS envelopes is bounded (max depth 32, correct
indefinite-length/EOC handling) and looks correct, but homegrown parsing
of attacker-influenceable encodings warrants a `cargo-fuzz` target.

**Resolution:** a fuzz target already exists at
`fuzz/fuzz_targets/fuzz_ber_parse.rs` and exercises every public
`DerParser` entry point (`read_tlv`, `read_tlv_ber`, `expect_*`, `skip_*`,
`read_implicit_octet_string_ber`) plus sequential indefinite-length reads.
Migration to the `der` crate was evaluated and rejected: although `der` 0.8
(Feb 2026) genuinely added indefinite-length BER support, adopting it would
introduce a second major version of `der` (the P-256/x509 stack pins 0.7),
violating `deny.toml`'s `multiple-versions = "deny"` — net new supply-chain
debt in exchange for replacing a working, already-fuzzed parser.

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

## Addendum — Second-Pass Evaluation (June 2026)

A second pass focused on areas the original review covered less deeply: OAuth
grant extensions (RFC 8693/8628/9101/9396), server-side outbound HTTP fetches
(SSRF), upstream-IdP federation, and the AMI/packaging scripts. Findings below
are **new** relative to P1.1–P3.5 and were verified against the source at the
current branch `HEAD` (`5c3253e`); line references are to that tree.

The original posture summary still holds — no critical, directly exploitable
vulnerability was found. The headline new item (SP1) is an unauthenticated
**blind** SSRF surface that is reachable but constrained (no response
reflection, and IMDSv2 on the shipped AMI blocks instance-credential theft).

### SP1 — High/Medium: SSRF via server-side `jwks_uri` / `request_uri` fetch with no private-network blocklist

The server makes outbound HTTPS requests to URLs that an **unauthenticated**
caller can control, and the only egress guard is an HTTPS-scheme check plus a
256 KiB response cap. There is no rejection of loopback, private, link-local,
unique-local, or multicast destinations (a grep for `169.254` / `is_private` /
`is_blocked` finds no server-side egress filtering).

Attack-reachable fetch paths:

- **Client `jwks_uri`.** `POST /oauth/register` is unauthenticated RFC 7591
  dynamic client registration (`crates/vouch-server/src/infra/router.rs:218-239`).
  A registrant can store an arbitrary HTTPS `jwks_uri`; the server later fetches
  it while *verifying* a `private_key_jwt` client assertion — i.e. **before**
  client authentication succeeds:
  `services/oidc/jwt_bearer/client_auth.rs:204` → `resolve_client_jwks`
  (`jwt_bearer/jwks.rs:64`) → `fetch_and_parse_jwks` (`jwks.rs:188`) →
  `fetch_jwks` (`jwks.rs:131`, `http_client.get(uri).send()` at `jwks.rs:140`).
  The HTTPS-only enforcement is exercised by tests (`jwks.rs:881-909`) but does
  not constrain the host.
- **JAR `request_uri`.** `services/oidc/jar.rs:173` fetches a request-object URI
  via `http_client.get(uri)`. When a client's pre-registered allowlist is unset
  (`OAuthClient.request_uris == None`), *any* HTTPS `request_uri` is accepted
  (`db/oauth.rs:72-76`).

```rust
// jwt_bearer/jwks.rs — only scheme + size are checked, never the host/IP
async fn fetch_jwks(uri: &str, http_client: &reqwest::Client) -> ServiceResult<String> {
    // ... HTTPS-scheme check ...
    let response = http_client.get(uri).send().await /* ... */;
    // ... 256 KiB content-length / body cap ...
}
```

A related fetch, `fetch_discovery` (`services/idp/oidc.rs:295`), retrieves the
operator-configured `issuer_url` / SAML `metadata_url`. It is **operator**
controlled rather than attacker controlled (lower severity), but it shares the
same missing egress guard and should be covered by the same fix.

**Severity:** Medium. The SSRF is blind (no response body is returned to the
caller; only coarse success/failure and timing leak). IMDSv2 enforced on the
shipped AMI prevents the classic `169.254.169.254` credential-theft pivot, but
internal-service reachability, port/host scanning of the VPC, and link-local
ranges remain. Severity rises toward High in any deployment where IMDSv1 is
reachable or where the server sits adjacent to sensitive internal services.

**Remediation:** introduce a single egress-policy helper that resolves the
target host and rejects loopback (`127.0.0.0/8`, `::1`), private
(`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`), link-local
(`169.254/16`, `fe80::/10`), multicast, and unspecified addresses; apply it in
`fetch_jwks`, the `jar.rs` `request_uri` fetch, and `fetch_discovery`. Prefer a
resolve → validate → connect-to-pinned-IP flow (e.g. a custom
`reqwest`/hyper resolver) so a hostname cannot re-resolve to a blocked address
between validation and connection (DNS-rebinding TOCTOU). Additionally enforce
the same check at write time in the registration `jwks_uri` / `request_uris`
validators for fail-fast operator feedback. A loopback exception, gated the same
way as the existing dev-mode relaxations, may be retained for local testing.

### SP2 — Low/Medium: AMI build downloads `coldsnap` binary unpinned and pipes it into tar

`packaging/ami/user-data.sh.tpl:137` streams a GitHub release tarball straight
into `tar` and then executes the extracted binary, with no checksum:

```bash
curl -sL "https://github.com/jplock/coldsnap/releases/download/${COLDSNAP_VERSION}/coldsnap-${COLDSNAP_VERSION}-${ARCH}-unknown-linux-musl.tar.gz" | tar -xzf - -C /usr/local/bin
chmod +x /usr/local/bin/coldsnap
```

Impact is build-time and bounded by HTTPS transport trust, but a compromised or
swapped release artifact would run with full AMI-build privileges.

**Remediation:** pin and verify a SHA-256 before extraction (mirror the
`tailwindcss` checksum-pin pattern already used in the Dockerfile and the
release workflow), and add `-f` so the `curl` fails closed on an HTTP error.

### SP3 — Low/Medium: `vouch-config.service` lacks the systemd hardening applied to the main service

`packaging/ami/root/usr/lib/systemd/system/vouch-config.service` runs
`vouch-fetch-config.sh` as **root** (no `User=`) to fetch configuration —
including secrets — from Parameter Store, but sets **none** of the hardening
directives present on `vouch-server.service`
(`vouch-server.service:26-29` has `NoNewPrivileges=yes`, `ProtectSystem=strict`,
`ProtectHome=yes`, `PrivateTmp=yes`).

**Remediation:** add the same hardening (`NoNewPrivileges`, `ProtectSystem`,
`ProtectHome`, `PrivateTmp`, `PrivateDevices`, `ProtectClock`,
`ProtectHostname`) with `ReadWritePaths` scoped to `/run/vouch-server` and
`/var/log/vouch-config`.

### SP4 — Low/Medium: IMDSv2 token fetch has no empty-token guard (silent IMDSv1 fallback)

`packaging/ami/root/usr/local/bin/vouch-fetch-config.sh:16-17` captures the
IMDSv2 session token without checking the result; on failure `$TOKEN` is empty
and the subsequent metadata calls (`:20`, `:22`, `:27`) degrade silently to
unauthenticated IMDSv1.

**Remediation:** fail closed when `$TOKEN` is empty
(`[ -z "$TOKEN" ] && { echo "ERROR: no IMDSv2 token" >&2; exit 1; }`).

### SP5 — Low: Entra `/organizations/v2.0` federation is implicitly multi-tenant

When an operator configures the Entra `/organizations/v2.0` issuer, the
template-issuer path in `services/idp/oidc.rs` accepts verified ID tokens from
**any** Entra tenant; there is no per-tenant (`tid`) restriction or explicit
warning. `/common/` is already rejected outright (`oidc.rs:281-291`), and an
operator who wants a single tenant can configure the per-tenant issuer URL, so
this is a documentation/ergonomics gap rather than a clear vulnerability.

**Remediation:** document the multi-tenant behavior at the config site, emit a
startup `warn` when `/organizations/` is configured, and optionally support an
allowed-tenant list checked against the token `tid` claim.

### Verified non-issues (second pass)

Checked and intentionally **not** filed as findings, recorded to save future
audits the effort:

- **OAuth scope escalation** (authorization-code `authorization.rs:539`,
  token-exchange `exchange.rs:265`, device-grant `device.rs`) — there is no
  per-client registered-scope concept to escalate against (`db/oauth.rs:22-77`
  carries an `access_scope` enum, not an OAuth-scope allowlist), and only
  `openid` / `email` exist, both granted to every authenticated user. Scope is
  already intersected against the subject/known set in `calculate_granted_scope`
  (`exchange.rs:549-585`).
- **Token-exchange actor scope** — the issued token's authority derives from the
  *subject* token, not the actor; the actor is recorded only in the `act` claim.
  Using a token as `subject_token` requires already possessing that valid,
  non-revoked session (`exchange.rs:212-224`), so no privilege is gained.
- **JAR `aud` optional for non-FAPI clients** (`jar.rs:467-489`) — matches RFC
  9101 (RECOMMENDED, not REQUIRED); the request-object signature is verified, and
  FAPI clients *are* required to carry `aud`.
- **WebAuthn challenge compared with `==`** (`webauthn_verify.rs:376`) — the
  challenge is not a secret (single-use is enforced via atomic challenge-state
  consumption), so constant-time comparison is unnecessary.
- **SSH certificate `valid_seconds` has no explicit bounds** (`ssh_ca.rs:228-254`)
  — the value is derived from server config (`session_hours`,
  `handlers/credentials.rs:84`), never from attacker input; a bounds check is
  defense-in-depth at most.
- **SCIM cross-org group membership** — cross-org `user_id`s are filtered at read
  time (`db/scim.rs`), so no cross-tenant data leaks today; enforcing the org
  boundary at write time as well is optional Low hardening.

### Suggested order of work (second pass)

1. **SP1** — add the shared SSRF egress guard; highest-value new item.
2. **SP2–SP4** — small, contained AMI/packaging hardening.
3. **SP5** — documentation plus an optional tenant-allowlist config.
