# Security Hardening

Vouch ships with secure defaults, so most of this page is describing behavior you get for free —
worth knowing because it shapes what you will see in logs and support tickets. Two sections
describe controls you must opt into: authenticator policy and trusted proxies.

## Authenticator policy

Vouch only issues credentials to a hardware security key it can prove is genuine, and there is no
setting that relaxes that. Every registration must satisfy both checks below; the only thing you
configure is whether to narrow it further to specific models.

**Attestation format.** Only `packed` and `fido-u2f` are accepted. Everything else is rejected at
registration with a 400 — `none` (software authenticators and browser-synced passkeys), the
platform formats `tpm`, `apple`, `android-key` and `android-safetynet` (Windows Hello, Touch ID,
Android), and any identifier not on that list. Format identifiers are matched case-sensitively, so
`Packed` is not `packed`.

**Attestation certificate.** The authenticator must present an `x5c` chain that validates against
a pinned Yubico root. Self-attestation is rejected, and so is a chain that is present but does not
verify — a self-signed certificate offered in `x5c` is refused exactly like no certificate at all.
This is what makes the `hardware_verified` claim in issued tokens a statement Vouch can support,
so it is not configurable.

The practical consequence: **Vouch enrolls YubiKeys.** Authenticators from other vendors chain to
their own vendor roots, which are not pinned, and are rejected at registration.

### Restricting which authenticator models may enroll

```bash
# Any authenticator with a valid attestation chain (default)
VOUCH_ALLOWED_AAGUIDS=

# Only FIPS-certified YubiKey models
VOUCH_ALLOWED_AAGUIDS=fips-only

# Any YubiKey 5 series model, including FIPS, Enterprise, and Bio Multi-protocol
VOUCH_ALLOWED_AAGUIDS=yubikey-5

# An explicit allowlist of AAGUIDs
VOUCH_ALLOWED_AAGUIDS=cb69481e-8ff7-4039-93ec-0a2729a154a8,d8522d9f-575b-4866-88a9-ba99fa02f35b
```

The AAGUID identifies an authenticator *model*, not an individual device. The two keywords are
maintained lists: `fips-only` matches FIPS-certified YubiKeys, `yubikey-5` matches the YubiKey 5
series (excluding the Security Key series and Bio FIDO Edition). Anything else is parsed as a
comma-separated list of AAGUID UUIDs, and a malformed entry is a fatal startup error.

The AAGUID is read from the `id-fido-gen-ce-aaguid` extension of the verified attestation
certificate, never from the client-supplied `authData`. A chain that validates but carries no such
extension proves the key is genuine without saying which model it is, so it yields no AAGUID and
is rejected whenever a policy is configured.

If your organization has a contractual FIPS requirement for the authenticator itself, `fips-only`
is the control that enforces it. Nothing else in Vouch does.

> Restricting AAGUIDs affects enrollment. Users who already enrolled a now-disallowed model keep
> working; tighten the policy before rolling out keys, not after.

### What the certificate is checked against

The leaf is checked against the certificate requirements in WebAuthn Level 2 section 8.2.1, in
addition to the chain terminating at a pinned Yubico root:

- the certificate is X.509 version 3;
- if it carries a Basic Constraints extension, `cA` is false;
- if it carries the `id-fido-gen-ce-aaguid` extension, that extension is not marked critical and
  its value is the AAGUID wrapped in two OCTET STRINGs.

A malformed AAGUID extension fails the registration rather than being skipped. When `authData`
also carries an AAGUID, the two are cross-checked and a disagreement fails the registration. There
is no setting for any of this.

## Rate limiting

Three tiers, applied per resolved client IP using a GCRA limiter. **The limits are compile-time
constants; there is no environment variable to tune them.**

| Tier | Burst | Sustained | Applies to |
|------|-------|-----------|------------|
| Authentication | 8 | 1 per 2s | `/oauth/token`, `/oauth/par`, `/oauth/fido2/challenge`, `/oauth/device`, `/oauth/register*`, `/v1/keys/register/*`, `/login/webauthn/*`, `/enroll/webauthn/*` |
| Credential issuance | 15 | 1 per 2s | `/v1/credentials/ssh`, `/v1/credentials/aws/token`, `/v1/credentials/github/token` |
| General | 20 | 1 per 1s | `/oauth/authorize`, `/oauth/logout`, `/oauth/introspect`, `/oauth/revoke`, `/api/v1/org/*`, `/scim/v2/*`, `/v1/keys*`, `/api/v1/applications*`, `/api/webhooks/github`, `/admin/*`, public SSH CA and KRL reads |

The bursts are sized for real client behavior: a full FAPI 2.0 login makes several rapid calls to
authentication endpoints, and `kubectl` spawns parallel credential processes at startup — hence the
larger credential burst.

Every response carries `x-ratelimit-limit` and `x-ratelimit-remaining`. A rejected request gets
**429** with `retry-after` and `x-ratelimit-after`.

Not rate-limited at all: `/health`, `/health/ready`, `/metrics`, `/`, `/static/*`, `/oauth/jwks`,
`/oauth/userinfo`, `/oauth/callback`, `/saml/acs`, and the `.well-known` endpoints.

> **Rate limiting keys on client IP, so it depends on
> [`VOUCH_TRUSTED_PROXIES`](../configuration/reverse-proxy.md).** Behind an unconfigured proxy,
> every user shares one bucket and a moderately busy deployment will 429 everyone at once. This is
> the single most common cause of unexplained 429s.

## Response headers

Applied to every response, with no configuration:

| Header | Value |
|--------|-------|
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `X-DNS-Prefetch-Control` | `off` |
| `Cache-Control` | `no-cache` (API routes additionally get `no-store, must-revalidate`) |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` — **only when TLS is configured** |

HSTS is emitted only when Vouch itself terminates TLS. If you terminate at a proxy, the proxy must
add HSTS.

### Content Security Policy

```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self';
font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self';
form-action 'self' <IdP origins>
```

No `unsafe-inline` and no nonces — every script and stylesheet is served from the origin.

`form-action` is widened at startup with the origin of each configured identity provider. This is
required, not decorative: Chromium enforces `form-action` across redirects, so the `POST /device`
→ IdP redirect is blocked without it. Adding an IdP therefore changes the CSP, which takes effect
on restart.

## CORS

- **API routes** allow any origin with credentials disabled. Safe because they authenticate with
  headers and bodies, never cookies.
- **UI routes** are same-origin by default. `VOUCH_CORS_ORIGINS` opts in specific origins with
  credentials enabled.
- **`/oauth/authorize` and `/oauth/logout` send no CORS headers at all**, under either setting.
  RFC 9700 §2.6: "CORS MUST NOT be supported at the authorization endpoint, as the client does
  not access this endpoint directly; instead, the client redirects the user agent to it." Both
  are reached by top-level browser navigation, which does not consult CORS, so nothing that
  worked before stops working.

`VOUCH_CORS_ORIGINS=*` is a **fatal startup error**. UI routes use credentialed cookie sessions,
and the CORS specification forbids combining wildcard origins with credentials. List origins
explicitly.

## Request limits

| Limit | Value |
|-------|-------|
| Global request timeout | 30 seconds (408 on expiry) |
| Global body limit | 256 KiB |
| Credential issuance | 8 KiB |
| SCIM, `/oauth/authorize`, SAML ACS | 64 KiB |
| Enroll and login WebAuthn | 32 KiB |
| GitHub webhook | 1 MiB |

## Server-side request forgery

Before fetching any URL a *client* controls — an OAuth client's `jwks_uri` at dynamic registration,
or a JAR `request_uri` — Vouch resolves the hostname and rejects the request if **any** A or AAAA
record points somewhere non-global: loopback, RFC 1918, link-local (including
`169.254.169.254`), CGNAT, multicast, documentation and benchmarking ranges, and the IPv6
equivalents.

This matters because `POST /oauth/register` is unauthenticated, so the `jwks_uri` fetch happens
before any client has proven anything.

Loopback is permitted only when TLS is *not* configured, i.e. local development. Cloud metadata
addresses stay blocked even then.

The upstream IdP discovery and SAML metadata fetches are deliberately exempt — those URLs come from
your configuration, not from a client, and legitimately point at internal hosts.

## Certification test mode

```bash
VOUCH_CERTIFICATION_TEST_TOKEN=<token>
```

**Never set this in production.** It exists for running the OpenID Foundation conformance suite,
and it does three things:

1. Registers `/certification/complete-login` and `/certification/deny-login` — a **login bypass**
   that mints a session for a synthetic user with no FIDO2 credential.
2. **Disables all rate limiting**, globally.
3. Relaxes the requirement that at least one upstream IdP be configured.

The server logs a warning to the `security` target at startup when it is active. If you find that
warning in a production log, treat it as an incident: see the
[Security Incident Runbook](incident-runbook.md).

## Hardening checklist

- [ ] `VOUCH_JWT_SECRET` is at least 32 random characters, or KMS HMAC is used instead
- [ ] Durable `VOUCH_OIDC_SIGNING_KEY` and `VOUCH_OIDC_RSA_SIGNING_KEY` — not the ephemeral defaults
- [ ] SSH CA key provisioned explicitly, so it cannot be silently auto-generated
- [ ] `VOUCH_ALLOWED_DOMAINS` set, so enrollment is not open to any domain
- [ ] Client IP preserved if anything fronts the server — `VOUCH_TRUSTED_PROXIES` for a proxy that terminates TLS, or client IP preservation on a TCP-passthrough target group
- [ ] `VOUCH_CERTIFICATION_TEST_TOKEN` **unset**
- [ ] `VOUCH_METRICS_BEARER_TOKEN` set to a strong random value if metrics are scraped
- [ ] `VOUCH_ALLOWED_AAGUIDS` set if you restrict enrollment to particular authenticator models
      (verified attestation chains are always required and need no configuration)
- [ ] TLS terminated in Vouch where possible; HSTS present either way
- [ ] Database and S3 configuration encrypted at rest with least-privilege access
