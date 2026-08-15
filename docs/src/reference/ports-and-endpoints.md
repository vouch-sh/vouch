# Ports and Endpoints

Reference for writing firewall rules, security groups, and load balancer routing.

## Ports

| Port | Protocol | Purpose | Configurable |
|------|----------|---------|--------------|
| **443** | HTTPS | Main listener | No — fixed whenever TLS is configured |
| **80** | HTTP | 308 redirect to HTTPS, plus `/health` | No |
| **8443** | HTTPS + mTLS | Client-certificate listener for RFC 8705 certificate-bound tokens | Port only, via `VOUCH_MTLS_PORT` |
| **3000** | HTTP | Default listener when TLS is **not** configured | Yes, via `VOUCH_LISTEN_ADDR` |

Which ports are live depends on whether `VOUCH_TLS_CERT` and `VOUCH_TLS_KEY` are set:

**TLS configured** — the server listens on 443 and 80 and starts the mTLS listener on 8443.
`VOUCH_LISTEN_ADDR` is **ignored**.

**TLS not configured** — the server listens only on `VOUCH_LISTEN_ADDR` (default `[::]:3000`).
No redirect listener, no mTLS listener.

Three things regularly surprise operators here:

- **The mTLS listener has no on/off switch.** It starts automatically whenever TLS is configured.
  A security group that opens only 80 and 443 silently breaks certificate-bound tokens; a firewall
  audit that flags 8443 is seeing expected behavior.
- **Binding 80 and 443 needs `CAP_NET_BIND_SERVICE`** on Linux. The RPM and DEB packages configure
  it. A bind failure on port 80 is logged as a warning and is *not* fatal — you lose the HTTP
  redirect while everything else keeps working.
- **A bind failure on the mTLS port is fatal.** Unlike port 80, it aborts startup.

## Endpoints by authentication type

| Auth | What it means |
|------|---------------|
| **None** | Public, unauthenticated |
| **Bearer/DPoP** | A Vouch access token, in `Authorization: Bearer` or `Authorization: DPoP` |
| **Signed** | Bearer/DPoP *plus* an RFC 9421 HTTP message signature |
| **Session** | Browser cookie session |
| **Admin** | Session or Bearer, and the user must be an active org administrator |
| **SCIM token** | A `vouch_scim_…` bearer token |
| **Metrics token** | The `VOUCH_METRICS_BEARER_TOKEN` value |
| **HMAC** | GitHub webhook signature |

### Operations

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/health` | GET | None | Liveness. Returns `ok` as plain text. Also served on port 80 |
| `/health/ready` | GET | None | Readiness. Checks the database; 503 when unreachable |
| `/metrics` | GET | Metrics token | Only registered when `VOUCH_METRICS_BEARER_TOKEN` is set |

### Discovery and metadata

| Endpoint | Method | Auth |
|----------|--------|------|
| `/.well-known/openid-configuration` | GET | None |
| `/.well-known/oauth-authorization-server` | GET | None |
| `/.well-known/oauth-protected-resource` | GET | None |
| `/.well-known/security.txt` | GET | None |
| `/oauth/jwks` | GET | None |
| `/saml/metadata` | GET | None |

### OAuth and authentication

| Endpoint | Method | Auth | Rate-limit tier |
|----------|--------|------|-----------------|
| `/oauth/token` | POST | Client auth | Authentication |
| `/oauth/par` | POST | Client auth | Authentication |
| `/oauth/fido2/challenge` | POST | None | Authentication |
| `/oauth/device` | POST | None | Authentication |
| `/oauth/register` | POST | None (RFC 7591) | Authentication |
| `/oauth/register/{client_id}` | GET/PUT/DELETE | Registration access token | Authentication |
| `/oauth/authorize` | GET | Session | General |
| `/oauth/introspect` | POST | Client auth | General |
| `/oauth/revoke` | POST | Client auth | General |
| `/oauth/userinfo` | GET | Bearer/DPoP | Not limited |
| `/oauth/callback` | GET | None (IdP redirect) | Not limited |
| `/saml/acs` | POST | None (IdP assertion) | Not limited |

### Credentials and keys

| Endpoint | Method | Auth | Rate-limit tier |
|----------|--------|------|-----------------|
| `/v1/credentials/ssh` | POST | Signed | Credential |
| `/v1/credentials/aws/token` | GET | Signed | Credential |
| `/v1/credentials/github/token` | POST | Signed | Credential |
| `/v1/credentials/ssh/ca` | GET | None | General |
| `/v1/credentials/ssh/krl` | GET | None | General |
| `/v1/credentials/ssh/krl/{serial}` | GET | None | General |
| `/v1/credentials/github/status` | GET | None | General |
| `/v1/keys` | GET | Signed | General |
| `/v1/keys/{id}` | PATCH/DELETE | Signed | General |
| `/v1/keys/register/start` · `/complete` | POST | Signed | Authentication |
| `/v1/auth/status` | GET | None | Not limited |

The public read endpoints are unauthenticated by design: SSH hosts fetch the CA public key and
revocation list without holding credentials.

### Administration

| Endpoint | Method | Auth | Rate-limit tier |
|----------|--------|------|-----------------|
| `/admin` and `/admin/*` | GET/POST | Admin | General |
| `/api/v1/org/scim-tokens` | GET/POST | Admin | General |
| `/api/v1/org/scim-tokens/{id}` | DELETE | Admin | General |
| `/api/v1/org/policies/validate` | POST | Admin | General |
| `/scim/v2/*` | GET/POST/PATCH/DELETE | SCIM token | General |
| `/api/v1/applications*` | various | Bearer/DPoP | General |
| `/api/webhooks/github` | POST | HMAC | General |

Admin form POSTs additionally require an `Origin` header matching the server's own origin; a
mismatch is rejected with 403.

### Browser UI

`/`, `/login`, `/device`, `/install`, `/integrations`, `/enroll/*`, `/logout`, `/github/*`,
`/applications/*`, `/static/*`, `/favicon.ico`, `/i18n.js` — session-based or public, HTML
responses.

`/privacy` and `/terms` are 301 redirects to `vouch.sh`. If you need your own legal pages, put them
in front of Vouch at your proxy.

## Request limits

| Scope | Limit |
|-------|-------|
| Global timeout | 30 seconds (408 on expiry) |
| Global body | 256 KiB |
| Credential issuance | 8 KiB |
| SCIM, `/oauth/authorize`, SAML ACS | 64 KiB |
| Enroll and login WebAuthn | 32 KiB |
| GitHub webhook | 1 MiB |

## Outbound connections

The server itself makes outbound HTTPS calls; egress rules must allow them:

| Destination | When |
|-------------|------|
| Your upstream IdP (discovery, JWKS, token) | Always — at startup and during enrollment |
| Your SAML IdP metadata URL | At startup, if a SAML IdP is configured |
| AWS KMS, S3, STS | When KMS keys, S3 configuration, or the AWS integration are used |
| `api.github.com` | When the GitHub App integration is used |
| DNS resolvers | Domain-ownership TXT verification |
| An OAuth client's `jwks_uri` | At dynamic client registration — restricted to public IPs by SSRF protection |

Discovery and metadata fetches happen **at startup and are fatal on failure**: a blocked egress
rule shows up as a server that will not boot, not as a degraded feature. Use `VOUCH_EXTRA_CA_CERTS`
if any of these present certificates from an internal CA.
