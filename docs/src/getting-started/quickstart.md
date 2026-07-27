# Quick Start

This walks through getting a Vouch server running and proving it works, end to end: start the
server, enroll the first user, log in, and issue a credential. It uses SQLite and no TLS, so it is
a development setup — not a production deployment. [Deployment
Overview](overview.md) covers what changes for production.

Budget about 20 minutes. You will need a YubiKey.

## Before you start

You need an **upstream identity provider**. The server refuses to start without one, and this is
the step that takes longest, so do it first. Any OIDC provider works; Google Workspace is the
quickest if you already have it.

Register an OAuth client with your IdP and set the redirect URI to:

```
http://localhost:3000/oauth/callback
```

Keep the client ID and secret. See [Identity Providers](../idp/overview.md) for provider-specific
instructions.

## 1. Configure

```bash
# Where users reach this server. WebAuthn credentials bind to this value.
export VOUCH_RP_ID=localhost
export VOUCH_LISTEN_ADDR=0.0.0.0:3000

# A local database file
export VOUCH_DATABASE_URL="sqlite:vouch-dev.db?mode=rwc"

# Signs internal state tokens. Minimum 32 characters.
export VOUCH_JWT_SECRET="$(openssl rand -base64 48)"

# Your upstream IdP. "google" here is a slug you choose.
export VOUCH_IDPS=google
export VOUCH_IDP_GOOGLE_TYPE=oidc
export VOUCH_IDP_GOOGLE_ISSUER=https://accounts.google.com
export VOUCH_IDP_GOOGLE_CLIENT_ID=<your-client-id>
export VOUCH_IDP_GOOGLE_CLIENT_SECRET=<your-client-secret>

# Restrict who may enroll. Without this, anyone your IdP authenticates can.
export VOUCH_ALLOWED_DOMAINS=example.com
```

Two of these deserve a second look before you go further:

- **`VOUCH_RP_ID`** is baked into every WebAuthn credential. Changing it later invalidates every
  enrolled key. `localhost` is correct for this walkthrough and wrong for anything else.
- **`VOUCH_ALLOWED_DOMAINS`**, if unset, means open enrollment — any domain your IdP will
  authenticate. The startup log says `(open enrollment)` when that is the case.

## 2. Start the server

```bash
vouch-server serve
```

## 3. Read the startup log

The startup log is the real health check. It reports what the server actually loaded, which is
usually where a misconfiguration shows up. Confirm these lines:

```
Configuration source: environment variables
Database migrations up to date (N total)
SSH CA initialized: ssh-ed25519 AAAA... vouch-ca@localhost
IdP 'google' (oidc): brand=Google, issuer=https://accounts.google.com, ..., enrollment_domains=example.com
Document encryption: plaintext (no document key configured)
Database pool: max_connections=25, ...
Sessions: duration=8h, dpop_max_age=300s, ...
CORS: same-origin only
```

Watch for these warnings. All three are fine here and none are fine in production:

| Warning | Meaning |
|---------|---------|
| `Using ephemeral OIDC signing key` | Tokens die on restart, and fail across instances. Set `VOUCH_OIDC_SIGNING_KEY`. |
| `Using ephemeral OIDC RSA signing key` | Same, for AWS credential tokens. Set `VOUCH_OIDC_RSA_SIGNING_KEY`. |
| `Generating new SSH CA keypair at ./ssh_ca_key` | No CA key existed, so one was created. Fine now; on a fresh volume in production it silently replaces your CA. |

**If the server exited instead**, the error message names the problem directly — a missing IdP
variable, a short JWT secret, an unreachable issuer. See
[Troubleshooting](../operations/troubleshooting.md#the-server-wont-start).

## 4. Verify it is serving

```bash
# Liveness — returns the plain string "ok", not JSON
curl -s http://localhost:3000/health

# Readiness — checks the database
curl -s http://localhost:3000/health/ready
# {"status":"ready"}

# The OIDC provider is up
curl -s http://localhost:3000/.well-known/openid-configuration | jq .issuer

# Signing keys are published
curl -s http://localhost:3000/oauth/jwks | jq '.keys[].alg'
# "ES256"
# "RS256"

# The SSH CA is loaded
curl -s http://localhost:3000/v1/credentials/ssh/ca
# {"public_key":"ssh-ed25519 AAAA...","comment":"vouch-ca@localhost"}
```

## 5. Enroll the first user

**This step decides who administers your organization**, so do it deliberately.

Vouch has no organizations and no administrators until somebody enrolls. On first enrollment the
server creates an organization from the user's email domain and makes that first user its
administrator. Whoever enrolls first holds the only admin account.

Enroll from a workstation with the CLI installed:

```bash
vouch --server http://localhost:3000 enroll
```

A browser opens; sign in with your IdP, then touch your YubiKey when prompted. (For CLI
installation, see [vouch.sh/docs](https://vouch.sh/docs/).)

You can also enroll entirely in the browser at `http://localhost:3000/enroll/start`.

## 6. Log in and get a credential

```bash
# FIDO2 login — touch the YubiKey
vouch --server http://localhost:3000 login

# Issue an SSH certificate
vouch --server http://localhost:3000 credential ssh
```

## 7. Confirm it was recorded

Open `http://localhost:3000/admin` in a browser, signed in as the user you just enrolled.

- **Members** lists your user, marked as an administrator.
- **Audit** shows `enrollment`, then `login_success`, then `ssh_credential`.

If `/admin` returns 403, you are signed in as a user who is not an administrator — that means
somebody else enrolled first.

## What to do next

You now have a working server. For production, the differences that matter most:

1. **[TLS, Ports, and mTLS](../configuration/tls.md)** — real certificates. The server moves to
   ports 443 and 80, and `VOUCH_LISTEN_ADDR` stops applying.
2. **[Signing Keys](../configuration/keys.md)** — replace both ephemeral OIDC keys with durable
   ones, and provision the SSH CA key explicitly instead of letting it auto-generate.
3. **[Database](../configuration/database.md)** — PostgreSQL if you will run more than one
   instance.
4. **[Behind a Reverse Proxy](../configuration/reverse-proxy.md)** — set `VOUCH_TRUSTED_PROXIES`
   if anything sits in front, or rate limiting will key on your load balancer.
5. **[Security Hardening](../operations/security-hardening.md)** — the pre-production checklist.
6. **[Monitoring and Metrics](../operations/monitoring.md)** — probes, metrics, and log format.
