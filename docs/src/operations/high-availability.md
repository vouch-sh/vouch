# Running Multiple Instances

Vouch runs stateless: all shared state lives in the database, so scaling out is mostly a matter of
running more processes behind a load balancer. The parts that are *not* automatic are the signing
keys — get those wrong and the deployment fails in ways that look random.

## Requirements

### 1. A shared database

SQLite is per-process and cannot back more than one instance. Use PostgreSQL, or Aurora DSQL on
AWS. See [Database](../configuration/database.md).

### 2. Identical signing keys on every instance

This is the requirement that bites. Three keys must be **the same value on every instance**:

| Key | If it differs between instances |
|-----|--------------------------------|
| `VOUCH_OIDC_SIGNING_KEY` (ES256) | Access tokens issued by instance A fail verification at instance B |
| `VOUCH_OIDC_RSA_SIGNING_KEY` (RS256) | AWS credential tokens and RS256 ID tokens fail verification; AWS federation breaks |
| `VOUCH_JWT_SECRET` | Authorization codes, WebAuthn challenge state, and CSRF tokens minted by one instance are rejected by another |

Both OIDC keys are **optional settings that silently auto-generate an ephemeral key when unset**.
On a single node that only means tokens die at restart. Across several nodes it means each instance
signs with its own key, and every request that lands on a different instance than the one that
issued the token fails.

The symptom is the giveaway: intermittent failures at roughly `(n-1)/n` of requests, which look
like flakiness rather than a configuration error. Logins that work on retry. AWS federation that
succeeds sometimes.

The server warns at startup when it generates an ephemeral key:

```
Using ephemeral OIDC signing key -- all issued tokens will be invalidated on server
restart. Set VOUCH_OIDC_SIGNING_KEY to persist.

Using ephemeral OIDC RSA signing key -- AWS credential tokens (and RS256 ID tokens)
will fail verification after a restart and across multiple instances.
```

Treat either warning as a failed deployment in a multi-instance setup.

The cleanest way to guarantee consistency is to put the keys in the
[S3 configuration document](../configuration/sources.md) or use KMS key IDs, so every instance
reads the same source rather than relying on the environment being identical everywhere.

### 3. Consistent everything else

`VOUCH_RP_ID` and `VOUCH_BASE_URL` must match across instances — WebAuthn credentials are bound to
the RP ID. So must the SSH CA key, or certificates will be signed by CAs your hosts do not trust.

## What you do not need

- **Sticky sessions.** Sessions live in the database and every instance can serve any request.
- **Cross-instance coordination for cleanup.** The background cleanup task staggers itself with a
  random jitter of up to 20% of the configured interval, so replicas do not all sweep at once.
- **A migration step.** Migrations run automatically at startup.

## Startup and migrations

Every instance runs migrations at boot. Starting several at once is safe:

- On **PostgreSQL**, sqlx's advisory lock serializes them.
- On **Aurora DSQL**, which has no advisory locks and cannot mix DDL and DML in one transaction,
  Vouch uses a dedicated migration runner. It records completion with `ON CONFLICT DO NOTHING`, so
  a replica that loses the race does not crash-loop, and it treats duplicate-object errors as
  evidence that a prior attempt already applied the DDL, so a crashed migration does not
  permanently block startup.

Rolling deployments are otherwise unremarkable: instances are interchangeable, and old and new
versions can serve simultaneously as long as they share the keys above.

## Load balancer configuration

Covered in [Behind a Reverse Proxy](../configuration/reverse-proxy.md). The two things to get right
for a multi-instance deployment specifically:

- Health check **`/health/ready`**, not `/health`. An instance that lost its database connection
  keeps passing `/health` and stays in rotation. Behind a TCP-passthrough NLB this has to be an
  HTTPS health check on port 443, because port 80 serves only `/health`.
- Preserve the client IP, or all rate limiting collapses onto the load balancer's IP. With TCP
  passthrough that means enabling client IP preservation on the target group; with a proxy that
  terminates TLS it means setting `VOUCH_TRUSTED_PROXIES`.

## Graceful shutdown

On `SIGTERM` or Ctrl-C, the server stops accepting connections and gives in-flight requests up to
**30 seconds** to finish, then closes the database pool and flushes any pending OpenTelemetry
spans.

Set your orchestrator's termination grace period above 30 seconds so it does not `SIGKILL` mid-
drain — Kubernetes defaults to 30, which leaves no margin.

The background cleanup and S3 polling tasks are aborted rather than drained; an interrupted cleanup
pass simply resumes on the next instance's next tick.

## Regional and multi-region notes

Aurora DSQL deployments can map regions to endpoints with the `dsql_endpoints` object in the S3
configuration, resolved at startup from `AWS_AZ` or `AWS_REGION`. See the
[S3 Configuration Schema](../reference/s3-config-schema.md).

DSQL connections authenticate with generated IAM tokens, refreshed automatically every 10 minutes
against a 15-minute expiry. A refresh failure is logged as a warning and retried; it is not fatal.
