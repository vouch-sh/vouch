# Monitoring and Metrics

## Health endpoints

Vouch exposes two health endpoints. They answer different questions and are **not**
interchangeable.

| Endpoint | Checks | Success | Failure |
|----------|--------|---------|---------|
| `GET /health` | Nothing — the process is running | `200`, body `ok` (plain text, not JSON) | Only fails if the process is hung or dead |
| `GET /health/ready` | Database connectivity (`SELECT 1`) | `200 {"status":"ready"}` | `503 {"status":"not_ready","reason":"database"}` |

Neither requires authentication. Both are reachable over plain HTTP on port 80 when TLS is
configured, so a load balancer can health-check without TLS.

```bash
curl -s https://auth.example.com/health
# ok

curl -s https://auth.example.com/health/ready
# {"status":"ready"}
```

> **Use the right one for the right probe.** `/health` is a liveness probe: it tells you whether to
> restart the process. `/health/ready` is a readiness probe: it tells you whether to send traffic.
> Pointing a readiness probe or a load balancer target group at `/health` means an instance whose
> database has failed keeps reporting healthy and keeps receiving requests.

Other unauthenticated endpoints useful for synthetic checks:

| Endpoint | Confirms |
|----------|----------|
| `/.well-known/openid-configuration` | The OIDC provider is serving discovery |
| `/.well-known/oauth-protected-resource` | RFC 9728 protected-resource metadata |
| `/oauth/jwks` | Signing keys are loaded and published |
| `/v1/credentials/ssh/ca` | The SSH CA is loaded |

## Prometheus metrics

Vouch exposes Prometheus metrics at `GET /metrics`, but **only when you set a bearer token**:

```bash
VOUCH_METRICS_BEARER_TOKEN=<a long random string>
```

If the variable is unset the endpoint is not registered at all, and the startup log says
`Prometheus /metrics endpoint disabled (VOUCH_METRICS_BEARER_TOKEN not set)`. There is no
unauthenticated mode.

Scrape it with the token in an `Authorization: Bearer` header; the comparison is constant-time and
anything else returns 401.

```yaml
# prometheus.yml
scrape_configs:
  - job_name: vouch
    scheme: https
    authorization:
      credentials: <the same token>
    static_configs:
      - targets: ["auth.example.com"]
```

`/metrics` is not rate-limited, but it is subject to the global 30-second request timeout.

### Exported metrics

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `http_requests_total` | counter | `method`, `path`, `status` | Requests served. See the label note below. |
| `http_request_duration_seconds` | histogram | `method`, `path` | Request latency. Not labelled by status. |
| `vouch_auth_events_total` | counter | `event_type` | Authentication outcomes |
| `vouch_credential_issuance_total` | counter | `type` | Credentials issued |

The `method` and `path` labels are both drawn from fixed sets, so the number of series has a
ceiling that no request can raise:

- `path` is the matched route template (e.g. `/v1/keys/{id}`), never the raw request target. A
  request that matches no route is labelled `<unmatched>` rather than by the target it asked for,
  so 404 traffic contributes exactly one series per method/status pair. To see what is actually
  being probed, read the request logs — every request logs its raw path on the `request` span.
- `method` is one of the nine methods registered by RFC 9110. Any other token — HTTP permits any
  token as a method — is labelled `OTHER`.

`vouch_auth_events_total` uses these `event_type` values: `enrollment`, `browser_login_success`,
`fido2_login_success`, `fido2_login_failure`, `authorization_code_success`.

`vouch_credential_issuance_total` uses these `type` values: `ssh`, `aws`, `github`, `oidc`.

> The metrics carry no `HELP` or `TYPE` descriptions in the scrape output. This page is the
> reference for what they mean.

There are no gauges, and no metrics for database pool saturation, cleanup runs, or rate-limit
rejections specifically. Use `http_requests_total{status="429"}` to observe rate limiting, and your
database's own monitoring for pool health.

### Useful queries

```promql
# Login failure rate
rate(vouch_auth_events_total{event_type="fido2_login_failure"}[5m])

# Credential issuance by type
sum by (type) (rate(vouch_credential_issuance_total[5m]))

# 95th percentile latency by route
histogram_quantile(0.95,
  sum by (le, path) (rate(http_request_duration_seconds_bucket[5m])))

# Rate-limited requests
sum(rate(http_requests_total{status="429"}[5m]))
```

## Logging

Vouch logs to stdout using `tracing`. Two settings control it.

**Format** — `VOUCH_LOG_FORMAT` accepts `text` (default) or `json`. Use `json` for anything that
ships logs to an aggregator; the server rejects any other value at startup.

```bash
VOUCH_LOG_FORMAT=json
```

**Level** — `RUST_LOG` takes a standard `EnvFilter` directive, defaulting to `info`.

```bash
RUST_LOG=info                          # normal operation
RUST_LOG=warn                          # quiet
RUST_LOG=debug                         # troubleshooting; verbose
RUST_LOG=info,vouch_server=debug       # debug just Vouch
RUST_LOG=vouch_server=debug,tower_http=info
```

Security-relevant conditions are logged to a `security` target — certification test mode being
active, a loopback `rp_id` combined with TLS, and rejected `Host` headers on the redirect
listener.

### Correlating requests

Every request is assigned an interaction ID, exposed and accepted as the FAPI header
**`x-fapi-interaction-id`** — not `x-request-id`. If a client supplies one it is propagated;
otherwise the server generates a UUIDv7. It is attached to every log line and trace span emitted
while handling that request, so it is the field to search on when tracing one user's problem.

Log it at your load balancer too, and a report of "my login failed at 14:32" becomes a single grep.

## Distributed tracing

The server exports OpenTelemetry spans over OTLP/gRPC when you point it at a collector:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
OTEL_SERVICE_NAME=vouch-server        # default: vouch-server
```

When `OTEL_EXPORTER_OTLP_ENDPOINT` is unset, tracing export is disabled entirely and costs nothing.
Spans are batched and flushed on graceful shutdown.

If the endpoint is set but the exporter cannot be built, the server fails to start — a
misconfigured collector address is a startup error, not a silent degradation.

## Alerting

| Condition | Severity | Why |
|-----------|----------|-----|
| `/health` non-200 or unreachable | Critical | The process is down |
| `/health/ready` returning 503 | Critical | The database is unreachable; the instance can serve nothing |
| Sustained rise in `fido2_login_failure` | Warning | Possible credential stuffing, or a broken IdP integration |
| `http_requests_total{status="429"}` climbing | Warning | Rate limiting is biting. If it started right after a load balancer change, check [`VOUCH_TRUSTED_PROXIES`](../configuration/reverse-proxy.md) — limits key on client IP, and an unconfigured proxy makes every user share one bucket |
| `/v1/credentials/ssh/ca` not returning a key | Warning | The SSH CA is not loaded; SSH certificates cannot be issued |
| Database size growth | Warning | Administrative audit events are never purged — see [Audit Events](../admin/audit.md#retention) |
| TLS certificate near expiry | Warning | Vouch reloads certificates but does not renew them |

## Audit events

Authentication, credential issuance, and administrative events are recorded separately from
application logs, in the database, and browsable at `/admin/audit`. See
[Audit Events](../admin/audit.md) for the full catalogue and retention behavior.
