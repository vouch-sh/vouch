# Audit Events

Every authentication, credential issuance, and administrative action is recorded as an audit
event. Events are stored in the `audit_events` table and browsable at `/admin/audit`.

Email addresses are masked to domain only, with an HMAC column alongside so you can correlate a
user's activity without the log itself holding their address. Events are enriched with the country
code, ASN, and network organization resolved from the client IP.

> The GeoIP databases are compiled into the server binary. They cannot be refreshed independently —
> new geolocation data arrives with a new Vouch release.

## Audit Events

### Authentication and key lifecycle

| Event Type | Description |
|------------|-------------|
| `login_success` | User authenticated — FIDO2 passkey login, or a returning user signing in on the website via the upstream IdP (the latter has no `authenticator_id`) |
| `login_failed` | Failed authentication attempt |
| `enrollment` | User enrolled their first hardware key |
| `logout` | User logged out (including RFC 7009 token revocation) |
| `key_registered` | Additional hardware key registered (`vouch register`) |
| `key_removed` | Hardware key removed |
| `device_auth_approved` | Browser approved a CLI device-authorization request |
| `key_registration_replay` | Replayed key-registration link rejected (possible attack) |
| `identity_bound` | Upstream IdP identity (issuer + subject) bound to an account on its first IdP login; `data.idp_issuer` names the issuer |
| `identity_bind_refused` | IdP sign-in refused: the asserted email matched an account already bound to a different subject at the same issuer (possible upstream email reassignment); `data.idp_issuer` names the issuer |

### Credential issuance

| Event Type | Description |
|------------|-------------|
| `ssh_credential` | SSH certificate issued; `data` includes the serial, principals, requesting agent, and expiry |
| `aws_credential` | AWS OIDC token issued; `data` includes the pinned IAM `role_arn` (the `https://aws.amazon.com/roles` claim), the requesting agent, and token expiry |
| `github_credential` | GitHub installation token issued or installation connected; `data` includes repositories and permissions |
| `token_exchange` | RFC 8693 token exchange (workload identity federation); `data` includes the client, audience, scope, and issued token type |

### OAuth clients

| Event Type | Description |
|------------|-------------|
| `oauth_token_issued` | Token issued at `/oauth/token` (`data.details` carries the grant type) |
| `oauth_token_revoked` | All tokens for an application revoked |
| `oauth_client_registered` | OAuth client registered (RFC 7591 or applications UI) |
| `oauth_client_updated` | OAuth client configuration updated |
| `oauth_client_deleted` | OAuth client deleted |
| `oauth_secret_added` | Client secret added |
| `oauth_secret_revoked` | Client secret revoked |

### Administration and organization

| Event Type | Description |
|------------|-------------|
| `admin_promote` / `admin_demote` | Org-admin role granted / removed |
| `admin_activate` / `admin_deactivate` | User account reactivated / deactivated |
| `admin_revoke_credentials` | Admin revoked a member's keys, sessions, and certificates |
| `admin_remove_user` | Admin removed a member from the organization |
| `admin_policy_create` / `admin_policy_update` / `admin_policy_delete` / `admin_policy_toggle` | Posture policy changes |
| `admin_create_scim_token` / `admin_delete_scim_token` / `admin_revoke_scim_token` | SCIM token lifecycle |
| `scim_operation` | SCIM provisioning operation (`data` carries operation and resource type) |
| `org_domain_added` / `org_domain_verified` / `org_domain_removed` / `org_domain_expired` / `org_domain_unverified` | Additional-domain lifecycle |
| `org_subdomain_claimed` / `org_subdomain_released` | Issuer subdomain lifecycle |
| `org_issuer_key_rotated` | Per-org issuer signing keys rotated (one event per algorithm) |
| `org_issuer_key_revoked` | Per-org previous signing keys revoked (one event per algorithm) |
| `org_issuer_key_emergency_rotation` | Emergency rotation of per-org issuer keys (one event per algorithm) |

## Retention

Events fall into three retention classes. The class is a property of the event type; it is not
configurable.

| Class | Governed by | Contains |
|-------|-------------|----------|
| Authentication | `VOUCH_AUTH_EVENTS_RETENTION_DAYS` (default 90) | Logins, enrollment, logout, key and device-auth lifecycle, SCIM operations |
| OAuth and credentials | `VOUCH_OAUTH_EVENTS_RETENTION_DAYS` (default 90) | Credential issuance, token issue/revoke, client registration — the high-volume events |
| **Kept forever** | *nothing — never deleted* | Every administrative action, OAuth client and secret lifecycle, and all organization domain, subdomain, and issuer-key events |

The third class is the one to know about. Administrative and organization-lifecycle records are
**never** purged by the cleanup task, regardless of how you set the two retention variables. That
is deliberate: these are the records that answer "who granted this person admin, and when", and
they are low-volume enough to keep indefinitely. Plan database growth accordingly, and if a
regulation requires you to delete them, that is a manual database operation.

```bash
# Keep authentication events for two years, credential events for 90 days.
VOUCH_AUTH_EVENTS_RETENTION_DAYS=730
VOUCH_OAUTH_EVENTS_RETENTION_DAYS=90
```

Expired events are removed by the background cleanup task, which runs every
`VOUCH_CLEANUP_INTERVAL` minutes (default 15). Setting the interval to `0` disables cleanup
entirely, and events then accumulate without bound.

> **Retention values must not be negative.** The server rejects a negative value at startup, because
> a negative window produces a cutoff in the future — which would delete the entire audit log on the
> first cleanup pass.

## Browsing and exporting

`/admin/audit` provides a paginated view scoped to your organization, with filters for event
type, user ID, email, and a date range.

For programmatic access — SIEM ingestion, backfills, ad hoc scripting — use the audit events
API described below. The raw `audit_events` table is still available as an operator escape
hatch:

```bash
# SQLite
sqlite3 /data/vouch.db \
  "SELECT * FROM audit_events WHERE created_at > datetime('now', '-1 day');"

# PostgreSQL
psql "$VOUCH_DATABASE_URL" -c \
  "SELECT * FROM audit_events WHERE created_at > now() - interval '1 day';"
```

Application logs are separate from audit events and go to stdout — see
[Monitoring and Metrics](../operations/monitoring.md) for structured logging and the
`x-fapi-interaction-id` correlation header.

## Audit Events API

`GET /api/v1/org/audit-events` returns audit events scoped to your organization (the primary
domain plus any verified additional domain) in ID order.

### Authentication

Two auth methods are accepted; cookie (browser session) auth is rejected outright, since this
endpoint is meant for unattended pollers as much as interactive use:

- **Org API token with the `audit:read` scope** — the token type used for SCIM provisioning,
  generalized to carry additional scopes. Mint one on `/admin/scim-tokens` (check "Also grant
  read-only audit log access") or via `POST /api/v1/org/scim-tokens` with `"audit_read": true`.
  A token minted without that option (or before this feature existed) is rejected with 403.
- **Org-admin user session** — a FIDO2-authenticated org admin's access token (`Authorization:
  Bearer` or `DPoP`), the same credential used for the other `/api/v1/org/*` endpoints.

```bash
curl -H "Authorization: Bearer $VOUCH_AUDIT_TOKEN" \
  "https://vouch.example.com/api/v1/org/audit-events"
```

### Filters

| Parameter | Description |
|-----------|-------------|
| `event_type` | Comma-separated list of event types (e.g. `login_success,login_failed`). Unknown or empty values return `400` rather than silently matching nothing. |
| `user_id` | Exact match. |
| `email` | Exact match (HMAC lookup, case-insensitive). |
| `since` / `until` | RFC 3339 timestamps; only events strictly after `since` and strictly before `until`. |
| `after` | Forward cursor: the `id` of the last event from a previous page. Returns events in **ascending** (oldest-first) order — the shape a poller wants. Takes precedence over `before`. |
| `before` | Backward cursor: the `id` of the last event from a previous page. Returns events in **descending** (newest-first) order, matching `/admin/audit`. |
| `limit` | Page size, default 500, maximum 1000. |
| `format` | `ocsf` to project events into OCSF (see below); omitted for native JSON. |

With neither `after` nor `before` set, the first call defaults to an ascending walk from the
start of retained history — a poller with no saved cursor yet can call the endpoint with no
parameters and just start following `next_cursor` forward. Pass `before` explicitly to browse
backward from the newest event instead.

### Response

Default response is a JSON envelope:

```json
{
  "events": [
    {
      "id": "01920000-...",
      "event_type": "login_success",
      "user_id": "01910000-...",
      "email_domain": "example.com",
      "email_hmac": "9f86d0...",
      "created_at": "2026-01-01T00:00:03.512Z",
      "data": { "authenticator_id": "..." }
    }
  ],
  "next_cursor": "01920000-..."
}
```

`email_hmac` is included — it is the documented correlation key for tying events to a specific
user without storing their address in the log (see "Email masking" above), and is already
org-scoped.

### Cursor semantics and delivery guarantee

`next_cursor` is present whenever there may be more matching events; pass it back as `after`
(or `before`, if you're walking backward) to continue. IDs are UUID v7 (time-ordered), but
authentication events are written from detached background tasks, so **commit order can trail
ID order by a few seconds under load** — a naive high-water-mark poller that just tracks "the
highest ID seen" can miss events that commit late.

The API's delivery guarantee instead of ID ordering: **an event is never returned with
`created_at` newer than `now - 30s`**, regardless of the `until` you pass. A poller that
requests `after=<last cursor>` no more often than every 30 seconds, and persists the returned
`next_cursor` after each successful page, will not miss events that commit within that 30-second
window. Because pages can be byte-capped (see NDJSON below), always follow `next_cursor` until a
page comes back without one rather than assuming one poll drains everything new.

This guarantee assumes an audit write actually commits within the window. `created_at` is
stamped when the event is minted, not when it commits, so a detached write task delayed past
30 seconds (executor saturation, a DSQL OCC retry storm) — or one that fails outright — is not
currently surfaced by any metric; the event would land later than the poller expects, or not at
all. Size your polling interval with margin above 30 seconds if your environment is prone to
write-path contention, and treat this as a best-effort guarantee under normal operating
conditions rather than a hard real-time bound.

### NDJSON

Send `Accept: application/x-ndjson` for one JSON object per line instead of the envelope.
Useful for streaming into a poller that appends to a file or pipes into `jq`. Responses are
buffered server-side and capped at 5 MiB; if a page would exceed that, the response stops at
the last complete line and a `Link: <...>; rel="next"` header carries the cursor for the rest
— always follow it the same way you'd follow `next_cursor` in the JSON envelope.

```bash
curl -H "Authorization: Bearer $VOUCH_AUDIT_TOKEN" \
     -H "Accept: application/x-ndjson" \
     "https://vouch.example.com/api/v1/org/audit-events" | jq -c .
```

### SIEM poller examples

**Microsoft Sentinel** (Codeless Connector Framework `RestApiPoller`): poll on an interval,
carry `next_cursor` forward as the `after` query parameter between polls, and treat the 30s
lag window as the platform's ingestion delay tolerance.

**Splunk / Elastic (generic HTTP poll)**: configure a REST/HTTP input against
`GET /api/v1/org/audit-events?format=ocsf` with the bearer token, checkpoint on the response's
`next_cursor`, and poll no more frequently than every 30 seconds.

### Reads are not audited

Polling this endpoint does not itself write an audit event — that would create a feedback loop
of one event per poll. Reads are logged to the application's structured log (`tracing::info!`,
token or user ID, event count) instead.

## OCSF Mapping

`?format=ocsf` projects each event into [OCSF](https://ocsf.io) 1.9.0, mapping Vouch's ~40
event types onto four Identity & Access Management classes. Native JSON stays the canonical,
lossless representation — this is a projection for SIEM ingestion, and every field Vouch
records is still present in `data`.

| Event Type | OCSF Class UID | OCSF Class Name |
|------------|-----------------|------------------|
| `login_success` | 3002 | Authentication |
| `login_failed` | 3002 | Authentication |
| `logout` | 3002 | Authentication |
| `device_auth_approved` | 3002 | Authentication |
| `identity_bind_refused` | 3002 | Authentication |
| `enrollment` | 3001 | Account Change |
| `identity_bound` | 3001 | Account Change |
| `key_registered` | 3001 | Account Change |
| `key_removed` | 3001 | Account Change |
| `key_registration_replay` | 3001 | Account Change |
| `admin_promote` | 3001 | Account Change |
| `admin_demote` | 3001 | Account Change |
| `admin_activate` | 3001 | Account Change |
| `admin_deactivate` | 3001 | Account Change |
| `admin_revoke_credentials` | 3001 | Account Change |
| `admin_remove_user` | 3001 | Account Change |
| `ssh_credential` | 3003 | Authorize Session |
| `aws_credential` | 3003 | Authorize Session |
| `github_credential` | 3003 | Authorize Session |
| `token_exchange` | 3003 | Authorize Session |
| `oauth_token_issued` | 3003 | Authorize Session |
| `oauth_token_revoked` | 3003 | Authorize Session |
| `scim_operation` | 3004 | Entity Management |
| `oauth_client_registered` | 3004 | Entity Management |
| `oauth_client_updated` | 3004 | Entity Management |
| `oauth_client_deleted` | 3004 | Entity Management |
| `oauth_secret_added` | 3004 | Entity Management |
| `oauth_secret_revoked` | 3004 | Entity Management |
| `admin_policy_toggle` | 3004 | Entity Management |
| `admin_policy_create` | 3004 | Entity Management |
| `admin_policy_update` | 3004 | Entity Management |
| `admin_policy_delete` | 3004 | Entity Management |
| `admin_create_scim_token` | 3004 | Entity Management |
| `admin_delete_scim_token` | 3004 | Entity Management |
| `admin_revoke_scim_token` | 3004 | Entity Management |
| `org_domain_added` | 3004 | Entity Management |
| `org_domain_verified` | 3004 | Entity Management |
| `org_domain_removed` | 3004 | Entity Management |
| `org_domain_expired` | 3004 | Entity Management |
| `org_domain_unverified` | 3004 | Entity Management |
| `org_subdomain_claimed` | 3004 | Entity Management |
| `org_subdomain_released` | 3004 | Entity Management |
| `org_issuer_key_rotated` | 3004 | Entity Management |
| `org_issuer_key_revoked` | 3004 | Entity Management |
| `org_issuer_key_emergency_rotation` | 3004 | Entity Management |

An event type this server doesn't recognize (a newer kind an older binary doesn't know about
yet) is emitted as an OCSF Base Event (`class_uid: 0`) with the raw type preserved in
`unmapped.event_type`, never a `500`.

This table and the mapping code are kept in sync by an automated test
(`ocsf_class` in `handlers/admin/ocsf.rs`) that fails the build if they drift apart.

## Known gap: events written before the NULL-domain fix

Org scoping (both `/admin/audit` and the API) filters by `email_domain`. Four write sites used
to insert SCIM and org-lifecycle cleanup events with a `NULL` `email_domain` (they act on
behalf of an organization rather than a specific user, so had no email to derive a domain
from). Events written by those code paths **before** the fix landed remain invisible to
org-scoped reads — there is no backfill migration, since the org that wrote them is only
recoverable from application logs, not the row itself. Events written after the fix carry the
org's primary domain and are visible normally.
