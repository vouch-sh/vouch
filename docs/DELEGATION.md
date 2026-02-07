# Agent Delegation

> **Status: Planned** — This document describes the planned agent delegation feature for Vouch. The commands and APIs described here are not yet implemented.

Vouch's delegation system allows humans to grant scoped, time-limited credentials to AI coding assistants and automation tools. Every delegated credential traces back to a YubiKey touch -- no stored secrets, no long-lived keys.

The protocol layer is [CIBA (Client Initiated Backchannel Authentication)](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html), a finalized OpenID Connect specification. CIBA was designed for exactly this pattern: the device requesting credentials (the agent) is different from the device approving them (the human's machine with the YubiKey). Vouch's contribution is making the YubiKey touch the approval mechanism.

## Why Delegation

AI coding assistants (Claude Code, GitHub Copilot, Cursor, etc.) need credentials to:
- Push code to repositories
- Deploy to cloud infrastructure
- Access internal APIs
- Query databases

Current approaches are problematic:

| Approach | Issue |
|----------|-------|
| Share your credentials | No audit trail, full access |
| Create long-lived API keys | Rot, get stolen, never expire |
| Manual approval per action | Kills developer velocity |
| No access | Agent can't help with real work |

### Why Not a Secrets Vault?

Tools like 1Password and HashiCorp Vault solve a different problem: they store and retrieve existing credentials. When an agent reads a credential from a vault, it gets access to the stored secret -- which may be a long-lived API key, a static password, or a token that never expires. The vault controls *who can read the secret*, but not *what the secret grants*.

Vouch is a **credential authority**, not a credential vault. Instead of handing agents stored secrets, Vouch **mints fresh, ephemeral credentials on demand** -- scoped to exactly what the agent needs, expiring in hours, and traceable to a specific human authorization.

| | Credential Authority (Vouch) | Secrets Vault (1Password, HashiCorp Vault) |
|---|---|---|
| What agents get | Freshly minted, scoped credentials | Stored secrets (whatever's in the vault) |
| Credential lifetime | Short-lived (minutes to hours) | Whatever the stored credential's lifetime is |
| Scope control | Server-enforced at issuance time | Vault-level (which items can you read) |
| Trust anchor | YubiKey hardware attestation | Platform account + service account token |
| After compromise | Credentials expire on their own | Stored secrets may remain valid indefinitely |

## Design Principles

1. **Hardware-attested authorization** -- Every delegation traces to a YubiKey touch. The human who authorized agent access proved physical presence with a hardware authenticator.

2. **Ephemeral credentials** -- Agents receive short-lived credentials minted per-request. There is nothing long-lived to steal. An SSH certificate expires in hours; a GitHub token expires in 1 hour.

3. **Server-enforced scope** -- Credentials are minted with minimal permissions. The Vouch server maps delegation scopes to service-specific permissions at issuance time, not at the agent's discretion.

4. **Full audit provenance** -- Every issued credential is traceable through a complete chain: human identity -> YubiKey attestation -> session -> delegation -> credential issuance.

## Agent Taxonomy

Not all agents are alike. The security considerations differ based on where and how the agent runs.

### Local Agents

**Examples**: Claude Code, Cursor, Aider on a developer's laptop

- Human is typically present (same machine)
- Shorter TTL is acceptable (1-2 hours)
- Environment variable delivery is reasonable (same user session)
- Risk: co-resident processes in the same shell session can read env vars

### Remote Agents

**Examples**: CI/CD pipelines, background automation, hosted coding assistants

- Autonomous operation, no human present
- May need longer TTL (up to max policy allows)
- Consider IP binding in organization policy
- Risk: broader attack surface, token accessible to more infrastructure

### Honest Limitations

Both local and remote agents are bearer-token holders. Agent identity is self-reported -- the `--to "claude-code"` parameter is a label, not a verified identity. Any process that obtains the delegation token can use it. This is an unsolved industry-wide problem: you cannot cryptographically prove that the process using a token is actually Claude Code vs. a malicious script.

## Architecture

Delegation supports two initiation models: **human-initiated** (the human proactively creates a delegation before starting an agent) and **agent-initiated** (the agent requests credentials mid-task, and the human approves via YubiKey touch). Both produce the same delegation token and are subject to the same security model.

### Human-Initiated Delegation

The human runs `vouch delegate` before starting the agent. This is the simpler model for local agents where the human knows what the agent will need.

```
Human                     Vouch Server                Agent
  |                            |                        |
  | vouch delegate             |                        |
  | --to claude-code           |                        |
  | --scope github:...:write   |                        |
  | --ttl 2h                   |                        |
  |--------------------------->|                        |
  |                            |                        |
  | Delegation token (JWT)     |                        |
  |<---------------------------|                        |
  |                            |                        |
  | VOUCH_DELEGATION_TOKEN=... |                        |
  | claude "implement feature" |                        |
  |----------------------------------------------->|   |
  |                            |                        |
  |                            | POST /api/credential   |
  |                            | Authorization: Bearer  |
  |                            |<-----------------------|
  |                            |                        |
  |                            | Scoped GitHub token    |
  |                            |----------------------->|
```

### Agent-Initiated Delegation (CIBA)

The agent is already running and realizes it needs credentials. It makes a backchannel request to Vouch, and the human approves by touching their YubiKey. This is the CIBA flow -- the agent and the human can be on different devices.

```
Agent                    Vouch Server                  Human (with YubiKey)
  |                           |                              |
  | POST /bc-authorize        |                              |
  | (scope, binding_message,  |                              |
  |  client_id, login_hint)   |                              |
  |-------------------------->|                              |
  |                           |                              |
  | 200 OK                    |                              |
  | { auth_req_id, interval } |                              |
  |<--------------------------|                              |
  |                           | Notification via vouch-agent:|
  |                           | "claude-code requests        |
  |                           |  github:myorg/repo:write     |
  |                           |  Reason: implement feature X |
  |                           |  Touch YubiKey to approve"   |
  |                           |----------------------------->|
  |                           |                              |
  | POST /token               |         [Human touches key]  |
  | grant_type=ciba           |                              |
  | auth_req_id=...           |<-----------------------------|
  |-------------------------->|                              |
  |                           |                              |
  | 200 OK                    |                              |
  | { access_token, scope,    |                              |
  |   expires_in }            |                              |
  |<--------------------------|                              |
  |                           |                              |
  | POST /api/credential      |                              |
  | Authorization: Bearer ... |                              |
  |-------------------------->|                              |
  |                           |                              |
  | Scoped GitHub token       |                              |
  |<--------------------------|                              |
```

### Why CIBA

CIBA was designed for the "consumption device ≠ authentication device" pattern. The spec calls out "RP agent" scenarios explicitly. Key properties that make it the right fit for Vouch:

- **Finalized standard** -- [CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) is a published OpenID specification, not a draft.
- **Approval mechanism is agnostic** -- The spec does not prescribe how the human approves. Push notification, SMS, biometric, or YubiKey touch all work. Vouch chooses YubiKey.
- **Binding message** -- The `binding_message` parameter lets the agent include context ("claude-code requests github:myorg/repo:contents:write") that the human sees before approving.
- **No browser redirect** -- Unlike authorization code flow, CIBA does not require the agent to open a browser. The agent makes an HTTP POST and polls for the result.
- **Financial-grade profile** -- The [FAPI-CIBA profile](https://openid.net/specs/openid-financial-api-ciba.html) adds security requirements that align with Vouch's model.
- **Industry validation** -- Auth0 has demonstrated [CIBA integration for AI agents](https://auth0.com/blog/secure-human-in-the-loop-interactions-for-ai-agents/) with LangGraph.

### Session Coupling

Delegation validity is **independent of session expiry**. If the human's 8-hour session expires mid-afternoon, active delegations continue until their own expiration. This prevents in-progress agent tasks from being killed when a human's session naturally expires.

However, **explicit logout revokes all delegations**. Running `vouch logout` immediately revokes every active delegation for that session, because logout is an intentional act that signals "I want everything stopped."

**Tradeoff**: This means a compromised session cannot be fully revoked by waiting for session expiry alone -- you must explicitly logout or revoke delegations. The delegation's own short TTL (default 2 hours, max controlled by org policy) bounds the risk.

## CIBA Implementation

### Backchannel Authorization Endpoint

```
POST /bc-authorize
Content-Type: application/x-www-form-urlencoded
```

**Request parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `scope` | Yes | Vouch delegation scope (e.g., `github:myorg/repo:contents:write`) |
| `binding_message` | Yes | Human-readable description displayed during approval. Max 256 characters. |
| `client_id` | Yes | Registered agent client ID |
| `login_hint` | Yes | Email or user ID of the human who should approve |
| `requested_expiry` | No | Requested delegation TTL in seconds. Server may shorten based on org policy. Default: 7200 (2 hours). |

Vouch requires `binding_message` (the CIBA spec makes it optional). The message must be displayed verbatim to the human -- it is the human's only context for what they are approving.

**Response (200 OK):**

```json
{
  "auth_req_id": "1c266114-a1be-4252-8ad1-04986c5b9ac1",
  "expires_in": 300,
  "interval": 5
}
```

| Field | Description |
|-------|-------------|
| `auth_req_id` | Unique identifier for this authorization request |
| `expires_in` | Seconds until this request expires if the human does not respond |
| `interval` | Minimum polling interval in seconds |

**Error responses:**

| HTTP Status | Error | When |
|-------------|-------|------|
| 400 | `invalid_scope` | Scope is malformed or not permitted by org policy |
| 400 | `invalid_binding_message` | Missing or exceeds 256 characters |
| 400 | `unknown_user_id` | `login_hint` does not match a Vouch user |
| 401 | `invalid_client` | `client_id` is not registered |
| 403 | `unauthorized_client` | Client is not permitted to request this scope |

### Token Endpoint

The agent polls the token endpoint until the human approves, rejects, or the request expires.

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:openid:params:grant-type:ciba&auth_req_id=1c266114-a1be-4252-8ad1-04986c5b9ac1
```

**Success response (200 OK):**

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 7200,
  "scope": "github:myorg/repo:contents:write"
}
```

The `access_token` is a delegation token (JWT signed by Vouch) that the agent uses for credential requests, identical to tokens produced by the human-initiated `vouch delegate` flow.

**Pending response (400):**

```json
{
  "error": "authorization_pending",
  "error_description": "The authorization request is still pending."
}
```

**Other error responses:**

| Error | Description |
|-------|-------------|
| `authorization_pending` | Human has not yet responded. Agent should continue polling. |
| `slow_down` | Agent is polling faster than `interval`. Back off by 5 seconds. |
| `access_denied` | Human explicitly rejected the request. |
| `expired_token` | Human did not respond before `expires_in` elapsed. |

### Token Delivery Modes

CIBA defines three modes for how the agent learns that the human has approved. Vouch will implement poll mode first.

**Poll mode (v0.7):** The agent polls `POST /token` at the specified `interval`. Simplest to implement, no infrastructure dependencies, works for both local and remote agents.

**Ping mode (future):** Vouch sends an HTTP callback to the agent's registered `notification_endpoint` when the human approves. The agent then calls the token endpoint once to retrieve the token. Requires the agent to expose an HTTP endpoint, but eliminates polling latency.

**Push mode:** Not planned. Push mode delivers the token directly in the callback, which means the token traverses an additional network hop and the callback endpoint must be trusted.

### Authentication Device (vouch-agent)

When a CIBA request arrives, Vouch needs to notify the human and collect their YubiKey approval. The vouch-agent daemon on the human's machine serves as the authentication device.

```
Vouch Server                    vouch-agent (human's machine)
  |                                  |
  | WebSocket/SSE: new auth request  |
  | { auth_req_id,                   |
  |   binding_message,               |
  |   client_id,                     |
  |   scope }                        |
  |--------------------------------->|
  |                                  |
  |                                  | Display to human:
  |                                  | ┌─────────────────────────────────┐
  |                                  | │ Credential Request              │
  |                                  | │                                 │
  |                                  | │ claude-code requests:           │
  |                                  | │ github:myorg/repo:contents:write│
  |                                  | │                                 │
  |                                  | │ "Implementing feature X"        │
  |                                  | │                                 │
  |                                  | │ Touch YubiKey to approve        │
  |                                  | │ Press Escape to deny            │
  |                                  | └─────────────────────────────────┘
  |                                  |
  |                                  | [Human touches YubiKey]
  |                                  | FIDO2 getAssertion (challenge
  |                                  | derived from auth_req_id)
  |                                  |
  | POST /bc-approve                 |
  | { auth_req_id,                   |
  |   fido2_assertion }              |
  |<---------------------------------|
  |                                  |
  | 200 OK                           |
  |--------------------------------->|
```

The FIDO2 challenge is derived from the `auth_req_id`, binding the hardware assertion to the specific delegation request. This prevents replay: a captured assertion cannot approve a different request.

### Open Design Questions

- **Notification transport**: WebSocket (persistent connection) vs SSE (simpler) vs push notification (works when laptop is closed). Start with WebSocket since vouch-agent already maintains a connection to the server.
- **Offline approval**: If the human's machine is offline when the CIBA request arrives, the request queues until the machine reconnects or `expires_in` elapses. Acceptable for v0.7; push notifications would improve this later.
- **Multiple devices**: If a user has vouch-agent running on multiple machines, which one gets the notification? Options: all of them (first approval wins), most recently active, or user-configured primary device.
- **Agent client registration**: How do agents register as CIBA clients? Options: static registration (admin creates client IDs in Vouch), dynamic registration ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)), or implicit registration (any agent with a valid delegation token can make CIBA requests for narrower scopes).

## Scope Specification

Scopes follow a hierarchical format:

```
<service>:<resource>:<permission>
```

### Implementation Note

Each service has a different permission model, and mapping Vouch scopes to service-specific permissions requires bespoke logic per service. Incorrect mappings could lead to privilege escalation. For this reason, delegation will initially support **GitHub scopes only**, with additional services added after the scope mapping is validated.

### GitHub Scopes (v0.7)

```bash
# Read/write to specific repo
github:myorg/myrepo:contents:write

# Read-only to all org repos
github:myorg/*:contents:read

# Manage issues only
github:myorg/myrepo:issues:write

# Multiple scopes (comma-separated)
github:myorg/myrepo:contents:write,github:myorg/myrepo:issues:write
```

GitHub scopes map to [GitHub App installation token permissions](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app). Vouch requests an installation token with only the permissions specified in the delegation scope and repository restrictions matching the delegation.

### Future Services

The following services will be added after the GitHub implementation is validated:

- **SSH**: `ssh:prod.example.com`, `ssh:*.staging.example.com`
- **AWS**: `aws:arn:aws:iam::123456789:role/developer`, `aws:s3:my-bucket:read`
- **GCP**: via Workload Identity Federation

Each requires careful mapping from Vouch's scope syntax to the service's native permission model. AWS IAM policies, SSH certificate principals, and GCP OAuth scopes are fundamentally different systems.

## Delegation Lifecycle

### Create (Human-Initiated)

```bash
$ vouch delegate --to claude-code --scope "github:myorg/repo:contents:write" --ttl 2h

Delegation created:
  ID:      del_abc123
  Grantee: claude-code
  Scope:   github:myorg/repo:contents:write
  Expires: 2025-01-14T14:00:00Z

The agent can now use: VOUCH_DELEGATION_TOKEN=eyJ...

# With reason (for audit)
$ vouch delegate \
    --to claude-code \
    --scope "github:myorg/repo:contents:write" \
    --ttl 2h \
    --reason "Implementing feature X"
```

### Create (Agent-Initiated via CIBA)

The agent calls the backchannel authorization endpoint. The human approves via vouch-agent + YubiKey touch. See [CIBA Implementation](#ciba-implementation) for the full flow.

### List Active

```bash
$ vouch delegation list

ID           GRANTEE       SCOPE                              EXPIRES      INITIATED BY
del_abc123   claude-code   github:myorg/repo:contents:write   2h remaining CLI
del_def456   claude-code   github:myorg/repo:issues:write     1h remaining CIBA
del_ghi789   ci-bot        github:myorg/repo:contents:read    12h remaining CLI
```

### Revoke

```bash
# Revoke specific delegation
$ vouch delegation revoke del_abc123

# Revoke all delegations to a grantee
$ vouch delegation revoke --grantee claude-code

# Revoke all your active delegations
$ vouch delegation revoke --all
```

### Inspect

```bash
$ vouch delegation show del_abc123

Delegation: del_abc123
  Grantee:    claude-code
  Scope:      github:myorg/repo:contents:write
  Created:    2025-01-14T12:00:00Z
  Expires:    2025-01-14T14:00:00Z
  Initiated:  CIBA (auth_req_id: 1c266114-...)
  Reason:     Implementing feature X

  Usage (last 24h):
    12:15 - github token issued (contents:write)
    12:32 - github token issued (contents:write)
    13:01 - github token issued (contents:write)
```

## Token Delivery

### Environment Variable (Human-Initiated)

Set the delegation token as an environment variable before invoking the agent:

```bash
export VOUCH_DELEGATION_TOKEN=$(vouch delegate --to claude-code --scope "..." --ttl 2h --output token)

# Agent sees the token and uses it for credential requests
claude "implement the user authentication feature"
```

**Risk**: Environment variables are readable by any process in the same shell session -- every tool, extension, and background process running as the same user. The short TTL and scoped credentials limit the blast radius.

### CIBA Token Response (Agent-Initiated)

For agent-initiated delegation, the agent receives the delegation token directly from the CIBA token endpoint response. No environment variable is needed -- the agent already has the token from the protocol exchange.

### GitHub Actions / CI

```yaml
# .github/workflows/deploy.yml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Get deployment credentials
        run: |
          # CI bot has a pre-configured delegation with limited scope
          export GITHUB_TOKEN=$(vouch credential github --delegation $CI_DELEGATION_TOKEN)
```

### vouch-agent IPC (Future)

Instead of passing tokens through environment variables, the vouch-agent could mediate credential delivery directly to agent processes via Unix domain socket:

```
Agent Process
    |
    | Request: "I need github:myorg/repo:contents:write"
    | (Unix socket, file permission restricted)
    |
    v
vouch-agent
    |
    | Validates delegation, issues credential
    |
    v
Returns scoped GitHub token directly to agent
```

This avoids exposing the delegation token in the process environment. The agent process authenticates via the Unix socket's file permissions (same mechanism vouch-agent uses for CLI IPC today).

### Custom Integrations

```python
import vouch

# Agent code
client = vouch.Client(delegation_token=os.environ["VOUCH_DELEGATION_TOKEN"])

# Request a scoped credential
github_token = client.get_credential("github",
    repository="myorg/myrepo",
    permissions=["contents:write"]
)

# Use the token
# ... git operations ...
```

## Security Model

### What Delegation Proves

1. **Human authorized this** -- Delegation token is signed, traceable to session or CIBA approval
2. **Approval was presence-attested** -- Human touched YubiKey + entered PIN (whether at session creation or CIBA approval time)
3. **Hardware-bound** -- Approval used hardware FIDO2 authenticator (no platform passkeys)
4. **Scope is bounded** -- Agent cannot exceed granted permissions
5. **Time is limited** -- Credentials expire automatically

### What Delegation Does NOT Prove

1. **Agent identity** -- Grantee name is self-reported; any process with the token can use it
2. **Agent behavior** -- What agent does within scope is the agent's responsibility
3. **Intent matching** -- Agent might do unexpected things within the granted permissions

### CIBA-Specific Security Properties

- **Per-request attestation** -- Unlike the human-initiated flow (where the YubiKey touch happens once at delegation creation), CIBA allows per-request hardware attestation. Each CIBA authorization request requires a fresh YubiKey touch.
- **Challenge binding** -- The FIDO2 challenge is derived from the `auth_req_id`, preventing assertion replay across requests.
- **Binding message integrity** -- The human sees the agent's requested scope in the `binding_message` before approving. The server enforces that the issued delegation matches what was displayed.
- **Request expiry** -- CIBA requests expire after `expires_in` seconds (default: 300). If the human doesn't respond, the agent gets `expired_token` and must make a new request.

### Comparison with Other Approaches

| | Vouch Delegation | Secrets Vault (1Password) | Long-Lived API Keys | Manual Approval |
|---|---|---|---|---|
| **Trust root** | Hardware FIDO2 attestation | Platform account | Key creator's identity | Approver's judgment |
| **Credential lifetime** | Minutes to hours | Whatever's stored | Until rotated (often never) | Per-approval |
| **Scope control** | Server-enforced per-credential | Vault-level (which items) | Whatever the key grants | Per-request |
| **Audit chain** | Human -> YubiKey -> session -> delegation -> credential | Service account -> vault item access | Key usage logs | Approval logs |
| **After theft** | Expires quickly, nothing to persist | Stored secret may be long-lived | Full access until rotated | N/A |
| **Agent identity** | Self-reported (bearer token) | Service account (bearer token) | N/A | N/A |
| **Revocation** | Per-delegation, per-grantee, or all | Per-service-account | Rotate/delete key | N/A |

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Stolen delegation token | Short TTL (default 2h), revocation, scoped credentials |
| Agent exceeds scope | Server enforces scope on every credential request |
| Grantor session compromised | Explicit logout revokes all delegations; delegation TTL bounds exposure |
| Agent persists credentials | Issued credentials also have short TTL |
| Co-resident process reads env var | Use CIBA (no env var needed) or vouch-agent IPC delivery; short TTL limits blast radius |
| Credential request flood | Rate limiting per delegation token |
| CIBA request to wrong user | `login_hint` must match a registered user; org policy restricts which agents can request from which users |
| Fake vouch-agent notification | vouch-agent authenticates to server via mutual TLS or session token; notification channel is authenticated |
| Binding message spoofing | Server generates the notification from the verified request parameters, not from agent-supplied display text |

### Rate Limiting

The Vouch server will enforce rate limits on credential requests per delegation token:

| Endpoint | Limit | Response |
|----------|-------|----------|
| `POST /api/credential/*` (per delegation) | 60 requests/hour | HTTP 429 with `Retry-After` |
| `POST /api/delegate` (per session) | 20 delegations/hour | HTTP 429 |
| `POST /bc-authorize` (per client) | 10 requests/hour | HTTP 429 |

Anomalous request patterns (sudden spikes, unusual hours) should be flagged in audit logs for admin review.

### Best Practices

1. **Minimal scope** -- Grant only what's needed for the task
2. **Short TTL** -- Start with 1-2 hours, extend only if needed
3. **Named grantees** -- Use descriptive names for audit trail clarity
4. **Revoke when done** -- Don't leave delegations active after work is complete
5. **Review audit logs** -- Monitor what agents are doing with delegated access
6. **Prefer CIBA for remote agents** -- Agent-initiated delegation with per-request YubiKey approval is stronger than pre-created delegation tokens
7. **Prefer agent IPC for local agents** -- When available, use vouch-agent socket delivery over env vars

## Audit Trail

Every delegated action is logged with full provenance:

```json
{
  "timestamp": "2025-01-14T12:32:15.123Z",
  "event_type": "credential_issued",

  "actor": {
    "type": "delegated_agent",
    "name": "claude-code",
    "delegation_id": "del_abc123"
  },

  "grantor": {
    "user_id": "usr_xyz789",
    "email": "alice@company.com",
    "session_id": "sess_abc123",
    "session_attestation": {
      "authenticator_aaguid": "2fc0579f-8113-47ea-b116-bb5a8db9202a",
      "authenticated_at": "2025-01-14T10:00:00Z"
    }
  },

  "credential": {
    "type": "github_token",
    "scope": "contents:write",
    "repository": "myorg/myrepo",
    "expires_at": "2025-01-14T13:32:15Z"
  },

  "delegation": {
    "id": "del_abc123",
    "created_at": "2025-01-14T12:00:00Z",
    "expires_at": "2025-01-14T14:00:00Z",
    "scope": "github:myorg/myrepo:contents:write",
    "initiated_by": "ciba",
    "auth_req_id": "1c266114-a1be-4252-8ad1-04986c5b9ac1",
    "reason": "Implementing feature X"
  }
}
```

This audit record proves:
- Alice authorized claude-code at 12:00 by touching her YubiKey
- Alice had presence-attested session from YubiKey at 10:00
- claude-code requested GitHub token at 12:32
- Token was scoped to contents:write on myorg/myrepo
- The delegation was initiated by the agent via CIBA (not pre-created by the human)

## Organization Policies

Admins can configure delegation policies:

```yaml
# Organization delegation policy
delegation:
  # Maximum TTL any user can grant
  max_ttl: 8h

  # Require approval for certain scopes
  require_approval:
    - "github:*:admin"

  # Allowed grantee patterns
  allowed_grantees:
    - "claude-*"
    - "github-actions"
    - "jenkins-*"

  # Scopes that cannot be delegated (patterns evaluated even for future services)
  restricted_scopes:
    - "github:myorg/infrastructure:*"

  # Rate limit overrides
  rate_limits:
    credential_requests_per_hour: 60
    delegations_per_hour: 20

  # CIBA-specific policies
  ciba:
    # Whether agent-initiated delegation is enabled
    enabled: true

    # Maximum CIBA request expiry (how long the human has to approve)
    max_request_expiry: 300

    # Registered agent clients allowed to make CIBA requests
    allowed_clients:
      - client_id: "claude-code"
        max_scope: "github:myorg/*:contents:write"
      - client_id: "ci-bot"
        max_scope: "github:myorg/*:contents:read"
```

## FAQ

**Q: Can an agent delegate to another agent?**
A: No. Delegation chains (agent-to-sub-agent) are out of scope. The transitive trust, scope narrowing, and cascading revocation problems require further design work.

**Q: What if my session expires during delegation?**
A: Delegation remains valid until its own expiration. Your session expiring naturally does not affect active delegations. However, explicitly running `vouch logout` revokes all delegations immediately.

**Q: Can I delegate to myself?**
A: Yes, this is useful for creating scoped credentials for specific tasks without full session access.

**Q: How do I know what an agent did?**
A: `vouch delegation audit del_abc123` shows all credential requests and usage for a delegation.

**Q: Can delegations be transferred between machines?**
A: The delegation token is portable. The agent can use it from anywhere, subject to any IP restrictions in your organization policy.

**Q: How is this different from 1Password's agent features?**
A: 1Password stores and retrieves existing credentials (a vault). Vouch mints fresh, ephemeral credentials on demand (an authority). When 1Password gives an agent a stored API key, that key may be long-lived and fully privileged. When Vouch gives an agent a GitHub token, that token was just created, scoped to specific permissions, and expires in an hour. Vouch also requires hardware presence proof (YubiKey touch) to authorize delegation -- 1Password relies on its platform and admin configuration.

**Q: Why not use a secrets vault for agents?**
A: Vaults are the right tool for storing secrets that must persist (database passwords, API keys for services that don't support short-lived tokens). But for services that support short-lived, scoped credentials -- GitHub, AWS, SSH, GCP -- minting fresh credentials is strictly better. Nothing is stored, nothing persists, and scope is enforced at issuance rather than at access.

**Q: Why CIBA instead of OAuth device code flow?**
A: Device code flow (RFC 8628) requires the human to navigate to a URL and enter a code -- it was designed for TVs and IoT devices. CIBA pushes the notification to the human's device directly, which is a better UX when vouch-agent is already running. CIBA also supports `binding_message` for displaying request context, and the approval can happen without a browser.

**Q: What if I'm not at my computer when an agent requests credentials?**
A: The CIBA request expires after `expires_in` seconds (default 300). The agent receives an `expired_token` error and must make a new request. If vouch-agent supports push notifications in the future, you could approve from a mobile device.

## Alternatives Considered

We evaluated several emerging agent credential standards before choosing CIBA as the protocol layer for agent-initiated delegation.

### A2A (Agent-to-Agent Protocol)

The [A2A protocol](https://a2a-protocol.org/latest/specification/), launched by Google and now governed by the Linux Foundation, defines an `auth-required` task state -- a standardized way for an agent to pause mid-task and request credentials.

```
Client Agent                Remote Agent
     |                           |
     | message/send (task)       |
     |-------------------------->|
     |                           |
     | TaskStatus:               |
     |   state: "auth-required"  |
     |<--------------------------|
     |                           |
     | [obtain credentials       |
     |  out-of-band]             |
     |                           |
     | message/send (with creds) |
     |-------------------------->|
```

A2A specifies *that* credentials are needed and *how* to deliver them, but leaves the "out-of-band" credential acquisition intentionally unspecified. A2A is complementary to Vouch's CIBA implementation: when an A2A agent enters `auth-required` state, the credential acquisition step could be a Vouch CIBA flow. A2A defines the agent interoperability layer; CIBA defines the human-approval protocol.

A2A supports OAuth 2.0, OpenID Connect, API keys, HTTP auth, and mutual TLS via the AgentCard's `securitySchemes` field.

**Source**: [A2A Specification](https://a2a-protocol.org/latest/specification/)

### MCP + XAA (Cross App Access)

The [MCP authorization spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) uses OAuth 2.1 for agent-to-tool authentication. The November 2025 spec update added [XAA (Cross App Access)](https://workos.com/blog/id-jag-cross-app-access) as an enterprise extension, using [ID-JAG](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) (Identity Assertion Authorization Grant) to route agent access through an enterprise IdP.

XAA eliminates per-tool consent flows by routing through the IdP. The tradeoff: approval happens at SSO time only, not per-credential-request. Once the user has an authenticated session, the agent gets tokens without further human interaction.

Vouch could serve as an MCP authorization server and enterprise IdP in the future. This is complementary to CIBA -- XAA handles enterprise tool access at the session level, while CIBA handles per-request approval when stronger authorization is needed.

**Sources**: [MCP Auth Spec (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), [ID-JAG IETF Draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/), [WorkOS: XAA](https://workos.com/blog/id-jag-cross-app-access)

### ACP (Agent Communication Protocol)

IBM's Agent Communication Protocol was a REST-based agent interoperability standard. As of September 2025, it merged with Google's A2A under Linux Foundation governance. No separate credential mechanisms beyond what A2A now provides.

**Source**: [IBM ACP](https://www.ibm.com/think/topics/agent-communication-protocol)

### Comparison

| Standard | Agent requests credentials? | Human approves per-request? | Vouch relationship |
|---|---|---|---|
| **CIBA** | Yes (backchannel request) | Yes (notification + YubiKey) | **Primary protocol** for agent-initiated delegation |
| **A2A** | Yes (`auth-required` state) | Unspecified | Vouch CIBA handles the out-of-band credential step |
| **MCP + XAA** | Yes (OAuth token exchange) | No (SSO-time only) | Future: Vouch as MCP authorization server |
| **ACP** | Merged into A2A | See A2A | N/A |
