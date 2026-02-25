# Security and Audit

This chapter covers the security model for agent delegation, including threat analysis, rate limiting, best practices, the audit trail format, organization policies, frequently asked questions, and alternatives that were considered.

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
  "timestamp": "2026-01-14T12:32:15.123Z",
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
      "authenticated_at": "2026-01-14T10:00:00Z"
    }
  },

  "credential": {
    "type": "github_token",
    "scope": "contents:write",
    "repository": "myorg/myrepo",
    "expires_at": "2026-01-14T13:32:15Z"
  },

  "delegation": {
    "id": "del_abc123",
    "created_at": "2026-01-14T12:00:00Z",
    "expires_at": "2026-01-14T14:00:00Z",
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

Admins can configure delegation policies. The policy format below is illustrative and subject to change:

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
A: Vaults are the right tool for storing secrets that must persist (database passwords, API keys for services that don't support short-lived tokens). But for services that support short-lived, scoped credentials -- GitHub, AWS, SSH -- minting fresh credentials is strictly better. Nothing is stored, nothing persists, and scope is enforced at issuance rather than at access.

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
