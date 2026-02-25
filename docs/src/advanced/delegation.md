# Agent Delegation (Planned)

Vouch's delegation system allows humans to grant scoped, time-limited credentials to AI coding assistants and automation tools. Every delegated credential traces back to a YubiKey touch -- no stored secrets, no long-lived keys.

> **Status: Planned** -- This document describes the planned agent delegation feature for Vouch. The commands and APIs described here are not yet implemented.

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

CIBA was designed for the "consumption device != authentication device" pattern. The spec calls out "RP agent" scenarios explicitly. Key properties that make it the right fit for Vouch:

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
