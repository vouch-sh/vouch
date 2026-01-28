# Agent Delegation

> **Status: Planned** — This document describes the planned agent delegation feature for Vouch (v0.7). The commands and APIs described here are not yet implemented. See [ROADMAP.md](ROADMAP.md) for development status.

Vouch's delegation system will allow humans to grant scoped, time-limited credentials to AI coding assistants and automation tools. Every delegated action will carry attestation of who delegated what to whom — and that attestation traces back to a YubiKey touch.

## The Problem

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

## Vouch's Solution

Delegation creates a **scoped, time-limited credential** that:
1. Is traceable to the human who authorized it (via YubiKey-attested session)
2. Has explicit scope boundaries
3. Expires automatically
4. Generates audit logs distinguishing human vs. agent actions

```bash
# Grant Claude Code access to push to your repo for 2 hours
$ vouch delegate \
    --to "claude-code" \
    --scope "github:myorg/myrepo:contents:write" \
    --ttl 2h

Delegation created:
  ID:      del_abc123
  Grantee: claude-code
  Scope:   github:myorg/myrepo:contents:write
  Expires: 2024-01-14T14:00:00Z
  
The agent can now use: VOUCH_DELEGATION_TOKEN=eyJ...
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Human (Grantor)                                    │
│                                                                              │
│  1. vouch delegate --to agent --scope ... --ttl 2h                          │
│                              │                                               │
│                              ▼                                               │
│  2. Vouch creates delegation with:                                          │
│     • Grantor identity (from active session)                                │
│     • Grantee identifier                                                    │
│     • Scope specification                                                   │
│     • Expiration time                                                       │
│     • Cryptographic binding to grantor's session attestation                │
│                              │                                               │
│                              ▼                                               │
│  3. Returns delegation token (JWT signed by Vouch)                          │
└─────────────────────────────────────────────────────────────────────────────┘
                               │
                               │ Token provided to agent
                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Agent (Grantee)                                    │
│                                                                              │
│  4. Agent uses delegation token to request credentials:                     │
│     POST /api/credential/github                                             │
│     Authorization: Bearer <delegation_token>                                │
│                              │                                               │
│                              ▼                                               │
│  5. Vouch validates:                                                        │
│     • Token signature                                                       │
│     • Expiration not passed                                                 │
│     • Scope matches request                                                 │
│     • Grantor's session still valid                                         │
│     • Delegation not revoked                                                │
│                              │                                               │
│                              ▼                                               │
│  6. If valid, issues credential with:                                       │
│     • Scope limited to delegation scope                                     │
│     • TTL limited to delegation TTL                                         │
│     • Audit metadata: "delegated by <grantor>"                              │
└─────────────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Protected Resource                                  │
│                                                                              │
│  7. Agent uses credential (e.g., pushes to GitHub)                          │
│                                                                              │
│  8. Audit log records:                                                      │
│     • Action: git push                                                      │
│     • Actor: claude-code (agent)                                            │
│     • Delegated by: alice@company.com                                       │
│     • Delegation ID: del_abc123                                             │
│     • Original session attestation: <YubiKey fingerprint>                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Scope Specification

Scopes follow a hierarchical format:

```
<service>:<resource>:<permission>
```

### GitHub Scopes

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

### AWS Scopes

```bash
# Assume specific role
aws:arn:aws:iam::123456789:role/developer

# S3 bucket access
aws:s3:my-bucket:read

# Multiple services
aws:s3:my-bucket:write,aws:dynamodb:my-table:read
```

### SSH Scopes

```bash
# Specific host
ssh:prod.example.com

# Host pattern
ssh:*.staging.example.com

# With user restriction
ssh:deploy@prod.example.com
```

## Delegation Lifecycle

### Create

```bash
$ vouch delegate --to claude-code --scope "github:myorg/repo:contents:write" --ttl 2h

# With reason (for audit)
$ vouch delegate \
    --to claude-code \
    --scope "github:myorg/repo:contents:write" \
    --ttl 2h \
    --reason "Implementing feature X"
```

### List Active

```bash
$ vouch delegation list

ID           GRANTEE       SCOPE                              EXPIRES
del_abc123   claude-code   github:myorg/repo:contents:write   2h remaining
del_def456   ci-bot        aws:arn:...developer               12h remaining
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
  Created:    2024-01-14T12:00:00Z
  Expires:    2024-01-14T14:00:00Z
  Reason:     Implementing feature X
  
  Usage (last 24h):
    12:15 - github token issued (contents:write)
    12:32 - github token issued (contents:write)
    13:01 - github token issued (contents:write)
```

## Integration with AI Assistants

### Claude Code / Aider / Similar

Set environment variable before invoking:

```bash
export VOUCH_DELEGATION_TOKEN=$(vouch delegate --to claude-code --scope "..." --ttl 2h --output token)

# Claude Code sees the token and uses it for credential requests
claude-code "implement the user authentication feature"
```

Or configure in the assistant's settings to request delegation at startup.

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
          export AWS_CREDENTIALS=$(vouch credential aws --delegation $CI_DELEGATION_TOKEN)
```

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

1. **Human authorized this** — Delegation token is signed, traceable to session
2. **Session was presence-attested** — Human touched YubiKey + entered PIN to create session
3. **Hardware-bound** — Original authentication used YubiKey 5 series (no platform passkeys)
4. **Scope is bounded** — Agent cannot exceed granted permissions
5. **Time is limited** — Credentials expire automatically

### What Delegation Does NOT Prove

1. **Agent identity** — Grantee name is self-reported
2. **Agent behavior** — What agent does with credentials is their responsibility
3. **Intent matching** — Agent might do unexpected things within scope

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Stolen delegation token | Short TTL (default 2h), revocation |
| Agent exceeds scope | Server enforces scope on every request |
| Grantor session compromised | Revoking session revokes all delegations |
| Agent persists credentials | Credentials also have short TTL |

### Best Practices

1. **Minimal scope** — Grant only what's needed
2. **Short TTL** — Start with 1-2 hours, extend only if needed
3. **Named grantees** — Use descriptive names for audit
4. **Revoke when done** — Don't leave delegations active
5. **Review audit logs** — Monitor what agents are doing

## Audit Trail

Every delegated action is logged with full provenance:

```json
{
  "timestamp": "2024-01-14T12:32:15.123Z",
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
      "authenticated_at": "2024-01-14T10:00:00Z"
    }
  },
  
  "credential": {
    "type": "github_token",
    "scope": "contents:write",
    "repository": "myorg/myrepo",
    "expires_at": "2024-01-14T13:32:15Z"
  },
  
  "delegation": {
    "id": "del_abc123",
    "created_at": "2024-01-14T12:00:00Z",
    "expires_at": "2024-01-14T14:00:00Z",
    "scope": "github:myorg/myrepo:contents:write",
    "reason": "Implementing feature X"
  }
}
```

This audit record proves:
- Alice authorized claude-code at 12:00
- Alice had presence-attested session from YubiKey at 10:00
- claude-code requested GitHub token at 12:32
- Token was scoped to contents:write on myorg/myrepo

## Organization Policies

Admins can configure delegation policies:

```yaml
# Organization delegation policy
delegation:
  # Maximum TTL any user can grant
  max_ttl: 8h
  
  # Require approval for certain scopes
  require_approval:
    - "aws:*:admin"
    - "github:*:admin"
  
  # Allowed grantee patterns
  allowed_grantees:
    - "claude-*"
    - "github-actions"
    - "jenkins-*"
  
  # Scopes that cannot be delegated
  restricted_scopes:
    - "ssh:prod-*.critical.com"
    - "aws:arn:aws:iam::*:role/admin"
```

## Future: Delegation Chains

Not in MVP, but planned:

```
Human (Alice)
    │
    │ delegates to
    ▼
Agent (claude-code)
    │
    │ sub-delegates to (with Alice's policy approval)
    ▼
Sub-Agent (code-review-bot)
```

Each link in the chain maintains attestation back to original human authorization.

## FAQ

**Q: Can an agent delegate to another agent?**
A: Not in v1. Delegation chains are planned for future versions with explicit policy controls.

**Q: What if my session expires during delegation?**
A: Delegation remains valid until its own expiration. However, if you explicitly logout (`vouch logout`), all delegations are revoked.

**Q: Can I delegate to myself?**
A: Yes, this is useful for creating scoped credentials for specific tasks without full session access.

**Q: How do I know what an agent did?**
A: `vouch delegation audit del_abc123` shows all credential requests and usage for a delegation.

**Q: Can delegations be transferred between machines?**
A: The delegation token is portable. The agent can use it from anywhere, subject to any IP restrictions in your organization policy.
