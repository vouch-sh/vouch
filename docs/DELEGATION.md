# Agent Delegation

This document describes vouch's delegation model for granting scoped access to AI agents and automated tools.

## The Problem

AI coding assistants (Claude, Copilot, Cursor) need access to your development resources:

- Push code to GitHub
- Deploy to AWS
- SSH into servers

Today, developers either:
1. **Share their own credentials** - No audit trail, full access
2. **Create service accounts** - Hard to manage, often over-permissioned
3. **Don't use AI assistants** - Miss out on productivity gains

vouch introduces **delegation** - a way to grant scoped, time-limited, auditable access to agents.

## Design Goals

1. **Scoped** - Agents only get access to what they need
2. **Time-limited** - Delegations expire automatically
3. **Auditable** - Clear distinction between human and agent actions
4. **Revocable** - Instant revocation if something goes wrong
5. **Frictionless** - Easy for humans to grant, easy for agents to use

## How It Works

### Creating a Delegation

```bash
vouch delegate create \
    --name "claude-code" \
    --github-repo "myorg/frontend" \
    --github-branch "feature/*" \
    --ttl 4h
```

This creates a delegation with:
- **Name**: Human-readable identifier
- **Scope**: What the agent can access (repos, branches, roles)
- **TTL**: How long the delegation is valid
- **Token**: A JWT the agent uses to request credentials

### Delegation Token

The token is a JWT containing:

```json
{
  "sub": "delegation:d7f3a2b1-...",
  "iss": "https://vouch.example.com",
  "iat": 1705334400,
  "exp": 1705348800,
  "scope": {
    "targets": [
      {
        "type": "github",
        "repositories": ["myorg/frontend"],
        "branches": ["feature/*"]
      }
    ]
  },
  "user_id": "u-abc123",
  "delegation_id": "d-xyz789"
}
```

The scope is cryptographically bound to the token - an agent cannot modify it.

### Agent Using a Delegation

The agent includes the delegation token when requesting credentials:

```bash
# Agent's request
curl -X POST https://vouch.example.com/v1/credentials/github \
  -H "Authorization: Bearer <delegation_token>" \
  -d '{"repository": "myorg/frontend"}'
```

The server:
1. Validates the delegation token signature
2. Checks the delegation is not expired or revoked
3. Verifies the requested resource is within scope
4. Issues a short-lived credential
5. Logs the issuance with `presence_type: human_delegated`

### Audit Trail

Every credential issued via delegation is logged:

```json
{
  "id": "audit-123",
  "timestamp": "2024-01-15T14:30:00Z",
  "user_id": "u-abc123",
  "action": "credential_issued",
  "target_type": "github",
  "target_details": {
    "repository": "myorg/frontend",
    "permissions": ["contents:write"]
  },
  "presence_type": "human_delegated",
  "delegation_id": "d-xyz789",
  "delegation_name": "claude-code"
}
```

This creates a clear paper trail: "User Alice delegated to claude-code, which pushed to myorg/frontend at 2:30 PM."

## Scope Model

### GitHub Scope

```yaml
type: github
repositories:
  - "myorg/frontend"      # Exact match
  - "myorg/api-*"         # Glob pattern
branches:
  - "feature/*"           # Can only push to feature branches
  - "fix/*"
permissions:
  contents: write
  pull_requests: write
  issues: read
```

### AWS Scope

```yaml
type: aws
role_arns:
  - "arn:aws:iam::123456789:role/dev-deploy"
  - "arn:aws:iam::123456789:role/staging-deploy"
# Note: Further permission scoping happens via IAM policies
```

### SSH Scope

```yaml
type: ssh
principals:
  - "deploy"
  - "ubuntu"
hosts:
  - "*.dev.example.com"   # Glob pattern
  - "staging.example.com"
```

## Scope Validation

When an agent requests a credential, the server validates:

1. **Target type matches** - GitHub request requires GitHub in scope
2. **Resource matches** - Requested repo matches a pattern in scope
3. **Permissions are subset** - Requested permissions ≤ delegated permissions
4. **Branch matches** (for GitHub) - Requested branch matches pattern

Example validation:

```
Delegation scope:
  github:
    repositories: ["myorg/*"]
    branches: ["feature/*"]

Request: github token for myorg/frontend, branch feature/new-ui
Result: ✅ Allowed

Request: github token for myorg/frontend, branch main
Result: ❌ Denied (branch not in scope)

Request: github token for other-org/repo
Result: ❌ Denied (repo not in scope)
```

## Revocation

Delegations can be revoked instantly:

```bash
vouch delegate revoke d-xyz789
```

After revocation:
- The delegation is marked `revoked: true` in the database
- All subsequent credential requests are rejected
- Existing credentials continue to work until they expire (short TTL)

For immediate credential invalidation, you would need to revoke at the target service level (e.g., revoke the GitHub token).

## Use Limits

Delegations can have use limits:

```bash
vouch delegate create \
    --name "one-time-deploy" \
    --aws-role "arn:aws:iam::123:role/prod-deploy" \
    --max-uses 1 \
    --ttl 1h
```

After the limit is reached, subsequent requests are rejected.

## Best Practices

### For Humans

1. **Scope narrowly** - Only grant access to what the agent needs
2. **Use short TTLs** - Start with 1-4 hours, extend if needed
3. **Name descriptively** - Use names like "claude-feature-123" not "agent"
4. **Review regularly** - Run `vouch delegate list` to see active delegations
5. **Revoke when done** - Don't let delegations expire naturally

### For Agent Developers

1. **Request minimum scope** - Ask for only what you need
2. **Handle rejection gracefully** - If scope is exceeded, explain to user
3. **Support step-up** - When you need more access, prompt user to create new delegation
4. **Log your actions** - Maintain your own audit trail
5. **Refresh proactively** - Request new credentials before expiry

## Integration Guide

### For AI Agent Frameworks

```python
import vouch

# Initialize with delegation token
client = vouch.Client(delegation_token=os.environ["VOUCH_DELEGATION_TOKEN"])

# Request credentials when needed
github_token = client.get_github_token(repository="myorg/frontend")

# Use the token
# Token is short-lived, refresh as needed
```

### Environment Variable Convention

Agents should accept delegation tokens via:

```bash
VOUCH_DELEGATION_TOKEN=eyJ...
```

This allows users to pass tokens without modifying agent code.

## Future Enhancements

### Planned

- **Step-up requests** - Agent can request human approval for out-of-scope actions
- **Delegation templates** - Pre-defined scopes for common use cases
- **Delegation chains** - Agents delegating to sub-agents (with scope reduction)
- **Usage analytics** - Dashboard showing delegation usage patterns

### Under Consideration

- **Approval workflows** - Require second human to approve sensitive delegations
- **Geo-fencing** - Restrict delegations to specific locations
- **Time-of-day restrictions** - Only allow delegations during business hours
