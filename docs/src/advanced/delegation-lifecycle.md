# Scopes and Lifecycle

This chapter covers how delegation scopes are specified and mapped to service-specific permissions, and describes the full delegation lifecycle from creation through revocation.

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

Each requires careful mapping from Vouch's scope syntax to the service's native permission model. AWS IAM policies and SSH certificate principals are fundamentally different systems.

## Delegation Lifecycle

### Create (Human-Initiated)

```bash
$ vouch delegate --to claude-code --scope "github:myorg/repo:contents:write" --ttl 2h

Delegation created:
  ID:      del_abc123
  Grantee: claude-code
  Scope:   github:myorg/repo:contents:write
  Expires: 2026-01-14T14:00:00Z

The agent can now use: VOUCH_DELEGATION_TOKEN=eyJ...

# With reason (for audit)
$ vouch delegate \
    --to claude-code \
    --scope "github:myorg/repo:contents:write" \
    --ttl 2h \
    --reason "Implementing feature X"
```

### Create (Agent-Initiated via CIBA)

The agent calls the backchannel authorization endpoint. The human approves via vouch-agent + YubiKey touch. See [CIBA Protocol](delegation-ciba.md) for the full flow.

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
  Created:    2026-01-14T12:00:00Z
  Expires:    2026-01-14T14:00:00Z
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
          # CI bot has a pre-configured delegation with limited scope.
          # CI_DELEGATION_TOKEN is provisioned via `vouch delegate` and stored
          # as a GitHub Actions secret by an administrator.
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

### Custom Integrations (Illustrative)

```python
import vouch  # SDK planned, not yet available

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
