# vouch

**Hardware-backed identity for developers.**

One tap. Any credential. Full audit trail.

```bash
vouch login                              # Touch YubiKey → 8hr session
vouch get github                         # → Short-lived token
vouch delegate --name claude-agent \     # → AI agent gets scoped creds
    --github-repo 'myorg/*' \
    --ttl 1h
```

## The Problem

Developers juggle too many long-lived secrets:

- GitHub PATs that never expire
- AWS access keys in `~/.aws/credentials`
- SSH keys that stick around forever

These secrets get leaked, shared, and forgotten. When an AI coding assistant needs access, developers often just hand over their own credentials with no audit trail.

## The Solution

vouch replaces long-lived secrets with short-lived credentials issued on demand:

1. **Hardware-bound authentication** - YubiKey or Touch ID required
2. **Short-lived credentials** - Expire in minutes or hours, not years
3. **Agent delegation** - Grant scoped access to AI assistants with full audit trail
4. **No proxy required** - Unlike Teleport, vouch doesn't intercept your traffic

## Quick Start

```bash
# Install
cargo install vouch-cli

# Register your YubiKey
vouch register

# Login (8-hour session)
vouch login

# Get GitHub credentials
vouch get github

# Configure git to use vouch
vouch git-config --global
```

## Agent Delegation

The killer feature: let AI agents act on your behalf with scoped, auditable credentials.

```bash
# Create a delegation for your AI coding agent
vouch delegate create \
    --name "claude-code" \
    --github-repo "myorg/frontend" \
    --github-branch "feature/*" \
    --ttl 4h

# Output:
# ✓ Delegation created
#   Name:       claude-code
#   ID:         d7f3a2b1-...
#   Expires:    2024-01-15T18:00:00Z
#
# Delegation token (give this to your agent):
# eyJhbGciOiJFZDI1NTE5...
```

The agent uses this token to get credentials. Every action is logged with `presence_type: "human_delegated"` so you know exactly what the agent did.

## How It Works

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│                 │       │                 │       │                 │
│   vouch CLI     │──────▶│  vouch server   │──────▶│    GitHub       │
│                 │       │                 │       │    AWS          │
│   vouch agent   │       │  (your infra)   │       │    SSH hosts    │
│                 │       │                 │       │                 │
└─────────────────┘       └─────────────────┘       └─────────────────┘
        │
        │ FIDO2
        ▼
   ┌─────────┐
   │ YubiKey │
   │ TouchID │
   └─────────┘
```

### Authentication Flow

1. `vouch login` opens a browser window
2. User authenticates with YubiKey/Touch ID (FIDO2/WebAuthn)
3. Server issues a JWT session token (8 hour TTL)
4. CLI stores token locally

### Credential Issuance

When you run `vouch get github`:

1. CLI sends session token to server
2. Server validates token, checks it's not expired
3. Server uses GitHub App to generate installation token
4. Server returns short-lived token to CLI
5. Server logs the issuance to audit trail

### Delegation Flow

When an AI agent uses a delegation token:

1. Agent requests credential with delegation token
2. Server validates delegation is not expired/revoked
3. Server checks requested scope is within delegation scope
4. Server issues credential with `presence_type: human_delegated`
5. Server logs with delegation ID for audit trail

## Integrations

### GitHub

vouch uses a GitHub App to issue short-lived installation tokens.

```bash
# Get a token for git operations
vouch get github

# Or configure git to use vouch automatically
vouch git-config --global
git push  # vouch handles auth transparently
```

### AWS

vouch acts as an OIDC identity provider, using AWS STS to issue temporary credentials.

```bash
# Get credentials as environment variables
eval $(vouch get aws --role arn:aws:iam::123456789:role/dev)

# Or configure AWS CLI to use vouch
vouch aws-config --profile dev --role-arn arn:aws:iam::123456789:role/dev
aws --profile dev s3 ls
```

### SSH

vouch includes a certificate authority for signing short-lived SSH certificates.

```bash
# Get a signed certificate
vouch get ssh --principal ubuntu

# SSH to a host that trusts vouch CA
ssh ubuntu@server
```

## Self-Hosting

```bash
# Run the server
docker run -d \
    -e VOUCH_RP_ID=auth.yourcompany.com \
    -e VOUCH_RP_ORIGIN=https://auth.yourcompany.com \
    -e VOUCH_JWT_SECRET=$(openssl rand -hex 32) \
    -v vouch-data:/data \
    ghcr.io/vouch-sh/vouch-server

# Point CLI to your server
export VOUCH_SERVER_URL=https://auth.yourcompany.com
vouch register
```

## Comparison

| Aspect | vouch | Teleport | Tailscale | 1Password |
|--------|-------|----------|-----------|-----------|
| **Primary Focus** | Developer identity | Infrastructure access | Network mesh | Secret storage |
| **Architecture** | Local agent | Proxy-based | WireGuard mesh | Cloud vault |
| **Auth Method** | Hardware FIDO2 | SSO + certs | OAuth | Master password |
| **Credential Scope** | Per-request capable | Session-level | Device-level | Manual retrieval |
| **Agent Delegation** | ✅ First-class | ❌ | ❌ | ❌ |
| **Audit Trail** | Human vs agent | User only | User only | User only |

## Project Structure

```
crates/
├── vouch-cli/      # CLI tool (`vouch` command)
├── vouch-server/   # Identity server
├── vouch-agent/    # Local credential agent
└── vouch-common/   # Shared types

docs/
├── ARCHITECTURE.md # System design
├── SECURITY.md     # Threat model
└── DELEGATION.md   # Agent delegation design
```

## Status

🚧 **Pre-alpha** — Not ready for production use.

See [docs/ROADMAP.md](docs/ROADMAP.md) for planned features.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

## License

Apache-2.0
