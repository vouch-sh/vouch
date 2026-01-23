# Architecture

This document describes the high-level architecture of vouch.

## Design Principles

1. **Hardware-bound identity** - Authentication requires physical presence (YubiKey tap or Touch ID)
2. **Short-lived credentials** - Nothing lasts longer than necessary
3. **Audit everything** - Every credential issuance is logged with context
4. **Human vs agent distinction** - The system knows whether a human or delegated agent performed an action
5. **No proxy** - vouch issues credentials, it doesn't intercept traffic

## Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DEVELOPER MACHINE                               │
│                                                                              │
│  ┌──────────────┐     ┌──────────────────────────────────────────────────┐  │
│  │              │     │                 vouch agent                       │  │
│  │  vouch CLI   │────▶│  ┌────────────────┐  ┌────────────────────────┐  │  │
│  │              │     │  │ Credential     │  │ Unix Socket API        │  │  │
│  └──────────────┘     │  │ Cache (memory) │  │ /run/vouch.sock        │  │  │
│         │             │  └────────────────┘  └────────────────────────┘  │  │
│         │             └──────────────────────────────────────────────────┘  │
│         │                              ▲                                     │
│         ▼                              │                                     │
│  ┌──────────────┐           ┌──────────┴─────────────────────────────────┐  │
│  │   YubiKey    │           │              Tool Integrations              │  │
│  │   Touch ID   │           │  ┌───────┐ ┌───────┐ ┌───────┐ ┌────────┐  │  │
│  │   (FIDO2)    │           │  │  git  │ │  aws  │ │  ssh  │ │ claude │  │  │
│  └──────────────┘           │  │       │ │  cli  │ │       │ │  code  │  │  │
│                             │  └───────┘ └───────┘ └───────┘ └────────┘  │  │
│                             └────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         │ HTTPS
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              vouch server                                    │
│                                                                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐  │
│  │                 │  │                 │  │                             │  │
│  │  FIDO2/WebAuthn │  │  Credential     │  │  Delegation                 │  │
│  │  Service        │  │  Issuance       │  │  Management                 │  │
│  │                 │  │                 │  │                             │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────────────────┘  │
│           │                    │                        │                    │
│           ▼                    ▼                        ▼                    │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                           SQLite Database                              │  │
│  │  users │ authenticators │ sessions │ delegations │ audit_log          │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         │ API calls
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           External Services                                  │
│                                                                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐  │
│  │                 │  │                 │  │                             │  │
│  │  GitHub API     │  │  AWS STS        │  │  SSH Hosts                  │  │
│  │  (App tokens)   │  │  (OIDC fed)     │  │  (CA-signed certs)          │  │
│  │                 │  │                 │  │                             │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## vouch CLI

The CLI (`vouch`) is the primary user interface. It handles:

- **Registration** - Enrolling a new FIDO2 authenticator
- **Login** - Starting a session by authenticating with hardware
- **Credential retrieval** - Getting short-lived tokens for GitHub/AWS/SSH
- **Delegation management** - Creating/revoking agent delegations

The CLI stores minimal state locally:
- Session token (JWT)
- Server URL
- User email (for display)

Credentials are never stored on disk - they're retrieved on demand and held in memory by the agent.

## vouch agent

The agent is a local daemon that:

- Caches credentials in memory (never on disk)
- Exposes a Unix socket for tool integrations
- Implements the git credential helper protocol
- Implements the AWS credential_process protocol

Tools like `git` and `aws` communicate with the agent via these standard protocols, making vouch transparent to existing workflows.

## vouch server

The server is the central authority. It:

- Manages FIDO2 registration and authentication
- Issues session tokens (JWTs)
- Issues short-lived credentials for external services
- Manages delegations
- Maintains the audit log

### Authentication Flow

```
┌────────┐          ┌────────┐          ┌────────┐
│  CLI   │          │ Server │          │Browser │
└───┬────┘          └───┬────┘          └───┬────┘
    │                   │                   │
    │ GET /login/start  │                   │
    │──────────────────▶│                   │
    │                   │                   │
    │  {login_url, code}│                   │
    │◀──────────────────│                   │
    │                   │                   │
    │                   │   Open URL        │
    │───────────────────┼──────────────────▶│
    │                   │                   │
    │                   │ WebAuthn ceremony │
    │                   │◀─────────────────▶│
    │                   │                   │
    │ POST /login/complete (poll)           │
    │──────────────────▶│                   │
    │                   │                   │
    │  {token, user}    │                   │
    │◀──────────────────│                   │
    │                   │                   │
```

### Credential Issuance Flow

```
┌────────┐          ┌────────┐          ┌────────┐
│  CLI   │          │ Server │          │ GitHub │
└───┬────┘          └───┬────┘          └───┬────┘
    │                   │                   │
    │ POST /credentials/github              │
    │ Authorization: Bearer <session>       │
    │──────────────────▶│                   │
    │                   │                   │
    │                   │ Generate App JWT  │
    │                   │──────────────────▶│
    │                   │                   │
    │                   │ Installation token│
    │                   │◀──────────────────│
    │                   │                   │
    │                   │ Log to audit_log  │
    │                   │                   │
    │  {token, expires} │                   │
    │◀──────────────────│                   │
    │                   │                   │
```

## Database Schema

The server uses SQLite with these tables:

- **users** - User accounts (from OIDC provider)
- **authenticators** - Registered FIDO2 devices
- **sessions** - Active login sessions
- **delegations** - Agent authorization grants
- **audit_log** - Credential issuance history

See `crates/vouch-server/migrations/001_initial.sql` for the full schema.

## Security Boundaries

### Trust Model

- The vouch server is trusted to issue credentials correctly
- FIDO2 authenticators are trusted to attest user presence
- External services (GitHub, AWS) trust vouch as an identity provider

### What vouch protects against

- Credential theft (no long-lived secrets to steal)
- Unauthorized agent actions (delegations are scoped and audited)
- Phishing (FIDO2 is phishing-resistant)

### What vouch does NOT protect against

- Compromised vouch server (it's a central authority)
- Malicious code running with user's session token
- Physical theft of unlocked device with active session

## Credential Types

### GitHub

vouch runs as a GitHub App. When you request a GitHub token:

1. Server generates a JWT signed with the App's private key
2. Server exchanges JWT for an installation access token
3. Token is scoped to the repositories the App is installed on
4. Token expires in 1 hour (GitHub's limit)

### AWS

vouch acts as an OIDC identity provider:

1. Server issues a vouch JWT with user identity claims
2. AWS STS validates the JWT against vouch's JWKS endpoint
3. STS issues temporary credentials for the requested role
4. Credentials expire based on role's max session duration

### SSH

vouch includes a Certificate Authority:

1. User provides their public key
2. Server signs a certificate with the CA key
3. Certificate includes principals (usernames) and validity period
4. Target hosts trust the CA public key

## Delegation Model

Delegations allow humans to grant agents permission to act on their behalf:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Delegation                                │
│                                                                  │
│  id: uuid                                                        │
│  user_id: uuid (who created it)                                  │
│  name: "claude-code"                                             │
│  scope:                                                          │
│    targets:                                                      │
│      - type: github                                              │
│        repositories: ["myorg/frontend", "myorg/api"]             │
│        branches: ["feature/*"]                                   │
│    operations: null (all allowed within scope)                   │
│  expires_at: 2024-01-15T18:00:00Z                                │
│  max_uses: null (unlimited)                                      │
│  revoked: false                                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

When an agent requests credentials with a delegation token:

1. Server validates delegation exists and is not expired/revoked
2. Server checks requested credential is within delegation scope
3. Server issues credential with `presence_type: human_delegated`
4. Server logs issuance with `delegation_id` for audit

This creates a clear audit trail distinguishing human actions from agent actions.
