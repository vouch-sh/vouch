# Roadmap

This document outlines the planned development milestones for vouch.

## Current Status: Pre-Alpha

The project is scaffolded but not yet functional. Core authentication flows are stubbed.

---

## Milestone 1: Core Authentication (v0.1)

**Goal**: One human can register, login, and get a GitHub token.

### Deliverables

- [ ] FIDO2 registration flow (server + browser)
- [ ] FIDO2 login flow (server + browser)
- [ ] JWT session token issuance
- [ ] JWT session token validation
- [ ] GitHub App integration
- [ ] `vouch register` working end-to-end
- [ ] `vouch login` working end-to-end
- [ ] `vouch get github` working end-to-end

### Technical Tasks

1. Wire up `webauthn-rs` for FIDO2 ceremonies
2. Implement challenge storage and validation
3. Add JWT signing with `jsonwebtoken`
4. Integrate `octocrab` for GitHub App tokens
5. Complete the browser WebAuthn pages

### Success Criteria

```bash
vouch register   # Opens browser, registers YubiKey
vouch login      # Opens browser, authenticates
vouch get github # Returns a working GitHub token
git push         # Works with the token
```

---

## Milestone 2: Agent Delegation (v0.2)

**Goal**: A human can delegate to an AI agent with scoped access.

### Deliverables

- [ ] Delegation creation (`vouch delegate create`)
- [ ] Delegation token issuance (JWT)
- [ ] Scope validation on credential requests
- [ ] Audit logging with presence_type
- [ ] Delegation listing and revocation
- [ ] Use count limits

### Technical Tasks

1. Implement delegation database operations
2. Add scope validation logic with glob matching
3. Extend audit logging
4. Add delegation JWT claims and validation

### Success Criteria

```bash
vouch delegate create --name claude --github-repo "myorg/*" --ttl 1h
# Returns delegation token

# Agent uses token
curl -H "Authorization: Bearer <delegation_token>" \
  https://vouch.example.com/v1/credentials/github

# Audit log shows presence_type: human_delegated
```

---

## Milestone 3: Local Agent (v0.3)

**Goal**: Transparent integration with git and other tools.

### Deliverables

- [ ] vouch-agent daemon
- [ ] Unix socket IPC
- [ ] Git credential helper protocol
- [ ] In-memory credential caching
- [ ] `vouch agent start/stop/status`
- [ ] `vouch git-config` helper

### Technical Tasks

1. Implement Unix socket listener
2. Add git credential helper protocol parsing
3. Implement credential cache with TTL
4. Daemonization (or systemd unit)

### Success Criteria

```bash
vouch agent start
vouch git-config --global
git push  # Works without manual token retrieval
```

---

## Milestone 4: AWS Integration (v0.4)

**Goal**: Get AWS credentials via OIDC federation.

### Deliverables

- [ ] OIDC provider endpoints (/.well-known/openid-configuration, /jwks)
- [ ] AWS STS integration
- [ ] `vouch get aws` command
- [ ] AWS credential_process support
- [ ] `vouch aws-config` helper

### Technical Tasks

1. Implement OIDC discovery endpoints
2. Add JWKS endpoint with signing keys
3. Integrate `aws-sdk-sts` for AssumeRoleWithWebIdentity
4. Implement credential_process JSON output

### Success Criteria

```bash
vouch get aws --role arn:aws:iam::123:role/dev --format json
# Returns credential_process format

aws --profile vouch sts get-caller-identity
# Works
```

---

## Milestone 5: SSH Certificates (v0.5)

**Goal**: Issue short-lived SSH certificates.

### Deliverables

- [ ] SSH CA key management
- [ ] Certificate signing
- [ ] `vouch get ssh` command
- [ ] Principal validation
- [ ] Certificate extensions

### Technical Tasks

1. Generate/store SSH CA key pair
2. Implement SSH certificate signing
3. Add principal/extension configuration
4. Document host-side setup

### Success Criteria

```bash
vouch get ssh --principal ubuntu > ~/.ssh/id_ed25519-cert.pub
ssh ubuntu@server  # Works with certificate
```

---

## Milestone 6: Production Readiness (v1.0)

**Goal**: Ready for production deployment.

### Deliverables

- [ ] Docker image
- [ ] Kubernetes Helm chart
- [ ] Configuration documentation
- [ ] Security hardening review
- [ ] Performance testing
- [ ] Monitoring/alerting integration

### Non-Functional Requirements

- < 100ms p99 latency for credential issuance
- Support 1000 concurrent users
- Zero-downtime deployments
- Backup/restore procedures

---

## Future Milestones (Post-1.0)

### v1.1: Enhanced Delegation

- Step-up approval requests
- Delegation templates
- Usage analytics dashboard

### v1.2: Enterprise Features

- SAML/OIDC SSO integration
- Multi-tenant support
- Policy-as-code (OPA integration)

### v1.3: Extended Integrations

- Kubernetes service account tokens
- Database credential rotation
- Cloud provider plugins (GCP, Azure)

---

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to get involved.

Priorities are determined by user feedback. Open an issue to suggest features or vote on existing ones.
