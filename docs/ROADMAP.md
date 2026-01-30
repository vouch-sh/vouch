# Roadmap

This document outlines Vouch's development roadmap from MVP through production readiness.

## Vision

Vouch aims to be the standard for hardware-backed authentication — proving a human touched hardware before any credential is issued.

**"No credential without proven human presence."**

## Implementation Phases

### Phase 1: Agent Daemon (Weeks 1-2)

**Goal**: Background infrastructure that all credential integrations use.

**Status**: ✅ Core IPC complete, remaining items deferred to later phases.

**Deliverables:**
- [x] Unix socket IPC server at `~/.vouch/agent.sock`
- [x] JSON-RPC 2.0 protocol implementation (length-prefixed framing)
- [x] Session state management (store, retrieve, clear)
- [x] CLI client for agent communication
- [x] CLI commands integrated (login stores, status reads, logout clears)
- [x] Certificate cache infrastructure
- [x] Background cleanup tasks (sessions, device auth, OIDC states, events)
- [x] Graceful shutdown with signal handling
- [x] Daemon lifecycle - daemonization with PID file, --stop, --status, logging

**Files:**
| File | Description |
|------|-------------|
| `crates/vouch-agent/src/lib.rs` | Public API exports |
| `crates/vouch-agent/src/error.rs` | `AgentError` enum |
| `crates/vouch-agent/src/state.rs` | `Session`, `SessionInfo`, `AgentState` |
| `crates/vouch-agent/src/protocol.rs` | JSON-RPC request/response types |
| `crates/vouch-agent/src/socket.rs` | Socket path utilities |
| `crates/vouch-agent/src/server.rs` | Unix socket server with handlers |
| `crates/vouch-agent/src/client.rs` | `AgentClient` for CLI |
| `crates/vouch-agent/src/main.rs` | Daemon binary entrypoint |

**IPC Methods:**
| Method | Description |
|--------|-------------|
| `ping` | Health check |
| `get_session` | Get current session info |
| `store_session` | Store session after login |
| `clear_session` | Clear session (logout) |
| `get_token` | Get raw JWT for API calls |

**Verification:**
```bash
# Terminal 1: Start agent
cargo run --bin vouch-agent -- --foreground --verbose

# Terminal 2: Use CLI
vouch login     # No email needed - YubiKey identifies user
vouch status    # Shows "Authenticated (via agent)"
vouch logout
```

---

### Phase 2: Enrollment Flow (Weeks 3-4)

**Goal**: `vouch enroll` links Google Workspace identity to YubiKey passkey.

**Status**: ✅ Complete - RFC 8628 Device Authorization Grant implemented.

**Deliverables:**
- [x] RFC 8628 Device Authorization Grant (device code + user code)
- [x] Configurable OIDC integration (Google, Okta, Azure AD)
- [x] Browser WebAuthn passkey creation
- [x] CLI polling for authorization completion
- [x] Enrollment state storage

**Implementation:**
Instead of a local HTTP callback server, we use RFC 8628 Device Authorization Grant:

1. CLI requests device code from server (`POST /oauth/device/code`)
2. User visits verification URL and enters user code
3. Browser flow: OIDC login → WebAuthn registration
4. CLI polls token endpoint until authorized (`POST /oauth/token`)

**Server Endpoints:**
- `POST /oauth/device/code` → Generate device/user codes
- `POST /oauth/token` → Poll for token (authorization_pending/slow_down/token)
- `GET /device` → User code entry form
- `POST /device` → Validate code, redirect to OIDC
- `GET /oauth/callback` → OIDC returns here, show WebAuthn registration
- `POST /enroll/webauthn/start` → Return PublicKeyCredentialCreationOptions
- `POST /enroll/webauthn/complete` → Verify attestation, authorize device

**Files:**
| File | Description |
|------|-------------|
| `crates/vouch-server/src/handlers/device.rs` | Device authorization endpoints |
| `crates/vouch-server/src/handlers/enroll.rs` | Browser enrollment flow |
| `crates/vouch-cli/src/commands/enroll.rs` | CLI enroll command |
| `crates/vouch-server/migrations/002_device_auth.sql` | Device auth tables |

**Configuration:**
```bash
# Required
VOUCH_RP_ID=vouch.example.com
VOUCH_JWT_SECRET=<32+ char secret>

# OIDC (optional - enables identity verification)
VOUCH_OIDC_ISSUER=https://accounts.google.com
VOUCH_OIDC_CLIENT_ID=<client-id>
VOUCH_OIDC_CLIENT_SECRET=<client-secret>

# Optional
VOUCH_VERIFICATION_URL=https://vouch.example.com  # defaults to https://{rp_id}
VOUCH_DEVICE_CODE_EXPIRES=600                      # seconds
VOUCH_DEVICE_POLL_INTERVAL=5                       # seconds
```

**Verification:**
```bash
# Terminal 1: Start server
VOUCH_RP_ID=localhost \
VOUCH_JWT_SECRET=test-secret-at-least-32-chars-long \
VOUCH_VERIFICATION_URL=http://localhost:3000 \
cargo run --bin vouch-server

# Terminal 2: Run enroll
cargo run --bin vouch -- enroll --server http://localhost:3000
# Shows: "Go to http://localhost:3000/device and enter: ABCD-1234"

# Browser: Visit URL, enter code, register YubiKey
# Terminal 2: "Enrollment successful! Enrolled as: user@localhost"
```

---

### Phase 3: Discoverable Credential Login (Weeks 5-6)

**Goal**: `vouch login` with no email, using passkey from YubiKey.

**Status**: ✅ Complete - Discoverable credential login implemented.

**Deliverables:**
- [x] CTAP2 discoverable credential retrieval
- [x] Server lookup by credential_id/user_handle (no email in request)
- [x] Session token issuance with email in response
- [x] Agent session storage via IPC
- [x] CLI registration creates discoverable credentials (`.resident_key()`)
- [x] Browser enrollment requires discoverable credentials (`residentKey: 'required'`)
- [x] Database stores user_handle for credential lookup
- [x] Native PIN setup (detect missing PIN and guide user through setup)
- [x] 8-character minimum PIN requirement
- [x] User-friendly CTAP2 error messages for PIN issues

**Key Implementation:**
```rust
// Get passkey from YubiKey without knowing credential ID
let assertion = device.get_assertion_with_discoverable(
    "vouch.sh",           // RP ID
    &challenge,           // Server challenge
    None,                 // No allowed_credentials - discover from device
    Some(&pin),           // PIN required
)?;

// assertion.credential_id tells us which credential was used
// assertion.user.id (user_handle) identifies the user
// Server looks up: credential_id → authenticator, user_handle → user@company.com
```

**Server Changes:**
- `POST /v1/auth/login/start` → No email in request, just return challenge
- `POST /v1/auth/login/complete` → Look up user by credential_id + user_handle, return email

**Verification:**
```bash
vouch login
# If PIN not set:
#   Your YubiKey does not have a PIN configured.
#   Let's set one up now.
#   New PIN (minimum 8 characters): ********
#   Confirm PIN: ********
#   Setting PIN... done!
#
# Touch your YubiKey...
# YubiKey PIN: ********
# ✓ Login successful as user@company.com!

vouch status
# Session: active
# User: user@company.com
# Expires: 8 hours
```

---

### Phase 4: SSH Certificate Authority (Weeks 7-8)

**Goal**: Built-in SSH CA that signs user certificates.

**Status**: ✅ Complete - SSH CA implemented with Ed25519 signing.

**Deliverables:**
- [x] Ed25519 CA key generation and storage
- [x] SSH certificate signing endpoint
- [x] Principal extraction from user email
- [x] Certificate TTL aligned with session expiry
- [x] CA public key export for hosts

**Server Implementation:**
```rust
struct SshCa {
    signing_key: ed25519_dalek::SigningKey,
    public_key: ed25519_dalek::VerifyingKey,
}

// POST /v1/credentials/ssh
async fn issue_ssh_cert(
    session: &Session,
    user_pubkey: &SshPublicKey,
) -> Result<SshCertificate> {
    let principals = vec![
        session.user_email.clone(),
        extract_username(&session.user_email),
    ];

    let cert = self.ca.sign_user_cert(
        user_pubkey,
        &principals,
        Timestamp::now(),
        session.expires_at,  // Cert expires with session
    )?;

    Ok(cert)
}
```

**Files:**
| File | Description |
|------|-------------|
| `crates/vouch-server/src/ssh_ca.rs` | SSH CA implementation (key gen, signing) |
| `crates/vouch-server/src/handlers/credentials.rs` | SSH certificate endpoints |
| `crates/vouch-common/src/api.rs` | SSH request/response types |

**New Dependencies:**
| Crate | Purpose |
|-------|---------|
| `ssh-key` | SSH key/certificate parsing and signing |

---

### Phase 5: SSH Integration (Weeks 9-10)

**Goal**: `vouch setup ssh` configures everything automatically.

**Status**: ✅ Complete - SSH agent protocol implemented, auto-config working.

**Deliverables:**
- [x] SSH keypair generation (`~/.ssh/id_ed25519_vouch`)
- [x] SSH agent protocol implementation
- [x] SSH agent socket at `~/.vouch/ssh-agent.sock`
- [x] `~/.ssh/config` modification (IdentityAgent, IdentityFile, CertificateFile)
- [x] Certificate refresh within session
- [x] Certificate cache infrastructure
- [x] `vouch setup ssh` command
- [x] `vouch credential ssh` command

**Files:**
| File | Description |
|------|-------------|
| `crates/vouch-cli/src/commands/credential/ssh.rs` | SSH certificate credential command |
| `crates/vouch-cli/src/commands/setup/ssh.rs` | SSH CA setup command |

**SSH Agent Protocol:**
```rust
// Implement SSH agent protocol on ~/.vouch/ssh-agent.sock
match message {
    SSH_AGENTC_REQUEST_IDENTITIES => {
        // Return cached SSH certificate
        send_identities(&[self.ssh_cert])?;
    }
    SSH_AGENTC_SIGN_REQUEST { key, data } => {
        // Sign with user's private key
        let signature = self.user_key.sign(data)?;
        send_signature(signature)?;
    }
}
```

**Setup Output:**
```bash
$ vouch setup ssh
Generating SSH keypair...
  → ~/.ssh/id_ed25519_vouch (private key)
  → ~/.ssh/id_ed25519_vouch.pub (public key)

Configuring SSH...
  → Added IdentityAgent to ~/.ssh/config

Vouch CA fingerprint: SHA256:aBcDeFgHiJk...
  → Add to target hosts' TrustedUserCAKeys

✓ SSH integration configured
```

**Verification:**
```bash
vouch setup ssh
# ✓ SSH integration configured

ssh user@server
# [No prompts - uses Vouch certificate]
```

---

### Phase 6: OIDC Provider & AWS (Weeks 11-12)

**Goal**: Vouch acts as OIDC provider for AWS federation.

**Status**: ✅ Complete - OIDC Provider, Admin IdP Portal, and AWS integration implemented.

**Deliverables:**
- [x] OIDC discovery endpoint (`/.well-known/openid-configuration`)
- [x] JWKS endpoint (`/oauth/jwks`)
- [x] Authorization endpoint (`/oauth/authorize`)
- [x] UserInfo endpoint (`/oauth/userinfo`)
- [x] Smart landing page routing (two-persona: admin vs developer)
- [x] Admin setup wizard page (`/admin-setup`)
- [x] Developer setup page (`/developer-setup`)
- [x] Cookie file storage for CLI tools (`~/.vouch/cookie.txt`)
- [x] Token exchange for authorization_code grant
- [x] Token Revocation endpoint (RFC 7009)
- [x] Token Introspection endpoint (RFC 7662)
- [x] Admin IdP Portal (self-service external IdP configuration)
- [x] AWS STS integration
- [x] `vouch credential aws` command
- [x] `vouch setup aws` command

**OIDC Endpoints:**
```
GET  /.well-known/openid-configuration  # Discovery document
GET  /oauth/jwks                         # Public keys
GET  /oauth/authorize                    # Authorization endpoint
POST /oauth/token                        # Token exchange (device + auth code)
POST /oauth/revoke                       # Token revocation (RFC 7009)
POST /oauth/introspect                   # Token introspection (RFC 7662)
GET  /oauth/userinfo                     # User info endpoint
```

**Landing Page Routing:**
- If OIDC not configured → Show two-persona page (admin/developer)
- If OIDC configured → Show org enrollment page

**Session Storage:**
- Cookie file at `~/.vouch/cookie.txt` (Netscape format)
- Written on login, cleared on logout
- 0600 permissions for security

**AWS Credential Flow:**
```bash
$ vouch credential aws --role arn:aws:iam::123456789:role/developer
# 1. Get OIDC token from Vouch server
# 2. Call AWS STS AssumeRoleWithWebIdentity
# 3. Return temporary credentials in credential_process format
```

**New Dependencies:**
| Crate | Purpose |
|-------|---------|
| `oauth2` | OAuth/OIDC client for enrollment |

---

### Phase 7: Application Registration Portal (Weeks 13-14)

**Goal**: Self-service portal for developers to register OAuth applications.

**Status**: ✅ Complete

**Deliverables:**
- [x] Application data model (clients, secrets, redirect URIs)
- [x] Self-service registration web UI
- [x] Client credential generation (client_id, client_secret)
- [x] Support for application types (web, native, SPA, service)
- [x] Credential rotation with grace period
- [x] Application revocation
- [x] Usage statistics per application
- [x] API endpoints for programmatic management
- [x] Token endpoint validation of registered clients

**Files:**
| File | Description |
|------|-------------|
| `crates/vouch-server/migrations/008_oauth_clients.sql` | OAuth clients schema |
| `crates/vouch-server/src/handlers/applications.rs` | Web UI and API handlers |
| `crates/vouch-server/src/db.rs` | CRUD operations for OAuth clients |
| `crates/vouch-server/templates/applications/` | Portal UI templates |

**User Flow:**
```
1. User authenticates to Vouch (with YubiKey)
2. User navigates to "My Applications" in web portal
3. User clicks "Register New Application"
4. User provides:
   - Application name
   - Redirect URIs (for authorization_code flow)
   - Application type (web, native, SPA)
5. Vouch generates:
   - client_id (public identifier)
   - client_secret (for confidential clients only)
6. User can view/rotate/revoke credentials
```

**Application Types:**
| Type | Description | PKCE | client_secret |
|------|-------------|------|---------------|
| Web | Server-side apps | Recommended | Yes |
| Native | Desktop/mobile apps | Required | No |
| SPA | Browser-only apps | Required | No |
| Service | Machine-to-machine | N/A | Yes |

**API Endpoints:**
```
GET    /api/v1/applications        # List user's applications
POST   /api/v1/applications        # Register new application
GET    /api/v1/applications/:id    # Get application details
PATCH  /api/v1/applications/:id    # Update application
DELETE /api/v1/applications/:id    # Delete application
POST   /api/v1/applications/:id/rotate  # Rotate client_secret
POST   /api/v1/applications/:id/revoke  # Revoke all tokens
```

**Verification:**
```bash
# After registering an application in the portal:
curl -X POST https://vouch.example.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "redirect_uri=https://myapp.com/callback"
```

---

## Post-MVP Milestones

### v0.5 — GitHub Integration (Month 4)

- [x] GitHub App registration
- [x] Installation token issuance
- [x] Git credential helper
- [x] `vouch setup github` command
- [x] Repository-scoped tokens

### v0.6 — Enterprise Features (Month 5)

- [ ] Admin console (web UI)
- [x] Admin IdP Portal
  - [x] Self-service external IdP configuration
  - [x] Google Workspace integration
  - [x] Microsoft Entra ID integration
  - [x] Generic OIDC provider support
  - [x] Connection testing and validation
- [x] SCIM 2.0 de-provisioning (RFC 7643/7644) — **launch requirement**
  - [x] User provisioning (create, update, list, get)
  - [x] User de-provisioning (immediate session invalidation)
  - [x] SCIM endpoint authentication (bearer token)
  - [x] Audit logging for provisioning events
  - [x] SCIM token management API
- [ ] Audit log export (Splunk, Datadog)
- [ ] Organization policies
- [x] Self-service YubiKey management
  - [x] `vouch keys` - Interactive key management menu
  - [x] `vouch keys list` - List registered keys
  - [x] `vouch keys remove` - Remove a registered key
  - [x] `vouch keys rename` - Rename a registered key

### v0.7 — Agent Delegation (Month 6)

- [ ] Delegation data model
- [ ] `vouch delegate` command
- [ ] Scoped credential issuance
- [ ] Delegation audit trail
- [ ] Revocation

### v0.8 — Air-Gapped Deployment (Month 7)

- [ ] Self-hosted server packaging
- [ ] On-premises CA setup
- [ ] Offline update bundles
- [ ] Time sync documentation
- [ ] Compliance documentation

### v0.9 — Kubernetes Integration (Month 8)

- [ ] Kubernetes exec credential plugin
- [ ] OIDC authentication to clusters
- [ ] `vouch setup kube` command
- [ ] Namespace/cluster scoping

### v1.0 — Production Ready (Month 9-10)

- [ ] SOC 2 Type II certification
- [ ] 99.9% SLA for Vouch Cloud
- [ ] Enterprise support tiers
- [ ] Penetration testing
- [ ] Public security audit

---

## Future Considerations (v1.0+)

### Additional RFC Standards (Implemented)
- **RFC 9449 (DPoP)** ✅ — Demonstrating Proof of Possession; sender-constrains tokens so stolen tokens can't be used. Full implementation with signature verification for ES256, RS256, and EdDSA algorithms, JTI replay prevention, nonce management, and discovery endpoint support.
- **RFC 8693 (Token Exchange)** ✅ — Exchange tokens between services; useful for microservices architectures. Full implementation with delegation policies, audience validation, scope downgrading, and policy-based TTL limits.

### Federation
- Cross-organization trust
- Contractor access patterns
- Multi-tenant delegation

### Browser Extension
- Native messaging bridge to vouch-agent
- Session sharing CLI ↔ browser
- Web app credential injection

### Mobile
- iOS/Android apps
- NFC YubiKey support
- Mobile-to-desktop session transfer

### Advanced Integrations
- HashiCorp Vault
- [x] GCP Workload Identity — **Implemented**
  - [x] `vouch credential gcp` command (AIP-4117 format)
  - [x] `vouch setup gcp` command with server-provided config
  - [x] Server-side integration config API (`/v1/integrations/gcp`)
  - [x] Organization-wide GCP settings (project_number, pool_id, provider_id)
  - [x] Profile support for multiple service accounts
- Azure Managed Identity
- Database credential rotation

### Compliance Expansion
- FedRAMP Moderate
- ISO 27001
- HIPAA BAA

---

## Success Metrics

### MVP (Phase 6 Complete)

| Metric | Target |
|--------|--------|
| User setup time | < 5 minutes |
| Time to first SSH | < 2 minutes after setup |
| Design partners | 5-10 active |
| Daily active users | 50+ |

### v1.0

| Metric | Target |
|--------|--------|
| Paying customers | 10+ |
| ARR | $100K+ |
| Uptime (Vouch Cloud) | 99.9% |
| P95 latency (credential issuance) | < 200ms |

---

## Distribution & Deployment

### CLI Distribution
- [ ] GitHub Releases with pre-compiled binaries (macOS, Linux, Windows)
- [ ] SBOM (Software Bill of Materials) for each release
- [ ] SLSA attestations for supply chain security
- [ ] Homebrew tap (`vouch-sh/tap/vouch`)
- [ ] APT/RPM repositories

### Server Distribution
- [ ] Docker images (multi-arch: amd64, arm64)
- [ ] Helm charts for Kubernetes deployment
- [ ] Terraform modules (AWS, GCP, Azure)
- [ ] docker-compose examples

### Multi-Tenancy (dev.vouch.sh)
- [x] Organizations table with domain-based isolation
- [x] `hd` claim extraction from Google OIDC
- [x] Personal accounts (gmail.com) with no org
- [x] First user from domain becomes org admin
- [x] Org-scoped admin views
- [x] Direct browser enrollment (no CLI required)
- [ ] Organization settings (name, branding)
- [ ] Usage metrics per organization

---

## Technical Debt & Improvements

Tracked but not blocking releases:

- [ ] Reproducible builds
- [ ] Fuzzing for FIDO2 parsing
- [ ] Performance benchmarks
- [x] Integration test suite (34 tests covering RFC compliance)
  - Device authorization lifecycle (RFC 8628)
  - OAuth client registration and management
  - SCIM user provisioning (RFC 7643/7644)
  - Session and token management
  - Authentication event logging
  - Cascade delete behavior
- [x] CLI shell completions (bash, zsh, fish, powershell, elvish)
- [x] `vouch doctor` diagnostic command (YubiKey, agent, server, session, SSH config)
- [ ] Internationalization
- [ ] Windows support

---

## How to Contribute

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development setup and guidelines.

Roadmap priorities are driven by:
1. Design partner feedback
2. Security requirements
3. Integration requests
4. Community contributions

To propose a feature, open a GitHub Discussion.
