# Components

This chapter describes the core components of the Vouch system, including the CLI, background agent, server modules, and external integrations.

## vouch CLI (`vouch-cli`)

The user-facing command-line tool. Written in Rust using:
- `ctap-hid-fido2` — Pure Rust FIDO2/CTAP2 implementation
- `clap` — CLI argument parsing
- `reqwest` + `rustls` — HTTPS without OpenSSL dependencies

**Key design decisions:**
- Single statically-linked binary (MUSL target for Linux)
- No runtime dependencies
- Startup time <1ms
- Open source (Apache-2.0 OR MIT) for security auditing

**FAPI 2.0 Client:**

The CLI operates as a FAPI 2.0 client with its own cryptographic identity:
- Generates an ES256 key pair stored at `~/.vouch/client_key.json` (file permissions 0600)
- Auto-registers with the server via RFC 7591 Dynamic Client Registration on first use (`vouch enroll` or `vouch login`)
- Uses `private_key_jwt` (RFC 7523) for client authentication — no shared secrets between CLI and server
- Sends DPoP proofs (RFC 9449) with every token request
- Access tokens are sender-constrained (DPoP-bound) — token theft without the key is useless
- FAPI interaction headers (`x-fapi-interaction-id`) included for end-to-end request tracing

Key management and FAPI protocol logic lives in `crates/vouch-cli/src/fapi/` (key.rs, dpop.rs, client_assertion.rs, registration.rs).

For more details on DPoP and FAPI 2.0, see [DPoP and FAPI 2.0](../oidc/dpop-fapi.md).

## vouch-agent

Background daemon managing session state and credential access.

```
+-----------------------------------------------------------+
|                     vouch-agent                            |
|                                                            |
|  +-------------+  +-------------+  +-------------------+   |
|  |   Session   |  |    Cert     |  |    SSH Agent      |   |
|  |   Manager   |  |    Cache    |  |    Protocol       |   |
|  |             |  |             |  |                   |   |
|  | * 8hr TTL   |  | * SSH certs |  | * Identities      |   |
|  | * SecretStr |  | * Auto-     |  | * Sign requests   |   |
|  | * Expiry    |  |   refresh   |  | * Certificate     |   |
|  +-------------+  +-------------+  +-------------------+   |
|                                                            |
|  IPC: Unix socket at ~/.vouch/agent.sock                  |
|  SSH Agent: Unix socket at ~/.vouch/ssh-agent.sock         |
|  Protocol: JSON-RPC 2.0 with 4-byte length-prefixed frames |
+-----------------------------------------------------------+
```

**Agent State (Implemented):**
```rust
// crates/vouch-agent/src/state.rs
pub struct AgentState {
    session: RwLock<Option<Session>>,  // Thread-safe session storage
}

pub struct Session {
    token: SecretString,           // JWT from server (zeroized on drop)
    user_email: String,            // User's email
    expires_at: Timestamp,         // jiff::Timestamp
    authenticated_at: Timestamp,
}

// Serializable for IPC responses
pub struct SessionInfo {
    pub user_email: String,
    pub expires_at: String,        // ISO 8601
    pub authenticated_at: String,  // ISO 8601
    pub expires_in_seconds: u64,
}
```

For the full IPC protocol specification, see [Agent IPC Protocol](agent-ipc.md).

## Vouch Server

The authentication backend with built-in certificate authority.

### Auth Portal
- WebAuthn registration and authentication
- Google Workspace OIDC for enrollment identity
- Session management with presence attestation

### SSH Certificate Authority (Built-in)
- Ed25519 signing key for user certificates
- 8-hour certificate TTL (matches session)
- Principals from user email

For details on SSH certificate integration, see [SSH Certificates](../integrations/ssh.md).

### OIDC Provider

Vouch is a **fully OIDC-compliant identity provider**, implementing OAuth 2.0 and OpenID Connect specifications. Any application can integrate using off-the-shelf OIDC libraries — no Vouch SDK required.

For the full OIDC specification, see [OIDC Overview](../oidc/overview.md).

### GitHub App Integration

Vouch integrates with GitHub via a shared GitHub App to provide short-lived Git credentials:

- **Installation tokens** — 15-minute TTL, scoped to specific repositories
- **Minimal permissions** — `contents:write`, `metadata:read` only
- **Multi-org support** — Organizations can connect multiple GitHub accounts
- **Automatic selection** — Vouch determines the correct installation from the repo URL

**Flow:**
1. Org admin connects GitHub at `/github/connect`
2. User runs `vouch setup github --configure` to set up git credential helper
3. Git operations automatically request tokens via `vouch credential github`
4. Tokens are scoped to the specific GitHub organization being accessed

For more on GitHub integration, see [GitHub](../integrations/github.md).

### External Identity Provider Integration

Vouch uses external identity providers (IdPs) to verify user identity during enrollment. This links a trusted corporate identity to a hardware-bound FIDO2 credential.

For the full IdP configuration details, see [Identity Provider Overview](../idp/overview.md).

### Application Registration

Developers register their applications through a self-service portal to obtain OAuth client credentials for integrating with Vouch.

For the full application registration workflow, see [Application Registration](../integrations/application-registration.md).
