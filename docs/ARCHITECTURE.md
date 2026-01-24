# Architecture

Vouch is a **hardware-backed authentication system** that issues short-lived credentials after verifying human presence via FIDO2 hardware keys (YubiKey 5 series only).

## Product Vision

**"No credential without proven human presence."**

```bash
$ vouch login
Touch your YubiKey...
Enter PIN: ****
Authenticated as user@company.com (8 hours)

$ ssh prod.example.com    # Just works
$ aws s3 ls               # Just works
$ git push origin main    # Just works
```

## Design Principles

1. **Hardware-bound only** — YubiKey 5 series required, no platform passkeys (Touch ID, Windows Hello)
2. **Presence is mandatory** — No credential issuance without YubiKey touch + PIN
3. **Credentials are ephemeral** — 8-hour maximum lifetime, no persistent secrets
4. **Tools stay native** — Configure standard credential providers, don't wrap commands
5. **Browser enrollment, CLI login** — One-time browser setup, daily use is CLI-only

## Security Proposition

| Factor | How Vouch Delivers |
|--------|-------------------|
| **Something you HAVE** | YubiKey (hardware-bound, not syncable) |
| **Something you KNOW** | PIN (verified on-device, never transmitted) |
| **Presence proof** | Physical touch sensor |
| **Time-bound** | 8-hour sessions, no long-lived secrets |

**Policy**: Hardware-bound authenticators only (YubiKey 5 series). No platform passkeys, no Touch ID/Windows Hello. This is the differentiator.

## System Overview

```
                              User's Machine
 +---------------------------------------------------------------------------+
 |                                                                           |
 |  +---------------------------------------------------------------------+  |
 |  |                           vouch CLI                                 |  |
 |  |                                                                     |  |
 |  |  * vouch enroll     (one-time, opens browser)                      |  |
 |  |  * vouch login      (daily, CLI only, discoverable credential)     |  |
 |  |  * vouch status                                                    |  |
 |  |  * vouch logout                                                    |  |
 |  |  * vouch keys list|remove                                          |  |
 |  |  * vouch setup ssh|aws|github                                      |  |
 |  +---------------------------------------------------------------------+  |
 |                    |                                                      |
 |                    | IPC (Unix socket)                                    |
 |                    v                                                      |
 |  +----------------------+     +----------------------------------------+  |
 |  |    vouch-agent       |     |        Native Tools                    |  |
 |  |    (background)      |     |                                        |  |
 |  |                      |     |  ssh --> IdentityAgent --> vouch agent |  |
 |  |  * Session cache     |     |  aws --> credential_process --> vouch  |  |
 |  |  * SSH certs         |     |  git --> credential.helper --> vouch   |  |
 |  |  * SSH agent protocol|     |                                        |  |
 |  +----------------------+     +----------------------------------------+  |
 |            |                                                              |
 |            | HTTPS                                                        |
 +---------------------------------------------------------------------------+
             |
             v
 +---------------------------------------------------------------------------+
 |                            Vouch Server                                   |
 |                                                                           |
 |  +------------------+  +------------------+  +--------------------------+ |
 |  |   Auth Portal    |  |   SSH CA         |  |   OIDC Provider          | |
 |  |                  |  |   (built-in)     |  |                          | |
 |  |  * WebAuthn      |  |                  |  |  * /.well-known/oidc     | |
 |  |  * Google OIDC   |  |  * Ed25519 CA    |  |  * /oauth/token          | |
 |  |  * Sessions      |  |  * User certs    |  |  * For AWS federation    | |
 |  +------------------+  +------------------+  +--------------------------+ |
 |                                                                           |
 |  Policy: Hardware-bound authenticators only (YubiKey 5 series)           |
 +---------------------------------------------------------------------------+
```

## Core Components

### vouch CLI (`vouch-cli`)

The user-facing command-line tool. Written in Rust using:
- `ctap-hid-fido2` — Pure Rust FIDO2/CTAP2 implementation
- `clap` — CLI argument parsing
- `reqwest` + `rustls` — HTTPS without OpenSSL dependencies

**Key design decisions:**
- Single statically-linked binary (MUSL target for Linux)
- No runtime dependencies
- Startup time <1ms
- Open source (Apache 2.0) for security auditing

### vouch-agent

Background daemon managing session state and credential access.

```
+-----------------------------------------------------------+
|                     vouch-agent                            |
|                                                            |
|  +-------------+  +-------------+  +-------------------+   |
|  |   Session   |  |    Cert     |  |    SSH Agent      |   |
|  |   Manager   |  |    Cache    |  |    Protocol       |   |
|  |   ✅ Done   |  |   (future)  |  |    (future)       |   |
|  |             |  |             |  |                   |   |
|  | * 8hr TTL   |  | * SSH certs |  | * Identities      |   |
|  | * SecretStr |  | * Auto-     |  | * Sign requests   |   |
|  | * Expiry    |  |   refresh   |  | * Certificate     |   |
|  +-------------+  +-------------+  +-------------------+   |
|                                                            |
|  IPC: Unix socket at ~/.vouch/agent.sock                  |
|  SSH Agent: Unix socket at ~/.vouch/ssh-agent.sock (future)|
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

**IPC Methods (JSON-RPC 2.0):**
| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `ping` | none | `"pong"` | Health check |
| `get_session` | none | `SessionInfo` | Get current session |
| `store_session` | `{token, user_email, expires_at}` | `true` | Store after login |
| `clear_session` | none | `true` | Logout |
| `get_token` | none | `string` | Get raw JWT |

**Error Codes:**
| Code | Constant | Meaning |
|------|----------|---------|
| -32000 | `NOT_AUTHENTICATED` | No active session |
| -32001 | `SESSION_EXPIRED` | Session has expired |
| -32601 | `METHOD_NOT_FOUND` | Unknown method |
| -32602 | `INVALID_PARAMS` | Bad parameters |

**Future IPC Operations (Phase 5):**
- `GetSshCert` — Request SSH certificate
- `SignSshChallenge(data)` — SSH agent protocol

### Vouch Server

The authentication backend with built-in certificate authority.

#### Auth Portal
- WebAuthn registration and authentication
- Google Workspace OIDC for enrollment identity
- Session management with presence attestation

#### SSH Certificate Authority (Built-in)
- Ed25519 signing key for user certificates
- 8-hour certificate TTL (matches session)
- Principals from user email

#### OIDC Provider
For AWS federation and other OIDC-capable services:
- `GET /.well-known/openid-configuration`
- `GET /oauth/jwks`
- `POST /oauth/token` (exchanges session token for OIDC ID token)

## Authentication Flows

### Enrollment (One-Time, Browser Required)

Links OIDC identity (Google Workspace, Okta, Azure AD) to YubiKey passkey using RFC 8628 Device Authorization Grant:

```
+--------+     +-----------+     +--------------+     +--------------+     +----------+
|  User  |     |   vouch   |     |  vouch.sh    |     |   OIDC       |     | YubiKey  |
|        |     |   CLI     |     |   (browser)  |     |   Provider   |     |          |
+---+----+     +-----+-----+     +------+-------+     +------+-------+     +----+-----+
    |                |                  |                    |                  |
    | vouch enroll   |                  |                    |                  |
    |--------------->|                  |                    |                  |
    |                |                  |                    |                  |
    |                | POST /oauth/device/code               |                  |
    |                |----------------->|                    |                  |
    |                |                  |                    |                  |
    |                | device_code,     |                    |                  |
    |                | user_code        |                    |                  |
    |                |<-----------------|                    |                  |
    |                |                  |                    |                  |
    | "Go to URL,    |                  |                    |                  |
    |  enter ABCD-   |                  |                    |                  |
    |  1234"         |                  |                    |                  |
    |<---------------|                  |                    |                  |
    |                |                  |                    |                  |
    |  [Opens browser, enters code]     |                    |                  |
    |---------------------------------->|                    |                  |
    |                |                  |                    |                  |
    |                |                  | Redirect to OIDC   |                  |
    |                |                  |------------------->|                  |
    |                |                  |                    |                  |
    |                |                  | OIDC callback      |                  |
    |                |                  |<-------------------|                  |
    |                |                  |                    |                  |
    |                |                  | WebAuthn create    |                  |
    |                |                  |----------------------------------->|
    |                |                  |                    |                  |
    |  [Touch key, enter PIN]           |    Attestation     |                  |
    |                |                  |<-----------------------------------|
    |                |                  |                    |                  |
    |                |                  | Mark authorized    |                  |
    |                |                  |                    |                  |
    |                | POST /oauth/token (poll)              |                  |
    |                |----------------->|                    |                  |
    |                |                  |                    |                  |
    |                | access_token     |                    |                  |
    |                |<-----------------|                    |                  |
    |                |                  |                    |                  |
    | Enrolled as    |                  |                    |                  |
    |   user@co.com  |                  |                    |                  |
    |<---------------|                  |                    |                  |
```

**Why RFC 8628?** Unlike traditional OAuth callbacks that require a local HTTP server, device authorization:
- Works in headless/SSH environments (no localhost binding)
- Works behind firewalls (no inbound connections)
- Simple user experience (enter 8-character code)
- Industry standard (used by Azure CLI, GitHub CLI, etc.)

**Server stores:** credential_id <-> user@company.com (from OIDC provider)

**Key insight**: The passkey is created as a *discoverable credential* (resident key) on the YubiKey, so subsequent logins don't require the user to provide their email.

### Daily Login (CLI Only, No Browser)

Uses discoverable credential from YubiKey:

```
+--------+     +-----------+     +--------------+     +----------+
|  User  |     |   vouch   |     |    Server    |     | YubiKey  |
|        |     |   CLI     |     |              |     |          |
+---+----+     +-----+-----+     +------+-------+     +----+-----+
    |                |                  |                  |
    | vouch login    |                  |                  |
    | (no email!)    |                  |                  |
    |--------------->|                  |                  |
    |                |                  |                  |
    |                | CTAP2: Get discoverable credentials |
    |                | for RP "vouch.sh"                   |
    |                |----------------------------------->|
    |                |                  |                  |
    |  Touch key     |                  |                  |
    |<---------------|                  |                  |
    |                |                  |                  |
    |  Enter PIN     |                  |                  |
    |<---------------|                  |                  |
    |                |                  |                  |
    |                | Assertion + credential_id          |
    |                |<-----------------------------------|
    |                |                  |                  |
    |                | POST /v1/auth/login                |
    |                | (assertion, credential_id)         |
    |                |----------------->|                  |
    |                |                  |                  |
    |                |                  | Lookup user by   |
    |                |                  | credential_id    |
    |                |                  | -> user@co.com   |
    |                |                  |                  |
    |                |  Session token   |                  |
    |                |  (8 hours)       |                  |
    |                |<-----------------|                  |
    |                |                  |                  |
    | Authenticated  |                  |                  |
    |   8 hours      |                  |                  |
    |<---------------|                  |                  |
```

**Key insight**: The YubiKey's discoverable credential (passkey) identifies the user. No email needed for daily login.

### Credential Request (Transparent)

```
+--------+     +-----------+     +-----------+     +--------------+
|  User  |     |    ssh    |     |   vouch   |     |    Server    |
+---+----+     +-----+-----+     +-----+-----+     +------+-------+
    |                |                 |                  |
    | ssh server     |                 |                  |
    |--------------->|                 |                  |
    |                |                 |                  |
    |                | Request identity|                  |
    |                | (via SSH agent) |                  |
    |                |---------------->|                  |
    |                |                 |                  |
    |                |                 | (if cert expired |
    |                |                 |  or missing)     |
    |                |                 |                  |
    |                |                 | GET /v1/creds/ssh|
    |                |                 | + session token  |
    |                |                 |----------------->|
    |                |                 |                  |
    |                |                 | SSH certificate  |
    |                |                 |<-----------------|
    |                |                 |                  |
    |                | Certificate     |                  |
    |                |<----------------|                  |
    |                |                 |                  |
    |                | [standard SSH   |                  |
    |                |  handshake]     |                  |
    |                |                 |                  |
    | Connected      |                 |                  |
    |<---------------|                 |                  |
```

**Note:** No additional user interaction required — the session token proves recent presence attestation.

## Integration Architecture

### SSH Integration

```
~/.ssh/config:
  Host *
    IdentityAgent ~/.vouch/ssh-agent.sock

How it works:
1. SSH client connects to vouch's agent socket
2. vouch-agent returns cached SSH certificate
3. If expired, fetches new cert from server (session required)
4. SSH proceeds with standard certificate authentication
5. Server validates cert against trusted CA
```

**`vouch setup ssh` creates:**
- SSH keypair at `~/.ssh/id_ed25519_vouch`
- Config entry pointing to vouch's SSH agent socket
- Outputs CA public key for host configuration

**Host-side configuration:**
```bash
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/vouch-ca.pub
```

### AWS Integration

```
~/.aws/config:
  [profile production]
    credential_process = vouch credential aws --role arn:aws:iam::123456789:role/developer

How it works:
1. AWS CLI/SDK calls credential_process
2. vouch gets OIDC token from server (exchanges session token)
3. vouch calls AWS STS AssumeRoleWithWebIdentity
4. Returns temporary credentials in credential_process format
5. Credentials expire in 1 hour, auto-refresh within session
```

### GitHub Integration

```
~/.gitconfig:
  [credential "https://github.com"]
    helper = vouch credential git

How it works:
1. Git calls credential helper for github.com
2. vouch requests GitHub App installation token
3. Server uses GitHub App private key to generate token
4. Token scoped to repositories org has granted access to
5. Short-lived (default 1 hour)
```

## Data Model

### Core Entities

```
+------------------+       +------------------+
|   Organization   |       |      User        |
+------------------+       +------------------+
| id               |       | id               |
| name             |       | org_id (FK)      |
| domain           |<------| email            |
| settings (JSON)  |       | display_name     |
| created_at       |       | created_at       |
+------------------+       +--------+---------+
                                    |
                                    | 1:N
                                    v
+------------------+       +------------------+
|     Session      |       |   Authenticator  |
+------------------+       |   (FIDO2)        |
| id               |       +------------------+
| user_id (FK)     |       | id               |
| token_hash       |       | user_id (FK)     |
| authenticator_id |       | public_key       |
| expires_at       |       | credential_id    |
| created_at       |       | device_name      |
+------------------+       | counter          |
                           | created_at       |
                           +------------------+
```

## Technology Stack

### CLI (Open Source)

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | Rust | Memory safety, single binary, <1ms startup |
| FIDO2 | ctap-hid-fido2 | Pure Rust, no system dependencies |
| HTTP | reqwest + rustls | No OpenSSL linking |
| CLI | clap | Standard, well-maintained |
| Time | jiff | Modern, no chrono |
| Crypto | aws-lc-rs | FIPS-validated, no ring |

### Server

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | Rust | Consistency with CLI, performance |
| Framework | Axum | Modern async, tower middleware |
| Database | SQLite (MVP) / PostgreSQL | Simple to start, scales later |
| SSH CA | Ed25519 (built-in) | No external dependencies |
| JWT | jsonwebtoken | Standard, well-audited |

## Security Properties

1. **Credential issuance requires presence** — Every credential traces to a FIDO2 assertion with user verification
2. **No persistent secrets** — All credentials expire, no long-lived keys to rotate or revoke
3. **Hardware-bound only** — Platform passkeys explicitly disallowed
4. **Discoverable credentials** — User identified by credential_id, not email
5. **Audit trail** — Every credential issuance logged with session attestation
6. **Compromise recovery** — Revoke YubiKey registration, all sessions invalidated

## Differences from Amazon Midway

Vouch is inspired by Amazon's internal Midway system but differs in several ways:

| Aspect | Midway (Amazon Internal) | Vouch |
|--------|-------------------------|-------|
| Deployment | Internal only | SaaS + self-hosted |
| Hardware | Amazon-issued Yubikeys | BYOD YubiKey 5 series |
| Login | Email required | Discoverable credential (no email) |
| CA | External PKI | Built-in Ed25519 CA |
| IdP | Internal | Google Workspace (extensible) |
| Open source | No | CLI is open source |
