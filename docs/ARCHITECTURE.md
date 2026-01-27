# Architecture

Vouch is a **hardware-backed authentication system** that issues short-lived credentials after verifying human presence via FIDO2 hardware keys (YubiKey 5 series only).

## Product Vision

**"No credential without proven human presence."**

```bash
$ vouch login
Touch your YubiKey...
YubiKey PIN: ********
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
 |  |  * vouch enroll     (one-time, opens browser, first key)           |  |
 |  |  * vouch login      (daily, CLI only, discoverable credential)     |  |
 |  |  * vouch register   (add backup key, requires login first)         |  |
 |  |  * vouch status                                                    |  |
 |  |  * vouch logout                                                    |  |
 |  |  * vouch keys        (interactive menu, or list|remove|rename)     |  |
 |  |  * vouch credential ssh|aws                                        |  |
 |  |  * vouch setup ssh|aws                                             |  |
 |  |  * vouch doctor     (diagnostic checks)                            |  |
 |  |  * vouch completions (shell completions)                           |  |
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

Vouch is a **fully OIDC-compliant identity provider**, implementing OAuth 2.0 and OpenID Connect specifications. Any application can integrate using off-the-shelf OIDC libraries — no Vouch SDK required.

**Standards Compliance:**
- OAuth 2.0 (RFC 6749)
- OpenID Connect Core 1.0
- OAuth 2.0 Device Authorization Grant (RFC 8628)
- Proof Key for Code Exchange (PKCE, RFC 7636)
- OAuth 2.0 Token Revocation (RFC 7009)
- OAuth 2.0 Token Introspection (RFC 7662)
- OAuth 2.0 Token Exchange (RFC 8693)
- SCIM 2.0 (RFC 7643/7644)
- DPoP (RFC 9449) — Demonstrating Proof of Possession
- OAuth 2.0 Security Best Current Practice (RFC 9700) — followed

**Supported Grant Types:**
| Grant Type | Use Case |
|------------|----------|
| `authorization_code` (with PKCE) | Web and native applications |
| `urn:ietf:params:oauth:grant-type:device_code` | CLI tools, headless devices (RFC 8628) |
| `urn:ietf:params:oauth:grant-type:token-exchange` | Service-to-service delegation (RFC 8693) |

**Supported Scopes:**
| Scope | Claims Returned |
|-------|-----------------|
| `openid` | `sub`, `iss`, `aud`, `exp`, `iat` (required) |
| `profile` | `name`, `preferred_username` |
| `email` | `email`, `email_verified` |
| `hardware` | `hardware_verified`, `hardware_aaguid` (Vouch-specific) |

**Client Authentication Methods:**
| Method | Description |
|--------|-------------|
| `client_secret_basic` | HTTP Basic Auth with client_id:client_secret |
| `client_secret_post` | client_id and client_secret in request body |
| `none` | Public clients (native apps with PKCE) |

**Standard OIDC Endpoints:**
- `GET /.well-known/openid-configuration` — Discovery document (RFC 8414)
- `GET /oauth/jwks` — Public keys for token verification (RFC 7517)
- `GET /oauth/authorize` — Authorization endpoint
- `POST /oauth/token` — Token issuance (device code, authorization code, token exchange)
- `POST /oauth/revoke` — Token revocation (RFC 7009)
- `POST /oauth/introspect` — Token introspection (RFC 7662)
- `GET /oauth/userinfo` — User info endpoint

**ID Token Claims:**
```json
{
  "iss": "https://vouch.yourcompany.com",
  "sub": "user@company.com",
  "email": "user@company.com",
  "email_verified": true,
  "hardware_verified": true,
  "hardware_aaguid": "2fc0579f-8113-47ea-b116-bb5a8db9202a",
  "iat": 1737849600,
  "exp": 1737878400
}
```

**Vouch-specific claims:**
- `hardware_verified: true` — Indicates hardware authentication was used
- `hardware_aaguid` — The AAGUID of the authenticator (identifies device model)

**Why OIDC:**
- Standard protocol, works with any language/framework
- No vendor lock-in - apps can switch IdPs later
- JWT tokens can be verified offline with public keys
- Existing libraries handle all the complexity

#### External Identity Provider Integration

Vouch uses external identity providers (IdPs) to verify user identity during enrollment. This links a trusted corporate identity to a hardware-bound YubiKey credential.

**Purpose:**
- Verify the user is a member of your organization during enrollment
- Pull user attributes (email, name, groups) from your existing identity system
- No separate user database to maintain in Vouch

**Self-Service Admin Portal:**

Administrators configure external IdPs through the Vouch web interface — no config files or server restarts required.

```
Admin Portal → Settings → Identity Providers → Add Provider
```

**Configuration Steps:**
1. Select provider type (Google Workspace, Microsoft Entra ID, Generic OIDC)
2. Enter client credentials from the external IdP
3. Configure allowed domains (e.g., `@company.com`)
4. Test the connection
5. Enable for user enrollment

**Supported Providers:**

| Provider | Status | Notes |
|----------|--------|-------|
| Google Workspace | ✅ Supported | First-class support, recommended |
| Microsoft Entra ID | 🔜 Planned | Next priority |
| Generic OIDC | 🔜 Planned | Any OIDC-compliant IdP |

**Claims Mapping:**

External IdP claims are mapped to Vouch user attributes:

| External Claim | Vouch Attribute | Required |
|----------------|-----------------|----------|
| `email` | User email / principal | Yes |
| `name` or `given_name`+`family_name` | Display name | No |
| `groups` | Group memberships | No |

**User Lifecycle:**
- User exists in external IdP but not Vouch → Enrollment creates Vouch user
- User removed from external IdP → Existing Vouch sessions continue until expiry; re-enrollment blocked
- User's groups change in external IdP → Updated on next enrollment/re-enrollment

#### Application Registration

Developers register their applications through a self-service portal to obtain OAuth client credentials for integrating with Vouch.

**Self-Service Portal:**

```
Web Portal → My Applications → Register New Application
```

**Registration Workflow:**

1. **Authenticate** — User logs into Vouch (with YubiKey)
2. **Navigate** — Go to "My Applications" section
3. **Register** — Click "Register New Application"
4. **Configure** — Provide application details:
   - Application name (human-readable identifier)
   - Application type (web, native, SPA, service)
   - Redirect URIs (for authorization_code flow)
   - Requested scopes
5. **Receive Credentials** — Vouch generates:
   - `client_id` — Public identifier for OAuth flows
   - `client_secret` — Secret for confidential clients (not shown for public clients)
6. **Manage** — View, rotate, or revoke credentials at any time

**Application Types:**

| Type | client_secret | PKCE Required | Use Case |
|------|---------------|---------------|----------|
| Web (confidential) | Yes | Recommended | Server-side web apps |
| Native | No | Required | Desktop/mobile apps |
| SPA | No | Required | Browser-only apps |
| Service | Yes | N/A | Machine-to-machine (future) |

**Credential Management:**

Registered applications can be managed via the portal:
- **View** — See application details and usage statistics
- **Rotate** — Generate new client_secret (old secret remains valid for 24 hours)
- **Revoke** — Immediately invalidate all tokens for an application
- **Delete** — Remove the application registration entirely

**API Access (Future):**

Applications can also be managed programmatically:
```bash
# List applications
curl -H "Authorization: Bearer $TOKEN" https://vouch.example.com/api/v1/applications

# Create application
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "My App", "type": "web", "redirect_uris": ["https://myapp.com/callback"]}' \
  https://vouch.example.com/api/v1/applications
```

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

**PIN Setup**: If the YubiKey doesn't have a PIN configured, `vouch login` and `vouch register` will detect this and guide the user through setting one up. Vouch requires a minimum 8-character PIN for security.

### Adding Additional Keys (CLI, Requires Login)

After initial enrollment, users can add backup keys via CLI:

```
+--------+     +-----------+     +--------------+     +----------+
|  User  |     |   vouch   |     |    Server    |     | YubiKey  |
|        |     |   CLI     |     |              |     | (new)    |
+---+----+     +-----+-----+     +------+-------+     +----+-----+
    |                |                  |                  |
    | vouch login    |  (with existing key)                |
    |--------------->|                  |                  |
    |                |  [... standard login flow ...]      |
    |                |                  |                  |
    | vouch register |                  |                  |
    | --name "Backup"|                  |                  |
    |--------------->|                  |                  |
    |                |                  |                  |
    |                | POST /v1/auth/register/start        |
    |                | Authorization: Bearer <token>       |
    |                |----------------->|                  |
    |                |                  |                  |
    |                |                  | Verify session   |
    |                |                  | Get user from    |
    |                |                  | session claims   |
    |                |                  | Return challenge |
    |                |                  | + excludeCredIDs |
    |                |                  |                  |
    |                | Challenge +      |                  |
    |                | exclude list     |                  |
    |                |<-----------------|                  |
    |                |                  |                  |
    |                | CTAP2: makeCredential               |
    |                |----------------------------------->|
    |                |                  |                  |
    |  Touch key     |                  |                  |
    |  Enter PIN     |                  |                  |
    |<---------------|                  |                  |
    |                |                  |                  |
    |                | Attestation      |                  |
    |                |<-----------------------------------|
    |                |                  |                  |
    |                | POST /v1/auth/register/complete     |
    |                |----------------->|                  |
    |                |                  |                  |
    |                |                  | Check duplicate  |
    |                |                  | Store credential |
    |                |                  |                  |
    |                | Success          |                  |
    |                |<-----------------|                  |
    |                |                  |                  |
    | "Key added"    |                  |                  |
    |<---------------|                  |                  |
```

**Security controls:**
- Requires valid session token (must `vouch login` first)
- Email comes from session claims (OIDC-verified), not user input
- `excludeCredentials` prevents re-registering the same credential on the same authenticator
- Server checks for duplicate credential_id per user before storing

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
| Templates | Askama | Compile-time checked, type-safe HTML |
| Styling | TailwindCSS | Utility-first, self-hosted (no CDN) |
| Database | SQLite (MVP) / PostgreSQL | Simple to start, scales later |
| SSH CA | Ed25519 (built-in) | No external dependencies |
| JWT | jsonwebtoken | Standard, well-audited |

## Session Storage

Vouch stores session information in multiple locations for different use cases:

### Agent IPC (Primary)

The vouch-agent daemon stores the active session in memory, accessible via Unix socket IPC:

```
~/.vouch/agent.sock    # JSON-RPC 2.0 IPC socket
```

**Used by:** CLI tools, credential helpers

### Config File (Fallback)

When the agent is not running, sessions are stored in the config file:

```
~/.config/vouch/config.json
```

**Format:** JSON with `token` field containing the JWT session token

### Cookie File (CLI Tools)

For CLI tools that support Netscape cookie format (curl, wget, etc.):

```
~/.vouch/cookie.txt
```

**Format:** Netscape HTTP Cookie File
```
# Netscape HTTP Cookie File
vouch.example.com	FALSE	/	TRUE	1737849600	vouch_session	<token>
```

**Use cases:**
- SSH credential helper reads cookie, exchanges for certificate
- AWS credential process reads cookie, gets OIDC token
- CLI tools that need quick auth without browser flow

**Security:** File permissions are set to 0600 (read/write for owner only)

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

## Competitive Positioning

### Vouch vs WorkOS

| Aspect | WorkOS | Vouch |
|--------|--------|-------|
| **Target Customer** | B2B SaaS vendors | Enterprises (internal use) |
| **Purpose** | "Make your app enterprise-ready" | "Secure internal access with hardware auth" |
| **IdP Role** | Integrates with customer's IdP | IS the IdP |
| **Direction** | Your app → customer's Okta/Entra | Your employees → Vouch → your apps |
| **Hardware Focus** | None specific | YubiKey required |

**Summary**: Not competitors. WorkOS helps SaaS companies add SSO/SCIM to sell to enterprises. Vouch IS the enterprise authentication system.

- WorkOS customer: "I'm building a SaaS product and need to support customer SSO."
- Vouch customer: "I'm an enterprise and need to secure my employees' access to internal tools."

### Vouch vs AWS Verified Access

| Aspect | AWS Verified Access | Vouch |
|--------|---------------------|-------|
| **What it is** | Zero-trust access gateway | Hardware-backed identity provider |
| **Authentication** | Integrates with IdPs | IS the IdP |
| **Where it runs** | AWS-hosted (network layer) | Self-hosted or cloud |
| **Access Model** | Per-request evaluation | Session + short-lived credentials |
| **Device Trust** | Via MDM integration | Via YubiKey hardware |
| **VPN** | Replaces VPN | Complements/replaces VPN |

**Summary**: Complementary, not competitive. AWS Verified Access needs an IdP to authenticate users — Vouch can be that IdP. Different layers: Vouch = identity layer, AWS VA = access layer.

### Vouch vs Traditional IdPs (Okta, Auth0, etc.)

| Feature | Vouch | Okta/Auth0/etc. | Platform Passkeys |
|---------|-------|-----------------|-------------------|
| Hardware required | Yes | Optional | No |
| Syncable credentials | No | Yes | Yes |
| Built-in SSH CA | Yes | No | No |
| Discoverable login | Yes | No | Yes |
| 8-hour sessions | Yes | Configurable | N/A |
| Self-hosted | Yes | No | N/A |

**Core differentiator**: Most identity systems allow platform passkeys (Touch ID, Windows Hello), TOTP/SMS, and push notifications. Vouch requires YubiKey 5 series only — hardware-bound, non-extractable, presence required.

### Positioning Summary

```
                    Hardware Required
                          │
          Vouch ◄─────────┼─────────► Platform Passkeys
     (YubiKey only)       │          (Touch ID, Windows Hello)
                          │
    Amazon Midway         │          Most IdPs
    (internal only)       │          (Okta, Auth0, etc.)
                          │
                          │
                    Software Optional
```

**Target customers**: Organizations where credential theft is an existential risk (finance, healthcare, critical infrastructure), compliance requires hardware tokens (SOC 2, FedRAMP, HIPAA), remote work makes "trust the network" obsolete, or platform passkeys are too risky (syncable = exfiltrable).
