# Security Model

This document describes Vouch's security architecture, threat model, and incident response procedures.

## Security Philosophy

Vouch is designed around three core principles:

1. **Hardware-bound only** — YubiKey 5 series required; no platform passkeys (Touch ID, Windows Hello)
2. **Minimize credential lifetime** — Short-lived credentials (8 hours max) limit blast radius of compromise
3. **Audit everything** — Every credential issuance is logged with provenance

**Policy**: This is non-negotiable. Platform passkeys can be synced, backed up, and extracted. Hardware-bound credentials cannot. This is Vouch's key differentiator.

## Threat Model

> For the comprehensive threat model with detailed threat statements, mitigations, and STRIDE analysis, see [THREAT_MODEL.md](THREAT_MODEL.md).

### What Vouch Protects Against

| Threat | Mitigation |
|--------|------------|
| **Credential theft** | Short-lived credentials expire before attackers can use them |
| **MFA fatigue attacks** | No push notifications; physical touch required |
| **Phishing** | YubiKey's origin binding prevents credential use on wrong domains |
| **Malware on workstation** | Private keys never leave the YubiKey |
| **Insider threats** | Audit trail with cryptographic attestation |
| **Credential stuffing** | No passwords to stuff |
| **Synced passkey extraction** | Hardware-bound only policy prevents syncable credentials |

### What Vouch Does NOT Protect Against

| Threat | Why | Mitigation | Monitoring |
|--------|-----|------------|------------|
| **Physical YubiKey theft + known PIN** | Attacker has both factors | Use biometric YubiKey (Bio series), rotate PIN | Audit logs, anomaly detection for unusual access patterns |
| **Compromised Vouch server** | Server issues credentials | Self-host for high-security, air-gapped deployment (planned) | Server integrity monitoring, audit log analysis |
| **Malware stealing session after login** | Session token in memory | 8-hour session lifetime, endpoint protection | EDR solutions, anomalous session usage patterns |
| **Supply chain attacks on CLI** | Compromised binary | Reproducible builds, code signing, open source auditing | Security researcher engagement, build provenance verification |

### Attacker Profiles

#### Script Kiddie
- **Capabilities**: Automated scanning, credential stuffing, phishing kits
- **Vouch defense**: No passwords, origin-bound hardware auth, short-lived creds

#### Sophisticated Attacker
- **Capabilities**: Targeted phishing, malware, network interception
- **Vouch defense**: Hardware attestation, hardware-bound only policy, audit logging

#### Nation-State
- **Capabilities**: Zero-days, supply chain compromise, physical access
- **Vouch defense**: Air-gapped deployment (planned), reproducible builds

### Trust Boundaries

| Boundary | Description | Protection |
|----------|-------------|------------|
| **Internet ↔ Server** | Public network to Vouch server | TLS 1.3, certificate validation |
| **Server ↔ Workstation** | Server to user machine | TLS 1.3, JWT validation |
| **CLI ↔ Agent** | User commands to daemon | Unix socket permissions (0700) |
| **Agent ↔ YubiKey** | Software to hardware | CTAP2 protocol, PIN verification |

### Security Assumptions

Vouch's security model relies on the following assumptions. If any assumption is violated, the corresponding security properties may be compromised.

| ID | Assumption | Rationale | If Violated |
|----|------------|-----------|-------------|
| **A-01** | **Hardware Authenticator Integrity**: YubiKey 5 series devices correctly implement FIDO2/CTAP2 and protect private keys from extraction | Yubico has undergone independent security audits. The secure element prevents key extraction even with physical access. | Attackers could clone YubiKey credentials, defeating hardware-bound authentication |
| **A-02** | **TLS Implementation Correctness**: The TLS 1.3 implementation (rustls) correctly encrypts communications and validates certificates | rustls is a well-audited, memory-safe TLS implementation with no OpenSSL dependencies | Network attackers could intercept or modify communications between components |
| **A-03** | **Cryptographic Primitive Security**: Ed25519, AES-GCM, and Argon2id provide their claimed security properties | These are widely reviewed, standardized algorithms implemented by aws-lc-rs (FIPS-validated) | Signature forgery, token decryption, or password hash reversal could occur |
| **A-04** | **Operating System Isolation**: The operating system provides process isolation and file permission enforcement | Unix socket permissions (0700) and file permissions (0600) are enforced by the kernel | Malicious processes could access agent sockets or credential files |
| **A-05** | **User PIN Confidentiality**: Users protect their YubiKey PIN and do not share it | PIN is verified on-device and never transmitted to servers | PIN + physical YubiKey access enables impersonation |
| **A-06** | **Server Infrastructure Security**: The Vouch server runs on secure, patched infrastructure with appropriate access controls | Server-side vulnerabilities are outside application scope but critical to overall security | Database access, CA key theft, or session injection could occur |
| **A-07** | **External IdP Trustworthiness**: External identity providers (Google Workspace, Entra ID) correctly verify user identities | These are enterprise-grade identity providers with their own security models | Unauthorized users could enroll by compromising external IdP accounts |
| **A-08** | **Clock Synchronization**: All systems maintain reasonably accurate time (within minutes) | JWT expiration and certificate validity depend on timestamp comparison | Expired tokens could be accepted or valid tokens rejected |

## Security Controls

### Authentication Layer

```
+------------------------------------------------------------------+
|                    Authentication Controls                        |
|                                                                   |
|  +------------------+  +------------------+  +-----------------+  |
|  |  FIDO2/WebAuthn  |  |   User Verify    |  |  Attestation    |  |
|  |                  |  |                  |  |                 |  |
|  | * Ed25519        |  | * PIN required   |  | * Hardware-     |  |
|  | * Discoverable   |  | * UV flag set    |  |   bound only    |  |
|  |   credential     |  | * No platform    |  | * AAGUID check  |  |
|  | * RP binding     |  |   passkeys       |  | * YubiKey 5     |  |
|  +------------------+  +------------------+  +-----------------+  |
+------------------------------------------------------------------+
```

**WebAuthn Configuration:**
```rust
// Server-side WebAuthn options
let options = PublicKeyCredentialCreationOptions {
    challenge: random_bytes(32),
    rp: RelyingParty { id: "vouch.sh", name: "Vouch" },
    user: UserEntity { id, name, display_name },

    // CRITICAL: Require hardware-bound authenticators
    authenticator_selection: AuthenticatorSelection {
        authenticator_attachment: Some(AuthenticatorAttachment::CrossPlatform),
        resident_key: ResidentKeyRequirement::Required,  // Discoverable
        user_verification: UserVerificationRequirement::Required,
    },

    // Reject platform authenticators
    exclude_credentials: vec![],  // Could exclude known platform creds

    attestation: AttestationConveyancePreference::Direct,
};
```

**Why these choices:**
- `authenticatorAttachment: cross-platform` — Rejects platform passkeys (Touch ID, Windows Hello)
- `residentKey: required` — Enables discoverable credential for email-less login
- `userVerification: required` — Ensures PIN or biometric, not just presence
- `attestation: direct` — Allows verifying authenticator is YubiKey 5 series

### PIN Requirements

Vouch enforces PIN requirements on all FIDO2 operations:

**Minimum PIN Length:** 8 characters (enforced by CLI)

**Native PIN Setup:** If a YubiKey doesn't have a PIN configured, the CLI (`vouch login`, `vouch register`) will detect this and guide the user through setting one up. No external tools required.

```
$ vouch login
Please insert your YubiKey... detected!

Your YubiKey does not have a PIN configured.
A PIN is required for FIDO2 authentication to prove you are present.

Let's set one up now.

New PIN (minimum 8 characters): ********
Confirm PIN: ********
Setting PIN... done!

Touch your YubiKey...
```

**PIN Error Handling:** The CLI provides user-friendly messages for common PIN errors:
- Incorrect PIN (with warning about lockout)
- PIN blocked (too many wrong attempts)
- PIN temporarily blocked (unplug/replug to reset)
- PIN policy violations

### Hardware-Bound Enforcement

Vouch validates that authenticators are hardware-bound:

```rust
// Server validates attestation during enrollment
fn validate_attestation(attestation: &AttestationObject) -> Result<(), Error> {
    // Check AAGUID against allowlist of YubiKey 5 series
    let allowed_aaguids = [
        "2fc0579f-8113-47ea-b116-bb5a8db9202a",  // YubiKey 5 NFC
        "c5ef55ff-ad9a-4b9f-b580-adebafe026d0",  // YubiKey 5Ci
        "fa2b99dc-9e39-4257-8f92-4a30d23c4118",  // YubiKey 5 Nano
        // ... other YubiKey 5 series AAGUIDs
    ];

    if !allowed_aaguids.contains(&attestation.aaguid) {
        return Err(Error::UnsupportedAuthenticator(
            "Only YubiKey 5 series authenticators are supported"
        ));
    }

    Ok(())
}
```

### Discoverable Credentials

Vouch uses discoverable credentials (resident keys) to enable email-less login:

```rust
// Login flow - no email required
async fn login() -> Result<Session> {
    // 1. Get challenge from server (no user identifier)
    let challenge = server.get_challenge().await?;

    // 2. Query YubiKey for discoverable credentials for this RP
    let assertion = yubikey.get_assertion_with_discoverable(
        "vouch.sh",     // RP ID
        &challenge,
        None,           // No allowed_credentials - discover from device
        Some(&pin),     // PIN required
    )?;

    // 3. Server looks up user by credential_id
    let session = server.complete_login(
        assertion.credential_id,
        assertion.authenticator_data,
        assertion.signature,
    ).await?;

    Ok(session)
}
```

**Security benefit**: The YubiKey identifies the user, not user-provided input. Eliminates username enumeration.

### Enrollment Security (RFC 8628)

Vouch uses RFC 8628 Device Authorization Grant for enrollment. Security considerations:

```
Device Code:   32 random bytes, SHA-256 hashed before storage
User Code:     8 characters from 20-char alphabet (~40 bits entropy)
               Format: XXXX-XXXX (no ambiguous chars: 0/O, 1/I/L)
Expiration:    10 minutes (configurable)
Polling:       5-second minimum interval, slow_down response
OIDC State:    32 random bytes, prevents CSRF
Nonce:         32 random bytes, prevents token replay
```

**Why this is secure:**
- Device codes are never stored in plain text (SHA-256 hash only)
- User codes have limited entropy but short expiration + rate limiting compensate
- Brute-force protection: `slow_down` response for rapid polling
- OIDC state parameter prevents authorization code injection
- Nonce in ID token prevents replay attacks

**Rate Limiting** (planned):
```
POST /oauth/device/code    10 requests/minute per IP
POST /oauth/token          1 request/5 seconds per device_code
POST /device               5 attempts/code (then code is invalidated)
```

### Key Registration Security

Vouch enforces a secure key registration model:

**First Key Registration:**
- First key MUST be registered via browser enrollment (`vouch enroll`)
- Browser flow requires OIDC authentication (Google, etc.)
- Email comes from verified OIDC provider, never self-asserted
- WebAuthn registration happens in browser with `excludeCredentials`

**Additional Key Registration:**
- Requires existing authentication (`vouch login` first)
- CLI registration endpoint (`/v1/auth/register/start`) requires valid session token
- Email is derived from session claims, not from request
- Prevents unauthorized key addition to accounts

**Duplicate Key Prevention:**
- Server returns `excludeCredentials` list to prevent re-registering the same credential on the same authenticator
- Server-side check before storing: returns HTTP 409 if credential_id already exists for this user
- Multiple keys of the same model (same AAGUID) are allowed — AAGUID identifies the device model, not the individual device
- Applies to both browser and CLI registration flows

```
User Workflow:
  First-time enrollment:
    vouch enroll → Browser → Google Sign-in → WebAuthn → Session token

  Adding additional keys:
    vouch login      → Authenticate with existing key
    vouch register   → Add new key (requires valid session)
```

**Email Binding:**
| Flow | Email Source | Verified By |
|------|--------------|-------------|
| `vouch enroll` | Google ID token | Google (OIDC) |
| `vouch register` | Session token | Previously verified via OIDC |
| `vouch login` | Stored in user record | Looked up via credential's user_handle |

The email is never self-asserted. It always traces back to the original OIDC verification.

### Transport Layer

All communication uses TLS 1.3 with:
- AEAD ciphers only (AES-GCM, ChaCha20-Poly1305)
- rustls (no OpenSSL)

### Credential Layer

**SSH Certificates:**
```
Certificate:
    Type: user certificate
    Public key: ssh-ed25519
    Signing CA: vouch-ca (built-in Ed25519)
    Key ID: user@example.com
    Serial: 1705234567
    Valid: 2024-01-14T10:00:00 to 2024-01-14T18:00:00 (8 hours)
    Principals: user@example.com, user
    Critical Options: (none)
    Extensions:
        permit-pty
        permit-user-rc
```

**AWS Credentials:**
- Obtained via `AssumeRoleWithWebIdentity` using Vouch as OIDC provider
- Maximum duration: 1 hour
- Role trust policy restricts to Vouch OIDC provider
- Session tags include attestation timestamp

**GCP Credentials:**
- Obtained via Workload Identity Federation using Vouch as OIDC provider
- OIDC token issued with audience validation (must match Workload Identity Pool)
- Token contains `email` and `email_verified` claims for principal mapping
- Service account impersonation optional (recommended for production)
- Credential configuration file permissions: 0600
- Token cache directory permissions: 0700

**Kubernetes Credentials:**
- Obtained via Vouch OIDC ID token presented to Kubernetes API server
- Token validated against Vouch's JWKS endpoint (`/oauth/jwks`)
- Username derived from `email` claim (configured via `--oidc-username-claim`)
- Token contains `hardware_verified` and `hardware_aaguid` claims for audit
- Maximum duration: matches session (8 hours)
- RBAC bindings use email address as subject
- Supports EKS, GKE, AKS, and self-managed Kubernetes clusters

### Audit Layer

Every credential issuance generates an audit log entry:

```json
{
  "timestamp": "2024-01-14T10:32:15.123Z",
  "event_type": "credential_issued",
  "user": {
    "id": "usr_abc123",
    "email": "user@example.com"
  },
  "session": {
    "id": "sess_xyz789",
    "authenticated_at": "2024-01-14T10:00:00Z",
    "authenticator_aaguid": "2fc0579f-8113-47ea-b116-bb5a8db9202a",
    "authenticator_type": "YubiKey 5 NFC"
  },
  "credential": {
    "type": "ssh_certificate",
    "fingerprint": "SHA256:...",
    "principals": ["user@example.com", "user"],
    "valid_until": "2024-01-14T18:00:00Z"
  }
}
```

Audit logs are:
- Immutable (append-only database storage); tamper detection (planned)
- Retained for compliance period (configurable, default 2 years)
- SIEM export (planned) (Splunk, Datadog, etc.) — see [ROADMAP.md](ROADMAP.md)
- Certificate transparency logging (planned)

## S3 Configuration Security

When using S3-based configuration, additional security considerations apply.

### S3 Bucket Requirements

| Requirement | Rationale |
|-------------|-----------|
| **Server-Side Encryption** | Config contains secrets (JWT secret, OIDC credentials, private keys) |
| **Block Public Access** | Config should never be publicly accessible |
| **IAM Least Privilege** | Server needs only `s3:GetObject` and `s3:HeadObject` |
| **Versioning** | Enables rollback and audit trail |
| **Access Logging** | Detect unauthorized access attempts |

**Recommended S3 Bucket Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/vouch-server"},
      "Action": ["s3:GetObject", "s3:HeadObject"],
      "Resource": "arn:aws:s3:::my-bucket/config/vouch-server.json"
    }
  ]
}
```

### Protected Configuration Fields

Certain security-sensitive fields cannot be changed via S3 config updates at runtime:

| Field | Protection | Rationale |
|-------|------------|-----------|
| `jwt_secret` | Blocked at runtime | Changing would invalidate all sessions; security impact of hot-swap |
| `database_url` | Blocked at runtime | Connection pool cannot be safely changed |

When these fields change in S3, the server logs a warning and ignores the change. A server restart is required to apply changes to protected fields.

### S3 Polling Security

- **ETag-based polling** — HEAD request checks for changes before full GET
- **Fail-open on polling errors** — If S3 becomes unreachable during operation, server continues with current config
- **Fail-fast on startup** — If S3 is unreachable at startup when configured, server fails to start
- **No caching of stale config** — Config is only updated when successfully fetched and parsed

### Base64 Encoding for Keys

All private keys and certificates in S3 config must be base64-encoded:
- Standard base64 or URL-safe base64 accepted
- Prevents JSON parsing issues with PEM format
- Decoded and validated before use

---

## Session Storage Security

Vouch stores session tokens in multiple locations with appropriate security controls:

### Cookie File (`~/.vouch/cookie.txt`)

A Netscape-format cookie file for CLI tools that need session access:

**Security Controls:**
- **File permissions**: 0600 (read/write for owner only)
- **Location**: User's home directory (`~/.vouch/`)
- **Contents**: Session token + expiration timestamp
- **Lifetime**: Cleared on logout or session expiration

**Format:**
```
# Netscape HTTP Cookie File
vouch.example.com	FALSE	/	TRUE	1737849600	vouch_session	<jwt-token>
```

**Why Netscape format:**
- Compatible with curl (`-b` flag), wget, and other CLI tools
- Industry standard for cookie storage
- Simple text format, easy to audit

**Risk mitigation:**
- Tokens are short-lived (8 hours max)
- File is deleted on logout
- Restrictive permissions prevent unauthorized access
- Token hash (not plaintext) is stored server-side for revocation

### Config File (`~/.config/vouch/config.json`)

Fallback storage when agent is not running:

**Security Controls:**
- **File permissions**: 0600
- **Contents**: JWT token, server URL
- **Cleared**: On logout via `vouch logout`

### Agent Memory (Primary)

In-memory storage via IPC socket:

**Security Controls:**
- **Socket permissions**: 0700 on socket directory
- **Memory**: Uses `SecretString` with automatic zeroization
- **Lifetime**: Cleared on agent shutdown or explicit logout

## SCIM Security

Vouch supports SCIM 2.0 (RFC 7643/7644) for user provisioning and de-provisioning from external identity providers. SCIM is a **launch requirement** for enterprise deployments.

### De-Provisioning Behavior

When a user is de-provisioned via SCIM (e.g., employee leaves the organization):

| Action | Timing | Effect |
|--------|--------|--------|
| Active sessions invalidated | Immediate | All current sessions for the user are terminated |
| Refresh tokens revoked | Immediate | No new access tokens can be issued |
| Enrolled authenticators disabled | Immediate | YubiKey credentials cannot be used for login |
| User record marked inactive | Immediate | User cannot re-enroll or authenticate |
| Audit event logged | Immediate | De-provisioning recorded with source IdP info |

**Key principle**: De-provisioning is immediate and complete. When someone leaves via SCIM, they lose all Vouch access instantly — no waiting for session expiration.

```rust
// SCIM de-provision handling
async fn handle_scim_delete_user(user_id: &str, scim_request: &ScimRequest) -> Result<()> {
    // 1. Invalidate all active sessions immediately
    session_store.revoke_all_for_user(user_id).await?;

    // 2. Revoke all refresh tokens
    token_store.revoke_all_refresh_tokens(user_id).await?;

    // 3. Disable all enrolled authenticators
    authenticator_store.disable_all_for_user(user_id).await?;

    // 4. Mark user as inactive
    user_store.deactivate(user_id).await?;

    // 5. Log audit event
    audit_log.record(AuditEvent::ScimUserDeprovisioned {
        user_id,
        source_idp: scim_request.source_idp(),
        timestamp: Timestamp::now(),
    }).await?;

    Ok(())
}
```

### SCIM Endpoint Authentication

SCIM endpoints require bearer token authentication:

**Endpoint**: `POST /scim/v2/Users`, `DELETE /scim/v2/Users/:id`, etc.

**Authentication**:
- Bearer token in `Authorization` header
- Token generated in Vouch admin portal per external IdP
- Tokens are long-lived but can be rotated/revoked
- Separate token per IdP integration (Okta, Azure AD, etc.)

```bash
# Example SCIM request from Okta
curl -X DELETE https://vouch.example.com/scim/v2/Users/usr_abc123 \
  -H "Authorization: Bearer scim_token_xyz789" \
  -H "Content-Type: application/scim+json"
```

**Token Security**:
- Tokens are hashed (Argon2id) before storage
- Shown once at creation, never retrievable after
- Bound to specific IdP and IP allowlist (optional)
- Minimum 256 bits of entropy

### SCIM Audit Logging

All SCIM operations are logged for compliance and security monitoring:

| Event | Logged Data |
|-------|-------------|
| `scim_user_created` | user_id, email, source_idp, scim_external_id, timestamp |
| `scim_user_updated` | user_id, changed_fields, source_idp, timestamp |
| `scim_user_deprovisioned` | user_id, email, source_idp, sessions_revoked_count, timestamp |
| `scim_group_updated` | group_id, members_added, members_removed, source_idp, timestamp |
| `scim_auth_failed` | source_ip, reason, attempted_operation, timestamp |

**Log Entry Example (De-provisioning)**:
```json
{
  "timestamp": "2024-01-14T10:32:15.123Z",
  "event_type": "scim_user_deprovisioned",
  "user": {
    "id": "usr_abc123",
    "email": "former.employee@company.com"
  },
  "source": {
    "idp": "okta",
    "scim_external_id": "00u1a2b3c4d5e6f7g8"
  },
  "effects": {
    "sessions_revoked": 3,
    "refresh_tokens_revoked": 2,
    "authenticators_disabled": 1
  }
}
```

### SCIM vs Manual Enrollment

| Aspect | SCIM Provisioning | Manual Enrollment |
|--------|-------------------|-------------------|
| User record creation | IdP pushes user info | User initiates enrollment |
| Hardware enrollment | Still requires physical YubiKey | Requires physical YubiKey |
| De-provisioning | Immediate via IdP | Manual admin action |
| Group membership | Synced from IdP | Managed in Vouch |

**Note**: SCIM pre-provisioning creates a user record, but they still cannot authenticate until they physically enroll a YubiKey. The security model remains: no credential without hardware.

## Client Credential Security

OAuth client credentials issued through the application registration portal follow strict security practices.

### Secret Storage

Client secrets are **never stored in plaintext**:

```rust
// Client secret handling
fn store_client_secret(secret: &str) -> StoredCredential {
    // Generate random salt
    let salt = generate_salt(16);

    // Hash with Argon2id (memory-hard, resistant to GPU attacks)
    let hash = argon2id::hash(
        secret.as_bytes(),
        &salt,
        &Argon2Params {
            memory_cost: 65536,  // 64 MB
            time_cost: 3,
            parallelism: 4,
        }
    );

    StoredCredential { hash, salt }
}
```

**Storage Properties:**
| Property | Value |
|----------|-------|
| Algorithm | Argon2id |
| Salt | 16 bytes, unique per secret |
| Plaintext stored | Never |
| Reversible | No |

### Secret Generation

Client secrets are cryptographically random:

```rust
// 32 bytes = 256 bits of entropy
let secret = SecretString::new(base64url_encode(random_bytes(32)));
// Example: "dGhpcyBpcyBhIHNlY3VyZSByYW5kb20gc2VjcmV0"
```

**Properties:**
- 256 bits of entropy
- Base64url encoding (URL-safe, no padding)
- Shown once at creation, never retrievable after

### Secret Rotation

Client secrets can be rotated with a grace period:

```
1. User requests rotation via portal or API
2. New secret generated and returned
3. Old secret remains valid for 24 hours (configurable)
4. After grace period, old secret is invalidated
5. Audit log records rotation event
```

**Grace Period Rationale:**
- Allows zero-downtime secret rotation
- Applications can update configuration before old secret expires
- Prevents lockouts from configuration timing issues

### Scope Restrictions

Each registered application has scoped permissions:

```rust
struct OAuthClient {
    client_id: String,
    allowed_scopes: Vec<Scope>,        // Maximum scopes client can request
    allowed_redirect_uris: Vec<Url>,   // Validated redirect destinations
    token_lifetime: Duration,           // Maximum token lifetime
}
```

**Enforcement:**
- Token requests cannot exceed `allowed_scopes`
- Redirect URIs must exactly match registered values (no wildcards)
- Tokens cannot exceed `token_lifetime` even if requested

### Audit Logging

All client credential operations are logged:

| Event | Logged Data |
|-------|-------------|
| `client_created` | client_id, owner, allowed_scopes, created_at |
| `client_updated` | client_id, changed_fields, updated_by, updated_at |
| `secret_rotated` | client_id, rotated_by, grace_period_ends, rotated_at |
| `client_revoked` | client_id, revoked_by, tokens_invalidated_count, revoked_at |
| `client_deleted` | client_id, deleted_by, deleted_at |
| `token_issued` | client_id, user_id (if applicable), scopes, expires_at |
| `token_rejected` | client_id, reason, requested_scopes |

**Log Entry Example:**
```json
{
  "timestamp": "2024-01-14T10:32:15.123Z",
  "event_type": "secret_rotated",
  "client": {
    "id": "cli_abc123",
    "name": "My Application"
  },
  "actor": {
    "user_id": "usr_xyz789",
    "email": "developer@company.com"
  },
  "details": {
    "grace_period_ends": "2024-01-15T10:32:15.123Z",
    "reason": "scheduled_rotation"
  }
}
```

### Token Security

Tokens issued to OAuth clients follow security best practices:

**Access Tokens:**
- Short-lived (default: 1 hour, max: 8 hours)
- JWT format with standard claims
- Bound to client_id and user (if applicable)
- Include `hardware_verified` claim when backed by YubiKey session

**Refresh Tokens:**
- Not issued for public clients (native, SPA)
- Rotation on use (new refresh token issued, old invalidated)
- Absolute lifetime: 30 days
- Revoked on logout or security event

### Revocation

Applications can be immediately revoked:

```
POST /api/v1/applications/:id/revoke
```

**Revocation Effects:**
1. All access tokens immediately invalidated
2. All refresh tokens immediately invalidated
3. Client secret marked as revoked
4. New token requests rejected
5. Audit log records revocation

## Memory Safety

Vouch is written in Rust, providing:

1. **No buffer overflows** — Bounds checking on all array access
2. **No use-after-free** — Ownership system prevents dangling pointers
3. **No data races** — Compiler-enforced thread safety

For sensitive data handling:

```rust
use secrecy::{ExposeSecret, SecretString, SecretVec};
use zeroize::Zeroize;

// Session tokens wrapped in SecretString
let session_token: SecretString = fetch_session_token()?;

// Automatically zeroized when dropped
// Debug output shows "[REDACTED]"

// Explicit zeroization for extra-sensitive data
let mut pin: SecretVec<u8> = SecretVec::new(read_pin()?);
// ... use pin ...
pin.zeroize();  // Explicit clear (also happens on drop)
```

## Supply Chain Security

### Dependency Management

```toml
# Cargo.toml
[dependencies]
# Prefer crates with:
# - Active maintenance
# - Security audits
# - Minimal transitive dependencies

# Crypto: AWS-backed, FIPS-validated
aws-lc-rs = "1.0"

# No OpenSSL linking
rustls = "0.23"
```

### Build Verification

```bash
# Reproducible builds
cargo build --release --locked

# Dependency audit
cargo audit

# Dependency review
cargo vet
```

### Distribution

- CLI binaries are signed with our release key
- macOS binaries are notarized with Apple
- Windows binaries are Authenticode signed (planned)
- SHA256 checksums published with every release
- Source releases include signed git tags
- Reproducible builds (see below)
- HSTS headers on web endpoints (planned)

### Reproducible Builds

Vouch implements reproducible builds to enable independent verification that the released binaries match the source code. This allows anyone to rebuild from source and compare checksums.

**How Reproducibility is Achieved:**

| Technique | Purpose |
|-----------|---------|
| **Pinned Rust toolchain** | `rust-toolchain.toml` specifies exact version (1.93.0) |
| **SOURCE_DATE_EPOCH** | Timestamps derived from git commit time, not build time |
| **Locked dependencies** | `Cargo.lock` ensures identical dependency versions |
| **Deterministic archives** | tar archives use `--sort=name`, `--mtime`, `--owner=0` |
| **CI verification** | Automated rebuild job compares hashes in release workflow |

**Verifying a Release (Linux):**

```bash
# Clone the repository at the release tag
git clone --branch v0.1.0 https://github.com/vouch-sh/vouch.git
cd vouch

# Set SOURCE_DATE_EPOCH from the commit
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)

# Build with locked dependencies
cargo build --release --locked -p vouch-cli -p vouch-agent

# Download the official release
curl -LO https://github.com/vouch-sh/vouch/releases/download/v0.1.0/vouch-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
tar xzf vouch-v0.1.0-x86_64-unknown-linux-gnu.tar.gz

# Compare hashes
sha256sum target/release/vouch vouch-v0.1.0-x86_64-unknown-linux-gnu/vouch
# Hashes should match for Linux builds
```

**Platform Notes:**

| Platform | Reproducibility |
|----------|-----------------|
| **Linux** | Fully reproducible with matching toolchain |
| **macOS** | Binaries differ due to Apple code signing and notarization |
| **Windows** | Binaries differ due to Authenticode signing (planned) |

**Why This Matters:**

Reproducible builds provide defense against:
- Compromised build infrastructure
- Supply chain attacks on CI/CD
- Tampering during distribution

If you can rebuild the exact same binary from source, you can trust that the released binary was built from that source code.

## Residual Risks

Despite comprehensive mitigations, the following residual risks remain and have been accepted:

### RR-01: Physical YubiKey Theft with PIN Knowledge

**Risk**: If an attacker obtains both physical possession of a YubiKey and knowledge of the PIN, they can authenticate as the user.

| Aspect | Detail |
|--------|--------|
| **Residual Impact** | Medium |
| **Acceptance Rationale** | This requires two independent factors to be compromised. The 8-hour session limit bounds the impact. Biometric YubiKeys (Bio series) can eliminate the PIN knowledge factor. |
| **Monitoring** | Audit logs track all authentication events. Anomaly detection can flag unusual access patterns. |

### RR-02: Compromised Vouch Server

**Risk**: A sophisticated attacker with server access could potentially extract the SSH CA key or manipulate authentication logic.

| Aspect | Detail |
|--------|--------|
| **Residual Impact** | High |
| **Acceptance Rationale** | Self-hosted deployment shifts this risk to the organization. Air-gapped deployment (planned) provides additional protection. Audit logs provide detection capability. |
| **Monitoring** | Server integrity monitoring, audit log analysis, and anomaly detection. |

### RR-03: Session Token Theft via Advanced Malware

**Risk**: Sophisticated malware with root/admin access could potentially extract session tokens from memory despite protections.

| Aspect | Detail |
|--------|--------|
| **Residual Impact** | Medium |
| **Acceptance Rationale** | 8-hour session lifetime limits the window. This risk exists for any authentication system and is mitigated by endpoint security. |
| **Monitoring** | Endpoint detection and response (EDR) solutions, anomalous session usage patterns. |

### RR-04: Supply Chain Compromise Before Detection

**Risk**: A supply chain attack could potentially affect users between compromise and detection.

| Aspect | Detail |
|--------|--------|
| **Residual Impact** | Medium-High |
| **Acceptance Rationale** | Open source code enables community review. Reproducible builds and SLSA attestations further reduce this risk. |
| **Monitoring** | Security researcher engagement, automated vulnerability scanning, build provenance verification. |

## Incident Response

### Severity Levels

| Level | Description | Response Time |
|-------|-------------|---------------|
| **Critical** | Active exploitation, credential theft | 1 hour |
| **High** | Exploitable vulnerability, no active exploitation | 24 hours |
| **Medium** | Vulnerability requiring unlikely conditions | 7 days |
| **Low** | Minor issues, defense in depth | 30 days |

### Response Procedure

1. **Triage** — Assess severity and scope
2. **Contain** — Revoke affected credentials, disable vulnerable features
3. **Investigate** — Root cause analysis
4. **Remediate** — Deploy fix
5. **Communicate** — Notify affected users
6. **Review** — Post-incident analysis

### Communication Channels

- **Security advisories**: https://vouch.sh/security
- **CVE assignments**: Via GitHub Security Advisories
- **Status page**: https://status.vouch.sh

## Vulnerability Disclosure

### Reporting

Email: **security@vouch.sh**

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes

### What to Expect

| Timeline | Action |
|----------|--------|
| 24 hours | Acknowledgment of report |
| 72 hours | Initial assessment and severity |
| 7 days | Estimated fix timeline |
| 90 days | Public disclosure (coordinated) |

### Bug Bounty

We offer bounties for responsibly disclosed vulnerabilities:

| Severity | Bounty |
|----------|--------|
| Critical (RCE, auth bypass) | $5,000 |
| High (privilege escalation) | $2,500 |
| Medium | $1,000 |
| Low | $250 |

Scope:
- vouch CLI and agent
- Vouch server (cloud and self-hosted)
- Documentation errors that could lead to insecure configurations

Out of scope:
- Social engineering
- Denial of service
- Issues in third-party dependencies (report upstream)

## Security Hardening Guide

### CLI Security

```bash
# Verify binary integrity before first use
sha256sum /usr/local/bin/vouch
# Compare with published checksum

# Use secure file permissions
chmod 700 ~/.vouch
chmod 600 ~/.vouch/config.json

# Verify YubiKey is genuine
ykman fido info
```

### YubiKey Configuration

Vouch requires a minimum 8-character PIN. If your YubiKey doesn't have a PIN configured,
`vouch login` or `vouch register` will guide you through setting one up.

```bash
# Change an existing PIN
ykman fido access change-pin

# Enable PIN complexity (if supported)
ykman fido access pin-complexity enable

# View registered credentials
ykman fido credentials list
```

### Host SSH Configuration

```bash
# /etc/ssh/sshd_config

# Trust Vouch CA for user certificates
TrustedUserCAKeys /etc/ssh/vouch-ca.pub

# Optionally restrict to specific principals
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

## Security Contacts

- **Security Team**: security@vouch.sh
- **Bug Bounty**: bounty@vouch.sh
- **Compliance**: compliance@vouch.sh

For non-security issues, use GitHub Issues.
