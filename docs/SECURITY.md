# Security Model

This document describes Vouch's security architecture, threat model, and incident response procedures.

## Security Philosophy

Vouch is designed around three core principles:

1. **Hardware-bound only** — YubiKey 5 series required; no platform passkeys (Touch ID, Windows Hello)
2. **Minimize credential lifetime** — Short-lived credentials (8 hours max) limit blast radius of compromise
3. **Audit everything** — Every credential issuance is logged with provenance

**Policy**: This is non-negotiable. Platform passkeys can be synced, backed up, and extracted. Hardware-bound credentials cannot. This is Vouch's key differentiator.

## Threat Model

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

| Threat | Why | Mitigation |
|--------|-----|------------|
| **Physical YubiKey theft + known PIN** | Attacker has both factors | Use biometric YubiKey (Bio series), rotate PIN |
| **Compromised Vouch server** | Server issues credentials | Self-host for high-security, monitor audit logs |
| **Malware stealing session after login** | Session token in memory | Minimize session duration, endpoint protection |
| **Supply chain attacks on CLI** | Compromised binary | Reproducible builds, code signing, open source auditing |

### Attacker Profiles

#### Script Kiddie
- **Capabilities**: Automated scanning, credential stuffing, phishing kits
- **Vouch defense**: No passwords, origin-bound hardware auth, short-lived creds

#### Sophisticated Attacker
- **Capabilities**: Targeted phishing, malware, network interception
- **Vouch defense**: Hardware attestation, hardware-bound only policy, audit logging

#### Nation-State
- **Capabilities**: Zero-days, supply chain compromise, physical access
- **Vouch defense**: Air-gapped deployment, HSM integration, reproducible builds

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

**Rate Limiting:**
```
POST /oauth/device/code    10 requests/minute per IP
POST /oauth/token          1 request/5 seconds per device_code
POST /device               5 attempts/code (then code is invalidated)
```

### Transport Layer

All communication uses TLS 1.3 with:
- AEAD ciphers only (AES-GCM, ChaCha20-Poly1305)
- Certificate pinning for CLI → server communication
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
- Immutable (append-only storage)
- Retained for compliance period (configurable, default 2 years)
- Exportable to SIEM (Splunk, Datadog, etc.)

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
- Windows binaries are Authenticode signed
- SHA256 checksums published with every release
- Source releases include signed git tags

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

```bash
# Set strong PIN (8+ characters recommended)
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
