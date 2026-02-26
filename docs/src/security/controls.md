# Security Controls

This chapter details the layered security controls that Vouch implements across authentication, transport, credentials, and auditing, as well as memory safety and supply chain protections.

## Authentication Layer

```
+------------------------------------------------------------------+
|                    Authentication Controls                        |
|                                                                   |
|  +------------------+  +------------------+  +-----------------+  |
|  |  FIDO2/WebAuthn  |  |   User Verify    |  |  Attestation    |  |
|  |                  |  |                  |  |                 |  |
|  | * Ed25519        |  | * PIN required   |  | * Hardware-     |  |
|  | * Discoverable   |  | * UV flag set    |  |   bound only    |  |
|  |   credential     |  | * No platform    |  | * Format check  |  |
|  | * RP binding     |  |   passkeys       |  |   (packed/u2f)  |  |
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
- `attestation: direct` — Allows verifying authenticator attestation format (packed/fido-u2f)

## PIN Requirements

Vouch enforces PIN requirements on all FIDO2 operations:

**Minimum PIN Length:** 8 characters (enforced by CLI)

**Native PIN Setup:** If a hardware authenticator doesn't have a PIN configured, the CLI (`vouch login`, `vouch register`) will detect this and guide the user through setting one up. No external tools required.

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

## Hardware-Bound Enforcement

Vouch validates that authenticators are hardware-bound by checking the attestation format during enrollment:

```rust
// Server validates attestation format during enrollment
fn validate_hardware_attestation(attestation: &[u8]) -> AttestationValidation {
    let fmt = extract_attestation_format(attestation);

    if fmt.is_hardware() {          // packed, fido-u2f
        AttestationValidation::Valid(fmt)
    } else if fmt.is_software() {   // none (software passkeys like 1Password)
        AttestationValidation::SoftwarePasskey
    } else if fmt.is_platform() {   // tpm, apple, android-key, android-safetynet
        AttestationValidation::PlatformAuthenticator
    } else {
        AttestationValidation::Unknown(fmt.to_string())
    }
}
```

The AAGUID (Authenticator Attestation GUID) is extracted and stored for device identification purposes (e.g., displaying "YubiKey 5 NFC" in the key list), but is not used as an allowlist filter. Any hardware FIDO2 authenticator with `packed` or `fido-u2f` attestation format is accepted.

## Discoverable Credentials

Vouch uses discoverable credentials (resident keys) to enable email-less login:

```rust
// Login flow - no email required
async fn login() -> Result<Session> {
    // 1. Get challenge from server (no user identifier)
    let challenge = server.get_challenge().await?;

    // 2. Query authenticator for discoverable credentials for this RP
    let assertion = authenticator.get_assertion(
        &rp_id,         // RP ID
        &challenge,
        &pin,            // PIN required
    )?;
    // No credential_id filter = discoverable mode

    // 3. Server looks up user by user_handle from assertion
    let session = server.complete_login(
        assertion.credential_id,
        assertion.authenticator_data,
        assertion.signature,
        assertion.user_handle,  // User identified by authenticator
    ).await?;

    Ok(session)
}
```

**Security benefit**: The hardware authenticator identifies the user via `user_handle`, not user-provided input. Eliminates username enumeration.

## Enrollment Security — Device Authorization Grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628))

Vouch uses the Device Authorization Grant for enrollment. The protocol uses two codes: the `device_code` (opaque polling token, never shown to the user) and the `user_code` (short human-readable code displayed in the terminal).

```
device_code:   32 random bytes, SHA-256 hashed before storage
user_code:     8 characters from 20-char alphabet (~40 bits entropy)
               Format: XXXX-XXXX (no ambiguous chars: 0/O, 1/I/L)
Expiration:    10 minutes (configurable)
Polling:       5-second minimum interval, slow_down response
OIDC State:    32 random bytes, prevents CSRF
Nonce:         32 random bytes, prevents token replay
```

**Security properties:**
- Device codes are never stored in plain text (SHA-256 hash only)
- User codes have limited entropy but short expiration + rate limiting compensate
- `slow_down` response prevents rapid polling brute force
- OIDC state parameter prevents authorization code injection
- Nonce in ID token prevents replay attacks

**Rate Limiting:**
```
POST /oauth/token          1 request/5 seconds per device_code (implemented)
POST /oauth/device/code    10 requests/minute per IP (planned)
POST /device               5 attempts per user_code before invalidation (planned)
```

## Key Registration Security

Vouch enforces a secure key registration model:

**First Key Registration:**
- First key MUST be registered via browser enrollment (`vouch enroll`)
- Browser flow requires OIDC authentication (Google, etc.)
- Email comes from verified OIDC provider, never self-asserted
- WebAuthn registration happens in browser with `excludeCredentials`

**Additional Key Registration:**
- Requires existing authentication (`vouch login` first)
- CLI registration endpoint (`/v1/keys/register/start`) requires valid access token
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
    vouch enroll → Browser → Google Sign-in → WebAuthn → OAuth access token

  Daily login (FAPI 2.0):
    vouch login → FIDO2 challenge → YubiKey assertion → DPoP-bound access token

  Adding additional keys:
    vouch login      → Authenticate with existing key (FAPI 2.0)
    vouch register   → Add new key (requires valid access token)
```

**Email Binding:**
| Flow | Email Source | Verified By |
|------|--------------|-------------|
| `vouch enroll` | Google ID token | Google (OIDC) |
| `vouch register` | Access token | Previously verified via OIDC |
| `vouch login` | Stored in user record | Looked up via credential's user_handle |

The email is never self-asserted. It always traces back to the original OIDC verification.

## Transport Layer

All communication uses TLS 1.3 with:
- AEAD ciphers only (AES-GCM, ChaCha20-Poly1305)
- rustls (no OpenSSL)

## Credential Layer

**SSH Certificates:**
```
Certificate:
    Type: user certificate
    Public key: ssh-ed25519
    Signing CA: vouch-ca (built-in Ed25519)
    Key ID: user@example.com@vouch.example.com
    Serial: 1705234567
    Valid: 2026-01-14T10:00:00 to 2026-01-14T18:00:00 (8 hours)
    Principals: user@example.com, user
    Critical Options: (none)
    Extensions:
        permit-X11-forwarding
        permit-agent-forwarding
        permit-port-forwarding
        permit-pty
        permit-user-rc
```

**AWS Credentials:**
- Obtained via `AssumeRoleWithWebIdentity` using Vouch as OIDC provider
- Maximum duration: 1 hour
- Role trust policy restricts to Vouch OIDC provider
- Session tags include attestation timestamp

**EKS Credentials:**
- Obtained through `vouch credential aws` → `aws eks get-token` chain
- Uses IAM-based authentication via EKS Access Entries
- No cluster-side OIDC configuration required
- Access controlled by IAM role trust policy and EKS Access Policies
- Maximum duration: matches AWS STS session (1 hour, auto-refresh within session)

## Audit Layer

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
- SIEM export (planned)
- Certificate transparency logging (planned)

## Memory Safety

Vouch is written in Rust, providing:

1. **No buffer overflows** — Bounds checking on all array access
2. **No use-after-free** — Ownership system prevents dangling pointers
3. **No data races** — Compiler-enforced thread safety

For sensitive data handling:

```rust
use secrecy::{ExposeSecret, SecretString};

// Access tokens wrapped in SecretString
let access_token: SecretString = fetch_access_token()?;

// Automatically zeroized when dropped
// Debug output shows "[REDACTED]"

// Credential structures use SecretString for sensitive fields
struct CredentialProcessOutput {
    access_key_id: String,
    secret_access_key: SecretString,  // Zeroized on drop, redacted in Debug
    session_token: SecretString,      // Zeroized on drop, redacted in Debug
}
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

# CI runs dependency-review-action on PRs
# CI runs Trivy vulnerability scanning on container images

# Dependency review (planned)
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
