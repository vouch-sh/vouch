# Security Model

This document describes vouch's security model, threat analysis, and security considerations.

## Core Security Properties

### 1. Hardware-Bound Authentication

All authentication requires physical interaction with a FIDO2 authenticator (YubiKey, Touch ID, etc.). This provides:

- **Phishing resistance** - The authenticator validates the origin, preventing credential theft via fake sites
- **Presence verification** - A human must physically interact with the device
- **Non-exportable keys** - Private keys never leave the authenticator

### 2. Short-Lived Credentials

vouch only issues credentials with short validity periods:

| Credential Type | Default TTL | Maximum TTL |
|-----------------|-------------|-------------|
| Session token   | 8 hours     | 24 hours    |
| GitHub token    | 1 hour      | 1 hour (GitHub limit) |
| AWS credentials | 1 hour      | 12 hours (role-dependent) |
| SSH certificate | 1 hour      | 24 hours    |
| Delegation      | 1 hour      | 7 days      |

Short TTLs limit the window of exposure if credentials are compromised.

### 3. Audit Trail

Every credential issuance is logged with:

- User identity
- Presence type (human_present vs human_delegated)
- Delegation ID (if applicable)
- Target service
- Timestamp
- Client IP and user agent

This enables forensic analysis and compliance reporting.

## Threat Model

### Assets to Protect

1. **User identity** - Prevent impersonation
2. **External service access** - Prevent unauthorized GitHub/AWS/SSH access
3. **Audit integrity** - Prevent tampering with logs

### Threat Actors

| Actor | Capability | Goal |
|-------|------------|------|
| External attacker | Network access, phishing | Gain unauthorized access |
| Malicious insider | Valid account | Exceed authorized access |
| Compromised agent | Delegation token | Exceed delegated scope |
| Compromised endpoint | Local access | Steal credentials |

### Attack Scenarios

#### 1. Phishing Attack

**Attack**: Attacker creates fake vouch login page to steal credentials.

**Mitigation**: FIDO2/WebAuthn validates the origin. Even if a user visits a fake site, the authenticator will refuse to sign the challenge because the origin doesn't match.

**Residual risk**: None for authentication. Users could still be tricked into authorizing actions on the real site.

#### 2. Session Token Theft

**Attack**: Attacker steals session token from user's machine.

**Mitigation**: 
- Tokens are stored in memory, not on disk
- Short TTL limits exposure window
- Tokens are bound to client metadata (IP, user agent) for anomaly detection

**Residual risk**: Attacker with local access during active session can use the token until it expires.

#### 3. Delegation Scope Escape

**Attack**: Malicious agent tries to access resources outside its delegation scope.

**Mitigation**:
- Server validates every credential request against delegation scope
- Scope is enforced at issuance time, not just logged
- Delegation tokens are cryptographically bound to their scope

**Residual risk**: None if implementation is correct. Bugs in scope validation are critical vulnerabilities.

#### 4. Server Compromise

**Attack**: Attacker gains control of vouch server.

**Mitigation**:
- Server does not store long-lived credentials for external services
- GitHub App private key should be stored in HSM/secure enclave
- Database encryption at rest

**Residual risk**: Compromised server can issue credentials for any user. This is the highest-impact attack.

#### 5. Replay Attack

**Attack**: Attacker captures and replays authentication messages.

**Mitigation**:
- FIDO2 challenges are single-use and time-limited (5 minutes)
- Challenge state is stored server-side and invalidated after use
- Authenticator counter prevents credential cloning

**Residual risk**: None if implementation is correct.

## Security Controls

### Authentication

- [ ] FIDO2/WebAuthn for all authentication
- [ ] Single-use, time-limited challenges
- [ ] Authenticator counter verification
- [ ] User verification (PIN/biometric) required

### Session Management

- [ ] JWT tokens with short expiry
- [ ] Token hash stored in DB, not the token itself
- [ ] Secure token generation (256-bit entropy)
- [ ] Session invalidation on logout

### Credential Issuance

- [ ] Scope validation for all requests
- [ ] Rate limiting per user
- [ ] Audit logging for all issuance
- [ ] No credential caching on server

### Delegation

- [ ] Cryptographic binding of scope to token
- [ ] Revocation checked on every use
- [ ] Use count limits enforced
- [ ] Clear expiration enforcement

### Infrastructure

- [ ] TLS for all connections
- [ ] Database encryption at rest
- [ ] Secrets in secure storage (not env vars in production)
- [ ] Regular security updates

## Cryptographic Choices

| Purpose | Algorithm | Rationale |
|---------|-----------|-----------|
| JWT signing | Ed25519 | Fast, small signatures, no known weaknesses |
| Challenge generation | CSPRNG (256-bit) | Sufficient entropy for single-use values |
| Token hashing | SHA-256 | Standard, fast, collision-resistant |
| TLS | TLS 1.3 | Modern, secure, fast |

We use `aws-lc-rs` as the cryptographic backend, which is FIPS-validated and maintained by AWS.

## Incident Response

### Token Compromise

If a session token is compromised:

1. User runs `vouch logout` to invalidate the session
2. Server marks session as revoked in database
3. All subsequent requests with that token are rejected

### Delegation Compromise

If a delegation token is compromised:

1. User runs `vouch delegate revoke <id>`
2. Server marks delegation as revoked
3. All subsequent requests with that token are rejected
4. Review audit log for unauthorized actions

### Server Compromise

If the vouch server is compromised:

1. Rotate all signing keys
2. Invalidate all sessions and delegations
3. Rotate GitHub App private key
4. Review audit logs
5. Notify affected users

## Security Recommendations

### For Operators

1. Run vouch server in isolated network segment
2. Use HSM for signing key storage
3. Enable database encryption
4. Set up alerting on audit log anomalies
5. Regular security assessments

### For Users

1. Use a hardware security key (YubiKey) rather than platform authenticator
2. Register multiple authenticators for backup
3. Review active delegations regularly
4. Use shortest practical TTL for delegations
5. Scope delegations as narrowly as possible

## Known Limitations

1. **Central authority** - vouch server is a single point of compromise
2. **No offline mode** - Credentials cannot be issued without server connectivity
3. **Trust in hardware** - Security depends on authenticator integrity
4. **No key recovery** - Lost authenticator requires re-registration

## Reporting Security Issues

Please report security vulnerabilities to security@vouch.sh. Do not open public issues for security problems.

We aim to:
- Acknowledge reports within 24 hours
- Provide an initial assessment within 72 hours
- Release fixes within 30 days for critical issues
