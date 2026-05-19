# Security Rules

## Non-Negotiable

These rules apply to all code in this repository without exception:

1. **No secrets in code** -- Use environment variables or config files
2. **No credential storage in plain types** -- Use `SecretString`, `Zeroizing`
3. **No timing-vulnerable comparisons** -- Use `subtle::ConstantTimeEq` for secrets/tokens
4. **No skipping FIDO2 user verification** -- `userVerification: required` always
5. **No custom crypto implementations** -- Use audited libraries only
6. **No unsafe code** -- Denied at the lint level
7. **No panics in production code** -- Denied at the lint level

## Sensitive Data Handling

```rust
// Secrets
use secrecy::{SecretString, ExposeSecret};

// Zeroize on drop
use zeroize::Zeroizing;

// Constant-time comparison
use subtle::ConstantTimeEq;
```

## Input Validation

- Validate all input from network or user
- Never trust client-supplied data without verification
- Use typed wrappers for validated data where possible

## Credential Lifecycle

- All credentials are short-lived (SSH certs: 8 hours, AWS: 1 hour auto-refresh)
- No long-lived tokens or keys
- Every issuance requires FIDO2 attestation

## Reporting Vulnerabilities

Security vulnerabilities should be reported to security@vouch.sh. Do not open public issues.

## Security-Relevant Specifications

- FIDO2/CTAP2, WebAuthn Level 2
- FAPI 2.0 Security Profile
- RFC 9449 (DPoP)
- RFC 9421 (HTTP Message Signatures)
- RFC 9700 (OAuth 2.0 Security BCP)
