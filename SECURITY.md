# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Vouch, please report it responsibly.

**Email:** [security@vouch.sh](mailto:security@vouch.sh)

Please **do not** open public GitHub issues for security vulnerabilities.

## What to Include

- Description of the vulnerability
- Steps to reproduce (if applicable)
- Affected versions or components
- Potential impact assessment

## Response Timeline

- **Acknowledgment:** Within 48 hours of receipt
- **Initial assessment:** Within 5 business days
- **Fix timeline:** Depends on severity; critical issues are prioritized immediately

## Scope

The following components are in scope:

| Component | Repository Path |
|-----------|----------------|
| vouch-cli | `crates/vouch-cli/` |
| vouch-agent | `crates/vouch-agent/` |
| vouch-server | `crates/vouch-server/` |
| vouch-common | `crates/vouch-common/` |
| vouch-httpsig | `crates/vouch-httpsig/` |

## Security Design Principles

- No credential issuance without FIDO2 human presence proof
- All credentials are short-lived (SSH certs: 8 hours, AWS: 1 hour auto-refresh)
- No custom cryptography — audited libraries only (aws-lc-rs, rustls)
- No unsafe code (denied at the lint level)
- No panics in production code (denied at the lint level)
- Constant-time comparison for all secrets and tokens

## Relevant Specifications

- FIDO2/CTAP2, WebAuthn Level 2
- FAPI 2.0 Security Profile
- RFC 9449 (DPoP)
- RFC 9421 (HTTP Message Signatures)
- RFC 9700 (OAuth 2.0 Security BCP)
