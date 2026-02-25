# Overview and Scope

This chapter introduces the Vouch threat model, describes the system under analysis, defines security objectives, lists foundational assumptions, and provides references and document history.

## System Description

### Overview

Vouch is a hardware-backed authentication system that issues short-lived credentials after FIDO2 verification with a hardware authenticator. The core security principle is: **no credential issuance without human presence proof**.

### Scope

This threat model covers:

- **vouch CLI** — User-facing command-line tool for authentication and credential management
- **vouch-agent** — Background daemon managing sessions, SSH certificates, and credential caching
- **Vouch Server** — Authentication backend with OIDC provider, SSH CA, and credential issuance
- **Integration Points** — SSH, AWS, EKS, GitHub, Docker, Cargo, CodeArtifact, and CodeCommit credential flows

Out of scope:
- Physical security of hardware authenticator devices (covered by vendor security models)
- Network infrastructure (firewalls, load balancers)
- Operating system security on user workstations
- External identity providers (Google Workspace, Microsoft Entra ID)

### Security Objectives

| Objective | Description |
|-----------|-------------|
| **Confidentiality** | Access tokens, private keys, and credentials are protected from unauthorized access |
| **Integrity** | Credentials are issued only after verified hardware authentication |
| **Availability** | Users can authenticate and obtain credentials when needed |
| **Non-repudiation** | All credential issuance is logged with cryptographic attestation |
| **Authentication** | Only authorized users with enrolled hardware keys can authenticate |

---

## Assumptions

### A-01: Hardware Authenticator Integrity

**Statement**: Hardware FIDO2 authenticators correctly implement FIDO2/CTAP2 and protect private keys from extraction.

**Rationale**: Leading hardware authenticator vendors (Yubico, etc.) have undergone independent security audits. Secure elements prevent key extraction even with physical access.

**If violated**: Attackers could clone authenticator credentials, defeating hardware-bound authentication.

### A-02: TLS Implementation Correctness

**Statement**: The TLS 1.3 implementation (rustls) correctly encrypts communications and validates certificates.

**Rationale**: rustls is a well-audited, memory-safe TLS implementation with no OpenSSL dependencies.

**If violated**: Network attackers could intercept or modify communications between components.

### A-03: Cryptographic Primitive Security

**Statement**: Ed25519 and SHA-256 provide their claimed security properties; TLS ciphers (AES-GCM, ChaCha20-Poly1305) are handled by rustls.

**Rationale**: These are widely reviewed, standardized algorithms implemented by aws-lc-rs (FIPS-validated).

**If violated**: Signature forgery, token hash reversal, or TLS decryption could occur.

### A-04: Operating System Isolation

**Statement**: The operating system provides process isolation and file permission enforcement.

**Rationale**: Unix socket permissions (0700) and file permissions (0600) are enforced by the kernel.

**If violated**: Malicious processes could access agent sockets or credential files.

### A-05: User PIN Confidentiality

**Statement**: Users protect their hardware authenticator PIN and do not share it.

**Rationale**: PIN is verified on-device and never transmitted to servers.

**If violated**: PIN + physical authenticator access enables impersonation.

### A-06: Server Infrastructure Security

**Statement**: The Vouch server runs on secure, patched infrastructure with appropriate access controls.

**Rationale**: Server-side vulnerabilities are outside application scope but critical to overall security.

**If violated**: Database access, CA key theft, or session injection could occur.

### A-07: External IdP Trustworthiness

**Statement**: External identity providers (Google Workspace, Entra ID) correctly verify user identities.

**Rationale**: These are enterprise-grade identity providers with their own security models.

**If violated**: Unauthorized users could enroll by compromising external IdP accounts.

### A-08: Clock Synchronization

**Statement**: All systems maintain reasonably accurate time (within minutes).

**Rationale**: JWT expiration and certificate validity depend on timestamp comparison.

**If violated**: Expired tokens could be accepted or valid tokens rejected.

---

## References

### Standards and Specifications

- [FIDO2/CTAP2 Specification](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- [WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/)
- [RFC 6749 - OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 7636 - PKCE](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 8628 - Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
- [RFC 8707 - Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707)
- [RFC 9068 - JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068)
- [RFC 9449 - DPoP](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 7591 - OAuth 2.0 Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591)
- [RFC 7523 - JWT Profile for OAuth 2.0 Client Authentication](https://www.rfc-editor.org/rfc/rfc7523)
- [RFC 9126 - Pushed Authorization Requests](https://www.rfc-editor.org/rfc/rfc9126)
- [RFC 7643/7644 - SCIM 2.0](https://www.rfc-editor.org/rfc/rfc7643)

### Methodology

- [AWS Threat Composer](https://github.com/awslabs/threat-composer)
- [AWS Security Blog - Threat Modeling](https://aws.amazon.com/blogs/security/threat-modeling-your-generative-ai-workload-to-evaluate-security-risk/)
- [STRIDE Threat Model](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)

### Related Documentation

- [Vouch Security Model](../security/model.md)
- [Vouch Architecture](../architecture/overview.md)

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.2 | 2026-02-25 | Vouch Security Team | Added FAPI 2.0 client threats (T-15b, T-15c, T-15d), updated assets for ES256 tokens and CLI key pair |
| 1.1 | 2026-02-04 | Vouch Security Team | Added S3 configuration threat (T-11a) and mitigations |
| 1.0 | 2026-01-31 | Vouch Security Team | Initial threat model |
