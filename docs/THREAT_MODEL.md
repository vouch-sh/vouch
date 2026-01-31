# Threat Model

This document provides a comprehensive threat model for Vouch, following the [AWS Threat Composer](https://github.com/awslabs/threat-composer) methodology. It identifies potential threats, documents assumptions, and maps mitigations to ensure the security of the hardware-backed authentication system.

**Last Updated**: 2026-01-31
**Version**: 1.0
**Status**: Active

## Table of Contents

1. [System Description](#system-description)
2. [Data Flow Diagram](#data-flow-diagram)
3. [Trust Boundaries](#trust-boundaries)
4. [Assets](#assets)
5. [Threat Actors](#threat-actors)
6. [Assumptions](#assumptions)
7. [Threat Statements](#threat-statements)
8. [Mitigations Summary](#mitigations-summary)
9. [Residual Risks](#residual-risks)
10. [References](#references)

---

## System Description

### Overview

Vouch is a hardware-backed authentication system that issues short-lived credentials after FIDO2 verification with a YubiKey. The core security principle is: **no credential issuance without human presence proof**.

### Scope

This threat model covers:

- **vouch CLI** — User-facing command-line tool for authentication and credential management
- **vouch-agent** — Background daemon managing sessions, SSH certificates, and credential caching
- **Vouch Server** — Authentication backend with OIDC provider, SSH CA, and credential issuance
- **Integration Points** — SSH, AWS, GCP, Kubernetes, and GitHub credential flows

Out of scope:
- Physical security of YubiKey devices (covered by Yubico's security model)
- Network infrastructure (firewalls, load balancers)
- Operating system security on user workstations
- External identity providers (Google Workspace, Microsoft Entra ID)

### Security Objectives

| Objective | Description |
|-----------|-------------|
| **Confidentiality** | Session tokens, private keys, and credentials are protected from unauthorized access |
| **Integrity** | Credentials are issued only after verified hardware authentication |
| **Availability** | Users can authenticate and obtain credentials when needed |
| **Non-repudiation** | All credential issuance is logged with cryptographic attestation |
| **Authentication** | Only authorized users with enrolled hardware keys can authenticate |

---

## Data Flow Diagram

```
                                    TRUST BOUNDARY: Internet
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                                                                 │
│                              External Services                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │
│  │ Google/Entra │  │   AWS STS    │  │   GCP STS    │  │   GitHub     │        │
│  │    OIDC      │  │              │  │              │  │   API        │        │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘        │
│         │                 │                 │                 │                │
└─────────┼─────────────────┼─────────────────┼─────────────────┼────────────────┘
          │                 │                 │                 │
          │ HTTPS/TLS 1.3   │                 │                 │
          ▼                 ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         TRUST BOUNDARY: Vouch Server                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                           Vouch Server                                   │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │   │
│  │  │ Auth Portal │  │   SSH CA    │  │    OIDC     │  │   GitHub    │     │   │
│  │  │             │  │  (Ed25519)  │  │  Provider   │  │    App      │     │   │
│  │  │ • WebAuthn  │  │             │  │             │  │             │     │   │
│  │  │ • Sessions  │  │ • Sign certs│  │ • JWKS      │  │ • Inst.     │     │   │
│  │  │ • Enrollment│  │ • 8hr TTL   │  │ • Tokens    │  │   tokens    │     │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘     │   │
│  │                                                                          │   │
│  │  ┌─────────────────────────────────────────────────────────────────┐    │   │
│  │  │                    Database (SQLite/PostgreSQL)                  │    │   │
│  │  │  • Users  • Authenticators  • Sessions  • Audit Logs            │    │   │
│  │  └─────────────────────────────────────────────────────────────────┘    │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ HTTPS/TLS 1.3
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         TRUST BOUNDARY: User Workstation                        │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                              vouch CLI                                   │   │
│  │  • vouch enroll      • vouch login       • vouch register               │   │
│  │  • vouch credential  • vouch setup       • vouch keys                   │   │
│  └────────────────────────────────┬────────────────────────────────────────┘   │
│                                   │ IPC (Unix socket)                          │
│                                   ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                            vouch-agent                                   │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                      │   │
│  │  │  Session    │  │    Cert     │  │  SSH Agent  │                      │   │
│  │  │  Manager    │  │    Cache    │  │  Protocol   │                      │   │
│  │  │             │  │             │  │             │                      │   │
│  │  │ • 8hr TTL   │  │ • SSH certs │  │ • Identities│                      │   │
│  │  │ • SecretStr │  │ • Auto-     │  │ • Sign      │                      │   │
│  │  │             │  │   refresh   │  │   requests  │                      │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                      │   │
│  │                                                                          │   │
│  │  ~/.vouch/agent.sock (0700)    ~/.vouch/ssh-agent.sock                  │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                          Native Tools                                    │   │
│  │  ssh → IdentityAgent    aws → credential_process    git → credential    │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ USB HID
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         TRUST BOUNDARY: Hardware                                │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                         YubiKey 5 Series                                 │   │
│  │                                                                          │   │
│  │  • Private keys (non-exportable)     • PIN verification (on-device)     │   │
│  │  • Discoverable credentials          • Touch sensor (presence proof)     │   │
│  │  • Attestation certificate           • Secure element                    │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Trust Boundaries

| Boundary | Description | Protection |
|----------|-------------|------------|
| **Internet ↔ Server** | Public network to Vouch server | TLS 1.3, certificate validation |
| **Server ↔ Database** | Application to data store | Parameterized queries, encryption at rest |
| **Server ↔ Workstation** | Server to user machine | TLS 1.3, JWT validation |
| **CLI ↔ Agent** | User commands to daemon | Unix socket permissions (0700) |
| **Agent ↔ YubiKey** | Software to hardware | CTAP2 protocol, PIN verification |
| **Workstation ↔ External Services** | Local machine to AWS/GCP/GitHub | TLS 1.3, short-lived tokens |

---

## Assets

### Critical Assets

| Asset | Description | CIA Priority |
|-------|-------------|--------------|
| **YubiKey Private Keys** | Non-exportable FIDO2 keys | C > I > A |
| **Session Tokens (JWT)** | 8-hour authentication tokens | C > I > A |
| **SSH CA Private Key** | Ed25519 key for signing certificates | C > I > A |
| **User Credentials** | Temporary AWS/GCP/GitHub tokens | C > I > A |
| **Audit Logs** | Credential issuance records | I > A > C |

### Supporting Assets

| Asset | Description | CIA Priority |
|-------|-------------|--------------|
| **User Database** | Email, credential mappings | I > C > A |
| **OIDC Configuration** | External IdP settings | I > A > C |
| **SSH Certificates** | Signed user certificates | I > C > A |
| **Cookie Files** | Local session storage | C > I > A |

---

## Threat Actors

### TA-1: Script Kiddie

- **Motivation**: Opportunistic, reputation
- **Capabilities**: Automated scanning, credential stuffing, phishing kits
- **Resources**: Low
- **Relevant Threats**: T-01, T-02, T-03

### TA-2: Sophisticated Attacker

- **Motivation**: Financial gain, corporate espionage
- **Capabilities**: Targeted phishing, custom malware, network interception
- **Resources**: Medium
- **Relevant Threats**: T-04, T-05, T-06, T-07, T-08

### TA-3: Malicious Insider

- **Motivation**: Financial gain, revenge, coercion
- **Capabilities**: Legitimate access, knowledge of systems
- **Resources**: Low-Medium
- **Relevant Threats**: T-09, T-10, T-11

### TA-4: Nation-State Actor

- **Motivation**: Espionage, disruption
- **Capabilities**: Zero-days, supply chain attacks, physical access
- **Resources**: High
- **Relevant Threats**: T-12, T-13, T-14, T-15

---

## Assumptions

### A-01: Hardware Authenticator Integrity

**Statement**: YubiKey 5 series devices correctly implement FIDO2/CTAP2 and protect private keys from extraction.

**Rationale**: Yubico has undergone independent security audits. The secure element prevents key extraction even with physical access.

**If violated**: Attackers could clone YubiKey credentials, defeating hardware-bound authentication.

### A-02: TLS Implementation Correctness

**Statement**: The TLS 1.3 implementation (rustls) correctly encrypts communications and validates certificates.

**Rationale**: rustls is a well-audited, memory-safe TLS implementation with no OpenSSL dependencies.

**If violated**: Network attackers could intercept or modify communications between components.

### A-03: Cryptographic Primitive Security

**Statement**: Ed25519, AES-GCM, and Argon2id provide their claimed security properties.

**Rationale**: These are widely reviewed, standardized algorithms implemented by aws-lc-rs (FIPS-validated).

**If violated**: Signature forgery, token decryption, or password hash reversal could occur.

### A-04: Operating System Isolation

**Statement**: The operating system provides process isolation and file permission enforcement.

**Rationale**: Unix socket permissions (0700) and file permissions (0600) are enforced by the kernel.

**If violated**: Malicious processes could access agent sockets or credential files.

### A-05: User PIN Confidentiality

**Statement**: Users protect their YubiKey PIN and do not share it.

**Rationale**: PIN is verified on-device and never transmitted to servers.

**If violated**: PIN + physical YubiKey access enables impersonation.

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

## Threat Statements

Threat statements follow the [AWS Threat Grammar](https://aws.amazon.com/blogs/security/threat-modeling-your-generative-ai-workload-to-evaluate-security-risk/):

> **A [threat source] with [prerequisites] can [threat action] which leads to [threat impact], negatively impacting [impacted assets].**

---

### Authentication Threats

#### T-01: Credential Stuffing Attack

**Threat Statement**: A **script kiddie** with **access to leaked password databases** can **attempt credential stuffing attacks** which leads to **failed authentication attempts flooding the system**, negatively impacting **system availability**.

**Likelihood**: Low
**Impact**: Low
**Risk**: Low

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-01 | No passwords in authentication flow | Implemented |
| M-02 | Rate limiting on authentication endpoints | Planned |
| M-03 | Account lockout after failed PIN attempts (YubiKey enforced) | Implemented |

---

#### T-02: Phishing for Credentials

**Threat Statement**: A **sophisticated attacker** with **a convincing phishing site** can **trick users into entering credentials on a fake Vouch site** which leads to **no credential theft due to origin binding**, negatively impacting **nothing (attack fails)**.

**Likelihood**: Medium (attack attempt)
**Impact**: None (due to mitigations)
**Risk**: Mitigated

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-04 | WebAuthn origin binding (RP ID validation) | Implemented |
| M-05 | Discoverable credentials bound to legitimate domain | Implemented |
| M-06 | No password to phish | Implemented |

---

#### T-03: MFA Fatigue Attack

**Threat Statement**: A **sophisticated attacker** with **compromised primary credentials** can **bombard user with push notifications** which leads to **user approving malicious request**, negatively impacting **nothing (attack vector doesn't exist)**.

**Likelihood**: None
**Impact**: None
**Risk**: Not Applicable

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-07 | No push notifications in authentication flow | Implemented |
| M-08 | Physical touch required on YubiKey | Implemented |

---

#### T-04: PIN Brute Force

**Threat Statement**: A **sophisticated attacker** with **physical access to a stolen YubiKey** can **attempt to brute force the PIN** which leads to **YubiKey lockout after 8 attempts**, negatively impacting **authenticator availability (device unusable)**.

**Likelihood**: Low
**Impact**: Medium (locked device)
**Risk**: Low

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-09 | YubiKey enforces 8-attempt lockout | Hardware |
| M-10 | Minimum 8-character PIN requirement | Implemented |
| M-11 | PIN never transmitted to server | Implemented |

---

#### T-05: Stolen YubiKey with Known PIN

**Threat Statement**: A **sophisticated attacker** with **physical possession of a YubiKey AND knowledge of the PIN** can **authenticate as the legitimate user** which leads to **unauthorized session creation and credential issuance**, negatively impacting **confidentiality of protected resources**.

**Likelihood**: Low
**Impact**: High
**Risk**: Medium

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-12 | 8-hour session lifetime limits blast radius | Implemented |
| M-13 | Self-service key revocation via `vouch keys remove` | Implemented |
| M-14 | Audit logging of all authentications | Implemented |
| M-15 | SCIM de-provisioning for immediate access revocation | Implemented |
| M-16 | Recommend biometric YubiKey (Bio series) for high-security | Documentation |

---

### Session Management Threats

#### T-06: Session Token Theft via Malware

**Threat Statement**: A **sophisticated attacker** with **malware on the user's workstation** can **read session tokens from memory or disk** which leads to **session hijacking until token expiration**, negatively impacting **confidentiality of issued credentials**.

**Likelihood**: Medium
**Impact**: Medium (8-hour window)
**Risk**: Medium

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-17 | 8-hour maximum session lifetime | Implemented |
| M-18 | SecretString with automatic zeroization | Implemented |
| M-19 | File permissions 0600 on cookie/config files | Implemented |
| M-20 | Socket permissions 0700 on agent directory | Implemented |
| M-21 | Explicit logout clears all session storage | Implemented |

---

#### T-07: Session Fixation

**Threat Statement**: A **sophisticated attacker** with **ability to inject session tokens** can **force a user to use an attacker-known session** which leads to **no impact due to session bound to hardware authentication**, negatively impacting **nothing (attack fails)**.

**Likelihood**: Low
**Impact**: None
**Risk**: Mitigated

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-22 | Sessions created only after FIDO2 assertion | Implemented |
| M-23 | Session tokens not predictable (cryptographically random) | Implemented |
| M-24 | Session bound to authenticator and user | Implemented |

---

#### T-08: Replay Attack on Authentication

**Threat Statement**: A **sophisticated attacker** with **captured authentication traffic** can **replay FIDO2 assertions** which leads to **no impact due to challenge-response protocol**, negatively impacting **nothing (attack fails)**.

**Likelihood**: Low
**Impact**: None
**Risk**: Mitigated

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-25 | Server-generated random challenges (32 bytes) | Implemented |
| M-26 | Challenge valid for single use | Implemented |
| M-27 | Signature counter verification | Implemented |
| M-28 | TLS 1.3 encryption of all traffic | Implemented |

---

### Server-Side Threats

#### T-09: Compromised Vouch Server

**Threat Statement**: A **nation-state actor** with **access to the Vouch server infrastructure** can **extract the SSH CA private key or modify authentication logic** which leads to **ability to forge SSH certificates or bypass authentication**, negatively impacting **integrity of all issued credentials**.

**Likelihood**: Low
**Impact**: Critical
**Risk**: High

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-29 | Self-hosted deployment option for high-security environments | Implemented |
| M-30 | Immutable audit logs with tamper detection | Planned |
| M-31 | SSH CA key stored with restrictive permissions | Implemented |
| M-32 | Certificate transparency logging (planned) | Planned |
| M-33 | Air-gapped deployment option | Planned |

---

#### T-10: SQL Injection

**Threat Statement**: A **sophisticated attacker** with **crafted malicious input** can **inject SQL commands** which leads to **no impact due to parameterized queries**, negatively impacting **nothing (attack fails)**.

**Likelihood**: Low
**Impact**: None
**Risk**: Mitigated

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-34 | All database queries use parameterized statements | Implemented |
| M-35 | SQLx compile-time query validation | Implemented |
| M-36 | Input validation on all API endpoints | Implemented |

---

#### T-11: SCIM Token Compromise

**Threat Statement**: A **malicious insider or external attacker** with **a compromised SCIM bearer token** can **provision unauthorized users or prevent de-provisioning** which leads to **unauthorized access or persistence**, negatively impacting **authentication integrity**.

**Likelihood**: Low
**Impact**: High
**Risk**: Medium

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-37 | SCIM tokens hashed with Argon2id (not stored plaintext) | Implemented |
| M-38 | Separate SCIM token per IdP integration | Implemented |
| M-39 | SCIM operations logged with source IdP info | Implemented |
| M-40 | Optional IP allowlist for SCIM endpoints | Implemented |
| M-41 | Token rotation capability | Implemented |

---

### Supply Chain Threats

#### T-12: Compromised CLI Binary

**Threat Statement**: A **nation-state actor** with **access to the build or distribution pipeline** can **inject malicious code into the CLI binary** which leads to **credential exfiltration or authentication bypass**, negatively impacting **confidentiality of all user credentials**.

**Likelihood**: Low
**Impact**: Critical
**Risk**: Medium (reduced by implemented mitigations)

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-42 | Open source CLI for public auditing | Implemented |
| M-43 | Reproducible builds | Planned |
| M-44 | Binary signing (macOS code signing + notarization) | Implemented |
| M-45 | SHA256 checksums with releases (SHA256SUMS.txt) | Implemented |
| M-46 | SBOM with each release (CycloneDX format) | Implemented |
| M-47 | SLSA build provenance attestations | Implemented |
| M-48a | Windows Authenticode signing | Planned |

---

#### T-13: Dependency Vulnerability

**Threat Statement**: A **sophisticated attacker** with **a compromised Rust crate** can **introduce vulnerabilities via transitive dependencies** which leads to **potential code execution or data leakage**, negatively impacting **system integrity**.

**Likelihood**: Low
**Impact**: High
**Risk**: Medium

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-49 | Minimal dependency policy | Implemented |
| M-50 | Dependency review in CI (actions/dependency-review-action) | Implemented |
| M-51 | Trivy vulnerability scanning in CI | Implemented |
| M-52 | `cargo vet` for dependency review | Planned |
| M-53 | Prefer well-audited crates (aws-lc-rs, rustls) | Implemented |
| M-54 | Cargo.lock pinned versions | Implemented |

---

### Credential Issuance Threats

#### T-14: Unauthorized Credential Issuance

**Threat Statement**: A **sophisticated attacker** with **no valid session** can **request credentials from Vouch server** which leads to **no credentials issued due to session validation**, negatively impacting **nothing (attack fails)**.

**Likelihood**: Medium (attempt)
**Impact**: None
**Risk**: Mitigated

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-55 | All credential endpoints require valid JWT session | Implemented |
| M-56 | JWT signature verification with server key | Implemented |
| M-57 | Session expiration checked on each request | Implemented |

---

#### T-15: Credential Scope Escalation

**Threat Statement**: A **sophisticated attacker** with **a valid but limited session** can **request credentials beyond their authorized scope** which leads to **no escalation due to server-enforced policies**, negatively impacting **nothing (attack fails)**.

**Likelihood**: Low
**Impact**: None
**Risk**: Mitigated

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-58 | SSH principals derived from verified email only | Implemented |
| M-59 | AWS roles require IAM trust policy | Implemented |
| M-60 | GCP uses Workload Identity with attribute mapping | Implemented |
| M-61 | OAuth scopes validated against client registration | Implemented |

---

### Network Threats

#### T-16: Man-in-the-Middle Attack

**Threat Statement**: A **sophisticated attacker** with **network position between user and server** can **intercept or modify traffic** which leads to **no impact due to TLS with certificate validation**, negatively impacting **nothing (attack fails)**.

**Likelihood**: Medium (attempt)
**Impact**: None
**Risk**: Mitigated

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-62 | TLS 1.3 mandatory for all connections | Implemented |
| M-63 | Certificate validation via rustls | Implemented |
| M-64 | HSTS headers on web endpoints | Planned |
| M-65 | No HTTP downgrade allowed | Implemented |

---

#### T-17: DNS Spoofing

**Threat Statement**: A **sophisticated attacker** with **control over DNS resolution** can **redirect users to malicious server** which leads to **no credential theft due to WebAuthn origin binding**, negatively impacting **authentication availability (users cannot authenticate)**.

**Likelihood**: Low
**Impact**: Low (availability only)
**Risk**: Low

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-66 | WebAuthn RP ID binding prevents credential use on wrong domain | Implemented |
| M-67 | TLS certificate validation fails for spoofed domains | Implemented |

---

### Enrollment Threats

#### T-18: Enrollment Code Brute Force

**Threat Statement**: A **script kiddie** with **automated tools** can **brute force the 8-character user code** which leads to **no success due to rate limiting and short expiration**, negatively impacting **nothing (attack fails)**.

**Likelihood**: Medium (attempt)
**Impact**: None
**Risk**: Mitigated

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-68 | User code ~40 bits entropy | Implemented |
| M-69 | 10-minute code expiration | Implemented |
| M-70 | 5 attempts per code before invalidation | Planned |
| M-71 | Rate limiting: 10 requests/minute per IP | Planned |
| M-72 | `slow_down` response for rapid polling | Implemented |

---

#### T-19: Device Code Interception

**Threat Statement**: A **sophisticated attacker** with **access to user's terminal output** can **see the device code and complete enrollment first** which leads to **no impact due to device code being useless without OIDC authentication**, negatively impacting **nothing (attack fails)**.

**Likelihood**: Low
**Impact**: None
**Risk**: Mitigated

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-73 | Device code alone cannot complete enrollment | Implemented |
| M-74 | OIDC authentication required in browser | Implemented |
| M-75 | WebAuthn registration required with physical YubiKey | Implemented |

---

### Key Management Threats

#### T-20: Unauthorized Key Registration

**Threat Statement**: A **sophisticated attacker** with **no existing authentication** can **register a malicious YubiKey to a user account** which leads to **no success due to session requirement**, negatively impacting **nothing (attack fails)**.

**Likelihood**: Medium (attempt)
**Impact**: None
**Risk**: Mitigated

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-76 | Key registration requires valid session (recent FIDO2 auth) | Implemented |
| M-77 | Email derived from session claims, not request | Implemented |
| M-78 | excludeCredentials prevents duplicate registration | Implemented |

---

#### T-21: Key Removal by Attacker

**Threat Statement**: A **sophisticated attacker** with **a stolen session token** can **remove legitimate keys from an account** which leads to **denial of service for legitimate user**, negatively impacting **authentication availability**.

**Likelihood**: Low
**Impact**: Medium
**Risk**: Low

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-79 | Key removal logged in audit trail | Implemented |
| M-80 | Admin notification on key changes | Planned |
| M-81 | Recovery flow via OIDC re-enrollment | Implemented |
| M-82 | 8-hour session limits attack window | Implemented |

---

### Platform Passkey Bypass Threats

#### T-22: Platform Passkey Enrollment Attempt

**Threat Statement**: A **sophisticated attacker** with **malware that can register platform passkeys** can **attempt to enroll syncable credentials** which leads to **no success due to authenticator attestation validation**, negatively impacting **nothing (attack fails)**.

**Likelihood**: Low
**Impact**: None
**Risk**: Mitigated

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-83 | `authenticatorAttachment: cross-platform` enforced | Implemented |
| M-84 | AAGUID map for device identification (display only) | Implemented |
| M-85 | Attestation format validation (reject TPM, AndroidKey, Apple) | Implemented |
| M-86 | User verification (PIN) required for all authenticators | Implemented |

---

### Denial of Service Threats

#### T-23: Authentication Endpoint DoS

**Threat Statement**: A **script kiddie** with **botnet or amplification techniques** can **flood authentication endpoints** which leads to **degraded service for legitimate users**, negatively impacting **authentication availability**.

**Likelihood**: Medium
**Impact**: Medium
**Risk**: Medium

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-87 | Rate limiting on all endpoints | Implemented |
| M-88 | DDoS protection via infrastructure (cloud provider) | Deployment |
| M-89 | Self-hosted option for critical environments | Implemented |

---

## Mitigations Summary

### By Implementation Status

| Status | Count | Mitigations |
|--------|-------|-------------|
| **Implemented** | 75 | M-01 through M-89 (most) |
| **Planned** | 11 | M-02, M-30, M-32, M-33, M-43, M-48a, M-52, M-64, M-70, M-71, M-80 |
| **Hardware** | 2 | M-09, M-10 (YubiKey enforced) |
| **Deployment** | 1 | M-88 (infrastructure dependent) |
| **Documentation** | 1 | M-16 (user guidance) |

### By Control Category

| Category | Mitigations |
|----------|-------------|
| **Authentication** | M-01 through M-16 |
| **Session Management** | M-17 through M-28 |
| **Server Security** | M-29 through M-41 |
| **Supply Chain** | M-42 through M-54 |
| **Credential Issuance** | M-55 through M-61 |
| **Network Security** | M-62 through M-67 |
| **Enrollment Security** | M-68 through M-78 |
| **Key Management** | M-79 through M-86 |
| **Availability** | M-87 through M-89 |

---

## Residual Risks

Despite comprehensive mitigations, the following residual risks remain:

### RR-01: Physical YubiKey Theft with PIN Knowledge

**Risk**: If an attacker obtains both physical possession of a YubiKey and knowledge of the PIN, they can authenticate as the user.

**Residual Impact**: Medium
**Acceptance Rationale**: This requires two independent factors to be compromised. The 8-hour session limit bounds the impact. Biometric YubiKeys (Bio series) can eliminate the PIN knowledge factor.

**Monitoring**: Audit logs track all authentication events. Anomaly detection can flag unusual access patterns.

### RR-02: Compromised Vouch Server

**Risk**: A sophisticated attacker with server access could potentially extract the SSH CA key or manipulate authentication logic.

**Residual Impact**: High
**Acceptance Rationale**: Self-hosted deployment shifts this risk to the organization. Air-gapped deployment (planned) provides additional protection. Audit logs provide detection capability.

**Monitoring**: Server integrity monitoring, audit log analysis, and anomaly detection.

### RR-03: Session Token Theft via Advanced Malware

**Risk**: Sophisticated malware with root/admin access could potentially extract session tokens from memory despite protections.

**Residual Impact**: Medium
**Acceptance Rationale**: 8-hour session lifetime limits the window. This risk exists for any authentication system and is mitigated by endpoint security.

**Monitoring**: Endpoint detection and response (EDR) solutions, anomalous session usage patterns.

### RR-04: Supply Chain Compromise Before Detection

**Risk**: A supply chain attack could potentially affect users between compromise and detection.

**Residual Impact**: Medium-High
**Acceptance Rationale**: Open source code enables community review. Planned reproducible builds and SLSA attestations will further reduce this risk.

**Monitoring**: Security researcher engagement, automated vulnerability scanning, build provenance verification.

---

## References

### Standards and Specifications

- [FIDO2/CTAP2 Specification](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- [WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/)
- [RFC 6749 - OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 7636 - PKCE](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 8628 - Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
- [RFC 9449 - DPoP](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 7643/7644 - SCIM 2.0](https://www.rfc-editor.org/rfc/rfc7643)

### Methodology

- [AWS Threat Composer](https://github.com/awslabs/threat-composer)
- [AWS Security Blog - Threat Modeling](https://aws.amazon.com/blogs/security/threat-modeling-your-generative-ai-workload-to-evaluate-security-risk/)
- [STRIDE Threat Model](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)

### Related Documentation

- [Vouch Security Model](SECURITY.md)
- [Vouch Architecture](ARCHITECTURE.md)
- [Vouch Roadmap](ROADMAP.md)

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-31 | Vouch Security Team | Initial threat model |
