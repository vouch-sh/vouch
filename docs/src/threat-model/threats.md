# Threat Statements

This chapter contains the complete catalog of threat statements for the Vouch system. Each threat follows the AWS Threat Grammar and includes likelihood, impact, risk rating, and mapped mitigations.

Threat statements follow the [AWS Threat Grammar](https://aws.amazon.com/blogs/security/threat-modeling-your-generative-ai-workload-to-evaluate-security-risk/):

> **A [threat source] with [prerequisites] can [threat action] which leads to [threat impact], negatively impacting [impacted assets].**

---

## Authentication Threats

### T-01: Credential Stuffing Attack

**Threat Statement**: A **script kiddie** with **access to leaked password databases** can **attempt credential stuffing attacks** which leads to **failed authentication attempts flooding the system**, negatively impacting **system availability**.

**Likelihood**: Low
**Impact**: Low
**Risk**: Low

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-01 | No passwords in authentication flow | Implemented |
| M-02 | Rate limiting on authentication endpoints | Planned |
| M-03 | Account lockout after failed PIN attempts (hardware authenticator enforced) | Implemented |

---

### T-02: Phishing for Credentials

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

### T-03: MFA Fatigue Attack

**Threat Statement**: A **sophisticated attacker** with **compromised primary credentials** can **bombard user with push notifications** which leads to **user approving malicious request**, negatively impacting **nothing (attack vector doesn't exist)**.

**Likelihood**: None
**Impact**: None
**Risk**: Not Applicable

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-07 | No push notifications in authentication flow | Implemented |
| M-08 | Physical touch required on hardware authenticator | Implemented |

---

### T-04: PIN Brute Force

**Threat Statement**: A **sophisticated attacker** with **physical access to a stolen hardware authenticator** can **attempt to brute force the PIN** which leads to **authenticator lockout after 8 attempts**, negatively impacting **authenticator availability (device unusable)**.

**Likelihood**: Low
**Impact**: Medium (locked device)
**Risk**: Low

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-09 | Hardware authenticator enforces 8-attempt lockout | Hardware |
| M-10 | Minimum 8-character PIN requirement | Implemented |
| M-11 | PIN never transmitted to server | Implemented |

---

### T-05: Stolen Authenticator with Known PIN

**Threat Statement**: A **sophisticated attacker** with **physical possession of a hardware authenticator AND knowledge of the PIN** can **authenticate as the legitimate user** which leads to **unauthorized session creation and credential issuance**, negatively impacting **confidentiality of protected resources**.

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
| M-16 | Recommend biometric authenticator (e.g., YubiKey Bio series) for high-security | Documentation |

---

## Session Management Threats

### T-06: Access Token Theft via Malware

**Threat Statement**: A **sophisticated attacker** with **malware on the user's workstation** can **read access tokens from memory or disk** which leads to **limited session hijacking (DPoP sender-constraint requires matching key)**, negatively impacting **confidentiality of issued credentials**.

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

### T-07: Session Fixation

**Threat Statement**: A **sophisticated attacker** with **ability to inject access tokens** can **force a user to use an attacker-known session** which leads to **no impact due to DPoP sender-constraint and hardware authentication binding**, negatively impacting **nothing (attack fails)**.

**Likelihood**: Low
**Impact**: None
**Risk**: Mitigated

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-22 | Sessions created only after FIDO2 assertion | Implemented |
| M-23 | Access tokens not predictable (ES256-signed JWTs) | Implemented |
| M-24 | Session bound to authenticator and user | Implemented |

---

### T-08: Replay Attack on Authentication

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

## Server-Side Threats

### T-09: Compromised Vouch Server

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

### T-10: SQL Injection

**Threat Statement**: A **sophisticated attacker** with **crafted malicious input** can **inject SQL commands** which leads to **no impact due to parameterized queries**, negatively impacting **nothing (attack fails)**.

**Likelihood**: Low
**Impact**: None
**Risk**: Mitigated

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-34 | All database queries use parameterized statements (sea_query builders) | Implemented |
| M-35 | SQLx runtime query execution with sea_query AST builders (no string concatenation) | Implemented |
| M-36 | Input validation on all API endpoints | Implemented |

---

### T-11: SCIM Token Compromise

**Threat Statement**: A **malicious insider or external attacker** with **a compromised SCIM bearer token** can **provision unauthorized users or prevent de-provisioning** which leads to **unauthorized access or persistence**, negatively impacting **authentication integrity**.

**Likelihood**: Low
**Impact**: High
**Risk**: Medium

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-37 | SCIM tokens hashed with SHA-256 (not stored plaintext) | Implemented |
| M-38 | Separate SCIM token per IdP integration | Implemented |
| M-39 | SCIM operations logged with source IdP info | Implemented |
| M-40 | Optional IP allowlist for SCIM endpoints | Implemented |
| M-41 | Token rotation capability | Implemented |

---

## Configuration Threats

### T-11a: S3 Configuration Bucket Compromise

**Threat Statement**: A **sophisticated attacker** with **compromised AWS credentials or S3 bucket access** can **modify the S3 configuration file** which leads to **potential credential theft via malicious OIDC config or TLS certificates**, negatively impacting **authentication integrity and confidentiality**.

**Likelihood**: Low
**Impact**: High
**Risk**: Medium

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-41a | Protected fields (jwt_secret, database_url) cannot be changed at runtime | Implemented |
| M-41b | S3 bucket encryption required (SSE-S3 or SSE-KMS) | Documentation |
| M-41c | IAM least-privilege (only GetObject, HeadObject) | Documentation |
| M-41d | S3 bucket versioning for rollback and audit | Documentation |
| M-41e | S3 access logging for unauthorized access detection | Documentation |
| M-41f | Block public access on S3 bucket | Documentation |
| M-41g | Configuration validation before applying changes | Implemented |

---

## Supply Chain Threats

### T-12: Compromised CLI Binary

**Threat Statement**: A **nation-state actor** with **access to the build or distribution pipeline** can **inject malicious code into the CLI binary** which leads to **credential exfiltration or authentication bypass**, negatively impacting **confidentiality of all user credentials**.

**Likelihood**: Low
**Impact**: Critical
**Risk**: Medium (reduced by implemented mitigations)

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-42 | Open source CLI for public auditing | Implemented |
| M-43 | Reproducible builds | Implemented |
| M-44 | Binary signing (macOS code signing + notarization) | Implemented |
| M-45 | SHA256 checksums with releases (SHA256SUMS.txt) | Implemented |
| M-46 | SBOM with each release (CycloneDX format) | Implemented |
| M-47 | SLSA build provenance attestations | Implemented |
| M-48a | Windows Authenticode signing | Planned |

---

### T-13: Dependency Vulnerability

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

## Credential Issuance Threats

### T-14: Unauthorized Credential Issuance

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

### T-15: Credential Scope Escalation

**Threat Statement**: A **sophisticated attacker** with **a valid but limited session** can **request credentials beyond their authorized scope** which leads to **no escalation due to server-enforced policies**, negatively impacting **nothing (attack fails)**.

**Likelihood**: Low
**Impact**: None
**Risk**: Mitigated

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-58 | SSH principals derived from verified email only | Implemented |
| M-59 | AWS roles require IAM trust policy | Implemented |
| M-60 | OAuth scopes validated against client registration | Implemented |

---

### T-15a: Token Misdirection (Confused Deputy)

**Threat Statement**: A **sophisticated attacker** with **a malicious resource server that receives a valid bearer token** can **replay the token at a different resource server** which leads to **no unauthorized access due to audience-restricted tokens**, negatively impacting **nothing (attack fails when resource indicators are used)**.

**Likelihood**: Medium (attempt)
**Impact**: None (when resource indicators are used)
**Risk**: Mitigated

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-60a | RFC 8707 resource indicators bind tokens to target resource server (`aud` claim) | Implemented |
| M-60b | Resource URIs must be pre-registered on the OAuth client | Implemented |
| M-60c | Single resource value per request prevents multi-audience tokens | Implemented |
| M-60d | Resource cannot be widened at token exchange time | Implemented |
| M-60e | `invalid_target` error for unregistered or malformed resource URIs | Implemented |

---

## FAPI 2.0 Client Threats

### T-15b: Compromised CLI ES256 Key

**Threat Statement**: A **sophisticated attacker** with **access to the user's workstation** can **steal the CLI ES256 key pair from `~/.vouch/client_key.json`** which leads to **ability to authenticate as the FAPI client but not obtain tokens without FIDO2 assertion**, negatively impacting **limited confidentiality (client identity only)**.

**Likelihood**: Low
**Impact**: Low (key alone cannot authenticate)
**Risk**: Low

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-60f | File permissions 0600 on `client_key.json` | Implemented |
| M-60g | Key is useless without FIDO2 assertion (cannot forge the FIDO2 grant) | Implemented |
| M-60h | DPoP binding prevents token use from different key | Implemented |
| M-60i | Re-registration with new key pair on compromise | Implemented |

---

### T-15c: RFC 7591 Registration Abuse

**Threat Statement**: A **script kiddie** with **network access to the server** can **flood `/oauth/register` with client registrations** which leads to **database pollution but no unauthorized access**, negatively impacting **system availability (storage)**.

**Likelihood**: Low
**Impact**: Low (no access tokens issued during registration)
**Risk**: Low

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-60j | Rate limiting on `/oauth/register` endpoint | Implemented |
| M-60k | client_id alone grants zero access — FIDO2 assertion required | Implemented |
| M-60l | Registration creates only a client record, no tokens issued | Implemented |

---

### T-15d: DPoP Proof Replay

**Threat Statement**: A **sophisticated attacker** with **captured network traffic** can **replay a DPoP proof to reuse a sender-constrained token** which leads to **no impact due to server-side replay protection**, negatively impacting **nothing (attack fails)**.

**Likelihood**: Low
**Impact**: None
**Risk**: Mitigated

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-60m | Server validates `jti` uniqueness (replay detection) | Implemented |
| M-60n | Server validates `iat` freshness (clock skew window) | Implemented |
| M-60o | `htu`/`htm` binding ensures proof is for specific endpoint and method | Implemented |
| M-60p | TLS 1.3 encryption of all traffic | Implemented |

---

## Network Threats

### T-16: Man-in-the-Middle Attack

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

### T-17: DNS Spoofing

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

## Enrollment Threats

### T-18: Enrollment Code Brute Force

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

### T-19: Device Code Interception

**Threat Statement**: A **sophisticated attacker** with **access to user's terminal output** can **see the device code and complete enrollment first** which leads to **no impact due to device code being useless without OIDC authentication**, negatively impacting **nothing (attack fails)**.

**Likelihood**: Low
**Impact**: None
**Risk**: Mitigated

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-73 | Device code alone cannot complete enrollment | Implemented |
| M-74 | OIDC authentication required in browser | Implemented |
| M-75 | WebAuthn registration required with physical hardware authenticator | Implemented |

---

## Key Management Threats

### T-20: Unauthorized Key Registration

**Threat Statement**: A **sophisticated attacker** with **no existing authentication** can **register a malicious hardware authenticator to a user account** which leads to **no success due to session requirement**, negatively impacting **nothing (attack fails)**.

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

### T-21: Key Removal by Attacker

**Threat Statement**: A **sophisticated attacker** with **a stolen access token and DPoP key** can **remove legitimate keys from an account** which leads to **denial of service for legitimate user**, negatively impacting **authentication availability**.

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

## Platform Passkey Bypass Threats

### T-22: Platform Passkey Enrollment Attempt

**Threat Statement**: A **sophisticated attacker** with **malware that can register platform passkeys** can **attempt to enroll syncable credentials** which leads to **no success due to authenticator attestation validation**, negatively impacting **nothing (attack fails)**.

**Likelihood**: Low
**Impact**: None
**Risk**: Mitigated

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-83 | `authenticatorAttachment: cross-platform` enforced | Implemented |
| M-84 | AAGUID map for device identification (display only) | Implemented |
| M-85 | Attestation format validation (reject `none`, TPM, AndroidKey, Apple; accept only `packed`, `fido-u2f`) | Implemented |
| M-86 | User verification (PIN) required for all authenticators | Implemented |

---

## Denial of Service Threats

### T-23: Authentication Endpoint DoS

**Threat Statement**: A **script kiddie** with **botnet or amplification techniques** can **flood authentication endpoints** which leads to **degraded service for legitimate users**, negatively impacting **authentication availability**.

**Likelihood**: Medium
**Impact**: Medium
**Risk**: Medium

**Mitigations**:
| ID | Mitigation | Status |
|----|------------|--------|
| M-87 | Rate limiting on authentication endpoints (`slow_down` for device polling; per-IP limits planned) | Partial |
| M-88 | DDoS protection via infrastructure (cloud provider) | Deployment |
| M-89 | Self-hosted option for critical environments | Implemented |
