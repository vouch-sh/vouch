# Compliance Mapping

This page maps Vouch features to common compliance frameworks. Vouch's hardware-backed authentication model satisfies many of the strictest access control requirements across multiple regulatory standards.

## NIST 800-53

| Control ID | Control Name | Vouch Implementation |
|------------|-------------|----------------------|
| IA-2 | Identification and Authentication | FIDO2 authentication with hardware-bound credentials |
| IA-2(1) | Multi-Factor Authentication to Privileged Accounts | Hardware FIDO2 key (something you have) + PIN (something you know) + physical touch (presence proof) |
| IA-2(2) | Multi-Factor Authentication to Non-Privileged Accounts | Same hardware MFA applied to all accounts; no weaker alternative |
| IA-2(6) | Access to Accounts — Separate Device | YubiKey is a separate hardware device from the workstation |
| IA-2(8) | Access to Accounts — Replay Resistant | FIDO2 challenge-response is inherently replay-resistant |
| IA-2(12) | Acceptance of PIV Credentials | FIDO2/WebAuthn hardware authenticators accepted |
| IA-5 | Authenticator Management | Short-lived credentials (8-hour SSH certificates, 1-hour AWS tokens); no long-lived secrets |
| IA-5(1) | Password-Based Authentication | YubiKey PIN verified on-device; never transmitted to server |
| IA-5(2) | Public Key-Based Authentication | Ed25519 SSH certificates issued by built-in CA; DPoP-bound OAuth tokens |
| IA-5(6) | Protection of Authenticators | Private keys are hardware-bound and non-extractable on YubiKey |
| AU-2 | Event Logging | All credential issuance and authentication events logged |
| AU-3 | Content of Audit Records | Audit records include user identity, timestamp, credential type, authenticator AAGUID, and IP address |
| AU-8 | Time Stamps | Certificate validity tied to server time; supports GPS/NTP in air-gapped environments |
| AU-9 | Protection of Audit Information | Audit logs stored in database with configurable retention periods |
| AC-2 | Account Management | User enrollment via verified identity (OIDC); key registration via CLI (`vouch register`); revocation via CLI (`vouch keys remove`) or admin API |
| AC-7 | Unsuccessful Logon Attempts | FIDO2 PIN retry limits enforced by YubiKey hardware (locks after 8 attempts) |
| AC-11 | Device Lock | Sessions expire after configurable duration (default 8 hours); re-authentication required |
| AC-12 | Session Termination | Explicit logout (`vouch logout`) and automatic session expiration |
| SC-12 | Cryptographic Key Establishment and Management | Ed25519 SSH CA key; ES256 OIDC signing key; support for HSM and split-custody key storage |
| SC-13 | Cryptographic Protection | FIDO2/CTAP2 with hardware-backed cryptography; TLS for transport; JWT signing for tokens; FIPS 140-3 validated cryptography (aws-lc-rs FIPS module embedded in server binaries on Linux; OS FIPS mode enabled in the attestable AMI) |
| SC-23 | Session Authenticity | DPoP (RFC 9449) sender-constrained tokens; FAPI 2.0 client authentication |

## SOC 2

| Trust Service Criteria | Requirement | Vouch Implementation |
|------------------------|-------------|----------------------|
| CC6.1 | Logical access security | Hardware FIDO2 authentication mandatory for all access; no password-only path |
| CC6.2 | Authentication mechanisms | Multi-factor: hardware key + PIN + physical presence |
| CC6.3 | Authorization and access management | Short-lived credentials scoped to specific services (SSH, AWS, GitHub); role-based AWS access via OIDC federation |
| CC6.6 | Restriction of system access | Credential expiration (8 hours) limits access window; no persistent credentials |
| CC6.7 | Management of credentials | Automated credential lifecycle for user credentials (SSH certificates, AWS tokens); per-org issuer signing keys rotated via admin UI |
| CC6.8 | Prevention of unauthorized access | Hardware-bound keys cannot be copied, phished, or replayed; DPoP prevents token theft |
| CC7.1 | Detection of unauthorized access | Authentication event logging; FIDO2 attestation recorded for each session |
| CC7.2 | Monitoring of system components | Audit trail of all credential issuance; configurable event retention |
| CC8.1 | Change management | Server configuration via environment variables or S3; TLS hot-reload for certificate rotation |

## FedRAMP

| Control Family | Control | Vouch Implementation |
|----------------|---------|----------------------|
| Identification and Authentication (IA) | IA-2(1), IA-2(2) | Hardware MFA required for all users; no option to bypass |
| Identification and Authentication (IA) | IA-2(6) | YubiKey is a physically separate authenticator device |
| Identification and Authentication (IA) | IA-2(8) | FIDO2 challenge-response protocol prevents replay attacks |
| Identification and Authentication (IA) | IA-5(2) | Public key authentication via Ed25519 SSH certificates and DPoP-bound tokens |
| Identification and Authentication (IA) | IA-5(6) | Hardware-bound, non-extractable private keys on YubiKey |
| Access Control (AC) | AC-2 | Centralized user enrollment and key management through Vouch server |
| Access Control (AC) | AC-7 | YubiKey enforces PIN lockout after consecutive failures |
| Access Control (AC) | AC-12 | Sessions auto-expire; explicit logout available |
| Audit and Accountability (AU) | AU-2, AU-3 | All authentication and credential issuance events logged with identity, timestamp, and method |
| Audit and Accountability (AU) | AU-8 | Time-bound certificates; NTP/GPS time sync supported for air-gapped deployments |
| System and Communications Protection (SC) | SC-12, SC-13 | Hardware-backed cryptography; Ed25519 CA; ES256 OIDC signing; TLS transport encryption; FIPS 140-3: aws-lc-rs FIPS module in server binaries, OS crypto-policy FIPS + kernel `fips=1` in the attestable AMI |
| System and Communications Protection (SC) | SC-23 | FAPI 2.0 with DPoP sender-constrained tokens; private_key_jwt client authentication |
| Configuration Management (CM) | CM-2 | Server configured via environment variables with S3 centralized config support |
| Contingency Planning (CP) | CP-9 | Database backup/restore procedures; CA key recovery with split custody |

## HIPAA

| HIPAA Section | Requirement | Vouch Implementation |
|---------------|-------------|----------------------|
| 164.312(a)(1) | Access Control — Unique User Identification | Each user enrolled with verified identity via OIDC; unique credentials per YubiKey |
| 164.312(a)(2)(i) | Unique User Identification | User email as principal in SSH certificates; `sub` claim in OIDC tokens |
| 164.312(a)(2)(iii) | Automatic Logoff | Sessions expire after configurable duration (default 8 hours) |
| 164.312(a)(2)(iv) | Encryption and Decryption | TLS for transport; hardware-backed cryptographic operations on YubiKey |
| 164.312(b) | Audit Controls | All authentication events logged; configurable retention (default 90 days, adjustable for compliance) |
| 164.312(c)(1) | Integrity Controls | FIDO2 attestation provides cryptographic proof of authenticator identity; signed SSH certificates and JWT tokens |
| 164.312(d) | Person or Entity Authentication | Hardware FIDO2 key + PIN + physical touch provides strong person authentication |
| 164.312(e)(1) | Transmission Security | TLS encryption for all server communication; DPoP prevents token interception |
| 164.312(e)(2)(ii) | Encryption | TLS 1.2+ enforced; base64-encoded PEM keys for configuration; `rustls` (no OpenSSL) |
| 164.308(a)(3)(ii)(A) | Workforce Clearance Procedure | Enrollment controlled by allowed email domains; administrative key revocation |
| 164.308(a)(4)(ii)(B) | Access Authorization | Role-based access via OIDC scopes and AWS IAM role federation |
| 164.308(a)(5)(ii)(C) | Log-in Monitoring | Authentication events include IP address, timestamp, authenticator AAGUID, and authentication method references (AMR) |
| 164.308(a)(5)(ii)(D) | Password Management | YubiKey PIN managed on-device; minimum 8 characters; lockout after failed attempts |
