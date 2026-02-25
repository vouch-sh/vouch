# Security Model

This chapter describes Vouch's security philosophy, threat model summary, and the residual risks that have been analyzed and accepted.

## Security Philosophy

Vouch is designed around three core principles:

1. **Hardware-bound only** — Hardware FIDO2 authenticators required; no platform passkeys (Touch ID, Windows Hello)
2. **Minimize credential lifetime** — Short-lived credentials (8 hours max) limit blast radius of compromise
3. **Audit everything** — Every credential issuance is logged with provenance

**Policy**: This is non-negotiable. Platform passkeys can be synced, backed up, and extracted. Hardware-bound credentials cannot. This is Vouch's key differentiator.

## Threat Model

> For the comprehensive threat model with detailed threat statements, mitigations, and STRIDE analysis, see [Threat Model Overview](../threat-model/overview.md).

### What Vouch Protects Against

| Threat | Mitigation |
|--------|------------|
| **Credential theft** | Short-lived credentials expire before attackers can use them |
| **MFA fatigue attacks** | No push notifications; physical touch required |
| **Phishing** | Hardware authenticator origin binding prevents credential use on wrong domains |
| **Malware on workstation** | Private keys never leave the hardware authenticator |
| **Insider threats** | Audit trail with cryptographic attestation |
| **Credential stuffing** | No passwords to stuff |
| **Synced passkey extraction** | Hardware-bound only policy prevents syncable credentials; attestation format validation rejects software passkeys |

### What Vouch Does NOT Protect Against

| Threat | Why | Mitigation | Monitoring |
|--------|-----|------------|------------|
| **Physical authenticator theft + known PIN** | Attacker has both factors | Use biometric authenticator (e.g., YubiKey Bio series), rotate PIN | Audit logs, anomaly detection for unusual access patterns |
| **Compromised Vouch server** | Server issues credentials | Self-host for high-security, air-gapped deployment (planned) | Server integrity monitoring, audit log analysis |
| **Malware stealing session after login** | Access token in memory | 8-hour session lifetime, endpoint protection | EDR solutions, anomalous session usage patterns |
| **Supply chain attacks on CLI** | Compromised binary | Reproducible builds, code signing, open source auditing | Security researcher engagement, build provenance verification |

For detailed attacker profiles, trust boundaries, and security assumptions, see [Threat Actors](../threat-model/actors.md).

## Residual Risks

Despite comprehensive mitigations, the following residual risks remain and have been accepted:

### RR-01: Physical Authenticator Theft with PIN Knowledge

**Risk**: If an attacker obtains both physical possession of a hardware authenticator and knowledge of the PIN, they can authenticate as the user.

| Aspect | Detail |
|--------|--------|
| **Residual Impact** | Medium |
| **Acceptance Rationale** | This requires two independent factors to be compromised. The 8-hour session limit bounds the impact. Biometric authenticators (e.g., YubiKey Bio series) can eliminate the PIN knowledge factor. |
| **Monitoring** | Audit logs track all authentication events. Anomaly detection can flag unusual access patterns. |

### RR-02: Compromised Vouch Server

**Risk**: A sophisticated attacker with server access could potentially extract the SSH CA key or manipulate authentication logic.

| Aspect | Detail |
|--------|--------|
| **Residual Impact** | High |
| **Acceptance Rationale** | Self-hosted deployment shifts this risk to the organization. Air-gapped deployment (planned) provides additional protection. Audit logs provide detection capability. |
| **Monitoring** | Server integrity monitoring, audit log analysis, and anomaly detection. |

### RR-03: Access Token Theft via Advanced Malware

**Risk**: Sophisticated malware with root/admin access could potentially extract access tokens from memory despite protections. With FAPI 2.0, DPoP sender-constraint limits the impact — stolen tokens cannot be used without the corresponding DPoP key.

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
