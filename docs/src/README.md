# Vouch Server Operator Guide

This documentation covers deploying, configuring, and operating **Vouch Server** — the authentication server that issues short-lived credentials after FIDO2 verification with a YubiKey.

For CLI installation, enrollment, and integration guides (SSH, AWS, EKS, GitHub, Docker), visit [vouch.sh](https://vouch.sh).

## What Vouch Server Does

Vouch Server is the backend that makes hardware-backed authentication work:

- **OIDC Provider** — Issues DPoP-bound access tokens after FIDO2 verification
- **SSH Certificate Authority** — Signs short-lived Ed25519 certificates
- **Credential Broker** — Exchanges access tokens for AWS STS credentials
- **SCIM Endpoint** — Receives user provisioning/de-provisioning from your IdP
- **WebAuthn Relying Party** — Manages FIDO2 credential registration and assertion

## Architecture

| Component | Description | License |
|-----------|-------------|---------|
| `vouch` CLI | User-facing commands, credential helpers | Apache-2.0 OR MIT |
| `vouch-agent` | Background daemon, session management | Apache-2.0 OR MIT |
| `vouch-common` | Shared types, FIDO2 helpers, API client | Apache-2.0 OR MIT |
| Vouch Server | OIDC provider, certificate authority | BSL 1.1 (converts to Apache-2.0) |

## Security

Vouch is designed for high-security environments:

- **Memory-safe implementation** — Written in Rust
- **No credential storage** — Vouch never sees your private keys
- **Cryptographic presence attestation** — FIDO2 with user verification
- **Short-lived credentials** — Minimize blast radius of compromise
- **Audit trail** — Every credential issuance logged with attestation

See [Security Model](security/model.md) for the full security model and [Threat Model](threat-model/overview.md) for the threat analysis.

---

Get started with the [Deployment Overview](deployment/overview.md).
