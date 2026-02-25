# Requirements

## Hardware

- **YubiKey 5 series** (firmware 5.2+) with FIDO2/WebAuthn support
  - YubiKey 5 NFC, YubiKey 5C, YubiKey 5C NFC, YubiKey 5Ci, or YubiKey 5 Nano variants
  - YubiKey Bio series also supported (adds fingerprint verification)
  - Other hardware FIDO2 authenticators may work but are not officially tested

> **Recommendation**: Each user should have at least two YubiKeys — a primary and a backup. Register both during enrollment to avoid lockout if one is lost.

## Software

| Platform | Minimum Version | Notes |
|----------|----------------|-------|
| **macOS** | 12 (Monterey)+ | Intel and Apple Silicon |
| **Linux** | glibc 2.31+ | x86_64 and aarch64 |
| **Windows** | — | Planned, not yet supported |

## Server-Side Prerequisites

Depending on which integrations you plan to use:

| Integration | Prerequisite |
|-------------|-------------|
| **SSH** | CA public key distributed to target hosts (`TrustedUserCAKeys`) |
| **AWS** | IAM role with OIDC federation trust policy pointing to your Vouch server |
| **EKS** | Cluster with Access Entries configured for the IAM role |
| **GitHub** | Organization admin installs the Vouch GitHub App |
| **Docker/ECR** | IAM role with ECR permissions |
| **CodeArtifact** | IAM role with CodeArtifact permissions |
| **CodeCommit** | IAM role with CodeCommit permissions |

## Network

- HTTPS access to the Vouch server from user workstations
- USB connectivity for YubiKey (USB-A, USB-C, or Lightning depending on model)
- Browser access for initial enrollment (one-time)

## Diagnostics

Run the built-in diagnostic tool to verify your setup:

```bash
vouch doctor
```

This checks:
- YubiKey detection and firmware version
- FIDO2 functionality
- Network connectivity to Vouch server
- Agent daemon status
- Integration configurations
