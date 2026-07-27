# Summary

[Introduction](README.md)

# Getting Started

- [Quick Start](getting-started/quickstart.md)
- [Deployment Overview](getting-started/overview.md)

# Installation

- [Systemd (RPM/DEB)](install/systemd.md)
- [Docker](install/docker.md)
- [Kubernetes (Helm)](install/kubernetes.md)

# Configuration

- [Configuration Sources](configuration/sources.md)
- [Database](configuration/database.md)
- [TLS, Ports, and mTLS](configuration/tls.md)
- [Behind a Reverse Proxy](configuration/reverse-proxy.md)
- [Identity Providers](idp/overview.md)
  - [Google Workspace (OIDC)](idp/google-workspace.md)
  - [Microsoft Entra ID (OIDC)](idp/entra-id.md)
  - [Generic OIDC Provider](idp/generic-oidc.md)
  - [SAML 2.0](idp/saml.md)
- [Signing Keys](configuration/keys.md)

# Administration

- [Organizations and Administrators](admin/organizations.md)
- [Posture Policies](admin/policies.md)
- [Email Domains](admin/domains.md)
- [SCIM Provisioning](admin/scim.md)
- [Audit Events](admin/audit.md)

# Operations

- [Monitoring and Metrics](operations/monitoring.md)
- [Security Hardening](operations/security-hardening.md)
- [Sessions and Tokens](operations/sessions.md)
- [Running Multiple Instances](operations/high-availability.md)
- [Backup and Recovery](operations/backup-recovery.md)
- [Software Updates](operations/updates.md)
- [Troubleshooting](operations/troubleshooting.md)
- [Security Incident Runbook](operations/incident-runbook.md)

# Advanced Topics

- [Air-Gapped Deployment](advanced/airgap.md)
  - [Installation](advanced/airgap-installation.md)
  - [Key Ceremony](advanced/airgap-key-ceremony.md)
  - [YubiKey Provisioning](advanced/airgap-yubikey.md)
  - [Operations](advanced/airgap-operations.md)

# Reference

- [Environment Variables](reference/environment-variables.md)
- [S3 Configuration Schema](reference/s3-config-schema.md)
- [Ports and Endpoints](reference/ports-and-endpoints.md)
