# Summary

[Introduction](README.md)

---

# Server Deployment

- [Deployment Overview](deployment/overview.md)
- [Configuration Reference](deployment/configuration.md)
- [Database Setup](deployment/database.md)
- [TLS Configuration](deployment/tls.md)
- [Deployment Methods](deployment/methods.md)
  - [Systemd (Bare Metal)](deployment/systemd.md)
  - [Docker](deployment/docker.md)
  - [Kubernetes (Helm)](deployment/kubernetes.md)
- [Health Checks and Monitoring](deployment/monitoring.md)

---

# Identity Provider Setup

- [Identity Provider Overview](idp/overview.md)
- [Google Workspace](idp/google-workspace.md)

---

# Operations

- [Session Management](operations/sessions.md)
- [Key Management](operations/key-management.md)
- [SCIM Provisioning](operations/scim.md)
- [S3 Configuration Storage](operations/s3-configuration.md)
- [Backup and Recovery](operations/backup-recovery.md)
- [Software Updates](operations/updates.md)
- [Troubleshooting](operations/troubleshooting.md)

---

# OIDC Provider

- [OIDC Overview](oidc/overview.md)
- [Endpoints and Discovery](oidc/endpoints.md)
- [Grant Types](oidc/grant-types.md)
- [Token Format and Claims](oidc/tokens.md)
- [DPoP and FAPI 2.0](oidc/dpop-fapi.md)
- [Resource Indicators (RFC 8707)](oidc/resource-indicators.md)
- [JWT Bearer (RFC 7523)](oidc/jwt-bearer.md)

---

# Architecture

- [System Overview](architecture/overview.md)
- [Components](architecture/components.md)
- [Authentication Flows](architecture/auth-flows.md)
- [Data Model](architecture/data-model.md)
- [Agent IPC Protocol](architecture/agent-ipc.md)
- [Technology Stack](architecture/tech-stack.md)

---

# Security

- [Security Model](security/model.md)
- [Security Controls](security/controls.md)
- [Session and Credential Security](security/session-credential.md)
- [Hardening Guide](security/hardening.md)
- [Incident Response](security/incident-response.md)
- [Vulnerability Disclosure](security/vulnerability-disclosure.md)

---

# Threat Model

- [Overview and Scope](threat-model/overview.md)
- [Trust Boundaries and Assets](threat-model/trust-boundaries.md)
- [Threat Actors](threat-model/actors.md)
- [Threat Statements](threat-model/threats.md)
- [Mitigations Summary](threat-model/mitigations.md)

---

# Advanced Topics

- [Air-Gapped Deployment](advanced/airgap.md)
  - [Installation](advanced/airgap-installation.md)
  - [Key Ceremony](advanced/airgap-key-ceremony.md)
  - [YubiKey Provisioning](advanced/airgap-yubikey.md)
  - [Operations](advanced/airgap-operations.md)


---

# Reference

- [Environment Variables](reference/environment-variables.md)
- [S3 Configuration Schema](reference/s3-config-schema.md)
- [Compliance Mapping](reference/compliance.md)
