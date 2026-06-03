# Air-Gapped Deployment

This chapter covers deploying Vouch in environments with no internet connectivity, such as defense contractors, government agencies, financial services, and critical infrastructure.

> **Supported with operational constraints** — You can run `vouch-server` and the `vouch` CLI on an isolated network today using the same binaries and deployment paths as on-premise (systemd, Docker, or Kubernetes). This chapter documents that workflow. A few operator conveniences (listed under [Roadmap](#roadmap) below) are not built into the product yet.

## Supported today

| Capability | Where to read |
|------------|----------------|
| Server install (RPM/DEB, containers, Helm) | [Installation](airgap-installation.md), [Deployment Methods](../deployment/methods.md) |
| Configuration, TLS, database, SSH CA | [Configuration Reference](../deployment/configuration.md) |
| Internal OIDC or SAML IdP | [Identity Provider Overview](../idp/overview.md), [SAML 2.0](../idp/saml.md) |
| Enrollment (YubiKey + browser on internal network) | [Installation](airgap-installation.md), [YubiKey Provisioning](airgap-yubikey.md) |
| Key ceremony on a trusted workstation | [Key Ceremony](airgap-key-ceremony.md) |
| Day-two ops (time sync, updates, audit export scripts) | [Operations](airgap-operations.md) |
| Packages via sneakernet | [packages.vouch.sh](https://packages.vouch.sh) (download on a connected machine, transfer in) |

Enrollment uses the standard `vouch enroll` device flow (browser opens the verification URL on your internal Vouch host) or browser-only `/enroll/start` on the server UI. There is no separate air-gap-only CLI mode.

For general on-prem deployment (reachable IdP, standard updates), start with [Deployment Overview](../deployment/overview.md).

## Roadmap

These items are **not** available in the product today; the chapters above describe manual procedures instead:

- **Server syslog / SIEM streaming** — use periodic database export in [Operations](airgap-operations.md#audit-log-export) until built-in export exists
- **Headless enrollment** — enrollment without any browser on the internal network

## Overview

In an air-gapped environment:
- No SaaS services available
- Updates delivered via sneakernet
- Internal identity provider (no Google Workspace)
- Time sync from isolated NTP or GPS

Vouch's built-in SSH CA and local-first architecture make it well-suited for these constraints.

## Architecture

```
+--------------------------------------------------------------------------+
|                          AIR-GAPPED ENCLAVE                              |
|                                                                          |
|  +--------------------------------------------------------------------+  |
|  |                     On-Premises Vouch Stack                        |  |
|  |                                                                    |  |
|  |  +--------------+  +----------------+  +-----------------------+   |  |
|  |  |   Vouch      |  |   Built-in     |  |       SQLite          |   |  |
|  |  |   Server     |  |   SSH CA       |  |                       |   |  |
|  |  |              |  |                |  |  * Users & credentials |   |  |
|  |  |  * WebAuthn  |  |  * Ed25519 CA  |  |  * Sessions           |   |  |
|  |  |  * OIDC      |  |  * SSH certs   |  |  * Audit logs         |   |  |
|  |  |  * Sessions  |  |  * 8hr TTL     |  |                       |   |  |
|  |  +--------------+  +----------------+  +-----------------------+   |  |
|  |         |                  |                      |                |  |
|  |         +------------------+----------------------+                |  |
|  |                            |                                       |  |
|  +----------------------------+---------------------------------------+  |
|                               |                                          |
|                               | Internal Network Only                    |
|                               v                                          |
|  +--------------------------------------------------------------------+  |
|  |                        Workstations                                |  |
|  |                                                                    |  |
|  |  +--------------+  +--------------+  +-------------------------+   |  |
|  |  | Workstation  |  | Workstation  |  |   Protected Resources   |   |  |
|  |  |              |  |              |  |                         |   |  |
|  |  | * vouch CLI  |  | * vouch CLI  |  |  * SSH servers          |   |  |
|  |  | * YubiKey    |  | * YubiKey    |  |  * Internal apps        |   |  |
|  |  | * Certs      |  | * Certs      |  |  * Databases            |   |  |
|  |  +--------------+  +--------------+  +-------------------------+   |  |
|  |                                                                    |  |
|  +--------------------------------------------------------------------+  |
|                                                                          |
|  +--------------------------------------------------------------------+  |
|  |                       Time Infrastructure                          |  |
|  |  +------------+     +-----------------+                            |  |
|  |  | GPS Time   |---->|  Internal NTP   |----> All hosts             |  |
|  |  | Receiver   |     |  (stratum 1)    |                            |  |
|  |  +------------+     +-----------------+                            |  |
|  +--------------------------------------------------------------------+  |
+--------------------------------------------------------------------------+
                                    |
                                    | Air Gap (sneakernet)
                                    v
+--------------------------------------------------------------------------+
|                         CONNECTED ENVIRONMENT                            |
|                                                                          |
|  * Signed software packages (from packages.vouch.sh)                     |
|  * CA certificate updates                                                |
|  * (Optional) Audit log export                                           |
+--------------------------------------------------------------------------+
```

## Identity Provider Considerations

In an air-gapped environment, you cannot use external identity providers like Google Workspace for enrollment. Vouch Server requires at least one upstream IdP to verify user identity, so an air-gapped deployment must include a self-hosted IdP inside the enclave:

- **Self-hosted OIDC provider** — Deploy an internal OIDC-compliant IdP inside the enclave (e.g., Keycloak, Dex, or Microsoft AD FS). Add it to Vouch Server's `VOUCH_IDPS` list with `VOUCH_IDP_<SLUG>_TYPE=oidc` plus the `_ISSUER`, `_CLIENT_ID`, and `_CLIENT_SECRET` variables pointing to the internal IdP.
- **Self-hosted SAML provider** — Deploy an internal SAML IdP (e.g., Shibboleth, AD FS) and configure it with `VOUCH_IDP_<SLUG>_TYPE=saml` plus `VOUCH_IDP_<SLUG>_METADATA_URL` pointing to the internal metadata document.

## Prerequisites

### Hardware
- Servers for Vouch stack (VMs or bare metal)
- YubiKey 5 series for each user (firmware 5.2+)
- GPS receiver for time sync (recommended)
- USB drives for sneakernet transfers

### Software (Pre-downloaded)
- Vouch Server packages (RPM/DEB from [packages.vouch.sh](https://packages.vouch.sh))
- vouch CLI packages (RPM/DEB from [packages.vouch.sh](https://packages.vouch.sh))
- Container images and/or Helm charts (for Kubernetes deployments)
