# Air-Gapped Deployment

This chapter covers deploying Vouch in environments with no internet connectivity, such as defense contractors, government agencies, financial services, and critical infrastructure.

> **Status: Planned** -- This document describes the air-gapped deployment architecture for Vouch. Server and CLI packages are available from [packages.vouch.sh](https://packages.vouch.sh), and the core components (SSH CA, FIDO2 authentication) exist today. However, air-gap-specific CLI commands (e.g., `vouch enroll --airgap`) and automation scripts are not yet implemented.

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
