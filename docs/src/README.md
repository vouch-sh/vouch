# Vouch Server Operator Guide

This is the handbook for **running your own Vouch server**. It covers installing the server,
configuring it, connecting it to your identity provider, administering your organization, and
operating it in production — across cloud, on-premise, and air-gapped deployments.

## What this guide is not

Vouch is three separate things, and only one of them is documented here.

| | What it is | Where it's documented |
|---|---|---|
| **This guide** (`docs.vouch.sh`) | The server you install and run yourself: deployment, configuration, administration, operations. | You are here |
| **Vouch CLI and integrations** (`vouch.sh/docs`) | Installing the `vouch` CLI, enrolling a hardware key, and the credential helpers — SSH, AWS, EKS, Kubernetes, GitHub, Docker and the rest. Also the OIDC provider reference: endpoints, tokens, grant types, claims. | [vouch.sh/docs](https://vouch.sh/docs/) |
| **The hosted Vouch service** (`us.vouch.sh`) | A managed multi-tenant deployment operated by Vouch. You do not install or operate it. | [vouch.sh](https://vouch.sh) |

If you are looking for how to run `vouch enroll`, wire up `credential_process` for the AWS CLI, or
configure `kubectl` — those are client-side tasks documented at
[vouch.sh/docs](https://vouch.sh/docs/), not here.

If you are evaluating the hosted service rather than self-hosting, most of this guide will not
apply. Capabilities that exist only on the hosted service — per-organization issuer subdomains,
for example — are noted where they intersect with something you can configure, but are not
documented in depth.

## What Vouch Server does

Vouch Server is the backend that makes hardware-backed authentication work. The core principle is
that no credential is issued without proof of human presence at a hardware authenticator.

- **OIDC Provider** — issues DPoP-bound access tokens after FIDO2 verification
- **SSH Certificate Authority** — signs short-lived Ed25519 certificates
- **Credential Broker** — exchanges access tokens for AWS STS credentials and GitHub tokens
- **SCIM Endpoint** — receives user provisioning and de-provisioning from your IdP
- **WebAuthn Relying Party** — manages FIDO2 credential registration and assertion

It sits *behind* the identity provider you already run rather than replacing it. Users prove who
they are to Google Workspace, Entra ID, Okta, or any OIDC/SAML provider; Vouch binds that verified
identity to a hardware key and issues short-lived credentials from it.

## What you will need

At minimum, to get a server running:

- A domain name, and a TLS certificate for it
- A database — SQLite for a single node, PostgreSQL for more than one
- At least one upstream identity provider; **the server refuses to start without one**
- A JWT secret of at least 32 characters, or an AWS KMS HMAC key

## Where to start

- **New to Vouch Server** — [Quick Start](getting-started/quickstart.md) takes you from nothing to
  a working enrollment.
- **Planning a production deployment** — [Deployment Overview](getting-started/overview.md) for
  sizing and architecture, then [Configuration Sources](configuration/sources.md).
- **Already running, something is wrong** — [Troubleshooting](operations/troubleshooting.md).

## Getting help

- [GitHub Issues](https://github.com/vouch-sh/vouch/issues) — bug reports
- [GitHub Discussions](https://github.com/vouch-sh/vouch/discussions) — questions
