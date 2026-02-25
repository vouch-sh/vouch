# Introduction

**Prove you're here.**

Hardware-backed authentication that issues short-lived credentials only after a human touches a YubiKey. One touch, one PIN, one 8-hour session — then SSH and AWS just work.

```bash
$ vouch login
🔑 Touch your YubiKey...
Enter PIN: ****
✓ Authenticated as you@company.com
✓ Session valid for 8 hours

$ ssh prod.example.com                        # Just works
$ aws s3 ls                                   # Just works
$ git push origin main                        # Just works
```

## The Problem

Modern authentication is broken in three ways:

1. **Push notification fatigue** — Duo pings you 47 times a day. Users approve reflexively. MFA fatigue attacks succeed because humans are tired.

2. **Credential sprawl** — Long-lived API keys in `~/.aws/credentials`. GitHub PATs that never expire. SSH keys from 2019 still floating around.

3. **No presence verification** — Existing tools verify *devices* or *sessions*, but not that a *human* is actually there. A compromised laptop with cached credentials is indistinguishable from its owner.

## The Solution

Vouch requires **physical presence** for every credential issuance:

| Traditional Auth | Vouch |
|------------------|-------|
| Password + SMS/Push | YubiKey touch + PIN |
| Long-lived API keys | 8-hour certificates |
| "Remember this device" | Per-session attestation |
| Optional hardware MFA | **Mandatory** hardware MFA |
| Device trust | Human presence proof |

### How It Works

```
┌────────────────────────────────────────────────────────────────────┐
│                           Your Machine                             │
│                                                                    │
│  ┌──────────┐     ┌──────────┐     ┌──────────────────────────┐   │
│  │ YubiKey  │────▶│  vouch   │────▶│ Short-lived credentials  │   │
│  │ (touch)  │     │  login   │     │ managed by vouch agent   │   │
│  └──────────┘     └──────────┘     └──────────────────────────┘   │
│                         │                      │                   │
│                         ▼                      ▼                   │
│                   ┌──────────┐          ┌──────────────┐          │
│                   │  vouch   │          │ Native tools │          │
│                   │  server  │          │ (ssh, aws)   │          │
│                   │  (OIDC)  │          │              │          │
│                   └──────────┘          └──────────────┘          │
└────────────────────────────────────────────────────────────────────┘
```

1. **`vouch login`** — Touch YubiKey, enter PIN, get 8-hour session
2. **Vouch issues credentials** — SSH certificates, AWS STS tokens
3. **Tools just work** — Standard credential helpers, no wrappers needed

## Key Features

### Mandatory Hardware Presence
Unlike optional MFA that can be bypassed, Vouch only issues credentials after FIDO2 verification. The credential itself carries proof of presence.

### Short-Lived Everything
- SSH certificates: 8 hours
- AWS credentials: 1 hour (auto-refresh within session)

No more rotating keys. No more revoking access. Credentials simply expire.

### Zero-Friction Integration
Vouch configures standard credential providers:
- SSH: `IdentityAgent` pointing to vouch's signing agent
- AWS: `credential_process` in `~/.aws/config`

After `vouch login`, existing workflows are unchanged.

## Requirements

- **YubiKey 5 series** (firmware 5.2+) with FIDO2/WebAuthn support
- **macOS** 12+ or **Linux** (glibc 2.31+) — Windows support is planned
- For AWS: IAM role with OIDC federation configured
- For EKS: Cluster with Access Entries configured for IAM role
- For SSH: CA public key distributed to target hosts
- For GitHub: Organization admin connects the Vouch GitHub App

## Architecture

Vouch consists of:

| Component | Description | Source |
|-----------|-------------|--------|
| `vouch` CLI | User-facing commands, credential helpers | Open source (Apache-2.0 OR MIT) |
| `vouch-agent` | Background daemon, session management | Open source (Apache-2.0 OR MIT) |
| `vouch-common` | Shared types, FIDO2 helpers, API client | Open source (Apache-2.0 OR MIT) |
| Vouch Server | OIDC provider, certificate authority | BSL 1.1 (converts to Apache-2.0) |

The CLI is fully open source for security auditing. The server source is available under the Business Source License 1.1, which converts to Apache-2.0 after two years.

## Security

Vouch is designed for high-security environments:

- **Memory-safe implementation** — Written in Rust
- **No credential storage** — Vouch never sees your private keys
- **Cryptographic presence attestation** — FIDO2 with user verification
- **Short-lived credentials** — Minimize blast radius of compromise
- **Audit trail** — Every credential issuance logged with attestation

See [Security Model](security/model.md) for our security model and responsible disclosure policy. For the threat model, see [Threat Model](threat-model/overview.md).

---

See the [Quick Start](getting-started/quick-start.md) to get started.
