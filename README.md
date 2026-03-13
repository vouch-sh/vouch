# Vouch

[![CI](https://github.com/vouch-sh/vouch/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/vouch-sh/vouch/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)](LICENSE-APACHE)
[![Rust](https://img.shields.io/badge/rust-1.94%2B-orange)](https://www.rust-lang.org)

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
│  ┌──────────┐     ┌──────────┐     ┌──────────────────────────┐    │
│  │ YubiKey  │────▶│  vouch   │────▶│ Short-lived credentials  │    │
│  │ (touch)  │     │  login   │     │ managed by vouch agent   │    │
│  └──────────┘     └──────────┘     └──────────────────────────┘    │
│                         │                      │                   │
│                         ▼                      ▼                   │
│                   ┌──────────┐          ┌──────────────┐           │
│                   │  vouch   │          │ Native tools │           │
│                   │  server  │          │ (ssh, aws)   │           │
│                   │  (OIDC)  │          │              │           │
│                   └──────────┘          └──────────────┘           │
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

## Quick Start

### Install
```bash
# macOS
brew install vouch-sh/tap/vouch

# Linux (Debian/Ubuntu)
# See https://packages.vouch.sh for repository setup
sudo apt install vouch

# Linux (RPM-based)
# See https://packages.vouch.sh for repository setup
sudo dnf install vouch

# From source (requires Rust 1.94+)
cargo install --git https://github.com/vouch-sh/vouch vouch-cli
```

### Setup
```bash
# Enroll with your YubiKey (one-time, opens browser)
vouch enroll

# Configure integrations
vouch setup ssh                                    # Configures SSH to use vouch certificates
vouch setup aws --role arn:aws:iam::ID:role/name   # Configures AWS credential_process
vouch setup eks --cluster my-cluster                # Configures kubectl for EKS via IAM
vouch setup github --configure                     # Configures git credential helper for GitHub
```

### Daily Use
```bash
# Start your day
vouch login

# Everything just works for 8 hours
ssh prod-server
aws s3 ls
git clone https://github.com/your-org/private-repo.git

# Check session status
vouch status
```

### Shell Completions
```bash
# Bash
vouch completions bash >> ~/.bashrc

# Zsh
vouch completions zsh > "${fpath[1]}/_vouch"

# Fish
vouch completions fish > ~/.config/fish/completions/vouch.fish
```

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
| `vouch` CLI | User-facing commands, credential helpers | Open source ([Apache-2.0 OR MIT](LICENSE-APACHE)) |
| `vouch-agent` | Background daemon, session management | Open source ([Apache-2.0 OR MIT](LICENSE-APACHE)) |
| `vouch-common` | Shared types, FIDO2 helpers, API client | Open source ([Apache-2.0 OR MIT](LICENSE-APACHE)) |
| Vouch Server | OIDC provider, certificate authority | [BSL 1.1](crates/vouch-server/LICENSE) (converts to Apache-2.0) |

The CLI is fully open source for security auditing. The server source is available under the Business Source License 1.1, which converts to Apache-2.0 after two years.

## Security

Vouch is designed for high-security environments:

- **Memory-safe implementation** — Written in Rust
- **No credential storage** — Vouch never sees your private keys
- **Cryptographic presence attestation** — FIDO2 with user verification
- **Short-lived credentials** — Minimize blast radius of compromise
- **Audit trail** — Every credential issuance logged with attestation

See the [Security Model](https://vouch.sh/docs/security/) for our security philosophy and the [Threat Model](https://vouch.sh/docs/threat-model/) for STRIDE analysis.

## Documentation

Full documentation is available as an [mdBook](https://rust-lang.github.io/mdBook/):

```bash
# Build and serve locally
make docs-serve
```

Key sections:

- [Getting Started](https://vouch.sh/docs/getting-started/) — Installation and first enrollment
- [Server Deployment](docs/src/deployment/overview.md) — Deploy and configure the Vouch server
- [Integrations](https://vouch.sh/docs/ssh/) — SSH, AWS, EKS, GitHub, Docker, and more
- [Architecture](https://vouch.sh/docs/architecture/) — System design and data flows
- [Security Model](https://vouch.sh/docs/security/) — Security controls and incident response
- [Threat Model](https://vouch.sh/docs/threat-model/) — STRIDE analysis and mitigations
- [Air-Gapped Deployment](docs/src/advanced/airgap.md) — On-premises installation guide

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

The CLI is open source under Apache-2.0 OR MIT. We believe security tools should be auditable.

## License

- CLI, agent, and shared libraries: [Apache-2.0](LICENSE-APACHE) OR [MIT](LICENSE-MIT)
- Server: [BSL 1.1](crates/vouch-server/LICENSE) (converts to Apache-2.0 after 2 years)
- Documentation: [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/)

---

**Vouch** — Prove you're here.

[Website](https://vouch.sh) · [Documentation](https://vouch.sh/docs) · [GitHub](https://github.com/vouch-sh/vouch)
