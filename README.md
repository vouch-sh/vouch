# Vouch

[![CI](https://github.com/vouch-sh/vouch/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/vouch-sh/vouch/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)](LICENSE-APACHE)
[![Rust](https://img.shields.io/badge/rust-1.94%2B-orange)](https://www.rust-lang.org)

**Prove you're here.**

[![OpenID Certified](https://openid.net/wordpress-content/uploads/2016/04/oid-l-certification-mark-l-rgb-150dpi-90mm-300x157.png)](https://openid.net/certification/)

Hardware-backed authentication that issues short-lived credentials only after a human touches a YubiKey. One touch, one PIN, one 8-hour session — then SSH, AWS, Kubernetes, and more just work.

```bash
$ vouch login
🔑 Touch your YubiKey...
Enter PIN: ****
✓ Authenticated as you@company.com
✓ Session valid for 8 hours

$ ssh prod.example.com                        # Just works
$ aws s3 ls                                   # Just works
$ kubectl get pods                            # Just works
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
│                   │  server  │          │ (ssh, aws, …)│           │
│                   │  (OIDC)  │          │              │           │
│                   └──────────┘          └──────────────┘           │
└────────────────────────────────────────────────────────────────────┘
```

1. **`vouch login`** — Touch YubiKey, enter PIN, get 8-hour session
2. **Vouch issues credentials** — SSH certificates, AWS STS tokens, Kubernetes tokens, and more
3. **Tools just work** — Standard credential helpers, no wrappers needed

## Key Features

### Mandatory Hardware Presence
Unlike optional MFA that can be bypassed, Vouch only issues credentials after FIDO2 verification. The credential itself carries proof of presence.

### Short-Lived Everything
- SSH certificates: 8 hours
- AWS credentials: 1 hour (auto-refresh within session)
- Kubernetes, Docker, RDS, Redshift, CodeArtifact, and more — see [Integrations](https://vouch.sh/docs/)

No more rotating keys. No more revoking access. Credentials simply expire.

### Zero-Friction Integration
Vouch configures standard credential providers:
- SSH: `IdentityAgent` pointing to vouch's signing agent
- AWS: `credential_process` in `~/.aws/config`
- Plus: Kubernetes, Docker, Git, Cargo, and more — see [Integrations](https://vouch.sh/docs/)

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
vouch setup ssh                                    # SSH certificates
vouch setup aws --role arn:aws:iam::ID:role/name   # AWS credential_process
vouch setup eks --cluster my-cluster               # kubectl for EKS via IAM
vouch setup k8s --cluster my-cluster --server URL  # kubectl via OIDC
vouch setup github --configure                     # Git credential helper for GitHub
vouch setup docker --configure ghcr.io             # Docker registry auth
# See all integrations: https://vouch.sh/docs/
```

### Daily Use
```bash
# Start your day
vouch login

# Everything just works for 8 hours
ssh prod-server
aws s3 ls
kubectl get pods
docker pull ghcr.io/your-org/image
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
- For SSH: CA public key distributed to target hosts
- For AWS: IAM role with OIDC federation configured
- For EKS: Cluster with Access Entries configured for IAM role
- For Kubernetes: API server with OIDC configured — see [Operator Guide](http://docs.vouch.sh)
- For GitHub: Organization admin connects the Vouch GitHub App

## Architecture

Vouch consists of:

| Component | Description |
|-----------|-------------|
| `vouch` CLI | User-facing commands, credential helpers |
| `vouch-agent` | Background daemon, session management |
| `vouch-common` | Shared types, FIDO2 helpers, API client |
| `vouch-server` | OIDC provider, certificate authority |
| `vouch-httpsig` | HTTP Message Signatures (RFC 9421) |
| `vouch-tests` | Integration and property-based tests |

All components are [Apache-2.0 OR MIT](LICENSE-APACHE) licensed.

## Security

Vouch is designed for high-security environments:

- **Memory-safe implementation** — Written in Rust
- **No credential storage** — Vouch never sees your private keys
- **Cryptographic presence attestation** — FIDO2 with user verification
- **Short-lived credentials** — Minimize blast radius of compromise
- **Audit trail** — Every credential issuance logged with attestation

See the [Security Model](https://vouch.sh/docs/security/) for our security philosophy and the [Threat Model](https://vouch.sh/docs/threat-model/) for STRIDE analysis.

## Documentation

- **User Guide:** [vouch.sh](https://vouch.sh) — Getting started, integrations, daily use
- **Operator Guide:** [docs.vouch.sh](http://docs.vouch.sh) — Server deployment, configuration, administration

Key sections:

- [Getting Started](https://vouch.sh/docs/getting-started/) — Installation and first enrollment
- [Integrations](https://vouch.sh/docs/ssh/) — SSH, AWS, EKS, Kubernetes, GitHub, Docker, and more
- [Server Deployment](http://docs.vouch.sh/deployment/overview/) — Deploy and configure the Vouch server
- [Architecture](https://vouch.sh/docs/architecture/) — System design and data flows
- [Security Model](https://vouch.sh/docs/security/) — Security controls and incident response
- [Threat Model](https://vouch.sh/docs/threat-model/) — STRIDE analysis and mitigations

```bash
# Build and serve docs locally
make docs-serve
```

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

We believe security tools should be auditable.

## License

- All crates: [Apache-2.0](LICENSE-APACHE) OR [MIT](LICENSE-MIT)
- Documentation: [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/)

---

**Vouch** — Prove you're here.

[Website](https://vouch.sh) · [Documentation](https://vouch.sh/docs) · [GitHub](https://github.com/vouch-sh/vouch)
