# Linux Installation

## APT (Debian/Ubuntu)

```bash
# Add the Vouch repository
# See https://packages.vouch.sh for full instructions
sudo apt install vouch
```

This installs both `vouch` (CLI) and `vouch-agent` (background daemon), and configures a systemd user service for the agent.

To update:

```bash
sudo apt update && sudo apt upgrade vouch
```

## DNF/YUM (Fedora/RHEL/Amazon Linux)

```bash
# Add the Vouch repository
# See https://packages.vouch.sh for full instructions
sudo dnf install vouch
```

To update:

```bash
sudo dnf upgrade vouch
```

## Direct Download

Download the latest release from [GitHub Releases](https://github.com/vouch-sh/vouch/releases):

```bash
# x86_64
curl -LO https://github.com/vouch-sh/vouch/releases/latest/download/vouch-x86_64-unknown-linux-gnu.tar.gz

# aarch64
curl -LO https://github.com/vouch-sh/vouch/releases/latest/download/vouch-aarch64-unknown-linux-gnu.tar.gz
```

Verify and install:

```bash
# Verify checksum
curl -LO https://github.com/vouch-sh/vouch/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing

# Extract and install
tar xzf vouch-*.tar.gz
sudo mv vouch /usr/local/bin/
sudo mv vouch-agent /usr/local/bin/
```

## Agent Setup

If installed via packages, the agent is configured as a systemd user service. Enable and start it:

```bash
systemctl --user enable vouch-agent
systemctl --user start vouch-agent
```

Check agent status:

```bash
systemctl --user status vouch-agent
```

## Verify Installation

```bash
vouch --version
vouch doctor
```

## Next Steps

- [Your First Enrollment](first-enrollment.md) — Register your YubiKey
- [Quick Start](quick-start.md) — Configure integrations
