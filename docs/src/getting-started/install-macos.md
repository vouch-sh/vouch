# macOS Installation

## Homebrew (Recommended)

```bash
brew install vouch-sh/tap/vouch
```

This installs both `vouch` (CLI) and `vouch-agent` (background daemon).

To update:

```bash
brew upgrade vouch
```

## Direct Download

Download the latest release from [GitHub Releases](https://github.com/vouch-sh/vouch/releases):

```bash
# Apple Silicon (M1/M2/M3/M4)
curl -LO https://github.com/vouch-sh/vouch/releases/latest/download/vouch-aarch64-apple-darwin.tar.gz

# Intel
curl -LO https://github.com/vouch-sh/vouch/releases/latest/download/vouch-x86_64-apple-darwin.tar.gz
```

Extract and install:

```bash
tar xzf vouch-*.tar.gz
sudo mv vouch /usr/local/bin/
sudo mv vouch-agent /usr/local/bin/
```

## MDM Deployment

For managed deployments via Jamf, Kandji, or other MDM tools, distribute the signed and notarized binaries from the release assets. The macOS binaries are:

- Code-signed with Apple Developer ID
- Notarized by Apple (no Gatekeeper warnings)
- Universal binaries available for both Intel and Apple Silicon

## Verify Installation

```bash
vouch --version
vouch doctor
```

## Agent Setup

The vouch-agent daemon starts automatically when needed. To run it manually in the foreground for debugging:

```bash
vouch-agent --verbose --foreground
```

## Next Steps

- [Your First Enrollment](first-enrollment.md) — Register your YubiKey
- [Quick Start](quick-start.md) — Configure integrations
