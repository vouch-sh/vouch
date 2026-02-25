# Hardening Guide

This guide provides recommended security hardening steps for the Vouch CLI, hardware authenticators, and host SSH configuration.

## CLI Security

```bash
# Verify binary integrity before first use
sha256sum /usr/local/bin/vouch
# Compare with published checksum

# Use secure file permissions
chmod 700 ~/.vouch
chmod 600 ~/.vouch/config.json

# Verify YubiKey is genuine
ykman fido info
```

## Authenticator Configuration

Vouch requires a minimum 8-character PIN. If your hardware authenticator doesn't have a PIN configured,
`vouch login` or `vouch register` will guide you through setting one up.

```bash
# Change an existing PIN
ykman fido access change-pin

# Enable PIN complexity (if supported)
ykman fido access pin-complexity enable

# View registered credentials
ykman fido credentials list
```

## Host SSH Configuration

```bash
# /etc/ssh/sshd_config

# Trust Vouch CA for user certificates
TrustedUserCAKeys /etc/ssh/vouch-ca.pub

# Optionally restrict to specific principals
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```
