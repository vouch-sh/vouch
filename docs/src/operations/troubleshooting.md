# Troubleshooting

## Diagnostic Tool

Run the built-in diagnostic tool first:

```bash
vouch doctor
```

This checks YubiKey detection, network connectivity, agent status, and integration configurations.

## Common Issues

### YubiKey Not Detected

**Symptoms**: `vouch login` hangs or reports "No FIDO2 device found"

**Solutions**:
- Ensure the YubiKey is fully inserted
- Try a different USB port
- On Linux, check udev rules: `lsusb | grep Yubico`
- On macOS, check System Settings > Privacy & Security > Input Monitoring

### PIN Issues

**"PIN is blocked"**
- Too many wrong PIN attempts locks the FIDO2 application
- Reset with `ykman fido reset` (destructive — deletes all credentials)
- Re-enrollment required after reset

**"PIN too short"**
- Vouch requires minimum 8-character PIN
- Set a new PIN: the CLI guides you through this during enrollment

### Agent Not Running

**Symptoms**: `vouch status` fails with connection error

**Solutions**:
```bash
# Check if agent is running
pgrep vouch-agent

# Start manually
vouch-agent --verbose --foreground

# On Linux with systemd
systemctl --user status vouch-agent
systemctl --user restart vouch-agent

# Check socket exists
ls -la ~/.vouch/agent.sock
```

### Session Expired

**Symptoms**: Credential commands fail with "not authenticated" or "session expired"

**Solution**: Run `vouch login` again. Sessions are intentionally short-lived (8 hours).

### SSH Certificate Issues

**"Permission denied (publickey)"**

1. Check session: `vouch status`
2. Check SSH agent: `SSH_AUTH_SOCK=~/.vouch/ssh-agent.sock ssh-add -l`
3. Verify host trusts the CA: check `TrustedUserCAKeys` in `/etc/ssh/sshd_config`
4. Check certificate principals match: `ssh-keygen -L -f ~/.ssh/id_ed25519_vouch-cert.pub`

### AWS Credential Issues

**"Unable to assume role"**

1. Check session: `vouch status`
2. Verify IAM role trust policy includes your Vouch server as a trusted OIDC provider
3. Check the role ARN in `~/.aws/config`
4. Test directly: `vouch credential aws --role <role-arn>`

### Server Connection Issues

**"Connection refused" or timeouts**

1. Check server health: `curl -k https://auth.example.com/health`
2. Check DNS resolution: `dig auth.example.com`
3. Check TLS: `openssl s_client -connect auth.example.com:443`
4. Check firewall rules (port 443 must be accessible)

### Enrollment Fails

**Device code expires**
- Codes expire after 10 minutes
- Run `vouch enroll` again for a fresh code

**"Email domain not allowed"**
- Your email domain is not in the server's `VOUCH_ALLOWED_DOMAINS` list
- Contact your administrator

## Debug Logging

Enable verbose logging for troubleshooting:

```bash
# CLI
RUST_LOG=debug vouch login

# Agent
RUST_LOG=debug vouch-agent --verbose --foreground

# Server
RUST_LOG=debug vouch-server
```

For component-specific logging:

```bash
RUST_LOG=vouch_cli=debug,vouch_common=debug
```

## Getting Help

- [GitHub Issues](https://github.com/vouch-sh/vouch/issues) — Bug reports
- [GitHub Discussions](https://github.com/vouch-sh/vouch/discussions) — Questions
- [Security Issues](../security/vulnerability-disclosure.md) — Security vulnerabilities
