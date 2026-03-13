# Troubleshooting

## Common Issues

### Server Connection Issues

**"Connection refused" or timeouts**

1. Check server health: `curl -k https://auth.example.com/health`
2. Check DNS resolution: `dig auth.example.com`
3. Check TLS: `openssl s_client -connect auth.example.com:443`
4. Check firewall rules (port 443 must be accessible)

### SCIM Provisioning Issues

**User not de-provisioned**
- Verify the SCIM bearer token is valid and not expired
- Check the SCIM audit log for errors
- Confirm the IdP is sending DELETE requests to the correct endpoint

**SCIM token rejected**
- Tokens are shown once at creation and cannot be retrieved after
- Generate a new token via the admin API (`POST /api/v1/org/scim-tokens`) and update the IdP configuration

## Debug Logging

Enable verbose logging for troubleshooting:

```bash
# Server
RUST_LOG=debug vouch-server
```

For component-specific logging:

```bash
RUST_LOG=vouch_server=debug
```

## Getting Help

- [GitHub Issues](https://github.com/vouch-sh/vouch/issues) — Bug reports
- [GitHub Discussions](https://github.com/vouch-sh/vouch/discussions) — Questions
- [Security Issues](https://vouch.sh/docs/) — Security vulnerabilities
