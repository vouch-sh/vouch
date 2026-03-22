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

### Identity Provider Issues

**"Failed to fetch upstream OIDC discovery document"**

1. Verify `VOUCH_OIDC_ISSUER` is correct and reachable from the server: `curl -s $VOUCH_OIDC_ISSUER/.well-known/openid-configuration | jq .issuer`
2. Check that the issuer URL uses HTTPS (HTTP is only allowed for `localhost`)
3. Ensure the server can make outbound HTTPS requests (check firewall/proxy)

**"Issuer mismatch" during OIDC discovery**
- The `issuer` field in the discovery document must exactly match `VOUCH_OIDC_ISSUER` (trailing slashes matter)
- Some providers require a trailing slash (e.g., Auth0: `https://tenant.auth0.com/`)

**"Failed to fetch SAML IdP metadata"**
- Verify `VOUCH_SAML_IDP_METADATA_URL` is correct and reachable
- Check that the URL returns XML, not an HTML login page
- Ensure the server can make outbound HTTPS requests

**SAML signature verification errors**
- Confirm the IdP's signing certificate in the metadata is current and not expired
- Ensure the server clock is synchronized via NTP — SAML assertions have time-based validity windows (typically 5 minutes of skew tolerance)
- Check the IdP assertion signing algorithm matches what the server expects

**"Both OIDC and SAML are configured"**
- OIDC and SAML are mutually exclusive — remove either the `VOUCH_OIDC_*` or `VOUCH_SAML_*` variables
- In S3 config, remove either the `oidc` or `saml` block

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
