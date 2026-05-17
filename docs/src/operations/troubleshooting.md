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

1. Verify the configured `VOUCH_IDP_<SLUG>_ISSUER` is correct and reachable: `curl -s $VOUCH_IDP_<SLUG>_ISSUER/.well-known/openid-configuration | jq .issuer`
2. Check that the issuer URL uses HTTPS (HTTP is only allowed for `localhost`)
3. Ensure the server can make outbound HTTPS requests (check firewall/proxy)

**"Issuer mismatch" during OIDC discovery**
- The `issuer` field in the discovery document must exactly match `VOUCH_IDP_<SLUG>_ISSUER` (trailing slashes matter)
- Some providers require a trailing slash (e.g., Auth0: `https://tenant.auth0.com/`)
- Entra `/organizations/v2.0` and `/common/v2.0` are special-cased automatically — the per-tenant template issuer is accepted

**"Failed to fetch SAML IdP metadata"**
- Verify the configured `VOUCH_IDP_<SLUG>_METADATA_URL` is correct and reachable
- Check that the URL returns XML, not an HTML login page
- Ensure the server can make outbound HTTPS requests

**SAML signature verification errors**
- Confirm the IdP's signing certificate in the metadata is current and not expired
- Ensure the server clock is synchronized via NTP — SAML assertions have time-based validity windows (typically 5 minutes of skew tolerance)
- Check the IdP assertion signing algorithm matches what the server expects

**"Legacy identity-provider configuration detected"**
- The flat `VOUCH_OIDC_*` and `VOUCH_SAML_*` variables (and the legacy S3 `oidc` / `saml` blocks) are no longer supported. The startup error lists which variables to rename. See [IdP Overview](../idp/overview.md#migration-from-legacy-variables) for the full mapping.

**"Duplicate IdP slug"**
- Every entry in `VOUCH_IDPS` / `idps[].id` must be unique. Rename one of them.

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
