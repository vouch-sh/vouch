# Troubleshooting

## The server won't start

Vouch fails fast: rather than starting in a half-configured state, it validates everything at boot
and exits with a message naming the problem. Read the last line of output — it is almost always
specific enough to act on.

The full list of fatal conditions is in
[Startup Validation](../reference/environment-variables.md#startup-validation). The ones that come
up most:

**`No upstream IdP configured. Set VOUCH_IDPS=<slug>[,<slug>...]`**
At least one identity provider is mandatory. Set `VOUCH_IDPS` plus that slug's
`VOUCH_IDP_<SLUG>_*` variables. Remember that hyphens in a slug become underscores in the variable
names: `corp-saml` → `VOUCH_IDP_CORP_SAML_*`.

**`Failed to configure IdP '<id>'`**
Discovery or metadata could not be fetched at startup. Check that the issuer or metadata URL is
reachable *from the server* and returns what it should:

```bash
curl -s "$VOUCH_IDP_GOOGLE_ISSUER/.well-known/openid-configuration" | jq .issuer
```

If the IdP uses an internal certificate authority, set `VOUCH_EXTRA_CA_CERTS` to a PEM bundle
containing it. If the discovery document's `issuer` field differs from what you configured — even
by a trailing slash — they must be made to match.

**`VOUCH_JWT_SECRET must be at least 32 characters`**
Generate one with `openssl rand -base64 48`. A secret made of one repeated character is also
rejected, and one with fewer than 8 distinct bytes logs a warning.

**`Partial TLS configuration: set both VOUCH_TLS_CERT and VOUCH_TLS_KEY ... or neither.`**
Both or neither. Setting only one is always a mistake, so it is refused rather than silently
serving plaintext.

**`Duplicate IdP slug '<id>'`**
Two entries in `VOUCH_IDPS` (or `idps[].id` in S3) share a slug. Rename one.

**Wildcard CORS rejected**
`VOUCH_CORS_ORIGINS=*` is invalid. UI routes use credentialed cookie sessions, and the CORS
specification forbids wildcard origins with credentials. List origins explicitly.

**`issuer subdomains are claimed but document encryption is not configured`**
An organization claimed an issuer subdomain while a document encryption key was configured, and
that key is now absent. Per-organization signing keys are never stored in plaintext, so the server
will not start without the key that decrypts them. Restore the `document_key` block in your S3
configuration, or release the subdomains before starting.

**`Failed to fetch S3 configuration`**
S3 configuration is enabled and the object could not be fetched or parsed. Unlike runtime polling —
which fails open and keeps the running configuration — startup fails closed. Check the bucket name,
key, region, and that the instance role has `s3:GetObject` and `s3:HeadObject`.

**`Failed to start mTLS listener`**
The mTLS listener starts automatically whenever TLS is configured, and a bind failure on its port
is fatal. The most common cause is another process on the port; change it with `VOUCH_MTLS_PORT`.

**The server starts but binds the wrong port.**
Not an error. When TLS is configured, `VOUCH_LISTEN_ADDR` is ignored and the server binds 443 and
80. See [Ports and Endpoints](../reference/ports-and-endpoints.md).

**Port 80 fails to bind but the server keeps running.**
Also expected: this is logged as a warning, not a fatal error, and you lose only the HTTP→HTTPS
redirect. On Linux, binding below 1024 needs `CAP_NET_BIND_SERVICE`.

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
2. Verify the issuer URL uses HTTPS (HTTP is only allowed for `localhost`)
3. Confirm the server can make outbound HTTPS requests (firewall, proxy)

**"Issuer mismatch" during OIDC discovery**
- The `issuer` field in the discovery document must exactly match `VOUCH_IDP_<SLUG>_ISSUER` (trailing slashes matter)
- Some providers require a trailing slash (e.g., Auth0: `https://tenant.auth0.com/`)
- Entra `/organizations/v2.0` is special-cased — its `{tenantid}` template issuer is accepted
- Entra `/common/v2.0` is rejected at startup; use `/organizations/v2.0` or a single-tenant URL (see [Microsoft Entra ID](../idp/entra-id.md))

**"Failed to fetch SAML IdP metadata"**
- Verify the configured `VOUCH_IDP_<SLUG>_METADATA_URL` is correct and reachable
- Verify the URL returns XML, not an HTML login page
- Confirm the server can make outbound HTTPS requests

**SAML signature verification errors**
- Confirm the IdP's signing certificate in the metadata is current and not expired
- Confirm the server clock is NTP-synchronized — SAML assertions have time-based validity windows (5 minutes of skew tolerance is common)
- Verify the IdP assertion signing algorithm matches what the server expects

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
