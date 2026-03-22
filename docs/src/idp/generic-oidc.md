# Generic OIDC Provider

Configure any OpenID Connect-compliant identity provider as the upstream IdP for Vouch enrollment.

## Prerequisites

- Your IdP must support [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) (a `/.well-known/openid-configuration` endpoint at the issuer URL)
- You need a registered OAuth 2.0 client (client ID and client secret)
- The redirect URI `https://<your-vouch-domain>/oauth/callback` must be registered with the IdP

## Finding the Issuer URL

The issuer URL is the base URL that hosts the OIDC discovery document. You can verify it by fetching `{issuer}/.well-known/openid-configuration` and confirming it returns a valid JSON document:

```bash
curl -s https://your-idp.example.com/.well-known/openid-configuration | jq .issuer
```

Common issuer URL patterns:

| Provider | Issuer URL Format |
|----------|-------------------|
| Okta | `https://{your-domain}.okta.com` or `https://{your-domain}.okta.com/oauth2/{auth-server-id}` |
| Keycloak | `https://{host}/realms/{realm}` |
| Auth0 | `https://{tenant}.auth0.com/` |
| Google Workspace | `https://accounts.google.com` |
| Entra ID | `https://login.microsoftonline.com/{tenant-id}/v2.0` |

## Configuration

Set the following environment variables:

```bash
VOUCH_OIDC_ISSUER=https://your-idp.example.com
VOUCH_OIDC_CLIENT_ID=<your-client-id>
VOUCH_OIDC_CLIENT_SECRET=<your-client-secret>
```

At startup, the server fetches the discovery document from `{issuer}/.well-known/openid-configuration` and automatically discovers the authorization, token, and JWKS endpoints. No manual endpoint configuration is needed.

## Domain Restrictions

Restrict enrollment to specific email domains:

```bash
VOUCH_ALLOWED_DOMAINS=example.com,subsidiary.com
```

If not set, users from any email domain can enroll (provided they authenticate with the upstream IdP).

## Tested Providers

The following providers have been tested with Vouch:

| Provider | Status | Notes |
|----------|--------|-------|
| Google Workspace | Tested | See [dedicated guide](google-workspace.md) |
| Microsoft Entra ID | Tested | See [dedicated guide](entra-id.md) |
| Okta | Tested | Use the Org Authorization Server or a custom one |
| Keycloak | Tested | Requires a configured realm with client credentials |
| Auth0 | Tested | Use the tenant issuer URL with trailing slash |

## Troubleshooting

**"Failed to fetch upstream OIDC discovery document"**
- Verify the issuer URL is correct and reachable from the server
- Check that the URL uses HTTPS (HTTP is only allowed for `localhost`)
- Confirm the discovery endpoint returns valid JSON

**"Issuer mismatch"**
- The `issuer` field in the discovery document must exactly match the configured `VOUCH_OIDC_ISSUER` value (trailing slashes matter)

**Token errors after authentication**
- Ensure the client secret is correct and not expired
- Verify the redirect URI registered with the IdP exactly matches `https://<your-vouch-domain>/oauth/callback`
