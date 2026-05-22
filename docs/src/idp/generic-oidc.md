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

Pick a slug for the IdP (e.g., `okta`, `keycloak`, `auth0-corp`) and add it to `VOUCH_IDPS`. Slug rules: `[a-z0-9-]{1,32}`, no leading or trailing hyphen, unique across IdPs.

```bash
VOUCH_IDPS=okta
VOUCH_IDP_OKTA_TYPE=oidc
VOUCH_IDP_OKTA_ISSUER=https://your-idp.example.com
VOUCH_IDP_OKTA_CLIENT_ID=<your-client-id>
VOUCH_IDP_OKTA_CLIENT_SECRET=<your-client-secret>
```

Hyphens in the slug become underscores in env-var names: a slug of `auth0-corp` becomes `VOUCH_IDP_AUTH0_CORP_*`.

At startup, the server fetches the discovery document from `{issuer}/.well-known/openid-configuration` and automatically discovers the authorization, token, and JWKS endpoints. No manual endpoint configuration is needed.

### S3 configuration

```json
{
  "idps": [
    {
      "id": "okta",
      "type": "oidc",
      "issuer": "https://your-idp.example.com",
      "client_id": "<your-client-id>",
      "client_secret": "<your-client-secret>"
    }
  ]
}
```

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
- The `issuer` field in the discovery document must exactly match the configured `VOUCH_IDP_<SLUG>_ISSUER` value (trailing slashes matter). Entra `/organizations/v2.0` is special-cased automatically — its discovery document returns a `{tenantid}` template that vouch handles transparently. The `/common/v2.0` endpoint is not supported; see [Microsoft Entra ID](./entra-id.md#why-personal-microsoft-accounts-arent-supported).

**Token errors after authentication**
- Ensure the client secret is correct and not expired
- Verify the redirect URI registered with the IdP exactly matches `https://<your-vouch-domain>/oauth/callback`
