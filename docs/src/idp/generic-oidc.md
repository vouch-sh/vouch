# Generic OIDC

Configure any OIDC-compliant identity provider for Vouch enrollment. This works with Okta, OneLogin, Keycloak, Auth0, and other providers that support OpenID Connect.

## Prerequisites

- Admin access to your identity provider
- The provider must support OpenID Connect with the `authorization_code` grant type

## Step 1: Register Vouch in Your IdP

Create a new application/client in your identity provider with these settings:

| Setting | Value |
|---------|-------|
| **Application type** | Web application |
| **Redirect URI** | `https://auth.example.com/oauth/callback` |
| **Scopes** | `openid`, `email`, `profile` |
| **Grant type** | Authorization Code |

Note the following values from your IdP:
- **Issuer URL** — The OIDC issuer (e.g., `https://your-org.okta.com`)
- **Client ID**
- **Client Secret**

## Step 2: Verify Discovery

Your IdP must serve a valid OIDC discovery document:

```bash
curl https://your-idp.example.com/.well-known/openid-configuration
```

The response must include `authorization_endpoint`, `token_endpoint`, and `jwks_uri`.

## Step 3: Configure Vouch

```bash
VOUCH_OIDC_ISSUER=https://your-idp.example.com
VOUCH_OIDC_CLIENT_ID=<your-client-id>
VOUCH_OIDC_CLIENT_SECRET=<your-client-secret>
```

Optionally restrict enrollment by email domain:

```bash
VOUCH_ALLOWED_DOMAINS=example.com
```

## Step 4: Test

1. Run `vouch enroll` on a workstation
2. The browser should redirect to your IdP's sign-in page
3. After signing in, complete the WebAuthn registration with your YubiKey

## Claims Requirements

The ID token from your IdP must include:

| Claim | Required | Description |
|-------|----------|-------------|
| `email` | Yes | User's email address |
| `email_verified` | Recommended | Whether the email is verified |
| `name` | No | User's display name |

## Provider-Specific Notes

### Okta

```bash
VOUCH_OIDC_ISSUER=https://your-org.okta.com
# or for a custom authorization server:
VOUCH_OIDC_ISSUER=https://your-org.okta.com/oauth2/default
```

### Keycloak

```bash
VOUCH_OIDC_ISSUER=https://keycloak.example.com/realms/your-realm
```

### Auth0

```bash
VOUCH_OIDC_ISSUER=https://your-tenant.auth0.com
```

## Troubleshooting

**Discovery document not found**
- Verify the issuer URL serves `/.well-known/openid-configuration`
- Some providers require a trailing path (e.g., `/oauth2/default`)

**"email" claim missing**
- Ensure the `email` scope is requested and granted
- Check your IdP's claim mapping configuration

**Redirect URI mismatch**
- The redirect URI must exactly match `https://<your-vouch-domain>/oauth/callback`
