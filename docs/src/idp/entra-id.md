# Microsoft Entra ID (OIDC)

Configure Microsoft Entra ID (formerly Azure AD) as your upstream identity provider for Vouch enrollment.

## Prerequisites

- Microsoft Entra ID tenant with admin access
- An app registration in the Azure portal

## Step 1: Register an Application in Entra ID

Follow [Microsoft's app registration guide](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app) to create a new app registration:

1. Sign in to the [Azure portal](https://portal.azure.com/)
2. Navigate to **Microsoft Entra ID > App registrations > New registration**
3. Configure:
   - **Name**: `Vouch`
   - **Supported account types**: **Accounts in this organizational directory only** (single-tenant)
   - **Redirect URI**: Select **Web** and enter `https://auth.example.com/oauth/callback`
4. Click **Register**

## Step 2: Create a Client Secret

1. In the app registration, go to **Certificates & secrets > Client secrets**
2. Click **New client secret**
3. Set a description and expiry period
4. Copy the **Value** (not the Secret ID) immediately — it is only shown once

## Step 3: Configure Vouch

Add Entra to the `VOUCH_IDPS` list with type `oidc`:

```bash
VOUCH_IDPS=entra
VOUCH_IDP_ENTRA_TYPE=oidc
# Tenant-specific issuer URL (single-tenant)
VOUCH_IDP_ENTRA_ISSUER=https://login.microsoftonline.com/{tenant-id}/v2.0
VOUCH_IDP_ENTRA_CLIENT_ID=<application-client-id>
VOUCH_IDP_ENTRA_CLIENT_SECRET=<client-secret-value>
```

Replace `{tenant-id}` with your Entra ID tenant ID (found in **Azure portal > Microsoft Entra ID > Overview**).

For multi-tenant deployments — accepting any organizational tenant — use the `/organizations/v2.0` endpoint:

```bash
VOUCH_IDP_ENTRA_ISSUER=https://login.microsoftonline.com/organizations/v2.0
```

To additionally accept personal Microsoft accounts (outlook.com, hotmail.com, live.com, and externally-bound MSA addresses), use `/common/v2.0` instead:

```bash
VOUCH_IDP_ENTRA_ISSUER=https://login.microsoftonline.com/common/v2.0
```

Vouch handles the tenant-template issuer both endpoints return at discovery time, then cross-checks the per-tenant `tid` claim in each ID token against the tenant UUID in the token's `iss` claim. Personal Microsoft accounts (tokens from the MSA meta-tenant `9188040d-6c67-4c5b-b112-36a304b66dad`) are allowed to sign in but are **not auto-grouped into an organization** — their domain is reported as `None`, matching how Google consumer accounts (no `hd` claim) are handled. They can manage their own security keys but are not added to any org-scoped membership.

The server automatically discovers authorization, token, and JWKS endpoints from the issuer URL via [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html). No manual endpoint configuration is needed.

Optionally restrict enrollment to specific email domains:

```bash
VOUCH_ALLOWED_DOMAINS=example.com
```

### S3 configuration

```json
{
  "idps": [
    {
      "id": "entra",
      "type": "oidc",
      "issuer": "https://login.microsoftonline.com/{tenant-id}/v2.0",
      "client_id": "<application-client-id>",
      "client_secret": "<client-secret-value>"
    }
  ]
}
```

## Step 4: Test

1. Run `vouch enroll` on a workstation
2. The browser should redirect to the Microsoft sign-in page
3. After signing in, complete the WebAuthn registration with your YubiKey

## Common Pitfalls

**Single-tenant vs multi-tenant**

Use single-tenant (`Accounts in this organizational directory only`) to restrict access to your organization. Multi-tenant configurations allow users from any Entra ID tenant to attempt enrollment, which is rarely desired. If you use multi-tenant, ensure `VOUCH_ALLOWED_DOMAINS` is set to restrict enrollment.

**v1 vs v2 endpoints**

Always use the v2.0 issuer URL (`https://login.microsoftonline.com/{tenant-id}/v2.0`). The v1 endpoints use a different token format and are not compatible with standard OIDC discovery.

**Redirect URI mismatch**

The redirect URI in the app registration must exactly match `https://<your-vouch-domain>/oauth/callback`. Azure does not support wildcard redirect URIs.
