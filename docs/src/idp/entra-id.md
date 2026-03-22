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

Set the following environment variables on your Vouch server:

```bash
# Tenant-specific issuer URL (single-tenant)
VOUCH_OIDC_ISSUER=https://login.microsoftonline.com/{tenant-id}/v2.0
VOUCH_OIDC_CLIENT_ID=<application-client-id>
VOUCH_OIDC_CLIENT_SECRET=<client-secret-value>
```

Replace `{tenant-id}` with your Entra ID tenant ID (found in **Azure portal > Microsoft Entra ID > Overview**).

The server automatically discovers authorization, token, and JWKS endpoints from the issuer URL via [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html). No manual endpoint configuration is needed.

Optionally restrict enrollment to specific email domains:

```bash
VOUCH_ALLOWED_DOMAINS=example.com
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
