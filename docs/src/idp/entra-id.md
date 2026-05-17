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

## Running Entra alongside another IdP

To offer both Google Workspace and Entra ID on the landing page, register Entra under a slug-prefixed entry alongside the existing Google shorthand config:

```bash
# Google via VOUCH_OIDC_* shorthand (slug = "default")
VOUCH_OIDC_ISSUER=https://accounts.google.com
VOUCH_OIDC_CLIENT_ID=...
VOUCH_OIDC_CLIENT_SECRET=...

# Add Entra as a second IdP (slug = "microsoft")
VOUCH_IDPS=microsoft
VOUCH_IDP_MICROSOFT_ISSUER=https://login.microsoftonline.com/{tenant-id}/v2.0
VOUCH_IDP_MICROSOFT_CLIENT_ID=<application-client-id>
VOUCH_IDP_MICROSOFT_CLIENT_SECRET=<client-secret-value>
```

The landing page now renders a button for each. See [Configuring Multiple IdPs](overview.md#configuring-multiple-idps).

## Multi-tenant configuration

Vouch supports Entra's multi-tenant issuers (`/common/v2.0` and `/organizations/v2.0`) — useful when you want any Entra user to sign in regardless of which tenant they belong to. The verifier checks that:

1. The JWT `iss` claim has the shape `https://login.microsoftonline.com/<tenant-guid>/v2.0`.
2. The `tid` claim is a valid GUID and matches the tenant in `iss` (defends against cross-tenant token injection).
3. The `tid` is **not** the well-known personal-accounts tenant — `@outlook.com`, `@hotmail.com`, `@live.com`, etc. are rejected automatically.

```bash
VOUCH_IDP_MICROSOFT_ISSUER=https://login.microsoftonline.com/common/v2.0
VOUCH_IDP_MICROSOFT_CLIENT_ID=...
VOUCH_IDP_MICROSOFT_CLIENT_SECRET=...
# Optional: restrict to specific tenants
VOUCH_IDP_MICROSOFT_ALLOWED_TENANTS=<tenant-guid>,<other-tenant-guid>
```

> **Custom domains are trusted because Microsoft verifies them.** Entra requires DNS TXT verification before a tenant can issue tokens for a custom domain, so the email-domain match against `VOUCH_ALLOWED_DOMAINS` cannot be spoofed by a different tenant. For belt-and-braces tenant pinning, set `VOUCH_IDP_<SLUG>_ALLOWED_TENANTS`.

## Common Pitfalls

**Single-tenant vs multi-tenant**

Single-tenant (`Accounts in this organizational directory only`) restricts access to your organization at the issuer level. Multi-tenant configurations (`/common/v2.0`, `/organizations/v2.0`) allow users from any Entra tenant; the `tid` cross-check and the consumer-tenant rejection are enforced automatically, but you should still set `VOUCH_ALLOWED_DOMAINS` (or `VOUCH_IDP_<SLUG>_ALLOWED_DOMAINS` / `_ALLOWED_TENANTS`) if you want to narrow further.

**v1 vs v2 endpoints**

Always use the v2.0 issuer URL (`https://login.microsoftonline.com/{tenant-id}/v2.0`). The v1 endpoints use a different token format and are not compatible with standard OIDC discovery.

**Redirect URI mismatch**

The redirect URI in the app registration must exactly match `https://<your-vouch-domain>/oauth/callback`. Azure does not support wildcard redirect URIs.
