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
   - **Supported account types**: choose one of:
     - **Accounts in this organizational directory only** (single-tenant) — restrict to your tenant.
     - **Accounts in any organizational directory (Any Microsoft Entra ID tenant – Multitenant)** — let users from any work/school tenant enroll.

     > **Do not select** "Accounts in any organizational directory and personal Microsoft accounts" or "Personal Microsoft accounts only". Personal Microsoft accounts (outlook.com, hotmail.com, live.com) are not supported by Vouch — see [Why personal accounts aren't supported](#why-personal-microsoft-accounts-arent-supported) below.
   - **Redirect URI**: Select **Web** and enter `https://auth.example.com/oauth/callback`
4. Click **Register**

## Step 2: Create a Client Secret

1. In the app registration, go to **Certificates & secrets > Client secrets**
2. Click **New client secret**
3. Set a description and expiry period
4. Copy the **Value** (not the Secret ID) immediately — it is only shown once

## Step 3: Configure the `xms_edov` optional claim

Vouch requires the `xms_edov` (Email Domain Owner Verified) claim to confirm the user's email is admin-verified by their tenant. Microsoft does not emit this claim by default — you must add it as an optional claim:

1. In the app registration, go to **Token configuration > Add optional claim**
2. Select token type **ID**
3. Check **xms_edov**
4. Click **Add**
5. If prompted to "Turn on the Microsoft Graph email permission", accept

The next ID token Microsoft issues will contain `"xms_edov": true` when the email's domain is verified by the user's tenant admin.

## Step 4: Configure Vouch

Add Entra to the `VOUCH_IDPS` list with type `oidc`:

### Single-tenant

```bash
VOUCH_IDPS=entra
VOUCH_IDP_ENTRA_TYPE=oidc
VOUCH_IDP_ENTRA_ISSUER=https://login.microsoftonline.com/{tenant-id}/v2.0
VOUCH_IDP_ENTRA_CLIENT_ID=<application-client-id>
VOUCH_IDP_ENTRA_CLIENT_SECRET=<client-secret-value>
```

Replace `{tenant-id}` with your Entra ID tenant ID (found in **Azure portal > Microsoft Entra ID > Overview**).

### Multi-tenant (any work/school tenant)

```bash
VOUCH_IDP_ENTRA_ISSUER=https://login.microsoftonline.com/organizations/v2.0
```

Vouch handles the `{tenantid}` template issuer that `/organizations/` discovery returns, then cross-checks the per-tenant `tid` claim in each ID token against the tenant UUID in the token's `iss` claim to prevent cross-tenant token injection.

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

## Step 5: Test

1. Run `vouch enroll` on a workstation
2. The browser redirects to the Microsoft sign-in page
3. After signing in, complete the WebAuthn registration with your YubiKey

## Why personal Microsoft accounts aren't supported

Vouch issues hardware-backed credentials and tracks users by verified email address. To verify an Entra email, Vouch requires the `xms_edov` optional claim, which provides a signed assertion that the email's domain is admin-verified.

Microsoft only emits optional claims (including `xms_edov`) for app registrations that target **Microsoft Entra ID accounts only**. Per Microsoft's [app manifest reference](https://learn.microsoft.com/en-us/entra/identity-platform/reference-microsoft-graph-app-manifest):

> Apps that support both personal accounts and Microsoft Entra ID can't use optional claims.

As a consequence, the `https://login.microsoftonline.com/common/v2.0` issuer is **rejected at startup** — Vouch will refuse to load an Entra IdP configured with `/common/`. Use `/organizations/v2.0` or a single-tenant URL instead.

## Common Pitfalls

**`InvalidIssuer` at the callback**

The configured issuer must end in `/v2.0`. The v1 endpoints use a different token format and are not compatible with standard OIDC discovery.

**`Email address is not verified by the identity provider` after sign-in**

The `xms_edov` optional claim isn't configured on the app registration. Repeat [Step 3](#step-3-configure-the-xms_edov-optional-claim). If the claim is already configured but the user's email still isn't accepted, the user's tenant admin has not verified the email domain — Microsoft only sets `xms_edov: true` when the domain is verified inside the user's tenant.

**Redirect URI mismatch**

The redirect URI in the app registration must exactly match `https://<your-vouch-domain>/oauth/callback`. Azure does not support wildcard redirect URIs.

**Multi-tenant without an allowlist**

If you use `/organizations/v2.0`, *any* Entra tenant can attempt enrollment. Set `VOUCH_ALLOWED_DOMAINS` to restrict which email domains Vouch will accept.
