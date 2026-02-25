# Microsoft Entra ID

Configure Microsoft Entra ID (formerly Azure AD) as your external identity provider for Vouch enrollment.

## Prerequisites

- Microsoft Entra ID admin access (Global Administrator or Application Administrator role)
- A verified domain in Entra ID

## Step 1: Register an Application

1. Go to [Microsoft Entra admin center](https://entra.microsoft.com/)
2. Navigate to **Identity > Applications > App registrations**
3. Click **New registration**
4. Configure:
   - **Name**: `Vouch`
   - **Supported account types**: Accounts in this organizational directory only (Single tenant)
   - **Redirect URI**: Web — `https://auth.example.com/oauth/callback`
5. Click **Register**

## Step 2: Configure Client Secret

1. In the app registration, go to **Certificates & secrets**
2. Click **New client secret**
3. Set a description and expiry
4. Copy the **Value** (shown only once)

Also note the following from the **Overview** page:
- **Application (client) ID**
- **Directory (tenant) ID**

## Step 3: Configure API Permissions

1. Go to **API permissions**
2. Add permissions:
   - Microsoft Graph > Delegated > `openid`
   - Microsoft Graph > Delegated > `email`
   - Microsoft Graph > Delegated > `profile`
3. Click **Grant admin consent** for your organization

## Step 4: Configure Vouch

Set the following environment variables:

```bash
VOUCH_OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
VOUCH_OIDC_CLIENT_ID=<application-client-id>
VOUCH_OIDC_CLIENT_SECRET=<client-secret-value>
```

Optionally restrict enrollment to specific domains:

```bash
VOUCH_ALLOWED_DOMAINS=example.com
```

## Step 5: Test

1. Run `vouch enroll` on a workstation
2. The browser should redirect to Microsoft sign-in
3. After signing in, complete the WebAuthn registration with your YubiKey

## Claims Mapping

| Entra ID Claim | Vouch Attribute |
|---------------|-----------------|
| `email` or `preferred_username` | User email / principal |
| `name` | Display name |

## Troubleshooting

**"AADSTS50011: The redirect URI does not match"**
- Verify the redirect URI exactly matches `https://<your-vouch-domain>/oauth/callback`

**"AADSTS700016: Application not found"**
- Ensure you're using the correct tenant ID in the issuer URL

**Users get "Need admin approval"**
- Grant admin consent in the API permissions section
