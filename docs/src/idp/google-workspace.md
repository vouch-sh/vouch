# Google Workspace

Configure Google Workspace as your external identity provider for Vouch enrollment.

## Prerequisites

- Google Workspace admin access
- A verified domain in Google Workspace

## Step 1: Create OAuth Client in Google Cloud Console

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Select or create a project
3. Navigate to **APIs & Services > Credentials**
4. Click **Create Credentials > OAuth client ID**
5. Select **Web application** as the application type
6. Configure:
   - **Name**: `Vouch`
   - **Authorized redirect URIs**: `https://auth.example.com/oauth/callback`
7. Click **Create**
8. Copy the **Client ID** and **Client Secret**

## Step 2: Configure Consent Screen

1. Navigate to **APIs & Services > OAuth consent screen**
2. Select **Internal** (restricts to your Google Workspace org)
3. Configure:
   - **App name**: `Vouch`
   - **User support email**: your admin email
   - **Authorized domains**: your Vouch server domain
4. Add scopes: `openid`, `email`, `profile`

## Step 3: Configure Vouch

Set the following environment variables on your Vouch server:

```bash
VOUCH_OIDC_ISSUER=https://accounts.google.com
VOUCH_OIDC_CLIENT_ID=<your-client-id>.apps.googleusercontent.com
VOUCH_OIDC_CLIENT_SECRET=<your-client-secret>
```

Optionally restrict enrollment to specific domains:

```bash
VOUCH_ALLOWED_DOMAINS=example.com,subsidiary.com
```

## Step 4: Test

1. Run `vouch enroll` on a workstation
2. The browser should redirect to Google sign-in
3. After signing in, complete the WebAuthn registration with your YubiKey

## Claims Mapping

| Google Claim | Vouch Attribute |
|-------------|-----------------|
| `email` | User email / principal |
| `name` | Display name |
| `email_verified` | Must be `true` |

## Troubleshooting

**"Access blocked: This app's request is invalid"**
- Verify the redirect URI exactly matches `https://<your-vouch-domain>/oauth/callback`

**"This app is not verified"**
- Ensure the OAuth consent screen is set to **Internal** for Google Workspace

**Users from wrong domain can enroll**
- Set `VOUCH_ALLOWED_DOMAINS` to restrict enrollment to specific email domains
