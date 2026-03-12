# AWS IAM Identity Center

Integrate Vouch with AWS IAM Identity Center (formerly AWS SSO) using the Trusted Token Issuer pattern. After setup, users authenticate with their YubiKey via `vouch login` and all AWS tools (CLI, SDKs, Terraform, CDK) work natively — no `credential_process` shim required.

## How it works

1. User authenticates to Vouch via FIDO2 (YubiKey tap)
2. Vouch server issues a signed OIDC ID token
3. Server exchanges the token for temporary IAM credentials via `AssumeRoleWithWebIdentity`
4. Server calls `CreateTokenWithIAM` to get an SSO access token
5. SSO token is returned to the CLI and cached locally at `~/.aws/sso/cache/`
6. AWS tools call `GetRoleCredentials` directly against Identity Center using the cached token

The SSO token is never stored server-side.

## Prerequisites

- A Vouch server deployed and accessible over HTTPS
- An AWS account with IAM Identity Center enabled
- AWS admin access to create IAM resources and Identity Center applications
- Vouch org admin access to configure the integration

## Administrator setup

### Step 1: Create an IAM OIDC Identity Provider

This lets AWS STS validate tokens issued by your Vouch server.

1. Go to **IAM** > **Identity providers** > **Add provider**
2. Select **OpenID Connect**
3. Configure:
   - **Provider URL**: `https://your-vouch-server.example.com`
   - **Audience**: `https://your-vouch-server.example.com`
4. Click **Add provider**

The audience must be the full URL including `https://` — it must match the `aud` claim in the JWT that Vouch issues.

### Step 2: Create a Trusted Token Issuer in Identity Center

1. Go to **IAM Identity Center** > **Settings** > **Authentication**
2. Under **Trusted token issuers**, click **Create trusted token issuer**
3. Configure:
   - **Name**: e.g., `vouch-prod`
   - **Issuer URL**: `https://your-vouch-server.example.com`
4. Click **Create**

### Step 3: Create a Customer Managed Application

1. Go to **IAM Identity Center** > **Applications** > **Add application**
2. Select **I have an application I want to set up** > **OAuth 2.0**
3. Name the application (e.g., `Vouch`)
4. Under **Trusted token issuers**, select the issuer created in Step 2
5. Set the **Aud claim** to: `https://your-vouch-server.example.com`
6. Save the application and note the **Application ARN**

### Step 4: Grant the account access scope

The application needs the `sso:account:access` scope so that Vouch can discover which AWS accounts and roles are available to each user. This scope is not configurable through the AWS Console — use the AWS CLI:

```bash
aws sso-admin put-application-access-scope \
  --application-arn "<application-arn-from-step-3>" \
  --scope "sso:account:access"
```

Verify it was set:

```bash
aws sso-admin list-application-access-scopes \
  --application-arn "<application-arn-from-step-3>"
```

### Step 5: Assign users to the application

For Identity Center to issue tokens for your users, they must be assigned to the application:

1. Go to **IAM Identity Center** > **Applications**
2. Select the application created in Step 3
3. Click **Assign users and groups**
4. Select the users or groups that should have access

### Step 6: Create a Bootstrap IAM Role

This role allows the Vouch server to call `CreateTokenWithIAM` on your Identity Center application. The Vouch server assumes this role using the OIDC token it issues.

1. Go to **IAM** > **Roles** > **Create role**
2. Select **Web identity** as the trusted entity type
3. Select the OIDC provider created in Step 1
4. Set **Audience** to `https://your-vouch-server.example.com`
5. Attach a policy with the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sso-oauth:CreateTokenWithIAM",
      "Resource": "<application-arn-from-step-3>"
    },
    {
      "Effect": "Allow",
      "Action": [
        "sso:ListInstances",
        "sso:ListAccountAssignmentsForPrincipal",
        "sso:DescribePermissionSet"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "identitystore:GetUserId",
      "Resource": "*"
    }
  ]
}
```

The `sso:List*` and `sso:Describe*` permissions allow Vouch to discover which AWS accounts and permission sets are available to each user. The `identitystore:GetUserId` permission resolves user emails to Identity Store principal IDs.

6. Name the role (e.g., `vouch-idc-bootstrap`) and create it
7. Note the **Role ARN**

The resulting trust policy should look like:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<account-id>:oidc-provider/your-vouch-server.example.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "your-vouch-server.example.com:aud": "https://your-vouch-server.example.com"
        }
      }
    }
  ]
}
```

### Step 7: Configure the application credentials

The Identity Center application needs to know which IAM role is authorized to call `CreateTokenWithIAM`:

1. Go to **IAM Identity Center** > **Applications**
2. Select the application created in Step 3
3. Under **Application credentials**, choose one of:
   - **Enter one or more IAM roles** — paste the bootstrap role ARN from Step 6
   - **Edit the application policy** — write a policy granting `sso-oauth:CreateTokenWithIAM` to the bootstrap role

### Step 8: Configure Vouch

**Option A: Web UI**

1. Log in to your Vouch server as an org admin
2. Navigate to `/integrations`
3. Fill in:
   - **Bootstrap Role ARN**: the IAM role ARN from Step 6
   - **Application ARN**: the Identity Center application ARN from Step 3
   - **Identity Center Region**: the AWS region where Identity Center is enabled (e.g., `us-east-1`)
4. Click **Save**

**Option B: REST API**

```bash
curl -X PUT https://your-vouch-server.example.com/v1/integrations/aws \
  -H "Authorization: Bearer $VOUCH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "idc_bootstrap_role_arn": "arn:aws:iam::<account-id>:role/vouch-idc-bootstrap",
    "idc_application_arn": "arn:aws:sso::<account-id>:application/ssoins-abc123/apl-xyz789",
    "idc_region": "us-east-1"
  }'
```

## End-user setup

### One-time: configure AWS profiles

Run the setup command to discover available accounts and roles:

```bash
vouch setup aws-idc
```

This calls the Vouch server to enumerate all AWS accounts and permission sets available to you via Identity Center. You'll see an interactive prompt to select which account/role pairs to configure:

```
Discovering accounts and roles from Identity Center...

? Select accounts and roles to configure:
  [x] Production (123456789012) / AdministratorAccess
  [x] Staging (234567890123) / ReadOnlyAccess
  [ ] Sandbox (345678901234) / PowerUserAccess (exists)
```

Selected pairs are written as native SSO profiles in `~/.aws/config`:

```ini
[sso-session vouch-your-vouch-server.example.com]
sso_start_url = https://your-vouch-server.example.com
sso_region = us-east-1

[profile vouch-idc-production-administratoraccess]
sso_session = vouch-your-vouch-server.example.com
sso_account_id = 123456789012
sso_role_name = AdministratorAccess
region = us-east-1
```

For a single profile without the interactive prompt:

```bash
vouch setup aws-idc --account-id 123456789012 --role-name AdministratorAccess
```

Discovery results are cached for 4 hours. To bypass the cache:

```bash
vouch setup aws-idc --refresh
```

### Daily use

```bash
vouch login
```

After FIDO2 authentication, `vouch login` automatically refreshes the SSO token and caches it locally. All AWS tools then work with the configured profiles:

```bash
aws sts get-caller-identity --profile vouch-idc-production-administratoraccess
aws s3 ls --profile vouch-idc-production-administratoraccess
terraform plan   # with AWS_PROFILE=vouch-idc-production-administratoraccess
```

To manually refresh the SSO token (e.g., if it expires mid-session):

```bash
vouch credential aws-idc
```

## Troubleshooting

### "AWS Identity Center is not configured for this organization"

The Vouch org admin has not configured the integration yet. Ask them to complete the administrator setup above.

### `AssumeRoleWithWebIdentity` fails

- Verify the IAM OIDC provider's **Audience** is the full URL (e.g., `https://your-vouch-server.example.com`), not just the hostname
- Verify the bootstrap role's trust policy references the correct OIDC provider ARN
- Verify the trust policy condition checks the correct audience value

### `CreateTokenWithIAM` fails

- Verify the Identity Center application's trusted token issuer has the correct **Aud claim** set to the full Vouch URL
- Verify the application credentials grant `sso-oauth:CreateTokenWithIAM` to the bootstrap role
- Verify users are assigned to the Identity Center application (Step 4)

### "No accounts or roles available from Identity Center"

The authenticated user has no permission set assignments in Identity Center. Assign them to accounts and permission sets through the Identity Center console.

### Profile names

Profiles follow the naming pattern `vouch-idc-{account-name}-{role-name}` (lowercased, special characters replaced with dashes). If the same role name exists across multiple accounts, the account ID is appended for disambiguation.
