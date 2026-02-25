# Identity Provider Overview

Vouch uses external identity providers (IdPs) to verify user identity during enrollment. This links a trusted corporate identity to a hardware-bound FIDO2 credential.

## Purpose

- Verify the user is a member of your organization during enrollment
- Pull user attributes (email, name, groups) from your existing identity system
- No separate user database to maintain in Vouch

## Self-Service Admin Portal

Administrators configure external IdPs through the Vouch web interface — no config files or server restarts required.

```
Admin Portal → Settings → Identity Providers → Add Provider
```

## Configuration Steps

1. Select provider type (Google Workspace, Microsoft Entra ID, Generic OIDC)
2. Enter client credentials from the external IdP
3. Configure allowed domains (e.g., `@company.com`)
4. Test the connection
5. Enable for user enrollment

## Supported Providers

| Provider | Status | Notes |
|----------|--------|-------|
| Google Workspace | Supported | First-class support, recommended |
| Microsoft Entra ID | Supported | Azure AD / Entra ID integration |
| Generic OIDC | Supported | Any OIDC-compliant IdP |

## Claims Mapping

External IdP claims are mapped to Vouch user attributes:

| External Claim | Vouch Attribute | Required |
|----------------|-----------------|----------|
| `email` | User email / principal | Yes |
| `name` or `given_name`+`family_name` | Display name | No |
| `groups` | Group memberships | No |

## User Lifecycle

- User exists in external IdP but not Vouch — Enrollment creates Vouch user
- User removed from external IdP — Existing Vouch sessions continue until expiry; re-enrollment blocked
- User's groups change in external IdP — Updated on next enrollment/re-enrollment
