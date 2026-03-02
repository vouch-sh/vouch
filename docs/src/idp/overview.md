# Identity Provider Overview

Vouch uses external identity providers (IdPs) to verify user identity during enrollment. This links a trusted corporate identity to a hardware-bound FIDO2 credential.

## Purpose

- Verify the user is a member of your organization during enrollment
- Pull user attributes (email) from your existing identity system
- No separate user database to maintain in Vouch

## Configuration

IdP configuration is via environment variables:

```bash
VOUCH_OIDC_ISSUER=https://accounts.google.com
VOUCH_OIDC_CLIENT_ID=<your-client-id>
VOUCH_OIDC_CLIENT_SECRET=<your-client-secret>
VOUCH_ALLOWED_DOMAINS=company.com
```

See the [Google Workspace](google-workspace.md) guide for setup instructions.

## Supported Providers

| Provider | Status | Notes |
|----------|--------|-------|
| Google Workspace | Supported | First-class support, recommended |

## Claims Mapping

External IdP claims are mapped to Vouch user attributes:

| External Claim | Vouch Attribute | Required |
|----------------|-----------------|----------|
| `email` | User email / principal | Yes |
| `email_verified` | Email verification status | Yes (must be `true`) |
| `hd` | Google Workspace hosted domain | No (Google-specific) |

## User Lifecycle

- User exists in external IdP but not Vouch — Enrollment creates Vouch user
- User removed from external IdP — Existing Vouch sessions continue until expiry; re-enrollment blocked
