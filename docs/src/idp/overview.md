# Identity Provider Overview

Vouch uses an external identity provider (IdP) to verify user identity during enrollment. This links a trusted corporate identity to a hardware-bound FIDO2 credential.

## Purpose

- Verify the user is a member of your organization during enrollment
- Pull user attributes (email) from your existing identity system
- No separate user database to maintain in Vouch

## Supported Protocols

Vouch supports two upstream IdP protocols:

| Protocol | Use Case |
|----------|----------|
| **OIDC** (OpenID Connect) | Recommended for most deployments. Supports auto-discovery of endpoints. |
| **SAML 2.0** | For organizations that require SAML or where OIDC is not available. |

> **OIDC and SAML are mutually exclusive.** Configure one or the other, not both. If both are configured, the server will refuse to start.

## OIDC Discovery

When using OIDC, the server automatically discovers authorization, token, and JWKS endpoints by fetching the `/.well-known/openid-configuration` document from the issuer URL at startup. Any OIDC-compliant provider works — no manual endpoint configuration is needed.

## Supported Providers

| Provider | Protocol | Guide |
|----------|----------|-------|
| Google Workspace | OIDC | [Google Workspace (OIDC)](google-workspace.md) |
| Microsoft Entra ID | OIDC or SAML | [Entra ID (OIDC)](entra-id.md), [SAML 2.0](saml.md) |
| Okta | OIDC or SAML | [Generic OIDC](generic-oidc.md), [SAML 2.0](saml.md) |
| Keycloak | OIDC or SAML | [Generic OIDC](generic-oidc.md), [SAML 2.0](saml.md) |
| Auth0 | OIDC | [Generic OIDC](generic-oidc.md) |
| Any OIDC-compliant provider | OIDC | [Generic OIDC](generic-oidc.md) |
| Any SAML 2.0-compliant provider | SAML | [SAML 2.0](saml.md) |

## Configuration

### OIDC

```bash
VOUCH_OIDC_ISSUER=https://accounts.google.com
VOUCH_OIDC_CLIENT_ID=<your-client-id>
VOUCH_OIDC_CLIENT_SECRET=<your-client-secret>
VOUCH_ALLOWED_DOMAINS=company.com
```

### SAML

```bash
VOUCH_SAML_IDP_METADATA_URL=https://idp.example.com/saml/metadata
VOUCH_SAML_SP_ENTITY_ID=https://auth.example.com
VOUCH_SAML_EMAIL_ATTRIBUTE=http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
VOUCH_ALLOWED_DOMAINS=company.com
```

## Claims and Attribute Mapping

### OIDC Claims

| OIDC Claim | Vouch Attribute | Required |
|------------|-----------------|----------|
| `email` | User email / principal | Yes |
| `email_verified` | Email verification status | Yes (must be `true`) |
| `hd` | Google Workspace hosted domain | No (Google-specific) |

### SAML Attributes

| SAML Attribute | Vouch Attribute | Notes |
|----------------|-----------------|-------|
| Configurable via `VOUCH_SAML_EMAIL_ATTRIBUTE` | User email / principal | Falls back to NameID if not found |
| Configurable via `VOUCH_SAML_DOMAIN_ATTRIBUTE` | Domain for enrollment restriction | Extracted from email if not set |

## User Lifecycle

- User exists in external IdP but not Vouch — Enrollment creates Vouch user
- User removed from external IdP — Existing Vouch sessions continue until expiry; re-enrollment blocked
