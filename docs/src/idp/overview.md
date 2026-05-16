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

> **The legacy `VOUCH_OIDC_*` / `VOUCH_SAML_*` shorthand picks one IdP.** If both shorthand families are set, the server refuses to start. To mix OIDC and SAML upstreams — or to register multiple OIDC providers — use the multi-IdP form (see [Configuring Multiple IdPs](#configuring-multiple-idps) below).

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

## Configuring Multiple IdPs

Run more than one upstream IdP side-by-side using the slug-prefixed form. Each slug enumerated in `VOUCH_IDPS` registers an extra entry; the landing page then shows one "Sign in with X" button per registered IdP.

```bash
# Legacy Google entry (slug = "default")
VOUCH_OIDC_ISSUER=https://accounts.google.com
VOUCH_OIDC_CLIENT_ID=...
VOUCH_OIDC_CLIENT_SECRET=...

# Add multi-tenant Entra (slug = "microsoft")
VOUCH_IDPS=microsoft
VOUCH_IDP_MICROSOFT_ISSUER=https://login.microsoftonline.com/common/v2.0
VOUCH_IDP_MICROSOFT_CLIENT_ID=...
VOUCH_IDP_MICROSOFT_CLIENT_SECRET=...
# Optional: restrict to specific Entra tenants
VOUCH_IDP_MICROSOFT_ALLOWED_TENANTS=<tenant-guid>,<other-tenant-guid>
# Optional: narrow VOUCH_ALLOWED_DOMAINS for just this IdP
VOUCH_IDP_MICROSOFT_ALLOWED_DOMAINS=acme.com
```

**Rules:**

- The slug `default` is reserved for the legacy shorthand entry.
- Per-IdP `allowed_domains` **narrows** `VOUCH_ALLOWED_DOMAINS`; it cannot widen it.
- Each slug must define **either** the OIDC fields (`_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`) **or** the SAML field (`_METADATA_URL`). Setting both on the same slug fails startup.
- Mixing OIDC and SAML upstreams across different slugs is supported.

See [Environment Variables](../reference/environment-variables.md#multiple-identity-providers) for the full variable list.

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
