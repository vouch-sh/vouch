# Identity Provider Overview

Vouch uses one or more upstream identity providers (IdPs) to verify user identity during enrollment. This links a trusted corporate identity to a hardware-bound FIDO2 credential.

## Purpose

- Verify the user is a member of your organization during enrollment
- Pull user attributes (email) from your existing identity system
- No separate user database to maintain in Vouch

## Supported Protocols

Vouch supports two upstream IdP protocols, configured as a unified list:

| Protocol | Use Case |
|----------|----------|
| **OIDC** (OpenID Connect) | Recommended for most deployments. Supports auto-discovery of endpoints. |
| **SAML 2.0** | For organizations that require SAML or where OIDC is not available. |

Multiple IdPs — of either protocol, in any combination — can be configured simultaneously. The login page renders one "Sign in with X" button per configured IdP, in the order operators listed them.

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

IdPs are configured as a unified list. Each IdP has an operator-chosen slug (e.g., `google`, `entra`, `corp-saml`) that becomes its identifier in the state table, login page query string (`?provider=<slug>`), and audit logs.

### Slug rules

- Match `[a-z0-9-]{1,32}`
- Must not start or end with a hyphen
- Must be unique across all configured IdPs

### Environment variables

Set `VOUCH_IDPS` to a comma-separated list of slugs. For each slug, set `VOUCH_IDP_<SLUG>_TYPE` to `oidc` or `saml`, plus the type-specific variables.

OIDC example (Google + Entra concurrently):

```bash
VOUCH_IDPS=google,entra

VOUCH_IDP_GOOGLE_TYPE=oidc
VOUCH_IDP_GOOGLE_ISSUER=https://accounts.google.com
VOUCH_IDP_GOOGLE_CLIENT_ID=<your-google-client-id>
VOUCH_IDP_GOOGLE_CLIENT_SECRET=<your-google-client-secret>

VOUCH_IDP_ENTRA_TYPE=oidc
VOUCH_IDP_ENTRA_ISSUER=https://login.microsoftonline.com/organizations/v2.0
VOUCH_IDP_ENTRA_CLIENT_ID=<your-entra-client-id>
VOUCH_IDP_ENTRA_CLIENT_SECRET=<your-entra-client-secret>

VOUCH_ALLOWED_DOMAINS=company.com
```

SAML example (mixed alongside OIDC):

```bash
VOUCH_IDPS=google,corp-saml

VOUCH_IDP_GOOGLE_TYPE=oidc
VOUCH_IDP_GOOGLE_ISSUER=https://accounts.google.com
VOUCH_IDP_GOOGLE_CLIENT_ID=<your-google-client-id>
VOUCH_IDP_GOOGLE_CLIENT_SECRET=<your-google-client-secret>

VOUCH_IDP_CORP_SAML_TYPE=saml
VOUCH_IDP_CORP_SAML_METADATA_URL=https://idp.example.com/saml/metadata
VOUCH_IDP_CORP_SAML_SP_ENTITY_ID=https://auth.example.com
VOUCH_IDP_CORP_SAML_EMAIL_ATTRIBUTE=http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
VOUCH_IDP_CORP_SAML_DOMAIN_ATTRIBUTE=department
```

Notes on slug-to-env-var conversion: hyphens in the slug become underscores in env-var names. `corp-saml` becomes `VOUCH_IDP_CORP_SAML_TYPE`, etc.

### S3 configuration

In production deployments using S3-backed configuration, IdPs live under the top-level `idps` array. Each entry has `id`, `type`, and type-specific fields:

```json
{
  "idps": [
    {
      "id": "google",
      "type": "oidc",
      "issuer": "https://accounts.google.com",
      "client_id": "<your-google-client-id>",
      "client_secret": "<your-google-client-secret>"
    },
    {
      "id": "corp-saml",
      "type": "saml",
      "metadata_url": "https://idp.example.com/saml/metadata",
      "sp_entity_id": "https://auth.example.com",
      "email_attribute": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
      "domain_attribute": "department"
    }
  ]
}
```

Order in the `idps` array controls login-page button order.

## Migration from legacy variables

The previous flat single-IdP environment variables (`VOUCH_OIDC_ISSUER`, `VOUCH_OIDC_CLIENT_ID`, `VOUCH_OIDC_CLIENT_SECRET`, `VOUCH_OIDC_PROVIDERS`, `VOUCH_SAML_IDP_METADATA_URL`, `VOUCH_SAML_SP_ENTITY_ID`, `VOUCH_SAML_EMAIL_ATTRIBUTE`, `VOUCH_SAML_DOMAIN_ATTRIBUTE`) and the legacy S3 `oidc` / `saml` nested blocks are no longer supported. The server fails to start with an actionable error if any are present.

| Legacy variable | Replacement |
|---|---|
| `VOUCH_OIDC_PROVIDERS=google,entra` | `VOUCH_IDPS=google,entra` |
| `VOUCH_OIDC_<SLUG>_ISSUER` | `VOUCH_IDP_<SLUG>_ISSUER` (with `VOUCH_IDP_<SLUG>_TYPE=oidc`) |
| `VOUCH_OIDC_<SLUG>_CLIENT_ID` | `VOUCH_IDP_<SLUG>_CLIENT_ID` |
| `VOUCH_OIDC_<SLUG>_CLIENT_SECRET` | `VOUCH_IDP_<SLUG>_CLIENT_SECRET` |
| `VOUCH_OIDC_ISSUER` (single-provider) | `VOUCH_IDPS=<slug>` + `VOUCH_IDP_<SLUG>_*` |
| `VOUCH_SAML_IDP_METADATA_URL` | `VOUCH_IDP_<SLUG>_METADATA_URL` (with `VOUCH_IDP_<SLUG>_TYPE=saml`) |
| `VOUCH_SAML_SP_ENTITY_ID` | `VOUCH_IDP_<SLUG>_SP_ENTITY_ID` |
| `VOUCH_SAML_EMAIL_ATTRIBUTE` | `VOUCH_IDP_<SLUG>_EMAIL_ATTRIBUTE` |
| `VOUCH_SAML_DOMAIN_ATTRIBUTE` | `VOUCH_IDP_<SLUG>_DOMAIN_ATTRIBUTE` |
| S3 `{"oidc": {...}}` | S3 `{"idps": [{"id": "...", "type": "oidc", ...}]}` |
| S3 `{"saml": {...}}` | S3 `{"idps": [{"id": "...", "type": "saml", ...}]}` |

## Claims and Attribute Mapping

### OIDC Claims

| OIDC Claim | Vouch Attribute | Required |
|------------|-----------------|----------|
| `email` | User email / principal | Yes |
| `email_verified` | Email verification status | Yes (must be `true`) |
| `hd` | Google Workspace hosted domain | No (Google-specific) |
| `tid` | Entra tenant ID | No (Entra-specific, cross-checked against issuer; MSA meta-tenant → no org auto-created) |

### SAML Attributes

| SAML Attribute | Vouch Attribute | Notes |
|----------------|-----------------|-------|
| Configurable via `VOUCH_IDP_<SLUG>_EMAIL_ATTRIBUTE` | User email / principal | Falls back to NameID if not found |
| Configurable via `VOUCH_IDP_<SLUG>_DOMAIN_ATTRIBUTE` | Domain for enrollment restriction | Extracted from email if not set |

## User Lifecycle

- User exists in external IdP but not Vouch — Enrollment creates Vouch user
- User removed from external IdP — Existing Vouch sessions continue until expiry; re-enrollment blocked
