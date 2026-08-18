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

Hyphens in the slug become underscores in env-var names: `corp-saml` becomes `VOUCH_IDP_CORP_SAML_*`.

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

## Claims and Attribute Mapping

### OIDC Claims

| OIDC Claim | Vouch Attribute | Required |
|------------|-----------------|----------|
| `email` | User email / principal | Yes |
| `email_verified` | Email verification status | Yes (must be `true`) |
| `sub` | Upstream subject, bound to the account together with the token issuer (see [Account linking](#account-linking-and-identity-binding)) | Yes |
| `hd` | Google Workspace hosted domain | No (Google-specific) |
| `tid` | Entra tenant ID | No (Entra-specific, cross-checked against issuer UUID to prevent cross-tenant token injection) |

### SAML Attributes

| SAML Attribute | Vouch Attribute | Notes |
|----------------|-----------------|-------|
| Configurable via `VOUCH_IDP_<SLUG>_EMAIL_ATTRIBUTE` | User email / principal | Falls back to NameID if not found |
| Configurable via `VOUCH_IDP_<SLUG>_DOMAIN_ATTRIBUTE` | Domain for enrollment restriction | Extracted from email if not set |

## Account Linking and Identity Binding

Email addresses are a lease, not a name: employers reassign them and providers recycle
them. Vouch therefore treats the upstream identity pair — the validated OIDC `(iss, sub)`
claims, or for SAML the IdP entity ID plus NameID — as the durable link between a Vouch
account and a person. The email address is profile data.

When an IdP sign-in completes, Vouch resolves the account in this order:

1. **Binding match.** An account already bound to this exact issuer + subject signs in,
   even if the asserted email has since changed upstream. The account email is canonical;
   a drifted upstream email is logged but never written back.
2. **Email match with lazy binding.** An account with a matching email and *no binding for
   this issuer* is bound to the asserted issuer + subject on the spot (audit event
   `identity_bound`), provided the sign-in asserts a subject at all — see the SAML caveat
   below. This is how accounts that predate identity binding, and SCIM-provisioned
   accounts, acquire their binding — there is no batch backfill; each account binds on its
   first eligible IdP sign-in.
3. **Refusal when the bound subject can't be reasserted.** If the email matches an account
   already bound for this issuer, and the sign-in either asserts a *different* subject or
   asserts none at all (e.g. a SAML NameID format identity binding doesn't trust — see
   [SAML 2.0](saml.md)), the sign-in is refused with an "Account Linking Blocked" error
   page and an `identity_bind_refused` audit event. This is deliberate: an email match that
   can't reassert the bound identity is what an upstream email reassignment (and the
   resulting account-takeover attempt) looks like, and a sign-in this weak must not fall
   back to matching on email alone once an account is bound.
4. **New account.** No match creates a new account carrying the binding.

Bindings are per-issuer: an account can hold one binding for each configured IdP, so
multi-IdP deployments and IdP migrations work without intervention — the first sign-in
through a newly configured IdP adds a binding for that issuer alongside the existing ones.

**Recovery.** If an IdP legitimately re-issues subjects (e.g. a directory tenant rebuild),
affected users are refused at step 3 and cannot sign in. There is currently no unbind
operation: an org admin must remove the affected user (Admin → Members → Remove), after
which the user re-enrolls and a fresh account binds to the new subject.

SAML deployments must send a `persistent`-format NameID to get identity binding — it is
the only format the SAML spec guarantees is stable per principal. Every other format
(`emailAddress`, `unspecified`, `transient`, or a missing `Format` attribute) cannot create
a binding: for an account with no existing binding for the IdP, matching falls back to
email alone, as it did before identity binding existed; for an account that already has a
binding, such a sign-in hits step 3 above and is refused instead — see [SAML 2.0](saml.md)
for details.

## User Lifecycle

- User exists in external IdP but not Vouch — Enrollment creates Vouch user
- User removed from external IdP — Existing Vouch sessions continue until expiry; re-enrollment blocked
