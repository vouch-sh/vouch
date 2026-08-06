# SAML 2.0

Configure one or more SAML 2.0 identity providers for Vouch enrollment. Vouch acts as a SAML Service Provider (SP) with HTTP-POST and HTTP-Redirect bindings.

SAML IdPs are configured under the same `VOUCH_IDPS` list as OIDC IdPs and can coexist with OIDC providers in any combination.

## Environment Variables

Pick a slug for the IdP (e.g., `corp-saml`, `partner-saml`) and add it to `VOUCH_IDPS`. Slug rules: `[a-z0-9-]{1,32}`, no leading/trailing hyphen, unique across IdPs.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_IDP_<SLUG>_TYPE` | Yes | _(none)_ | Must be `saml` for a SAML IdP. |
| `VOUCH_IDP_<SLUG>_METADATA_URL` | Yes | _(none)_ | URL to the IdP's SAML metadata XML document. Fetched at server startup. |
| `VOUCH_IDP_<SLUG>_SP_ENTITY_ID` | No | `{VOUCH_BASE_URL}` | SP entity ID sent in authentication requests. Defaults to the server's base URL. |
| `VOUCH_IDP_<SLUG>_EMAIL_ATTRIBUTE` | No | _(auto-detect)_ | SAML attribute name containing the user's email address. |
| `VOUCH_IDP_<SLUG>_DOMAIN_ATTRIBUTE` | No | _(none)_ | SAML attribute name containing the user's domain (for domain restriction). |

Hyphens in the slug become underscores in env-var names: a slug of `corp-saml` becomes `VOUCH_IDP_CORP_SAML_*`.

## SP Metadata

The Vouch server exposes SP metadata for configuring your IdP:

```
GET https://auth.example.com/saml/metadata
```

This returns an XML document containing the SP entity ID, Assertion Consumer Service (ACS) URL, and supported bindings. The SP entity ID comes from the first configured SAML IdP (or the server's base URL if none is set). Import the metadata into your IdP or configure the following values manually:

- **SP Entity ID**: `https://auth.example.com` (or the value of `VOUCH_IDP_<SLUG>_SP_ENTITY_ID`)
- **ACS URL**: `https://auth.example.com/saml/acs`
- **Bindings**: HTTP-POST (ACS), HTTP-Redirect (AuthnRequest)

All configured SAML IdPs share the single ACS URL; Vouch identifies the originating IdP via the per-request `RelayState` stored in the state table.

## Attribute Mapping

Vouch extracts user identity from SAML assertion attributes. By default, it looks for the email address in common attribute names. You can override this per-IdP with `VOUCH_IDP_<SLUG>_EMAIL_ATTRIBUTE`:

| Use Case | Attribute Example |
|----------|-------------------|
| Standard email | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` |
| NameID | _(used automatically if no attribute match)_ |
| Custom | Set `VOUCH_IDP_<SLUG>_EMAIL_ATTRIBUTE` to your IdP's attribute name |

For domain-based enrollment restrictions, set `VOUCH_IDP_<SLUG>_DOMAIN_ATTRIBUTE` to the attribute name containing the user's domain. If not set, the domain is extracted from the email address.

## NameID Stability

Vouch binds accounts to the pair (IdP entity ID, NameID) — not to the email address — so
the NameID must be a stable identifier for the user (see
[Account linking](overview.md#account-linking-and-identity-binding)). Configure the IdP to
send a NameID with one of these formats:

- `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`
- `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`

Vouch binds **only** these two formats. Any other format — `transient` (a fresh value on
every login), `unspecified`, a vendor-specific URN, or a NameID sent with no `Format`
attribute — is treated as potentially rotating and is **not** bound: Vouch skips identity
binding for that sign-in and falls back to email-only account matching, logging a warning.
This keeps such deployments working, but they do not get the reassignment protection that
identity binding provides — switch the IdP to `persistent` or `emailAddress` to enable it.

## Configuration Example

```bash
VOUCH_IDPS=corp-saml

VOUCH_IDP_CORP_SAML_TYPE=saml
VOUCH_IDP_CORP_SAML_METADATA_URL=https://login.microsoftonline.com/{tenant-id}/federationmetadata/2007-06/federationmetadata.xml
VOUCH_IDP_CORP_SAML_SP_ENTITY_ID=https://auth.example.com
VOUCH_IDP_CORP_SAML_EMAIL_ATTRIBUTE=http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress

VOUCH_ALLOWED_DOMAINS=example.com
```

### S3 configuration

```json
{
  "idps": [
    {
      "id": "corp-saml",
      "type": "saml",
      "metadata_url": "https://login.microsoftonline.com/{tenant-id}/federationmetadata/2007-06/federationmetadata.xml",
      "sp_entity_id": "https://auth.example.com",
      "email_attribute": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
    }
  ]
}
```

## Provider-Specific Notes

### Microsoft Entra ID

- Metadata URL: `https://login.microsoftonline.com/{tenant-id}/federationmetadata/2007-06/federationmetadata.xml`
- Email attribute: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`
- Create an Enterprise Application with SAML SSO and set the ACS URL to `https://auth.example.com/saml/acs`

### Okta

- Metadata URL: found in the Okta SAML app's **Sign On** tab under **Metadata URL**
- Email attribute: typically `email` or configure in the Okta attribute statements
- Set the Single Sign-On URL to `https://auth.example.com/saml/acs` and Audience URI to your SP entity ID

### Google Workspace

- Metadata URL: available from the Google Admin console under **Apps > Web and mobile apps > SAML app > Metadata**
- Email attribute: `email` (configure in attribute mapping)
- Add a custom SAML app in the Admin console with ACS URL `https://auth.example.com/saml/acs`

## Troubleshooting

**"Failed to fetch SAML IdP metadata"**
- Verify the metadata URL is correct and reachable from the server
- Check that the URL returns valid XML (not an HTML login page)
- Ensure the server can make outbound HTTPS requests

**Signature verification errors**
- Confirm the IdP's signing certificate in the metadata is current and not expired
- Ensure the server clock is synchronized (NTP). SAML assertions have time-based validity windows.

**Email not extracted from assertion**
- Check the SAML assertion attributes using debug logging (`RUST_LOG=vouch_server=debug`)
- Set `VOUCH_IDP_<SLUG>_EMAIL_ATTRIBUTE` to the exact attribute name used by your IdP
