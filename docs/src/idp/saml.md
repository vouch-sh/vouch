# SAML 2.0

Configure a SAML 2.0 identity provider for Vouch enrollment. Vouch acts as a SAML Service Provider (SP) with HTTP-POST and HTTP-Redirect bindings.

> **SAML and OIDC are mutually exclusive.** Configure one or the other, not both. If both `VOUCH_OIDC_ISSUER` and `VOUCH_SAML_IDP_METADATA_URL` are set, the server will refuse to start.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VOUCH_SAML_IDP_METADATA_URL` | Yes | _(none)_ | URL to the IdP's SAML metadata XML document. Fetched at server startup. |
| `VOUCH_SAML_SP_ENTITY_ID` | No | `{VOUCH_BASE_URL}` | SP entity ID sent in authentication requests. Defaults to the server's base URL. |
| `VOUCH_SAML_EMAIL_ATTRIBUTE` | No | _(auto-detect)_ | SAML attribute name containing the user's email address. |
| `VOUCH_SAML_DOMAIN_ATTRIBUTE` | No | _(none)_ | SAML attribute name containing the user's domain (for domain restriction). |

## SP Metadata

The Vouch server exposes SP metadata for configuring your IdP:

```
GET https://auth.example.com/saml/metadata
```

This returns an XML document containing the SP entity ID, Assertion Consumer Service (ACS) URL, and supported bindings. Import this into your IdP or configure the following values manually:

- **SP Entity ID**: `https://auth.example.com` (or the value of `VOUCH_SAML_SP_ENTITY_ID`)
- **ACS URL**: `https://auth.example.com/saml/acs`
- **Bindings**: HTTP-POST (ACS), HTTP-Redirect (AuthnRequest)

## Attribute Mapping

Vouch extracts user identity from SAML assertion attributes. By default, it looks for the email address in common attribute names. You can override this with `VOUCH_SAML_EMAIL_ATTRIBUTE`:

| Use Case | Attribute Example |
|----------|-------------------|
| Standard email | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` |
| NameID | _(used automatically if no attribute match)_ |
| Custom | Set `VOUCH_SAML_EMAIL_ATTRIBUTE` to your IdP's attribute name |

For domain-based enrollment restrictions, set `VOUCH_SAML_DOMAIN_ATTRIBUTE` to the attribute name containing the user's domain. If not set, the domain is extracted from the email address.

## Configuration Example

```bash
VOUCH_SAML_IDP_METADATA_URL=https://login.microsoftonline.com/{tenant-id}/federationmetadata/2007-06/federationmetadata.xml
VOUCH_SAML_SP_ENTITY_ID=https://auth.example.com
VOUCH_SAML_EMAIL_ATTRIBUTE=http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
VOUCH_ALLOWED_DOMAINS=example.com
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
- Set `VOUCH_SAML_EMAIL_ATTRIBUTE` to the exact attribute name used by your IdP

**"Both OIDC and SAML are configured"**
- Only one upstream IdP protocol can be active. Remove either the `VOUCH_OIDC_*` or `VOUCH_SAML_*` variables.
