# Token Format and Claims

This chapter describes the structure and claims of ID tokens and access tokens issued by Vouch.

## ID Token Claims

```json
{
  "iss": "https://vouch.yourcompany.com",
  "sub": "user@company.com",
  "email": "user@company.com",
  "email_verified": true,
  "hardware_verified": true,
  "hardware_aaguid": "2fc0579f-8113-47ea-b116-bb5a8db9202a",
  "amr": ["hwk", "pin", "user"],
  "acr": "urn:nist:authentication:assurance-level:aal3",
  "at_hash": "fUHyO2r2Z3DZ53EsNrWBb0",
  "iat": 1737849600,
  "exp": 1737878400
}
```

## Standard Claims (RFC 9068/8176)

- `amr` — Authentication methods used: `hwk` (hardware key), `pin`, `user` (presence) per RFC 8176
- `acr` — Authentication context class: NIST AAL3 (hardware multi-factor)
- `at_hash` — Access token hash (OIDC Core Section 3.1.3.6), present when issued alongside an access token

## Vouch-Specific Claims

- `hardware_verified: true` — Indicates hardware authentication was used
- `hardware_aaguid` — The AAGUID of the authenticator (identifies device model)

## Access Tokens

For access tokens (RFC 9068), `aud` validation is the resource server's responsibility per RFC 9068 Section 4.
