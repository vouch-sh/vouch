# JWT Bearer (RFC 7523)

This chapter describes Vouch's implementation of the JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants, built on the assertion framework of RFC 7521.

Vouch implements two capabilities from RFC 7523:

## JWT Bearer Authorization Grant

External services exchange a signed JWT assertion for a Vouch access token, enabling machine-to-machine authentication without browser-based flows.

Token endpoint request:
```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
&assertion=eyJhbGciOiJFUzI1NiIs...
&scope=openid email
```

JWT assertion claim requirements:
- `iss` — Issuer (must match a configured trusted issuer)
- `sub` — Subject (mapped to a Vouch user via trusted issuer configuration)
- `aud` — Audience (must be the Vouch token endpoint URL)
- `exp` — Expiration (must not exceed the trusted issuer's max lifetime)
- `iat` — Issued at
- `jti` — Unique token ID (for replay prevention)

Trusted issuers are configured per-organization with: issuer URL, JWKS URI for signature verification, subject-to-user mapping rules, allowed scopes, and maximum assertion lifetime.

Example response:
```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 28800
}
```

## JWT Client Authentication (`private_key_jwt`)

OAuth clients authenticate at the token endpoint using a signed JWT assertion instead of a shared client secret. This is used in combination with other grant types (e.g., authorization code, token exchange).

Request format:
```
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiIs...
```

JWT requirements: `iss` and `sub` must equal the `client_id`, `aud` must be the token endpoint URL. Clients configure their public keys via inline `jwks` or a `jwks_uri` on the client registration.

## Security

- Only ES256, RS256, and PS256 algorithms are accepted (no HMAC, no `none`)
- JTI-based replay prevention with server-side tracking
- JWKS responses are cached (1-hour TTL, 24-hour maximum staleness)
- JWKS URIs must use HTTPS
- Maximum assertion lifetime enforced per trusted issuer configuration
