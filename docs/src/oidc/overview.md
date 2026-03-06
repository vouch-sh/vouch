# OIDC Overview

Vouch is a **fully OIDC-compliant identity provider**, implementing OAuth 2.0 and OpenID Connect specifications. Any application can integrate using off-the-shelf OIDC libraries — no Vouch SDK required.

## Standards Compliance

- OAuth 2.0 (RFC 6749)
- OpenID Connect Core 1.0
- OAuth 2.0 Authorization Server Metadata (RFC 8414)
- OAuth 2.0 Device Authorization Grant (RFC 8628)
- Proof Key for Code Exchange (PKCE, RFC 7636)
- OAuth 2.0 Token Revocation (RFC 7009)
- OAuth 2.0 Token Introspection (RFC 7662)
- OAuth 2.0 Token Exchange (RFC 8693)
- Assertion Framework for OAuth 2.0 (RFC 7521)
- JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants (RFC 7523)
- Authentication Method Reference Values (RFC 8176)
- JWT Best Current Practices (RFC 8725) — explicit `typ` headers, issuer/audience validation
- JWT Profile for OAuth 2.0 Access Tokens (RFC 9068) — including `amr`/`acr` claims
- OAuth 2.0 Authorization Server Issuer Identification (RFC 9207)
- SCIM 2.0 (RFC 7643/7644)
- Resource Indicators for OAuth 2.0 (RFC 8707) — audience-restricted tokens
- JWT-Secured Authorization Request (RFC 9101) — signed Request Objects for authorization requests (FAPI 2.0 compatible)
- Pushed Authorization Requests (RFC 9126) — server-side parameter storage
- DPoP (RFC 9449) — Demonstrating Proof of Possession
- Step Up Authentication Challenge Protocol (RFC 9470) — `acr_values` and `max_age` in authorization requests
- OAuth 2.0 Security Best Current Practice (RFC 9700) — followed
- Rich Authorization Requests (RFC 9396) — fine-grained `authorization_details` beyond scopes
- OAuth 2.0 Dynamic Client Registration (RFC 7591) — programmatic client registration

## Why OIDC

- Standard protocol, works with any language/framework
- No vendor lock-in - apps can switch IdPs later
- JWT tokens can be verified offline with public keys
- Existing libraries handle all the complexity
