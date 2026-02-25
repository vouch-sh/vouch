# Endpoints and Discovery

This chapter lists the standard OIDC and OAuth 2.0 endpoints exposed by the Vouch server.

## Standard OIDC Endpoints

- `GET /.well-known/openid-configuration` — Discovery document (RFC 8414)
- `GET /oauth/jwks` — Public keys for token verification (RFC 7517)
- `GET /oauth/authorize` — Authorization endpoint
- `POST /oauth/token` — Token issuance (device code, authorization code, token exchange, JWT bearer)
- `POST /oauth/revoke` — Token revocation (RFC 7009)
- `POST /oauth/introspect` — Token introspection (RFC 7662)
- `POST /oauth/par` — Pushed Authorization Requests (RFC 9126)
- `POST /oauth/register` — Dynamic Client Registration (RFC 7591)
- `GET /oauth/userinfo` — User info endpoint
