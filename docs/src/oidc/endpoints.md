# Endpoints and Discovery

This chapter lists the standard OIDC and OAuth 2.0 endpoints exposed by the Vouch server.

## Standard OIDC Endpoints

- `GET /.well-known/openid-configuration` — Discovery document (RFC 8414)
- `GET /.well-known/oauth-authorization-server` — OAuth Authorization Server Metadata alias (RFC 8414 Section 3)
- `GET /oauth/jwks` — Public keys for token verification (RFC 7517)
- `GET /oauth/authorize` — Authorization endpoint
- `POST /oauth/token` — Token issuance (authorization code, device code, token exchange, JWT bearer, FIDO2 assertion)
- `POST /oauth/revoke` — Token revocation (RFC 7009)
- `POST /oauth/introspect` — Token introspection (RFC 7662)
- `POST /oauth/par` — Pushed Authorization Requests (RFC 9126)
- `POST /oauth/register` — Dynamic Client Registration (RFC 7591)
- `GET /oauth/register/{client_id}` — Read dynamic client registration (RFC 7591/7592)
- `GET|POST /oauth/userinfo` — User info endpoint (OIDC Core Section 5.3.1)
- `POST /oauth/device` — Device Authorization Grant (RFC 8628)
- `POST /oauth/fido2/challenge` — FIDO2 assertion challenge (Vouch-specific, used in FAPI 2.0 login flow)

## Credential Endpoints

- `POST /v1/credentials/ssh` — Issue SSH certificate (requires DPoP-bound access token)
- `GET /v1/credentials/ssh/ca` — SSH CA public key (unauthenticated)
- `GET /v1/credentials/ssh/krl` — SSH Key Revocation List (unauthenticated)
- `GET /v1/credentials/aws/token` — Exchange access token for AWS temporary credentials
- `POST /v1/credentials/github/token` — Exchange access token for GitHub token
