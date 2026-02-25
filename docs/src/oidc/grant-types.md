# Grant Types

This chapter describes the OAuth 2.0 grant types, scopes, and client authentication methods supported by Vouch.

## Supported Grant Types

| Grant Type | Use Case |
|------------|----------|
| `authorization_code` (with PKCE) | Web and native applications |
| `urn:ietf:params:oauth:grant-type:device_code` | CLI tools, headless devices (RFC 8628) |
| `urn:ietf:params:oauth:grant-type:token-exchange` | Service-to-service delegation (RFC 8693) |
| `urn:ietf:params:oauth:grant-type:jwt-bearer` | Machine-to-machine, federated service auth (RFC 7523) |
| `urn:ietf:params:oauth:grant-type:fido2-assertion` | CLI FIDO2 login (hardware key authentication) |

## Supported Scopes

| Scope | Claims Returned |
|-------|-----------------|
| `openid` | `sub`, `iss`, `aud`, `exp`, `iat` (required) |
| `profile` | `name`, `preferred_username` |
| `email` | `email`, `email_verified` |
| `hardware` | `hardware_verified`, `hardware_aaguid` (Vouch-specific) |

## Client Authentication Methods

| Method | Description |
|--------|-------------|
| `client_secret_basic` | HTTP Basic Auth with client_id:client_secret |
| `client_secret_post` | client_id and client_secret in request body |
| `none` | Public clients (native apps with PKCE) |
| `private_key_jwt` | JWT assertion signed with client's private key (RFC 7523) |
