# Grant Types

This chapter describes the OAuth 2.0 grant types, scopes, and client authentication methods supported by Vouch.

## Supported Grant Types

| Grant Type | Use Case | Specification |
|------------|----------|---------------|
| `authorization_code` (with PKCE) | Web and native applications | [RFC 6749 §4.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) |
| `urn:ietf:params:oauth:grant-type:device_code` | CLI enrollment, headless devices | [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) (Device Authorization Grant) |
| `urn:ietf:params:oauth:grant-type:token-exchange` | Service-to-service delegation | [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) |
| `urn:ietf:params:oauth:grant-type:jwt-bearer` | Machine-to-machine, federated service auth | [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) |
| `urn:ietf:params:oauth:grant-type:fido2-assertion` | CLI FIDO2 login (hardware key authentication) | Vouch-specific (FAPI 2.0 flow with DPoP) |

## Supported Scopes

| Scope | Claims Returned | Specification |
|-------|-----------------|---------------|
| `openid` | `sub`, `iss`, `aud`, `exp`, `iat` (required) | [OpenID Connect Core §5.4](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims) |
| `email` | `email`, `email_verified` | [OpenID Connect Core §5.4](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims) |
| `hardware` | `hardware_verified`, `hardware_aaguid` | Vouch-specific |

## Client Authentication Methods

| Method | Description | Specification |
|--------|-------------|---------------|
| `client_secret_basic` | HTTP Basic Auth with client_id:client_secret | [RFC 6749 §2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1) |
| `client_secret_post` | client_id and client_secret in request body | [RFC 6749 §2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1) |
| `none` | Public clients (native apps with PKCE) | [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) |
| `private_key_jwt` | JWT assertion signed with client's private key | [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) |
