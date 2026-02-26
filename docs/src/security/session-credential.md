# Session and Credential Security

This chapter covers how Vouch secures session storage across different backends and the security properties of OAuth client credentials, including FAPI 2.0 token binding and revocation.

## Session Storage Security

Vouch stores access tokens in multiple locations with appropriate security controls:

### Config File (`~/.vouch/config.json`)

Fallback storage when agent is not running:

**Security Controls:**
- **File permissions**: 0600
- **Contents**: JWT token, server URL
- **Cleared**: On logout via `vouch logout`

### Agent Memory (Primary)

In-memory storage via IPC socket:

**Security Controls:**
- **Socket permissions**: 0700 on socket directory
- **Memory**: Uses `SecretString` with automatic zeroization
- **Lifetime**: Cleared on agent shutdown or explicit logout

## Client Credential Security

OAuth client credentials issued through the application management UI (`/applications`) or API (`/api/v1/applications`) follow strict security practices.

### Secret Storage

Client secrets are **never stored in plaintext**:

```rust
// Client secret handling
fn hash_secret(secret: &str) -> String {
    hex::encode(digest::digest(&SHA256, secret.as_bytes()))
}
```

**Storage Properties:**
| Property | Value |
|----------|-------|
| Algorithm | SHA-256 |
| Plaintext stored | Never |
| Reversible | No |

### Secret Generation

Client secrets are cryptographically random:

```rust
// 32 bytes = 256 bits of entropy
let secret = SecretString::new(base64url_encode(random_bytes(32)));
// Example: "dGhpcyBpcyBhIHNlY3VyZSByYW5kb20gc2VjcmV0"
```

**Properties:**
- 256 bits of entropy
- Base64url encoding (URL-safe, no padding)
- Shown once at creation, never retrievable after

### Secret Rotation

Client secrets can be rotated via the web UI (`/applications/{id}`) or API (`POST /api/v1/applications/{id}/rotate`):

```
1. User requests rotation via web UI or API
2. New secret generated and returned (shown once)
3. All old secrets are immediately revoked
4. Audit log records rotation event
```

**Note:** Rotation is immediate — old secrets are revoked as soon as the new secret is created. Applications must update their configuration before rotating.

### Scope Restrictions

Each registered application has scoped permissions:

```rust
struct OAuthClient {
    client_id: String,
    allowed_scopes: Vec<Scope>,        // Maximum scopes client can request
    allowed_redirect_uris: Vec<Url>,   // Validated redirect destinations
    allowed_resource_uris: Vec<Url>,   // Validated resource indicators (RFC 8707)
    token_lifetime: Duration,           // Maximum token lifetime
}
```

**Enforcement:**
- Token requests cannot exceed `allowed_scopes`
- Redirect URIs must exactly match registered values (no wildcards)
- Resource URIs must match a pre-registered value (closed by default)
- Tokens cannot exceed `token_lifetime` even if requested

### Resource Indicators (RFC 8707)

Vouch supports audience-restricted tokens via RFC 8707 Resource Indicators. When a client includes the `resource` parameter in an authorization or token request, the access token's `aud` claim is set to the target resource server URI instead of the `client_id`.

**Token Misdirection Prevention:**

Resource indicators prevent the confused deputy problem — where a malicious resource server replays a bearer token at a different service. With audience-restricted tokens, each token is bound to a specific resource server.

| Control | Description |
|---------|-------------|
| Pre-registration required | Resource URIs must be registered on the OAuth client before use |
| URI validation | Resource URIs must be absolute URIs without fragment components |
| Single resource per request | Only one `resource` value per request (prevents multi-audience tokens) |
| No scope widening at token time | The `resource` parameter at token exchange cannot differ from the authorization grant |
| `invalid_target` error | Unregistered or malformed resource URIs return a specific OAuth error code |

**Resource Narrowing Rules:**

| Authorization `resource` | Token `resource` | Result |
|--------------------------|------------------|--------|
| `https://api.example.com` | (omitted) | `aud` = `https://api.example.com` |
| `https://api.example.com` | `https://api.example.com` | `aud` = `https://api.example.com` |
| `https://api.example.com` | `https://other.example.com` | Error: `invalid_target` |
| (omitted) | `https://api.example.com` | Error: `invalid_target` |
| (omitted) | (omitted) | `aud` = `client_id` (default) |

**Open Policy for Unregistered Clients:**

If an OAuth client has no resource URIs registered, the `resource` parameter is not validated against a list — any valid URI is accepted. This allows gradual adoption without breaking existing clients. Register resource URIs to enforce a closed allowlist.

### Audit Logging

All client credential operations are logged:

| Event | Logged Data |
|-------|-------------|
| `client_created` | client_id, owner, allowed_scopes, created_at |
| `client_updated` | client_id, changed_fields, updated_by, updated_at |
| `secret_rotated` | client_id, rotated_by, rotated_at |
| `client_revoked` | client_id, revoked_by, tokens_invalidated_count, revoked_at |
| `client_deleted` | client_id, deleted_by, deleted_at |
| `token_issued` | client_id, user_id (if applicable), scopes, expires_at |
| `token_rejected` | client_id, reason, requested_scopes |

**Log Entry Example:**
```json
{
  "timestamp": "2024-01-14T10:32:15.123Z",
  "event_type": "secret_rotated",
  "client": {
    "id": "cli_abc123",
    "name": "My Application"
  },
  "actor": {
    "user_id": "usr_xyz789",
    "email": "developer@company.com"
  },
  "details": {
    "reason": "scheduled_rotation"
  }
}
```

### FAPI 2.0 Security Properties

The CLI operates as a FAPI 2.0 client with strong security guarantees:

**CLI Key Security:**
- ES256 key pair stored in the OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager) with file fallback
- Used for `private_key_jwt` client authentication (RFC 7523) and DPoP proofs (RFC 9449)
- No shared secrets between CLI and server — only the public key is registered

**DPoP Sender Constraint:**
- Access tokens are bound to the client's DPoP key via the `cnf.jkt` claim
- Token theft without the corresponding DPoP key is useless — the server rejects requests where the DPoP proof doesn't match the token binding
- Each DPoP proof includes `jti` (unique identifier), `iat` (issuance time), and `htu`/`htm` (target URL/method)

**Private Key JWT:**
- Client authentication uses `private_key_jwt` (RFC 7523) — the CLI signs a JWT assertion with its ES256 private key
- The server verifies the assertion against the registered public key
- Eliminates shared client secrets entirely for CLI authentication

**FAPI Interaction ID:**
- Every request carries an `x-fapi-interaction-id` header for end-to-end tracing
- Enables correlation of client requests with server-side audit logs

### Token Security

All access tokens are ES256 JWTs following RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens). Legacy HS256 tokens are permanently rejected. Tokens issued to OAuth clients follow security best practices:

**Access Tokens:**
- Short-lived (default: 1 hour, max: 8 hours)
- ES256 JWT format with standard claims (RFC 9068)
- Bound to client_id and user (if applicable)
- DPoP-bound when issued to FAPI clients (sender-constrained)
- Include `hardware_verified` claim when backed by hardware authenticator session

**Refresh Tokens:**
- Not issued in the standard OIDC token exchange flow
- GitHub OAuth refresh tokens are stored per-user for refreshing GitHub access tokens

### Revocation

Applications can be immediately revoked:

```
POST /api/v1/applications/:id/revoke
```

**Revocation Effects:**
1. All access tokens immediately invalidated
2. All refresh tokens immediately invalidated
3. Client secret marked as revoked
4. New token requests rejected
5. Audit log records revocation
