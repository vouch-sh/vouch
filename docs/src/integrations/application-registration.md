# Application Registration

Developers register their applications through a self-service portal to obtain OAuth client credentials for integrating with Vouch.

## Self-Service Portal

```
Web Portal → My Applications → Register New Application
```

## Registration Workflow

1. **Authenticate** — User logs into Vouch (with hardware key)
2. **Navigate** — Go to "My Applications" section
3. **Register** — Click "Register New Application"
4. **Configure** — Provide application details:
   - Application name (human-readable identifier)
   - Application type (web, native, SPA, service)
   - Redirect URIs (for authorization_code flow)
   - Resource URIs (optional, for audience-restricted tokens per RFC 8707)
   - Requested scopes
5. **Receive Credentials** — Vouch generates:
   - `client_id` — Public identifier for OAuth flows
   - `client_secret` — Secret for confidential clients (not shown for public clients)
6. **Manage** — View, rotate, or revoke credentials at any time

## Application Types

| Type | client_secret | PKCE Required | Use Case |
|------|---------------|---------------|----------|
| Web (confidential) | Yes | Recommended | Server-side web apps |
| Native | No | Required | Desktop/mobile apps |
| SPA | No | Required | Browser-only apps |
| Service | Yes | N/A | Machine-to-machine (future) |

## Credential Management

Registered applications can be managed via the portal:
- **View** — See application details and usage statistics
- **Rotate** — Generate new client_secret (old secret immediately revoked)
- **Revoke** — Immediately invalidate all tokens for an application
- **Delete** — Remove the application registration entirely

## Programmatic Registration (RFC 7591)

Applications can also be registered programmatically via `POST /oauth/register` (RFC 7591 Dynamic Client Registration). The CLI uses this for automatic FAPI client registration on first use.

## API Access (Future)

Registered applications can also be managed programmatically:
```bash
# List applications
curl -H "Authorization: Bearer $TOKEN" https://vouch.example.com/api/v1/applications

# Create application
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "My App", "type": "web", "redirect_uris": ["https://myapp.com/callback"]}' \
  https://vouch.example.com/api/v1/applications
```
