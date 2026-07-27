# SCIM Provisioning

Vouch supports SCIM 2.0 (RFC 7643/7644) for user provisioning and de-provisioning from external identity providers. SCIM is a **launch requirement** for enterprise deployments.

## Setup

The admin API endpoints (`/api/v1/org/*`) require an authenticated Vouch session from a user with org admin privileges. The server accepts the access token via `Authorization: Bearer <token>`, `Authorization: DPoP <token>`, or the `vouch_session` cookie.

**Prerequisites:**
- You must belong to an organization and be an org administrator.

You do not create either by hand. Organizations are created automatically the first time someone
enrolls from a given email domain, and that first enrollee becomes the organization's
administrator. Every administrator after that is promoted from the admin UI. See
[Organizations and Administrators](organizations.md) for the full model.

### 1. Create a SCIM token

The simplest way is the admin UI: go to **`/admin/scim-tokens`**, create a token, and copy it.
Choose an expiry between 1 and 365 days.

To script it instead, call the API with an access token from an admin session:

```bash
curl -X POST https://auth.example.com/api/v1/org/scim-tokens \
  -H "Authorization: Bearer $(vouch credential token)" \
  -H "Content-Type: application/json" \
  -d '{"description": "SCIM integration", "expires_in_days": 90}'
```

Either way the token is prefixed `vouch_scim_` and is **shown once**. It is stored only as a
SHA-256 hash, so it cannot be recovered — if you lose it, revoke it and create another.

### 2. Configure your IdP

Enter the following in your IdP's SCIM configuration:
- **SCIM endpoint URL**: `https://auth.example.com/scim/v2/`
- **Bearer token**: the `vouch_scim_...` token from step 1

### 3. Manage tokens

List and revoke tokens at `/admin/scim-tokens`, or through the API:

```bash
# List active SCIM tokens
curl -H "Authorization: Bearer $(vouch credential token)" \
  https://auth.example.com/api/v1/org/scim-tokens

# Revoke a SCIM token
curl -X DELETE -H "Authorization: Bearer $(vouch credential token)" \
  https://auth.example.com/api/v1/org/scim-tokens/<token-id>
```

Revocation takes effect immediately — tokens are checked against the database on every request.
Expired tokens are removed by the background cleanup task.

## De-Provisioning Behavior

When a user is de-provisioned via SCIM (e.g., employee leaves the organization):

| Action | Timing | Effect |
|--------|--------|--------|
| Active sessions invalidated | Immediate | All current sessions for the user are terminated |
| SSH certificates revoked | Immediate | All issued SSH certificates are marked as revoked |
| Enrolled authenticators deleted | Immediate | All registered credentials are removed (cascade) |
| User record deleted | Immediate | User cannot re-enroll or authenticate |
| Audit event logged | Immediate | De-provisioning recorded with SCIM token info |

**Key principle**: De-provisioning is immediate and complete. When someone leaves via SCIM, they lose all Vouch access instantly — no waiting for session expiration.

## SCIM Endpoint Authentication

SCIM endpoints require bearer token authentication:

**Endpoint**: `POST /scim/v2/Users`, `DELETE /scim/v2/Users/:id`, etc.

**Authentication**:
- Bearer token in the `Authorization` header
- Token created in the admin UI or via `POST /api/v1/org/scim-tokens`
- Expiry is operator-chosen at creation, between 1 and 365 days
- Use a separate token per IdP integration, so one can be revoked without disturbing the others

```bash
# Example SCIM request
curl -X DELETE https://auth.example.com/scim/v2/Users/usr_abc123 \
  -H "Authorization: Bearer vouch_scim_..." \
  -H "Content-Type: application/scim+json"
```

**Token Security**:
- Tokens are hashed (SHA-256) before storage
- Shown once at creation, never retrievable after
- Bound to specific organization
- Minimum 256 bits of entropy

## SCIM Audit Logging

All SCIM operations are logged for compliance and security monitoring:

| Operation | Resource Type | Logged Data |
|-----------|--------------|-------------|
| `create` | `User` | resource_id, email, scim_token_id, timestamp |
| `update` | `User` | resource_id, scim_token_id, timestamp |
| `delete` | `User` | resource_id, email, scim_token_id, timestamp |
| `create` | `Group` | resource_id, display_name, scim_token_id, timestamp |
| `update` | `Group` | resource_id, scim_token_id, timestamp |
| `delete` | `Group` | resource_id, scim_token_id, timestamp |

## SCIM vs Manual Enrollment

| Aspect | SCIM Provisioning | Manual Enrollment |
|--------|-------------------|-------------------|
| User record creation | IdP pushes user info | User initiates enrollment |
| Hardware enrollment | Still requires physical hardware key | Requires physical hardware key |
| De-provisioning | Immediate via IdP (user deleted, sessions invalidated, certs revoked) | Manual admin action (sessions invalidated, certs revoked) |
| Group membership | Synced from IdP | Not available outside SCIM |

**Note**: SCIM pre-provisioning creates a user record, but they still cannot authenticate until they physically enroll a hardware FIDO2 authenticator. The security model remains: no credential without hardware.
