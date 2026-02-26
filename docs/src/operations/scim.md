# SCIM Provisioning

Vouch supports SCIM 2.0 (RFC 7643/7644) for user provisioning and de-provisioning from external identity providers. SCIM is a **launch requirement** for enterprise deployments.

## Setup

The admin API endpoints (`/api/v1/org/*`) require an authenticated Vouch session from a user with org admin privileges. The server accepts the access token via `Authorization: Bearer <token>`, `Authorization: DPoP <token>`, or the `vouch_session` cookie.

**Prerequisites:**
- Your user account must have the `is_org_admin` flag set in the database
- You must be assigned to an organization (`org_id`)

### 1. Create a SCIM token

Log in with `vouch login`, then create a SCIM token using the cookie file or token command:

```bash
# Using cookie file (written automatically on login)
curl -X POST https://auth.example.com/api/v1/org/scim-tokens \
  -b ~/.vouch/cookie.txt \
  -H "Content-Type: application/json" \
  -d '{"description": "SCIM integration", "expires_in_days": 90}'

# Or using the token command
curl -X POST https://auth.example.com/api/v1/org/scim-tokens \
  -H "Authorization: Bearer $(vouch credential token)" \
  -H "Content-Type: application/json" \
  -d '{"description": "SCIM integration", "expires_in_days": 90}'
```

The response includes a token prefixed `vouch_scim_...`. This token is shown once and cannot be retrieved again.

### 2. Configure your IdP

Enter the following in your IdP's SCIM configuration:
- **SCIM endpoint URL**: `https://auth.example.com/scim/v2/`
- **Bearer token**: the `vouch_scim_...` token from step 1

### 3. Manage tokens

```bash
# List active SCIM tokens
curl -b ~/.vouch/cookie.txt \
  https://auth.example.com/api/v1/org/scim-tokens

# Revoke a SCIM token
curl -X DELETE -b ~/.vouch/cookie.txt \
  https://auth.example.com/api/v1/org/scim-tokens/<token-id>
```

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

```rust
// SCIM de-provision handling (DELETE /scim/v2/Users/:id)
async fn delete_user(user_id: &str) -> Result<()> {
    // 1. Invalidate all active sessions immediately
    db::delete_sessions_for_user(&db, user_id).await?;

    // 2. Revoke all SSH certificates for this user
    db::revoke_all_ssh_certificates_for_user(&db, user_id, Some("User deleted via SCIM"), Some("scim")).await?;

    // 3. Delete user (cascades to authenticators)
    db::delete_user(&db, user_id).await?;

    // 4. Log audit event
    db::insert_scim_audit(&db, "delete", "User", user_id, Some(&token_id), Some(&details)).await?;

    Ok(())
}
```

## SCIM Endpoint Authentication

SCIM endpoints require bearer token authentication:

**Endpoint**: `POST /scim/v2/Users`, `DELETE /scim/v2/Users/:id`, etc.

**Authentication**:
- Bearer token in `Authorization` header
- Token generated via the admin API (`POST /api/v1/org/scim-tokens`)
- Tokens are long-lived but can be rotated/revoked
- Separate token per IdP integration

```bash
# Example SCIM request
curl -X DELETE https://vouch.example.com/scim/v2/Users/usr_abc123 \
  -H "Authorization: Bearer scim_token_xyz789" \
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
| De-provisioning | Immediate via IdP (user deleted, sessions invalidated, certs revoked) | Manual admin action |
| Group membership | Synced from IdP | Not available outside SCIM |

**Note**: SCIM pre-provisioning creates a user record, but they still cannot authenticate until they physically enroll a hardware FIDO2 authenticator. The security model remains: no credential without hardware.
