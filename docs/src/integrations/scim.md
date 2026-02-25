# SCIM Provisioning

Vouch supports SCIM 2.0 (RFC 7643/7644) for user provisioning and de-provisioning from external identity providers. SCIM is a **launch requirement** for enterprise deployments.

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
- Token generated in Vouch admin portal per external IdP
- Tokens are long-lived but can be rotated/revoked
- Separate token per IdP integration (Okta, Azure AD, etc.)

```bash
# Example SCIM request from Okta
curl -X DELETE https://vouch.example.com/scim/v2/Users/usr_abc123 \
  -H "Authorization: Bearer scim_token_xyz789" \
  -H "Content-Type: application/scim+json"
```

**Token Security**:
- Tokens are hashed (SHA-256) before storage
- Shown once at creation, never retrievable after
- Bound to specific IdP and IP allowlist (optional)
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
