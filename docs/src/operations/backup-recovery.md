# Backup and Recovery

## What to Back Up

| Component | Criticality | Recovery Impact |
|-----------|-------------|-----------------|
| Database | Critical | Loss of user registrations, sessions, authenticator records |
| SSH CA private key | Critical | Must re-distribute new CA public key to all hosts |
| OIDC signing key | High | Token verification fails until new key distributed |
| JWT secret | High | All sessions invalidated on change |
| TLS certificate & key | Medium | Service unavailable until replaced |
| Server configuration | Medium | Can be reconstructed from documentation |

## Backup Strategy

### Database

**SQLite:**
```bash
# Simple file copy (stop writes first or use backup API)
cp /data/vouch.db /backup/vouch.db.$(date +%Y%m%d_%H%M%S)

# Or use SQLite backup command (safe during writes)
sqlite3 /data/vouch.db ".backup '/backup/vouch.db.backup'"
```

**PostgreSQL:**
```bash
pg_dump -Fc vouch > /backup/vouch.$(date +%Y%m%d_%H%M%S).dump
```

**Frequency**: Daily minimum. More frequent for high-activity deployments.

### Cryptographic Keys

Back up all keys to a secure, offline location:

```bash
# SSH CA key
cp ssh_ca_key /secure-backup/ssh_ca_key

# OIDC signing key
cp oidc_signing_key.pem /secure-backup/oidc_signing_key.pem
```

Store key backups:
- Encrypted at rest
- In a separate location from the server
- With restricted access (minimum two-person rule for production)

## Recovery Procedures

### Full Server Recovery

1. **Deploy new server** with the same configuration
2. **Restore database** from backup
3. **Restore cryptographic keys** (SSH CA, OIDC signing, JWT secret)
4. **Start the server** — migrations run automatically if needed
5. **Verify**: `curl https://auth.example.com/health`

### Lost SSH CA Key

If the SSH CA key is lost and no backup exists:

1. Generate a new SSH CA key
2. Distribute the new public key to all SSH hosts
3. Configure Vouch with the new key
4. All users must run `vouch login` to get new certificates

### Lost JWT Secret

If the JWT secret changes (lost or compromised):

1. Set the new `VOUCH_JWT_SECRET`
2. Restart the server
3. All existing sessions are invalidated
4. Users must run `vouch login` again

### Database Corruption

1. Stop the server
2. Restore from backup
3. Users who enrolled after the backup will need to re-enroll
4. Start the server

## Disaster Recovery Testing

Periodically test your recovery procedures:

1. Restore a database backup to a test environment
2. Start a test server with production keys
3. Verify enrollment, login, and credential flows
4. Document any issues and update procedures
