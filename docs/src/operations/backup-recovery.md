# Backup and Recovery

## What to Back Up

| Component | Criticality | Recovery Impact |
|-----------|-------------|-----------------|
| **Document encryption KMS key** | **Unrecoverable** | On an encrypted deployment, every stored document — including the entire audit history — becomes permanently unreadable. There is no regeneration path. |
| Database | Critical | Loss of user registrations, sessions, authenticator records |
| SSH CA private key | Critical | Must re-distribute new CA public key to all hosts |
| OIDC signing key (ES256) | High | Token verification fails until new key distributed |
| OIDC RSA signing key (RS256) | High | RS256 ID token verification fails until new key distributed |
| JWT secret | High | All sessions invalidated on change |
| TLS certificate & key | Medium | Service unavailable until replaced |
| Server configuration | Medium | Can be reconstructed from documentation |

> **The document encryption key is the one you cannot recover from.** Every other item on this list
> can be regenerated at some cost: issue a new SSH CA and redistribute it, generate new signing
> keys and make users log in again. Documents sealed by a deleted KMS customer master key are gone,
> and that includes the audit history you would need to reconstruct anything.
>
> It also fails in a way you will not notice: the server refuses to start, long after the key was
> scheduled for deletion. Enable KMS key deletion protection, and never delete a key that has ever
> sealed documents — even one you believe is unused.

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

# OIDC signing key (ES256)
cp oidc_signing_key.pem /secure-backup/oidc_signing_key.pem

# OIDC RSA signing key (RS256) — if configured
cp oidc_rsa_key.pem /secure-backup/oidc_rsa_key.pem
```

Store key backups:
- Encrypted at rest
- In a separate location from the server
- With restricted access (minimum two-person rule for production)

### Document encryption key

If your S3 configuration contains a `document_key` block, that block and the KMS key it names are
part of your backup set:

- **The KMS customer master key** cannot be exported. Protect it instead: enable deletion
  protection, enable automatic key rotation only if you understand the implications for existing
  ciphertext, and replicate it as a multi-region key if you run in more than one region.
- **The `document_key` block** in the S3 configuration holds the KMS-encrypted private key. Back it
  up with the rest of the configuration document; S3 versioning gives you this for free.

Both are required. The block without the KMS key is undecryptable, and the KMS key without the
block has nothing to decrypt.

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
3. Users who enrolled after the backup must re-enroll
4. Start the server

## Disaster Recovery Testing

Test the recovery procedures before you need them:

1. Restore a database backup to a test environment
2. Start a test server with production keys
3. Verify enrollment, login, and credential flows
4. Document any issues and update procedures
