# Software Updates

## Update Procedure

### Pre-Update

1. **Read the release notes** for breaking changes
2. **Back up the database** before upgrading
3. **Test in staging** if possible

### Server Update

```bash
# Back up database
cp /data/vouch.db /data/vouch.db.pre-upgrade

# Update via package manager
sudo apt upgrade vouch-server    # Debian/Ubuntu
sudo dnf upgrade vouch-server    # RHEL/Fedora

# Or via Docker
docker pull ghcr.io/vouch-sh/vouch:latest
docker compose up -d

# Or via Helm
helm upgrade vouch-server oci://ghcr.io/vouch-sh/charts/vouch-server \
  --version <new-version> --namespace vouch

# Verify
curl -k https://auth.example.com/health
```

Database migrations run automatically on startup. No manual migration steps are needed.

### Client Update

```bash
# macOS
brew upgrade vouch

# Linux
sudo apt upgrade vouch    # Debian/Ubuntu
sudo dnf upgrade vouch    # RHEL/Fedora
```

### Rollback

If an update causes issues:

1. Stop the server
2. Restore the database from pre-upgrade backup
3. Install the previous version
4. Start the server

> **Note**: Database migrations may not be reversible. Always back up before upgrading.

## Version Compatibility

- The server is backward-compatible with older CLI versions
- Upgrade the server first, then clients
- Major version bumps may require simultaneous client updates (documented in release notes)

## Release Channels

| Channel | Stability | Use Case |
|---------|-----------|----------|
| `latest` | Stable releases | Production |
| `x.y.z` | Pinned version | Production (recommended) |
| `main` | Development builds | Testing only |
