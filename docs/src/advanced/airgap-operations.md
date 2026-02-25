# Operations

This chapter covers the day-to-day operational procedures for maintaining a Vouch deployment in an air-gapped environment, including time synchronization, software updates, audit log export, disaster recovery, and troubleshooting.

## Time Synchronization

Certificate validity depends on accurate time. Options for air-gapped networks:

### GPS Time Receiver (Recommended)

```
+----------------+     +--------------------+
| GPS Receiver   |---->| Internal NTP       |
| (one-way data) |     | Server (stratum 1) |
+----------------+     +--------------------+
         |                      |
         |                      v
    One-way only         All internal hosts
    (no data out)
```

Configure NTP clients:
```bash
# /etc/ntp.conf
server ntp.internal iburst
```

### Manual Time Sync

For truly isolated networks without GPS:

1. Reference time from secure source (atomic clock, verified external)
2. Set time on NTP server manually
3. Document time sync in audit log

Vouch server configuration is done via environment variables (see [Configure Vouch Server](airgap-installation.md#step-6-configure-vouch-server)). JWT clock skew tolerance is handled automatically.

## Software Updates

### Update Procedure

1. **Download updated packages** (connected environment)
```bash
# Download latest packages from packages.vouch.sh
curl -LO https://packages.vouch.sh/rpm/x86_64/vouch-server-1.1.0-1.x86_64.rpm
curl -LO https://packages.vouch.sh/rpm/x86_64/vouch-1.1.0-1.x86_64.rpm

# For container deployments
docker pull ghcr.io/vouch-sh/vouch:1.1.0
docker save ghcr.io/vouch-sh/vouch:1.1.0 -o vouch-server-1.1.0.tar
```

2. **Verify signatures** (connected environment)
```bash
rpm -K vouch-server-1.1.0-1.x86_64.rpm
rpm -K vouch-1.1.0-1.x86_64.rpm
```

3. **Transfer via approved media** (sneakernet)

4. **Verify again** (air-gapped environment)
```bash
rpm -K vouch-server-1.1.0-1.x86_64.rpm
sha256sum -c SHA256SUMS
```

5. **Apply update**

For RPM installations:
```bash
# Backup database before upgrade
cp /data/vouch.db /data/vouch.db.backup.$(date +%Y%m%d)

# Upgrade package (migrations run automatically on next startup)
rpm -Uvh vouch-server-1.1.0-1.x86_64.rpm

# Restart service
systemctl restart vouch-server

# Verify health
curl -k https://auth.internal/health
```

For container deployments:
```bash
docker load < vouch-server-1.1.0.tar
# Update docker-compose.yml image tag, then:
docker-compose up -d
```

### Rollback

For RPM installations:
```bash
# Restore database backup
cp /data/vouch.db.backup.YYYYMMDD /data/vouch.db

# Downgrade package
rpm -Uvh --oldpackage vouch-server-1.0.0-1.x86_64.rpm

# Restart service
systemctl restart vouch-server
```

## Audit Log Export

Air-gapped environments still need audit trails for compliance.

### One-Way Data Diode

```
+-----------------+     +-------------+     +-----------------+
| Air-Gapped      |---->| Data Diode  |---->| SIEM            |
| Vouch Server    |     | (hardware)  |     | (connected)     |
|                 |     |             |     |                 |
| UDP syslog out  |     | One-way     |     | Splunk/Datadog  |
+-----------------+     +-------------+     +-----------------+
```

Syslog export is planned but not yet implemented. Currently, use the periodic export method below.

### Periodic Export

```bash
#!/bin/bash
# Weekly audit log export script

DATE=$(date +%Y%m%d)
OUTPUT_DIR=/mnt/export

# Export audit logs from SQLite directly
sqlite3 /data/vouch.db \
  ".mode json" \
  "SELECT * FROM auth_events WHERE created_at >= datetime('now', '-7 days');" \
  > $OUTPUT_DIR/audit-$DATE.json

# Encrypt for transport
gpg --encrypt --recipient auditor@company.com \
  $OUTPUT_DIR/audit-$DATE.json

# Generate checksum
sha256sum $OUTPUT_DIR/audit-$DATE.json.gpg > $OUTPUT_DIR/audit-$DATE.sha256

# Remove unencrypted
rm $OUTPUT_DIR/audit-$DATE.json

echo "Export complete: audit-$DATE.json.gpg"
```

Transfer encrypted exports via approved media to connected compliance systems.

## Disaster Recovery

### Backup Strategy

| Component | Frequency | Method | Retention |
|-----------|-----------|--------|-----------|
| SQLite database | Daily | File copy, encrypted | 90 days |
| SSH CA keys | On change | HSM backup or split custody | Permanent |
| Configuration | On change | Git (internal) | Permanent |
| Audit logs | Continuous | Append-only storage | Per policy |

### Recovery Procedure

1. **Stop the service**
```bash
systemctl stop vouch-server
```

2. **Restore database from backup**
```bash
cp /data/vouch.db.backup.YYYYMMDD /data/vouch.db
chown vouch:vouch /data/vouch.db
```

3. **Re-sync time**
```bash
# Verify NTP synchronization
timedatectl status
chronyc tracking  # or ntpq -p
```

4. **Start and validate**
```bash
systemctl start vouch-server
curl -k https://auth.internal/health
```

### CA Key Recovery

If CA keys are lost, all issued certificates become unverifiable.

**Prevention:**
- Store CA keys in HSM with backup
- Use split-knowledge for key recovery
- Document key ceremony procedures

**Recovery:**
1. Generate new CA from backup
2. Re-provision all user credentials
3. Redistribute new CA public key
4. Update all SSH server trust anchors

## Security Considerations

### Network Segmentation

```
+-------------------------------------------------------------+
|                    Air-Gapped Network                        |
|                                                              |
|  +-----------------+        +-----------------------------+  |
|  |   Management    |        |      User Network           |  |
|  |   VLAN          |        |                             |  |
|  |                 |        |  +-------+  +-----------+   |  |
|  |  * Vouch Server |<------>|  |Workst.|  | Protected |   |  |
|  |  * SQLite       |        |  +-------+  | Resources |   |  |
|  |                 |        |             +-----------+   |  |
|  +-----------------+        +-----------------------------+  |
|           |                                                  |
|           | Restricted                                       |
|           v                                                  |
|  +-----------------+                                         |
|  | Admin Jumpbox   | <-- Physical access control             |
|  +-----------------+                                         |
+--------------------------------------------------------------+
```

### Physical Security

- Server room access controls
- YubiKey storage procedures
- Media transfer protocols
- Tamper-evident logging

### Compliance Mapping

| Requirement | NIST 800-53 | Implementation |
|-------------|-------------|----------------|
| Hardware auth | IA-2(1) | FIDO2 with YubiKey |
| Credential lifetime | IA-5(1) | 8-hour certificates |
| Audit logging | AU-2, AU-3 | All credential issuance logged |
| Time sync | AU-8 | GPS/NTP infrastructure |
| Key management | SC-12 | HSM or split-custody |

## Troubleshooting

### Cannot Connect to Vouch Server

```bash
# Check network connectivity
ping auth.internal

# Verify TLS
openssl s_client -connect auth.internal:443 -CAfile /etc/vouch/root-ca.crt

# Check server logs (systemd)
journalctl -u vouch-server --since "1 hour ago"

# Check server logs (Docker)
docker-compose logs vouch-server
```

### Certificate Validation Failures

```bash
# Check system time
date
timedatectl status

# Verify CA is trusted
ssh-keygen -L -f /path/to/cert  # View certificate details

# Check certificate dates
ssh-keygen -L -f /path/to/cert | grep Valid
```

### YubiKey Not Recognized

```bash
# Check USB connection
lsusb | grep Yubico

# Verify FIDO2 functionality
ykman fido info

# Reset FIDO2 application (destructive - re-enrollment required)
ykman fido reset
```
