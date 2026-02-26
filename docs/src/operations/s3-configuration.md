# S3 Configuration Storage

When using S3-based configuration, additional security considerations apply. This chapter covers bucket requirements, protected fields, polling behavior, and key encoding.

## S3 Bucket Requirements

| Requirement | Rationale |
|-------------|-----------|
| **Server-Side Encryption** | Config contains secrets (JWT secret, OIDC credentials, private keys) |
| **Block Public Access** | Config should never be publicly accessible |
| **IAM Least Privilege** | Server needs only `s3:GetObject` and `s3:HeadObject` |
| **Versioning** | Enables rollback and audit trail |
| **Access Logging** | Detect unauthorized access attempts |

**Recommended S3 Bucket Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/vouch-server"},
      "Action": ["s3:GetObject", "s3:HeadObject"],
      "Resource": "arn:aws:s3:::my-bucket/config/vouch-server.json"
    }
  ]
}
```

## Protected Configuration Fields

Only TLS certificates can be hot-reloaded at runtime via S3 polling. All other configuration fields are silently ignored during runtime S3 polling and require a server restart to take effect.

## S3 Polling Security

- **ETag-based polling** — HEAD request checks for changes before full GET
- **Fail-open on polling errors** — If S3 becomes unreachable during operation, server continues with current config
- **Fail-fast on startup** — If S3 is unreachable at startup when configured, server fails to start
- **No caching of stale config** — Config is only updated when successfully fetched and parsed

## Base64 Encoding for Keys

All private keys and certificates in S3 config must be base64-encoded:
- Standard base64 or URL-safe base64 accepted
- Prevents JSON parsing issues with PEM format
- Decoded and validated before use
