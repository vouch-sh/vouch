# Key Management

Vouch uses several cryptographic keys. This page covers their lifecycle and rotation.

## Key Inventory

| Key | Algorithm | Purpose | Storage |
|-----|-----------|---------|---------|
| SSH CA Key | Ed25519 | Signs SSH user certificates | File, env var, S3 config, or KMS |
| OIDC Signing Key | P-256 EC (ES256) | Signs access tokens and ID tokens (default) | Env var, S3 config, or KMS |
| OIDC RSA Signing Key | RSA-3072 (RS256) | Signs ID tokens (per-client, OIDC Core conformance) | Env var, S3 config, or KMS |
| JWT Secret | HMAC-SHA256 | Signs internal state tokens (authorization codes, WebAuthn state, CSRF) | Env var, S3 config, or KMS |
| Document Encryption Key | P-384 EC (HPKE) | Encrypts sensitive documents stored alongside S3 config | S3 config (KMS-protected) |
| TLS Certificate | EC/RSA | HTTPS transport | Env var or S3 config |
| Client Key (per-CLI) | P-256 EC (ES256) | FAPI 2.0 client auth, DPoP proofs | OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager), file fallback |

## SSH CA Key

The SSH CA key signs all SSH user certificates. Every host that trusts Vouch certificates must have the corresponding public key in `TrustedUserCAKeys`.

### Generation

```bash
ssh-keygen -t ed25519 -f ssh_ca_key -N "" -C "vouch-ca@example.com"
```

### Configuration

```bash
# Option 1: File path
VOUCH_SSH_CA_KEY_PATH=./ssh_ca_key

# Option 2: Inline (base64-encoded PEM, takes precedence over file)
VOUCH_SSH_CA_KEY="$(base64 -i ssh_ca_key | tr -d '\n')"

# Option 3: AWS KMS (overrides Options 1 and 2)
VOUCH_SSH_CA_KMS_KEY_ID=mrk-1234abcd5678efgh

# Option 4: Disable SSH CA
VOUCH_SSH_CA_KEY_PATH=""
```

When using KMS, the server calls `kms:Sign` with Ed25519. The KMS key must be an asymmetric signing key with `ECC_EDWARDS_CURVE_25519` key spec. Multi-region keys (`mrk-` prefix) are recommended for high availability.

### Rotation

SSH CA key rotation requires coordinated updates:

1. Generate a new CA key
2. Distribute the new public key to all hosts (add to `TrustedUserCAKeys`)
3. Update the Vouch server configuration with the new private key
4. Restart the server
5. After all existing certificates expire (max 8 hours), remove the old public key from hosts

> **Important**: During rotation, hosts should trust both old and new CA public keys to avoid disruption.

### Public Key Distribution

Retrieve the CA public key:

```bash
curl https://auth.example.com/v1/credentials/ssh/ca
# ssh-ed25519 AAAA... vouch-ca@example.com
```

## OIDC Signing Key (ES256)

Used to sign access tokens ([RFC 9068](https://www.rfc-editor.org/rfc/rfc9068)) and ID tokens (default algorithm) with ES256.

### Configuration

```bash
# Option 1: Local key (base64-encoded PEM)
VOUCH_OIDC_SIGNING_KEY="$(base64 -i oidc_signing_key.pem | tr -d '\n')"

# Option 2: AWS KMS (overrides Option 1)
VOUCH_OIDC_SIGNING_KMS_KEY_ID=mrk-abcd1234efgh5678
```

If neither is set, an ephemeral key is generated on startup. This means tokens cannot be verified after a server restart unless the same key is provided.

When using KMS, the server calls `kms:Sign` with P-256 ECDSA (`ECC_NIST_P256` key spec). Multi-region keys (`mrk-` prefix) are recommended.

### Generation

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out oidc_signing_key.pem
```

> **Note**: You must use `openssl genpkey` (which produces PKCS#8 format) rather than `openssl ecparam -genkey` (which produces SEC1 format). The server requires PKCS#8 (`-----BEGIN PRIVATE KEY-----`).

### Rotation

When rotating the OIDC signing key:

1. Generate a new key
2. Update the server configuration
3. Restart the server
4. The JWKS endpoint (`/oauth/jwks`) automatically serves the new public key
5. Relying parties that cache JWKS will pick up the new key on their next refresh

## OIDC RSA Signing Key (RS256)

Used to sign ID tokens with RS256 algorithm per [OIDC Core Section 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) and AWS IAM Identity Center trusted-token-issuer tokens. RS256 is the default `id_token_signed_response_alg` in the OIDC specification and must be supported for conformance. Clients can select RS256 via OAuth 2.0 Dynamic Client Registration (`id_token_signed_response_alg` field). AWS's trusted-token-issuer contract also requires RS256 — the Identity Center endpoint (`/v1/credentials/aws/sso/token`) issues RS256-signed tokens for `sso-oidc:CreateTokenWithIAM`, distinct from the ES256 `AssumeRoleWithWebIdentity` token (`/v1/credentials/aws/token`).

Access tokens are always signed with ES256 (the OIDC Signing Key above).

### Generation

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out oidc_rsa_key.pem
```

A minimum key size of 3072 bits is enforced. Keys smaller than 3072 bits are rejected at startup.

### Configuration

```bash
# Option 1: Local key (base64-encoded PEM)
VOUCH_OIDC_RSA_SIGNING_KEY="$(base64 -i oidc_rsa_key.pem | tr -d '\n')"

# Option 2: AWS KMS (overrides Option 1)
VOUCH_OIDC_RSA_SIGNING_KMS_KEY_ID=mrk-rsa1234abcd5678
```

If neither is set, an ephemeral RSA-3072 key is generated on startup. This means RS256 ID tokens cannot be verified after a server restart unless the same key is provided. A warning is logged when an ephemeral key is generated.

When using KMS, the key must be:
- Key spec: `RSA_3072`
- Key usage: `SIGN_VERIFY`
- Signing algorithm: `RSASSA_PKCS1_V1_5_SHA_256`

Multi-region keys (`mrk-` prefix) are recommended.

### Rotation

When rotating the OIDC RSA signing key:

1. Generate a new RSA-3072 key
2. Update the server configuration
3. Restart the server
4. The JWKS endpoint (`/oauth/jwks`) automatically serves the new public key
5. Relying parties that cache JWKS will pick up the new key on their next refresh

## JWT Secret

Used for signing internal state tokens (authorization codes, WebAuthn challenge state, CSRF tokens) with HS256. Access tokens are signed with the OIDC signing key (ES256) per [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068).

### Configuration

```bash
# Option 1: Local secret (must be at least 32 characters)
VOUCH_JWT_SECRET="$(openssl rand -base64 48)"

# Option 2: AWS KMS HMAC (eliminates the need for VOUCH_JWT_SECRET)
VOUCH_JWT_HMAC_KMS_KEY_ID=mrk-5678abcd1234efgh
```

When using KMS, the server uses `kms:GenerateMac` and `kms:VerifyMac` with HMAC-SHA256. The KMS key must be a `HMAC_256` key type. Multi-region keys (`mrk-` prefix) are recommended.

### Generation (local secret)

```bash
openssl rand -base64 48
```

### Rotation

Changing the JWT secret (or KMS key) invalidates all existing sessions. Users must re-authenticate.

1. Generate a new secret or KMS key
2. Update `VOUCH_JWT_SECRET` or `VOUCH_JWT_HMAC_KMS_KEY_ID`
3. Restart the server
4. All users must run `vouch login` again

## Document Encryption Key

Used for HPKE (Hybrid Public Key Encryption) of sensitive documents stored alongside the S3 configuration. The private key is encrypted by a KMS key and stored in the S3 config as `document_key`.

### Provisioning

```bash
vouch-server generate-document-key --kms-key-id mrk-<your-kms-key-id>
```

This generates a P-384 EC key pair, encrypts the private key with the specified KMS key, and outputs the `document_key` JSON block to add to your S3 config.

### Configuration

The `document_key` field in S3 config contains:

```json
{
  "document_key": {
    "kms_key_id": "mrk-<your-kms-key-id>",
    "encrypted_private_key": "<base64-encoded KMS ciphertext>"
  }
}
```

At startup, the server decrypts the private key via `kms:Decrypt` and holds the key material in memory for the lifetime of the process.

## Per-Org Issuer Signing Keys (ES256 + RS256)

When an organization claims a custom subdomain on an encrypted deployment, Vouch generates a
dedicated ES256 and RS256 signing key pair for that org's OIDC issuer. AWS federation tokens,
Identity Center tokens, and all RFC 8693 token-exchange assertions for that org are signed with
these keys and served at the org's own JWKS endpoint
(`https://<org-subdomain>.auth.example.com/oauth/jwks`).

This makes each subdomain a real cryptographic tenant boundary: a token issued for org A cannot
be verified against org B's JWKS.

Per-org keys are only created when all three conditions are met:

- The deployment has document encryption enabled (a KMS-backed document key in the S3 config).
- The organization has a claimed subdomain.
- A credential-issuance request arrives for that org (lazy first-use creation).

### Graceful Rotation

Graceful rotation is a zero-downtime two-phase process:

**Phase 1 — Stage:** The "Rotate Signing Keys" button generates successor keys and publishes them
immediately in the org JWKS. Both the current (Active) and successor (Pending) keys appear in the
JWKS. No token breakage occurs because signing continues with the Active key during the 24-hour
publish window.

**Phase 2 — Activate:** Approximately 24 hours after staging, the scheduled cleanup task promotes
the successor key to Active and demotes the old key to Retiring. Signing switches to the new key.
The old key remains in the JWKS for the duration of the retirement window (session lifetime + 1
hour + a safety margin) so outstanding tokens signed by the old key remain verifiable.

**Phase 3 — Reap:** After the retirement window elapses, the cleanup task removes the old Retiring
key from the JWKS entirely.

The full cycle takes roughly 24 hours (publish window) plus the retirement window (~9 hours for an
8-hour session lifetime). No operator action is required after clicking "Rotate Signing Keys" —
the cleanup task handles activation and reaping automatically.

> **Operator note:** Reducing `VOUCH_SESSION_HOURS` immediately before a rotation can
> under-cover tokens minted under the old key (the retirement window is derived from the current
> session lifetime). If you need to shorten session lifetimes, do so well before or after a
> rotation, not immediately before one.

### Emergency Rotation

The "Emergency Rotate" button immediately replaces both the ES256 and RS256 keys in a single
atomic operation. Use this only when key compromise is suspected.

**Consequences:**

- Both keys are replaced immediately; any in-flight staged rotation is cancelled.
- Outstanding tokens signed by the old keys will fail verification until relying parties
  refetch the JWKS. Cross-instance propagation takes up to 60 seconds (cache TTL); downstream
  relying parties that respect the `Cache-Control: public, max-age=3600` response header may
  take up to 1 hour to pick up the new keys.
- AWS STS `AssumeRoleWithWebIdentity` and IAM Identity Center `CreateTokenWithIAM` calls that
  carry a token signed by the old key will fail until the session expires or the user
  re-authenticates with `vouch login`.

**Runbook:**

1. Navigate to **Admin → Subdomain** for the affected org.
2. Click **Emergency Rotate** and confirm.
3. Instruct affected users to run `vouch login` to obtain a new token signed by the replacement
   key.
4. If the org is federated with AWS IAM, existing STS sessions will expire naturally (up to
   session lifetime) or can be revoked via the IAM console.

### JWKS Caching and the 24-Hour Publish Window

The 24-hour publish window before activation is a deliberate product decision (S2). AWS IAM and
IAM Identity Center cache JWKS responses for an undocumented internal period that is believed to
exceed the advertised 1-hour `Cache-Control` max-age. Publishing the successor key 24 hours before
activation ensures relying parties have ample time to cache the new `kid` before Vouch starts
signing with it. Changing this window requires verifying the behaviour of all federated relying
parties.

## TLS Certificate

See [TLS Configuration](../deployment/tls.md) for details on TLS certificate management and hot-reload.
