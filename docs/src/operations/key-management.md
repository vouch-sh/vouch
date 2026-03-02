# Key Management

Vouch uses several cryptographic keys. This page covers their lifecycle and rotation.

## Key Inventory

| Key | Algorithm | Purpose | Storage |
|-----|-----------|---------|---------|
| SSH CA Key | Ed25519 | Signs SSH user certificates | File, env var, S3 config, or KMS |
| OIDC Signing Key | P-256 EC (ES256) | Signs ID tokens and access tokens | Env var, S3 config, or KMS |
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

## OIDC Signing Key

Used to sign ID tokens ([OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)) and access tokens ([RFC 9068](https://www.rfc-editor.org/rfc/rfc9068)) with ES256 algorithm.

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
openssl ecparam -name prime256v1 -genkey -noout -out oidc_signing_key.pem
```

### Rotation

When rotating the OIDC signing key:

1. Generate a new key
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

## TLS Certificate

See [TLS Configuration](../deployment/tls.md) for details on TLS certificate management and hot-reload.
