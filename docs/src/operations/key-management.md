# Key Management

Vouch uses several cryptographic keys. This page covers their lifecycle and rotation.

## Key Inventory

| Key | Algorithm | Purpose | Storage |
|-----|-----------|---------|---------|
| SSH CA Key | Ed25519 | Signs SSH user certificates | File, env var, or S3 config |
| OIDC Signing Key | P-256 EC (ES256) | Signs ID tokens and access tokens | Env var or S3 config |
| JWT Secret | HMAC-SHA256 | Signs internal state tokens (authorization codes, WebAuthn state, CSRF) | Env var or S3 config |
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

# Option 2: Inline (base64-encoded PEM, takes precedence)
VOUCH_SSH_CA_KEY="$(base64 -i ssh_ca_key | tr -d '\n')"

# Option 3: Disable SSH CA
VOUCH_SSH_CA_KEY_PATH=""
```

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
curl https://auth.example.com/.well-known/ssh-ca.pub
# ssh-ed25519 AAAA... vouch-ca@example.com
```

## OIDC Signing Key

Used to sign ID tokens ([OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)) and access tokens ([RFC 9068](https://www.rfc-editor.org/rfc/rfc9068)) with ES256 algorithm.

### Configuration

```bash
# Provide a P-256 EC key (base64-encoded PEM)
VOUCH_OIDC_SIGNING_KEY="$(base64 -i oidc_signing_key.pem | tr -d '\n')"
```

If not set, an ephemeral key is generated on startup. This means tokens cannot be verified after a server restart unless the same key is provided.

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

Used for signing internal state tokens (authorization codes, WebAuthn challenge state, CSRF tokens) with HS256. Access tokens are signed with the OIDC signing key (ES256) per [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068). Must be at least 32 characters.

### Generation

```bash
openssl rand -base64 48
```

### Rotation

Changing the JWT secret invalidates all existing sessions. Users must re-authenticate.

1. Generate a new secret
2. Update `VOUCH_JWT_SECRET`
3. Restart the server
4. All users must run `vouch login` again

## TLS Certificate

See [TLS Configuration](../deployment/tls.md) for details on TLS certificate management and hot-reload.
