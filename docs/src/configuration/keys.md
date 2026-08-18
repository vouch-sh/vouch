# Key Management

Vouch uses seven kinds of cryptographic keys. This page covers their lifecycle and rotation.

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

All of these keys use classical (pre-quantum) algorithms. For why that is currently the right
choice for each of them, and what Vouch already does about quantum resistance, see
[vouch.sh/docs/security](https://vouch.sh/docs/security/). TLS key exchange is the one surface that is
already hybrid post-quantum — see [TLS, Ports, and mTLS](tls.md#post-quantum-key-exchange).

## SSH CA Key

The SSH CA key signs all SSH user certificates. Every host that trusts Vouch certificates must have the corresponding public key in `TrustedUserCAKeys`.

### Generation

```bash
ssh-keygen -t ed25519 -f ssh_ca_key -N "" -C "vouch-ca@example.com"
```

### Configuration

```bash
# Option 1: File path (raw OpenSSH PEM)
VOUCH_SSH_CA_KEY_PATH=./ssh_ca_key

# Option 2: Inline (raw or base64-encoded PEM; takes precedence over the file)
VOUCH_SSH_CA_KEY="$(base64 -i ssh_ca_key | tr -d '\n')"

# Option 3: AWS KMS (overrides Options 1 and 2)
VOUCH_SSH_CA_KMS_KEY_ID=mrk-1234abcd5678efgh

# Option 4: Disable SSH CA
VOUCH_SSH_CA_KEY_PATH=""
```

`VOUCH_SSH_CA_KEY` accepts either raw PEM or base64-encoded PEM — the server detects which by
looking for the `-----BEGIN` header. The file at `VOUCH_SSH_CA_KEY_PATH` must be raw PEM.

> **Warning**: if the file at `VOUCH_SSH_CA_KEY_PATH` does not exist, the server **generates a
> new Ed25519 CA key and writes it there** (mode `0600`, comment `vouch-ca@{rp_id}`). That is
> convenient on first install and dangerous afterwards: starting on a fresh container, an empty
> volume, or an unmounted data directory silently issues you a brand-new CA. Every host's
> `TrustedUserCAKeys` entry stops matching and users can no longer log in with newly issued
> certificates, while `/health` stays green. Prefer `VOUCH_SSH_CA_KEY` or
> `VOUCH_SSH_CA_KMS_KEY_ID` for anything beyond a single-node install — neither auto-generates.

When using KMS, the server calls `kms:Sign` with Ed25519. The KMS key must be an asymmetric signing key with `ECC_EDWARDS_CURVE_25519` key spec. Use a multi-region key (`mrk-` prefix) for high availability.

### Rotation

SSH CA key rotation requires coordinated updates:

1. Generate a new CA key
2. Distribute the new public key to all hosts (add to `TrustedUserCAKeys`)
3. Update the Vouch server configuration with the new private key
4. Restart the server
5. After all existing certificates expire (max 8 hours), remove the old public key from hosts

> **Important**: During rotation, keep both the old and new CA public keys in `TrustedUserCAKeys` until step 5 — removing the old key early invalidates certificates that have not yet expired.

### Public Key Distribution

Retrieve the CA public key. The endpoint returns JSON, not an authorized-keys line:

```bash
curl -s https://auth.example.com/v1/credentials/ssh/ca
# {"public_key":"ssh-ed25519 AAAA...","comment":"vouch-ca@example.com"}
```

To write a file that `sshd` can use as `TrustedUserCAKeys`, extract the `public_key` field:

```bash
curl -s https://auth.example.com/v1/credentials/ssh/ca \
  | jq -r .public_key > /etc/ssh/vouch-ca.pub
```

> Redirecting the raw response into that file writes JSON where `sshd` expects a key, and every
> certificate login then fails.

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

When using KMS, the server calls `kms:Sign` with P-256 ECDSA (`ECC_NIST_P256` key spec). Use a multi-region key (`mrk-` prefix) for high availability.

### Generation

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out oidc_signing_key.pem
```

> **Note**: use `openssl genpkey`, which produces PKCS#8, rather than `openssl ecparam -genkey`,
> which produces SEC1. The server accepts only PKCS#8. Tell them apart from the PEM header on the
> first line: PKCS#8 labels it `PRIVATE KEY`, while SEC1 labels it `EC PRIVATE KEY`. If you have a
> SEC1 key, convert it:
>
> ```bash
> openssl pkey -in sec1_key.pem -out pkcs8_key.pem
> ```

### Rotation

When rotating the OIDC signing key:

1. Generate a new key
2. Update the server configuration
3. Restart the server
4. The JWKS endpoint (`/oauth/jwks`) automatically serves the new public key
5. Relying parties that cache JWKS will pick up the new key on their next refresh

## OIDC RSA Signing Key (RS256)

Used to sign ID tokens with RS256 algorithm per [OIDC Core Section 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) and all AWS credential tokens. RS256 is the default `id_token_signed_response_alg` in the OIDC specification and must be supported for conformance. Clients can select RS256 via OAuth 2.0 Dynamic Client Registration (`id_token_signed_response_alg` field). The AWS token endpoint (`/v1/credentials/aws/token`) issues one RS256-signed token that serves both STS `AssumeRoleWithWebIdentity` and, as the `sso-oidc:CreateTokenWithIAM` assertion, the IAM Identity Center trusted-token-issuer contract (which rejects ES256).

Access tokens are always signed with ES256 (the OIDC Signing Key above).

### Generation

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out oidc_rsa_key.pem
```

The server rejects keys smaller than 3072 bits at startup.

### Configuration

```bash
# Option 1: Local key (base64-encoded PEM)
VOUCH_OIDC_RSA_SIGNING_KEY="$(base64 -i oidc_rsa_key.pem | tr -d '\n')"

# Option 2: AWS KMS (overrides Option 1)
VOUCH_OIDC_RSA_SIGNING_KMS_KEY_ID=mrk-rsa1234abcd5678
```

If neither is set, an ephemeral RSA-3072 key is generated on startup. This means RS256 ID tokens and AWS credential tokens cannot be verified after a server restart, and verification fails across multiple instances (each generates its own key). Any deployment using the AWS integration needs a durable key. A warning is logged when an ephemeral key is generated.

When using KMS, the key must be:
- Key spec: `RSA_3072`
- Key usage: `SIGN_VERIFY`
- Signing algorithm: `RSASSA_PKCS1_V1_5_SHA_256`

Use a multi-region key (`mrk-` prefix) for high availability.

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

When using KMS, the server uses `kms:GenerateMac` and `kms:VerifyMac` with HMAC-SHA256. The KMS key must be a `HMAC_256` key type. Use a multi-region key (`mrk-` prefix) for high availability.

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

This generates a P-384 EC key pair, encrypts the private key with the specified KMS key, and outputs the `document_key` JSON block to add to your S3 config. `--algorithm p384` is the default and currently the only supported algorithm; the flag exists so post-quantum algorithms can be added later without changing the command or config shape.

### Configuration

The `document_key` field in S3 config contains:

```json
{
  "document_key": {
    "kms_key_id": "mrk-<your-kms-key-id>",
    "encrypted_private_key": "<base64-encoded KMS ciphertext>",
    "algorithm": "p384"
  }
}
```

`algorithm` is optional and defaults to `p384`, so configs provisioned before the field existed keep working unchanged.

At startup, the server decrypts the private key via `kms:Decrypt` and holds the key material in memory for the lifetime of the process.

### Cipher-suite tagging and the post-quantum path

Every document row records the HPKE cipher suite it was sealed with: the stored
encapsulated key is prefixed `hpke:<kem_id>:<kdf_id>:<aead_id>:` using the RFC 9180
codepoints (`hpke:0011:0002:0002:` for the current DHKEM(P-384) + HKDF-SHA384 +
AES-256-GCM suite). Rows written before tagging existed are plain base64 and are read
as that same P-384 suite. Rows sealed under different suites can therefore coexist in
one database, which is what makes a future key-encapsulation migration — e.g. to the
ML-KEM hybrid suites from draft-ietf-hpke-pq — an operational rotation rather than a
breaking format change.

There is no document-key rotation mechanism today. When post-quantum suites become
available in the underlying libraries (rustls / aws-lc-rs), the expected migration is:

1. Provision a new `document_key` with the new algorithm (one new
   `generate-document-key --algorithm` value).
2. Run a dual-key read period: the server decrypts old rows with the old private key
   (selected by each row's suite tag) while sealing new writes under the new suite.
3. Re-encrypt existing rows opportunistically on write, plus an offline sweep for the
   remainder; then retire the old key.

Steps 2–3 are not implemented yet — only the storage format and configuration
groundwork exist. Do not remove the old key from KMS until every row carries the new
suite tag.

## Per-Org Issuer Signing Keys

Vouch can give an organization its own OIDC issuer host with a dedicated signing key set, so that
a token issued for one organization does not verify against another's JWKS. This only activates on
a deployment that has both document encryption (a KMS-backed `document_key` in the S3 config) and
an organization that has claimed an issuer subdomain — the shape used by the hosted Vouch service.

A single-organization self-hosted deployment does not use it: every token is signed with the
platform keys described above.

> **Startup invariant**: if any issuer subdomain is claimed in the database but document
> encryption is *not* configured, the server refuses to start. Per-org private keys are never
> stored in plaintext, so the encrypting document store is a hard requirement. See
> [Troubleshooting](../operations/troubleshooting.md#the-server-wont-start).

## TLS Certificate

See [TLS Configuration](tls.md) for details on TLS certificate management and hot-reload.
