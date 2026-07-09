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

All of these keys use classical (pre-quantum) algorithms. For why that is currently the right choice for each of them, and what Vouch already does about quantum resistance, see [Post-Quantum Cryptography](post-quantum.md).

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

Used to sign ID tokens with RS256 algorithm per [OIDC Core Section 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) and all AWS credential tokens. RS256 is the default `id_token_signed_response_alg` in the OIDC specification and must be supported for conformance. Clients can select RS256 via OAuth 2.0 Dynamic Client Registration (`id_token_signed_response_alg` field). The AWS token endpoint (`/v1/credentials/aws/token`) issues one RS256-signed token that serves both STS `AssumeRoleWithWebIdentity` and, as the `sso-oidc:CreateTokenWithIAM` assertion, the IAM Identity Center trusted-token-issuer contract (which rejects ES256).

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

If neither is set, an ephemeral RSA-3072 key is generated on startup. This means RS256 ID tokens and AWS credential tokens cannot be verified after a server restart, and verification fails across multiple instances (each generates its own key). Any deployment using the AWS integration needs a durable key. A warning is logged when an ephemeral key is generated.

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

### Key Lifecycle

Each algorithm's key set always contains two keys, and sometimes three:

| State | Role | Published in JWKS | Signs tokens |
|-------|------|-------------------|--------------|
| **Current** | The signer | yes | yes |
| **Next** | Pre-staged successor | yes | no |
| **Previous** | Demoted signer awaiting revocation | yes | no |

The Next key is created together with the first key and re-staged automatically whenever a
rotation consumes it, so relying-party JWKS caches always hold the key that will sign next —
long before it ever signs. Nothing in the lifecycle runs on a timer: both rotation steps are
explicit operator actions on the **Admin → Subdomain** page.

### Rotating Keys

**Step 1 — Rotate.** The "Rotate Signing Keys" button switches signing to the pre-staged Next
keys for both algorithms in one transaction. The old signers become Previous keys: still
published, still verifying outstanding tokens, no longer signing. Fresh Next keys are staged in
the same transaction.

The rotate is rejected in two situations:

- **The Next keys are younger than 24 hours.** Relying parties (AWS IAM in particular) cache the
  org JWKS on their own schedule; signing with a key their cache has not seen fails federation
  until they refetch. Because the Next key is normally staged months earlier (at first use or by
  the previous rotation), this gate only bites on back-to-back rotations.
- **Previous keys from an earlier rotation are still published.** Revoke them first — the key
  set keeps at most one retired generation per algorithm.

**Step 2 — Revoke.** The "Revoke Old Keys" button deletes the Previous keys and removes them
from the JWKS. It is rejected until `max(session lifetime, 8 hours) + 2 hours` have passed since
the rotate, because until then tokens signed by the old keys may still be live — deleting the
keys would log those sessions out. After the window, revocation affects nobody.

A Previous key that is never revoked stays visible on the admin page indefinitely (it can
verify, but never sign). Nothing deletes it automatically; revoking promptly after the drain
window keeps the published key set minimal.

> **Operator note:** Reducing `VOUCH_SESSION_HOURS` between a rotate and its revoke can shorten
> the revoke gate below what tokens issued under the old lifetime need. Revoke first, then
> shorten session lifetimes.

### Emergency Rotation

The "Emergency Rotate" button replaces the **entire key set** — fresh Current and Next keys for
both algorithms, Previous keys deleted — in one atomic operation. Use it only when key
compromise is suspected: on an encrypted deployment all private keys are sealed by the same
document key, so a compromise of one is treated as a compromise of all.

**Consequences:**

- Every key that existed before the emergency is removed from the JWKS immediately.
- Outstanding tokens signed by the old keys will fail verification until relying parties
  refetch the JWKS. Cross-instance propagation takes up to 60 seconds (signing cache TTL);
  downstream relying parties that respect the `Cache-Control: public, max-age=3600` response
  header may take up to 1 hour to pick up the new keys.
- AWS STS `AssumeRoleWithWebIdentity` and IAM Identity Center `CreateTokenWithIAM` calls that
  carry a token signed by an old key will fail until the user re-authenticates with
  `vouch login`.
- The fresh Next keys start a new 24-hour publish window, so a graceful rotate is unavailable
  for a day afterwards.

**Runbook:**

1. Navigate to **Admin → Subdomain** for the affected org.
2. Click **Emergency Rotate** and confirm.
3. Instruct affected users to run `vouch login` to obtain a new token signed by the replacement
   key.
4. If the org is federated with AWS IAM, existing STS sessions will expire naturally (up to
   session lifetime) or can be revoked via the IAM console.

### JWKS Caching and the 24-Hour Publish Window

The 24-hour minimum age before a Next key may sign is a deliberate product decision. AWS IAM and
IAM Identity Center cache JWKS responses for an undocumented internal period that is believed to
exceed the advertised 1-hour `Cache-Control` max-age. Keeping the successor published for at
least 24 hours before it signs ensures relying parties have ample time to cache the new `kid`.
Changing this window requires verifying the behaviour of all federated relying parties.

Releasing a subdomain deletes the Next and Previous keys (the publish window is meaningless
while the issuer host is unclaimed) but keeps the Current key, so a same-org reclaim resumes
with the same signer. The first use after a reclaim stages a fresh Next key, which restarts its
24-hour window.

## TLS Certificate

See [TLS Configuration](../deployment/tls.md) for details on TLS certificate management and hot-reload.
