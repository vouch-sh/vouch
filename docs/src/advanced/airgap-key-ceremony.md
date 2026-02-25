# Key Ceremony

This chapter details the cryptographic key generation procedures required for an air-gapped Vouch deployment. All key generation should be performed on a trusted, air-gapped workstation following your organization's key ceremony procedures.

## JWT Secret Generation (Required)

The JWT secret is used to sign all OAuth tokens and session cookies. It must be at least 32 characters.

```bash
# Generate cryptographically secure 64-character secret
openssl rand -base64 48

# Alternative using /dev/urandom
head -c 48 /dev/urandom | base64

# Store securely - this will be VOUCH_JWT_SECRET
```

**Security Notes:**
- Use a minimum of 32 characters (48+ recommended)
- Never reuse secrets across environments
- Rotate periodically (requires re-authentication of all users)

## SSH CA Key Generation (Ed25519)

The SSH CA signs user SSH certificates. If not provided, SSH certificate issuance will be disabled.

```bash
# Generate Ed25519 SSH CA key pair (no passphrase for automated use)
ssh-keygen -t ed25519 -f ssh_ca_key -N "" -C "vouch-ca@auth.internal"

# Set restrictive permissions
chmod 600 ssh_ca_key

# Verify key type and fingerprint
ssh-keygen -l -f ssh_ca_key
# Output: 256 SHA256:xxxx vouch-ca@auth.internal (ED25519)

# View public key (for distribution to SSH servers)
cat ssh_ca_key.pub
```

**Environment variable format (base64-encoded):**
```bash
# Option 1: Provide base64-encoded key content (preferred for containers)
export VOUCH_SSH_CA_KEY="$(base64 -i ssh_ca_key | tr -d '\n')"

# Option 2: Provide path to key file (file contains raw PEM, not base64)
export VOUCH_SSH_CA_KEY_PATH="/secrets/ssh_ca_key"
```

**Key Storage Options:**
- **HSM** (recommended for high-security) -- Store in hardware security module
- **Encrypted file** with split knowledge -- Two administrators hold partial keys
- **YubiKey PIV** (for smaller deployments) -- Store on hardware token

## OIDC Signing Key Generation (P-256 ECDSA)

The OIDC signing key signs ID tokens using ES256 algorithm. If not provided, an ephemeral key is generated on each server restart (not recommended for production as it invalidates all existing tokens).

```bash
# Generate P-256 EC private key in PKCS#8 format
openssl ecparam -name prime256v1 -genkey -noout | \
  openssl pkcs8 -topk8 -nocrypt -out oidc_signing_key.pem

# Set restrictive permissions
chmod 600 oidc_signing_key.pem

# Verify key type
openssl ec -in oidc_signing_key.pem -text -noout 2>/dev/null | head -3
# Output should include: Private-Key: (256 bit, prime256v1)

# Extract public key (for debugging/verification)
openssl ec -in oidc_signing_key.pem -pubout -out oidc_signing_key.pub
```

**Environment variable format (base64-encoded):**
```bash
# Provide base64-encoded PEM content
export VOUCH_OIDC_SIGNING_KEY="$(base64 -i oidc_signing_key.pem | tr -d '\n')"
```

## TLS Certificate Generation

For production, use certificates signed by your internal CA. For testing, self-signed certificates can be used.

```bash
# Generate EC private key and self-signed certificate
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout tls_key.pem -out tls_cert.pem -days 365 -nodes \
  -subj "/CN=auth.internal" \
  -addext "subjectAltName=DNS:auth.internal,DNS:localhost"

# Set restrictive permissions
chmod 600 tls_key.pem

# Verify certificate
openssl x509 -in tls_cert.pem -text -noout | head -15
```

**Environment variable format (base64-encoded):**
```bash
# Base64 encode for environment variables
export VOUCH_TLS_CERT="$(base64 -i tls_cert.pem | tr -d '\n')"
export VOUCH_TLS_KEY="$(base64 -i tls_key.pem | tr -d '\n')"
```

## Key Security Best Practices

1. **File Permissions**: Always use `chmod 600` for private keys
2. **Never Commit Keys**: Add `*.pem`, `*_key`, `*.key` to `.gitignore`
3. **Audit Key Access**: Log all access to key material
4. **Backup Securely**: Store encrypted backups in separate secure location
5. **Document Fingerprints**: Record key fingerprints in secure documentation
6. **Key Rotation**: Plan for periodic rotation (SSH CA annually, JWT secret quarterly)
