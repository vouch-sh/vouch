# Post-Quantum Cryptography

This page describes Vouch's post-quantum cryptography (PQC) posture: what is quantum-resistant today, what is still classical and why, and what to watch. It exists so that operators fielding "are we quantum-safe?" questions have a precise answer.

## Threat Model Summary

A cryptographically relevant quantum computer breaks the elliptic-curve and RSA algorithms Vouch uses (P-256, P-384, Ed25519, RSA-3072). The two exposure classes have very different urgency:

- **Key exchange / encryption — urgent.** An adversary can record encrypted traffic or steal encrypted data *today* and decrypt it once a quantum computer exists ("harvest now, decrypt later"). This is why the industry moved TLS and SSH key exchange to hybrid post-quantum schemes first (NIST IR 8547; OpenSSH 10 defaults; the majority of browser traffic).
- **Signatures — not yet exposed.** A signature is verified at use time. A future quantum computer cannot retroactively forge a login, token, or certificate that was verified years earlier. Signatures only become a problem once quantum computers are close to real, and the surrounding ecosystems (JOSE, OpenSSH, FIDO2, WebPKI) have not yet standardized replacements.

## What Is Quantum-Resistant Today

**TLS key exchange, in both directions.** All Vouch binaries enable the rustls `prefer-post-quantum` feature, which makes **X25519MLKEM768** (hybrid X25519 + ML-KEM-768, the FIPS 203 lattice KEM) the preferred TLS key-exchange group:

- **Inbound**: the server's HTTPS and mTLS listeners.
- **Outbound**: CLI → server, agent → server, and server → upstream IdP / AWS / GitHub connections.

Hybrid means the session keys are secure if *either* X25519 or ML-KEM-768 holds, so this is a strict upgrade. Peers that do not support ML-KEM negotiate classical groups transparently. No configuration is involved; an integration test (`pq_tls.rs` in `vouch-tests`) pins the negotiated group so a silent downgrade fails CI.

## What Is Still Classical, and Why

Every signature in the system is classical, because none of the protocols involved have a standardized, deployable post-quantum alternative yet. None of these are "harvest now, decrypt later" exposed.

| Surface | Algorithm | Blocked on |
|---------|-----------|------------|
| OIDC access/ID tokens, token exchange | ES256 / RS256 | ML-DSA in JOSE is still an IETF draft (`draft-ietf-cose-dilithium`); no production-grade Rust JWT support |
| DPoP proofs, private_key_jwt, JAR/JARM | ES256 / PS256 / EdDSA | Same JOSE draft; FAPI 2.0 profile algorithms |
| HTTP message signatures (RFC 9421, `/v1/*`) | ecdsa-p256-sha256 | No PQC algorithms registered for RFC 9421 |
| SSH user certificates (SSH CA) | Ed25519 | OpenSSH has **no** post-quantum signature or host-key algorithms yet — its PQC support is key exchange only |
| WebAuthn / FIDO2 assertions | ES256 / RS256 / EdDSA | No PQC in released CTAP/WebAuthn; YubiKey ML-DSA support is prototype-only and requires new hardware |
| SAML assertions | RSA/ECDSA-SHA256 | XML-DSig PQC unstandardized |
| Internal state tokens | HMAC-SHA256 | Symmetric; already quantum-resistant at this key size (no action needed) |

One **encryption** surface is classical and is the known harvest-now-decrypt-later item:

| Surface | Algorithm | Status |
|---------|-----------|--------|
| Document encryption at rest (S3 config documents) | HPKE with DHKEM(P-384) + AES-256-GCM | Roadmap item: move to a hybrid ML-KEM HPKE suite (X-Wing) once it is standardized, with a versioned envelope and re-encryption of existing documents. Exposure requires an attacker to first obtain the encrypted documents; the KMS-sealed private key and S3 access controls remain the primary defense. |

## Watch List

Ecosystem developments that unblock the classical surfaces above, roughly in the order they are expected to land:

1. **HPKE hybrid KEMs (X-Wing / ML-KEM in HPKE)** — unblocks document encryption at rest. First candidate for adoption since it is entirely under Vouch's control (no protocol peers involved).
2. **ML-DSA in JOSE/COSE** (`draft-ietf-cose-dilithium` → RFC, plus Rust library support) — unblocks OIDC tokens, DPoP, and client assertions. AWS KMS already offers ML-DSA signing keys, so the KMS-backed key path is the likely first implementation.
3. **OpenSSH post-quantum signature algorithms** — unblocks the SSH CA. Nothing to do until OpenSSH itself ships them.
4. **FIDO2/CTAP PQC + authenticator hardware** — unblocks WebAuthn. Requires new YubiKey hardware generations; expect years, and expect hybrid classical+PQC attestation first.
5. **ML-DSA in WebPKI certificates** — affects TLS server certificates, which Vouch consumes rather than issues; adopt whatever the CA ecosystem (e.g. Let's Encrypt) ships.

When adopting any of these, prefer hybrid (classical + PQC) constructions over pure PQC, matching current NIST/BSI guidance.

## Operator FAQ

**Do I need to configure anything to get post-quantum TLS?** No. It is compiled in and negotiated automatically when the peer supports it.

**How do I verify a connection used post-quantum key exchange?** From a client with OpenSSL 3.5+: `openssl s_client -connect auth.example.com:443 -groups X25519MLKEM768` and check the negotiated group in the handshake output. Browsers show the key-exchange group in their developer-tools security panel.

**Are my SSH certificates quantum-safe?** The certificate signature is Ed25519 (classical), but certificates live at most 8 hours and cannot be retroactively forged, so there is no stored-data exposure. The SSH *transport* is between your SSH client and your hosts — OpenSSH 10 uses post-quantum key exchange by default.

**Does the 8-hour credential lifetime matter here?** Yes — short-lived credentials are themselves a quantum mitigation. Even aggressive estimates for cryptographically relevant quantum computers are measured in years, not hours; nothing Vouch signs outlives the transition window it would need to survive to be at risk.
