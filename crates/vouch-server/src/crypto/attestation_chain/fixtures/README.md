# Real-hardware attestation fixtures

`yubikey-5c-nano-fips-enterprise.attestation.b64` is a base64url WebAuthn
attestation object captured from a physical YubiKey 5C Nano FIPS (Enterprise),
AAGUID `28969c24-0487-4a46-be39-37bc6337a24f`.

Every other test in this module builds certificates with a freshly generated
key, which by construction cannot chain to `PINNED_ROOTS`. Those tests exercise
the chain-walking logic but can never catch a pinned root being dropped,
reordered, or corrupted, because they never touch one. This fixture is the only
test input that does.

What it pins:

- The leaf (`CN=Yubico U2F EE Serial 516926366`) is signed directly by
  `CN=Yubico U2F Root CA Serial 457200631`, the certificate in
  `root_certs/yubico-fido-ca-1.pem`.
- The leaf carries `id-fido-gen-ce-aaguid` (OID 1.3.6.1.4.1.45724.1.1.4),
  non-critical, wrapping the AAGUID in two OCTET STRINGs per WebAuthn Level 2
  section 8.2.1.
- The certificate AAGUID equals the authData AAGUID, so the section 8.2 step 2
  cross-check is exercised on real data rather than a constructed pair.

Contents are not sensitive. The leaf is a Yubico *batch* attestation
certificate shared across a large production run, not a device-unique one. The
credential was throwaway and non-discoverable (`residentKey: "discouraged"`),
so it was never stored on the key or bound to an account, and `rpIdHash` is the
SHA-256 of `localhost`.

## Regenerating

Serve a page over `http://localhost` (a secure context, so WebAuthn is
available) that calls:

```js
navigator.credentials.create({ publicKey: {
  challenge: crypto.getRandomValues(new Uint8Array(32)),
  rp: { name: 'capture', id: location.hostname },
  user: { id: crypto.getRandomValues(new Uint8Array(16)),
          name: 'probe', displayName: 'probe' },
  pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
  authenticatorSelection: { authenticatorAttachment: 'cross-platform',
                            residentKey: 'discouraged' },
  attestation: 'direct',
}})
```

then base64url-encode `response.attestationObject`. `attestation: "direct"` is
required — under the default `"none"` conveyance the browser strips the AAGUID
and replaces the statement, per WebAuthn Level 2 section 5.1.3.

A capture from a different YubiKey model will have a different AAGUID and may
chain to a different pinned root; update the expectations in `tests.rs` to
match rather than assuming these values.
