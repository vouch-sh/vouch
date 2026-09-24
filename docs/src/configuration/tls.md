# TLS Configuration

Vouch requires HTTPS in production. TLS can be configured directly on the Vouch server or terminated at a load balancer.

## Direct TLS (Recommended)

When TLS is configured, the server automatically:
- Listens on port **443** (HTTPS)
- Runs an HTTP redirect server on port **80** (308 redirect to HTTPS)
- Makes the `/health` endpoint accessible on HTTP (for load balancer health checks)
- Validates the `Host` header against `rp_id` to prevent injection attacks
- Ignores `VOUCH_LISTEN_ADDR` (ports are fixed at 443/80)

> **Note**: Binding to ports 80 and 443 requires `CAP_NET_BIND_SERVICE` capability on Linux. The RPM/DEB packages configure this automatically.

### Configuration

Provide base64-encoded PEM certificates via environment variables:

```bash
# Encode your certificate and key
export VOUCH_TLS_CERT="$(base64 -i cert.pem | tr -d '\n')"
export VOUCH_TLS_KEY="$(base64 -i key.pem | tr -d '\n')"
```

Both `VOUCH_TLS_CERT` and `VOUCH_TLS_KEY` must be set together. If only one is set, the server fails to start.

### TLS Properties

- **Protocol**: TLS 1.3 and TLS 1.2
- **Implementation**: rustls (no OpenSSL)
- **Ciphers**: BCP 195 (RFC 9325) suites only — TLS 1.3 AEAD suites, and ECDHE+AEAD suites for TLS 1.2 (AES-GCM, ChaCha20-Poly1305)

### Post-Quantum Key Exchange

Both TLS listeners (HTTPS and mTLS) and all outbound TLS clients (CLI, agent, and server-to-IdP/AWS connections) prefer the **X25519MLKEM768** hybrid post-quantum key-exchange group. When the peer supports it — modern browsers, Cloudflare, and AWS endpoints do — the TLS session keys are protected against "harvest now, decrypt later" attacks. Peers without ML-KEM support negotiate classical X25519 or P-256 as usual; no configuration is required on either side.

To confirm a connection actually negotiated it, from a client with OpenSSL 3.5 or later:

```bash
openssl s_client -connect auth.example.com:443 -groups X25519MLKEM768 </dev/null 2>/dev/null \
  | grep -i 'negotiated group'
```

Browsers show the negotiated key-exchange group in their developer-tools security panel.

For Vouch's overall post-quantum posture — which surfaces are still classical, why, and what is
being tracked — see the security documentation at
[vouch.sh/docs/security](https://vouch.sh/docs/security/).

## Client Certificate Authorities for `tls_client_auth`

OAuth clients can authenticate to the token, PAR, revocation, introspection, and device
authorization endpoints with a TLS client certificate on the mTLS port (RFC 8705). There are two
methods, and they trust certificates differently:

| Method | What the server checks | Needs `VOUCH_MTLS_CLIENT_CA_CERTS` |
|--------|------------------------|------------------------------------|
| `tls_client_auth` | The certificate chains to a CA in `VOUCH_MTLS_CLIENT_CA_CERTS`, is valid now, allows client authentication, **and** its subject DN or SAN matches the one registered for the client | Yes |
| `self_signed_tls_client_auth` | The certificate is one of the certificates in the client's registered JWKS (`x5c`) | No |

Point `VOUCH_MTLS_CLIENT_CA_CERTS` at a PEM file holding the CA certificates that issue your
clients' certificates. Concatenate several CAs in one file if needed:

```bash
cat issuing-ca.pem other-issuing-ca.pem > /etc/vouch/mtls-client-cas.pem
export VOUCH_MTLS_CLIENT_CA_CERTS=/etc/vouch/mtls-client-cas.pem
```

Trust only CAs whose issuance you control or whose issuance policy you accept. Any certificate
one of these CAs issues with a client's registered subject authenticates as that client, so a
broad CA (a public web CA, for example) lets anyone who can obtain a certificate for that name
act as the client. Clients that send an intermediate CA certificate in the TLS handshake are
supported; put the root or the issuing CA in the bundle.

The file is read once at startup; restart the server to change it. It is not reloaded by
`SIGHUP` or S3 configuration polling. Revocation (CRL/OCSP) is not checked.

When the variable is unset and TLS is configured, the server logs
`tls_client_auth disabled: VOUCH_MTLS_CLIENT_CA_CERTS is not set` at startup and:

- omits `tls_client_auth` from `token_endpoint_auth_methods_supported` in discovery,
- refuses dynamic registration of `tls_client_auth` clients with `invalid_client_metadata`, and
- rejects authentication by existing `tls_client_auth` clients with `invalid_client`.

Before upgrading a server that has `tls_client_auth` clients, set this variable to the CA bundle
that issued their certificates, or those clients stop authenticating.

## Certificate Hot-Reload

Vouch supports automatic TLS certificate reloading without dropping connections. This is useful for certificate rotation (e.g., Let's Encrypt renewals).

### Via S3 Configuration

If using [S3 configuration storage](sources.md), update the `tls.cert` and `tls.key` fields in the S3 config file. The server detects changes via ETag polling and reloads automatically.

### Via SIGHUP

Send `SIGHUP` to the server process to reload TLS certificates:

```bash
kill -SIGHUP $(pgrep vouch-server)
```

> **Note**: SIGHUP only reloads TLS certificates. It does not reload any other configuration.

## Self-Signed Certificates (Development)

For development or testing:

```bash
# Generate self-signed EC certificate
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout tls_key.pem -out tls_cert.pem -days 365 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# Base64 encode for Vouch
export VOUCH_TLS_CERT="$(base64 -i tls_cert.pem | tr -d '\n')"
export VOUCH_TLS_KEY="$(base64 -i tls_key.pem | tr -d '\n')"
```
