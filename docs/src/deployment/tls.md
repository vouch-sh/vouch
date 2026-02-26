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

Both `VOUCH_TLS_CERT` and `VOUCH_TLS_KEY` must be set together. If only one is provided, the server will fail to start.

### TLS Properties

- **Protocol**: TLS 1.3 only
- **Implementation**: rustls (no OpenSSL)
- **Ciphers**: AEAD only (AES-GCM, ChaCha20-Poly1305)

## Certificate Hot-Reload

Vouch supports automatic TLS certificate reloading without dropping connections. This is useful for certificate rotation (e.g., Let's Encrypt renewals).

### Via S3 Configuration

If using [S3 configuration storage](../operations/s3-configuration.md), update the `tls.cert` and `tls.key` fields in the S3 config file. The server detects changes via ETag polling and reloads automatically.

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
