# Behind a Reverse Proxy

Most deployments put something in front of the Vouch server: an AWS Network Load Balancer, nginx,
HAProxy, a Kubernetes ingress controller. This chapter covers what has to be configured for that to
work correctly, and the one setting whose absence degrades security silently.

## Terminate TLS in Vouch where you can

The recommended topology is **TCP passthrough with TLS terminated inside Vouch**, not TLS
terminated at the proxy.

Vouch pins a BCP 195 cipher suite list, prefers hybrid post-quantum key exchange, and hosts the
mTLS listener used for certificate-bound tokens. Terminating at the proxy replaces all of that with
whatever the proxy negotiates, and breaks RFC 8705 certificate-bound tokens outright, because the
client certificate never reaches Vouch.

Terminate at the proxy only when something else forces it — a corporate WAF requirement, or a
managed load balancer that cannot pass TCP through, such as an AWS Application Load Balancer. If
you do, everything below still applies.

## Trusted proxies

This is the setting to get right.

```bash
VOUCH_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12
```

`VOUCH_TRUSTED_PROXIES` is a comma-separated list of CIDR ranges holding your proxies. It controls
how Vouch decides a request's client IP, which in turn drives **rate limiting** and the client IP
recorded on **audit events**.

**When it is unset** (the default), `X-Forwarded-For` is ignored completely and the TCP peer
address is used as the client IP. Behind a proxy, that peer address is the proxy. Every user
therefore shares a single rate-limit bucket, and every audit event records the load balancer's
address instead of the user's.

Nothing warns you about this. The server starts cleanly, requests succeed, and the only symptom is
that a moderately busy deployment starts returning 429s to everyone at once, with audit records
that cannot attribute anything to anyone.

**When it is set**, Vouch walks `X-Forwarded-For` from right to left and takes the first address
that is *not* in the trusted set — the RFC 7239 rightmost-trusted algorithm. This is the only
approach resistant to a client spoofing extra `X-Forwarded-For` entries: injected values sit to the
left of the addresses your own proxies appended, so the walk stops before reaching them.

The behavior in full:

| Situation | Client IP used |
|-----------|----------------|
| No trusted proxies configured | TCP peer address; `X-Forwarded-For` ignored |
| Peer is not in the trusted set | TCP peer address; `X-Forwarded-For` ignored (fail closed) |
| Peer is trusted, header present | First right-to-left `X-Forwarded-For` entry outside the trusted set |
| Peer is trusted, header absent or empty | TCP peer address |
| Peer is trusted, every entry trusted | TCP peer address |
| Peer is trusted, an entry is unparseable | The walk stops there and the peer address is used |

List **only** the ranges your proxies actually occupy. Trusting an over-broad range lets anything
inside it forge a client IP. An invalid CIDR is a fatal startup error, not a warning.

Verify it by checking that audit events at `/admin/audit` show real client addresses rather than
your load balancer's.

## Host header validation

Vouch validates the `Host` header against the configured `rp_id`. A request arriving with a
mismatched host gets **421 Misdirected Request**.

This matters because WebAuthn credentials are cryptographically bound to the RP ID. Accepting an
arbitrary `Host` would let a request through under a name the browser will not honor at
authentication time.

Configure your proxy to pass the original host through:

- **nginx** — `proxy_set_header Host $host;`
- **HAProxy** — preserved by default
- **AWS NLB (TCP passthrough)** — no HTTP layer, so `Host` is never rewritten
- **Kubernetes ingress-nginx** — preserved by default

A blanket 421 across every request almost always means the proxy is rewriting `Host` to the
backend's address. On the HTTP→HTTPS redirect listener, the redirect target is built from the
configured `rp_id` rather than the incoming header, so a mismatched host cannot be used to bounce
users to another origin.

## Ports

When TLS is configured, the listen ports are **fixed** and `VOUCH_LISTEN_ADDR` is ignored:

| Port | Purpose | Configurable |
|------|---------|--------------|
| 443 | HTTPS | No — fixed when TLS is configured |
| 80 | HTTP→HTTPS redirect (308), plus `/health` | No |
| 8443 | mTLS listener for certificate-bound tokens | Yes — `VOUCH_MTLS_PORT` |

Without TLS configured, the server listens on `VOUCH_LISTEN_ADDR` (default `[::]:3000`) and none of
the above applies. That is the mode to use when the proxy terminates TLS.

The mTLS listener starts automatically whenever TLS is configured — there is no flag to disable it.
Firewall rules and security groups that open only 80 and 443 will silently break certificate-bound
tokens. See [TLS, Ports, and mTLS](tls.md).

Binding to 80 and 443 requires `CAP_NET_BIND_SERVICE` on Linux. The RPM and DEB packages set this
up; a bind failure on port 80 is logged as a warning and is not fatal, so a deployment can lose its
HTTP redirect without otherwise failing.

## Timeouts and body limits

Vouch applies a **30-second** global request timeout and a **256 KiB** global body limit, with
tighter per-route limits (8 KiB for credential issuance, 64 KiB for SCIM and SAML ACS). Set your
proxy's timeouts at or above 30 seconds so that Vouch, not the proxy, produces the timeout
response; and do not set a body limit below Vouch's, or you will convert precise 413s into opaque
proxy errors.

## Example configurations

### nginx (TLS passthrough — recommended)

```nginx
stream {
    upstream vouch {
        server 10.0.1.10:443;
    }
    server {
        listen 443;
        proxy_pass vouch;
    }
}
```

With passthrough there is no `X-Forwarded-For`: Vouch sees the client's real address as the TCP
peer, so leave `VOUCH_TRUSTED_PROXIES` unset.

### nginx (TLS terminated at the proxy)

```nginx
server {
    listen 443 ssl;
    server_name auth.example.com;

    ssl_certificate     /etc/nginx/certs/auth.example.com.pem;
    ssl_certificate_key /etc/nginx/certs/auth.example.com.key;

    location / {
        proxy_pass http://10.0.1.10:3000;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
    }
}
```

On the Vouch side, leave `VOUCH_TLS_CERT` and `VOUCH_TLS_KEY` unset, set
`VOUCH_LISTEN_ADDR=0.0.0.0:3000`, set `VOUCH_BASE_URL=https://auth.example.com` so issued URLs use
the public scheme and host, and set `VOUCH_TRUSTED_PROXIES` to the nginx host's range.

### AWS Network Load Balancer (TCP passthrough — recommended)

An NLB with TCP listeners forwards bytes untouched, so Vouch terminates TLS itself and keeps its
cipher policy, its hybrid post-quantum key exchange, and its mTLS listener. Prefer it to an
Application Load Balancer, which is HTTP-aware and always terminates TLS: that gives up all three
and breaks RFC 8705 certificate-bound tokens outright, because the client certificate never reaches
Vouch.

Use three TCP listeners, each forwarding to a **TCP** target group on the same port. A TLS target
group would terminate at the load balancer and defeat the point.

| Listener | Target group | Carries |
|----------|--------------|---------|
| TCP 443 | TCP 443 | HTTPS |
| TCP 80 | TCP 80 | Vouch's own 308 redirect to HTTPS, plus `/health` |
| TCP 8443 | TCP 8443 | mTLS, for certificate-bound tokens |

NLB listeners have no redirect action of their own, which is why port 80 forwards to the instances
and Vouch issues the redirect itself. Omit the 8443 listener only if you do not use
certificate-bound tokens.

Health-check the 443 target group with protocol **HTTPS** and path **`/health/ready`**. The health
check's `Host` header is the load balancer node's IP rather than your domain, which is fine — Vouch
validates `Host` only on the port 80 redirect listener. Do not health-check port 80 instead: it
serves `/health` but not `/health/ready`, so it reports a live process even when the database is
unreachable.

On the Vouch side, set `VOUCH_TLS_CERT` and `VOUCH_TLS_KEY`, set `VOUCH_BASE_URL` to the public
HTTPS URL, and leave `VOUCH_TRUSTED_PROXIES` **unset**.

**Client IP preservation is the setting that bites.** TCP passthrough has no `X-Forwarded-For`, so
the TCP peer address is the only client identity Vouch ever sees, and `VOUCH_TRUSTED_PROXIES`
cannot recover it. Preservation is on by default for **instance** targets, but **off by default for
IP targets on TCP and TLS target groups**. Left off, every request appears to come from a load
balancer node: all users share one rate-limit bucket and audit events attribute nothing to anyone.
Set `preserve_client_ip.enabled` to `true` on IP target groups.

If cross-zone load balancing is disabled, register a target in **every** Availability Zone the load
balancer has a node in. A zone whose node has no local target does not fail fast — it holds the
connection for several seconds before falling back to another zone, which surfaces as intermittent
multi-second latency rather than as an error.

## Checklist

With TCP passthrough:

- [ ] Client IP preservation is on for the target group, and `VOUCH_TRUSTED_PROXIES` is unset
- [ ] Listeners exist for 443, 80, and 8443 if you use certificate-bound tokens
- [ ] Health checks use HTTPS on 443, not HTTP on 80

With TLS terminated at the proxy:

- [ ] `VOUCH_TRUSTED_PROXIES` covers your proxy ranges, and nothing wider
- [ ] The proxy forwards the original `Host`
- [ ] The proxy appends to `X-Forwarded-For` rather than replacing it

Either way:

- [ ] Health checks target `/health/ready`, not `/health`
- [ ] `VOUCH_BASE_URL` is the public URL clients use
- [ ] Proxy timeouts are at least 30 seconds
- [ ] Audit events at `/admin/audit` show real client IPs
