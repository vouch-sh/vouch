# Sessions and Tokens

Vouch sessions are time-limited, DPoP-bound OAuth 2.0 access tokens (ES256 JWTs per RFC 9068) that prove recent hardware presence verification.

## Session Lifecycle

1. **Creation** — `vouch login` performs FIDO2 assertion with YubiKey touch + PIN
2. **Active** — Access token stored in agent memory, valid for 8 hours (default)
3. **Usage** — Credential helpers exchange the access token for service-specific credentials
4. **Expiry** — Session expires automatically after the configured duration
5. **Revocation** — `vouch logout` explicitly ends the session

## Session Duration

Default: 8 hours. Configurable via:

```bash
VOUCH_SESSION_HOURS=8
```

## Where sessions live

Server-side, every session is a database record holding a **hash** of the token, never the token
itself. The token exists in full only on the client.

On the client, the access token is held in the `vouch-agent` process and, as a fallback, in files
under the user's XDG directories. That is client-side territory and is documented with the CLI at
[vouch.sh/docs](https://vouch.sh/docs/) — it is not something you configure or operate on the
server.

## Expiry and cleanup

Expired sessions are cleaned up automatically by a background task:

```bash
# Cleanup interval in minutes (default: 15, set to 0 to disable)
VOUCH_CLEANUP_INTERVAL=15
```

## Security Properties

- **Presence-bound** — Every session traces to a FIDO2 assertion with user verification
- **Time-limited** — Sessions cannot be renewed; a new login is required after expiry
- **DPoP-bound** — Access tokens are bound to the client's DPoP key; token theft without the key is useless
- **Non-transferable** — Sessions are bound to the client that created them
- **Audience-restricted** — Tokens narrowed to a specific resource are rejected at every other resource (see below)
- **Audited** — Every session creation and usage is logged

## Audience Enforcement (RFC 8707 Resource Indicators)

Access tokens carry an `aud` (audience) claim per RFC 9068. By default the
audience equals the requesting `client_id` and the token is valid at every
Vouch resource endpoint — this covers all standard flows (`vouch login`,
browser sessions, device flow, client credentials).

A client may instead narrow a token to a specific resource, either with the
RFC 8707 `resource` parameter at the authorization endpoint or with the
`audience`/`resource` parameters at token exchange (RFC 8693). Vouch's
resource endpoints (`/v1/credentials/*`, `/v1/keys`, `/api/v1/*`, RFC 7592
client management) enforce that narrowing: a narrowed token is accepted only
when its audience names this deployment (same scheme, host, and port as the
configured base URL) and its path covers the request at a path-segment
boundary. An audience of the deployment root (the base URL itself) covers
every endpoint; `{base_url}/v1/keys` covers `/v1/keys` and everything below
it, but nothing else. Requests failing the check receive `401 invalid_token`
with the standard `WWW-Authenticate` challenge, and the rejection is logged
with the client ID, audience, and request path.

Per their RFCs, the authorization-server endpoints remain audience-agnostic:
`/oauth/userinfo` accepts tokens from any client, and `/oauth/introspect` and
`/oauth/revoke` answer about any token the server issued. Token exchange
accepts narrowed subject tokens, since re-scoping them is its purpose, but
keeps them narrowed, the way it keeps a bound subject token bound. Without an
`audience` or `resource` the exchanged token carries the subject's audience,
and a request for an audience Vouch itself accepts (the exchanging client's
default, or any resource on this deployment) is refused with
`invalid_request` unless it is the subject's own. A narrowed token can
therefore be re-scoped to another external service, but never turned back
into one Vouch's endpoints accept.

The `__Host-vouch_session` cookie holds only a browser session: a token
issued to this deployment itself (browser sign-in, enrollment, and
certification all mint one), covering the whole deployment, and not
sender-constrained. The UI pages and `/oauth/authorize` treat any other token
in the cookie, such as an access token issued to an OAuth client or narrowed
to a resource, as signed out.

Clients registered without `resource_uris` may request any `resource` value
at issuance. This is safe under enforcement: a token narrowed to an external
resource server is *less* usable at Vouch, not more — it can only be spent at
the external service it names. Registering `resource_uris` additionally
restricts which values a client may request at all. That includes the default:
an RFC 8693 exchange for an ID token with no `audience` gets `aud` set to the
issuer, so a client with `resource_uris` must list the issuer to use it.
`resource_uris` entries are compared as exact strings, because the value
becomes the token's `aud` and RFC 7519 §2 compares those "as case-sensitive
strings with no transformations or canonicalizations applied". Register the
issuer exactly as `/.well-known/openid-configuration` publishes it, with no
trailing slash: `https://vouch.example.com/` does not match.
