# Session Management

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

## Session Storage

Sessions are stored in multiple locations for different access patterns:

| Location | Purpose | Security |
|----------|---------|----------|
| `vouch-agent` memory | Primary access for CLI and credential helpers | In-process, zeroized on drop |
| `~/.vouch/config.json` | Fallback when agent is not running | File permissions 0600 |
| `~/.vouch/cookie.txt` | Netscape cookie file for `curl -b` usage | File permissions 0600 |
| Server database | Server-side session record | Token hash stored, not plaintext |

## Server-Side Session Management

### Cleanup

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
- **Audited** — Every session creation and usage is logged
