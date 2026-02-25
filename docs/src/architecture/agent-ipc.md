# Agent IPC Protocol

This chapter documents the inter-process communication protocol between the vouch CLI and the vouch-agent background daemon.

## IPC Methods (JSON-RPC 2.0)

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `ping` | none | `"pong"` | Health check |
| `get_session` | none | `SessionInfo` | Get current session |
| `store_session` | `{token, user_email, expires_at}` | `true` | Store after login |
| `clear_session` | none | `true` | Logout |
| `get_token` | none | `string` | Get raw JWT |

## Error Codes

| Code | Constant | Meaning |
|------|----------|---------|
| -32000 | `NOT_AUTHENTICATED` | No active session |
| -32001 | `SESSION_EXPIRED` | Session has expired |
| -32601 | `METHOD_NOT_FOUND` | Unknown method |
| -32602 | `INVALID_PARAMS` | Bad parameters |

## SSH Agent IPC Operations

SSH agent operations are available via `~/.vouch/ssh-agent.sock`:

- `REQUEST_IDENTITIES` — Returns cached SSH certificate
- `SIGN_REQUEST` — Signs data with user's private key
- Certificate refresh triggered automatically when expiring (30-minute threshold)
