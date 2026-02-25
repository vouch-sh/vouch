# CIBA Protocol

This chapter describes the CIBA (Client Initiated Backchannel Authentication) implementation for agent-initiated delegation, including endpoint specifications, token delivery modes, and the authentication device integration.

## Backchannel Authorization Endpoint

```
POST /bc-authorize
Content-Type: application/x-www-form-urlencoded
```

**Request parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `scope` | Yes | Vouch delegation scope (e.g., `github:myorg/repo:contents:write`) |
| `binding_message` | Yes | Human-readable description displayed during approval. Max 256 characters. |
| `client_id` | Yes | Registered agent client ID |
| `login_hint` | Yes | Email or user ID of the human who should approve |
| `requested_expiry` | No | Requested delegation TTL in seconds. Server may shorten based on org policy. Default: 7200 (2 hours). |

Vouch requires `binding_message` (the CIBA spec makes it optional). The message must be displayed verbatim to the human -- it is the human's only context for what they are approving.

**Response (200 OK):**

```json
{
  "auth_req_id": "1c266114-a1be-4252-8ad1-04986c5b9ac1",
  "expires_in": 300,
  "interval": 5
}
```

| Field | Description |
|-------|-------------|
| `auth_req_id` | Unique identifier for this authorization request |
| `expires_in` | Seconds until this request expires if the human does not respond |
| `interval` | Minimum polling interval in seconds |

**Error responses:**

| HTTP Status | Error | When |
|-------------|-------|------|
| 400 | `invalid_scope` | Scope is malformed or not permitted by org policy |
| 400 | `invalid_binding_message` | Missing or exceeds 256 characters |
| 400 | `unknown_user_id` | `login_hint` does not match a Vouch user |
| 401 | `invalid_client` | `client_id` is not registered |
| 403 | `unauthorized_client` | Client is not permitted to request this scope |

## Token Endpoint

The agent polls the token endpoint until the human approves, rejects, or the request expires.

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:openid:params:grant-type:ciba&auth_req_id=1c266114-a1be-4252-8ad1-04986c5b9ac1
```

**Success response (200 OK):**

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 7200,
  "scope": "github:myorg/repo:contents:write"
}
```

The `access_token` is a delegation token (JWT signed by Vouch) that the agent uses for credential requests, identical to tokens produced by the human-initiated `vouch delegate` flow.

**Pending response (400):**

```json
{
  "error": "authorization_pending",
  "error_description": "The authorization request is still pending."
}
```

**Other error responses:**

| Error | Description |
|-------|-------------|
| `authorization_pending` | Human has not yet responded. Agent should continue polling. |
| `slow_down` | Agent is polling faster than `interval`. Back off by 5 seconds. |
| `access_denied` | Human explicitly rejected the request. |
| `expired_token` | Human did not respond before `expires_in` elapsed. |

## Token Delivery Modes

CIBA defines three modes for how the agent learns that the human has approved. Vouch will implement poll mode first.

**Poll mode (v0.7):** The agent polls `POST /token` at the specified `interval`. Simplest to implement, no infrastructure dependencies, works for both local and remote agents.

**Ping mode (future):** Vouch sends an HTTP callback to the agent's registered `notification_endpoint` when the human approves. The agent then calls the token endpoint once to retrieve the token. Requires the agent to expose an HTTP endpoint, but eliminates polling latency.

**Push mode:** Not planned. Push mode delivers the token directly in the callback, which means the token traverses an additional network hop and the callback endpoint must be trusted.

## Authentication Device

When a CIBA request arrives, Vouch needs to notify the human and collect their YubiKey approval. The vouch-agent daemon on the human's machine serves as the authentication device.

```
Vouch Server                    vouch-agent (human's machine)
  |                                  |
  | WebSocket/SSE: new auth request  |
  | { auth_req_id,                   |
  |   binding_message,               |
  |   client_id,                     |
  |   scope }                        |
  |--------------------------------->|
  |                                  |
  |                                  | Display to human:
  |                                  | +-----------------------------------+
  |                                  | | Credential Request                |
  |                                  | |                                   |
  |                                  | | claude-code requests:             |
  |                                  | | github:myorg/repo:contents:write  |
  |                                  | |                                   |
  |                                  | | "Implementing feature X"          |
  |                                  | |                                   |
  |                                  | | Touch YubiKey to approve          |
  |                                  | | Press Escape to deny              |
  |                                  | +-----------------------------------+
  |                                  |
  |                                  | [Human touches YubiKey]
  |                                  | FIDO2 getAssertion (challenge
  |                                  | derived from auth_req_id)
  |                                  |
  | POST /bc-approve                 |
  | { auth_req_id,                   |
  |   fido2_assertion }              |
  |<---------------------------------|
  |                                  |
  | 200 OK                           |
  |--------------------------------->|
```

The FIDO2 challenge is derived from the `auth_req_id`, binding the hardware assertion to the specific delegation request. This prevents replay: a captured assertion cannot approve a different request.

## Open Design Questions

- **Notification transport**: WebSocket (persistent connection) vs SSE (simpler) vs push notification (works when laptop is closed). Start with WebSocket since vouch-agent already maintains a connection to the server.
- **Offline approval**: If the human's machine is offline when the CIBA request arrives, the request queues until the machine reconnects or `expires_in` elapses. Acceptable for v0.7; push notifications would improve this later.
- **Multiple devices**: If a user has vouch-agent running on multiple machines, which one gets the notification? Options: all of them (first approval wins), most recently active, or user-configured primary device.
- **Agent client registration**: How do agents register as CIBA clients? Options: static registration (admin creates client IDs in Vouch), dynamic registration ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)), or implicit registration (any agent with a valid delegation token can make CIBA requests for narrower scopes).
