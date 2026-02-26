# Authentication Flows

This chapter describes the core authentication flows in Vouch, from initial enrollment through daily login, key management, and transparent credential requests.

## Enrollment (One-Time, Browser Required)

Links OIDC identity (Google Workspace) to hardware FIDO2 passkey using RFC 8628 Device Authorization Grant:

```
+--------+     +-----------+     +--------------+     +--------------+     +----------+
|  User  |     |   vouch   |     |  vouch.sh    |     |   OIDC       |     | YubiKey  |
|        |     |   CLI     |     |   (browser)  |     |   Provider   |     |          |
+---+----+     +-----+-----+     +------+-------+     +------+-------+     +----+-----+
    |                |                  |                    |                  |
    | vouch enroll   |                  |                    |                  |
    |--------------->|                  |                    |                  |
    |                |                  |                    |                  |
    |                | POST /oauth/device/code               |                  |
    |                |----------------->|                    |                  |
    |                |                  |                    |                  |
    |                | device_code,     |                    |                  |
    |                | user_code        |                    |                  |
    |                |<-----------------|                    |                  |
    |                |                  |                    |                  |
    | "Go to URL,    |                  |                    |                  |
    |  enter ABCD-   |                  |                    |                  |
    |  1234"         |                  |                    |                  |
    |<---------------|                  |                    |                  |
    |                |                  |                    |                  |
    |  [Opens browser, enters code]     |                    |                  |
    |---------------------------------->|                    |                  |
    |                |                  |                    |                  |
    |                |                  | Redirect to OIDC   |                  |
    |                |                  |------------------->|                  |
    |                |                  |                    |                  |
    |                |                  | OIDC callback      |                  |
    |                |                  |<-------------------|                  |
    |                |                  |                    |                  |
    |                |                  | WebAuthn create    |                  |
    |                |                  |----------------------------------->|
    |                |                  |                    |                  |
    |  [Touch key, enter PIN]           |    Attestation     |                  |
    |                |                  |<-----------------------------------|
    |                |                  |                    |                  |
    |                |                  | Mark authorized    |                  |
    |                |                  |                    |                  |
    |                | POST /oauth/token (poll)              |                  |
    |                |----------------->|                    |                  |
    |                |                  |                    |                  |
    |                | access_token     |                    |                  |
    |                |<-----------------|                    |                  |
    |                |                  |                    |                  |
    | Enrolled as    |                  |                    |                  |
    |   user@co.com  |                  |                    |                  |
    |<---------------|                  |                    |                  |
```

**Why [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)?** Unlike traditional OAuth callbacks that require a local HTTP server, the Device Authorization Grant:
- Works in headless/SSH environments (no localhost binding)
- Works behind firewalls (no inbound connections)
- Simple user experience — the CLI displays a `user_code`, the user enters it in the browser
- Industry standard (used by Azure CLI, GitHub CLI, etc.)

**Server stores:** credential_id <-> user@company.com (from OIDC provider)

**Key insight**: The passkey is created as a *discoverable credential* (resident key) on the hardware authenticator, so subsequent logins don't require the user to provide their email.

**Note:** During first `vouch enroll`, the CLI auto-registers as a FAPI 2.0 client via RFC 7591 Dynamic Client Registration (`POST /oauth/register`), generating an ES256 key pair for subsequent `private_key_jwt` client authentication and DPoP proofs.

## Daily Login (CLI Only, No Browser)

Uses discoverable credential from the hardware authenticator via FAPI 2.0:

```
+--------+     +-----------+     +--------------+     +----------+
|  User  |     |   vouch   |     |    Server    |     | YubiKey  |
|        |     |   CLI     |     |              |     |          |
+---+----+     +-----+-----+     +------+-------+     +----+-----+
    |                |                  |                  |
    | vouch login    |                  |                  |
    | (no email!)    |                  |                  |
    |--------------->|                  |                  |
    |                |                  |                  |
    |                | POST /oauth/fido2/challenge         |
    |                |----------------->|                  |
    |                |                  |                  |
    |                | challenge +      |                  |
    |                | state            |                  |
    |                |<-----------------|                  |
    |                |                  |                  |
    |                | CTAP2: Get discoverable credentials |
    |                | for RP "vouch.sh"                   |
    |                |----------------------------------->|
    |                |                  |                  |
    |  Touch key     |                  |                  |
    |<---------------|                  |                  |
    |                |                  |                  |
    |  Enter PIN     |                  |                  |
    |<---------------|                  |                  |
    |                |                  |                  |
    |                | Assertion + credential_id          |
    |                |<-----------------------------------|
    |                |                  |                  |
    |                | POST /oauth/token                  |
    |                |   grant_type=fido2-assertion        |
    |                |   client_assertion (private_key_jwt)|
    |                |   DPoP proof                        |
    |                |   base64url assertion               |
    |                |----------------->|                  |
    |                |                  |                  |
    |                |                  | Verify assertion |
    |                |                  | Lookup user by   |
    |                |                  | credential_id    |
    |                |                  | -> user@co.com   |
    |                |                  |                  |
    |                | DPoP-bound OAuth |                  |
    |                | access token     |                  |
    |                | (8 hours)        |                  |
    |                |<-----------------|                  |
    |                |                  |                  |
    | Authenticated  |                  |                  |
    |   8 hours      |                  |                  |
    |<---------------|                  |                  |
```

**Key insight**: The authenticator's discoverable credential (passkey) identifies the user. No email needed for daily login. The CLI auto-registers as a FAPI client (RFC 7591) during first `vouch enroll` or `vouch login`.

**PIN Setup**: If the hardware authenticator doesn't have a PIN configured, `vouch login` and `vouch register` will detect this and guide the user through setting one up. Vouch requires a minimum 8-character PIN for security.

## Adding Additional Keys (CLI, Requires Login)

After initial enrollment, users can add backup keys via CLI:

```
+--------+     +-----------+     +--------------+     +----------+
|  User  |     |   vouch   |     |    Server    |     | YubiKey  |
|        |     |   CLI     |     |              |     | (new)    |
+---+----+     +-----+-----+     +------+-------+     +----+-----+
    |                |                  |                  |
    | vouch login    |  (with existing key)                |
    |--------------->|                  |                  |
    |                |  [... standard login flow ...]      |
    |                |                  |                  |
    | vouch register |                  |                  |
    | --name "Backup"|                  |                  |
    |--------------->|                  |                  |
    |                |                  |                  |
    |                | POST /v1/keys/register/start        |
    |                | Authorization: Bearer <token>       |
    |                |----------------->|                  |
    |                |                  |                  |
    |                |                  | Verify session   |
    |                |                  | Get user from    |
    |                |                  | session claims   |
    |                |                  | Return challenge |
    |                |                  | + excludeCredIDs |
    |                |                  |                  |
    |                | Challenge +      |                  |
    |                | exclude list     |                  |
    |                |<-----------------|                  |
    |                |                  |                  |
    |                | CTAP2: makeCredential               |
    |                |----------------------------------->|
    |                |                  |                  |
    |  Touch key     |                  |                  |
    |  Enter PIN     |                  |                  |
    |<---------------|                  |                  |
    |                |                  |                  |
    |                | Attestation      |                  |
    |                |<-----------------------------------|
    |                |                  |                  |
    |                | POST /v1/keys/register/complete     |
    |                |----------------->|                  |
    |                |                  |                  |
    |                |                  | Check duplicate  |
    |                |                  | Store credential |
    |                |                  |                  |
    |                | Success          |                  |
    |                |<-----------------|                  |
    |                |                  |                  |
    | "Key added"    |                  |                  |
    |<---------------|                  |                  |
```

**Security controls:**
- Requires valid access token (must `vouch login` first)
- Email comes from session claims (OIDC-verified), not user input
- `excludeCredentials` prevents re-registering the same credential on the same authenticator
- Server checks for duplicate credential_id per user before storing

## Credential Request (Transparent)

```
+--------+     +-----------+     +-----------+     +--------------+
|  User  |     |    ssh    |     |   vouch   |     |    Server    |
+---+----+     +-----+-----+     +-----+-----+     +------+-------+
    |                |                 |                  |
    | ssh server     |                 |                  |
    |--------------->|                 |                  |
    |                |                 |                  |
    |                | Request identity|                  |
    |                | (via SSH agent) |                  |
    |                |---------------->|                  |
    |                |                 |                  |
    |                |                 | (if cert expired |
    |                |                 |  or missing)     |
    |                |                 |                  |
    |                |                 | GET /v1/creds/ssh|
    |                |                 | + access token   |
    |                |                 |----------------->|
    |                |                 |                  |
    |                |                 | SSH certificate  |
    |                |                 |<-----------------|
    |                |                 |                  |
    |                | Certificate     |                  |
    |                |<----------------|                  |
    |                |                 |                  |
    |                | [standard SSH   |                  |
    |                |  handshake]     |                  |
    |                |                 |                  |
    | Connected      |                 |                  |
    |<---------------|                 |                  |
```

**Note:** No additional user interaction required — the access token proves recent presence attestation.
