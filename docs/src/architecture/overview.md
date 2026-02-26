# System Overview

This chapter covers Vouch's product vision, core design principles, security proposition, and high-level system architecture.

## Product Vision

**"No credential without proven human presence."**

```bash
$ vouch login
Touch your YubiKey...
YubiKey PIN: ********
Authenticated as user@company.com (8 hours)

$ ssh prod.example.com    # Just works
$ aws s3 ls               # Just works
$ git push origin main    # Just works
```

## Design Principles

1. **Hardware-bound only** — Hardware FIDO2 authenticators required, no platform passkeys (Touch ID, Windows Hello)
2. **Presence is mandatory** — No credential issuance without authenticator touch + PIN
3. **Credentials are ephemeral** — 8-hour maximum lifetime, no persistent secrets
4. **Tools stay native** — Configure standard credential providers, don't wrap commands
5. **Browser enrollment, CLI login** — One-time browser setup, daily use is CLI-only

## Security Proposition

| Factor | How Vouch Delivers |
|--------|-------------------|
| **Something you HAVE** | Hardware FIDO2 key (hardware-bound, not syncable) |
| **Something you KNOW** | PIN (verified on-device, never transmitted) |
| **Presence proof** | Physical touch sensor |
| **Time-bound** | 8-hour sessions, no long-lived secrets |

**Policy**: Hardware-bound FIDO2 authenticators only. No platform passkeys, no Touch ID/Windows Hello. This is the differentiator.

## System Overview

```
                              User's Machine
 +---------------------------------------------------------------------------+
 |                                                                           |
 |  +---------------------------------------------------------------------+  |
 |  |                           vouch CLI                                 |  |
 |  |                                                                     |  |
 |  |  * vouch enroll     (one-time, opens browser, first key)           |  |
 |  |  * vouch login      (daily, CLI only, discoverable credential)     |  |
 |  |  * vouch register   (add backup key, requires login first)         |  |
 |  |  * vouch status                                                    |  |
 |  |  * vouch logout                                                    |  |
 |  |  * vouch keys        (interactive menu, or list|remove|rename)     |  |
 |  |  * vouch credential ssh|aws|github|docker|cargo|codeartifact        |  |
 |  |  * vouch setup ssh|aws|github|docker|cargo|eks|codeartifact|codecommit |  |
 |  |  * vouch doctor     (diagnostic checks)                            |  |
 |  |  * vouch completions (shell completions)                           |  |
 |  +---------------------------------------------------------------------+  |
 |                    |                                                      |
 |                    | IPC (Unix socket)                                    |
 |                    v                                                      |
 |  +----------------------+     +----------------------------------------+  |
 |  |    vouch-agent       |     |        Native Tools                    |  |
 |  |    (background)      |     |                                        |  |
 |  |                      |     |  ssh --> IdentityAgent --> vouch agent |  |
 |  |  * Session cache     |     |  aws --> credential_process --> vouch  |  |
 |  |  * SSH certs         |     |  git --> credential helper --> vouch   |  |
 |  |  * SSH agent protocol|     |  cargo -> credential provider -> vouch |  |
 |  +----------------------+     +----------------------------------------+  |
 |            |                                                              |
 |            | HTTPS                                                        |
 +---------------------------------------------------------------------------+
             |
             v
 +---------------------------------------------------------------------------+
 |                            Vouch Server                                   |
 |                                                                           |
 |  +----------------+  +----------------+  +----------------+  +---------+ |
 |  |  Auth Portal   |  |   SSH CA       |  | OIDC Provider  |  | GitHub  | |
 |  |                |  |   (built-in)   |  |                |  |  App    | |
 |  |  * WebAuthn    |  |                |  | * /.well-known |  |         | |
 |  |  * Google OIDC |  |  * Ed25519 CA  |  | * /oauth/token |  | * Inst. | |
 |  |  * Sessions    |  |  * User certs  |  | * AWS federat. |  |  tokens | |
 |  +----------------+  +----------------+  +----------------+  +---------+ |
 |                                                                           |
 |  Policy: Hardware-bound FIDO2 authenticators only                       |
 +---------------------------------------------------------------------------+
```

## Vouch Cloud

Vouch Cloud is the managed deployment at [https://us.vouch.sh](https://us.vouch.sh). It runs on Amazon EC2 instances with [NitroTPM attestation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation.html), providing cryptographic proof that the server runs on genuine AWS hardware. This removes the need to trust the operator with access to the underlying compute environment.

## Session Storage

Vouch stores session information in multiple locations for different use cases:

### Agent IPC (Primary)

The vouch-agent daemon stores the active session in memory, accessible via Unix socket IPC:

```
~/.vouch/agent.sock    # JSON-RPC 2.0 IPC socket
```

**Used by:** CLI tools, credential helpers

### Config File (Fallback)

When the agent is not running, sessions are stored in the config file:

```
~/.vouch/config.json
```

**Format:** JSON with `token` field containing the JWT access token

### Cookie File

A Netscape-format cookie file is written on login for use with `curl -b`:

```
~/.vouch/cookie.txt
```

**Used by:** `curl -b ~/.vouch/cookie.txt`, `wget --load-cookies`, and other HTTP tools that support Netscape cookie format.

## Security Properties

1. **Credential issuance requires presence** — Every credential traces to a FIDO2 assertion with user verification
2. **No persistent secrets** — All credentials expire, no long-lived keys to rotate or revoke
3. **Hardware-bound only** — Platform passkeys explicitly disallowed
4. **Discoverable credentials** — User identified by credential_id, not email
5. **Audit trail** — Every credential issuance logged with session attestation
6. **Compromise recovery** — Revoke authenticator registration, all sessions invalidated

For a detailed analysis of the security model, see the [Security Model](../security/model.md). For threat analysis, see the [Threat Model](../threat-model/overview.md).

