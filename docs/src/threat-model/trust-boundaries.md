# Trust Boundaries and Assets

This chapter documents the data flow diagram showing how components interact across trust boundaries, defines each trust boundary and its protections, and catalogs the critical and supporting assets in the Vouch system.

## Data Flow Diagram

```
                                    TRUST BOUNDARY: Internet
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                                                                 │
│                              External Services                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                         │
│  │ Google OIDC  │  │   AWS STS    │  │   GitHub     │                         │
│  │    OIDC      │  │   / EKS     │  │   API        │                         │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                         │
│         │                 │                 │                                 │
└─────────┼─────────────────┼─────────────────┼─────────────────────────────────┘
          │                 │                 │
          │ HTTPS/TLS 1.3   │                 │
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         TRUST BOUNDARY: Vouch Server                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                           Vouch Server                                   │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │   │
│  │  │ Auth Portal │  │   SSH CA    │  │    OIDC     │  │   GitHub    │     │   │
│  │  │             │  │  (Ed25519)  │  │  Provider   │  │    App      │     │   │
│  │  │ • WebAuthn  │  │             │  │             │  │             │     │   │
│  │  │ • Sessions  │  │ • Sign certs│  │ • JWKS      │  │ • Inst.     │     │   │
│  │  │ • Enrollment│  │ • 8hr TTL   │  │ • Tokens    │  │   tokens    │     │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘     │   │
│  │                                                                          │   │
│  │  ┌─────────────────────────────────────────────────────────────────┐    │   │
│  │  │              Database (SQLite/PostgreSQL/Aurora DSQL)            │    │   │
│  │  │  • Users  • Authenticators  • Sessions  • Audit Logs            │    │   │
│  │  └─────────────────────────────────────────────────────────────────┘    │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ HTTPS/TLS 1.3
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         TRUST BOUNDARY: User Workstation                        │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                              vouch CLI                                   │   │
│  │  • vouch enroll      • vouch login       • vouch register               │   │
│  │  • vouch credential  • vouch setup       • vouch keys                   │   │
│  └────────────────────────────────┬────────────────────────────────────────┘   │
│                                   │ IPC (Unix socket)                          │
│                                   ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                            vouch-agent                                   │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                      │   │
│  │  │  Session    │  │    Cert     │  │  SSH Agent  │                      │   │
│  │  │  Manager    │  │    Cache    │  │  Protocol   │                      │   │
│  │  │             │  │             │  │             │                      │   │
│  │  │ • 8hr TTL   │  │ • SSH certs │  │ • Identities│                      │   │
│  │  │ • SecretStr │  │ • Auto-     │  │ • Sign      │                      │   │
│  │  │             │  │   refresh   │  │   requests  │                      │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                      │   │
│  │                                                                          │   │
│  │  ~/.vouch/agent.sock (0700)    ~/.vouch/ssh-agent.sock                  │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                          Native Tools                                    │   │
│  │  ssh → IdentityAgent    aws → credential_process    git → credential    │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ USB HID
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         TRUST BOUNDARY: Hardware                                │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    Hardware FIDO2 Authenticator                           │   │
│  │                                                                          │   │
│  │  • Private keys (non-exportable)     • PIN verification (on-device)     │   │
│  │  • Discoverable credentials          • Touch sensor (presence proof)     │   │
│  │  • Attestation certificate           • Secure element                    │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Trust Boundaries

| Boundary | Description | Protection |
|----------|-------------|------------|
| **Internet ↔ Server** | Public network to Vouch server | TLS 1.3, certificate validation |
| **Server ↔ Database** | Application to data store | Parameterized queries, encryption at rest |
| **Server ↔ Workstation** | Server to user machine | TLS 1.3, JWT validation |
| **CLI ↔ Agent** | User commands to daemon | Unix socket permissions (0700) |
| **Agent ↔ Hardware Authenticator** | Software to hardware | CTAP2 protocol, PIN verification |
| **Workstation ↔ External Services** | Local machine to AWS/GitHub | TLS 1.3, short-lived tokens |

---

## Assets

### Critical Assets

| Asset | Description | CIA Priority |
|-------|-------------|--------------|
| **Authenticator Private Keys** | Non-exportable FIDO2 keys | C > I > A |
| **OAuth Access Tokens (ES256, RFC 9068)** | 8-hour DPoP-bound authentication tokens | C > I > A |
| **CLI ES256 Key Pair** | FAPI 2.0 client key for DPoP and private_key_jwt | C > I > A |
| **SSH CA Private Key** | Ed25519 key for signing certificates | C > I > A |
| **User Credentials** | Temporary AWS/GitHub tokens | C > I > A |
| **Audit Logs** | Credential issuance records | I > A > C |

### Supporting Assets

| Asset | Description | CIA Priority |
|-------|-------------|--------------|
| **User Database** | Email, credential mappings | I > C > A |
| **OIDC Configuration** | External IdP settings | I > A > C |
| **SSH Certificates** | Signed user certificates | I > C > A |
| **Config File** | Local session storage (`~/.vouch/config.json`) | C > I > A |
| **FAPI Client Registration** | RFC 7591 client_id and server-stored public key | I > C > A |
