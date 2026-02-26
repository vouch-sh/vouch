# DPoP and FAPI 2.0

This chapter describes how the Vouch CLI operates as a FAPI 2.0 client with DPoP (Demonstrating Proof of Possession) for sender-constrained access tokens.

## FAPI 2.0 Client

The CLI operates as a FAPI 2.0 client with its own cryptographic identity:
- Generates an ES256 key pair stored in the OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager) with file fallback
- Auto-registers with the server via RFC 7591 Dynamic Client Registration on first use (`vouch enroll` or `vouch login`)
- Uses `private_key_jwt` (RFC 7523) for client authentication — no shared secrets between CLI and server
- Sends DPoP proofs (RFC 9449) with every token request
- Access tokens are sender-constrained (DPoP-bound) — token theft without the key is useless
- FAPI interaction headers (`x-fapi-interaction-id`) included for end-to-end request tracing

Key management and FAPI protocol logic lives in `crates/vouch-cli/src/fapi/` (key.rs, dpop.rs, client_assertion.rs, registration.rs).

## DPoP (RFC 9449)

DPoP binds access tokens to the client's proof-of-possession key. Every token request includes a DPoP proof JWT signed with the client's ES256 key. The server validates the proof and binds the resulting access token to that key's thumbprint.

This means:
- **Token theft is mitigated** — A stolen access token cannot be used without the corresponding private key
- **Replay protection** — DPoP proofs include a unique `jti` and the server's `nonce` value
- **No bearer tokens** — All access tokens are DPoP-bound, not bearer tokens

## Dynamic Client Registration (RFC 7591)

On first use, the CLI automatically registers itself as an OAuth client:

1. The CLI generates an ES256 key pair and stores it locally
2. It sends a `POST /oauth/register` request with its public key in the `jwks` field
3. The server returns a `client_id`
4. All subsequent token requests use `private_key_jwt` client authentication with this key

This eliminates the need for pre-shared client secrets and allows each CLI installation to have its own cryptographic identity.
