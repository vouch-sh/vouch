# Cargo Registries

This chapter describes how Vouch integrates with Cargo for authenticating to private Rust package registries.

## Configuration

```
~/.cargo/config.toml:
  [registry]
  global-credential-providers = ["vouch", "credential", "cargo", "--"]

  # Or for a specific registry:
  [registries.my-private-registry]
  credential-provider = ["vouch", "credential", "cargo", "--"]

How it works:
1. Cargo invokes vouch as credential provider (Cargo credential provider protocol)
2. vouch sends Hello message with supported protocol versions
3. Cargo sends JSON request with registry info and action (get/login/logout)
4. vouch returns access token for registry authentication
5. Token cached by Cargo based on JWT expiration
```

## Setup

**`vouch setup cargo` creates:**
- Global credential provider configuration in `~/.cargo/config.toml`
- Or per-registry configuration with `--registry` flag

## Protocol Details

- Implements Cargo's credential provider protocol (stdin/stdout JSON)
- Supports actions: `get` (return token), `login` (redirect to vouch login), `logout`
- Token cache control derived from JWT expiration claim
- Compatible with any private Cargo registry that accepts Bearer tokens

## Usage

```bash
# Configure Cargo to use Vouch
vouch setup cargo --configure

# Or for a specific registry
vouch setup cargo --registry my-private-registry --configure

# Then use Cargo normally
cargo publish --registry my-private-registry
cargo build  # fetches from private registries automatically
```
