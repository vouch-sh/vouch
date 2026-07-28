# Dependency Management

## General Rules

- Add dependencies sparingly -- each is attack surface
- All workspace dependencies are declared in the root `Cargo.toml` under `[workspace.dependencies]`
- Pin to exact versions with minimal features
- Crates reference them with `dep.workspace = true`

## Before Adding a Dependency

1. Check maintenance status
2. Review security advisories (`cargo audit`)
3. Consider size impact
4. Prefer pure Rust over C bindings when possible

## Preferred Crates

| Purpose | Use | Do NOT use |
|---------|-----|------------|
| Time | `jiff` | `chrono` |
| Crypto | `aws-lc-rs` | `ring` |
| HTTP client | `reqwest` + `rustls` | OpenSSL |
| HTML templates | `askama` (compile-time checked) | Tera, Handlebars |
| i18n | `i18n-embed` + `unic-langid` (Fluent backend, RFC 9110 negotiation) | `gettext-rs`, raw `fluent-rs` |
| Embedded assets | `rust-embed` | bundling via build.rs |
| CLI parsing | `clap` | structopt |
| Web framework | `axum` | actix-web, rocket |
| FIDO2 | `ctap-hid-fido2` (pure Rust) | |
| SSH keys | `ssh-key` | |
| Credential storage | `keyring-core` | |
| Serialization | `serde` + `serde_json` | |
| Async runtime | `tokio` | async-std |
| Error types | `thiserror` (libraries), `anyhow` (binaries) | |

## Frontend (Server UI)

**Allowed:**
- TailwindCSS (self-hosted, no CDN)
- Tailkit (pre-built Tailwind components, full license)
- HTMX (server-driven interactivity)
- Vanilla JavaScript (WebAuthn APIs, simple UI interactions)

**Not allowed:**
- jQuery
- React, Vue, Angular, Svelte
- Any npm/node.js build toolchain for JavaScript
- External CDN dependencies

Rationale: The server UI is for enrollment tasks, not a complex SPA. Askama templates + TailwindCSS + minimal JS keeps it auditable.
