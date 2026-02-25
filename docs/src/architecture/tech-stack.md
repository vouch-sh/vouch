# Technology Stack

This chapter lists the technology choices for both the Vouch CLI and Server components, along with the rationale for each.

## CLI (Open Source)

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | Rust | Memory safety, single binary, <1ms startup |
| FIDO2 | ctap-hid-fido2 | Pure Rust, no system dependencies |
| HTTP | reqwest + rustls | No OpenSSL linking |
| CLI | clap | Standard, well-maintained |
| Time | jiff | Modern, no chrono |
| Crypto | aws-lc-rs | FIPS-validated, no ring |

## Server

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | Rust | Consistency with CLI, performance |
| Framework | Axum | Modern async, tower middleware |
| Templates | Askama | Compile-time checked, type-safe HTML |
| Styling | TailwindCSS | Utility-first, self-hosted (no CDN) |
| Database | SQLite / PostgreSQL / Aurora DSQL | Simple to start, scales later |
| SSH CA | Ed25519 (built-in) | No external dependencies |
| JWT | jsonwebtoken | Standard, well-audited |
