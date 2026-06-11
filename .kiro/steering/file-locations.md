# File Locations

## Quick Reference

| Need | Location |
|------|----------|
| CLI commands | `crates/vouch-cli/src/commands/` |
| Credential helpers | `crates/vouch-cli/src/commands/credential/` |
| Setup commands | `crates/vouch-cli/src/commands/setup/` |
| FAPI client (DPoP, etc.) | `crates/vouch-cli/src/fapi/` |
| Agent IPC | `crates/vouch-agent/src/` (state.rs, socket.rs, protocol.rs, wire.rs) |
| SSH agent protocol | `crates/vouch-agent/src/ssh_agent/` |
| API types | `crates/vouch-common/src/api.rs` |
| FIDO2 types | `crates/vouch-common/src/fido2_types.rs` |
| Encoding helpers | `crates/vouch-common/src/encoding.rs` |
| Server handlers | `crates/vouch-server/src/handlers/` |
| Server services | `crates/vouch-server/src/services/` (oidc/, integrations/) |
| Crypto primitives | `crates/vouch-server/src/crypto/` (jwt.rs, ssh_ca.rs, webauthn_verify.rs, tpm_decrypt.rs, ber.rs, pem.rs) |
| Server infra | `crates/vouch-server/src/infra/` (tls.rs, cleanup.rs, s3_config.rs, generate_document_key.rs) |
| Database modules | `crates/vouch-server/src/db/` (pool.rs, users.rs, sessions.rs, etc.) |
| DB migrations | `crates/vouch-server/migrations/{sqlite,postgres}/` |
| HTML templates | `crates/vouch-server/templates/` |
| CSS source | `crates/vouch-server/styles/input.css` |
| Static assets | `crates/vouch-server/static/` |
| HTTP signatures | `crates/vouch-httpsig/src/` |
| Integration tests | `crates/vouch-tests/tests/` |
| Property-based tests | `crates/vouch-tests/tests/proptest.rs` |
| Golden file tests | `crates/vouch-tests/tests/golden_files.rs` |
| Fuzz targets | `fuzz/` |
| Documentation (mdBook) | `docs/` |
| Packaging/AMI scripts | `packaging/` |
| Helm charts | `charts/` |
| Docker config | `Dockerfile`, `Dockerfile.build`, `docker-bake.hcl` |
| Dependency audit | `deny.toml` |

## Adding New Components

### New CLI Command
1. Create file in `crates/vouch-cli/src/commands/`
2. Add to command enum in `crates/vouch-cli/src/commands/mod.rs`
3. Implement `run()` function
4. Add tests

### New Credential Type
1. Add type to `vouch-common/src/api.rs`
2. Add credential helper in `vouch-cli/src/commands/credential/`
3. Add setup command in `vouch-cli/src/commands/setup/`
4. Update documentation

### New Server Endpoint
1. Add handler in `crates/vouch-server/src/handlers/`
2. Add service logic in `crates/vouch-server/src/services/`
3. Register route in the router
4. Add integration tests in `crates/vouch-tests/`
