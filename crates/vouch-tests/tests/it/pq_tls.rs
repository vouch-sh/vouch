// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Post-quantum TLS key-exchange tests.
//!
//! Vouch relies on the rustls `prefer-post-quantum` feature (enabled in the
//! `vouch-server`, `vouch-cli`, and `vouch-agent` crates) to make the hybrid
//! X25519MLKEM768 group the preferred TLS key exchange on both inbound
//! listeners and reqwest-based outbound clients. The feature is pure
//! Cargo wiring — losing it silently downgrades every connection to
//! classical X25519, which unit tests would never notice. These tests pin
//! the negotiated group so that regression is loud.

#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panicking on an assertion failure is the point"
)]

use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConnection, NamedGroup, RootCertStore, ServerConnection};

// Throwaway self-signed P-256 cert (SAN: localhost) + PKCS#8 key, generated
// for this test only. Valid until 2036.
const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBoDCCAUagAwIBAgIUPOBIDoD8Akv9FXfEjb8GEV6GYLowCgYIKoZIzj0EAwIw\n\
HDEaMBgGA1UEAwwRdm91Y2gtcHEtdGxzLXRlc3QwHhcNMjYwNzA5MTEzMDE1WhcN\n\
MzYwNzA2MTEzMDE1WjAcMRowGAYDVQQDDBF2b3VjaC1wcS10bHMtdGVzdDBZMBMG\n\
ByqGSM49AgEGCCqGSM49AwEHA0IABO7wN7GBAX4FydRe2AvENBb6WZ9XHh4NKbkO\n\
G9ulpEIAVoZaGHMAlK7ZGTLf/tBukQxhXDwQKLLot23POsF8nP+jZjBkMB0GA1Ud\n\
DgQWBBQ3svXuWL2wS8xcHilgxDuYURTVwDAfBgNVHSMEGDAWgBQ3svXuWL2wS8xc\n\
HilgxDuYURTVwDAUBgNVHREEDTALgglsb2NhbGhvc3QwDAYDVR0TAQH/BAIwADAK\n\
BggqhkjOPQQDAgNIADBFAiEAqVgc77k203H6G5gEaAcHuna5DKJmQPCQjQLQAtry\n\
KnMCICKcoY9vNlshsz2y7RVcfGqowba3/xXj3aYFegT/BdAW\n\
-----END CERTIFICATE-----\n";

const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTljx1Qv2H2TQMKaX\n\
+palx1XsuLkORqDCzFBkRDcz3tihRANCAATu8DexgQF+BcnUXtgLxDQW+lmfVx4e\n\
DSm5DhvbpaRCAFaGWhhzAJSu2Rky3/7QbpEMYVw8ECiy6LdtzzrBfJz/\n\
-----END PRIVATE KEY-----\n";

/// Mirror of `vouch-server`'s `infra/tls.rs::bcp195_crypto_provider`: the
/// default aws-lc-rs provider with cipher suites filtered to the BCP 195
/// allowlist. Key-exchange groups are deliberately left at the provider
/// default, which is what makes `prefer-post-quantum` take effect.
fn bcp195_crypto_provider() -> rustls::crypto::CryptoProvider {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let bcp195_suites: Vec<rustls::SupportedCipherSuite> = provider
        .cipher_suites
        .iter()
        .filter(|cs| {
            matches!(
                cs.suite(),
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
                    | rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
                    | rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                    | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                    | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                    | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                    | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            )
        })
        .copied()
        .collect();

    rustls::crypto::CryptoProvider {
        cipher_suites: bcp195_suites,
        ..provider
    }
}

fn server_connection() -> ServerConnection {
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(TEST_CERT_PEM.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse test certificate");
    let key = PrivateKeyDer::from_pem_slice(TEST_KEY_PEM.as_bytes()).expect("parse test key");

    let config = rustls::ServerConfig::builder_with_provider(Arc::new(bcp195_crypto_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("configure TLS versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("build server config");

    ServerConnection::new(Arc::new(config)).expect("server connection")
}

/// Client configured like the CLI/agent outbound clients: the compiled-in
/// default provider (aws-lc-rs) with default key-exchange groups, exactly
/// what reqwest's rustls `ClientConfig` uses.
fn client_connection() -> ClientConnection {
    let mut roots = RootCertStore::empty();
    let cert = CertificateDer::from_pem_slice(TEST_CERT_PEM.as_bytes()).expect("parse test cert");
    roots.add(cert).expect("add root");

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let server_name = ServerName::try_from("localhost").expect("server name");
    ClientConnection::new(Arc::new(config), server_name).expect("client connection")
}

/// Drive an in-memory handshake between the two connections to completion.
fn complete_handshake(client: &mut ClientConnection, server: &mut ServerConnection) {
    for _ in 0..32 {
        if !client.is_handshaking() && !server.is_handshaking() {
            return;
        }

        let mut client_out = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut client_out).expect("client write_tls");
        }
        let mut unread: &[u8] = &client_out;
        while !unread.is_empty() {
            server.read_tls(&mut unread).expect("server read_tls");
        }
        server
            .process_new_packets()
            .expect("server process packets");

        let mut server_out = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut server_out).expect("server write_tls");
        }
        let mut unread: &[u8] = &server_out;
        while !unread.is_empty() {
            client.read_tls(&mut unread).expect("client read_tls");
        }
        client
            .process_new_packets()
            .expect("client process packets");
    }
    panic!("TLS handshake did not complete");
}

/// The compiled-in default provider must list the hybrid post-quantum group
/// first — this is exactly what the `prefer-post-quantum` Cargo feature
/// controls, and what makes clients send the ML-KEM key share up front.
#[test]
fn default_provider_prefers_post_quantum_key_exchange() {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let first = provider
        .kx_groups
        .first()
        .expect("provider has key-exchange groups");
    assert_eq!(
        first.name(),
        NamedGroup::X25519MLKEM768,
        "X25519MLKEM768 must be the preferred key-exchange group; \
         is the rustls `prefer-post-quantum` feature still enabled?"
    );
}

/// A server configured like vouch-server's listeners and a client configured
/// like the CLI/agent outbound clients must negotiate hybrid post-quantum
/// key exchange over TLS 1.3.
#[test]
fn handshake_negotiates_x25519mlkem768() {
    let mut client = client_connection();
    let mut server = server_connection();

    complete_handshake(&mut client, &mut server);

    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3),
        "handshake must use TLS 1.3"
    );
    for (side, group) in [
        ("client", client.negotiated_key_exchange_group()),
        ("server", server.negotiated_key_exchange_group()),
    ] {
        assert_eq!(
            group.expect("negotiated key-exchange group").name(),
            NamedGroup::X25519MLKEM768,
            "{side} must negotiate the hybrid post-quantum group"
        );
    }
}
