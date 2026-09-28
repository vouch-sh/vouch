// SPDX-License-Identifier: Apache-2.0 OR MIT
//! mTLS listener for RFC 8705 certificate-bound access tokens.
//!
//! Provides the [`Handshake`] the shared accept loop ([`super::accept`]) runs
//! for the mTLS port. It:
//! 1. Performs the TLS handshake with optional client certificate verification
//! 2. Extracts the peer certificate chain DER for injection into request
//!    extensions as `ConnectInfo<PeerClientCert>`
//!
//! The mTLS listener runs on a separate port (default 8443) from the main
//! HTTPS listener (443), matching RFC 8705's `mtls_endpoint_aliases` pattern.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio_rustls::TlsAcceptor;

use super::accept::{ClientStream, Handshake};

/// The mTLS connection's peer certificate chain and remote socket address.
///
/// Both travel in a single connection extension because the accept loop
/// inserts exactly one `ConnectInfo<T>` per connection, where `T` is the
/// [`Handshake::Info`] of the listener. The mTLS listener's is
/// `PeerClientCert`, so on the mTLS port `ConnectInfo<PeerClientCert>` is the
/// *only* connection extension present — there is no separate
/// `ConnectInfo<SocketAddr>`. The peer `SocketAddr` therefore rides along
/// here so the rate limiter and the audit `ClientInfo` extractor (which read
/// `ConnectInfo<SocketAddr>` on the HTTPS/plain ports) can fall back to it via
/// [`connection_peer`].
///
/// `peer_chain_der` is the DER-encoded certificate chain the client presented
/// in the TLS handshake, leaf first; empty when the client presented none.
/// The intermediates travel with the leaf because `tls_client_auth`
/// (RFC 8705 §2.1) validates the chain at the application layer.
#[derive(Clone, Debug)]
pub(crate) struct PeerClientCert {
    /// DER-encoded client certificate chain, leaf first; empty if the client
    /// presented none.
    pub(crate) peer_chain_der: Vec<Vec<u8>>,
    /// Remote socket address of the mTLS connection.
    pub(crate) peer_addr: SocketAddr,
}

/// The TCP peer of a request, tagged by the listener that accepted it.
///
/// The tag decides whether `X-Forwarded-For` may be consulted, so it travels
/// with the address rather than being recomputed by each reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnectionPeer {
    /// Accepted by the HTTPS/plain listener, which may sit behind a
    /// TLS-terminating reverse proxy listed in `VOUCH_TRUSTED_PROXIES`.
    Tcp(std::net::IpAddr),
    /// Accepted by the mTLS listener. Vouch terminates TLS on this port
    /// itself, so the peer is the TLS client: a TCP passthrough proxy relays
    /// ciphertext and cannot add a header, and a proxy that terminated TLS
    /// would present its own client certificate. Any `X-Forwarded-For` here
    /// was written by the client.
    Mtls(std::net::IpAddr),
}

/// Classify a request's peer from its connection extensions.
///
/// On the main HTTPS/plain ports the connection's `ConnectInfo<SocketAddr>`
/// extension is present. On the mTLS port the accept loop only injects
/// `ConnectInfo<PeerClientCert>` (it inserts a single `ConnectInfo<T>` per
/// connection), so the peer `SocketAddr` rides on `PeerClientCert`. The IP
/// is canonicalized.
///
/// Callers resolve the client IP through
/// [`client_ip_from_request`], which honors `X-Forwarded-For` only for
/// [`ConnectionPeer::Tcp`].
///
/// [`client_ip_from_request`]: crate::infra::rate_limit::client_ip_from_request
pub(crate) fn connection_peer(extensions: &axum::http::Extensions) -> Option<ConnectionPeer> {
    if let Some(ci) = extensions.get::<axum::extract::ConnectInfo<std::net::SocketAddr>>() {
        return Some(ConnectionPeer::Tcp(ci.0.ip().to_canonical()));
    }
    extensions
        .get::<axum::extract::ConnectInfo<PeerClientCert>>()
        .map(|ci| ConnectionPeer::Mtls(ci.0.peer_addr.ip().to_canonical()))
}

/// Shared handle to the mTLS listener's rustls config.
///
/// The handshake snapshots this on every connection (`load_full`), so storing a
/// rebuilt config makes new handshakes pick up rotated certificates without
/// restarting the listener.
pub(crate) type MtlsConfigSwap = Arc<ArcSwap<rustls::ServerConfig>>;

/// TLS handshake for the mTLS port, with optional client certificate
/// verification.
///
/// Certificate verification is delegated to the application layer (see
/// [`build_mtls_server_config`]); this only records the chain the client
/// presented.
pub(crate) struct MtlsHandshake {
    tls_config: MtlsConfigSwap,
}

impl MtlsHandshake {
    /// `tls_config` is the rustls config with client cert verifier, wrapped in
    /// `ArcSwap` for hot reload.
    pub(crate) fn new(tls_config: MtlsConfigSwap) -> Self {
        Self { tls_config }
    }
}

impl Handshake for MtlsHandshake {
    type Io = tokio_rustls::server::TlsStream<ClientStream>;
    type Info = PeerClientCert;

    async fn handshake(
        &self,
        stream: ClientStream,
        peer_addr: SocketAddr,
    ) -> io::Result<(Self::Io, PeerClientCert)> {
        let acceptor = TlsAcceptor::from(self.tls_config.load_full());
        let tls_stream = acceptor.accept(stream).await?;
        let peer_chain_der = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .map(|certs| certs.iter().map(|cert| cert.to_vec()).collect())
            .unwrap_or_default();
        Ok((
            tls_stream,
            PeerClientCert {
                peer_chain_der,
                peer_addr,
            },
        ))
    }
}

/// Build a rustls `ServerConfig` for the mTLS listener.
///
/// Uses the same server certificate as the main HTTPS listener, with
/// a custom client certificate verifier that **accepts any certificate**
/// (including self-signed) and delegates identity validation to the
/// application layer.
///
/// This is required for RFC 8705 Section 2.2 (`self_signed_tls_client_auth`),
/// where clients present self-signed certificates that won't chain to any
/// CA. The TLS handshake proves possession of the private key; the
/// application layer verifies the certificate matches the client's
/// registered JWKS `x5c`, or for `tls_client_auth` (Section 2.1) validates
/// the chain against `VOUCH_MTLS_CLIENT_CA_CERTS` before matching the
/// subject.
///
/// Clients may also connect without a certificate — the application
/// layer handles unauthenticated connections.
///
/// Supports TLS 1.3 and TLS 1.2 with BCP 195 (RFC 9325) cipher suites.
/// TLS 1.2 is needed for FAPI2 conformance suite `RequireOnlyBCP195
/// RecommendedCiphersForTLS12` checks. Only ECDHE+AEAD suites are
/// permitted for TLS 1.2.
pub(crate) fn build_mtls_server_config(
    server_cert_der: Vec<rustls::pki_types::CertificateDer<'static>>,
    server_key_der: rustls::pki_types::PrivateKeyDer<'static>,
) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let client_verifier = Arc::new(AcceptAnyClientCert);

    let mut config =
        rustls::ServerConfig::builder_with_provider(Arc::new(super::tls::bcp195_crypto_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| anyhow::anyhow!("Failed to configure TLS versions: {e}"))?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_cert_der, server_key_der)
            .map_err(|e| anyhow::anyhow!("Failed to build mTLS server config: {e}"))?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

/// Rebuild the mTLS server config from PEM cert/key and store it into the
/// listener's [`MtlsConfigSwap`].
///
/// Called from the SIGHUP handler and the S3 config polling task so the
/// mTLS listener picks up rotated certificates alongside the main HTTPS
/// listener. On error the swap is left unchanged (existing connections and
/// new handshakes keep the previous certificates).
pub(crate) fn reload_mtls_from_config(
    mtls_config: &MtlsConfigSwap,
    cert: &str,
    key: &secrecy::SecretString,
) -> anyhow::Result<()> {
    let (certs, key_der) = super::tls::parse_cert_and_key_pem(cert, key)?;
    let new_config = build_mtls_server_config(certs, key_der)?;
    mtls_config.store(new_config);
    Ok(())
}

/// Client certificate verifier that accepts any certificate.
///
/// Delegates all identity validation to the application layer. The TLS
/// handshake still proves the client possesses the private key for the
/// presented certificate — this verifier simply skips chain validation.
///
/// This supports:
/// - `tls_client_auth` (RFC 8705 §2.1): app layer validates the chain
///   against the configured client CAs, then checks subject/SAN
/// - `self_signed_tls_client_auth` (RFC 8705 §2.2): app layer checks x5c
/// - Unauthenticated connections: app layer handles auth via other methods
#[derive(Debug)]
struct AcceptAnyClientCert;

impl rustls::server::danger::ClientCertVerifier for AcceptAnyClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // Accept any certificate — application layer validates identity.
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::AppState;
    use crate::client_info::ClientInfo;
    use crate::infra::accept::{self, ConnLimits, ProxyProtocol};
    use crate::infra::conn_caps::ConnCaps;
    use crate::infra::router::build_app;
    use crate::infra::tls;
    use crate::test_utils;
    use std::io::{Read as _, Write as _};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_util::sync::CancellationToken;

    /// Build a self-signed server cert and PKCS#8 key for testing.
    ///
    /// Returns `(cert_der_bytes, pkcs8_der_bytes)`.
    fn make_self_signed_server_cert() -> (Vec<u8>, Vec<u8>) {
        use der::{Decode, Encode};
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::EncodePrivateKey;
        use spki::EncodePublicKey;
        use x509_cert::builder::{Builder as _, CertificateBuilder, Profile};
        use x509_cert::name::RdnSequence;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);

        // Build CN-only subject
        let cn_oid = der::oid::ObjectIdentifier::new_unwrap("2.5.4.3");
        let cn_value = der::asn1::Utf8StringRef::new("test.example.com").expect("CN");
        let atv = x509_cert::attr::AttributeTypeAndValue {
            oid: cn_oid,
            value: der::asn1::Any::from(cn_value),
        };
        let mut rdn_set = der::asn1::SetOfVec::new();
        rdn_set.insert(atv).expect("insert RDN");
        let subject = RdnSequence(vec![x509_cert::name::RelativeDistinguishedName(rdn_set)]);

        let validity =
            Validity::from_now(core::time::Duration::from_secs(86400)).expect("validity");
        let serial = SerialNumber::new(&[1u8]).expect("serial");
        let spki_der = key.verifying_key().to_public_key_der().expect("spki DER");
        let spki =
            spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_ref()).expect("parse spki");

        let builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer: subject.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            serial,
            validity,
            subject,
            spki,
            &key,
        )
        .expect("builder");

        let cert = builder
            .build::<p256::ecdsa::DerSignature>()
            .expect("build cert");
        let cert_der = cert.to_der().expect("cert DER");

        let pkcs8_der = key.to_pkcs8_der().expect("PKCS#8 DER");
        let pkcs8_bytes = pkcs8_der.as_bytes().to_vec();

        (cert_der, pkcs8_bytes)
    }

    /// `build_mtls_server_config` with a valid server cert/key must succeed.
    #[test]
    fn test_build_mtls_server_config_valid() {
        let (cert_der, pkcs8_der) = make_self_signed_server_cert();

        let server_cert = rustls::pki_types::CertificateDer::from(cert_der);
        let server_key = rustls::pki_types::PrivateKeyDer::Pkcs8(pkcs8_der.into());

        let result = build_mtls_server_config(vec![server_cert], server_key);

        assert!(
            result.is_ok(),
            "valid server cert must succeed, got: {:?}",
            result.err()
        );
    }

    /// Wrap DER bytes in a PEM envelope.
    fn der_to_pem(label: &str, der: &[u8]) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let wrapped: Vec<String> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect();
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            wrapped.join("\n")
        )
    }

    /// A successful reload must store a NEW config into the swap so the
    /// next handshake picks up the rotated certificate (#710).
    #[test]
    fn test_reload_mtls_from_config_swaps_config() {
        let (cert_der, pkcs8_der) = make_self_signed_server_cert();
        let server_cert = rustls::pki_types::CertificateDer::from(cert_der.clone());
        let server_key = rustls::pki_types::PrivateKeyDer::Pkcs8(pkcs8_der.clone().into());
        let initial = build_mtls_server_config(vec![server_cert], server_key).expect("config");
        let swap: MtlsConfigSwap = Arc::new(ArcSwap::from(initial.clone()));

        let cert_pem = der_to_pem("CERTIFICATE", &cert_der);
        let key_pem = der_to_pem("PRIVATE KEY", &pkcs8_der);
        let key_secret = secrecy::SecretString::from(key_pem);

        reload_mtls_from_config(&swap, &cert_pem, &key_secret).expect("reload");
        assert!(
            !Arc::ptr_eq(&swap.load_full(), &initial),
            "reload must store a fresh config"
        );
    }

    /// A failed reload must leave the previous config in place.
    #[test]
    fn test_reload_mtls_from_config_failure_keeps_old_config() {
        let (cert_der, pkcs8_der) = make_self_signed_server_cert();
        let server_cert = rustls::pki_types::CertificateDer::from(cert_der);
        let server_key = rustls::pki_types::PrivateKeyDer::Pkcs8(pkcs8_der.into());
        let initial = build_mtls_server_config(vec![server_cert], server_key).expect("config");
        let swap: MtlsConfigSwap = Arc::new(ArcSwap::from(initial.clone()));

        let key_secret = secrecy::SecretString::from("not a key".to_string());
        let result = reload_mtls_from_config(&swap, "not a certificate", &key_secret);
        assert!(result.is_err(), "garbage PEM must fail");
        assert!(
            Arc::ptr_eq(&swap.load_full(), &initial),
            "failed reload must not touch the swap"
        );
    }

    // ========================================================================
    // connection_peer Tests
    // ========================================================================

    /// On the HTTPS/plain ports `ConnectInfo<SocketAddr>` is present and the
    /// peer is tagged `Tcp`.
    #[test]
    fn connection_peer_reads_socket_addr_as_tcp() {
        let mut ext = http::Extensions::new();
        ext.insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [203, 0, 113, 7],
            5000,
        ))));
        assert_eq!(
            connection_peer(&ext),
            Some(ConnectionPeer::Tcp(
                "203.0.113.7".parse().expect("valid IPv4")
            )),
        );
    }

    /// On the mTLS port only `ConnectInfo<PeerClientCert>` is injected; the peer
    /// resolves from `PeerClientCert.peer_addr` and is tagged `Mtls`.
    #[test]
    fn connection_peer_reads_peer_client_cert_as_mtls() {
        let mut ext = http::Extensions::new();
        ext.insert(axum::extract::ConnectInfo(PeerClientCert {
            peer_chain_der: Vec::new(),
            peer_addr: std::net::SocketAddr::from(([198, 51, 100, 42], 8443)),
        }));
        assert_eq!(
            connection_peer(&ext),
            Some(ConnectionPeer::Mtls(
                "198.51.100.42".parse().expect("valid IPv4")
            )),
        );
    }

    /// `ConnectInfo<SocketAddr>` wins when both extensions are present (the test
    /// harness can inject both); `PeerClientCert` is only a fallback.
    #[test]
    fn connection_peer_prefers_socket_addr_over_peer_client_cert() {
        let mut ext = http::Extensions::new();
        ext.insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [203, 0, 113, 7],
            5000,
        ))));
        ext.insert(axum::extract::ConnectInfo(PeerClientCert {
            peer_chain_der: Vec::new(),
            peer_addr: std::net::SocketAddr::from(([198, 51, 100, 42], 8443)),
        }));
        assert_eq!(
            connection_peer(&ext),
            Some(ConnectionPeer::Tcp(
                "203.0.113.7".parse().expect("SocketAddr wins")
            )),
        );
    }

    /// No connection extension yields `None` — the rate limiter then fails key
    /// extraction with `UnableToExtractKey` (the original 500 cause).
    #[test]
    fn connection_peer_returns_none_when_absent() {
        let ext = http::Extensions::new();
        assert_eq!(connection_peer(&ext), None);
    }

    /// Client-side verifier for the end-to-end test below: the test server's
    /// certificate is self-signed and CN-only, so name and chain checks are
    /// skipped, while handshake signatures are still verified.
    #[derive(Debug)]
    struct AcceptAnyServerCert(Arc<rustls::crypto::CryptoProvider>);

    impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    /// Serve `app` through the real accept loop and `MtlsHandshake`, as
    /// `serve.rs` wires the mTLS port, on an ephemeral loopback port.
    async fn serve_over_mtls(
        app: axum::Router,
        limits: ConnLimits,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        serve_over_mtls_with(app, limits, ProxyProtocol::off()).await
    }

    async fn serve_over_mtls_with(
        app: axum::Router,
        limits: ConnLimits,
        proxy: ProxyProtocol,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let (cert_der, pkcs8_der) = make_self_signed_server_cert();
        let server_cert = rustls::pki_types::CertificateDer::from(cert_der);
        let server_key = rustls::pki_types::PrivateKeyDer::Pkcs8(pkcs8_der.into());
        let server_config =
            build_mtls_server_config(vec![server_cert], server_key).expect("config");
        let swap: MtlsConfigSwap = Arc::new(ArcSwap::from(server_config));

        let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = tcp.local_addr().expect("local addr");
        let server = tokio::spawn(accept::serve(
            tcp,
            proxy,
            MtlsHandshake::new(swap),
            app,
            limits,
            ConnCaps::for_test(),
            CancellationToken::new(),
        ));
        (addr, server)
    }

    /// POST an unauthenticated `client_credentials` token request over a fresh
    /// TLS connection, with `extra_headers` appended, and return the HTTP
    /// status code.
    async fn post_token_over_mtls(addr: SocketAddr, extra_headers: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let provider = Arc::new(tls::bcp195_crypto_provider());
        let client_config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("client versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        let exchange = async {
            let tcp = TcpStream::connect(addr).await.expect("connect");
            let server_name =
                rustls::pki_types::ServerName::try_from("localhost").expect("server name");
            let mut tls = connector
                .connect(server_name, tcp)
                .await
                .expect("handshake");
            let body = "grant_type=client_credentials";
            let request = format!(
                "POST /oauth/token HTTP/1.1\r\nHost: localhost\r\n\
                 Content-Type: application/x-www-form-urlencoded\r\n{extra_headers}\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            tls.write_all(request.as_bytes()).await.expect("write");
            let mut response = Vec::new();
            tls.read_to_end(&mut response).await.expect("read");
            String::from_utf8_lossy(&response).into_owned()
        };
        tokio::time::timeout(std::time::Duration::from_secs(30), exchange)
            .await
            .expect("mTLS exchange timed out")
    }

    fn status_of(response: &str) -> &str {
        response.split_whitespace().nth(1).unwrap_or_default()
    }

    /// The application router served through the real accept loop and
    /// `MtlsHandshake`, as `serve.rs` wires the mTLS port, must get a
    /// rate-limited request past the limiter to its handler.
    ///
    /// The other tests in this crate build `ConnectInfo<PeerClientCert>` by
    /// hand, so they cannot notice when the listener stops supplying what the
    /// router reads. That is how the mTLS port answered every rate-limited
    /// request with 500 while the suite passed: the harness also injected a
    /// `ConnectInfo<SocketAddr>` the real listener never provides.
    #[tokio::test]
    async fn mtls_listener_serves_rate_limited_route_end_to_end() {
        // `test_config()` leaves `certification_test_token` unset, so the auth
        // rate limiter is installed on `/oauth/token`, as in production.
        let (app, _state) = test_utils::test_app().await;
        let (addr, server) = serve_over_mtls(app, ConnLimits::DEFAULT).await;

        let response = post_token_over_mtls(addr, "").await;
        server.abort();

        let status = status_of(&response);
        assert!(
            status.starts_with('4') && status != "429",
            "a client_credentials request with no client authentication must reach the \
             token handler and be refused there (4xx); a 500 means the rate limiter found \
             no client IP on the mTLS port. Response:\n{response}"
        );
    }

    /// A direct mTLS client cannot pick its own rate-limit bucket with
    /// `X-Forwarded-For`, even when its address falls inside
    /// `VOUCH_TRUSTED_PROXIES`.
    ///
    /// Vouch terminates TLS on this port, so no proxy can have written the
    /// header. Here the loopback client sits inside a trusted `127.0.0.0/8`
    /// and rotates the header on every request: were it honored, each value
    /// would be a fresh bucket and none of the requests would be limited.
    #[tokio::test]
    async fn mtls_listener_ignores_forwarded_for_from_trusted_range() {
        let state = test_utils::test_app_state().await;
        let mut config = (**state.config()).clone();
        config.trusted_proxies = vec!["127.0.0.0/8".parse().expect("valid CIDR")];
        state.config.store(Arc::new(config.clone()));
        let app = build_app(state, &config).expect("build app");
        let (addr, server) = serve_over_mtls(app, ConnLimits::DEFAULT).await;

        // `build_auth_rate_limiter` allows a burst of 8; four more requests
        // leave margin for the 2/s refill during the run.
        let mut statuses = Vec::new();
        for i in 0..12 {
            let xff = format!("X-Forwarded-For: 203.0.113.{i}\r\n");
            let response = post_token_over_mtls(addr, &xff).await;
            statuses.push(status_of(&response).to_string());
        }
        server.abort();

        assert!(
            statuses.iter().any(|s| s == "429"),
            "rotating X-Forwarded-For on the mTLS port must not reset the per-IP rate limit; \
             statuses: {statuses:?}"
        );
    }

    /// The HTTPS listener's `TlsHandshake` supplies `ConnectInfo<SocketAddr>`,
    /// so a rate-limited request reaches its handler there too.
    #[tokio::test]
    async fn https_listener_serves_rate_limited_route_end_to_end() {
        let (app, _state) = test_utils::test_app().await;
        let (cert_der, pkcs8_der) = make_self_signed_server_cert();
        let server_cert = rustls::pki_types::CertificateDer::from(cert_der);
        let server_key = rustls::pki_types::PrivateKeyDer::Pkcs8(pkcs8_der.into());
        let server_config =
            build_mtls_server_config(vec![server_cert], server_key).expect("config");
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(server_config);

        let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = tcp.local_addr().expect("local addr");
        let server = tokio::spawn(accept::serve(
            tcp,
            ProxyProtocol::off(),
            accept::TlsHandshake(tls),
            app,
            ConnLimits::DEFAULT,
            ConnCaps::for_test(),
            CancellationToken::new(),
        ));

        let response = post_token_over_mtls(addr, "").await;
        server.abort();

        let status = status_of(&response);
        assert!(
            status.starts_with('4') && status != "429",
            "the token handler must refuse the request (4xx); a 500 means the rate limiter \
             found no client IP. Response:\n{response}"
        );
    }

    /// Loopback, where the tests' PROXY sender connects from.
    fn loopback_sender() -> ProxyProtocol {
        ProxyProtocol::from_sources(&["127.0.0.0/8".parse().expect("CIDR")])
    }

    /// Serve `app` through the real accept loop and the HTTPS listener's
    /// `TlsHandshake`, taking the PROXY protocol from loopback.
    async fn serve_over_https_proxied(
        app: axum::Router,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let (cert_der, pkcs8_der) = make_self_signed_server_cert();
        let server_cert = rustls::pki_types::CertificateDer::from(cert_der);
        let server_key = rustls::pki_types::PrivateKeyDer::Pkcs8(pkcs8_der.into());
        let server_config =
            build_mtls_server_config(vec![server_cert], server_key).expect("config");
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(server_config);

        let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = tcp.local_addr().expect("local addr");
        let server = tokio::spawn(accept::serve(
            tcp,
            loopback_sender(),
            accept::TlsHandshake(tls),
            app,
            ConnLimits::DEFAULT,
            ConnCaps::for_test(),
            CancellationToken::new(),
        ));
        (addr, server)
    }

    /// A PROXY v2 header for a TCP connection from `source`.
    fn proxy_v2(source: &str) -> Vec<u8> {
        let header = proxy_header::ProxyHeader::with_address(proxy_header::ProxiedAddress::stream(
            source.parse().expect("source"),
            "192.0.2.1:443".parse().expect("destination"),
        ));
        let mut buf = Vec::new();
        header.encode_v2(&mut buf).expect("encode");
        buf
    }

    /// A socket whose first write carries `prefix` ahead of the caller's
    /// bytes, so the PROXY header and the start of the TLS ClientHello leave
    /// in one write, as a proxy relaying a client's first segment sends them.
    struct PrefixedWrite {
        tcp: std::net::TcpStream,
        prefix: Option<Vec<u8>>,
    }

    impl std::io::Read for PrefixedWrite {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.tcp.read(buf)
        }
    }

    impl std::io::Write for PrefixedWrite {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if let Some(mut first) = self.prefix.take() {
                first.extend_from_slice(buf);
                self.tcp.write_all(&first)?;
                return Ok(buf.len());
            }
            self.tcp.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.tcp.flush()
        }
    }

    /// Send `header`, then a TLS session carrying one `GET path` request, and
    /// return the response. `client_cert` is a `(cert DER, PKCS#8 DER)` pair
    /// to present. Blocking rustls, so the header can share the ClientHello's
    /// write; run on the blocking pool.
    async fn get_over_tls_after(
        addr: SocketAddr,
        header: Vec<u8>,
        path: &'static str,
        client_cert: Option<(Vec<u8>, Vec<u8>)>,
    ) -> String {
        let exchange = tokio::task::spawn_blocking(move || {
            let provider = Arc::new(tls::bcp195_crypto_provider());
            let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .expect("client versions")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)));
            let client_config = match client_cert {
                Some((cert, key)) => builder
                    .with_client_auth_cert(
                        vec![rustls::pki_types::CertificateDer::from(cert)],
                        rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()),
                    )
                    .expect("client cert"),
                None => builder.with_no_client_auth(),
            };
            let server_name =
                rustls::pki_types::ServerName::try_from("localhost").expect("server name");
            let conn = rustls::ClientConnection::new(Arc::new(client_config), server_name)
                .expect("client connection");
            let tcp = std::net::TcpStream::connect(addr).expect("connect");
            tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))
                .expect("read timeout");
            let mut tls = rustls::StreamOwned::new(
                conn,
                PrefixedWrite {
                    tcp,
                    prefix: Some(header),
                },
            );
            let request =
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            tls.write_all(request.as_bytes()).expect("write");
            let mut response = Vec::new();
            // The server may close without close_notify; what arrived is kept.
            let _eof = tls.read_to_end(&mut response);
            String::from_utf8_lossy(&response).into_owned()
        });
        tokio::time::timeout(std::time::Duration::from_secs(60), exchange)
            .await
            .expect("TLS exchange timed out")
            .expect("join")
    }

    /// The route the PROXY tests read: the client IP the audit `ClientInfo`
    /// extractor resolves.
    fn client_ip_app(state: Arc<AppState>) -> axum::Router {
        use axum::routing::get;
        axum::Router::new()
            .route(
                "/client-ip",
                get(|info: ClientInfo| async move {
                    info.client_ip()
                        .map(|ip| ip.to_string())
                        .unwrap_or_default()
                }),
            )
            .with_state(state)
    }

    /// On the HTTPS listener the PROXY header's source is the client the
    /// audit `ClientInfo` records, and the TLS handshake completes although
    /// the header and the ClientHello arrive in one write.
    #[tokio::test]
    async fn https_proxy_header_client_reaches_client_info() {
        let state = test_utils::test_app_state().await;
        let (addr, server) = serve_over_https_proxied(client_ip_app(state)).await;

        let response =
            get_over_tls_after(addr, proxy_v2("203.0.113.9:40000"), "/client-ip", None).await;
        server.abort();

        assert!(response.starts_with("HTTP/1.1 200"), "response: {response}");
        assert!(
            response.ends_with("203.0.113.9"),
            "ClientInfo must record the PROXY header's source; response: {response}"
        );
    }

    /// Each client behind the proxy gets its own rate-limit bucket: requests
    /// that all arrive from the proxy's one TCP address, but carry distinct
    /// PROXY sources, are not limited together, while the same source is.
    #[tokio::test]
    async fn https_proxy_header_client_keys_the_rate_limiter() {
        let (app, _state) = test_utils::test_app().await;
        let (addr, server) = serve_over_https_proxied(app).await;

        // `build_auth_rate_limiter` allows a burst of 8 on `/oauth/token`; a
        // GET is refused by the handler after the limiter has counted it.
        let mut distinct = Vec::new();
        for i in 0..12 {
            let header = proxy_v2(&format!("203.0.113.{i}:40000"));
            let response = get_over_tls_after(addr, header, "/oauth/token", None).await;
            distinct.push(status_of(&response).to_string());
        }
        let mut same = Vec::new();
        for _ in 0..12 {
            let header = proxy_v2("198.51.100.7:40000");
            let response = get_over_tls_after(addr, header, "/oauth/token", None).await;
            same.push(status_of(&response).to_string());
        }
        server.abort();

        assert!(
            distinct.iter().all(|s| !s.is_empty() && s != "429"),
            "distinct clients behind one proxy must not share a bucket; statuses: {distinct:?}"
        );
        assert!(
            same.iter().any(|s| s == "429"),
            "one client behind the proxy is still limited; statuses: {same:?}"
        );
    }

    /// On the mTLS listener the client certificate chain survives the PROXY
    /// header, and the header's source is both `PeerClientCert.peer_addr` and
    /// the client IP `ClientInfo` records.
    #[tokio::test]
    async fn mtls_client_certificate_arrives_after_proxy_header() {
        use axum::extract::ConnectInfo;
        use axum::routing::get;

        let (client_cert, client_key) = make_self_signed_server_cert();
        let expected_leaf = client_cert.clone();
        let state = test_utils::test_app_state().await;
        let app = axum::Router::new()
            .route(
                "/peer",
                get(
                    move |ConnectInfo(peer): ConnectInfo<PeerClientCert>,
                          info: ClientInfo| async move {
                        let leaf_matches = peer.peer_chain_der.first() == Some(&expected_leaf);
                        format!(
                            "{} {} {} {leaf_matches}",
                            peer.peer_addr.ip(),
                            info.client_ip()
                                .map(|ip| ip.to_string())
                                .unwrap_or_default(),
                            peer.peer_chain_der.len(),
                        )
                    },
                ),
            )
            .with_state(state);
        let (addr, server) =
            serve_over_mtls_with(app, ConnLimits::DEFAULT, loopback_sender()).await;

        let response = get_over_tls_after(
            addr,
            proxy_v2("203.0.113.9:40000"),
            "/peer",
            Some((client_cert, client_key)),
        )
        .await;
        server.abort();

        assert!(response.starts_with("HTTP/1.1 200"), "response: {response}");
        assert!(
            response.ends_with("203.0.113.9 203.0.113.9 1 true"),
            "expected peer_addr, ClientInfo IP, chain length, and leaf match; \
             response: {response}"
        );
    }

    /// A client that opens a TCP connection and never starts the TLS handshake
    /// must not block other clients from connecting.
    ///
    /// The handshake timeout is set far beyond the test's own bound, so the
    /// second request can only succeed if the stalled handshake runs in its
    /// own task rather than inside `accept`.
    #[tokio::test]
    async fn stalled_handshake_does_not_block_other_clients() {
        let (app, _state) = test_utils::test_app().await;
        let limits = ConnLimits {
            handshake: std::time::Duration::from_secs(3600),
            ..ConnLimits::DEFAULT
        };
        let (addr, server) = serve_over_mtls(app, limits).await;

        let _stalled = TcpStream::connect(addr).await.expect("connect");
        let response = post_token_over_mtls(addr, "").await;
        server.abort();

        assert!(
            status_of(&response).starts_with('4'),
            "a request must be served while another client stalls its handshake; \
             response:\n{response}"
        );
    }

    /// A client that never completes the TLS handshake is disconnected once
    /// the handshake timeout expires.
    #[tokio::test]
    async fn stalled_handshake_is_closed_after_timeout() {
        use tokio::io::AsyncReadExt;

        let (app, _state) = test_utils::test_app().await;
        let limits = ConnLimits {
            handshake: std::time::Duration::from_millis(300),
            ..ConnLimits::DEFAULT
        };
        let (addr, server) = serve_over_mtls(app, limits).await;

        let mut stalled = TcpStream::connect(addr).await.expect("connect");
        let mut received = Vec::new();
        let closed = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            stalled.read_to_end(&mut received),
        )
        .await;
        server.abort();

        assert!(
            closed.is_ok(),
            "stalled handshake must be closed by the server"
        );
    }
}
