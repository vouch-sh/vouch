// SPDX-License-Identifier: Apache-2.0 OR MIT
//! mTLS listener for RFC 8705 certificate-bound access tokens.
//!
//! Provides a custom axum [`Listener`] implementation that:
//! 1. Accepts TCP connections
//! 2. Performs TLS handshake with optional client certificate verification
//! 3. Extracts the peer certificate DER for injection into request extensions
//!
//! The mTLS listener runs on a separate port (default 8443) from the main
//! HTTPS listener (443), matching RFC 8705's `mtls_endpoint_aliases` pattern.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use arc_swap::ArcSwap;
use axum::serve::Listener;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// DER-encoded peer client certificate extracted from TLS handshake.
///
/// Injected as a connection extension via [`axum::extract::ConnectInfo`] so
/// handlers can extract the client certificate for authentication.
#[derive(Clone, Debug)]
pub(crate) struct PeerClientCert(pub Option<Vec<u8>>);

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, MtlsListener>>
    for PeerClientCert
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, MtlsListener>) -> Self {
        Self(stream.io().peer_cert_der.clone())
    }
}

/// TLS stream with extracted peer certificate.
///
/// Wraps `tokio_rustls::server::TlsStream<TcpStream>` and delegates
/// `AsyncRead`/`AsyncWrite`. The peer certificate DER is extracted
/// during the TLS handshake and stored for later injection.
pub(crate) struct MtlsStream {
    inner: tokio_rustls::server::TlsStream<TcpStream>,
    /// DER-encoded leaf client certificate, if the client presented one.
    peer_cert_der: Option<Vec<u8>>,
}

impl AsyncRead for MtlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for MtlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Custom listener for mTLS: TLS with client certificate verification.
///
/// Bound to a separate port from the main HTTPS listener. Client
/// certificate verification is configured via `WebPkiClientVerifier`
/// trusting our Client Certificate CA.
pub(crate) struct MtlsListener {
    tcp: TcpListener,
    tls_config: Arc<ArcSwap<rustls::ServerConfig>>,
}

impl MtlsListener {
    /// Create a new mTLS listener.
    ///
    /// # Arguments
    /// * `tcp` - Bound TCP listener
    /// * `tls_config` - Rustls config with client cert verifier (wrapped
    ///   in `ArcSwap` for hot reload)
    pub(crate) fn new(tcp: TcpListener, tls_config: Arc<ArcSwap<rustls::ServerConfig>>) -> Self {
        Self { tcp, tls_config }
    }
}

impl Listener for MtlsListener {
    type Io = MtlsStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            // Accept TCP connection
            let (tcp_stream, remote_addr) = match self.tcp.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::debug!("mTLS TCP accept error: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };

            // Set TCP_NODELAY
            if let Err(e) = tcp_stream.set_nodelay(true) {
                tracing::trace!("Failed to set TCP_NODELAY on mTLS connection: {e:#}");
            }

            // Perform TLS handshake
            let tls_config = self.tls_config.load_full();
            let acceptor = TlsAcceptor::from(tls_config);
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    tracing::debug!(
                        remote_addr = %remote_addr,
                        "mTLS handshake failed: {e}"
                    );
                    continue;
                }
            };

            // Extract peer certificate (leaf cert only)
            let peer_cert_der = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|cert| cert.to_vec());

            let stream = MtlsStream {
                inner: tls_stream,
                peer_cert_der,
            };

            return (stream, remote_addr);
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}

/// Build a rustls `ServerConfig` for the mTLS listener.
///
/// Uses the same server certificate as the main HTTPS listener, but
/// adds a `WebPkiClientVerifier` that trusts our Client Certificate CA.
/// `allow_unauthenticated()` is used so clients without certificates
/// can still connect (application-layer auth handles the rest).
pub(crate) fn build_mtls_server_config(
    server_cert_der: Vec<rustls::pki_types::CertificateDer<'static>>,
    server_key_der: rustls::pki_types::PrivateKeyDer<'static>,
    ca_cert_der: &[u8],
) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    use anyhow::Context;
    use rustls::server::WebPkiClientVerifier;

    // Build trust store with our CA cert
    let mut root_store = rustls::RootCertStore::empty();
    let ca_cert = rustls::pki_types::CertificateDer::from(ca_cert_der.to_vec());
    root_store
        .add(ca_cert)
        .context("Failed to add CA cert to mTLS trust store")?;

    // Build client verifier: trust our CA, but allow unauthenticated
    // connections (for endpoints that don't require mTLS)
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .allow_unauthenticated()
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build mTLS client verifier: {e}"))?;

    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_cert_der, server_key_der)
        .map_err(|e| anyhow::anyhow!("Failed to build mTLS server config: {e}"))?;

    // TLS 1.3 only, ALPN h2/http1.1
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_client_cert_clone() {
        let cert = PeerClientCert(Some(vec![1, 2, 3]));
        let cloned = cert.clone();
        assert_eq!(cloned.0, Some(vec![1, 2, 3]));

        let empty = PeerClientCert(None);
        let cloned_empty = empty.clone();
        assert!(cloned_empty.0.is_none());
    }

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

    /// `build_mtls_server_config` with a valid CA cert and server cert/key must succeed.
    #[test]
    fn test_build_mtls_server_config_valid() {
        // Generate a CA
        let ca = crate::crypto::client_cert_ca::ClientCertCa::load_or_generate(None, None)
            .expect("CA generation");
        let ca_cert_der = ca.ca_cert_der();

        // Generate a self-signed server cert and private key
        let (cert_der, pkcs8_der) = make_self_signed_server_cert();

        let server_cert = rustls::pki_types::CertificateDer::from(cert_der);
        let server_key = rustls::pki_types::PrivateKeyDer::Pkcs8(pkcs8_der.into());

        let result = build_mtls_server_config(vec![server_cert], server_key, ca_cert_der);

        assert!(
            result.is_ok(),
            "valid CA + server cert must succeed, got: {:?}",
            result.err()
        );
    }

    /// `build_mtls_server_config` with garbage CA cert bytes must return an error.
    #[test]
    fn test_build_mtls_server_config_invalid_ca() {
        let (cert_der, pkcs8_der) = make_self_signed_server_cert();

        let server_cert = rustls::pki_types::CertificateDer::from(cert_der);
        let server_key = rustls::pki_types::PrivateKeyDer::Pkcs8(pkcs8_der.into());

        // Pass garbage bytes as the CA cert — should fail to parse or add to trust store
        let garbage_ca = b"this is not a valid certificate";
        let result = build_mtls_server_config(vec![server_cert], server_key, garbage_ca);

        assert!(
            result.is_err(),
            "garbage CA cert must cause build_mtls_server_config to fail"
        );
    }
}
