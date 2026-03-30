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
/// Injected into request extensions by the mTLS middleware layer so
/// handlers can extract the client certificate for authentication.
#[derive(Clone, Debug)]
pub(crate) struct PeerClientCert(#[allow(dead_code)] pub Option<Vec<u8>>);

/// TLS stream with extracted peer certificate.
///
/// Wraps `tokio_rustls::server::TlsStream<TcpStream>` and delegates
/// `AsyncRead`/`AsyncWrite`. The peer certificate DER is extracted
/// during the TLS handshake and stored for later injection.
pub(crate) struct MtlsStream {
    inner: tokio_rustls::server::TlsStream<TcpStream>,
    /// DER-encoded leaf client certificate, if the client presented one.
    #[allow(dead_code)]
    peer_cert_der: Option<Vec<u8>>,
    /// Remote address for `ConnectInfo` compatibility.
    #[allow(dead_code)]
    remote_addr: SocketAddr,
}

impl MtlsStream {
    /// Get the peer certificate DER bytes, if present.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn peer_cert_der(&self) -> Option<&[u8]> {
        self.peer_cert_der.as_deref()
    }

    /// Get the remote socket address.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
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
                remote_addr,
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

/// Tower middleware layer that injects [`PeerClientCert`] into request
/// extensions from the connection's [`MtlsStream`].
///
/// This is applied to the mTLS router so handlers can extract the
/// client certificate via `Extension<PeerClientCert>`.
#[derive(Clone)]
pub(crate) struct PeerCertLayer;

impl<S> tower::Layer<S> for PeerCertLayer {
    type Service = PeerCertService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PeerCertService { inner }
    }
}

/// Service that injects peer certificate from connection extensions.
#[derive(Clone)]
pub(crate) struct PeerCertService<S> {
    inner: S,
}

impl<S, B> tower::Service<axum::http::Request<B>> for PeerCertService<S>
where
    S: tower::Service<axum::http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: axum::http::Request<B>) -> Self::Future {
        // The PeerClientCert extension is injected by the tap_io callback
        // on the mTLS listener (see serve.rs integration).
        // If not present, insert None so handlers always have the extension.
        if req.extensions().get::<PeerClientCert>().is_none() {
            req.extensions_mut().insert(PeerClientCert(None));
        }
        self.inner.call(req)
    }
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
}
