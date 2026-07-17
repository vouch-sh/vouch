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

/// Shared handle to the mTLS listener's rustls config.
///
/// The listener snapshots this on every accept (`load_full`), so storing a
/// rebuilt config makes new handshakes pick up rotated certificates without
/// restarting the listener.
pub(crate) type MtlsConfigSwap = Arc<ArcSwap<rustls::ServerConfig>>;

/// Custom listener for mTLS: TLS with client certificate verification.
///
/// Bound to a separate port from the main HTTPS listener. Client
/// certificate verification is configured via `WebPkiClientVerifier`
/// trusting our Client Certificate CA.
pub(crate) struct MtlsListener {
    tcp: TcpListener,
    tls_config: MtlsConfigSwap,
}

impl MtlsListener {
    /// Create a new mTLS listener.
    ///
    /// # Arguments
    /// * `tcp` - Bound TCP listener
    /// * `tls_config` - Rustls config with client cert verifier (wrapped
    ///   in `ArcSwap` for hot reload)
    pub(crate) fn new(tcp: TcpListener, tls_config: MtlsConfigSwap) -> Self {
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
/// Uses the same server certificate as the main HTTPS listener, with
/// a custom client certificate verifier that **accepts any certificate**
/// (including self-signed) and delegates identity validation to the
/// application layer.
///
/// This is required for RFC 8705 Section 2.2 (`self_signed_tls_client_auth`),
/// where clients present self-signed certificates that won't chain to any
/// CA. The TLS handshake proves possession of the private key; the
/// application layer verifies the certificate matches the client's
/// registered JWKS `x5c`.
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
/// This supports both:
/// - `tls_client_auth` (RFC 8705 §2.1): app layer checks subject/SAN
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
}
