// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Connection accept loop shared by every listener.
//!
//! `axum::serve` and `axum-server` build hyper's connection builder privately
//! and never install a [`hyper::rt::Timer`]. Without a timer, hyper resolves
//! its default 30-second HTTP/1 header read timeout to "no timeout", so a
//! client that sends nothing, or dribbles a request head one byte at a time,
//! holds a connection open indefinitely (#1127). This module drives hyper
//! directly so the timer can be installed.
//!
//! Each accepted connection runs this pipeline in its own task:
//!
//! ```text
//! accept → set_nodelay → spawn → [PROXY header, #1583] → handshake (timeout)
//!        → protocol sniff (timeout) → hyper HTTP/1 or HTTP/2 (TokioTimer)
//! ```
//!
//! The task is spawned before any per-connection I/O, so a client that stalls
//! its TLS handshake occupies only its own task and never blocks `accept` for
//! everyone else.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use axum_server::tls_rustls::RustlsConfig;
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

/// Time limits applied to every connection.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConnLimits {
    /// From TCP accept to a finished [`Handshake`] (the TLS handshake on the
    /// HTTPS and mTLS listeners).
    pub(crate) handshake: Duration,
    /// For the first bytes of the connection to arrive (the protocol sniff),
    /// and again as hyper's HTTP/1 header read timeout. hyper re-arms the
    /// latter before every request head, so it also closes a keep-alive
    /// connection that sits idle between requests for this long.
    pub(crate) header_read: Duration,
    /// Interval between HTTP/2 keep-alive pings.
    pub(crate) h2_keep_alive_interval: Duration,
    /// How long an HTTP/2 keep-alive ping may go unacknowledged before the
    /// connection is closed.
    pub(crate) h2_keep_alive_timeout: Duration,
    /// After shutdown is signalled, how long in-flight connections get to
    /// finish before they are dropped.
    pub(crate) drain: Duration,
}

impl ConnLimits {
    /// Limits for the production listeners. `header_read` matches hyper's own
    /// default, which it only enforces once a timer is installed.
    pub(crate) const DEFAULT: Self = Self {
        handshake: Duration::from_secs(10),
        header_read: Duration::from_secs(30),
        h2_keep_alive_interval: Duration::from_secs(20),
        h2_keep_alive_timeout: Duration::from_secs(20),
        drain: Duration::from_secs(30),
    };
}

/// Per-connection setup between TCP accept and HTTP.
///
/// `Info` is inserted into every request on the connection as
/// `ConnectInfo<Info>`, and is the only `ConnectInfo` the connection carries.
pub(crate) trait Handshake: Send + Sync + 'static {
    /// Stream handed to hyper.
    type Io: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    /// Connection metadata exposed to handlers.
    type Info: Clone + Send + Sync + 'static;

    /// Turn an accepted TCP stream into the stream hyper serves.
    fn handshake(
        &self,
        tcp: TcpStream,
        peer: SocketAddr,
    ) -> impl Future<Output = io::Result<(Self::Io, Self::Info)>> + Send;
}

/// Plain TCP: no handshake, `ConnectInfo<SocketAddr>`.
pub(crate) struct PlainHandshake;

impl Handshake for PlainHandshake {
    type Io = TcpStream;
    type Info = SocketAddr;

    async fn handshake(
        &self,
        tcp: TcpStream,
        peer: SocketAddr,
    ) -> io::Result<(TcpStream, SocketAddr)> {
        Ok((tcp, peer))
    }
}

/// Server-authenticated TLS for the HTTPS listener, `ConnectInfo<SocketAddr>`.
///
/// The rustls config is read from the [`RustlsConfig`] on every handshake, so
/// a certificate reload applies to the next connection.
pub(crate) struct TlsHandshake(pub(crate) RustlsConfig);

impl Handshake for TlsHandshake {
    type Io = tokio_rustls::server::TlsStream<TcpStream>;
    type Info = SocketAddr;

    async fn handshake(
        &self,
        tcp: TcpStream,
        peer: SocketAddr,
    ) -> io::Result<(Self::Io, SocketAddr)> {
        let tls = TlsAcceptor::from(self.0.get_inner()).accept(tcp).await?;
        Ok((tls, peer))
    }
}

/// Serve `app` on `listener` until `shutdown` is cancelled, then give open
/// connections [`ConnLimits::drain`] to finish.
pub(crate) async fn serve<H: Handshake>(
    listener: TcpListener,
    handshake: H,
    app: Router,
    limits: ConnLimits,
    shutdown: CancellationToken,
) {
    let handshake = Arc::new(handshake);
    let mut conns = JoinSet::new();

    loop {
        let accepted = tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            // Reap finished connection tasks so the set does not grow.
            Some(_) = conns.join_next(), if !conns.is_empty() => continue,
            accepted = listener.accept() => accepted,
        };
        let (tcp, peer) = match accepted {
            Ok(conn) => conn,
            Err(err) => {
                handle_accept_error(err).await;
                continue;
            }
        };
        if let Err(err) = tcp.set_nodelay(true) {
            tracing::trace!("failed to set TCP_NODELAY on incoming connection: {err:#}");
        }
        conns.spawn(serve_connection(
            tcp,
            peer,
            Arc::clone(&handshake),
            app.clone(),
            limits,
            shutdown.clone(),
        ));
    }

    drop(listener);
    let drained = tokio::time::timeout(limits.drain, async {
        while conns.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        tracing::warn!(
            remaining = conns.len(),
            "connections still open after the {}s drain timeout; closing them",
            limits.drain.as_secs()
        );
        conns.shutdown().await;
    }
}

/// Mirror `axum::serve`: per-connection errors are the client's business;
/// anything else (for example `EMFILE`) backs off so the loop does not spin.
async fn handle_accept_error(err: io::Error) {
    if matches!(
        err.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    ) {
        return;
    }
    tracing::error!("accept error: {err}");
    tokio::time::sleep(Duration::from_secs(1)).await;
}

fn timed_out(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("{what} timed out"))
}

/// Drive one connection from handshake to close.
async fn serve_connection<H: Handshake>(
    tcp: TcpStream,
    peer: SocketAddr,
    handshake: Arc<H>,
    app: Router,
    limits: ConnLimits,
    shutdown: CancellationToken,
) {
    // Everything before hyper takes over is bounded here: hyper's own timers
    // only start once it owns the stream.
    let setup = async {
        // A PROXY protocol v2 header read (#1583) belongs here, ahead of the
        // handshake and under its own timeout; it replaces `peer` with the
        // header's source address.
        let (io, info) = tokio::time::timeout(limits.handshake, handshake.handshake(tcp, peer))
            .await
            .map_err(|_| timed_out("handshake"))??;
        let (io, version) = tokio::time::timeout(limits.header_read, sniff_version(io))
            .await
            .map_err(|_| timed_out("first read"))??;
        Ok::<_, io::Error>((io, info, version))
    };
    let (io, info, version) = tokio::select! {
        () = shutdown.cancelled() => return,
        setup = setup => match setup {
            Ok(ready) => ready,
            Err(err) => {
                tracing::debug!(remote_addr = %peer, "connection closed before HTTP: {err}");
                return;
            }
        },
    };

    let service =
        TowerToHyperService::new(tower::service_fn(move |req: hyper::Request<Incoming>| {
            let mut req = req.map(axum::body::Body::new);
            req.extensions_mut().insert(ConnectInfo(info.clone()));
            app.clone().oneshot(req)
        }));
    let io = TokioIo::new(io);

    // The two hyper connection types share no trait carrying
    // `graceful_shutdown`, so the drive loop is spelled out per protocol.
    macro_rules! drive {
        ($conn:expr) => {{
            let conn = $conn;
            tokio::pin!(conn);
            tokio::select! {
                result = conn.as_mut() => result,
                () = shutdown.cancelled() => {
                    conn.as_mut().graceful_shutdown();
                    conn.await
                }
            }
        }};
    }

    let result = match version {
        Version::H1 => {
            let mut builder = http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(limits.header_read);
            drive!(builder.serve_connection(io, service).with_upgrades())
        }
        Version::H2 => {
            let mut builder = http2::Builder::new(TokioExecutor::new());
            builder
                .timer(TokioTimer::new())
                .keep_alive_interval(limits.h2_keep_alive_interval)
                .keep_alive_timeout(limits.h2_keep_alive_timeout);
            drive!(builder.serve_connection(io, service))
        }
    };
    if let Err(err) = result {
        tracing::trace!(remote_addr = %peer, "connection error: {err:#}");
    }
}

/// The HTTP/2 connection preface (RFC 9113 §3.4).
const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Version {
    H1,
    H2,
}

/// Read until the bytes either diverge from the HTTP/2 preface (HTTP/1) or
/// complete it (HTTP/2), and hand back a stream that replays them.
///
/// `hyper_util`'s auto builder does the same detection but without a timeout,
/// and runs it even when restricted to one protocol, so the version is decided
/// here where the caller can bound it.
async fn sniff_version<I: AsyncRead + Unpin>(mut io: I) -> io::Result<(Rewind<I>, Version)> {
    let mut buf = [0u8; H2_PREFACE.len()];
    let mut filled = 0usize;
    let version = loop {
        let Some(unfilled) = buf.get_mut(filled..).filter(|rest| !rest.is_empty()) else {
            break Version::H2;
        };
        let read = io.read(unfilled).await?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        filled = filled.saturating_add(read);
        if buf.get(..filled) != H2_PREFACE.get(..filled) {
            break Version::H1;
        }
    };
    let prefix = buf.get(..filled).unwrap_or_default().to_vec();
    Ok((
        Rewind {
            prefix,
            pos: 0,
            inner: io,
        },
        version,
    ))
}

/// A stream that yields `prefix` before reading from `inner`.
struct Rewind<I> {
    prefix: Vec<u8>,
    pos: usize,
    inner: I,
}

impl<I: AsyncRead + Unpin> AsyncRead for Rewind<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(rest) = this.prefix.get(this.pos..)
            && !rest.is_empty()
        {
            let len = rest.len().min(buf.remaining());
            if let Some(chunk) = rest.get(..len) {
                buf.put_slice(chunk);
                this.pos = this.pos.saturating_add(len);
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for Rewind<I> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    use axum::routing::get;
    use tokio::io::AsyncWriteExt;

    /// Short limits so the timeout tests finish quickly; the drain is long
    /// enough that no test depends on it expiring.
    const SHORT: ConnLimits = ConnLimits {
        handshake: Duration::from_millis(300),
        header_read: Duration::from_millis(300),
        h2_keep_alive_interval: Duration::from_secs(20),
        h2_keep_alive_timeout: Duration::from_secs(20),
        drain: Duration::from_secs(30),
    };

    /// Upper bound on how long any test waits for the server to act. Far above
    /// the `SHORT` limits, so a pass never depends on scheduling.
    const BOUND: Duration = Duration::from_secs(20);

    fn app() -> Router {
        Router::new().route(
            "/peer",
            get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.ip().to_string() }),
        )
    }

    async fn start(
        limits: ConnLimits,
    ) -> (SocketAddr, CancellationToken, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let shutdown = CancellationToken::new();
        let server = tokio::spawn(serve(
            listener,
            PlainHandshake,
            app(),
            limits,
            shutdown.clone(),
        ));
        (addr, shutdown, server)
    }

    /// Read until the server closes the connection; `Err` if it is still open
    /// after [`BOUND`].
    async fn read_until_closed(stream: &mut TcpStream) -> Result<Vec<u8>, &'static str> {
        let mut received = Vec::new();
        match tokio::time::timeout(BOUND, stream.read_to_end(&mut received)).await {
            Ok(_) => Ok(received),
            Err(_) => Err("connection still open"),
        }
    }

    #[tokio::test]
    async fn serves_http1_with_connect_info() {
        let (addr, shutdown, server) = start(ConnLimits::DEFAULT).await;
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(b"GET /peer HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let response = read_until_closed(&mut stream).await.expect("response");
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 200"), "response: {response}");
        assert!(
            response.ends_with("127.0.0.1"),
            "handler must see the peer through ConnectInfo<SocketAddr>; response: {response}"
        );
        shutdown.cancel();
        tokio::time::timeout(BOUND, server)
            .await
            .expect("shutdown")
            .expect("join");
    }

    /// A client that connects and sends nothing is closed once the header read
    /// timeout expires, instead of holding its slot forever.
    #[tokio::test]
    async fn silent_connection_is_closed() {
        let (addr, _shutdown, _server) = start(SHORT).await;
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        read_until_closed(&mut stream)
            .await
            .expect("silent client must be disconnected");
    }

    /// Slowloris: a request head that keeps arriving but never completes is
    /// closed by hyper's header read timeout, which only runs with a timer.
    #[tokio::test]
    async fn dribbled_request_head_is_closed() {
        let (addr, _shutdown, _server) = start(SHORT).await;
        let stream = TcpStream::connect(addr).await.expect("connect");
        let (mut reader, mut writer) = stream.into_split();
        writer
            .write_all(b"GET /peer HTTP/1.1\r\nHost: localhost\r\n")
            .await
            .expect("write");

        // One header byte every 50ms, never the blank line that ends the head.
        let dribble = async move {
            let mut tick = tokio::time::interval(Duration::from_millis(50));
            loop {
                tick.tick().await;
                if writer.write_all(b"x").await.is_err() {
                    return;
                }
            }
        };
        let closed = async {
            let mut received = Vec::new();
            let _read = reader.read_to_end(&mut received).await;
        };
        tokio::time::timeout(BOUND, async {
            tokio::select! {
                () = dribble => {}
                () = closed => {}
            }
        })
        .await
        .expect("dribbling client must be disconnected");
    }

    /// A client that sends the HTTP/2 preface (prior knowledge, as h2c does)
    /// is served over HTTP/2: the server answers with its SETTINGS frame.
    #[tokio::test]
    async fn http2_preface_is_served_as_http2() {
        let (addr, _shutdown, _server) = start(ConnLimits::DEFAULT).await;
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream.write_all(H2_PREFACE).await.expect("write preface");
        // Empty client SETTINGS frame: length 0, type 0x4, flags 0, stream 0.
        stream
            .write_all(&[0, 0, 0, 0x4, 0, 0, 0, 0, 0])
            .await
            .expect("write settings");
        let mut header = [0u8; 9];
        tokio::time::timeout(BOUND, stream.read_exact(&mut header))
            .await
            .expect("server frame")
            .expect("read");
        // RFC 9113 §3.4: the server connection preface is a SETTINGS frame "that
        // MUST be the first frame the server sends in the HTTP/2 connection."
        assert_eq!(header.get(3), Some(&0x4), "first server frame: {header:?}");
    }

    /// Cancelling the token stops accepting and returns once the open
    /// connections have closed.
    #[tokio::test]
    async fn shutdown_closes_idle_connections_and_returns() {
        let (addr, shutdown, server) = start(ConnLimits::DEFAULT).await;
        // Mid-setup (nothing sent yet): abandoned on shutdown.
        let mut silent = TcpStream::connect(addr).await.expect("connect");
        // Idle keep-alive after one request: closed gracefully.
        let mut idle = TcpStream::connect(addr).await.expect("connect");
        idle.write_all(b"GET /peer HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("write");
        let mut first = [0u8; 12];
        idle.read_exact(&mut first).await.expect("response");
        assert_eq!(&first, b"HTTP/1.1 200");

        shutdown.cancel();
        tokio::time::timeout(BOUND, server)
            .await
            .expect("serve must return after shutdown")
            .expect("join");
        read_until_closed(&mut silent).await.expect("silent closed");
        read_until_closed(&mut idle).await.expect("idle closed");
    }

    #[tokio::test]
    async fn rewind_replays_prefix_then_reads_inner() {
        let (mut client, server) = tokio::io::duplex(64);
        client
            .write_all(b"GET / HTTP/1.1\r\n")
            .await
            .expect("write");
        drop(client);
        let (mut rewound, version) = sniff_version(server).await.expect("sniff");
        assert_eq!(version, Version::H1);
        let mut all = Vec::new();
        rewound.read_to_end(&mut all).await.expect("read");
        assert_eq!(all, b"GET / HTTP/1.1\r\n");
    }

    #[tokio::test]
    async fn sniff_detects_h2_preface() {
        let (mut client, server) = tokio::io::duplex(64);
        client.write_all(H2_PREFACE).await.expect("write");
        let (_rewound, version) = sniff_version(server).await.expect("sniff");
        assert_eq!(version, Version::H2);
    }
}
