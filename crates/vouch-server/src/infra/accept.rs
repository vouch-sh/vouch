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
//!        → hyper-util auto HTTP/1 or HTTP/2 (TokioTimer, idle limit)
//! ```
//!
//! The task is spawned before any per-connection I/O, so a client that stalls
//! its TLS handshake occupies only its own task and never blocks `accept` for
//! everyone else.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum_server::tls_rustls::RustlsConfig;
use hyper::body::{Body as HttpBody, Frame, Incoming, SizeHint};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use crate::infra::router::REQUEST_TIMEOUT;

/// Time limits applied to every connection.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConnLimits {
    /// From TCP accept to a finished [`Handshake`] (the TLS handshake on the
    /// HTTPS and mTLS listeners).
    pub(crate) handshake: Duration,
    /// hyper's HTTP/1 header read timeout, and the idle limit: a connection
    /// with no request in flight for this long is closed.
    ///
    /// The idle limit covers what hyper leaves unbounded: hyper-util's
    /// protocol detection before the first bytes arrive, and HTTP/2, which
    /// has no header timer (a HEADERS frame whose CONTINUATION never arrives,
    /// or a client that simply idles while answering keep-alive pings).
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
    /// Limits for the production listeners. A legitimate client finishes a
    /// handshake or sends a request head in well under a second, so these
    /// only ever fire on a stalled or hostile peer. `drain` is the router's
    /// request timeout, so shutdown never cuts off a request that could still
    /// have completed.
    pub(crate) const DEFAULT: Self = Self {
        handshake: Duration::from_secs(5),
        header_read: Duration::from_secs(10),
        h2_keep_alive_interval: Duration::from_secs(20),
        h2_keep_alive_timeout: Duration::from_secs(20),
        drain: REQUEST_TIMEOUT,
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

/// Drive one connection from handshake to close.
async fn serve_connection<H: Handshake>(
    tcp: TcpStream,
    peer: SocketAddr,
    handshake: Arc<H>,
    app: Router,
    limits: ConnLimits,
    shutdown: CancellationToken,
) {
    // A PROXY protocol v2 header read (#1583) belongs here, ahead of the
    // handshake and under its own timeout; it replaces `peer` with the
    // header's source address.
    let handshake = tokio::time::timeout(limits.handshake, handshake.handshake(tcp, peer));
    let (io, info) = tokio::select! {
        () = shutdown.cancelled() => return,
        handshake = handshake => match handshake {
            Ok(Ok(ready)) => ready,
            Ok(Err(err)) => {
                tracing::debug!(remote_addr = %peer, "handshake failed: {err}");
                return;
            }
            Err(_) => {
                tracing::debug!(remote_addr = %peer, "handshake timed out");
                return;
            }
        },
    };

    let activity = Activity::default();
    let idle = activity.subscribe();
    let service =
        TowerToHyperService::new(tower::service_fn(move |req: hyper::Request<Incoming>| {
            let mut req = req.map(Body::new);
            req.extensions_mut().insert(ConnectInfo(info.clone()));
            let in_flight = activity.begin();
            let response = app.clone().oneshot(req);
            async move {
                let response = response.await?;
                Ok::<_, Infallible>(response.map(|inner| TrackedBody {
                    inner,
                    _in_flight: in_flight,
                }))
            }
        }));

    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(limits.h2_keep_alive_interval)
        .keep_alive_timeout(limits.h2_keep_alive_timeout);
    let conn = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
    tokio::pin!(conn);
    let result = tokio::select! {
        result = conn.as_mut() => result,
        () = shutdown.cancelled() => {
            conn.as_mut().graceful_shutdown();
            conn.await
        }
        () = idle_for(idle, limits.header_read) => {
            tracing::debug!(remote_addr = %peer, "closing idle connection");
            // HTTP/2 graceful shutdown sends GOAWAY and then waits for the
            // client to acknowledge a PING, which a stalling client never
            // does; give it one more idle period, then drop.
            conn.as_mut().graceful_shutdown();
            tokio::time::timeout(limits.header_read, conn)
                .await
                .unwrap_or(Ok(()))
        }
    };
    if let Err(err) = result {
        tracing::trace!(remote_addr = %peer, "connection error: {err:#}");
    }
}

/// Count of requests in flight on one connection, from dispatch until the
/// response body has been sent.
#[derive(Clone, Default)]
struct Activity(Arc<watch::Sender<usize>>);

impl Activity {
    fn begin(&self) -> InFlight {
        self.0.send_modify(|n| *n = n.saturating_add(1));
        InFlight(Arc::clone(&self.0))
    }

    fn subscribe(&self) -> watch::Receiver<usize> {
        self.0.subscribe()
    }
}

/// One in-flight request; dropping it ends the request.
struct InFlight(Arc<watch::Sender<usize>>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n = n.saturating_sub(1));
    }
}

/// Resolve once no request has been in flight for `idle`.
async fn idle_for(mut in_flight: watch::Receiver<usize>, idle: Duration) {
    loop {
        let busy = *in_flight.borrow_and_update() > 0;
        let changed = if busy {
            in_flight.changed().await
        } else {
            tokio::select! {
                () = tokio::time::sleep(idle) => return,
                changed = in_flight.changed() => changed,
            }
        };
        if changed.is_err() {
            // Every sender is gone, so the connection is finishing on its own.
            std::future::pending::<()>().await;
        }
    }
}

/// A response body that keeps its request counted as in flight until hyper
/// has finished sending it.
struct TrackedBody {
    inner: Body,
    _in_flight: InFlight,
}

impl HttpBody for TrackedBody {
    type Data = <Body as HttpBody>::Data;
    type Error = <Body as HttpBody>::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.get_mut().inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The HTTP/2 client connection preface (RFC 9113 §3.4).
    const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

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

    /// Write the HTTP/2 client connection preface and an empty SETTINGS frame.
    async fn open_h2(stream: &mut TcpStream) {
        stream.write_all(H2_PREFACE).await.expect("write preface");
        // Empty client SETTINGS frame: length 0, type 0x4, flags 0, stream 0.
        stream
            .write_all(&[0, 0, 0, 0x4, 0, 0, 0, 0, 0])
            .await
            .expect("write settings");
    }

    /// hyper has no header timer for HTTP/2 and a live client answers
    /// keep-alive pings, so an HTTP/2 connection that never sends a request
    /// must be closed by the idle limit.
    #[tokio::test]
    async fn idle_http2_connection_is_closed() {
        let (addr, _shutdown, _server) = start(SHORT).await;
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        open_h2(&mut stream).await;
        read_until_closed(&mut stream)
            .await
            .expect("idle HTTP/2 client must be disconnected");
    }

    /// The HTTP/2 form of slowloris: a HEADERS frame without END_HEADERS,
    /// whose CONTINUATION never arrives, dispatches no request and so leaves
    /// the connection idle.
    #[tokio::test]
    async fn unfinished_http2_request_head_is_closed() {
        let (addr, _shutdown, _server) = start(SHORT).await;
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        open_h2(&mut stream).await;
        // HEADERS frame: length 1, type 0x1, flags 0 (neither END_HEADERS nor
        // END_STREAM), stream 1, payload 0x82 (HPACK indexed `:method: GET`).
        stream
            .write_all(&[0, 0, 1, 0x1, 0, 0, 0, 0, 1, 0x82])
            .await
            .expect("write headers");
        read_until_closed(&mut stream)
            .await
            .expect("client stalled mid-request-head must be disconnected");
    }

    /// A request in flight, including its response body, keeps a connection
    /// from counting as idle; the idle clock starts once it ends.
    #[tokio::test(start_paused = true)]
    async fn in_flight_request_defers_idle() {
        let idle = Duration::from_secs(30);
        let activity = Activity::default();
        let request = activity.begin();

        let waited = tokio::time::timeout(idle * 10, idle_for(activity.subscribe(), idle)).await;
        assert!(
            waited.is_err(),
            "a connection with a request in flight must not go idle"
        );

        drop(request);
        let started = tokio::time::Instant::now();
        idle_for(activity.subscribe(), idle).await;
        assert_eq!(started.elapsed(), idle);
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
}
