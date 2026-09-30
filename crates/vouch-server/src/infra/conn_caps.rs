// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Caps on how many connections may be open at once.
//!
//! The request rate limiter (`infra/rate_limit.rs`) only sees requests that
//! reach the router; a client that opens connections and sends nothing is
//! invisible to it. These caps act at accept time instead, before any TLS
//! work, the model of nginx's `limit_conn` and HAProxy's `maxconn`:
//!
//! - **Total**: a semaphore shared by the application and mTLS listeners,
//!   taken for each accepted connection. When it is exhausted each accept
//!   loop holds the one connection it has accepted until a place frees, and
//!   stops accepting, so further connections wait in the kernel backlog rather
//!   than being accepted and dropped. The port-80 listener draws from a pool
//!   of its own ([`REDIRECT_MAX_TOTAL`]): it serves only the HTTPS redirect
//!   and readiness probes, and must not take places the other two need.
//! - **Per client**: open connections per client address, closed at once when
//!   over the cap. IPv6 clients are counted per /64, since one host can use a
//!   whole /64. A peer in `VOUCH_TRUSTED_PROXIES` is exempt where it can be a
//!   proxy, since behind a proxy every client shares the proxy's address: the
//!   TCP peer of the application or port-80 listener, and a PROXY-protocol
//!   peer whose header names no client. The TCP peer of the mTLS listener is
//!   never exempt: Vouch terminates TLS there, so the peer is the client. An
//!   address from a PROXY header is never exempt: it is the client, not the
//!   proxy, even when it falls inside that range.
//!
//! One [`ConnCaps`] is shared by every listener in the process, and each
//! listener reaches it through a [`ListenerCaps`] that names its
//! [`ListenerRole`]. Per-client counts span all listeners, so a client cannot
//! multiply its allowance by spreading over the ports.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use ipnet::IpNet;
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore};

use crate::config::ServerConfig;

/// Operator-configurable connection caps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnCapConfig {
    /// Open connections across all listeners.
    pub max_total: u32,
    /// Open connections per client address (IPv6: per /64).
    pub max_per_ip: u32,
}

impl ConnCapConfig {
    /// Defaults for every field, and the source of the `VOUCH_MAX_CONNECTIONS*`
    /// flag defaults in `config::Args`.
    ///
    /// A browser or the CLI holds a handful of connections; 64 per address
    /// leaves room for an office behind one NAT. 10,000 in total fits the
    /// AMI's 65,535 open-file limit with room for the database pool and
    /// outbound calls.
    pub const DEFAULT: Self = Self {
        max_total: 10_000,
        max_per_ip: 64,
    };
}

impl Default for ConnCapConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Open connections on the port-80 listener, a pool apart from
/// [`ConnCapConfig::max_total`]. Redirects and readiness probes are short
/// requests; 256 covers a load balancer's probes with room to spare.
pub(crate) const REDIRECT_MAX_TOTAL: usize = 256;

/// Which listener accepted a connection. It decides whether the TCP peer can
/// be a proxy and which total pool the connection draws from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ListenerRole {
    /// The application listener: HTTPS, or plain HTTP without TLS. A proxy
    /// that terminates TLS can sit in front of it.
    App,
    /// The mTLS listener. Vouch terminates TLS here, so the TCP peer is the
    /// client: a TCP passthrough proxy relays ciphertext, and a proxy that
    /// terminated TLS would present its own client certificate.
    Mtls,
    /// Port 80: the HTTPS redirect and readiness probes, often forwarded by
    /// the load balancer. It draws from its own pool.
    Redirect,
}

impl ListenerRole {
    fn tcp_peer_can_be_proxy(self) -> bool {
        match self {
            Self::App | Self::Redirect => true,
            Self::Mtls => false,
        }
    }
}

/// A connection's client address and where it came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Peer {
    /// The TCP peer of a listener without the PROXY protocol: the client, or
    /// a proxy where the [`ListenerRole`] allows one.
    Tcp(SocketAddr),
    /// The TCP peer of a PROXY-protocol connection whose header names no
    /// client (a `LOCAL` health check): the proxy itself.
    Proxy(SocketAddr),
    /// The source address in a PROXY header: the client behind the proxy.
    Header(SocketAddr),
}

impl Peer {
    pub(crate) fn addr(self) -> SocketAddr {
        match self {
            Self::Tcp(addr) | Self::Proxy(addr) | Self::Header(addr) => addr,
        }
    }

    fn can_be_proxy(self, role: ListenerRole) -> bool {
        match self {
            Self::Tcp(_) => role.tcp_peer_can_be_proxy(),
            Self::Proxy(_) => true,
            Self::Header(_) => false,
        }
    }
}

/// Shared connection caps; see the module docs.
#[derive(Debug)]
pub(crate) struct ConnCaps {
    total: Arc<Semaphore>,
    redirect_total: Arc<Semaphore>,
    per_ip: Mutex<HashMap<IpAddr, u32>>,
    max_per_ip: u32,
    exempt: Vec<IpNet>,
}

impl ConnCaps {
    pub(crate) fn new(config: ConnCapConfig, exempt: Vec<IpNet>) -> Arc<Self> {
        let total = usize::try_from(config.max_total).unwrap_or(usize::MAX);
        Arc::new(Self {
            total: Arc::new(Semaphore::new(total)),
            redirect_total: Arc::new(Semaphore::new(REDIRECT_MAX_TOTAL)),
            per_ip: Mutex::new(HashMap::new()),
            max_per_ip: config.max_per_ip,
            exempt,
        })
    }

    /// The caps for `config`, shared by every listener in the process.
    pub(crate) fn for_config(config: &ServerConfig) -> Arc<Self> {
        Self::new(config.connection_caps, config.trusted_proxies.clone())
    }

    /// The caps as seen by a listener in `role`.
    pub(crate) fn listener(self: &Arc<Self>, role: ListenerRole) -> ListenerCaps {
        ListenerCaps {
            caps: Arc::clone(self),
            role,
        }
    }

    /// Wait until `role`'s total pool has room for one more connection.
    ///
    /// Cancel-safe: dropping the future gives up the place in the queue.
    async fn reserve(&self, role: ListenerRole) -> Result<TotalSlot, AcquireError> {
        let pool = match role {
            ListenerRole::App | ListenerRole::Mtls => &self.total,
            ListenerRole::Redirect => &self.redirect_total,
        };
        let permit = Arc::clone(pool).acquire_owned().await?;
        metrics::gauge!("vouch_connections_open").increment(1.0);
        Ok(TotalSlot(permit))
    }

    /// Count one more connection from `peer` on a listener in `role`, or
    /// `None` if its address is already at the per-client cap.
    fn admit(self: &Arc<Self>, peer: Peer, role: ListenerRole) -> Option<ClientSlot> {
        let exemptible = peer.can_be_proxy(role);
        let peer = peer.addr().ip().to_canonical();
        if exemptible && self.exempt.iter().any(|net| net.contains(&peer)) {
            return Some(ClientSlot(None));
        }
        let key = client_key(peer);
        let mut counts = self.per_ip.lock().unwrap_or_else(PoisonError::into_inner);
        let count = counts.entry(key).or_insert(0);
        if *count >= self.max_per_ip {
            if *count == 0 {
                counts.remove(&key);
            }
            metrics::counter!("vouch_connections_rejected_total", "reason" => "per_ip")
                .increment(1);
            return None;
        }
        *count = count.saturating_add(1);
        Some(ClientSlot(Some((Arc::clone(self), key))))
    }

    fn release(&self, key: IpAddr) {
        let mut counts = self.per_ip.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&key);
            }
        }
    }

    /// Default caps with no exempt peers, for tests that are not about caps.
    #[cfg(test)]
    pub(crate) fn for_test() -> Arc<Self> {
        Self::new(ConnCapConfig::DEFAULT, Vec::new())
    }

    /// Places left under the total cap shared by the application and mTLS
    /// listeners.
    #[cfg(test)]
    pub(crate) fn available(&self) -> usize {
        self.total.available_permits()
    }

    #[cfg(test)]
    fn tracked_clients(&self) -> usize {
        self.per_ip
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// [`ConnCaps`] bound to one listener's [`ListenerRole`].
#[derive(Clone, Debug)]
pub(crate) struct ListenerCaps {
    caps: Arc<ConnCaps>,
    role: ListenerRole,
}

impl ListenerCaps {
    /// Wait until this listener's total pool has room for one more
    /// connection.
    ///
    /// Cancel-safe: dropping the future gives up the place in the queue.
    pub(crate) async fn reserve(&self) -> Result<TotalSlot, AcquireError> {
        self.caps.reserve(self.role).await
    }

    /// Count one more connection from `peer`, or `None` if its address is
    /// already at the per-client cap.
    pub(crate) fn admit(&self, peer: Peer) -> Option<ClientSlot> {
        self.caps.admit(peer, self.role)
    }
}

/// The address a connection is counted under: IPv4 as is, IPv6 by its /64.
fn client_key(peer: IpAddr) -> IpAddr {
    const PREFIX_64: u128 = 0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000;
    match peer {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from_bits(v6.to_bits() & PREFIX_64)),
    }
}

/// One place under the total cap, held for the life of a connection.
#[derive(Debug)]
pub(crate) struct TotalSlot(
    #[expect(dead_code, reason = "held for its Drop")] OwnedSemaphorePermit,
);

impl Drop for TotalSlot {
    fn drop(&mut self) {
        metrics::gauge!("vouch_connections_open").decrement(1.0);
    }
}

/// One place under a client's cap, held for the life of a connection.
/// `None` for an exempt peer.
#[derive(Debug)]
pub(crate) struct ClientSlot(Option<(Arc<ConnCaps>, IpAddr)>);

impl Drop for ClientSlot {
    fn drop(&mut self) {
        if let Some((caps, key)) = self.0.take() {
            caps.release(key);
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    fn caps(max_total: u32, max_per_ip: u32, exempt: &[&str]) -> Arc<ConnCaps> {
        ConnCaps::new(
            ConnCapConfig {
                max_total,
                max_per_ip,
            },
            exempt
                .iter()
                .map(|net| net.parse().expect("CIDR"))
                .collect(),
        )
    }

    fn tcp(ip: &str) -> Peer {
        Peer::Tcp(SocketAddr::new(ip.parse().expect("IP"), 40000))
    }

    fn header(ip: &str) -> Peer {
        Peer::Header(SocketAddr::new(ip.parse().expect("IP"), 40000))
    }

    fn proxy(ip: &str) -> Peer {
        Peer::Proxy(SocketAddr::new(ip.parse().expect("IP"), 40000))
    }

    #[test]
    fn default_config_is_the_documented_one() {
        assert_eq!(ConnCapConfig::default(), ConnCapConfig::DEFAULT);
    }

    #[test]
    fn per_client_cap_refuses_the_next_connection_until_one_closes() {
        let caps = caps(100, 2, &[]);
        let first = caps
            .admit(tcp("203.0.113.7"), ListenerRole::App)
            .expect("first");
        let _second = caps
            .admit(tcp("203.0.113.7"), ListenerRole::App)
            .expect("second");
        assert!(
            caps.admit(tcp("203.0.113.7"), ListenerRole::App).is_none(),
            "third is over the cap"
        );
        assert!(
            caps.admit(tcp("203.0.113.8"), ListenerRole::App).is_some(),
            "another client has its own allowance"
        );

        drop(first);
        assert!(
            caps.admit(tcp("203.0.113.7"), ListenerRole::App).is_some(),
            "a closed slot is reusable"
        );
    }

    #[test]
    fn ipv6_clients_are_counted_per_64() {
        let caps = caps(100, 1, &[]);
        let _held = caps
            .admit(tcp("2001:db8:1:2::1"), ListenerRole::App)
            .expect("first");
        assert!(
            caps.admit(tcp("2001:db8:1:2:ffff::9"), ListenerRole::App)
                .is_none(),
            "same /64, so the same client"
        );
        assert!(
            caps.admit(tcp("2001:db8:1:3::1"), ListenerRole::App)
                .is_some(),
            "a different /64 is a different client"
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_counts_as_the_ipv4_client() {
        let caps = caps(100, 1, &[]);
        let _held = caps
            .admit(tcp("203.0.113.7"), ListenerRole::App)
            .expect("first");
        assert!(
            caps.admit(tcp("::ffff:203.0.113.7"), ListenerRole::App)
                .is_none()
        );
    }

    #[test]
    fn trusted_proxies_are_exempt() {
        let caps = caps(100, 1, &["10.0.0.0/8"]);
        let held: Vec<_> = (0..5)
            .map(|_| {
                caps.admit(tcp("10.1.2.3"), ListenerRole::App)
                    .expect("exempt")
            })
            .collect();
        assert_eq!(held.len(), 5);
        assert_eq!(caps.tracked_clients(), 0, "exempt peers are not counted");
    }

    #[test]
    fn trusted_tcp_peer_is_exempt_on_the_redirect_listener() {
        let caps = caps(100, 1, &["10.0.0.0/8"]);
        let _first = caps
            .admit(tcp("10.1.2.3"), ListenerRole::Redirect)
            .expect("first");
        assert!(
            caps.admit(tcp("10.1.2.3"), ListenerRole::Redirect)
                .is_some(),
            "a load balancer forwarding port 80 is every client's address"
        );
    }

    #[test]
    fn mtls_tcp_peer_inside_trusted_proxies_is_counted() {
        let caps = caps(100, 1, &["10.0.0.0/8"]);
        let _held = caps
            .admit(tcp("10.1.2.3"), ListenerRole::Mtls)
            .expect("first");
        assert!(
            caps.admit(tcp("10.1.2.3"), ListenerRole::Mtls).is_none(),
            "Vouch terminates TLS on the mTLS port, so its TCP peer is the client"
        );
        assert_eq!(caps.tracked_clients(), 1);
    }

    #[test]
    fn local_header_proxy_is_exempt_on_every_listener() {
        let caps = caps(100, 1, &["10.0.0.0/8"]);
        for role in [
            ListenerRole::App,
            ListenerRole::Mtls,
            ListenerRole::Redirect,
        ] {
            let held: Vec<_> = (0..3)
                .map(|_| caps.admit(proxy("10.1.2.3"), role).expect("exempt"))
                .collect();
            assert_eq!(held.len(), 3, "{role:?}");
        }
        assert_eq!(caps.tracked_clients(), 0, "exempt peers are not counted");
    }

    #[test]
    fn header_addresses_inside_trusted_proxies_are_counted() {
        let caps = caps(100, 1, &["10.0.0.0/8"]);
        let _held = caps
            .admit(header("10.1.2.3"), ListenerRole::App)
            .expect("first");
        assert!(
            caps.admit(header("10.1.2.3"), ListenerRole::App).is_none(),
            "a PROXY header's source is the client, never an exempt proxy"
        );
    }

    #[test]
    fn header_and_tcp_peers_share_one_count() {
        let caps = caps(100, 1, &["10.0.0.0/8"]);
        let _held = caps
            .admit(header("203.0.113.7"), ListenerRole::App)
            .expect("first");
        assert!(
            caps.admit(tcp("203.0.113.7"), ListenerRole::App).is_none(),
            "a client cannot add a listener without the PROXY protocol to its allowance"
        );
    }

    #[test]
    fn closed_connections_leave_no_entry_behind() {
        let caps = caps(100, 4, &[]);
        let slots: Vec<_> = ["203.0.113.1", "203.0.113.2", "2001:db8::1"]
            .iter()
            .map(|peer| caps.admit(tcp(peer), ListenerRole::App).expect("admit"))
            .collect();
        assert_eq!(caps.tracked_clients(), 3);
        drop(slots);
        assert_eq!(caps.tracked_clients(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn redirect_listener_draws_from_its_own_pool() {
        const WAIT: std::time::Duration = std::time::Duration::from_millis(50);
        let caps = caps(1, 64, &[]);
        let _app = caps.reserve(ListenerRole::App).await.expect("app");
        let mut redirect = Vec::with_capacity(REDIRECT_MAX_TOTAL);
        for _ in 0..REDIRECT_MAX_TOTAL {
            let slot = tokio::time::timeout(WAIT, caps.reserve(ListenerRole::Redirect))
                .await
                .expect("port 80 is not held back by a full shared pool")
                .expect("semaphore open");
            redirect.push(slot);
        }
        let over = tokio::time::timeout(WAIT, caps.reserve(ListenerRole::Redirect));
        assert!(over.await.is_err(), "port 80's own pool is capped");
        assert_eq!(caps.available(), 0, "port 80 took no shared place");

        let mtls = tokio::time::timeout(WAIT, caps.reserve(ListenerRole::Mtls));
        assert!(
            mtls.await.is_err(),
            "the mTLS listener shares the application listener's pool"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn total_cap_waits_for_a_slot_to_free() {
        let caps = caps(1, 64, &[]);
        let held = caps.reserve(ListenerRole::App).await.expect("first");
        let waiting = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            caps.reserve(ListenerRole::App),
        );
        assert!(
            waiting.await.is_err(),
            "the second waits while the cap is full"
        );

        drop(held);
        caps.reserve(ListenerRole::App)
            .await
            .expect("a slot frees when a connection closes");
    }
}
