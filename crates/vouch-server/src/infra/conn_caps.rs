// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Caps on how many connections may be open at once.
//!
//! The request rate limiter (`infra/rate_limit.rs`) only sees requests that
//! reach the router; a client that opens connections and sends nothing is
//! invisible to it. These caps act at accept time instead, before any TLS
//! work, the model of nginx's `limit_conn` and HAProxy's `maxconn`:
//!
//! - **Total**: a semaphore shared by every listener, taken for each accepted
//!   connection. When it is exhausted each accept loop holds the one
//!   connection it has accepted until a place frees, and stops accepting, so
//!   further connections wait in the kernel backlog rather than being
//!   accepted and dropped.
//! - **Per client**: open connections per client address, closed at once when
//!   over the cap. IPv6 clients are counted per /64, since one host can use a
//!   whole /64. Peers in `VOUCH_TRUSTED_PROXIES` are exempt: behind a proxy
//!   that terminates TLS every client shares the proxy's address. On the
//!   listeners that read the PROXY header (HTTPS, mTLS) with
//!   `VOUCH_PROXY_PROTOCOL` on, no peer is exempt: the peer is the header's
//!   source, which is the client, not the proxy. The port-80 redirect
//!   listener never reads the header (its TCP peer is the proxy), so it keeps
//!   the trusted proxy exempt regardless — see [`ConnCaps::for_http_redirect`].
//!
//! The total cap (one semaphore) is shared by every listener, so a client
//! cannot multiply its allowance by spreading over the HTTPS and mTLS ports.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
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

/// Shared connection caps; see the module docs.
#[derive(Debug)]
pub(crate) struct ConnCaps {
    total: Arc<Semaphore>,
    per_ip: Mutex<HashMap<IpAddr, u32>>,
    max_per_ip: u32,
    exempt: Vec<IpNet>,
}

impl ConnCaps {
    pub(crate) fn new(config: ConnCapConfig, exempt: Vec<IpNet>) -> Arc<Self> {
        let total = usize::try_from(config.max_total).unwrap_or(usize::MAX);
        Arc::new(Self {
            total: Arc::new(Semaphore::new(total)),
            per_ip: Mutex::new(HashMap::new()),
            max_per_ip: config.max_per_ip,
            exempt,
        })
    }

    /// The caps for `config`, used by the PROXY-protocol listeners (HTTPS,
    /// mTLS) and the single plain listener. The exempt list comes from
    /// [`ServerConfig::forwarded_for_proxies`]: empty with the PROXY
    /// protocol on, since the header's source is the client, not the proxy.
    pub(crate) fn for_config(config: &ServerConfig) -> Arc<Self> {
        Self::new(
            config.connection_caps,
            config.forwarded_for_proxies().to_vec(),
        )
    }

    /// Caps for the port-80 HTTP→HTTPS redirect listener.
    ///
    /// Port 80 is wired with `ProxyProtocol::off()` (see `serve.rs` and
    /// `docs/src/configuration/reverse-proxy.md`: "Port 80 never takes the
    /// PROXY protocol"), so its TCP peer is the proxy, not the header's
    /// client. The trusted proxy must therefore stay exempt even when
    /// `VOUCH_PROXY_PROTOCOL` is on — otherwise the proxy's redirect
    /// connections share one per-IP bucket and are dropped under load.
    ///
    /// The total cap is shared with `shared` (every listener draws from one
    /// pool), but the per-IP map is not: the only peer on port 80 is the
    /// exempt proxy, so the map is effectively empty and a client cannot
    /// use port 80 to multiply a per-IP allowance counted on 443/mTLS.
    pub(crate) fn for_http_redirect(shared: &Arc<Self>, config: &ServerConfig) -> Arc<Self> {
        Arc::new(Self {
            total: Arc::clone(&shared.total),
            per_ip: Mutex::new(HashMap::new()),
            max_per_ip: shared.max_per_ip,
            exempt: config.trusted_proxies.clone(),
        })
    }

    /// Wait until the total cap has room for one more connection.
    ///
    /// Cancel-safe: dropping the future gives up the place in the queue.
    pub(crate) async fn reserve(&self) -> Result<TotalSlot, AcquireError> {
        let permit = Arc::clone(&self.total).acquire_owned().await?;
        metrics::gauge!("vouch_connections_open").increment(1.0);
        Ok(TotalSlot(permit))
    }

    /// Count one more connection from `peer`, or `None` if its address is
    /// already at the per-client cap.
    pub(crate) fn admit(self: &Arc<Self>, peer: IpAddr) -> Option<ClientSlot> {
        let peer = peer.to_canonical();
        if self.exempt.iter().any(|net| net.contains(&peer)) {
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

    /// Places left under the total cap.
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

    use crate::test_utils::test_config;

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

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("IP")
    }

    #[test]
    fn default_config_is_the_documented_one() {
        assert_eq!(ConnCapConfig::default(), ConnCapConfig::DEFAULT);
    }

    #[test]
    fn per_client_cap_refuses_the_next_connection_until_one_closes() {
        let caps = caps(100, 2, &[]);
        let first = caps.admit(ip("203.0.113.7")).expect("first");
        let _second = caps.admit(ip("203.0.113.7")).expect("second");
        assert!(
            caps.admit(ip("203.0.113.7")).is_none(),
            "third is over the cap"
        );
        assert!(
            caps.admit(ip("203.0.113.8")).is_some(),
            "another client has its own allowance"
        );

        drop(first);
        assert!(
            caps.admit(ip("203.0.113.7")).is_some(),
            "a closed slot is reusable"
        );
    }

    #[test]
    fn ipv6_clients_are_counted_per_64() {
        let caps = caps(100, 1, &[]);
        let _held = caps.admit(ip("2001:db8:1:2::1")).expect("first");
        assert!(
            caps.admit(ip("2001:db8:1:2:ffff::9")).is_none(),
            "same /64, so the same client"
        );
        assert!(
            caps.admit(ip("2001:db8:1:3::1")).is_some(),
            "a different /64 is a different client"
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_counts_as_the_ipv4_client() {
        let caps = caps(100, 1, &[]);
        let _held = caps.admit(ip("203.0.113.7")).expect("first");
        assert!(caps.admit(ip("::ffff:203.0.113.7")).is_none());
    }

    #[test]
    fn trusted_proxies_are_exempt() {
        let caps = caps(100, 1, &["10.0.0.0/8"]);
        let held: Vec<_> = (0..5)
            .map(|_| caps.admit(ip("10.1.2.3")).expect("exempt"))
            .collect();
        assert_eq!(held.len(), 5);
        assert_eq!(caps.tracked_clients(), 0, "exempt peers are not counted");
    }

    #[test]
    fn closed_connections_leave_no_entry_behind() {
        let caps = caps(100, 4, &[]);
        let slots: Vec<_> = ["203.0.113.1", "203.0.113.2", "2001:db8::1"]
            .iter()
            .map(|peer| caps.admit(ip(peer)).expect("admit"))
            .collect();
        assert_eq!(caps.tracked_clients(), 3);
        drop(slots);
        assert_eq!(caps.tracked_clients(), 0);
    }

    /// `for_http_redirect` shares the total cap with the PROXY-protocol
    /// listener caps (every listener draws from one semaphore) but keeps the
    /// trusted proxies exempt even in PROXY mode, because the port-80
    /// listener never reads the PROXY header and its TCP peer is the proxy.
    #[tokio::test]
    async fn for_http_redirect_shares_total_and_exempts_trusted_proxies() {
        let mut config = test_config();
        config.proxy_protocol = true;
        config.trusted_proxies = vec!["10.0.0.0/8".parse().expect("CIDR")];
        config.connection_caps = ConnCapConfig {
            max_total: 2,
            max_per_ip: 1,
        };

        let shared = ConnCaps::for_config(&config);
        assert!(
            shared.exempt.is_empty(),
            "PROXY-mode listener caps (443/mTLS) exempt no one"
        );

        let http = ConnCaps::for_http_redirect(&shared, &config);
        assert_eq!(
            http.exempt.len(),
            1,
            "port-80 caps keep trusted_proxies exempt even in PROXY mode"
        );

        // The total cap is shared: holding a slot on `shared` reduces `http`'s
        // available capacity, proving both draw from one semaphore.
        assert_eq!(shared.available(), 2);
        assert_eq!(http.available(), 2);
        let _held = shared.reserve().await.expect("reserve");
        assert_eq!(shared.available(), 1);
        assert_eq!(http.available(), 1);

        // The trusted proxy is exempt on the port-80 caps but capped on the
        // 443/mTLS caps (empty exempt list, max_per_ip = 1).
        let _exempt: Vec<_> = (0..3)
            .map(|_| http.admit(ip("10.1.2.3")).expect("exempt on port 80"))
            .collect();
        assert_eq!(
            http.tracked_clients(),
            0,
            "exempt proxy peers are not counted on port 80"
        );
        let _first = shared
            .admit(ip("10.1.2.3"))
            .expect("first 443 connection admitted");
        assert!(
            shared.admit(ip("10.1.2.3")).is_none(),
            "second 443 connection capped (no exemption in PROXY mode)"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn total_cap_waits_for_a_slot_to_free() {
        let caps = caps(1, 64, &[]);
        let held = caps.reserve().await.expect("first");
        let waiting = tokio::time::timeout(std::time::Duration::from_millis(50), caps.reserve());
        assert!(
            waiting.await.is_err(),
            "the second waits while the cap is full"
        );

        drop(held);
        caps.reserve()
            .await
            .expect("a slot frees when a connection closes");
    }
}
