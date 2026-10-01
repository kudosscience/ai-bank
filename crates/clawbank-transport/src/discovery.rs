//! Kademlia discovery plumbing for Comms 02 (ADR-0002 Phase 1).
//!
//! A fresh node joins through one well-known bootstrap multiaddr and then
//! discovers peers on its own: the routing table populates from the DHT,
//! and on a LAN two nodes find each other via mDNS with zero configuration.
//!
//! What this module owns:
//! - [`new_kad`]: Kademlia behaviour pinned in [`Mode::Server`] (reachable
//!   nodes must serve the DHT; libp2p defaults to `Client` + auto-mode).
//! - [`handle_identify_received`]: the mandatory identify→kad wiring —
//!   libp2p does not auto-wire it, so every `identify::Event::Received`
//!   must feed `listen_addrs` into [`kad`](libp2p_kad::Behaviour::add_address).
//! - [`parse_bootstrap`] / [`add_bootstrap`] / [`start_bootstrap`]: the
//!   well-known-address join path. The address is a rendezvous hint, not an
//!   authority: no registry, CA, or hosted directory.
//! - [`handle_mdns_discovered`]: LAN peers feed the same routing table.
//!
//! Record shapes, signed alias hints, and registry semantics belong to the
//! future Registry track (ADR-0008) — this module is find-peers only.

use crate::PeerId;
use libp2p_kad::{store::MemoryStore, Behaviour as KadBehaviour, Mode};
use multiaddr::{Multiaddr, Protocol};

/// Kademlia behaviour type used by [`crate::BankBehaviour`].
pub type Kad = KadBehaviour<MemoryStore>;

/// Build a Kademlia behaviour pinned in [`Mode::Server`].
///
/// `Behaviour::new` defaults to `Client` with auto-mode enabled (it flips to
/// `Server` only after a confirmed external address). Reachable nodes must
/// serve the DHT from the start, so auto-mode is disabled via
/// `set_mode(Some(Server))` — the acceptance criterion "Kademlia runs in
/// Server mode on reachable nodes".
pub fn new_kad(local: PeerId) -> Kad {
    let store = MemoryStore::new(local);
    let mut kad = KadBehaviour::new(local, store);
    kad.set_mode(Some(Mode::Server));
    kad
}

/// A parsed well-known bootstrap address: the peer plus its dialable
/// multiaddr(s) with the `/p2p` component stripped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapPeer {
    /// The bootstrap peer's identity.
    pub peer_id: PeerId,
    /// Dialable address without the `/p2p` suffix (for `kad.add_address`).
    pub address: Multiaddr,
    /// Full address with `/p2p` (for `Swarm::dial`).
    pub full: Multiaddr,
}

/// Parse a well-known bootstrap multiaddr of the form
/// `/ip4/.../tcp/.../p2p/<PeerId>`.
///
/// Returns `None` when the multiaddr carries no `/p2p` component, carries
/// more than one (malformed — the identity is ambiguous), or has no dialable
/// address left after stripping `/p2p`: a bootstrap address without a
/// usable peer + address is not dialable and must be rejected, not silently
/// treated as an anonymous directory.
pub fn parse_bootstrap(addr: &Multiaddr) -> Option<BootstrapPeer> {
    let mut peer: Option<PeerId> = None;
    let mut bare = Multiaddr::empty();
    for proto in addr.iter() {
        match proto {
            Protocol::P2p(id) => {
                if peer.is_some() {
                    return None;
                }
                peer = Some(id);
            }
            _ => bare.push(proto),
        }
    }
    let peer_id = peer?;
    if bare.is_empty() {
        return None;
    }
    Some(BootstrapPeer {
        peer_id,
        address: bare,
        full: addr.clone(),
    })
}

/// Feed an identify observation into Kademlia (the mandatory wiring).
///
/// Returns the number of addresses passed to `kad.add_address`. Every
/// `identify::Event::Received` must call this — libp2p does not auto-wire
/// identify→kad, so without it the routing table never learns the listen
/// addresses of nodes that query us.
pub fn handle_identify_received(kad: &mut Kad, peer: &PeerId, listen_addrs: &[Multiaddr]) -> usize {
    feed_addrs(kad, peer, listen_addrs.iter().cloned())
}

/// Feed mDNS LAN discoveries into the same routing table.
///
/// Each `(peer, addr)` pair is added to kad; returns the count added.
/// Callers should additionally `Swarm::dial` the peer (see
/// [`crate::dial_mdns_peer`] helper pattern in tests) so identify runs and
/// the connection — not just the address — is confirmed.
pub fn handle_mdns_discovered(kad: &mut Kad, discovered: &[(PeerId, Multiaddr)]) -> usize {
    discovered
        .iter()
        .map(|(peer, addr)| feed_addrs(kad, peer, [addr.clone()]))
        .sum()
}

/// Feed addresses for one peer into kad; returns how many were passed on.
fn feed_addrs(kad: &mut Kad, peer: &PeerId, addrs: impl IntoIterator<Item = Multiaddr>) -> usize {
    let mut fed = 0;
    for addr in addrs {
        kad.add_address(peer, addr);
        fed += 1;
    }
    fed
}

/// Number of peers currently in the Kademlia routing table (kbuckets).
pub fn routing_table_len(kad: &mut Kad) -> usize {
    kad.kbuckets().map(|b| b.num_entries()).sum()
}

/// True when the DHT is operating in [`Mode::Server`].
pub fn is_server_mode(kad: &Kad) -> bool {
    kad.mode() == Mode::Server
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kad_starts_in_server_mode() {
        let id = PeerId::random();
        let kad = new_kad(id);
        assert!(is_server_mode(&kad), "kad must run in Server mode");
    }

    #[test]
    fn parse_bootstrap_splits_peer_and_bare_addr() {
        let id = PeerId::random();
        let mut full = Multiaddr::empty();
        full.push(Protocol::Ip4(std::net::Ipv4Addr::new(203, 0, 113, 7)));
        full.push(Protocol::Tcp(4001));
        full.push(Protocol::P2p(id));
        let parsed = parse_bootstrap(&full).expect("parses");
        assert_eq!(parsed.peer_id, id);
        assert_eq!(parsed.full, full);
        assert!(parsed
            .address
            .iter()
            .all(|p| !matches!(p, Protocol::P2p(_))));
    }

    #[test]
    fn parse_bootstrap_rejects_anonymous_addr() {
        let mut addr = Multiaddr::empty();
        addr.push(Protocol::Ip4(std::net::Ipv4Addr::new(203, 0, 113, 7)));
        addr.push(Protocol::Tcp(4001));
        assert!(parse_bootstrap(&addr).is_none());
    }

    #[test]
    fn parse_bootstrap_rejects_bare_peer_id() {
        let mut addr = Multiaddr::empty();
        addr.push(Protocol::P2p(PeerId::random()));
        assert!(
            parse_bootstrap(&addr).is_none(),
            "a /p2p suffix with no dialable address is not a bootstrap"
        );
    }

    #[test]
    fn parse_bootstrap_rejects_ambiguous_multi_p2p() {
        let mut addr = Multiaddr::empty();
        addr.push(Protocol::Ip4(std::net::Ipv4Addr::new(203, 0, 113, 7)));
        addr.push(Protocol::Tcp(4001));
        addr.push(Protocol::P2p(PeerId::random()));
        addr.push(Protocol::P2p(PeerId::random()));
        assert!(
            parse_bootstrap(&addr).is_none(),
            "two /p2p components leave the identity ambiguous"
        );
    }

    #[test]
    fn identify_wiring_populates_routing_table() {
        let local = PeerId::random();
        let mut kad = new_kad(local);
        assert_eq!(routing_table_len(&mut kad), 0);
        let remote = PeerId::random();
        let mut addr = Multiaddr::empty();
        addr.push(Protocol::Ip4(std::net::Ipv4Addr::LOCALHOST));
        addr.push(Protocol::Tcp(4001));
        let wired = handle_identify_received(&mut kad, &remote, &[addr]);
        assert_eq!(wired, 1);
        assert_eq!(routing_table_len(&mut kad), 1);
    }

    #[test]
    fn mdns_discovery_feeds_same_routing_table() {
        let local = PeerId::random();
        let mut kad = new_kad(local);
        let remote = PeerId::random();
        let mut addr = Multiaddr::empty();
        addr.push(Protocol::Ip4(std::net::Ipv4Addr::LOCALHOST));
        addr.push(Protocol::Tcp(4002));
        let added = handle_mdns_discovered(&mut kad, &[(remote, addr)]);
        assert_eq!(added, 1);
        assert_eq!(routing_table_len(&mut kad), 1);
    }
}
