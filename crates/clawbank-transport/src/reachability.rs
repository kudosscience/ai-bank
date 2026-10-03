//! NAT traversal and reachability for Comms 03 (ADR-0002).
//!
//! A node behind a home NAT or firewall still joins and transacts: it
//! classifies its own reachability via AutoNAT, reserves a capped slot on a
//! community-run relay only when it must, attempts a hole-punch upgrade via
//! DCUtR with a logged outcome, and plainly reports `relay-only (limited)`
//! when it stays relay-routed. No paid STUN/TURN fleet exists anywhere.
//!
//! This module is the pure-logic seam: classification, reservation caps,
//! relayed-address helpers, circuit-address construction (relay addresses
//! come from config — kad discovery is not required), and the hole-punch
//! outcome log line. The swarm wiring lives in [`crate::swarm`]; the
//! behaviours there (`autonat`, `relay`, `relay_client`, `dcutr`, `upnp`)
//! execute what these helpers decide.
//!
//! Transports: TCP + QUIC + DNS (+ relay `p2p-circuit`) with opportunistic
//! UPnP port mapping. QUIC gives UDP hole-punching where TCP cannot go;
//! DNS lets bootstrap / relay addresses use names; UPnP is best-effort and
//! never required.

use multiaddr::{Multiaddr, Protocol};

use crate::PeerId;

/// Self-classified reachability from AutoNAT probes.
///
/// Maps 1:1 from `libp2p_autonat::NatStatus`: `Public(confirmed)` when a
/// dial-back succeeded, `Private` when probes prove we are unreachable,
/// `Unknown` before any conclusive probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reachability {
    /// No conclusive AutoNAT probe yet.
    Unknown,
    /// Publicly dialable; carries the confirmed external address.
    Public {
        /// The address a remote successfully dialed back.
        confirmed_addr: Multiaddr,
    },
    /// Behind NAT/firewall: inbound dials fail.
    Private,
}

impl Reachability {
    /// True when the node is known to be directly dialable.
    pub fn is_public(&self) -> bool {
        matches!(self, Reachability::Public { .. })
    }

    /// True when the node is known to need traversal help.
    pub fn is_private(&self) -> bool {
        matches!(self, Reachability::Private)
    }
}

/// Map an AutoNAT status onto [`Reachability`].
///
/// `Public(addr)` → [`Reachability::Public`]; anything else maps by variant.
/// Takes the status by reference so callers keep owning the swarm event.
pub fn reachability_from_autonat(status: &libp2p_autonat::NatStatus) -> Reachability {
    match status {
        libp2p_autonat::NatStatus::Public(addr) => Reachability::Public {
            confirmed_addr: addr.clone(),
        },
        libp2p_autonat::NatStatus::Private => Reachability::Private,
        libp2p_autonat::NatStatus::Unknown => Reachability::Unknown,
    }
}

/// Whether this node should hold a relay reservation.
///
/// Only NATed (or not-yet-classified) nodes reserve a slot; public nodes
/// serve as relays instead of consuming slots. This is the "only when
/// needed" gate in front of the capped reservation.
pub fn should_reserve_relay_slot(reachability: &Reachability) -> bool {
    match reachability {
        Reachability::Public { .. } => false,
        Reachability::Private | Reachability::Unknown => true,
    }
}

/// Capped relay load: a community relay serves many peers at negligible
/// cost because every dimension is bounded.
///
/// Defaults mirror `libp2p_relay::Config::default` (128 reservations total,
/// 4 per peer, 16 circuits total, 4 per peer, 128 KiB per circuit, 1h
/// reservations, 2min circuits) — the values the swarm builder installs via
/// [`capped_relay_config`]. Any public node can serve as relay with these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLimits {
    /// Total concurrent reservations the relay accepts.
    pub max_reservations: usize,
    /// Reservations accepted from a single peer.
    pub max_reservations_per_peer: usize,
    /// Total concurrent relayed circuits.
    pub max_circuits: usize,
    /// Circuits accepted for a single peer.
    pub max_circuits_per_peer: usize,
    /// Bytes allowed per circuit before it is torn down.
    pub max_circuit_bytes: u64,
    /// How long one reservation lasts before renewal.
    pub reservation_duration: std::time::Duration,
    /// How long one relayed circuit may stay open.
    pub max_circuit_duration: std::time::Duration,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self::capped()
    }
}

impl RelayLimits {
    /// The capped defaults the relay server runs with.
    pub fn capped() -> Self {
        Self {
            max_reservations: 128,
            max_reservations_per_peer: 4,
            max_circuits: 16,
            max_circuits_per_peer: 4,
            max_circuit_bytes: 1 << 17, // 128 KiB
            reservation_duration: std::time::Duration::from_secs(60 * 60),
            max_circuit_duration: std::time::Duration::from_secs(2 * 60),
        }
    }

    /// True when one more reservation fits within both caps.
    pub fn allows_reservation(&self, total: usize, per_peer: usize) -> bool {
        total < self.max_reservations && per_peer < self.max_reservations_per_peer
    }

    /// True when one more relayed circuit fits within both caps.
    pub fn allows_circuit(&self, total: usize, per_peer: usize) -> bool {
        total < self.max_circuits && per_peer < self.max_circuits_per_peer
    }
}

/// Build the `libp2p_relay` server config with the capped limits.
///
/// Any public node runs this: bounded reservations + circuits keep relay
/// load negligible, so no dedicated fleet is needed. Caps are pinned from
/// [`RelayLimits::capped`] field-by-field (not `Config::default`), so a
/// future upstream default change cannot silently uncap us.
pub fn capped_relay_config() -> libp2p_relay::Config {
    let limits = RelayLimits::capped();
    let mut cfg = libp2p_relay::Config::default();
    cfg.max_reservations = limits.max_reservations;
    cfg.max_reservations_per_peer = limits.max_reservations_per_peer;
    cfg.max_circuits = limits.max_circuits;
    cfg.max_circuits_per_peer = limits.max_circuits_per_peer;
    cfg.max_circuit_bytes = limits.max_circuit_bytes;
    cfg.reservation_duration = limits.reservation_duration;
    cfg.max_circuit_duration = limits.max_circuit_duration;
    cfg
}

/// True when the multiaddr routes via a relay (`/p2p-circuit` present).
pub fn is_relayed_address(addr: &Multiaddr) -> bool {
    addr.iter()
        .any(|proto| matches!(proto, Protocol::P2pCircuit))
}

/// True when at least one address in the set is relay-routed.
pub fn has_relayed_address(addrs: &[Multiaddr]) -> bool {
    addrs.iter().any(is_relayed_address)
}

/// True when at least one address is directly dialable (not relayed).
pub fn has_direct_address(addrs: &[Multiaddr]) -> bool {
    addrs.iter().any(|a| !is_relayed_address(a))
}

/// True when the node has only relay-routed addresses to offer.
///
/// Empty sets are NOT relay-only (nothing is known yet); a non-empty set
/// where every address contains `/p2p-circuit` is. Callers surface
/// [`RELAY_ONLY_INDICATOR`] when this holds.
pub fn is_relay_only(addrs: &[Multiaddr]) -> bool {
    !addrs.is_empty() && addrs.iter().all(is_relayed_address)
}

/// Visible indicator for nodes stuck relay-routed (symmetric NAT, ~5-15%).
pub const RELAY_ONLY_INDICATOR: &str = "relay-only (limited)";

/// Indicator for directly reachable nodes.
pub const DIRECT_INDICATOR: &str = "direct";

/// Human-visible reachability indicator.
///
/// Returns [`RELAY_ONLY_INDICATOR`] when the address set is relay-only,
/// otherwise [`DIRECT_INDICATOR`]. Empty/unknown sets report direct-capable
/// (nothing proved us stuck yet) — the relay-only flag appears only on
/// positive evidence of being stuck behind an unpunchable NAT.
pub fn reachability_indicator(addrs: &[Multiaddr]) -> &'static str {
    if is_relay_only(addrs) {
        RELAY_ONLY_INDICATOR
    } else {
        DIRECT_INDICATOR
    }
}

/// Build a relay-routed dial address for `dest` via `relay`.
///
/// `relay_addr` is the relay's dialable address WITHOUT any `/p2p`
/// component (from config); the result is
/// `<relay_addr>/p2p/<relay>/p2p-circuit/p2p/<dest>` — the shape the relay
/// client transport dials. Returns an error when `relay_addr` is empty
/// (nothing to route through).
pub fn build_relay_circuit_addr(
    relay_addr: &Multiaddr,
    relay_peer: &PeerId,
    dest_peer: &PeerId,
) -> Result<Multiaddr, RelayAddrError> {
    if relay_addr.is_empty() {
        return Err(RelayAddrError::EmptyRelayAddr);
    }
    let mut out = relay_addr.clone();
    out.push(Protocol::P2p(*relay_peer));
    out.push(Protocol::P2pCircuit);
    out.push(Protocol::P2p(*dest_peer));
    Ok(out)
}

/// A relay circuit address that could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayAddrError {
    /// The configured relay address had no dialable component.
    EmptyRelayAddr,
}

impl std::fmt::Display for RelayAddrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayAddrError::EmptyRelayAddr => write!(f, "relay address is empty"),
        }
    }
}

impl std::error::Error for RelayAddrError {}

/// Outcome of the DCUtR hole-punch upgrade attempt.
///
/// Every relay-routed connection attempts an upgrade; the result is logged
/// via [`format_hole_punch_outcome`] so operators see whether the direct
/// path opened or the node stays relay-routed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HolePunchOutcome {
    /// No upgrade was attempted (already direct, or no relayed peer).
    NotAttempted,
    /// The direct connection replaced the relayed one.
    DirectUpgraded {
        /// The new direct address, when known.
        new_addr: Option<Multiaddr>,
    },
    /// Still relay-routed; the node shows [`RELAY_ONLY_INDICATOR`].
    StillRelayed {
        /// Why the punch did not open a direct path.
        reason: String,
    },
}

/// One-line log string for a hole-punch outcome.
///
/// `StillRelayed` always mentions the relay-only indicator so the "stuck"
/// state is visible in logs, not just in the status surface.
pub fn format_hole_punch_outcome(peer: &PeerId, outcome: &HolePunchOutcome) -> String {
    match outcome {
        HolePunchOutcome::NotAttempted => {
            format!("hole-punch not attempted for {peer}")
        }
        HolePunchOutcome::DirectUpgraded { new_addr } => match new_addr {
            Some(addr) => format!("hole-punch to {peer} succeeded via {addr}"),
            None => format!("hole-punch to {peer} succeeded (direct)"),
        },
        HolePunchOutcome::StillRelayed { reason } => {
            format!("hole-punch to {peer} failed ({reason}); staying {RELAY_ONLY_INDICATOR}")
        }
    }
}

/// True when the multiaddr uses QUIC (`/quic-v1` present).
///
/// QUIC extends reachability with UDP hole-punching where TCP cannot go.
pub fn is_quic_address(addr: &Multiaddr) -> bool {
    addr.iter()
        .any(|proto| matches!(proto, Protocol::QuicV1))
}

/// True when the multiaddr needs DNS resolution (`/dns*` present).
///
/// DNS transports let bootstrap and relay addresses use names.
pub fn is_dns_address(addr: &Multiaddr) -> bool {
    addr.iter().any(|proto| {
        matches!(
            proto,
            Protocol::Dns(_)
                | Protocol::Dns4(_)
                | Protocol::Dns6(_)
                | Protocol::Dnsaddr(_)
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback_tcp(port: u16) -> Multiaddr {
        format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap()
    }

    #[test]
    fn autonat_maps_to_reachability() {
        let addr = loopback_tcp(4001);
        assert_eq!(
            reachability_from_autonat(&libp2p_autonat::NatStatus::Public(addr.clone())),
            Reachability::Public {
                confirmed_addr: addr
            }
        );
        assert_eq!(
            reachability_from_autonat(&libp2p_autonat::NatStatus::Private),
            Reachability::Private
        );
        assert_eq!(
            reachability_from_autonat(&libp2p_autonat::NatStatus::Unknown),
            Reachability::Unknown
        );
    }

    #[test]
    fn only_nated_nodes_reserve_relay_slots() {
        let public = Reachability::Public {
            confirmed_addr: loopback_tcp(4001),
        };
        assert!(!should_reserve_relay_slot(&public));
        assert!(should_reserve_relay_slot(&Reachability::Private));
        // Unknown reserves conservatively until proven public.
        assert!(should_reserve_relay_slot(&Reachability::Unknown));
    }

    #[test]
    fn relay_caps_are_bounded() {
        let limits = RelayLimits::capped();
        assert_eq!(limits.max_reservations, 128);
        assert_eq!(limits.max_reservations_per_peer, 4);
        assert_eq!(limits.max_circuits, 16);
        assert_eq!(limits.max_circuits_per_peer, 4);
        assert!(limits.allows_reservation(0, 0));
        assert!(limits.allows_reservation(127, 3));
        assert!(!limits.allows_reservation(128, 0));
        assert!(!limits.allows_reservation(0, 4));
        assert!(limits.allows_circuit(0, 0));
        assert!(!limits.allows_circuit(16, 0));
        assert!(!limits.allows_circuit(0, 4));
    }

    #[test]
    fn relayed_detection_and_relay_only_indicator() {
        let direct = loopback_tcp(4001);
        let relayed: Multiaddr = "/ip4/203.0.113.7/tcp/4001/p2p/12D3KooWDrFGgb3hRZL5X9eXFPzbK1629hHR2Xv3z1gAkiED9Hcn/p2p-circuit"
            .parse()
            .unwrap();
        assert!(!is_relayed_address(&direct));
        assert!(is_relayed_address(&relayed));
        assert!(!is_relay_only(&[]));
        assert!(!is_relay_only(&[direct.clone()]));
        assert!(!is_relay_only(&[direct.clone(), relayed.clone()]));
        assert!(is_relay_only(&[relayed.clone()]));
        assert_eq!(reachability_indicator(&[relayed.clone()]), RELAY_ONLY_INDICATOR);
        assert_eq!(reachability_indicator(&[direct.clone()]), DIRECT_INDICATOR);
        assert_eq!(reachability_indicator(&[]), DIRECT_INDICATOR);
        assert!(has_relayed_address(&[relayed.clone()]));
        assert!(!has_relayed_address(&[direct.clone()]));
        assert!(has_direct_address(&[direct]));
        assert!(!has_direct_address(&[relayed]));
    }

    #[test]
    fn circuit_addr_shape_routes_via_relay() {
        let relay_addr: Multiaddr = "/ip4/203.0.113.7/tcp/4001".parse().unwrap();
        let relay_peer = PeerId::random();
        let dest = PeerId::random();
        let circuit = build_relay_circuit_addr(&relay_addr, &relay_peer, &dest).unwrap();
        assert!(is_relayed_address(&circuit));
        let text = circuit.to_string();
        assert!(text.contains("/p2p-circuit/"), "circuit shape: {text}");
        assert!(text.contains(&relay_peer.to_string()));
        assert!(text.contains(&dest.to_string()));
        assert_eq!(
            build_relay_circuit_addr(&Multiaddr::empty(), &relay_peer, &dest),
            Err(RelayAddrError::EmptyRelayAddr)
        );
    }

    #[test]
    fn hole_punch_outcome_logs_relay_only_when_stuck() {
        let peer = PeerId::random();
        let ok = format_hole_punch_outcome(
            &peer,
            &HolePunchOutcome::DirectUpgraded { new_addr: None },
        );
        assert!(ok.contains("succeeded"), "{ok}");
        let ok_addr = format_hole_punch_outcome(
            &peer,
            &HolePunchOutcome::DirectUpgraded {
                new_addr: Some(loopback_tcp(4001)),
            },
        );
        assert!(ok_addr.contains("succeeded"), "{ok_addr}");
        let stuck = format_hole_punch_outcome(
            &peer,
            &HolePunchOutcome::StillRelayed {
                reason: "symmetric NAT".to_string(),
            },
        );
        assert!(stuck.contains(RELAY_ONLY_INDICATOR), "{stuck}");
        assert!(stuck.contains("symmetric NAT"), "{stuck}");
        let skipped =
            format_hole_punch_outcome(&peer, &HolePunchOutcome::NotAttempted);
        assert!(skipped.contains("not attempted"), "{skipped}");
    }

    #[test]
    fn quic_and_dns_addresses_detected() {
        let quic: Multiaddr = "/ip4/127.0.0.1/udp/4001/quic-v1".parse().unwrap();
        assert!(is_quic_address(&quic));
        assert!(!is_quic_address(&loopback_tcp(4001)));
        let dns: Multiaddr = "/dns/bootstrap.example.com/tcp/4001".parse().unwrap();
        assert!(is_dns_address(&dns));
        assert!(!is_dns_address(&loopback_tcp(4001)));
    }
}
