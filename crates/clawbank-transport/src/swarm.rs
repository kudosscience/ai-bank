//! Swarm for Comms 01-03 (ADR-0002 Phases 0-1 + NAT traversal).
//!
//! One libp2p swarm per node on the shared Tokio runtime: TCP + QUIC + DNS
//! transports (plus relay `p2p-circuit`) with the Identity 05 Noise XX
//! handshake ([`noise_config`]) and Yamux multiplexing, plus `identify`,
//! `ping`, Kademlia DHT in Server mode, mDNS LAN discovery, AutoNAT
//! self-classification, relay v2 server (capped, community-run) + relay
//! client, DCUtR hole-punching, and opportunistic UPnP port mapping. No
//! paid STUN/TURN fleet, no central server — two locally running nodes dial
//! each other by multiaddr and observe verified [`PeerId`]s; a NATed node
//! reserves a relay slot only when needed (see [`crate::reachability`])
//! and attempts a hole-punch upgrade with a logged outcome.

use crate::{
    discovery::{self, BootstrapPeer, Kad},
    noise_config,
    reachability::{capped_relay_config, format_hole_punch_outcome, HolePunchOutcome, Reachability},
    Keypair, PeerId,
};
use libp2p_core::{muxing::StreamMuxerBox, upgrade::Version, Transport};
use libp2p_swarm::NetworkBehaviour;
use multiaddr::Multiaddr;

/// Phase-1 + Comms 03 node behaviour: identification, liveness, DHT,
/// LAN discovery, NAT classification, relaying, hole-punching, UPnP.
///
/// `identify` publishes the local public key and listen addresses so a
/// connected peer learns our verified [`PeerId`]; `ping` keeps a health
/// signal on every connection. `kad` is the DHT routing table (Server mode
/// on reachable nodes); `mdns` finds LAN peers with zero configuration.
/// Every `identify::Event::Received` MUST be fed to kad via
/// [`discovery::handle_identify_received`] — libp2p does not auto-wire it.
///
/// Comms 03: `autonat` classifies public vs behind-NAT (see
/// [`Reachability`]); `relay` lets any public node serve as a capped
/// community relay; `relay_client` reserves a slot only when needed and
/// dials `/p2p-circuit` addresses; `dcutr` attempts the hole-punch upgrade;
/// `upnp` opportunistically maps ports where the gateway allows it.
/// Gossipsub arrives in Comms 04.
#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p_swarm::derive_prelude")]
pub struct BankBehaviour {
    /// Identifies the remote's public key and listen addresses.
    pub identify: libp2p_identify::Behaviour,
    /// Liveness probe on every connection.
    pub ping: libp2p_ping::Behaviour,
    /// DHT routing table; always [`libp2p_kad::Mode::Server`] here.
    pub kad: Kad,
    /// LAN discovery with no manual address exchange.
    pub mdns: libp2p_mdns::tokio::Behaviour,
    /// NAT/firewall self-classification (public vs behind-NAT).
    pub autonat: libp2p_autonat::Behaviour,
    /// Capped community relay server: any public node can serve.
    pub relay: libp2p_relay::Behaviour,
    /// Relay client: reserves a slot only when needed, dials circuits.
    pub relay_client: libp2p_relay::client::Behaviour,
    /// Direct-connection upgrade through relay (hole-punching).
    pub dcutr: libp2p_dcutr::Behaviour,
    /// Opportunistic UPnP port mapping (best-effort, never required).
    pub upnp: libp2p_upnp::tokio::Behaviour,
}

/// A Phase-1 swarm: TCP + Noise XX + Yamux with [`BankBehaviour`].
pub type BankSwarm = libp2p_swarm::Swarm<BankBehaviour>;

/// Identify protocol version advertised by this node.
pub const IDENTIFY_PROTOCOL_VERSION: &str = "clawbank/1.0.0";

/// Default idle timeout: connections with no keep-alive substream stay open
/// this long. Neither `identify` nor `ping` holds a keep-alive (ping streams
/// call `ignore_for_keep_alive` by design in `libp2p-ping 0.48`, so successful
/// probes do not reset the idle timer — see `libp2p-swarm 0.48`
/// `connection::compute_new_shutdown`). The pool would otherwise close an idle
/// connection immediately; 30s keeps it alive long enough for the Phase-0
/// smoke-test probes to run. This is a finite window, not indefinite
/// persistence: a ping-only connection still closes after the timeout and is
/// re-dialed on demand. Persistent keep-alive arrives with later phases
/// (gossipsub/kad).
pub const DEFAULT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Headroom added to the ping interval when deriving the idle timeout, so at
/// least one ping fits inside the idle window with room for jitter. 15s
/// preserves the historical default: 15s (default ping interval) + 15s = 30s.
pub const IDLE_TIMEOUT_BUFFER: std::time::Duration = std::time::Duration::from_secs(15);

/// Derive a safe idle timeout for a given ping interval.
///
/// Returns `max(DEFAULT_IDLE_TIMEOUT, interval + IDLE_TIMEOUT_BUFFER)` so the
/// first ping at a caller-supplied cadence of 30s or more still fits inside
/// the idle window. It does not grant indefinite persistence: ping streams are
/// ignored for keep-alive, so the idle timer is not reset by successful
/// probes and a ping-only connection still closes after the timeout.
pub fn idle_timeout_for_interval(interval: std::time::Duration) -> std::time::Duration {
    std::cmp::max(
        DEFAULT_IDLE_TIMEOUT,
        interval.saturating_add(IDLE_TIMEOUT_BUFFER),
    )
}

/// Build a swarm bound to the Identity 01 node keypair.
///
/// The Noise XX config is exactly [`noise_config`] — the choice proven in
/// Identity 05 — so the swarm handshake verifies the same [`PeerId`]
/// identity the raw [`crate::dial`]/[`crate::listen`] channel proved. Yamux
/// multiplexes the authenticated TCP stream; `identify` + `ping` run on top.
///
/// Idle connections stay open for [`DEFAULT_IDLE_TIMEOUT`] (instead of the
/// libp2p default of immediate close): neither `identify` nor `ping` holds a
/// keep-alive on an otherwise idle connection, and Phase 0 needs the
/// connection to survive long enough for the smoke-test ping to run. This is
/// intentionally finite — ping does not reset the idle timer by upstream
/// design, so ping-only connections close after the timeout. Later phases
/// with gossipsub/kad add persistent keep-alive as needed.
///
/// Uses the default ping cadence (15s interval, 20s timeout), safely inside
/// the 30s idle window, and the default mDNS config.
///
/// Returns the swarm; callers own listening (`Swarm::listen_on`) and dialing
/// (`Swarm::dial`) on the shared Tokio runtime.
pub fn new_swarm(keypair: &Keypair) -> Result<BankSwarm, SwarmBuildError> {
    new_swarm_with_ping(
        keypair,
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(20),
    )
}

/// Build a swarm with an explicit ping cadence (tests use a short interval).
///
/// Same stack as [`new_swarm`]; the idle timeout is derived via
/// [`idle_timeout_for_interval`] so at least the first ping fits inside the
/// idle window, no matter how long `ping_interval` is. Does not promise
/// indefinite liveness — see [`DEFAULT_IDLE_TIMEOUT`].
pub fn new_swarm_with_ping(
    keypair: &Keypair,
    ping_interval: std::time::Duration,
    ping_timeout: std::time::Duration,
) -> Result<BankSwarm, SwarmBuildError> {
    let ping_config = libp2p_ping::Config::new()
        .with_interval(ping_interval)
        .with_timeout(ping_timeout);
    new_swarm_with_config(
        keypair,
        ping_config,
        idle_timeout_for_interval(ping_interval),
    )
}

/// Build a swarm with an explicit ping config and idle timeout.
///
/// Same stack as [`new_swarm`]. Prefer [`new_swarm_with_ping`] unless you
/// need full control: callers who supply both values directly MUST keep
/// `idle_timeout` strictly greater than the ping interval embedded in
/// `ping_config` so at least the first ping fits, otherwise the idle closer
/// reaps the connection before it runs. Even when satisfied, the window stays
/// finite (ping never resets the idle timer); indefinite keep-alive is a
/// later-phase concern.
pub fn new_swarm_with_config(
    keypair: &Keypair,
    ping_config: libp2p_ping::Config,
    idle_timeout: std::time::Duration,
) -> Result<BankSwarm, SwarmBuildError> {
    new_swarm_full(
        keypair,
        ping_config,
        idle_timeout,
        libp2p_mdns::Config::default(),
    )
}

/// Build a swarm with full control over ping and mDNS (tests shorten the
/// mDNS query interval so LAN discovery fires inside the test timeout).
///
/// `mdns_config.query_interval` of ~1s keeps the `mdns_discovery` test fast;
/// production uses the default (5min) to avoid LAN chatter.
///
/// Transport is TCP + QUIC + DNS + relay `p2p-circuit`, all sharing the
/// Identity 05 Noise XX handshake. Behaviour adds AutoNAT classification,
/// a capped community relay server, a relay client (reserves only when
/// needed), DCUtR hole-punching, and opportunistic UPnP.
pub fn new_swarm_full(
    keypair: &Keypair,
    ping_config: libp2p_ping::Config,
    idle_timeout: std::time::Duration,
    mdns_config: libp2p_mdns::Config,
) -> Result<BankSwarm, SwarmBuildError> {
    let local_peer = PeerId::from(keypair.public());

    // TCP with Noise XX + Yamux (the proven base).
    let tcp =
        libp2p_tcp::tokio::Transport::new(libp2p_tcp::Config::new().nodelay(true));
    let noise_tcp = noise_config(keypair).map_err(|e| SwarmBuildError::Noise(e.to_string()))?;
    // Yamux 0.14.x via libp2p-yamux 0.48 (lockfile pins yamux 0.14.1,
    // which contains the CVE-2026-32314 Data-frame panic fix first
    // shipped in 0.13.10). The vulnerable yamux 0.12.1 shim vendored by
    // libp2p-yamux 0.45.x is gone: 0.48 depends only on yamux 0.14.
    let tcp_upgraded = tcp
        .upgrade(Version::V1Lazy)
        .authenticate(noise_tcp)
        .multiplex(libp2p_yamux::Config::default())
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)));

    // QUIC: TLS-bound to the same identity key, UDP hole-punching where
    // TCP cannot go. Already authenticated + multiplexed, so no upgrade.
    let quic = libp2p_quic::tokio::Transport::new(libp2p_quic::Config::new(keypair))
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)));

    let tcp_or_quic = tcp_upgraded
        .or_transport(quic)
        .map(|either, _| either.into_inner());

    // Relay client transport (handles `/p2p-circuit` dials + listens),
    // upgraded with the same Noise XX + Yamux choice.
    let (relay_transport, relay_client) =
        libp2p_relay::client::new(local_peer);
    let noise_relay =
        noise_config(keypair).map_err(|e| SwarmBuildError::Noise(e.to_string()))?;
    let relay_upgraded = relay_transport
        .upgrade(Version::V1Lazy)
        .authenticate(noise_relay)
        .multiplex(libp2p_yamux::Config::default())
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)));

    let combined = relay_upgraded
        .or_transport(tcp_or_quic)
        .map(|either, _| either.into_inner());

    // DNS: resolves `/dns*` bootstrap / relay names, then delegates.
    let dns_wrapped = libp2p_dns::tokio::Transport::system(combined)
        .map_err(SwarmBuildError::Dns)?;
    let transport = dns_wrapped.boxed();

    let identify_cfg =
        libp2p_identify::Config::new(IDENTIFY_PROTOCOL_VERSION.to_string(), keypair.public())
            .with_agent_version(format!("clawbank/{}", env!("CARGO_PKG_VERSION")));
    let behaviour = BankBehaviour {
        identify: libp2p_identify::Behaviour::new(identify_cfg),
        ping: libp2p_ping::Behaviour::new(ping_config),
        kad: discovery::new_kad(local_peer),
        mdns: libp2p_mdns::tokio::Behaviour::new(mdns_config, local_peer)
            .map_err(SwarmBuildError::Mdns)?,
        autonat: libp2p_autonat::Behaviour::new(local_peer, Default::default()),
        relay: libp2p_relay::Behaviour::new(local_peer, capped_relay_config()),
        relay_client,
        dcutr: libp2p_dcutr::Behaviour::new(local_peer),
        upnp: libp2p_upnp::tokio::Behaviour::default(),
    };
    Ok(BankSwarm::new(
        transport,
        behaviour,
        local_peer,
        libp2p_swarm::Config::with_tokio_executor().with_idle_connection_timeout(idle_timeout),
    ))
}

/// Map an AutoNAT swarm event onto [`Reachability`.
///
/// Returns `Some` only for `StatusChanged` (the self-classification the
/// acceptance criterion requires); inbound/outbound probe chatter returns
/// `None` so callers do not flap on every probe.
pub fn autonat_reachability(event: &libp2p_autonat::Event) -> Option<Reachability> {
    match event {
        libp2p_autonat::Event::StatusChanged { new, .. } => {
            Some(crate::reachability::reachability_from_autonat(new))
        }
        _ => None,
    }
}

/// Map a DCUtR event onto a loggable [`HolePunchOutcome`].
///
/// `Ok(connection)` means the direct path replaced the relayed one;
/// `Err` means the node stays relay-routed (caller surfaces the
/// `relay-only (limited)` indicator and logs via
/// [`format_hole_punch_outcome`]).
pub fn hole_punch_outcome(event: &libp2p_dcutr::Event) -> (PeerId, HolePunchOutcome) {
    match &event.result {
        Ok(_) => (
            event.remote_peer_id,
            HolePunchOutcome::DirectUpgraded { new_addr: None },
        ),
        Err(e) => (
            event.remote_peer_id,
            HolePunchOutcome::StillRelayed {
                reason: e.to_string(),
            },
        ),
    }
}

/// Format a DCUtR event as its one-line hole-punch log.
///
/// Convenience for swarm event loops: maps then formats in one call so
/// every relay-routed dial logs its upgrade attempt outcome.
pub fn format_dcutr_event(event: &libp2p_dcutr::Event) -> String {
    let (peer, outcome) = hole_punch_outcome(event);
    format_hole_punch_outcome(&peer, &outcome)
}

/// Force-enable the relay server HOP advertisement.
///
/// The relay server starts disabled until it holds a confirmed external
/// address (learned via AutoNAT/identify on a public node). Loopback and
/// CI relays never gain one, so tests and explicitly-configured community
/// relays call this to serve reservations anyway. Public nodes in the wild
/// enable automatically once AutoNAT confirms reachability; calling this
/// is equivalent to operator intent "serve as relay".
pub fn enable_relay_server(swarm: &mut BankSwarm) {
    swarm
        .behaviour_mut()
        .relay
        .set_status(Some(libp2p_relay::Status::Enable));
}
///
/// `relay_addr` is the configured relay's dialable address (without `/p2p`);
/// this appends `/p2p/<relay>/p2p-circuit` and calls `listen_on`, which
/// drives the relay client reservation. Only call when
/// [`crate::reachability::should_reserve_relay_slot`] holds — public nodes
/// serve as relays instead of consuming slots.
pub fn reserve_relay_slot(
    swarm: &mut BankSwarm,
    relay_addr: &Multiaddr,
    relay_peer: &PeerId,
) -> Result<libp2p_core::transport::ListenerId, RelayReserveError> {
    if relay_addr.is_empty() {
        return Err(RelayReserveError::EmptyRelayAddr);
    }
    let mut circuit = relay_addr.clone();
    circuit.push(multiaddr::Protocol::P2p(*relay_peer));
    circuit.push(multiaddr::Protocol::P2pCircuit);
    swarm.listen_on(circuit).map_err(RelayReserveError::listen)
}

/// Build the relay-routed dial address for `dest` via `relay`.
///
/// Thin wrapper over [`crate::reachability::build_relay_circuit_addr`]
/// for swarm call sites.
pub fn relay_circuit_dial_addr(
    relay_addr: &Multiaddr,
    relay_peer: &PeerId,
    dest_peer: &PeerId,
) -> Result<Multiaddr, RelayReserveError> {
    crate::reachability::build_relay_circuit_addr(relay_addr, relay_peer, dest_peer)
        .map_err(|_| RelayReserveError::EmptyRelayAddr)
}

/// Reserving or addressing a relay circuit failed.
#[derive(Debug)]
pub enum RelayReserveError {
    /// The configured relay address had no dialable component.
    EmptyRelayAddr,
    /// `Swarm::listen_on` rejected the circuit address.
    Listen(String),
}

impl RelayReserveError {
    fn listen(e: impl std::fmt::Display) -> Self {
        RelayReserveError::Listen(e.to_string())
    }
}

impl std::fmt::Display for RelayReserveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayReserveError::EmptyRelayAddr => write!(f, "relay address is empty"),
            RelayReserveError::Listen(detail) => {
                write!(f, "relay reservation listen failed: {detail}")
            }
        }
    }
}

impl std::error::Error for RelayReserveError {}

/// Failure to build a [`BankSwarm`]: Noise key material, mDNS sockets, or
/// DNS resolver config.
#[derive(Debug)]
pub enum SwarmBuildError {
    /// The Noise XX config rejected the node keypair.
    Noise(String),
    /// mDNS could not watch interfaces / bind its UDP socket.
    Mdns(std::io::Error),
    /// DNS-over-system resolver could not be built (e.g. no resolv.conf).
    Dns(std::io::Error),
}

impl std::fmt::Display for SwarmBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SwarmBuildError::Noise(detail) => write!(f, "swarm noise config failed: {detail}"),
            SwarmBuildError::Mdns(e) => write!(f, "swarm mdns init failed: {e}"),
            SwarmBuildError::Dns(e) => write!(f, "swarm dns init failed: {e}"),
        }
    }
}

impl std::error::Error for SwarmBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SwarmBuildError::Noise(_) => None,
            SwarmBuildError::Mdns(e) => Some(e),
            SwarmBuildError::Dns(e) => Some(e),
        }
    }
}

/// Add a well-known bootstrap peer: feed its address to kad and dial it.
///
/// The address is a rendezvous hint, not an authority — after this single
/// dial the node discovers the rest of the DHT on its own (identify→kad
/// wiring plus `kad.bootstrap`). Returns the parsed peer for callers that
/// need to wait for the connection / routing-table entry.
pub fn add_bootstrap(
    swarm: &mut BankSwarm,
    bootstrap: &Multiaddr,
) -> Result<BootstrapPeer, BootstrapError> {
    let parsed = discovery::parse_bootstrap(bootstrap).ok_or(BootstrapError::MissingPeerId)?;
    swarm
        .behaviour_mut()
        .kad
        .add_address(&parsed.peer_id, parsed.address.clone());
    swarm
        .dial(parsed.full.clone())
        .map_err(BootstrapError::dial)?;
    Ok(parsed)
}

/// Start a Kademlia bootstrap query against the peers added so far.
///
/// Call after [`add_bootstrap`] (and after the identify→kad wiring has run
/// for the dialed peer). Succeeds once at least one known peer exists;
/// with zero known peers libp2p returns `NoKnownPeers` — callers must add
/// the bootstrap address first.
pub fn start_bootstrap(
    swarm: &mut BankSwarm,
) -> Result<libp2p_kad::QueryId, libp2p_kad::NoKnownPeers> {
    swarm.behaviour_mut().kad.bootstrap()
}

/// Number of peers in this swarm's Kademlia routing table.
pub fn routing_table_len(swarm: &mut BankSwarm) -> usize {
    discovery::routing_table_len(&mut swarm.behaviour_mut().kad)
}

/// True when this swarm's kad runs in Server mode (must always hold).
pub fn is_server_mode(swarm: &BankSwarm) -> bool {
    discovery::is_server_mode(&swarm.behaviour().kad)
}

/// Bootstrap failure: unparsable well-known address or dial rejection.
#[derive(Debug)]
pub enum BootstrapError {
    /// The multiaddr carried no `/p2p` identity — not a usable bootstrap.
    MissingPeerId,
    /// `Swarm::dial` rejected the address (e.g. bad transport / unknown).
    Dial(String),
}

impl BootstrapError {
    fn dial(e: impl std::fmt::Display) -> Self {
        BootstrapError::Dial(e.to_string())
    }
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootstrapError::MissingPeerId => {
                write!(f, "bootstrap multiaddr has no /p2p peer id")
            }
            BootstrapError::Dial(detail) => write!(f, "bootstrap dial failed: {detail}"),
        }
    }
}

impl std::error::Error for BootstrapError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_timeout_covers_ping_interval() {
        // Historical defaults preserved.
        assert_eq!(
            idle_timeout_for_interval(std::time::Duration::from_millis(500)),
            DEFAULT_IDLE_TIMEOUT
        );
        assert_eq!(
            idle_timeout_for_interval(std::time::Duration::from_secs(15)),
            std::time::Duration::from_secs(30)
        );
        // Long intervals extend the window instead of starving ping.
        assert_eq!(
            idle_timeout_for_interval(std::time::Duration::from_secs(30)),
            std::time::Duration::from_secs(45)
        );
        assert_eq!(
            idle_timeout_for_interval(std::time::Duration::from_secs(60)),
            std::time::Duration::from_secs(75)
        );
    }
}
