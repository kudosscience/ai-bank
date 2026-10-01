//! Swarm skeleton for Comms 01 (ADR-0002 Phase 0).
//!
//! One libp2p swarm per node on the shared Tokio runtime: TCP transport with
//! the Identity 05 Noise XX handshake ([`noise_config`]) and Yamux
//! multiplexing, plus `identify` and `ping` behaviours. No relay, no STUN
//! fleet, no central server at this layer — two locally running nodes dial
//! each other by multiaddr and observe verified [`PeerId`]s.
//!
//! Later phases (kad, autonat, relay, dcutr, mdns, gossipsub, QUIC) extend
//! [`BankBehaviour`]; the transport stack built here stays the shared base.

use crate::{noise_config, Keypair, PeerId};
use libp2p_core::{upgrade::Version, Transport};
use libp2p_swarm::NetworkBehaviour;

/// Phase-0 node behaviour: peer identification plus liveness ping.
///
/// `identify` publishes the local public key and listen addresses so a
/// connected peer learns our verified [`PeerId`]; `ping` keeps a health
/// signal on every connection. Gossipsub, kad, autonat, relay, dcutr and
/// mdns arrive in later phases.
#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p_swarm::derive_prelude")]
pub struct BankBehaviour {
    /// Identifies the remote's public key and listen addresses.
    pub identify: libp2p_identify::Behaviour,
    /// Liveness probe on every connection.
    pub ping: libp2p_ping::Behaviour,
}

/// A Phase-0 swarm: TCP + Noise XX + Yamux with [`BankBehaviour`].
pub type BankSwarm = libp2p_swarm::Swarm<BankBehaviour>;

/// Identify protocol version advertised by this node.
pub const IDENTIFY_PROTOCOL_VERSION: &str = "clawbank/1.0.0";

/// Build a swarm bound to the Identity 01 node keypair.
///
/// The Noise XX config is exactly [`noise_config`] — the choice proven in
/// Identity 05 — so the swarm handshake verifies the same [`PeerId`]
/// identity the raw [`crate::dial`]/[`crate::listen`] channel proved. Yamux
/// multiplexes the authenticated TCP stream; `identify` + `ping` run on top.
///
/// Idle connections stay open for 30s (instead of the libp2p default of
/// immediate close): neither `identify` nor `ping` holds a keep-alive on an
/// otherwise idle connection, and Phase 0 needs the connection to survive
/// long enough for the periodic ping to run. Later phases with gossipsub/kad
/// may revisit this.
///
/// Returns the swarm; callers own listening (`Swarm::listen_on`) and dialing
/// (`Swarm::dial`) on the shared Tokio runtime.
pub fn new_swarm(keypair: &Keypair) -> Result<BankSwarm, libp2p_noise::Error> {
    new_swarm_with_config(keypair, libp2p_ping::Config::new())
}

/// Build a swarm with an explicit ping config (tests use a short interval).
///
/// Same stack as [`new_swarm`]; `ping_config` only tunes the liveness probe
/// cadence, not the transport or identity binding.
pub fn new_swarm_with_config(
    keypair: &Keypair,
    ping_config: libp2p_ping::Config,
) -> Result<BankSwarm, libp2p_noise::Error> {
    let local_peer = PeerId::from(keypair.public());
    let tcp = libp2p_tcp::tokio::Transport::new(libp2p_tcp::Config::new().nodelay(true));
    let noise = noise_config(keypair)?;
    let yamux = libp2p_yamux::Config::default();
    let transport = tcp
        .upgrade(Version::V1Lazy)
        .authenticate(noise)
        .multiplex(yamux)
        .boxed();

    let identify_cfg = libp2p_identify::Config::new(
        IDENTIFY_PROTOCOL_VERSION.to_string(),
        keypair.public(),
    )
    .with_agent_version(format!("clawbank/{}", env!("CARGO_PKG_VERSION")));
    let behaviour = BankBehaviour {
        identify: libp2p_identify::Behaviour::new(identify_cfg),
        ping: libp2p_ping::Behaviour::new(ping_config),
    };
    Ok(BankSwarm::new(
        transport,
        behaviour,
        local_peer,
        libp2p_swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(std::time::Duration::from_secs(30)),
    ))
}
