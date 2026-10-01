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

/// Default idle timeout: connections with no keep-alive substream stay open
/// this long. Neither `identify` nor `ping` holds a keep-alive (ping streams
/// call `ignore_for_keep_alive`), so the pool would otherwise close an idle
/// connection immediately; 30s keeps it alive for the periodic ping.
pub const DEFAULT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Headroom added to the ping interval when deriving the idle timeout, so at
/// least one ping fits inside the idle window with room for jitter. 15s
/// preserves the historical default: 15s (default ping interval) + 15s = 30s.
pub const IDLE_TIMEOUT_BUFFER: std::time::Duration = std::time::Duration::from_secs(15);

/// Derive a safe idle timeout for a given ping interval.
///
/// Returns `max(DEFAULT_IDLE_TIMEOUT, interval + IDLE_TIMEOUT_BUFFER)` so a
/// caller-supplied ping cadence of 30s or more cannot be starved by the idle
/// closer before the next ping runs.
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
/// connection to survive long enough for the periodic ping to run. Later
/// phases with gossipsub/kad may revisit this.
///
/// Uses the default ping cadence (15s interval, 20s timeout), safely inside
/// the 30s idle window.
///
/// Returns the swarm; callers own listening (`Swarm::listen_on`) and dialing
/// (`Swarm::dial`) on the shared Tokio runtime.
pub fn new_swarm(keypair: &Keypair) -> Result<BankSwarm, libp2p_noise::Error> {
    new_swarm_with_ping(
        keypair,
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(20),
    )
}

/// Build a swarm with an explicit ping cadence (tests use a short interval).
///
/// Same stack as [`new_swarm`]; the idle timeout is derived via
/// [`idle_timeout_for_interval`] so the connection cannot be reaped before
/// the next ping, no matter how long `ping_interval` is.
pub fn new_swarm_with_ping(
    keypair: &Keypair,
    ping_interval: std::time::Duration,
    ping_timeout: std::time::Duration,
) -> Result<BankSwarm, libp2p_noise::Error> {
    let ping_config = libp2p_ping::Config::new()
        .with_interval(ping_interval)
        .with_timeout(ping_timeout);
    new_swarm_with_config(keypair, ping_config, idle_timeout_for_interval(ping_interval))
}

/// Build a swarm with an explicit ping config and idle timeout.
///
/// Same stack as [`new_swarm`]. Prefer [`new_swarm_with_ping`] unless you
/// need full control: callers who supply both values directly MUST keep
/// `idle_timeout` strictly greater than the ping interval embedded in
/// `ping_config`, otherwise the idle closer reaps the connection before the
/// next ping and liveness monitoring stops.
pub fn new_swarm_with_config(
    keypair: &Keypair,
    ping_config: libp2p_ping::Config,
    idle_timeout: std::time::Duration,
) -> Result<BankSwarm, libp2p_noise::Error> {
    let local_peer = PeerId::from(keypair.public());
    let tcp = libp2p_tcp::tokio::Transport::new(libp2p_tcp::Config::new().nodelay(true));
    let noise = noise_config(keypair)?;
    // Default Yamux config negotiates yamux/1.0.0 (rust-yamux 0.13.x, already
    // at 0.13.10 with the CVE-2026-32314 Data-frame panic fix); the legacy
    // 0.12 shim in libp2p-yamux is only reached if a caller explicitly opts
    // into the old client/server constructors, which Phase 0 never does.
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
        libp2p_swarm::Config::with_tokio_executor().with_idle_connection_timeout(idle_timeout),
    ))
}

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
