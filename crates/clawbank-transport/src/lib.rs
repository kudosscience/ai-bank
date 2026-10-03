//! Transport authenticity: Noise XX bound to the ADR-0001 identity key.
//!
//! [`listen`] accepts Noise-authenticated TCP connections on loopback and
//! [`dial`] opens one, checking the handshake-verified remote [`PeerId`]
//! against the expected peer before any application bytes flow. Both sides
//! observe the other's verified [`PeerId`] through [`SecureChannel`].
//!
//! Wire shape: TCP with `Noise_XX_25519_ChaChaPoly_SHA256` applied per stream
//! via `libp2p-noise` `Config::new`, built directly from the Identity 01
//! node keypair — there are no separate transport credentials. The Noise
//! handshake payload carries the static identity key plus a signature over
//! the ephemeral; `libp2p-noise` verifies both and reports the remote
//! [`PeerId`] derived from the verified key, so a forged key fails the
//! handshake itself. A valid-but-unexpected key completes the handshake and
//! is then rejected by [`dial`]'s expected-peer check, which drops the
//! channel on mismatch — either way no application data flows to a peer
//! that did not prove the required identity.
//!
//! Scope: Identity 05 proved handshake authenticity at the raw-channel
//! seam; Comms 01 adds the swarm (Yamux, identify, ping) on top, reusing
//! [`noise_config`] for the shared Noise choice.
//! All libp2p transport dependencies stay in this crate, keeping the
//! Identity 01-04 surface (key lifecycle, export, petnames, signing) light.

mod channel;
pub mod discovery;
mod net;
pub mod reachability;
mod swarm;

pub use channel::SecureChannel;
pub use clawbank_identity::{Keypair, PeerId};
pub use discovery::{
    handle_identify_received, handle_mdns_discovered, is_server_mode as kad_is_server_mode,
    new_kad, parse_bootstrap, routing_table_len as kad_routing_table_len, BootstrapPeer, Kad,
};
pub use net::{dial, listen, DialError, Listener};
pub use reachability::{
    build_relay_circuit_addr, capped_relay_config, format_hole_punch_outcome, has_direct_address,
    has_relayed_address, is_dns_address, is_quic_address, is_relay_only, is_relayed_address,
    reachability_from_autonat, reachability_indicator, should_reserve_relay_slot,
    HolePunchOutcome, Reachability, RelayAddrError, RelayLimits, DIRECT_INDICATOR,
    RELAY_ONLY_INDICATOR,
};
pub use swarm::{
    add_bootstrap, autonat_reachability, enable_relay_server, format_dcutr_event,
    hole_punch_outcome, idle_timeout_for_interval, is_server_mode, new_swarm, new_swarm_full,
    new_swarm_with_config, new_swarm_with_ping, relay_circuit_dial_addr, reserve_relay_slot,
    routing_table_len, start_bootstrap, BankBehaviour, BankBehaviourEvent, BankSwarm,
    BootstrapError, RelayReserveError, SwarmBuildError, DEFAULT_IDLE_TIMEOUT,
    IDENTIFY_PROTOCOL_VERSION, IDLE_TIMEOUT_BUFFER,
};

/// Build the Noise XX handshake config bound to the node identity key.
///
/// Returns the exact `libp2p-noise` config [`listen`] and [`dial`] use, so
/// later swarm code (Comms 01) shares one proven Noise choice instead of
/// re-deciding it.
pub fn noise_config(keypair: &Keypair) -> Result<libp2p_noise::Config, libp2p_noise::Error> {
    libp2p_noise::Config::new(keypair)
}
