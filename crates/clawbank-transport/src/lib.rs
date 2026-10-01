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
//! Scope: this crate proves handshake authenticity only (Identity 05).
//! Multiplexing (Yamux), the swarm, and application protocols arrive with
//! Comms 01, which reuses [`noise_config`] for the shared Noise choice.
//! All libp2p transport dependencies stay in this crate, keeping the
//! Identity 01-04 surface (key lifecycle, export, petnames, signing) light.

mod channel;
mod net;

pub use channel::SecureChannel;
pub use clawbank_identity::{Keypair, PeerId};
pub use net::{dial, listen, DialError, Listener};

/// Build the Noise XX handshake config bound to the node identity key.
///
/// Returns the exact `libp2p-noise` config [`listen`] and [`dial`] use, so
/// later swarm code (Comms 01) shares one proven Noise choice instead of
/// re-deciding it.
pub fn noise_config(keypair: &Keypair) -> Result<libp2p_noise::Config, libp2p_noise::Error> {
    libp2p_noise::Config::new(keypair)
}
