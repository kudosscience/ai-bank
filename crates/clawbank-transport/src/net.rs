//! Loopback listener and dialer for Noise-authenticated channels.
//!
//! The stack is plain TCP with the Noise XX upgrade applied directly to each
//! stream: no swarm, no multiplexing, no multistream-select negotiation, no
//! application protocols. That is the whole point — Identity 05 proves
//! handshake authenticity at this seam, and Comms 01 later feeds the same
//! [`noise_config`] into the full swarm builder (multistream-select V1
//! negotiation, Yamux, identify, ping), which is also what makes the node
//! dialable by stock libp2p peers. The Noise XX bytes on the wire are
//! produced by `libp2p-noise` itself either way, so the proof transfers
//! verbatim.

use crate::{noise_config, Keypair, PeerId, SecureChannel};
use libp2p_core::{
    transport::{ListenerId, TransportEvent},
    upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade},
    Transport,
};
use multiaddr::{Multiaddr, Protocol};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;

/// Plain TCP transport; Noise is applied per stream in [`listen`]/[`dial`].
type TcpTransport = libp2p_tcp::tokio::Transport;
/// The Noise-encrypted stream type behind [`SecureChannel`].
type NoiseStream = libp2p_noise::Output<libp2p_tcp::tokio::TcpStream>;

/// Bind a Noise-authenticated listener on `127.0.0.1` with an OS-assigned port.
///
/// Returns the listener; [`Listener::local_addr`] is the address dialers
/// connect to. Loopback-only: no external infrastructure is involved.
pub async fn listen(keypair: &Keypair) -> io::Result<Listener> {
    let noise =
        noise_config(keypair).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut transport = TcpTransport::new(libp2p_tcp::Config::new());
    let id = ListenerId::next();
    transport
        .listen_on(id, loopback(0))
        .map_err(|e| io::Error::new(io::ErrorKind::AddrNotAvailable, e))?;
    let addr = loop {
        match next_event(&mut transport).await {
            TransportEvent::NewAddress { listen_addr, .. } => break socket_addr(&listen_addr)?,
            TransportEvent::ListenerClosed { reason, .. } => {
                reason.map_err(aborted)?;
                return Err(listener_closed());
            }
            TransportEvent::ListenerError { error, .. } => return Err(error),
            _ => continue,
        }
    };
    Ok(Listener {
        transport,
        noise,
        addr,
    })
}

/// A bound listener awaiting Noise-authenticated inbound connections.
pub struct Listener {
    transport: TcpTransport,
    noise: libp2p_noise::Config,
    addr: SocketAddr,
}

impl Listener {
    /// The loopback address dialers connect to.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Accept the next inbound connection and run the Noise XX handshake.
    ///
    /// The handshake verifies the dialer's static identity key before
    /// returning, so [`SecureChannel::remote_peer`] is authenticated —
    /// a forged identity fails here, never at the application layer.
    ///
    /// No internal timeout: a silent peer keeps `accept` pending until the
    /// handshake completes or fails. Callers own the timeout and must wrap
    /// `accept` (e.g. `tokio::time::timeout`), as the smoke tests do; a
    /// failed handshake returns an `io::Result` error and `accept` may be
    /// called again for the next inbound connection.
    pub async fn accept(&mut self) -> io::Result<SecureChannel> {
        loop {
            match next_event(&mut self.transport).await {
                TransportEvent::Incoming { upgrade, .. } => {
                    let raw = upgrade.await.map_err(aborted)?;
                    let (remote_peer, stream) = self
                        .noise
                        .clone()
                        .upgrade_inbound(raw, "/noise")
                        .await
                        .map_err(aborted)?;
                    return Ok(SecureChannel::new(remote_peer, stream));
                }
                TransportEvent::ListenerClosed { reason, .. } => {
                    reason.map_err(aborted)?;
                    return Err(listener_closed());
                }
                TransportEvent::ListenerError { error, .. } => return Err(error),
                _ => continue,
            }
        }
    }
}

/// Poll the next event from a TCP transport.
async fn next_event(
    transport: &mut TcpTransport,
) -> TransportEvent<<TcpTransport as Transport>::ListenerUpgrade, io::Error> {
    futures::future::poll_fn(|cx| Pin::new(&mut *transport).poll(cx)).await
}

/// Open a Noise-authenticated channel to `addr`, requiring the handshake to
/// prove `expected`.
///
/// The Noise handshake cryptographically verifies the server's static
/// identity key; when the verified [`PeerId`] differs from `expected` the
/// channel is dropped before returning, so no application bytes can flow
/// to the wrong peer ([`DialError::PeerMismatch`]).
pub async fn dial(
    keypair: &Keypair,
    addr: SocketAddr,
    expected: &PeerId,
) -> Result<SecureChannel, DialError> {
    let noise = noise_config(keypair).map_err(DialError::connection)?;
    let mut transport = TcpTransport::new(libp2p_tcp::Config::new());
    let dial_addr = socket_multiaddr(addr);
    let raw: libp2p_tcp::tokio::TcpStream = transport
        .dial(dial_addr)
        .map_err(DialError::connection)?
        .await
        .map_err(DialError::connection)?;
    let (observed, stream): (PeerId, NoiseStream) = noise
        .upgrade_outbound(raw, "/noise")
        .await
        .map_err(DialError::connection)?;
    if observed != *expected {
        return Err(DialError::PeerMismatch {
            expected: Box::new(*expected),
            observed: Box::new(observed),
        });
    }
    Ok(SecureChannel::new(observed, stream))
}

/// A failed [`dial`].
#[derive(Debug)]
pub enum DialError {
    /// TCP connect or the Noise handshake failed.
    Connection(String),
    /// The handshake proved a different identity than requested. The channel
    /// was dropped before any application bytes flowed.
    ///
    /// The peers are boxed: a [`PeerId`] is wider than one might expect, and
    /// keeping the `Err` variant small keeps `dial`'s return cheap to move.
    PeerMismatch {
        /// The [`PeerId`] the dialer required.
        expected: Box<PeerId>,
        /// The [`PeerId`] the handshake actually verified.
        observed: Box<PeerId>,
    },
}

impl DialError {
    fn connection(e: impl fmt::Display) -> Self {
        DialError::Connection(e.to_string())
    }
}

impl fmt::Display for DialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DialError::Connection(detail) => write!(f, "noise dial failed: {detail}"),
            DialError::PeerMismatch { expected, observed } => write!(
                f,
                "peer identity mismatch: expected {expected}, handshake proved {observed}"
            ),
        }
    }
}

impl std::error::Error for DialError {}

/// Loopback TCP multiaddr with the given port (`0` lets the OS choose).
fn loopback(port: u16) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Ip4(Ipv4Addr::LOCALHOST));
    addr.push(Protocol::Tcp(port));
    addr
}

/// Render a dial-side address for the TCP transport.
fn socket_multiaddr(addr: SocketAddr) -> Multiaddr {
    let mut multiaddr = Multiaddr::empty();
    match addr.ip() {
        IpAddr::V4(ip) => multiaddr.push(Protocol::Ip4(ip)),
        IpAddr::V6(ip) => multiaddr.push(Protocol::Ip6(ip)),
    }
    multiaddr.push(Protocol::Tcp(addr.port()));
    multiaddr
}

/// Extract the bound loopback address from a listener multiaddr.
fn socket_addr(addr: &Multiaddr) -> io::Result<SocketAddr> {
    let mut ip: Option<IpAddr> = None;
    let mut port: Option<u16> = None;
    for protocol in addr.iter() {
        match protocol {
            Protocol::Ip4(v4) => ip = Some(IpAddr::V4(v4)),
            Protocol::Ip6(v6) => ip = Some(IpAddr::V6(v6)),
            Protocol::Tcp(p) => port = Some(p),
            _ => {}
        }
    }
    match (ip, port) {
        (Some(ip), Some(port)) => Ok(SocketAddr::new(ip, port)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("listener address is not TCP: {addr}"),
        )),
    }
}

fn aborted(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, e)
}

fn listener_closed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "listener closed")
}
