//! An encrypted channel with a handshake-verified remote [`PeerId`].

use crate::PeerId;
use futures::io::{AsyncRead, AsyncWrite};
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A byte stream the Noise handshake has authenticated.
///
/// `remote_peer` is the [`PeerId`] derived from the static identity key the
/// handshake verified — not a self-reported name. The stream only exists
/// after the handshake, so writing to it cannot leak bytes to an
/// unauthenticated peer.
pub struct SecureChannel {
    remote_peer: PeerId,
    stream: Box<dyn Duplex>,
}

trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

impl SecureChannel {
    pub(crate) fn new(
        remote_peer: PeerId,
        stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    ) -> Self {
        Self {
            remote_peer,
            stream: Box::new(stream),
        }
    }

    /// The handshake-verified [`PeerId`] of the remote node.
    pub fn remote_peer(&self) -> PeerId {
        self.remote_peer
    }
}

impl fmt::Debug for SecureChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureChannel")
            .field("remote_peer", &self.remote_peer)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for SecureChannel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for SecureChannel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_close(cx)
    }
}
