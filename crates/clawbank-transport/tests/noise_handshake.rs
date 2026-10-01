//! Noise XX handshake proving PeerId node-to-node (ADR-0001, Identity 05).
//!
//! Two-node smoke test for transport authenticity: distinct identities
//! connect over loopback TCP, and each side observes the other's verified
//! PeerId. No external infrastructure is involved.
//!
//! The rejection test dials with the wrong expected PeerId and asserts the
//! dial fails with [`DialError::PeerMismatch`] while the server observes
//! connection close rather than any application bytes.

use clawbank_identity::{generate, peer_id};
use clawbank_transport::{dial, listen, DialError};
use futures::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn two_nodes_complete_noise_handshake_and_observe_verified_peer_ids() {
    let server_keys = generate();
    let client_keys = generate();
    let server_id = peer_id(&server_keys);
    let client_id = peer_id(&client_keys);
    assert_ne!(server_id, client_id);

    let mut listener = tokio::time::timeout(TIMEOUT, listen(&server_keys))
        .await
        .expect("listen must not hang")
        .expect("listen on loopback must succeed");
    let addr = listener.local_addr();

    let accept = tokio::spawn(async move {
        tokio::time::timeout(TIMEOUT, listener.accept())
            .await
            .expect("accept must not hang")
            .expect("accept must succeed")
    });

    let mut client = tokio::time::timeout(TIMEOUT, dial(&client_keys, addr, &server_id))
        .await
        .expect("dial must not hang")
        .expect("dial with the correct expected PeerId must succeed");
    assert_eq!(
        client.remote_peer(),
        server_id,
        "dialer must observe the server's verified PeerId"
    );

    let mut server = accept.await.expect("accept task must not panic");
    assert_eq!(
        server.remote_peer(),
        client_id,
        "listener must observe the dialer's verified PeerId"
    );

    // The encrypted channel carries application bytes after the handshake.
    client.write_all(b"ping").await.unwrap();
    client.flush().await.unwrap();
    let mut buf = [0u8; 4];
    server.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    server.write_all(b"pong").await.unwrap();
    server.flush().await.unwrap();
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
}

#[tokio::test]
async fn plaintext_bytes_are_rejected_by_the_noise_handshake() {
    let server_keys = generate();
    let mut listener = listen(&server_keys)
        .await
        .expect("listen on loopback must succeed");
    let addr = listener.local_addr();

    let accept =
        tokio::spawn(async move { tokio::time::timeout(TIMEOUT, listener.accept()).await });

    // A peer that does not speak Noise XX: garbage bytes, then close.
    let mut raw = tokio::net::TcpStream::connect(addr)
        .await
        .expect("raw TCP connect must succeed");
    tokio::io::AsyncWriteExt::write_all(&mut raw, b"this is not a noise handshake")
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::shutdown(&mut raw).await.unwrap();
    let outcome = accept.await.expect("accept task must not panic");
    match outcome {
        Err(_) => panic!("accept itself must not hang on garbage input"),
        Ok(Err(_)) => {} // Handshake rejected the plaintext peer.
        Ok(Ok(_)) => panic!("plaintext bytes must never produce an authenticated channel"),
    }
}

#[tokio::test]
async fn dial_rejects_mismatched_peer_id_before_app_data_flows() {
    let server_keys = generate();
    let client_keys = generate();
    let bystander_keys = generate();
    let server_id = peer_id(&server_keys);
    let client_id = peer_id(&client_keys);
    let wrong_expected = peer_id(&bystander_keys);
    assert_ne!(server_id, wrong_expected);

    let mut listener = listen(&server_keys)
        .await
        .expect("listen on loopback must succeed");
    let addr = listener.local_addr();

    // The server completes the Noise handshake, then waits for application
    // bytes it must never receive: the dialer aborts first.
    let accept = tokio::spawn(async move {
        let mut server = tokio::time::timeout(TIMEOUT, listener.accept())
            .await
            .expect("accept must not hang")
            .expect("Noise handshake itself succeeds; rejection happens after");
        assert_eq!(server.remote_peer(), client_id);
        let mut buf = [0u8; 8];
        tokio::time::timeout(Duration::from_secs(2), server.read_exact(&mut buf)).await
    });

    let err = tokio::time::timeout(TIMEOUT, dial(&client_keys, addr, &wrong_expected))
        .await
        .expect("dial must not hang")
        .expect_err("dial with the wrong expected PeerId must fail");
    match &err {
        DialError::PeerMismatch { expected, observed } => {
            assert_eq!(**expected, wrong_expected);
            assert_eq!(**observed, server_id);
        }
        other => panic!("expected PeerMismatch, got: {other}"),
    }

    // The server saw the connection close without any application bytes:
    // either an EOF-shaped read error or the read timeout elapsed.
    let read_outcome = accept.await.expect("accept task must not panic");
    match read_outcome {
        Err(_) => {}     // Elapsed: no bytes arrived before the deadline.
        Ok(Err(_)) => {} // EOF / reset: closed before any application data.
        Ok(Ok(())) => panic!("server must not receive application bytes after a rejected dial"),
    }
}
