//! Comms 01 swarm skeleton: TCP + Noise + Yamux with identify + ping.
//!
//! Two locally running nodes dial each other by multiaddr, learn each other's
//! verified PeerId through identify, and exchange pings — with no external
//! infrastructure.

use clawbank_identity::{generate, peer_id};
use clawbank_transport::{new_swarm_with_ping, BankBehaviourEvent};
use futures::StreamExt;
use libp2p_swarm::SwarmEvent;
use multiaddr::{Multiaddr, Protocol};
use std::collections::HashSet;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(20);
const PING_INTERVAL: Duration = Duration::from_millis(500);
const PING_TIMEOUT: Duration = Duration::from_secs(5);

fn is_loopback(addr: &Multiaddr) -> bool {
    addr.iter()
        .any(|proto| matches!(proto, Protocol::Ip4(ip) if ip.is_loopback()))
}

#[tokio::test]
async fn two_local_nodes_identify_and_ping_over_encrypted_swarm() {
    let key_a = generate();
    let key_b = generate();
    let id_a = peer_id(&key_a);
    let id_b = peer_id(&key_b);
    assert_ne!(id_a, id_b);

    let mut swarm_a =
        new_swarm_with_ping(&key_a, PING_INTERVAL, PING_TIMEOUT).expect("swarm A builds");
    let mut swarm_b =
        new_swarm_with_ping(&key_b, PING_INTERVAL, PING_TIMEOUT).expect("swarm B builds");
    assert_eq!(*swarm_a.local_peer_id(), id_a);
    assert_eq!(*swarm_b.local_peer_id(), id_b);

    swarm_a
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .expect("A listens on loopback");
    swarm_b
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .expect("B listens on loopback");

    let mut addr_a: Option<Multiaddr> = None;
    let mut addr_b: Option<Multiaddr> = None;

    // Wait for both listeners to report addresses, then cross-dial by
    // multiaddr with the peer id attached.
    tokio::time::timeout(TIMEOUT, async {
        while addr_a.is_none() || addr_b.is_none() {
            tokio::select! {
                ev = swarm_a.select_next_some() => {
                    if let SwarmEvent::NewListenAddr { address, .. } = ev {
                        addr_a = Some(address);
                    }
                }
                ev = swarm_b.select_next_some() => {
                    if let SwarmEvent::NewListenAddr { address, .. } = ev {
                        addr_b = Some(address);
                    }
                }
            }
        }
    })
    .await
    .expect("listeners report addresses");

    let addr_a = addr_a.unwrap();
    let addr_b = addr_b.unwrap();

    let mut dial_a = addr_b.clone();
    dial_a.push(Protocol::P2p(id_b));
    let mut dial_b = addr_a.clone();
    dial_b.push(Protocol::P2p(id_a));

    swarm_a.dial(dial_a).expect("A dials B by multiaddr");
    swarm_b.dial(dial_b).expect("B dials A by multiaddr");

    let mut a_saw_b_via_identify = false;
    let mut b_saw_a_via_identify = false;
    let mut a_saw_b_addrs = false;
    let mut b_saw_a_addrs = false;
    let mut a_pinged_b = false;
    let mut b_pinged_a = false;
    let mut a_connected_to_b = false;
    let mut b_connected_to_a = false;

    tokio::time::timeout(TIMEOUT, async {
        while !(a_saw_b_via_identify
            && b_saw_a_via_identify
            && a_saw_b_addrs
            && b_saw_a_addrs
            && a_pinged_b
            && b_pinged_a
            && a_connected_to_b
            && b_connected_to_a)
        {
            tokio::select! {
                ev = swarm_a.select_next_some() => match ev {
                    SwarmEvent::Behaviour(BankBehaviourEvent::Identify(
                        libp2p_identify::Event::Received { peer_id, info, .. },
                    )) if peer_id == id_b => {
                        a_saw_b_via_identify = true;
                        // Must report the exact loopback listener we dialed,
                        // not just any non-empty set (catches stale/wrong addrs).
                        if info.listen_addrs.contains(&addr_b) {
                            assert!(
                                info.listen_addrs.iter().all(is_loopback),
                                "identify addrs must be loopback, got {:?}",
                                info.listen_addrs
                            );
                            a_saw_b_addrs = true;
                        }
                    }
                    SwarmEvent::Behaviour(BankBehaviourEvent::Ping(
                        libp2p_ping::Event { peer, result: Ok(_), .. },
                    )) if peer == id_b => {
                        a_pinged_b = true;
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == id_b => {
                        a_connected_to_b = true;
                    }
                    _ => {}
                },
                ev = swarm_b.select_next_some() => match ev {
                    SwarmEvent::Behaviour(BankBehaviourEvent::Identify(
                        libp2p_identify::Event::Received { peer_id, info, .. },
                    )) if peer_id == id_a => {
                        b_saw_a_via_identify = true;
                        if info.listen_addrs.contains(&addr_a) {
                            assert!(
                                info.listen_addrs.iter().all(is_loopback),
                                "identify addrs must be loopback, got {:?}",
                                info.listen_addrs
                            );
                            b_saw_a_addrs = true;
                        }
                    }
                    SwarmEvent::Behaviour(BankBehaviourEvent::Ping(
                        libp2p_ping::Event { peer, result: Ok(_), .. },
                    )) if peer == id_a => {
                        b_pinged_a = true;
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == id_a => {
                        b_connected_to_a = true;
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("identify + ping in both directions");

    // Loopback-only: no relay, no external addresses.
    let mut loopback_seen = HashSet::new();
    for addr in [addr_a, addr_b] {
        for proto in addr.iter() {
            if let Protocol::Ip4(ip) = proto {
                assert!(ip.is_loopback(), "listen must be loopback, got {ip}");
                loopback_seen.insert(ip);
            }
        }
    }
    assert!(!loopback_seen.is_empty());
}
