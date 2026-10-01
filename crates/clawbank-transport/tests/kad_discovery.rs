//! Comms 02 discovery: Server-mode kad, bootstrap join, LAN mDNS.
//!
//! A fresh node joins through one well-known bootstrap multiaddr and its
//! routing table populates from the DHT; on a LAN two nodes find each other
//! via mDNS with no manual address exchange. Record shapes and registry
//! semantics belong to the future Registry track — find-peers only.

use clawbank_identity::{generate, peer_id};
use clawbank_transport::{
    add_bootstrap, handle_identify_received, handle_mdns_discovered, is_server_mode,
    new_swarm_full, new_swarm_with_ping, routing_table_len, start_bootstrap, BankBehaviourEvent,
};
use futures::StreamExt;
use libp2p_ping::Config as PingConfig;
use libp2p_swarm::SwarmEvent;
use multiaddr::{Multiaddr, Protocol};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(25);
const PING_INTERVAL: Duration = Duration::from_millis(500);
const PING_TIMEOUT: Duration = Duration::from_secs(5);

fn fast_mdns() -> libp2p_mdns::Config {
    libp2p_mdns::Config {
        query_interval: Duration::from_secs(1),
        ..libp2p_mdns::Config::default()
    }
}

fn swarm_pair() -> (
    clawbank_transport::BankSwarm,
    clawbank_transport::BankSwarm,
    clawbank_transport::PeerId,
    clawbank_transport::PeerId,
) {
    let key_a = generate();
    let key_b = generate();
    let id_a = peer_id(&key_a);
    let id_b = peer_id(&key_b);
    let ping = PingConfig::new()
        .with_interval(PING_INTERVAL)
        .with_timeout(PING_TIMEOUT);
    let idle = clawbank_transport::idle_timeout_for_interval(PING_INTERVAL);
    let mut swarm_a =
        new_swarm_full(&key_a, ping.clone(), idle, fast_mdns()).expect("swarm A builds");
    let mut swarm_b = new_swarm_full(&key_b, ping, idle, fast_mdns()).expect("swarm B builds");
    assert_ne!(id_a, id_b);
    // Silence unused-mut until listeners attach below (callers own the swarms).
    let _ = (&mut swarm_a, &mut swarm_b);
    (swarm_a, swarm_b, id_a, id_b)
}

async fn listen_addr(swarm: &mut clawbank_transport::BankSwarm) -> Multiaddr {
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .expect("listen on loopback");
    tokio::time::timeout(TIMEOUT, async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                return address;
            }
        }
    })
    .await
    .expect("listener reports address")
}

#[tokio::test]
async fn kad_runs_in_server_mode() {
    let key = generate();
    let swarm = new_swarm_with_ping(&key, PING_INTERVAL, PING_TIMEOUT).expect("swarm builds");
    assert!(
        is_server_mode(&swarm),
        "kad must run in Server mode on reachable nodes"
    );
}

#[tokio::test]
async fn bootstrap_from_single_well_known_addr_populates_routing_table() {
    let (mut swarm_a, mut swarm_b, id_a, id_b) = swarm_pair();
    assert!(is_server_mode(&swarm_a) && is_server_mode(&swarm_b));

    let addr_a = listen_addr(&mut swarm_a).await;
    let _addr_b = listen_addr(&mut swarm_b).await;

    // The well-known bootstrap address: A's addr + A's peer id. Not an
    // authority — just the single rendezvous hint B starts from.
    let mut bootstrap = addr_a.clone();
    bootstrap.push(Protocol::P2p(id_a));
    let parsed = add_bootstrap(&mut swarm_b, &bootstrap).expect("bootstrap dials");
    assert_eq!(parsed.peer_id, id_a);

    // A learns B'sbares addr via the inbound identify; B already fed A's
    // addr via add_bootstrap, and identify→kad wiring completes both sides.
    let mut b_bootstrapped = false;
    tokio::time::timeout(TIMEOUT, async {
        loop {
            if routing_table_len(&mut swarm_a) > 0 && routing_table_len(&mut swarm_b) > 0 {
                // Run the DHT bootstrap query once both sides know each other.
                if !b_bootstrapped {
                    start_bootstrap(&mut swarm_b).expect("bootstrap query starts");
                    b_bootstrapped = true;
                } else {
                    break;
                }
            }
            tokio::select! {
                ev = swarm_a.select_next_some() => {
                    if let SwarmEvent::Behaviour(
                        BankBehaviourEvent::Identify(libp2p_identify::Event::Received { peer_id, info, .. }),
                    ) = ev
                    {
                        handle_identify_received(
                            &mut swarm_a.behaviour_mut().kad,
                            &peer_id,
                            &info.listen_addrs,
                        );
                    }
                }
                ev = swarm_b.select_next_some() => {
                    match ev {
                        SwarmEvent::Behaviour(BankBehaviourEvent::Identify(
                            libp2p_identify::Event::Received { peer_id, info, .. },
                        )) => {
                            handle_identify_received(
                                &mut swarm_b.behaviour_mut().kad,
                                &peer_id,
                                &info.listen_addrs,
                            );
                        }
                        SwarmEvent::Behaviour(BankBehaviourEvent::Mdns(
                            libp2p_mdns::Event::Discovered(peers),
                        )) => {
                            handle_mdns_discovered(&mut swarm_b.behaviour_mut().kad, &peers);
                        }
                        _ => {}
                    }
                }
            }
        }
    })
    .await
    .expect("routing tables populate from single bootstrap");

    assert!(
        routing_table_len(&mut swarm_a) > 0,
        "bootstrap node learns joiner"
    );
    assert!(
        routing_table_len(&mut swarm_b) > 0,
        "joiner learns bootstrap"
    );
    let _ = id_b;
}

#[tokio::test]
async fn lan_peers_discover_each_other_via_mdns_with_no_manual_dial() {
    let (mut swarm_a, mut swarm_b, id_a, id_b) = swarm_pair();
    // mDNS only advertises non-loopback listen addresses (upstream
    // `libp2p-mdns` filters `addr_matches_interface`), so LAN nodes must
    // listen on all interfaces — loopback-only listeners stay invisible.
    for swarm in [&mut swarm_a, &mut swarm_b] {
        swarm
            .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
            .expect("listen on all interfaces");
    }
    tokio::time::timeout(TIMEOUT, async {
        // Wait until both swarms report at least one listen address.
        let mut a_ready = false;
        let mut b_ready = false;
        while !(a_ready && b_ready) {
            tokio::select! {
                ev = swarm_a.select_next_some() => {
                    if matches!(ev, SwarmEvent::NewListenAddr { .. }) {
                        a_ready = true;
                    }
                }
                ev = swarm_b.select_next_some() => {
                    if matches!(ev, SwarmEvent::NewListenAddr { .. }) {
                        b_ready = true;
                    }
                }
            }
        }
    })
    .await
    .expect("listeners report addresses");

    // No add_bootstrap, no manual dial: mDNS alone must introduce them.
    let mut a_saw_b = false;
    let mut b_saw_a = false;
    tokio::time::timeout(TIMEOUT, async {
        loop {
            if a_saw_b && b_saw_a {
                // Both LAN peers discovered; confirm the DHT path also
                // carries them (mDNS feeds the same routing table).
                if routing_table_len(&mut swarm_a) > 0 && routing_table_len(&mut swarm_b) > 0 {
                    break;
                }
            }
            tokio::select! {
                ev = swarm_a.select_next_some() => match ev {
                    SwarmEvent::Behaviour(BankBehaviourEvent::Mdns(
                        libp2p_mdns::Event::Discovered(peers),
                    )) => {
                        for (peer, addr) in &peers {
                            if *peer == id_b {
                                a_saw_b = true;
                                handle_mdns_discovered(&mut swarm_a.behaviour_mut().kad, &[(*peer, addr.clone())]);
                                // Dial so identify runs and the connection confirms.
                                let _ = swarm_a.dial(addr.clone().with_p2p(*peer).unwrap());
                            }
                        }
                    }
                    SwarmEvent::Behaviour(BankBehaviourEvent::Identify(
                        libp2p_identify::Event::Received { peer_id, info, .. },
                    )) => {
                        handle_identify_received(
                            &mut swarm_a.behaviour_mut().kad,
                            &peer_id,
                            &info.listen_addrs,
                        );
                    }
                    _ => {}
                },
                ev = swarm_b.select_next_some() => match ev {
                    SwarmEvent::Behaviour(BankBehaviourEvent::Mdns(
                        libp2p_mdns::Event::Discovered(peers),
                    )) => {
                        for (peer, addr) in &peers {
                            if *peer == id_a {
                                b_saw_a = true;
                                handle_mdns_discovered(&mut swarm_b.behaviour_mut().kad, &[(*peer, addr.clone())]);
                                let _ = swarm_b.dial(addr.clone().with_p2p(*peer).unwrap());
                            }
                        }
                    }
                    SwarmEvent::Behaviour(BankBehaviourEvent::Identify(
                        libp2p_identify::Event::Received { peer_id, info, .. },
                    )) => {
                        handle_identify_received(
                            &mut swarm_b.behaviour_mut().kad,
                            &peer_id,
                            &info.listen_addrs,
                        );
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("mDNS discovers LAN peer with no manual address exchange");
}
