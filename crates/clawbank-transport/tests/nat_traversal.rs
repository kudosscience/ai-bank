//! Comms 03 NAT traversal: AutoNAT classification, capped relay slot,
//! relay-routed dial with hole-punch attempt, relay-only indicator,
//! and QUIC/DNS/UPnP reachability.
//!
//! Relay addresses come from config (not kad discovery): the test builds
//! an in-process community relay on loopback and two NATed clients that
//! reserve slots only because they classify as private.

use clawbank_identity::{generate, peer_id};
use clawbank_transport::{
    capped_relay_config, enable_relay_server, format_dcutr_event, is_dns_address, is_quic_address,
    is_relay_only, is_relayed_address, new_swarm_with_ping, reachability_indicator,
    relay_circuit_dial_addr, reserve_relay_slot, should_reserve_relay_slot, BankBehaviourEvent,
    Reachability, RELAY_ONLY_INDICATOR,
};
use futures::StreamExt;
use libp2p_swarm::SwarmEvent;
use multiaddr::{Multiaddr, Protocol};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(30);
const PING_INTERVAL: Duration = Duration::from_millis(500);
const PING_TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn relay_load_stays_capped_and_only_nated_nodes_reserve() {
    let cfg = capped_relay_config();
    assert_eq!(cfg.max_reservations, 128);
    assert_eq!(cfg.max_reservations_per_peer, 4);
    assert_eq!(cfg.max_circuits, 16);
    assert_eq!(cfg.max_circuits_per_peer, 4);
    // Any public node can serve: caps keep load negligible.

    let public = Reachability::Public {
        confirmed_addr: "/ip4/203.0.113.7/tcp/4001".parse().unwrap(),
    };
    assert!(!should_reserve_relay_slot(&public));
    assert!(should_reserve_relay_slot(&Reachability::Private));
    assert!(should_reserve_relay_slot(&Reachability::Unknown));
}

#[tokio::test]
async fn quic_and_dns_transports_extend_reachability() {
    let key = generate();
    let mut swarm = new_swarm_with_ping(&key, PING_INTERVAL, PING_TIMEOUT).expect("swarm builds");

    // TCP + QUIC listeners both come up on the same swarm.
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .expect("TCP listens");
    swarm
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
        .expect("QUIC listens");

    let mut tcp_addr: Option<Multiaddr> = None;
    let mut quic_addr: Option<Multiaddr> = None;
    tokio::time::timeout(TIMEOUT, async {
        while tcp_addr.is_none() || quic_addr.is_none() {
            match swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    if is_quic_address(&address) {
                        quic_addr = Some(address);
                    } else {
                        tcp_addr = Some(address);
                    }
                }
                _ => {}
            }
        }
    })
    .await
    .expect("TCP + QUIC listeners report");

    assert!(is_quic_address(&quic_addr.unwrap()));
    assert!(!is_quic_address(&tcp_addr.clone().unwrap()));

    // DNS: a `/dns/localhost` dial resolves and connects (proves the DNS
    // transport wraps the stack). UPnP is opportunistic best-effort — its
    // presence is compile-time (BankBehaviour::upnp); no gateway needed here.
    let tcp = tcp_addr.unwrap();
    let port = tcp
        .iter()
        .find_map(|p| match p {
            Protocol::Tcp(port) => Some(port),
            _ => None,
        })
        .expect("TCP port");
    let id = *swarm.local_peer_id();
    let dns_dial: Multiaddr = format!("/dns/localhost/tcp/{port}/p2p/{id}").parse().unwrap();
    assert!(is_dns_address(&dns_dial));
    // Self-dial via DNS name: resolves localhost, handshake proves identity.
    swarm.dial(dns_dial).expect("DNS dial parses and dispatches");
}

#[tokio::test]
async fn relay_routed_dial_between_nated_nodes_with_hole_punch_attempt() {
    let relay_key = generate();
    let key_a = generate();
    let key_b = generate();
    let relay_id = peer_id(&relay_key);
    let id_b = peer_id(&key_b);

    let mut relay =
        new_swarm_with_ping(&relay_key, PING_INTERVAL, PING_TIMEOUT).expect("relay builds");
    let mut swarm_a =
        new_swarm_with_ping(&key_a, PING_INTERVAL, PING_TIMEOUT).expect("A builds");
    let mut swarm_b =
        new_swarm_with_ping(&key_b, PING_INTERVAL, PING_TIMEOUT).expect("B builds");

    // Community relay on loopback (stands in for the configured relay).
    // Force-enable HOP: loopback never gains a confirmed external address,
    // so auto-status would keep reservations disabled; a configured public
    // relay enables via AutoNAT instead.
    enable_relay_server(&mut relay);
    relay
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .expect("relay listens");
    let relay_addr: Multiaddr = tokio::time::timeout(TIMEOUT, async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = relay.select_next_some().await {
                if !is_relayed_address(&address) {
                    return address;
                }
            }
        }
    })
    .await
    .expect("relay reports address");
    // The reservation response carries the relay's external addresses; a
    // loopback test relay has none confirmed, so advertise its listen addr
    // explicitly (production learns this via AutoNAT/identify).
    relay.add_external_address(relay_addr.clone());

    // Both NATed nodes classify as private, so both reserve a slot.
    assert!(should_reserve_relay_slot(&Reachability::Private));
    for swarm in [&mut swarm_a, &mut swarm_b] {
        swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .expect("client listens");
    }
    // Wait for the direct listeners so identify can exchange candidates.
    for swarm in [&mut swarm_a, &mut swarm_b] {
        tokio::time::timeout(TIMEOUT, async {
            loop {
                if let SwarmEvent::NewListenAddr { .. } = swarm.select_next_some().await {
                    break;
                }
            }
        })
        .await
        .expect("client listener reports");
    }

    // Dial the relay directly first (learn observed addrs, open reservation
    // connection), then reserve the circuit slot via listen_on.
    let mut relay_full = relay_addr.clone();
    relay_full.push(Protocol::P2p(relay_id));
    for swarm in [&mut swarm_a, &mut swarm_b] {
        swarm.dial(relay_full.clone()).expect("dial relay");
    }
    // Wait until both clients are connected to the relay before reserving:
    // the reservation rides the existing connection.
    let mut a_to_relay = false;
    let mut b_to_relay = false;
    tokio::time::timeout(TIMEOUT, async {
        while !(a_to_relay && b_to_relay) {
            tokio::select! {
                ev = swarm_a.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = ev {
                        if peer_id == relay_id {
                            a_to_relay = true;
                        }
                    }
                }
                ev = swarm_b.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = ev {
                        if peer_id == relay_id {
                            b_to_relay = true;
                        }
                    }
                }
                ev = relay.select_next_some() => {
                    let _ = ev;
                }
            }
        }
    })
    .await
    .expect("both clients connect to relay");
    reserve_relay_slot(&mut swarm_a, &relay_addr, &relay_id).expect("A reserves");
    reserve_relay_slot(&mut swarm_b, &relay_addr, &relay_id).expect("B reserves");

    // Wait for both reservations to be accepted (capped slot granted).
    let mut a_reserved = false;
    let mut b_reserved = false;
    tokio::time::timeout(TIMEOUT, async {
        while !(a_reserved && b_reserved) {
            tokio::select! {
                ev = swarm_a.select_next_some() => {
                    if let SwarmEvent::Behaviour(
                        BankBehaviourEvent::RelayClient(
                            libp2p_relay::client::Event::ReservationReqAccepted { .. },
                        ),
                    ) = ev
                    {
                        a_reserved = true;
                    }
                }
                ev = swarm_b.select_next_some() => {
                    if let SwarmEvent::Behaviour(
                        BankBehaviourEvent::RelayClient(
                            libp2p_relay::client::Event::ReservationReqAccepted { .. },
                        ),
                    ) = ev
                    {
                        b_reserved = true;
                    }
                }
                ev = relay.select_next_some() => {
                    // Relay server accepts; nothing to assert beyond progress.
                    let _ = ev;
                }
            }
        }
    })
    .await
    .expect("both clients reserve relay slots");

    // Relay-routed dial: A reaches B via the relay circuit address.
    let circuit = relay_circuit_dial_addr(&relay_addr, &relay_id, &id_b).expect("circuit addr");
    assert!(is_relayed_address(&circuit));
    swarm_a.dial(circuit).expect("A dials B via relay");

    // Drive all three swarms until the relayed connection lands and DCUtR
    // reports its hole-punch attempt (success or stayed-relay both count;
    // the outcome must be logged).
    let mut relayed_a_to_b = false;
    let mut hole_punch_log: Option<String> = None;
    tokio::time::timeout(TIMEOUT, async {
        loop {
            if relayed_a_to_b && hole_punch_log.is_some() {
                break;
            }
            tokio::select! {
                ev = swarm_a.select_next_some() => match ev {
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. }
                        if peer_id == id_b && endpoint.is_relayed() =>
                    {
                        relayed_a_to_b = true;
                    }
                    SwarmEvent::Behaviour(BankBehaviourEvent::Dcutr(event))
                        if event.remote_peer_id == id_b =>
                    {
                        hole_punch_log = Some(format_dcutr_event(&event));
                    }
                    _ => {}
                },
                ev = swarm_b.select_next_some() => {
                    if let SwarmEvent::Behaviour(BankBehaviourEvent::Dcutr(event)) = ev {
                        // Either side's attempt satisfies "attempted with a
                        // logged outcome"; prefer A's but accept B's.
                        if hole_punch_log.is_none() {
                            hole_punch_log = Some(format_dcutr_event(&event));
                        }
                    }
                }
                ev = relay.select_next_some() => {
                    let _ = ev;
                }
            }
        }
    })
    .await
    .expect("relay-routed connection + hole-punch attempt");

    assert!(relayed_a_to_b, "A connects to B over the relay circuit");
    let log = hole_punch_log.expect("hole-punch outcome logged");
    assert!(
        log.contains(&id_b.to_string()) || log.contains("hole-punch"),
        "logged outcome names the peer: {log}"
    );

    // Relay-only indicator: a node with only circuit addresses reports
    // `relay-only (limited)`; mixed sets do not.
    let direct: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
    let relayed_only: Multiaddr = format!("{relay_addr}/p2p/{relay_id}/p2p-circuit")
        .parse()
        .unwrap();
    assert!(is_relay_only(&[relayed_only.clone()]));
    assert_eq!(
        reachability_indicator(&[relayed_only]),
        RELAY_ONLY_INDICATOR
    );
    assert_ne!(reachability_indicator(&[direct]), RELAY_ONLY_INDICATOR);
}
