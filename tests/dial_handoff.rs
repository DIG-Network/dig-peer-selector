//! The DigPeer hand-off (SPEC §5.8, epic #1283): the selector hands a caller the `dig-peer`
//! `PeerTarget` for each chosen peer, so nobody re-derives dial addressing per consumer.
//!
//! Every test here drives the PRODUCTION seam — `PeerSelector::select` then
//! `PeerSelector::dial_plan` / `peer_target` — rather than the address helper underneath it, so a
//! correct helper wired to nothing cannot make them pass.

use std::net::SocketAddr;

use dig_dht::{AddressKind, CandidateAddr};
use dig_peer_selector::{
    Candidate, ContentId, ContentRequest, PeerId, PeerSelector, SelectorConfig, MAX_DIAL_CANDIDATES,
};

const NETWORK: &str = "mainnet";

fn pid(b: u8) -> PeerId {
    PeerId::from_bytes([b; 32])
}

fn selector() -> PeerSelector {
    PeerSelector::new(SelectorConfig::default())
}

fn request() -> ContentRequest {
    ContentRequest::new(ContentId::store([0x42; 32]), 8)
}

fn addr(host: &str, port: u16, kind: AddressKind) -> CandidateAddr {
    CandidateAddr {
        host: host.to_string(),
        port,
        kind,
    }
}

/// Select `candidates` and return the plan, keyed for convenient per-peer assertions.
fn plan(candidates: &[Candidate]) -> Vec<(PeerId, dig_peer_selector::PeerTarget)> {
    let selector = selector();
    let selection = selector.select(&request(), candidates);
    assert!(!selection.is_empty(), "fixture must select something");
    selector
        .dial_plan(&selection, NETWORK)
        .into_iter()
        .map(|(chosen, target)| (chosen.peer_id, target))
        .collect()
}

/// The hand-off carries the peer's REAL learned addresses, not a bare identity: a plan that always
/// answered relay-only would satisfy "a target per peer" identically, and this is what separates them.
#[test]
fn plan_carries_the_peers_dialable_address() {
    let c = Candidate::new(pid(1), vec![addr("10.0.0.7", 9444, AddressKind::Direct)]);
    let plan = plan(&[c]);

    let (_, target) = &plan[0];
    assert_eq!(
        target.direct_addrs(),
        &["10.0.0.7:9444".parse::<SocketAddr>().unwrap()][..],
    );
}

/// The target's identity is the CHOSEN peer's identity — the property `DigPeer::connect` pins the
/// handshake to (NC-12). Two peers, so a plan that returned the same target twice, or paired the
/// wrong peer with the wrong addresses, is visible.
#[test]
fn each_target_pins_its_own_peers_identity_and_addresses() {
    let a = Candidate::new(pid(1), vec![addr("10.0.0.1", 9444, AddressKind::Direct)]);
    let b = Candidate::new(pid(2), vec![addr("10.0.0.2", 9445, AddressKind::Direct)]);
    let plan = plan(&[a, b]);
    assert_eq!(plan.len(), 2);

    for (peer_id, target) in plan {
        assert_eq!(target.peer_id, peer_id);
        let expected: SocketAddr = match peer_id {
            p if p == pid(1) => "10.0.0.1:9444".parse().unwrap(),
            _ => "10.0.0.2:9445".parse().unwrap(),
        };
        assert_eq!(target.direct_addrs(), &[expected][..]);
    }
}

/// A relay marker and a hostname are BOTH unusable as direct dials, for DIFFERENT reasons — and the
/// relay marker carries an IP LITERAL host on purpose: with a hostname there, the literal check alone
/// would drop it and the kind filter could be deleted without any test noticing. The honest IPv4 is
/// the control, so a filter that dropped everything fails too.
#[test]
fn undialable_candidates_are_dropped_and_the_honest_one_survives() {
    let c = Candidate::new(
        pid(1),
        vec![
            addr("10.0.0.250", 9444, AddressKind::Relay),
            addr("peer.example.com", 9444, AddressKind::Direct),
            addr("10.0.0.9", 9444, AddressKind::Direct),
        ],
    );
    let plan = plan(&[c]);

    assert_eq!(
        plan[0].1.direct_addrs(),
        &["10.0.0.9:9444".parse::<SocketAddr>().unwrap()][..],
    );
}

/// An IPv6 host must reach the target as a V6 socket with its OWN port. Text-concatenating
/// `host:port` yields `::1:9000`, which parses as a DIFFERENT address (port 0x9000-ish semantics) or
/// not at all — so this fixture, unlike any IPv4 one, distinguishes parse-then-attach from format.
#[test]
fn ipv6_candidate_keeps_its_address_and_port() {
    let c = Candidate::new(pid(1), vec![addr("2001:db8::1", 9444, AddressKind::Direct)]);
    let plan = plan(&[c]);

    let addrs = plan[0].1.direct_addrs();
    assert_eq!(addrs.len(), 1);
    assert!(addrs[0].is_ipv6(), "expected a v6 socket, got {addrs:?}");
    assert_eq!(addrs[0].port(), 9444);
    assert_eq!(
        addrs[0].ip(),
        "2001:db8::1".parse::<std::net::IpAddr>().unwrap()
    );
}

/// The address cap is pinned from BOTH sides: exactly `MAX_DIAL_CANDIDATES` must pass through untouched,
/// and one more must be truncated to the cap. A bound tested only from above can be satisfied by any
/// smaller cap.
#[test]
fn address_count_is_capped_at_the_bound_and_not_below_it() {
    let hosts = [
        "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6",
    ];
    let at_bound: Vec<CandidateAddr> = hosts[..MAX_DIAL_CANDIDATES]
        .iter()
        .map(|h| addr(h, 9444, AddressKind::Direct))
        .collect();
    let over_bound: Vec<CandidateAddr> = hosts
        .iter()
        .map(|h| addr(h, 9444, AddressKind::Direct))
        .collect();
    assert!(
        over_bound.len() > MAX_DIAL_CANDIDATES,
        "fixture must exceed the bound"
    );

    assert_eq!(
        plan(&[Candidate::new(pid(1), at_bound)])[0]
            .1
            .direct_addrs()
            .len(),
        MAX_DIAL_CANDIDATES,
    );
    assert_eq!(
        plan(&[Candidate::new(pid(2), over_bound)])[0]
            .1
            .direct_addrs()
            .len(),
        MAX_DIAL_CANDIDATES,
    );
}

/// A padded record must not spend the whole cap on ONE address repeated. Six copies of the same
/// `host:port` plus one distinct address: a plain truncation keeps four (all identical, one real
/// destination), the inherited `dial_candidates` dedup keeps two DISTINCT destinations.
#[test]
fn repeated_addresses_do_not_fill_the_cap_with_one_destination() {
    let mut addresses: Vec<CandidateAddr> = (0..6)
        .map(|_| addr("10.0.0.1", 9444, AddressKind::Direct))
        .collect();
    addresses.push(addr("10.0.0.2", 9444, AddressKind::Direct));

    let plan = plan(&[Candidate::new(pid(1), addresses)]);
    let dialed = plan[0].1.direct_addrs();

    assert_eq!(
        dialed,
        &[
            "10.0.0.1:9444".parse::<SocketAddr>().unwrap(),
            "10.0.0.2:9444".parse::<SocketAddr>().unwrap(),
        ][..],
        "expected two distinct destinations, got {dialed:?}",
    );
}

/// The cap must never exclude EVERY non-IPv6 candidate: a dual-stack holder legitimately advertises
/// several IPv6 candidates, and an IPv6 address with no working route is ordinary, so a truncation
/// that drops the only IPv4 leaves a dialer walking every address it was given and still never
/// reaching the peer (#836's read-leg failure). Five IPv6 plus one IPv4 — a plain `.take(4)` on the
/// IPv6-first order keeps four IPv6 and no fallback; the inherited reservation keeps the IPv4.
#[test]
fn truncation_reserves_a_slot_for_the_ipv4_fallback() {
    let mut addresses: Vec<CandidateAddr> = (1..=5)
        .map(|n| addr(&format!("2001:db8::{n}"), 9444, AddressKind::Direct))
        .collect();
    addresses.push(addr("10.0.0.9", 9444, AddressKind::Direct));

    let plan = plan(&[Candidate::new(pid(1), addresses)]);
    let dialed = plan[0].1.direct_addrs();

    assert_eq!(dialed.len(), MAX_DIAL_CANDIDATES);
    assert!(
        dialed.contains(&"10.0.0.9:9444".parse::<SocketAddr>().unwrap()),
        "the IPv4 fallback was truncated away: {dialed:?}",
    );
    assert!(
        dialed[0].is_ipv6(),
        "IPv6 must still lead the list: {dialed:?}",
    );
}

/// Unusable hosts must be removed BEFORE the ordering bounds the list, not after. Five IPv6 literals
/// and one hostname: the cap reserves its last slot for the best non-IPv6 candidate, and with the
/// hostname still present that candidate IS the hostname — so filtering afterwards spends a slot on
/// something undialable and hands back three usable addresses where four exist.
#[test]
fn unusable_hosts_are_removed_before_the_cap_not_after() {
    let mut addresses: Vec<CandidateAddr> = (1..=5)
        .map(|n| addr(&format!("2001:db8::{n}"), 9444, AddressKind::Direct))
        .collect();
    addresses.push(addr("peer.example.com", 9444, AddressKind::Direct));

    let plan = plan(&[Candidate::new(pid(1), addresses)]);
    let dialed = plan[0].1.direct_addrs();

    assert_eq!(
        dialed.len(),
        MAX_DIAL_CANDIDATES,
        "a hostname consumed a dial slot: {dialed:?}",
    );
    assert!(dialed.iter().all(|a| a.is_ipv6()));
}

/// A peer with no usable address is still handed back — reachable by identity over the relay — rather
/// than silently dropped from the plan, which would make a selected peer unconnectable.
#[test]
fn a_peer_with_no_dialable_address_is_handed_back_relay_only() {
    let c = Candidate::new(
        pid(1),
        vec![addr("relay.example", 9444, AddressKind::Relay)],
    );
    let plan = plan(&[c]);

    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].1.peer_id, pid(1));
    assert!(plan[0].1.direct_addrs().is_empty());
}

/// The plan is in selection order, so `plan[0]` is the best peer. Asserted against the selection the
/// same call produced, not against insertion order, so it holds however the scorer ranks.
#[test]
fn plan_follows_selection_rank_order() {
    let candidates: Vec<Candidate> = (1u8..=4)
        .map(|b| {
            Candidate::new(
                pid(b),
                vec![addr(&format!("10.0.0.{b}"), 9444, AddressKind::Direct)],
            )
        })
        .collect();

    let selector = selector();
    let selection = selector.select(&request(), &candidates);
    let plan = selector.dial_plan(&selection, NETWORK);

    let planned: Vec<PeerId> = plan.iter().map(|(chosen, _)| chosen.peer_id).collect();
    let selected: Vec<PeerId> = selection.peers.iter().map(|p| p.peer_id).collect();
    assert_eq!(planned, selected);
}

/// The selector never invents reachability for an identity it was never told about — an unknown peer
/// has NO target, as distinct from a relay-only one.
#[test]
fn an_unknown_peer_has_no_target() {
    let selector = selector();
    let known = Candidate::new(pid(1), vec![addr("10.0.0.1", 9444, AddressKind::Direct)]);
    selector.upsert_candidate(&known);

    assert!(selector.peer_target(&pid(1), NETWORK).is_some());
    assert!(selector.peer_target(&pid(99), NETWORK).is_none());
}

/// The network id reaches the target — it is what keeps a mainnet dial off a foreign network.
#[test]
fn target_carries_the_network_id() {
    let c = Candidate::new(pid(1), vec![addr("10.0.0.1", 9444, AddressKind::Direct)]);
    assert_eq!(plan(&[c])[0].1.network_id, NETWORK);
}
